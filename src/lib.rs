//! Offline, bounded dataset evidence checks. The report describes observed bytes
//! and declared ODD bins; it does not establish data rights or airworthiness.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use ed25519_dalek::{SigningKey, VerifyingKey};
use hash_attestation::{
    canonical_hash_jcs, parse_jcs_json_strict, Attestation, Attestor, Verifier, JCS_HASH_PROFILE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

pub const MAX_SAMPLES: usize = 10_000;
pub const MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub struct Error(pub String);

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

fn fail(message: impl Into<String>) -> Error {
    Error(message.into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub manifest_version: String,
    pub dataset_id: String,
    pub odd_bins: BTreeMap<String, Vec<String>>,
    pub minimum_evaluation_samples_per_bin: u32,
    /// Optional declared boundary. Train captures must precede it; validation
    /// and test captures must be at or after it. All timestamps are UTC seconds.
    pub temporal_train_before_epoch_s: Option<i64>,
    pub samples: Vec<Sample>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub id: String,
    pub path: String,
    pub split: Split,
    /// Pseudonymous aircraft, flight, subject, or acquisition unit identifier.
    /// Samples from one group must not cross splits.
    pub group_id: String,
    pub captured_at_epoch_s: Option<i64>,
    pub odd_values: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Split {
    Train,
    Validation,
    Test,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SampleRecord {
    pub id: String,
    pub path: String,
    pub split: Split,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeakageFinding {
    pub kind: String,
    pub key_sha256: String,
    pub sample_ids: Vec<String>,
    pub splits: Vec<Split>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemporalViolation {
    pub sample_id: String,
    pub split: Split,
    pub captured_at_epoch_s: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinObservation {
    pub bin: String,
    pub evaluation_samples: u32,
    pub meets_declared_minimum: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OddObservation {
    pub dimension: String,
    pub bins: Vec<BinObservation>,
    pub missing_or_undeclared_value_samples: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub report_version: String,
    pub dataset_id: String,
    pub manifest_jcs_sha256: String,
    pub sample_count: usize,
    pub evaluation_sample_count: usize,
    pub samples: Vec<SampleRecord>,
    pub leakage_findings: Vec<LeakageFinding>,
    pub temporal_policy_evaluated: bool,
    pub temporal_violations: Vec<TemporalViolation>,
    pub odd_observations: Vec<OddObservation>,
    pub declared_checks_passed: bool,
    pub limitations: Vec<String>,
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn nonempty(label: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.trim() != value || value.len() > 256 {
        return Err(fail(format!(
            "{label} must be nonempty, trimmed, and at most 256 bytes"
        )));
    }
    Ok(())
}

fn reject_reparse_or_symlink(path: &Path) -> Result<(), Error> {
    let metadata = path
        .symlink_metadata()
        .map_err(|e| fail(format!("cannot inspect path: {e}")))?;
    if metadata.file_type().is_symlink() {
        return Err(fail("symlinked dataset paths are not accepted"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(fail("reparse-point dataset paths are not accepted"));
        }
    }
    Ok(())
}

fn checked_path(root: &Path, path: &str) -> Result<std::path::PathBuf, Error> {
    if path.is_empty() || path.len() > 1024 {
        return Err(fail("invalid sample path length"));
    }
    let relative = Path::new(path);
    if !relative
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(fail(format!("unsafe sample path: {path}")));
    }
    let mut selected = root.to_path_buf();
    for part in relative.components() {
        selected.push(part.as_os_str());
        reject_reparse_or_symlink(&selected)?;
    }
    if !selected.is_file() {
        return Err(fail(format!("sample path is not a regular file: {path}")));
    }
    Ok(selected)
}

fn hash_file(path: &Path, label: &str) -> Result<(String, u64), Error> {
    let mut file = File::open(path).map_err(|e| fail(format!("cannot read {label}: {e}")))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = file
            .read(&mut buffer)
            .map_err(|e| fail(format!("cannot read {label}: {e}")))?;
        if size == 0 {
            break;
        }
        bytes += size as u64;
        if bytes > MAX_FILE_BYTES {
            return Err(fail(format!("sample exceeds 100 MiB: {label}")));
        }
        hasher.update(&buffer[..size]);
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), bytes))
}

/// Analyze a strict JSON manifest against files rooted at `dataset_root`.
/// Relative sample paths are checked below the supplied absolute root, with
/// symlink and reparse-point traversal rejected. Use an immutable snapshot.
pub fn analyze(manifest_json: &str, dataset_root: &Path) -> Result<Report, Error> {
    if manifest_json.len() > MAX_MANIFEST_BYTES {
        return Err(fail("manifest exceeds 8 MiB"));
    }
    let value = parse_jcs_json_strict(manifest_json)
        .map_err(|e| fail(format!("invalid strict JSON: {e}")))?;
    let manifest: Manifest = serde_json::from_value(value.clone())
        .map_err(|e| fail(format!("invalid manifest: {e}")))?;
    if manifest.manifest_version != "0.1.0" {
        return Err(fail("unsupported manifest_version"));
    }
    nonempty("dataset_id", &manifest.dataset_id)?;
    if manifest.samples.is_empty() || manifest.samples.len() > MAX_SAMPLES {
        return Err(fail("sample count must be 1..10000"));
    }
    if manifest.minimum_evaluation_samples_per_bin == 0
        || manifest.minimum_evaluation_samples_per_bin > 10_000
    {
        return Err(fail("minimum_evaluation_samples_per_bin must be 1..10000"));
    }
    if manifest.odd_bins.is_empty() || manifest.odd_bins.len() > 32 {
        return Err(fail("odd_bins must declare 1..32 dimensions"));
    }
    for (dimension, bins) in &manifest.odd_bins {
        nonempty("ODD dimension", dimension)?;
        if bins.is_empty() || bins.len() > 128 {
            return Err(fail(format!(
                "ODD dimension {dimension} must have 1..128 bins"
            )));
        }
        let mut seen = BTreeSet::new();
        for bin in bins {
            nonempty("ODD bin", bin)?;
            if !seen.insert(bin) {
                return Err(fail(format!("duplicate ODD bin in {dimension}")));
            }
        }
    }
    if !dataset_root.is_absolute()
        || dataset_root
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(fail(
            "dataset root must be an absolute path without dot components",
        ));
    }
    reject_reparse_or_symlink(dataset_root)?;
    let root = dataset_root.to_path_buf();
    if !root.is_dir() {
        return Err(fail("dataset root is not a directory"));
    }

    let mut ids = BTreeSet::new();
    let mut records = Vec::with_capacity(manifest.samples.len());
    let mut exact: BTreeMap<String, Vec<(String, Split)>> = BTreeMap::new();
    let mut groups: BTreeMap<String, Vec<(String, Split)>> = BTreeMap::new();
    let mut temporal_violations = Vec::new();
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    let mut unknowns: BTreeMap<String, u32> = BTreeMap::new();
    let mut evaluation_count = 0usize;

    for sample in &manifest.samples {
        nonempty("sample id", &sample.id)?;
        nonempty("group_id", &sample.group_id)?;
        if !ids.insert(sample.id.clone()) {
            return Err(fail(format!("duplicate sample id: {}", sample.id)));
        }
        for dimension in sample.odd_values.keys() {
            if !manifest.odd_bins.contains_key(dimension) {
                return Err(fail(format!("undeclared ODD dimension: {dimension}")));
            }
        }
        let file = checked_path(&root, &sample.path)?;
        let (digest, byte_length) = hash_file(&file, &sample.path)?;
        exact
            .entry(digest.clone())
            .or_default()
            .push((sample.id.clone(), sample.split));
        groups
            .entry(sample.group_id.clone())
            .or_default()
            .push((sample.id.clone(), sample.split));
        records.push(SampleRecord {
            id: sample.id.clone(),
            path: sample.path.clone(),
            split: sample.split,
            sha256: digest,
            byte_length,
        });

        if let Some(boundary) = manifest.temporal_train_before_epoch_s {
            let wrong_side = sample
                .captured_at_epoch_s
                .is_none_or(|capture| match sample.split {
                    Split::Train => capture >= boundary,
                    Split::Validation | Split::Test => capture < boundary,
                });
            if wrong_side {
                temporal_violations.push(TemporalViolation {
                    sample_id: sample.id.clone(),
                    split: sample.split,
                    captured_at_epoch_s: sample.captured_at_epoch_s,
                });
            }
        }
        if sample.split != Split::Train {
            evaluation_count += 1;
            for (dimension, bins) in &manifest.odd_bins {
                match sample.odd_values.get(dimension) {
                    Some(value) if bins.contains(value) => {
                        *counts
                            .entry((dimension.clone(), value.clone()))
                            .or_default() += 1
                    }
                    _ => *unknowns.entry(dimension.clone()).or_default() += 1,
                }
            }
        }
    }
    records.sort_by(|a, b| a.id.cmp(&b.id));
    temporal_violations.sort_by(|a, b| a.sample_id.cmp(&b.sample_id));

    let mut leakage_findings = Vec::new();
    for (kind, index) in [("exact_file_sha256", &exact), ("group_id", &groups)] {
        for (key, members) in index {
            let splits: BTreeSet<Split> = members.iter().map(|(_, split)| *split).collect();
            if splits.len() <= 1 {
                continue;
            }
            let mut sample_ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
            sample_ids.sort();
            leakage_findings.push(LeakageFinding {
                kind: kind.into(),
                key_sha256: sha256(key.as_bytes()),
                sample_ids,
                splits: splits.into_iter().collect(),
            });
        }
    }
    leakage_findings.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.key_sha256.cmp(&b.key_sha256)));

    let mut odd_observations = Vec::new();
    for (dimension, bins) in &manifest.odd_bins {
        let observations: Vec<BinObservation> = bins
            .iter()
            .map(|bin| {
                let count = *counts.get(&(dimension.clone(), bin.clone())).unwrap_or(&0);
                BinObservation {
                    bin: bin.clone(),
                    evaluation_samples: count,
                    meets_declared_minimum: count >= manifest.minimum_evaluation_samples_per_bin,
                }
            })
            .collect();
        odd_observations.push(OddObservation {
            dimension: dimension.clone(),
            bins: observations,
            missing_or_undeclared_value_samples: *unknowns.get(dimension).unwrap_or(&0),
        });
    }
    let bins_meet_minimum = odd_observations.iter().all(|dimension| {
        dimension.missing_or_undeclared_value_samples == 0
            && dimension.bins.iter().all(|bin| bin.meets_declared_minimum)
    });
    let declared_checks_passed =
        leakage_findings.is_empty() && temporal_violations.is_empty() && bins_meet_minimum;
    Ok(Report {
        report_version: "0.1.0".into(),
        dataset_id: manifest.dataset_id,
        manifest_jcs_sha256: canonical_hash_jcs(&value).map_err(|e| fail(e.to_string()))?,
        sample_count: records.len(),
        evaluation_sample_count: evaluation_count,
        samples: records,
        leakage_findings,
        temporal_policy_evaluated: manifest.temporal_train_before_epoch_s.is_some(),
        temporal_violations,
        odd_observations,
        declared_checks_passed,
        limitations: vec![
            "Hashes bind observed bytes, not dataset origin, rights, label quality, or completeness.".into(),
            "ODD counts are observations against declared bins and minimums; bin labels are not machine-bound to aviation-card operating conditions. They do not establish statistical representativeness or airworthiness approval.".into(),
            "Group leakage is limited to supplied pseudonymous group_id values; temporal leakage is evaluated only when a boundary is declared.".into(),
            "File replacement during analysis is not prevented; operate on an immutable snapshot for release evidence.".into(),
        ],
    })
}

/// Sign a strict report JSON value with the pinned hash-attestation v0.2 profile.
/// The key URL is a selector; key ownership and signer authority are external.
pub fn sign_report(
    report_json: &str,
    signing_key: SigningKey,
    key_url: &str,
) -> Result<Attestation, Error> {
    validate_key_url(key_url)?;
    validate_report_json(report_json)?;
    Attestor::new(signing_key, key_url.into())
        .sign_raw_json(report_json)
        .map_err(|e| fail(e.to_string()))
}

/// Verify report bytes against a caller-trusted key and independently expected URL.
pub fn verify_report(
    report_json: &str,
    attestation: &Attestation,
    expected_key_url: &str,
    verifying_key: VerifyingKey,
) -> Result<(), Error> {
    validate_key_url(expected_key_url)?;
    validate_report_json(report_json)?;
    if attestation.hash_profile.as_deref() != Some(JCS_HASH_PROFILE) {
        return Err(fail("legacy or unsupported signature profile"));
    }
    let mut verifier = Verifier::new();
    verifier.trust(expected_key_url, verifying_key);
    verifier
        .verify_raw_json_for_key_url(expected_key_url, attestation, report_json)
        .map_err(|e| fail(e.to_string()))
}

fn validate_key_url(key_url: &str) -> Result<(), Error> {
    let authority = key_url
        .strip_prefix("https://")
        .ok_or_else(|| fail("key URL must be an absolute HTTPS URL"))?
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || key_url
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err(fail(
            "key URL must have a host and no userinfo or whitespace",
        ));
    }
    let parsed = Url::parse(key_url).map_err(|_| fail("invalid key URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(fail("key URL must have a HTTPS host and no userinfo"));
    }
    Ok(())
}

fn validate_report_json(raw: &str) -> Result<(), Error> {
    if raw.len() > MAX_MANIFEST_BYTES {
        return Err(fail("report exceeds 8 MiB"));
    }
    let value =
        parse_jcs_json_strict(raw).map_err(|e| fail(format!("invalid strict report JSON: {e}")))?;
    let report: Report =
        serde_json::from_value(value).map_err(|e| fail(format!("invalid report: {e}")))?;
    if report.report_version != "0.1.0" {
        return Err(fail("unsupported report_version"));
    }
    Ok(())
}
