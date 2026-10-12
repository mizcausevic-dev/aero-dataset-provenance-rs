use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};

mod common;

use aero_dataset_provenance::{analyze, sign_report, verify_report, REPORT_VERSION};
use ed25519_dalek::SigningKey;
use hash_attestation::Attestor;
use serde_json::{json, Value};

struct Dataset {
    root: PathBuf,
}
impl Dataset {
    fn new() -> Self {
        let root = common::create_unique_temp_dir("aero-provenance-test");
        fs::write(root.join("train.txt"), b"synthetic train observation").unwrap();
        fs::write(root.join("val.txt"), b"synthetic validation observation").unwrap();
        fs::write(root.join("test.txt"), b"synthetic test observation").unwrap();
        Self { root }
    }
    fn root(&self) -> &Path {
        &self.root
    }
}
impl Drop for Dataset {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn concurrent_dataset_fixtures_have_distinct_directories() {
    const WORKERS: usize = 32;
    let barrier = Arc::new(Barrier::new(WORKERS));
    let handles: Vec<_> = (0..WORKERS)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                Dataset::new()
            })
        })
        .collect();
    let mut roots = HashSet::new();
    let datasets: Vec<_> = handles
        .into_iter()
        .map(|handle| {
            let dataset = handle.join().unwrap();
            assert!(roots.insert(dataset.root.clone()));
            dataset
        })
        .collect();
    assert_eq!(datasets.len(), WORKERS);
}

fn manifest() -> Value {
    json!({
        "manifest_version":"0.1.0", "dataset_id":"SYNTHETIC-DEMO",
        "odd_bins":{"lighting":["day","night"]},
        "minimum_evaluation_samples_per_bin":1,
        "temporal_train_before_epoch_s":200,
        "samples":[
            {"id":"train-1","path":"train.txt","split":"train","group_id":"synthetic-unit-1","captured_at_epoch_s":100,"odd_values":{"lighting":"day"}},
            {"id":"val-1","path":"val.txt","split":"validation","group_id":"synthetic-unit-2","captured_at_epoch_s":200,"odd_values":{"lighting":"day"}},
            {"id":"test-1","path":"test.txt","split":"test","group_id":"synthetic-unit-3","captured_at_epoch_s":300,"odd_values":{"lighting":"night"}}
        ]
    })
}

#[test]
fn positive_report_is_deterministic_and_bounded_in_claims() {
    let dataset = Dataset::new();
    let input = manifest().to_string();
    let first = analyze(&input, dataset.root()).unwrap();
    let second = analyze(&input, dataset.root()).unwrap();
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
    assert!(first.declared_checks_passed);
    assert_eq!(first.report_version, REPORT_VERSION);
    assert_eq!(first.sample_count, 3);
    assert_eq!(first.evaluation_sample_count, 2);
    assert!(first.leakage_findings.is_empty());
    assert!(first.temporal_policy_evaluated);
    assert!(first
        .limitations
        .iter()
        .any(|item| item.contains("airworthiness")));
}

#[test]
fn repeated_evaluation_bytes_do_not_satisfy_odd_minimum() {
    let dataset = Dataset::new();
    fs::copy(
        dataset.root().join("val.txt"),
        dataset.root().join("val-copy.txt"),
    )
    .unwrap();
    fs::copy(
        dataset.root().join("test.txt"),
        dataset.root().join("test-copy.txt"),
    )
    .unwrap();
    let mut input = manifest();
    input["minimum_evaluation_samples_per_bin"] = json!(2);
    input["samples"].as_array_mut().unwrap().extend([
        json!({"id":"val-2","path":"val-copy.txt","split":"validation","group_id":"synthetic-unit-4","captured_at_epoch_s":200,"odd_values":{"lighting":"day"}}),
        json!({"id":"test-2","path":"test-copy.txt","split":"test","group_id":"synthetic-unit-5","captured_at_epoch_s":300,"odd_values":{"lighting":"night"}}),
    ]);

    let report = analyze(&input.to_string(), dataset.root()).unwrap();
    assert_eq!(report.evaluation_sample_count, 4); // Raw manifest rows.
    assert!(report.leakage_findings.is_empty()); // No cross-split leakage.
    assert!(!report.declared_checks_passed);
    let bins = &report.odd_observations[0].bins;
    assert_eq!(
        bins.iter()
            .map(|bin| bin.evaluation_samples)
            .collect::<Vec<_>>(),
        [1, 1]
    );
    assert!(bins.iter().all(|bin| !bin.meets_declared_minimum));
    assert_eq!(report.samples[0].sha256, report.samples[1].sha256); // test pair, sorted by ID.
    assert_eq!(report.samples[3].sha256, report.samples[4].sha256); // validation pair.
}

#[test]
fn distinct_evaluation_bytes_can_satisfy_odd_minimum() {
    let dataset = Dataset::new();
    fs::write(
        dataset.root().join("val-2.txt"),
        b"different synthetic validation observation",
    )
    .unwrap();
    fs::write(
        dataset.root().join("test-2.txt"),
        b"different synthetic test observation",
    )
    .unwrap();
    let mut input = manifest();
    input["minimum_evaluation_samples_per_bin"] = json!(2);
    input["samples"].as_array_mut().unwrap().extend([
        json!({"id":"val-2","path":"val-2.txt","split":"validation","group_id":"synthetic-unit-4","captured_at_epoch_s":200,"odd_values":{"lighting":"day"}}),
        json!({"id":"test-2","path":"test-2.txt","split":"test","group_id":"synthetic-unit-5","captured_at_epoch_s":300,"odd_values":{"lighting":"night"}}),
    ]);

    let report = analyze(&input.to_string(), dataset.root()).unwrap();
    assert!(report.declared_checks_passed);
    assert_eq!(report.evaluation_sample_count, 4);
    let bins = &report.odd_observations[0].bins;
    assert_eq!(
        bins.iter()
            .map(|bin| bin.evaluation_samples)
            .collect::<Vec<_>>(),
        [2, 2]
    );
    assert!(bins.iter().all(|bin| bin.meets_declared_minimum));
}

#[test]
fn rejects_conflicting_odd_labels_for_identical_evaluation_bytes() {
    let dataset = Dataset::new();
    let mut input = manifest();
    input["samples"].as_array_mut().unwrap().push(json!({
        "id":"test-2", "path":"test.txt", "split":"test", "group_id":"synthetic-unit-4",
        "captured_at_epoch_s":300, "odd_values":{"lighting":"day"}
    }));

    let error = analyze(&input.to_string(), dataset.root()).unwrap_err();
    assert!(error.to_string().contains("conflicting ODD bins"));
}

#[test]
fn cross_split_duplicate_bytes_still_produce_leakage_finding() {
    let dataset = Dataset::new();
    let mut input = manifest();
    input["samples"][2]["path"] = json!("val.txt"); // Test row duplicates validation bytes.
    let report = analyze(&input.to_string(), dataset.root()).unwrap();
    assert!(!report.declared_checks_passed);
    assert!(report
        .leakage_findings
        .iter()
        .any(|finding| finding.kind == "exact_file_sha256"));
}

#[test]
fn detects_exact_and_group_cross_split_leakage() {
    let dataset = Dataset::new();
    let mut input = manifest();
    input["samples"][2]["path"] = json!("train.txt");
    input["samples"][2]["group_id"] = json!("synthetic-unit-1");
    let report = analyze(&input.to_string(), dataset.root()).unwrap();
    assert!(!report.declared_checks_passed);
    assert!(report
        .leakage_findings
        .iter()
        .any(|finding| finding.kind == "exact_file_sha256"));
    assert!(report
        .leakage_findings
        .iter()
        .any(|finding| finding.kind == "group_id"));
    assert!(report
        .leakage_findings
        .iter()
        .all(|finding| finding.sample_ids == ["test-1", "train-1"]));
}

#[test]
fn detects_temporal_leakage_and_missing_or_unknown_odd_bins() {
    let dataset = Dataset::new();
    let mut input = manifest();
    input["samples"][0]["captured_at_epoch_s"] = json!(250);
    input["samples"][2]["odd_values"]["lighting"] = json!("dusk");
    let report = analyze(&input.to_string(), dataset.root()).unwrap();
    assert!(!report.declared_checks_passed);
    assert_eq!(report.temporal_violations.len(), 1);
    assert_eq!(report.temporal_violations[0].sample_id, "train-1");
    assert_eq!(
        report.odd_observations[0].missing_or_undeclared_value_samples,
        1
    );
    assert!(!report.odd_observations[0].bins[1].meets_declared_minimum);
}

#[test]
fn rejects_escaping_paths_and_duplicate_json_keys() {
    let dataset = Dataset::new();
    let mut input = manifest();
    input["samples"][0]["path"] = json!("../outside.txt");
    assert!(analyze(&input.to_string(), dataset.root())
        .unwrap_err()
        .to_string()
        .contains("unsafe sample path"));
    let raw = r#"{"manifest_version":"0.1.0","manifest_version":"0.1.0"}"#;
    assert!(analyze(raw, dataset.root())
        .unwrap_err()
        .to_string()
        .contains("invalid strict JSON"));
}

#[test]
fn signature_verification_rejects_tamper_and_wrong_expected_key() {
    let dataset = Dataset::new();
    let report = analyze(&manifest().to_string(), dataset.root()).unwrap();
    let raw = serde_json::to_string(&report).unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]); // synthetic in-memory test key only
    let public = key.verifying_key();
    let url = "https://example.invalid/keys/synthetic";
    let signature = sign_report(&raw, key, url).unwrap();
    verify_report(&raw, &signature, url, public).unwrap();
    assert!(verify_report(
        &raw,
        &signature,
        "https://example.invalid/keys/other",
        public
    )
    .is_err());
    let mut tampered: Value = serde_json::from_str(&raw).unwrap();
    tampered["dataset_id"] = json!("different");
    assert!(verify_report(&tampered.to_string(), &signature, url, public).is_err());
    let mut metadata_tampered = signature;
    metadata_tampered.signed_at = "2001-01-01T00:00:00Z".into();
    assert!(verify_report(&raw, &metadata_tampered, url, public).is_err());
}

#[test]
fn old_report_signatures_remain_verifiable_but_cannot_be_newly_signed() {
    let dataset = Dataset::new();
    let mut old_report =
        serde_json::to_value(analyze(&manifest().to_string(), dataset.root()).unwrap()).unwrap();
    old_report["report_version"] = json!("0.1.0");
    let raw = old_report.to_string();
    let key = SigningKey::from_bytes(&[7u8; 32]); // Synthetic compatibility fixture.
    let public = key.verifying_key();
    let url = "https://example.invalid/keys/synthetic";
    let signature = Attestor::new(key, url.into()).sign_raw_json(&raw).unwrap();

    verify_report(&raw, &signature, url, public).unwrap();
    assert!(sign_report(&raw, SigningKey::from_bytes(&[7u8; 32]), url).is_err());
}

#[test]
fn signing_and_verification_reject_malformed_or_credential_bearing_key_urls() {
    let dataset = Dataset::new();
    let report = analyze(&manifest().to_string(), dataset.root()).unwrap();
    let raw = serde_json::to_string(&report).unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let public = key.verifying_key();
    let valid_url = "https://example.invalid/keys/synthetic";
    let signature = sign_report(&raw, key, valid_url).unwrap();

    for invalid_url in [
        "http://example.invalid/key",
        "https://",
        "https:///key",
        "https://user@example.invalid/key",
        "https://user:password@example.invalid/key",
        "https://@example.invalid/key",
        "https://example.invalid:bad/key",
        "https://example.invalid/a b",
        "https://example.invalid\\@other.invalid/key",
    ] {
        assert!(
            sign_report(&raw, SigningKey::from_bytes(&[7u8; 32]), invalid_url).is_err(),
            "sign accepted {invalid_url}"
        );
        assert!(
            verify_report(&raw, &signature, invalid_url, public).is_err(),
            "verify accepted {invalid_url}"
        );
    }
    verify_report(&raw, &signature, valid_url, public).unwrap();
}
