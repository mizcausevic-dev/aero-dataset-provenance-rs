use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod common;

use aero_dataset_provenance::{MAX_MANIFEST_BYTES, REPORT_VERSION};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use hash_attestation::Attestor;
use serde_json::{json, Value};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(common::create_unique_temp_dir("aero-cli-test"))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn cli_analyze_sign_verify_and_failure_exit_are_observable() {
    let scratch = Scratch::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/synthetic");
    let fixture = root.join("manifest.json");
    let report = scratch.0.join("report.json");
    let signature = scratch.0.join("report.sig.json");
    let binary = env!("CARGO_BIN_EXE_aero-dataset-provenance");
    let status = Command::new(binary)
        .args(["analyze"])
        .arg(&fixture)
        .arg(&root)
        .arg(&report)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(0));
    let parsed: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(parsed["declared_checks_passed"], true);
    assert_eq!(parsed["report_version"], REPORT_VERSION);

    let key = SigningKey::from_bytes(&[7u8; 32]); // generated in memory for this synthetic test
    let url = "https://example.invalid/keys/synthetic";
    let signed = Command::new(binary)
        .args(["sign"])
        .arg(&report)
        .arg(url)
        .arg(&signature)
        .env("AERO_DATASET_SIGNING_KEY_B64", B64.encode(key.to_bytes()))
        .status()
        .unwrap();
    assert_eq!(signed.code(), Some(0));
    let verified = Command::new(binary)
        .args(["verify"])
        .arg(&report)
        .arg(&signature)
        .arg(url)
        .env(
            "AERO_DATASET_VERIFYING_KEY_B64",
            B64.encode(key.verifying_key().to_bytes()),
        )
        .output()
        .unwrap();
    assert_eq!(verified.status.code(), Some(0));
    let verification_output = String::from_utf8(verified.stdout).unwrap();
    assert!(verification_output.contains("report_version=0.2.0"));
    assert!(verification_output.contains("distinct_odd_count_profile=true"));
    assert!(verification_output.contains("key_identity_verified=false"));

    let legacy_report = scratch.0.join("legacy-report.json");
    let legacy_signature = scratch.0.join("legacy-report.sig.json");
    let mut legacy = parsed.clone();
    legacy["report_version"] = json!("0.1.0");
    let raw_legacy = legacy.to_string();
    fs::write(&legacy_report, &raw_legacy).unwrap();
    let detached = Attestor::new(SigningKey::from_bytes(&[7u8; 32]), url.into())
        .sign_raw_json(&raw_legacy)
        .unwrap();
    fs::write(&legacy_signature, serde_json::to_vec(&detached).unwrap()).unwrap();
    let legacy_verified = Command::new(binary)
        .args(["verify"])
        .arg(&legacy_report)
        .arg(&legacy_signature)
        .arg(url)
        .env(
            "AERO_DATASET_VERIFYING_KEY_B64",
            B64.encode(key.verifying_key().to_bytes()),
        )
        .output()
        .unwrap();
    assert_eq!(legacy_verified.status.code(), Some(0));
    let legacy_output = String::from_utf8(legacy_verified.stdout).unwrap();
    assert!(legacy_output.contains("report_version=0.1.0"));
    assert!(legacy_output.contains("distinct_odd_count_profile=false"));

    let mut bad_manifest: Value = serde_json::from_slice(&fs::read(fixture).unwrap()).unwrap();
    bad_manifest["samples"][2]["group_id"] = json!("synthetic-unit-1");
    let bad_manifest_path = scratch.0.join("bad-manifest.json");
    let bad_report = scratch.0.join("bad-report.json");
    fs::write(
        &bad_manifest_path,
        serde_json::to_vec(&bad_manifest).unwrap(),
    )
    .unwrap();
    let failed = Command::new(binary)
        .args(["analyze"])
        .arg(&bad_manifest_path)
        .arg(&root)
        .arg(&bad_report)
        .status()
        .unwrap();
    assert_eq!(failed.code(), Some(2));
    let parsed: Value = serde_json::from_slice(&fs::read(&bad_report).unwrap()).unwrap();
    assert_eq!(parsed["declared_checks_passed"], false);
    assert!(!parsed["leakage_findings"].as_array().unwrap().is_empty());
}

#[test]
fn cli_rejects_oversized_manifest_report_and_signature_without_writing_outputs() {
    let scratch = Scratch::new();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/synthetic");
    let fixture = root.join("manifest.json");
    let binary = env!("CARGO_BIN_EXE_aero-dataset-provenance");
    let oversized = scratch.0.join("oversized.json");
    fs::write(&oversized, vec![b' '; MAX_MANIFEST_BYTES + 1]).unwrap();

    let blocked_report = scratch.0.join("blocked-report.json");
    let analyze = Command::new(binary)
        .arg("analyze")
        .arg(&oversized)
        .arg(&root)
        .arg(&blocked_report)
        .output()
        .unwrap();
    assert_eq!(analyze.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&analyze.stderr).contains("input exceeds 8388608 bytes"));
    assert!(!blocked_report.exists());

    let blocked_signature = scratch.0.join("blocked-signature.json");
    let sign = Command::new(binary)
        .arg("sign")
        .arg(&oversized)
        .arg("https://example.invalid/key")
        .arg(&blocked_signature)
        .output()
        .unwrap();
    assert_eq!(sign.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&sign.stderr).contains("input exceeds 8388608 bytes"));
    assert!(!blocked_signature.exists());

    let report = scratch.0.join("valid-report.json");
    assert!(Command::new(binary)
        .arg("analyze")
        .arg(&fixture)
        .arg(&root)
        .arg(&report)
        .status()
        .unwrap()
        .success());
    let oversized_signature = scratch.0.join("oversized-signature.json");
    fs::write(&oversized_signature, vec![b' '; 64 * 1024 + 1]).unwrap();
    let verify = Command::new(binary)
        .arg("verify")
        .arg(&report)
        .arg(&oversized_signature)
        .arg("https://example.invalid/key")
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&verify.stderr).contains("input exceeds 65536 bytes"));
}
