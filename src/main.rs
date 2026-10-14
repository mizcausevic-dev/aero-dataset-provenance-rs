use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use aero_dataset_provenance::{
    analyze, sign_report, verify_report, Report, MAX_MANIFEST_BYTES, REPORT_VERSION,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hash_attestation::Attestation;

fn read_bounded(path: &str, limit: usize) -> Result<String, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(format!("input exceeds {limit} bytes: {path}").into());
    }
    Ok(String::from_utf8(bytes)?)
}

fn write_new(path: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn key_from_env(name: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let encoded = env::var(name).map_err(|_| format!("{name} is required"))?;
    let bytes = B64.decode(encoded.trim())?;
    bytes
        .try_into()
        .map_err(|_| format!("{name} must decode to 32 bytes").into())
}

fn usage() -> &'static str {
    "Usage:\n  aero-dataset-provenance analyze MANIFEST.json DATASET_ROOT REPORT.json\n  aero-dataset-provenance sign REPORT.json EXPECTED_KEY_URL REPORT.sig.json\n  aero-dataset-provenance verify REPORT.json REPORT.sig.json EXPECTED_KEY_URL\n\nSign reads AERO_DATASET_SIGNING_KEY_B64 (base64 Ed25519 32-byte seed).\nVerify reads AERO_DATASET_VERIFYING_KEY_B64 (base64 Ed25519 32-byte public key).\nProvision keys through a trusted secret mechanism; the tool never generates or prints them.\nOutput paths must not already exist. analyze exits 2 after writing a report with failed declared checks.\n"
}

fn run() -> Result<i32, Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprint!("{}", usage());
        return Ok(64);
    }
    match args[1].as_str() {
        "analyze" => {
            let raw = read_bounded(&args[2], MAX_MANIFEST_BYTES)?;
            let report = analyze(&raw, Path::new(&args[3]))?;
            let bytes = serde_json::to_vec_pretty(&report)?;
            write_new(&args[4], &bytes)?;
            println!("report written: {}", args[4]);
            if report.declared_checks_passed {
                Ok(0)
            } else {
                eprintln!("declared checks failed; inspect report");
                Ok(2)
            }
        }
        "sign" => {
            let raw = read_bounded(&args[2], MAX_MANIFEST_BYTES)?;
            let seed = key_from_env("AERO_DATASET_SIGNING_KEY_B64")?;
            let signature = sign_report(&raw, SigningKey::from_bytes(&seed), &args[3])?;
            write_new(&args[4], &serde_json::to_vec_pretty(&signature)?)?;
            println!("detached attestation written: {}", args[4]);
            Ok(0)
        }
        "verify" => {
            let raw = read_bounded(&args[2], MAX_MANIFEST_BYTES)?;
            let signature_raw = read_bounded(&args[3], 64 * 1024)?;
            let attestation: Attestation = serde_json::from_str(&signature_raw)?;
            let public_bytes = key_from_env("AERO_DATASET_VERIFYING_KEY_B64")?;
            let public_key = VerifyingKey::from_bytes(&public_bytes)?;
            verify_report(&raw, &attestation, &args[4], public_key)?;
            let report: Report = serde_json::from_str(&raw)?;
            let version = report.report_version;
            println!(
                "signature_valid=true; report_version={version}; distinct_odd_count_profile={}; key_identity_verified=false; certification_verified=false",
                version == REPORT_VERSION
            );
            Ok(0)
        }
        _ => {
            eprint!("{}", usage());
            Ok(64)
        }
    }
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
