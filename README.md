# Aero Dataset Provenance (draft v0.1)

An offline Rust CLI that hashes a declared dataset snapshot, checks exact-file and acquisition-group leakage across train/validation/test splits, tests a declared UTC split boundary, and counts evaluation samples against declared operational design domain (ODD) bins. It emits deterministic JSON that can be signed with the published [`hash-attestation` v0.2](https://crates.io/crates/hash-attestation) format.

**Status:** draft engineering aid. A passing report is not proof of dataset origin, usage rights, label quality, representative coverage, aviation certification, or airworthiness approval. The tool does not inspect model behavior. All included data are synthetic text fixtures, not aircraft records.

## Run the synthetic fixture

```powershell
cd C:\Users\chaus\Documents\Codex\repos\aero-dataset-provenance-rs
$root = (Get-Location).Path + '\examples\synthetic'
cargo run --locked -- analyze examples\synthetic\manifest.json $root .\synthetic-report.json
```

`analyze` writes a new report file and exits `0` when **declared checks** pass. It writes the report and exits `2` when a declared check fails. Invalid input or I/O errors exit `1`; misuse exits `64`. Output paths must not exist, preventing an accidental overwrite.

The [manifest format](docs/MANIFEST.md) contains only relative file paths under an absolute dataset root. Each sample has a stable pseudonymous group ID, split, and ODD observations. The CLI rejects parent traversal, symlinks and Windows reparse points in sample paths; it streams files with a 100 MiB per-file cap. It does not send data to a service. Reports include relative paths and sample IDs, so treat them as potentially sensitive and review before sharing.

## Detached signature

The `sign` and `verify` commands use the actual `hash-attestation` v0.2 RFC 8785/JCS SHA-256 + Ed25519 implementation. Inject `AERO_DATASET_SIGNING_KEY_B64` from your trusted secret mechanism for signing (base64 32-byte Ed25519 seed); inject `AERO_DATASET_VERIFYING_KEY_B64` from an independently trusted source for verification (base64 32-byte public key). The program never generates or prints keys.

```text
aero-dataset-provenance sign REPORT.json https://vendor.example/keys/dataset REPORT.sig.json
aero-dataset-provenance verify REPORT.json REPORT.sig.json https://vendor.example/keys/dataset
```

The key selector must be an absolute HTTPS URL with a host and no userinfo. It is an **expected selector**, not a fetched key or identity proof. The verifier must establish its binding to the vendor outside this tool. The signed report binds report JSON, not current files on disk. A signing timestamp is signer-asserted; no trusted timestamp, revocation, custody, or signer authority is established. Signing a failed report is permitted so a failure can be preserved honestly.

## Check semantics

| Check | What it reports | Important limit |
| --- | --- | --- |
| Byte hashing | SHA-256 of each observed file and RFC 8785 hash of the manifest | No proof of origin or rights; use an immutable snapshot to avoid file-replacement races |
| Exact leakage | Identical file bytes in different splits | Transformations of the same underlying source can evade exact-byte comparison |
| Group leakage | One supplied `group_id` in different splits | Only as complete as the supplied group IDs |
| Temporal boundary | Train captures before, evaluation captures at/after the declared UTC epoch | Not evaluated when no boundary is supplied; capture times are not independently authenticated |
| ODD bins | Evaluation sample counts, threshold gaps, and unknown/missing values | Bin labels are not machine-bound to the aviation card's `odd.operating_conditions`; counts do not prove representativeness, statistical adequacy, or operational safety |

This is a proposed input and report format for a Suite aviation extension. The optional aviation MCP tools can reference its report as evidence, but the current MCP ODD check only checks declared card fields and references; it does not independently rerun this CLI or certify coverage.

## Verify changes

```text
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The repository CI runs these checks plus the positive CLI fixture. Negative fixtures in `tests/analysis.rs` cover exact/group/temporal leakage, ODD gaps, unsafe paths, duplicate JSON keys, report tampering, signed metadata tampering, and invalid or wrong expected key URLs. CLI tests also cover oversized inputs.

See [origin and limits](docs/ORIGIN.md). Licensed MIT.
