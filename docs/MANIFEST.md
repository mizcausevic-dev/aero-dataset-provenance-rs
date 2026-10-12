# Manifest format, v0.1.0

The input is strict UTF-8 JSON. Duplicate keys, unsafe numeric values, unknown fields, and unsupported versions are rejected. File paths are relative to the **absolute** dataset root supplied to `analyze` and must contain only normal path components. A report is deterministic for a stable manifest and byte-for-byte stable dataset snapshot.

| Field | Meaning |
| --- | --- |
| `manifest_version` | Exactly `"0.1.0"` |
| `dataset_id` | Local pseudonymous identifier, not proof of source |
| `odd_bins` | Map of dimension to declared bin names, e.g. `lighting: [day, night]` |
| `minimum_evaluation_samples_per_bin` | Positive engineering threshold chosen by the manifest author, not a regulatory threshold |
| `temporal_train_before_epoch_s` | Optional UTC epoch boundary; train captures before it, validation/test captures at or after it |
| `samples` | 1–10,000 file records with unique `id`, relative `path`, `split`, pseudonymous `group_id`, optional `captured_at_epoch_s`, and `odd_values` |

`split` is one of `train`, `validation`, `test`. When a temporal boundary is declared, every sample needs a capture timestamp; absent or wrong-side timestamps become violations. The ODD count uses validation and test samples only. An absent or unrecognized bin value counts as unknown. An unknown dimension name is an input error. A declared bin with fewer than the author-supplied minimum is a gap; this is **not** a statistically justified coverage test.

The `odd_bins` labels belong to this manifest. This version does not machine-bind a label to an Aviation ML Assurance Card `odd.operating_conditions` entry. A reviewer must establish that mapping before citing the report as coverage evidence for a card condition.

The report has `report_version`, `manifest_jcs_sha256`, per-sample byte hashes, leakage findings, temporal status and violations, ODD bin observations, and `declared_checks_passed`. That boolean means only the checks specified above had no recorded violations. It does not assert adequacy, provenance, regulatory conformance, or safe use.

The current bounds are 8 MiB manifest, 10,000 samples, 100 MiB per file, 32 dimensions, and 128 bins per dimension. Analyze an immutable snapshot under controlled file permissions for release evidence. This v0.1 tool does not harden against a hostile process changing files during the read.
