# Origin, evidence, and limits

This tool and format are original Kinetic Gain draft engineering work. It is designed to support evidence preparation for aviation ML assurance discussions; it is not a reproduction of EASA, FAA, SAE, EUROCAE, RTCA, or NIST text or an implementation of a certification standard. The synthetic fixture contains only invented labels and three short text files.

The aviation regulatory references for the accompanying Suite crosswalk are maintained in `aero-assurance-crosswalk`. Its proposed/draft/voluntary statuses must be read before using the report in an assurance argument. No standards objective text or unpublished standard content is bundled here.

The cryptographic format is provided by [`hash-attestation` 0.2.0](https://crates.io/crates/hash-attestation), pinned in `Cargo.toml` and `Cargo.lock`. That library signs a canonical JSON hash and metadata under a caller-provided Ed25519 key. This repository does not create a signer identity, distribute keys, perform revocation, or guarantee an independent custodian. For a real program, define those controls with the operator and regulator before treating a detached signature as trusted evidence.
