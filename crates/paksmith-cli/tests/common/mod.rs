//! Shared constants for the CLI integration test binaries.
//!
//! Rust compiles each `tests/*.rs` file into its own binary, so values
//! needed by more than one (the AES fixture key, used by both
//! `cli_integration.rs` and `extract_cli.rs`) live here and are pulled in
//! via `mod common;`. The `common/mod.rs` form keeps it from being treated
//! as a standalone test binary.

/// AES-256 key (64 hex chars) for the vendored `real_v8b_encrypted_*.pak`
/// fixtures. Must match `FIXTURE_AES_KEY` in
/// `paksmith-fixture-gen/src/encryption.rs`; if the vendored fixtures are
/// ever replaced, update both.
pub const FIXTURE_AES_KEY_HEX: &str =
    "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";
