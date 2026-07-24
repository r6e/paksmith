//! Shared constants + helpers for the CLI integration test binaries.
//!
//! Rust compiles each `tests/*.rs` file into its own binary, so values
//! needed by more than one live here and are pulled in via `mod common;`.
//! The `common/mod.rs` form keeps it from being treated as a standalone
//! test binary. Items are `#[allow(dead_code)]` because each binary
//! compiles this module independently and none uses every item.

/// AES-256 key (64 hex chars) for the vendored `real_v8b_encrypted_*.pak`
/// fixtures. Must match `FIXTURE_AES_KEY` in
/// `paksmith-fixture-gen/src/encryption.rs`; if the vendored fixtures are
/// ever replaced, update both.
#[allow(dead_code)]
pub const FIXTURE_AES_KEY_HEX: &str =
    "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

/// Repo-root `tests/fixtures/<name>` (two parents up from the crate
/// manifest).
#[allow(dead_code)]
pub fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

/// Seed `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml` with a `hero`
/// profile whose mappings source is `usmap_path` (#651 tests).
#[allow(
    dead_code,
    clippy::unnecessary_debug_formatting,
    reason = "Debug formatting of the path IS the TOML string encoding: it \
              quotes and backslash-escapes (Windows paths) exactly as a TOML \
              basic string requires; .display() would emit invalid TOML"
)]
pub fn seed_hero_profile(config_dir: &std::path::Path, usmap_path: &std::path::Path) {
    let dir = config_dir.join("paksmith");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profiles.toml"),
        format!("[profiles.hero]\nname = \"Hero\"\nmappings = {{ path = {usmap_path:?} }}\n"),
    )
    .unwrap();
}
