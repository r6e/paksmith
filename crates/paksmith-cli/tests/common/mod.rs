//! Shared constants + helpers for the CLI integration test binaries.
//!
//! Rust compiles each `tests/*.rs` file into its own binary, so values
//! needed by more than one live here and are pulled in via `mod common;`.
//! The `common/mod.rs` form keeps it from being treated as a standalone
//! test binary.
#![allow(
    dead_code,
    reason = "each test binary compiles this module independently and none \
              uses every item"
)]

/// AES-256 key (64 hex chars) for the vendored `real_v8b_encrypted_*.pak`
/// fixtures. Must match `FIXTURE_AES_KEY` in
/// `paksmith-fixture-gen/src/encryption.rs`; if the vendored fixtures are
/// ever replaced, update both.
pub const FIXTURE_AES_KEY_HEX: &str =
    "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

/// Repo-root `tests/fixtures/<name>` (two parents up from the crate
/// manifest).
pub fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

/// Shared writer for the `hero` profile seeders: `extra` is appended
/// verbatim after the `[profiles.hero]` table (pass `""` for none).
#[allow(
    clippy::unnecessary_debug_formatting,
    reason = "Debug formatting of the path IS the TOML string encoding: it \
              quotes and backslash-escapes (Windows paths) exactly as a TOML \
              basic string requires; .display() would emit invalid TOML"
)]
fn write_hero_profile(config_dir: &std::path::Path, usmap_path: &std::path::Path, extra: &str) {
    let dir = config_dir.join("paksmith");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("profiles.toml"),
        format!(
            "[profiles.hero]\nname = \"Hero\"\nmappings = {{ path = {usmap_path:?} }}\n{extra}"
        ),
    )
    .unwrap();
}

/// Seed `$PAKSMITH_CONFIG_DIR/paksmith/profiles.toml` with a `hero`
/// profile whose mappings source is `usmap_path` (#651 tests).
pub fn seed_hero_profile(config_dir: &std::path::Path, usmap_path: &std::path::Path) {
    write_hero_profile(config_dir, usmap_path, "");
}

/// Like [`seed_hero_profile`] but the profile also carries detect rules
/// requiring `Game/Paks` under the scanned directory — for `--detect`
/// selector-attribution tests.
pub fn seed_hero_profile_with_detect(config_dir: &std::path::Path, usmap_path: &std::path::Path) {
    write_hero_profile(
        config_dir,
        usmap_path,
        "\n[profiles.hero.detect]\nrequire_paths = [\"Game/Paks\"]\ncontains = []\n",
    );
}

/// Assert `stdout` is a JSON object whose FIRST key in the raw bytes is
/// `schema_version`, and that `body_key` is present.
///
/// The raw-byte position is the point. `parsed["schema_version"] == 1` passes
/// on any envelope, including one that emits the version LAST — the exact
/// shape the check exists to catch. There is deliberately no separate
/// "schema_version is present" assertion: it is subsumed by the `starts_with`
/// below and so could not fail on its own. The `body_key` lookup is NOT
/// subsumed — it names a different key.
pub fn assert_envelope_first(stdout: &str, body_key: &str, ctx: &str) {
    let _ = stdout
        .find(&format!("\"{body_key}\""))
        .unwrap_or_else(|| panic!("{ctx}: no {body_key} in {stdout}"));
    let after_brace = stdout
        .trim_start()
        .strip_prefix('{')
        .unwrap_or_else(|| panic!("{ctx}: not a JSON object: {stdout}"))
        .trim_start();
    assert!(
        after_brace.starts_with("\"schema_version\""),
        "{ctx}: schema_version must be the FIRST key, got: {stdout}"
    );
}

/// A `paksmith` invocation pinned to TABLE output.
///
/// `profile` honours `--format` since #658, and `--format auto` resolves to
/// JSON whenever stdout is not a TTY — always true under `assert_cmd`. Any
/// test asserting on human output must ask for the table explicitly, as
/// `cli_integration`'s `list ... --format table` already does.
pub fn paksmith_table(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    let _ = c.args(["--format", "table"]);
    c
}

/// A `paksmith` invocation pinned to JSON output (#658).
pub fn paksmith_json(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    let _ = c.args(["--format", "json"]);
    c
}

/// A `paksmith` invocation with NO `--format`, exercising the default
/// resolution.
///
/// For tests whose subject is a CONTAINER command (`--game … list`,
/// `--detect … list`) rather than the `profile` family. Those already honoured
/// `--format` before #658, so off-TTY they have always asserted against the
/// JSON writer; pinning them to the table through a shared helper would be an
/// undeclared coverage shift dressed as consistency.
pub fn paksmith_unpinned(config_dir: &std::path::Path) -> assert_cmd::Command {
    let mut c = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    c
}

/// Write a raw registry-cache document under `config_dir`, with `profiles`
/// spliced in verbatim as the JSON array body.
///
/// Raw on purpose: the duplicate-id and shadowing tests need documents the
/// typed seeders cannot express (repeated ids, per-entry detect rules), and
/// eight call sites — seven tests plus the typed seeder — were hand-rolling
/// this identical create-dir + write.
pub fn seed_registry_cache_json(config_dir: &std::path::Path, profiles: &str) {
    let base = config_dir.join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("registry-cache.json"),
        format!(r#"{{"fetched_at_unix":9999999999,"profiles":[{profiles}]}}"#),
    )
    .unwrap();
}
