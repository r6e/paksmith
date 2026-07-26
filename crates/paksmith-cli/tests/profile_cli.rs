//! Integration tests for the `profile` subcommand.
#![allow(missing_docs)]

use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;

fn paksmith(config_dir: &std::path::Path) -> Command {
    let mut c = Command::cargo_bin("paksmith").unwrap();
    let _ = c.env("PAKSMITH_CONFIG_DIR", config_dir);
    c
}

/// Deterministic test keypair (seed `[7u8; 32]`) + its verifying key as lowercase
/// hex. Shared by every signed-registry test so the seed/fold isn't duplicated.
fn test_keypair() -> (SigningKey, String) {
    use std::fmt::Write as _;
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = sk
        .verifying_key()
        .as_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            write!(s, "{b:02x}").expect("write to String is infallible");
            s
        });
    (sk, pk)
}

#[test]
fn add_with_pak_paths_shows_patterns() {
    // #655: `profile add --pak-path <glob>` (repeatable) persists the
    // patterns in order and `profile show` renders them unredacted
    // (not key material — mappings precedent).
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "add",
            "hero",
            "--name",
            "Hero",
            "--pak-path",
            "/games/hero/Paks/*.pak",
            "--pak-path",
            "Content/Paks/patch/*.pak",
        ])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "show", "hero"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("pak_paths:") && stdout.contains("/games/hero/Paks/*.pak"),
        "show must render the patterns: {stdout}"
    );
    let first = stdout.find("/games/hero/Paks/*.pak").unwrap();
    let second = stdout.find("Content/Paks/patch/*.pak").unwrap();
    assert!(first < second, "patterns render in stored order: {stdout}");
}

#[test]
fn add_rejects_invalid_pak_path_glob() {
    // Validation at store time (defense in depth): a syntactically
    // invalid glob never reaches profiles.toml.
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args([
            "profile",
            "add",
            "hero",
            "--name",
            "Hero",
            "--pak-path",
            "/x/[",
        ])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("not a valid glob"),
        "the rejection names the defect: {stderr}"
    );
    // And nothing was stored: the id is free for a valid retry.
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero"])
        .assert()
        .success();
}

#[test]
fn add_rejects_empty_pak_path() {
    // `glob` compiles "" without complaint, so empty needs its own
    // store-time rejection.
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero", "--pak-path", ""])
        .assert()
        .failure()
        .code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("empty pattern"),
        "the rejection names the defect: {stderr}"
    );
}

#[test]
fn show_without_pak_paths_renders_dash() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "plain", "--name", "Plain"])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "show", "plain"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("pak_paths: -"),
        "absent patterns render as a dash: {stdout}"
    );
}

#[test]
fn add_with_mappings_shows_source_path() {
    // #651: `profile add --mappings <path>` persists the source and
    // `profile show` renders it unredacted (it is not key material).
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "add",
            "hero",
            "--name",
            "Hero",
            "--mappings",
            "/maps/hero.usmap",
        ])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "show", "hero"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("mappings: /maps/hero.usmap"),
        "show must render the mappings path: {stdout}"
    );
}

#[test]
fn show_without_mappings_renders_dash() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "plain", "--name", "P"])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "show", "plain"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("mappings: -"),
        "show must render a dash for absent mappings: {stdout}"
    );
}

#[test]
fn add_list_show_remove_roundtrip() {
    let cfg = tempdir().unwrap();
    // add
    let _add = paksmith(cfg.path())
        .args([
            "profile",
            "add",
            "fortnite",
            "--name",
            "Fortnite",
            "--engine-version",
            "5.3",
        ])
        .assert()
        .success();
    // list shows it
    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("fortnite"), "list shows the id: {txt}");
    assert!(txt.contains("Fortnite"), "list shows the name: {txt}");
    // show
    let shown = paksmith(cfg.path())
        .args(["profile", "show", "fortnite"])
        .assert()
        .success();
    let stxt = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    assert!(stxt.contains("5.3"), "show includes engine version: {stxt}");
    // remove
    let _remove = paksmith(cfg.path())
        .args(["profile", "remove", "fortnite"])
        .assert()
        .success();
    let out2 = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt2 = String::from_utf8(out2.get_output().stdout.clone()).unwrap();
    assert!(
        !txt2.contains("fortnite"),
        "removed profile is gone: {txt2}"
    );
}

#[test]
fn show_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "show", "nope"])
        .assert()
        .code(2);
}

#[test]
fn add_duplicate_id_is_rejected() {
    let cfg = tempdir().unwrap();
    let _add1 = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _add2 = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G2"])
        .assert()
        .code(2);
}

#[test]
fn remove_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "remove", "nope"])
        .assert()
        .code(2);
}

#[test]
fn show_redacts_keys_by_default() {
    let cfg = tempdir().unwrap();
    let _add = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Verify show on a no-key profile succeeds and contains a "keys:" section.
    let out = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains("keys:"),
        "show output contains keys section: {txt}"
    );
    // No raw 64-hex key material should appear.
    assert!(
        !txt.contains(&"a".repeat(64)),
        "show must not expose raw key hex by default: {txt}"
    );
}

#[test]
fn list_empty_is_success() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
}

const KEY: &str = "94d25bc3aeb420e0be914edc9d5435a1eaab5f2864e09e94019ac205b727a7de";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn key_add_then_show_redacts_then_reveals() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // show redacts by default
    let red = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let rtxt = String::from_utf8(red.get_output().stdout.clone()).unwrap();
    assert!(rtxt.contains("<redacted>"), "default show redacts: {rtxt}");
    assert!(
        !rtxt.contains(KEY),
        "default show must not leak the key: {rtxt}"
    );
    // --show-keys reveals
    let rev = paksmith(cfg.path())
        .args(["profile", "show", "g", "--show-keys"])
        .assert()
        .success();
    let vtxt = String::from_utf8(rev.get_output().stdout.clone()).unwrap();
    assert!(vtxt.contains(KEY), "--show-keys reveals: {vtxt}");
}

#[test]
fn profile_test_reports_verified_for_correct_key() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.to_lowercase().contains("verified"),
        "correct key reports verified: {txt}"
    );
}

#[test]
fn key_add_bad_hex_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", "nothex"])
        .assert()
        .code(2);
}

// ── key remove ────────────────────────────────────────────────────────────────

#[test]
fn key_remove_happy_path() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // remove by zero guid (32 zeros)
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "g",
            "--guid",
            "00000000000000000000000000000000",
        ])
        .assert()
        .success();
    // show must no longer contain the key material or <redacted>
    let out = paksmith(cfg.path())
        .args(["profile", "show", "g"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !txt.contains("<redacted>"),
        "after remove, no redacted entry expected: {txt}"
    );
    assert!(!txt.contains(KEY), "after remove, key must be gone: {txt}");
}

#[test]
fn key_remove_missing_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // profile has no keys; attempt to remove a non-existent GUID → NoKeyForGuid → exit 2
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "g",
            "--guid",
            "deadbeefdeadbeefdeadbeefdeadbeef",
        ])
        .assert()
        .code(2);
}

#[test]
fn key_remove_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    // no profiles at all — ProfileNotFound → exit 2
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "remove",
            "nope",
            "--guid",
            "00000000000000000000000000000000",
        ])
        .assert()
        .code(2);
}

// ── profile test negative paths ───────────────────────────────────────────────

#[test]
fn profile_test_wrong_key_exits_1() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // 64 hex zeros = a valid AES key that is NOT the correct key for the fixture
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(1);
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.to_lowercase().contains("wrong key"),
        "wrong-key failure must mention 'wrong key': {txt}"
    );
}

#[test]
fn profile_test_no_key_for_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Add the correct key but under a NON-zero GUID only — no zero-default entry.
    // The fixture's GUID is all-zero, so resolve_key will find no entry → NoKeyForGuid → exit 2.
    let _ = paksmith(cfg.path())
        .args([
            "profile",
            "key",
            "add",
            "g",
            "--key",
            KEY,
            "--guid",
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
        ])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

// ── --game global flag ────────────────────────────────────────────────────────

#[test]
fn game_flag_opens_encrypted_pak_via_profile() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // --game resolves the key and `list` succeeds on the encrypted-index fixture
    let out = paksmith(cfg.path())
        .args(["--game", "g", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains("test.txt"),
        "encrypted entries listed via --game: {txt}"
    );
}

#[test]
fn game_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["--game", "nope", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

#[test]
fn aes_key_overrides_game() {
    let cfg = tempdir().unwrap();
    // profile `g` has the WRONG key; --aes-key supplies the RIGHT one and wins.
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args(["--game", "g", "--aes-key", KEY, "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
}

// ── key add --guid bad-hex ────────────────────────────────────────────────────

#[test]
fn key_add_bad_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith(cfg.path())
        .args([
            "profile", "key", "add", "g", "--key", KEY, "--guid", "nothex",
        ])
        .assert()
        .code(2);
}

// ── profile fetch ──────────────────────────────────────────────────────────────

/// Spin up a wiremock server, write a config.toml pointing at it, and confirm
/// `paksmith profile fetch` succeeds and produces a cache file.
///
/// `PAKSMITH_ALLOW_HTTP=1` activates the test/dev env gate in `RegistryClient::fetch`
/// that bypasses the https-only guard — see `registry.rs` for the security note.
/// The subprocess carries the env var; no in-process env mutation is performed.
#[tokio::test]
async fn profile_fetch_caches_signed_registry() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cfg = tempdir().unwrap();
    let (sk, pk) = test_keypair();
    let body = r#"[{"id":"g","name":"G","keys":{}}]"#;
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wpath("/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wpath("/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
        .mount(&server)
        .await;

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("config.toml"),
        format!(
            "[registry]\nurl = \"{}/r.json\"\npublic_key = \"{pk}\"\n",
            server.uri()
        ),
    )
    .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let _ = cmd
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch"])
        .assert()
        .success();

    assert!(
        base.join("registry-cache.json").exists(),
        "cache file must exist after a successful fetch"
    );
}

// ── --game auto-fetch + offline degradation ───────────────────────────────────

/// `--game` with an id that has no local profile and no cache triggers an
/// auto-fetch of the registry. On success the resolved profile's default key
/// decrypts the v8b encrypted-index fixture and `list` outputs `test.txt`.
#[tokio::test]
async fn game_auto_fetches_registry_only_profile() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cfg = tempfile::tempdir().unwrap();
    let (sk, pk) = test_keypair();
    // Registry profile whose zero-GUID default key decrypts the v8b fixture.
    let body = format!(
        r#"[{{"id":"reg","name":"R","keys":{{"00000000000000000000000000000000":"{KEY}"}}}}]"#
    );
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wpath("/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wpath("/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
        .mount(&server)
        .await;

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("config.toml"),
        format!(
            "[registry]\nurl=\"{}/r.json\"\npublic_key=\"{pk}\"\n",
            server.uri()
        ),
    )
    .unwrap();

    // No local profile, no cache. Auto-fetch fires and resolves the key.
    let out = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["--game", "reg", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    assert!(
        String::from_utf8(out.get_output().stdout.clone())
            .unwrap()
            .contains("test.txt"),
        "encrypted entries listed via auto-fetched registry profile"
    );
}

/// Offline degradation: a stale cache entry is used (with a warn) when the
/// configured registry URL is unreachable. The command succeeds — ProfileNotFound
/// must NOT be returned when a stale cache resolves the id.
///
/// The "dead URL" technique: point config at `http://...` but leave
/// `PAKSMITH_ALLOW_HTTP` unset so the InsecureUrl error fires without any network
/// I/O — identical degradation branch to a real connection failure.
#[test]
fn game_offline_degrades_to_stale_cache() {
    let cfg = tempfile::tempdir().unwrap();
    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();

    // Stale config: http:// URL + matching signing key (arbitrary; ALLOW_HTTP not set
    // so we never reach the network — InsecureUrl Err fires immediately).
    let (_sk, pk) = test_keypair();
    std::fs::write(
        base.join("config.toml"),
        format!("[registry]\nurl=\"http://127.0.0.1:1/dead.json\"\npublic_key=\"{pk}\"\n"),
    )
    .unwrap();

    // Pre-seed a stale cache (fetched_at_unix=1 → >24h old by any real clock).
    let body = format!(
        r#"[{{"id":"reg","name":"R","keys":{{"00000000000000000000000000000000":"{KEY}"}}}}]"#
    );
    let cache_json = format!(
        r#"{{"fetched_at_unix":1,"profiles":[{{"id":"reg","name":"R","keys":{{"00000000000000000000000000000000":"{KEY}"}}}}]}}"#
    );
    let _ = body; // keep for clarity
    std::fs::write(base.join("registry-cache.json"), cache_json).unwrap();

    // PAKSMITH_ALLOW_HTTP is NOT set → InsecureUrl fires (no network) → warn + stale fallback.
    let out = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .args(["--game", "reg", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    // The stale cache resolved the key; the pak's test.txt entry is listed.
    assert!(
        String::from_utf8(out.get_output().stdout.clone())
            .unwrap()
            .contains("test.txt"),
        "stale-cache offline fallback must decrypt and list entries"
    );
    // The warn must appear on stderr (tracing subscriber defaults to WARN).
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("registry fetch failed"),
        "offline degradation must emit a WARN on stderr: {stderr}"
    );
}

/// `profile list` includes cached registry profiles tagged `[registry]` alongside
/// local ones tagged `[local]`. When the same id appears locally and in the cache,
/// only the local entry (tagged `[local]`) is shown.
#[test]
fn profile_list_shows_cached_registry_profiles() {
    let cfg = tempfile::tempdir().unwrap();
    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();

    // One local profile.
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "local-game", "--name", "Local"])
        .assert()
        .success();

    // Pre-seed a cache with two entries: one unique registry-only, one shadowed by local.
    // We use a fake (non-matching) local profile id for the shadowed entry.
    let cache_json = format!(
        r#"{{"fetched_at_unix":9999999999,"profiles":[{{"id":"reg-only","name":"RegOnly","keys":{{"00000000000000000000000000000000":"{KEY}"}}}},{{"id":"local-game","name":"Shadowed","keys":{{}}}}]}}"#
    );
    std::fs::write(base.join("registry-cache.json"), cache_json).unwrap();

    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // Local appears with [local] tag.
    assert!(
        txt.contains("[local]") && txt.contains("local-game"),
        "list must show local profile with [local] tag: {txt}"
    );
    // Registry-only entry appears with [registry] tag.
    assert!(
        txt.contains("[registry]") && txt.contains("reg-only"),
        "list must show registry-only profile with [registry] tag: {txt}"
    );
    // Shadowed entry: only [local] version shown, not [registry] duplicate.
    assert!(
        !txt.contains("Shadowed"),
        "shadowed registry entry (same id as local) must not appear: {txt}"
    );
}

/// A corrupt `registry-cache.json` must not prevent `profile list` from printing
/// local profiles — `list` must degrade to "no cached section" + warn, not fail.
#[test]
fn list_degrades_on_corrupt_cache() {
    let cfg = tempfile::tempdir().unwrap();
    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();

    // Create a local profile so we have something to confirm in the output.
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "my-local", "--name", "MyLocal"])
        .assert()
        .success();

    // Write a deliberately corrupt cache file (not valid JSON).
    std::fs::write(base.join("registry-cache.json"), b"not json {{{").unwrap();

    // `profile list` must succeed and still show the local profile.
    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        stdout.contains("my-local"),
        "local profile must appear even when registry cache is corrupt: {stdout}"
    );
}

/// `profile list` with no profiles and no cache prints "no profiles".
/// Pins the `if !any` guard so deleting `!` (printing on non-empty) is caught.
#[test]
fn list_empty_prints_no_profiles_message() {
    let cfg = tempdir().unwrap();
    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains("no profiles"),
        "empty list must print 'no profiles': {txt}"
    );
}

/// `profile list` with a local profile must NOT print "no profiles".
/// Pins the `if !any` guard from the other direction: profile present → suppress.
#[test]
fn list_non_empty_suppresses_no_profiles_message() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let out = paksmith(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !txt.contains("no profiles"),
        "non-empty list must NOT print 'no profiles': {txt}"
    );
}

/// `profile fetch --force` re-fetches even when the cache is still fresh.
/// Pins the `!a.force` guard: without `!`, force=false would skip instead of
/// force=true, which should never skip.
#[tokio::test]
async fn profile_fetch_force_ignores_fresh_cache() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cfg = tempdir().unwrap();
    let (sk, pk) = test_keypair();
    let body = r#"[{"id":"g","name":"G","keys":{}}]"#;
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wpath("/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wpath("/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
        .mount(&server)
        .await;

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("config.toml"),
        format!(
            "[registry]\nurl = \"{}/r.json\"\npublic_key = \"{pk}\"\n",
            server.uri()
        ),
    )
    .unwrap();

    // First fetch — populates a fresh cache (fetched_at_unix = now).
    let _ = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch"])
        .assert()
        .success();

    // Second fetch WITHOUT --force on a fresh cache should print "fresh" and skip.
    let skip_out = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch"])
        .assert()
        .success();
    let skip_txt = String::from_utf8(skip_out.get_output().stdout.clone()).unwrap();
    assert!(
        skip_txt.contains("fresh"),
        "without --force, a fresh cache must be reported as fresh and skipped: {skip_txt}"
    );

    // Third fetch WITH --force should re-fetch (not skip) and print profile count.
    let force_out = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch", "--force"])
        .assert()
        .success();
    let force_txt = String::from_utf8(force_out.get_output().stdout.clone()).unwrap();
    assert!(
        force_txt.contains("fetched"),
        "--force must always re-fetch even on a fresh cache: {force_txt}"
    );
    // Also pins the staleness check: the fresh-cache early-return message must NOT appear.
    assert!(
        !force_txt.contains("fresh"),
        "--force must bypass the fresh-cache check: {force_txt}"
    );
}

/// Security invariant: `PAKSMITH_ALLOW_HTTP` relaxes ONLY the transport (https)
/// gate — it must NOT bypass ed25519 signature verification. With the env set
/// and a TAMPERED `.sig` (signature over different bytes), `profile fetch` must
/// still FAIL and write no cache. Pins verify-safety against future refactors.
#[tokio::test]
async fn profile_fetch_allow_http_still_verifies_signature() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cfg = tempdir().unwrap();
    let (sk, pk) = test_keypair();
    let body = r#"[{"id":"g","name":"G","keys":{}}]"#;
    // Sign DIFFERENT bytes → the .sig does not match `body`.
    let bad_sig = sk.sign(b"not the body").to_bytes().to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wpath("/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wpath("/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bad_sig))
        .mount(&server)
        .await;

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("config.toml"),
        format!(
            "[registry]\nurl = \"{}/r.json\"\npublic_key = \"{pk}\"\n",
            server.uri()
        ),
    )
    .unwrap();

    let mut cmd = assert_cmd::Command::cargo_bin("paksmith").unwrap();
    let _ = cmd
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["profile", "fetch"])
        .assert()
        .failure();

    assert!(
        !base.join("registry-cache.json").exists(),
        "no cache may be written when signature verification fails"
    );
}

// ---------------------------------------------------------------------------
// Issue #658 item 1: `profile show` / `profile test` resolve LAYERED, so a
// cached registry profile can be inspected and key-tested. `profile list`
// already did this (`profile_list_shows_cached_registry_profiles`); these two
// were local-store-only, so a registry-supplied game could be auto-detected
// and used for extraction yet could not be shown or diagnosed.
// ---------------------------------------------------------------------------

/// Seed a registry cache holding one profile with the encrypted fixture's key.
fn seed_registry_cache(config_dir: &std::path::Path, id: &str, name: &str) {
    let base = config_dir.join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    let cache_json = format!(
        r#"{{"fetched_at_unix":9999999999,"profiles":[{{"id":"{id}","name":"{name}","engine_version":"5.3","keys":{{"00000000000000000000000000000000":"{KEY}"}}}}]}}"#
    );
    std::fs::write(base.join("registry-cache.json"), cache_json).unwrap();
}

/// `profile show` resolves a registry-cached id and reports its provenance.
#[test]
fn show_resolves_cached_registry_profile() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let out = paksmith(cfg.path())
        .args(["profile", "show", "reg-only"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();

    assert!(txt.contains("reg-only"), "id must appear: {txt}");
    assert!(txt.contains("RegOnly"), "name must appear: {txt}");
    assert!(
        txt.contains("5.3"),
        "the registry profile's engine_version must appear: {txt}"
    );
    // The FULL line, not the bare word: `contains("registry")` passes on any
    // incidental mention and would survive deleting the line outright.
    assert!(
        txt.contains("source: registry"),
        "provenance must be stated so a user knows why it is not editable: {txt}"
    );
}

/// Keys stay redacted for registry profiles too — the reveal is `--show-keys`
/// only, exactly as for local ones.
#[test]
fn show_registry_profile_redacts_keys_by_default() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let out = paksmith(cfg.path())
        .args(["profile", "show", "reg-only"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        !txt.contains(KEY),
        "registry key material must not leak without --show-keys: {txt}"
    );
    assert!(
        txt.contains("<redacted>"),
        "redaction marker expected: {txt}"
    );

    let out = paksmith(cfg.path())
        .args(["profile", "show", "reg-only", "--show-keys"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        txt.contains(KEY),
        "--show-keys must reveal registry keys as it does local ones: {txt}"
    );
}

/// A local profile shadows a cached registry entry with the same id — the same
/// precedence `resolve_profile_layered` applies everywhere else.
#[test]
fn show_local_shadows_cached_registry_entry() {
    let cfg = tempdir().unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "dual", "--name", "LocalWins"])
        .assert()
        .success();
    seed_registry_cache(cfg.path(), "dual", "RegistryLoses");

    let out = paksmith(cfg.path())
        .args(["profile", "show", "dual"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("LocalWins"), "local must win: {txt}");
    // Pins the OTHER arm's literal. Without this, swapping the two source
    // strings passes the whole suite — and the only mutants CI generates here
    // are whole-body `Ok(0)`/`Ok(1)` replacements, which never perturb them.
    assert!(
        txt.contains("source: local"),
        "a local profile must report local provenance: {txt}"
    );
    assert!(
        !txt.contains("RegistryLoses"),
        "shadowed registry entry must not be shown: {txt}"
    );
}

/// An id in neither the store nor the cache is still `ProfileNotFound` (exit 2)
/// — layering must not soften the unknown-id contract.
#[test]
fn show_unknown_id_still_not_found_with_a_cache_present() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let _ = paksmith(cfg.path())
        .args(["profile", "show", "absent"])
        .assert()
        .code(2);
}

/// `profile test` key-tests a registry-cached profile against a real encrypted
/// pak — the diagnostic that tells a user whether a registry-shipped key works.
#[test]
fn test_resolves_cached_registry_profile() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let out = paksmith(cfg.path())
        .args(["profile", "test", "reg-only"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    // Unhedged on purpose: this fixture + key deterministically yields
    // `Verified` (see `profile_test_reports_verified_for_correct_key`), and
    // `KeyTestOutcome::Decrypted` is the documented WEAKER outcome — a zeroed
    // hash slot can be forced by a downgrade attack. Accepting either would let
    // a Verified→Decrypted regression pass, and `.success()` above already
    // covers "one of the two".
    assert!(
        txt.contains("verified"),
        "the registry-supplied key must VERIFY, not merely decrypt: {txt}"
    );
}

/// `profile test` on an id present nowhere stays `ProfileNotFound` (exit 2),
/// distinct from the exit-1 "key didn't work" outcome.
#[test]
fn test_unknown_id_still_not_found_with_a_cache_present() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let _ = paksmith(cfg.path())
        .args(["profile", "test", "absent"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

/// A corrupt cache must not make a LOCAL profile unshowable. `show` and `test`
/// now depend on `load_cache_lenient`'s degradation, which only `list` covered
/// (`list_degrades_on_corrupt_cache`) — swapping it for a hard `load()?` would
/// turn a corrupt cache into exit 2 for local ids and nothing would catch it.
#[test]
fn show_and_test_degrade_on_corrupt_cache_for_a_local_id() {
    let cfg = tempdir().unwrap();
    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    let _ = paksmith(cfg.path())
        .args(["profile", "add", "mine", "--name", "Mine"])
        .assert()
        .success();
    std::fs::write(base.join("registry-cache.json"), b"not json {{{").unwrap();

    let out = paksmith(cfg.path())
        .args(["profile", "show", "mine"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("source: local"), "{txt}");

    // `test` reaches the same degradation before touching the pak.
    let _ = paksmith(cfg.path())
        .args(["profile", "test", "mine"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2); // no key for the GUID — resolution itself succeeded
}

/// The mutating commands are read-only w.r.t. registry profiles, and say so
/// instead of claiming the profile does not exist (#658). Exit code stays 2;
/// only the wording gained the remediation hint.
#[test]
fn mutating_commands_hint_that_registry_profiles_are_read_only() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    for args in [
        vec!["profile", "remove", "reg-only"],
        vec![
            "profile",
            "key",
            "remove",
            "reg-only",
            "--guid",
            &"00".repeat(16),
        ],
    ] {
        let out = paksmith(cfg.path()).args(&args).assert().code(2);
        let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
        assert!(
            err.contains("registry profile") && err.contains("read-only"),
            "{args:?} must explain the id is a read-only registry profile: {err}"
        );
    }

    // An id in NEITHER layer gets no such hint — the plain not-found stands.
    let out = paksmith(cfg.path())
        .args(["profile", "remove", "nowhere"])
        .assert()
        .code(2);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("read-only"),
        "an absent id must not be described as a registry profile: {err}"
    );
}
