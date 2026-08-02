//! Integration tests for the `profile` subcommand.
#![allow(missing_docs)]

use assert_cmd::Command;
use ed25519_dalek::{Signer, SigningKey};
use tempfile::tempdir;

mod common;
use common::{
    assert_envelope_first, paksmith_json, paksmith_table, paksmith_unpinned,
    seed_registry_cache_json,
};

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
    let _ = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero"])
        .assert()
        .success();
}

#[test]
fn add_rejects_empty_pak_path() {
    // `glob` compiles "" without complaint, so empty needs its own
    // store-time rejection.
    let cfg = tempdir().unwrap();
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "plain", "--name", "Plain"])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "plain", "--name", "P"])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
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
    let _add = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("fortnite"), "list shows the id: {txt}");
    assert!(txt.contains("Fortnite"), "list shows the name: {txt}");
    // show
    let shown = paksmith_table(cfg.path())
        .args(["profile", "show", "fortnite"])
        .assert()
        .success();
    let stxt = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    assert!(stxt.contains("5.3"), "show includes engine version: {stxt}");
    // remove
    let _remove = paksmith_table(cfg.path())
        .args(["profile", "remove", "fortnite"])
        .assert()
        .success();
    let out2 = paksmith_table(cfg.path())
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
    let _assert = paksmith_table(cfg.path())
        .args(["profile", "show", "nope"])
        .assert()
        .code(2);
}

#[test]
fn add_duplicate_id_is_rejected() {
    let cfg = tempdir().unwrap();
    let _add1 = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _add2 = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G2"])
        .assert()
        .code(2);
}

#[test]
fn remove_unknown_profile_exits_2() {
    let cfg = tempdir().unwrap();
    let _assert = paksmith_table(cfg.path())
        .args(["profile", "remove", "nope"])
        .assert()
        .code(2);
}

#[test]
fn show_redacts_keys_by_default() {
    let cfg = tempdir().unwrap();
    let _add = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Verify show on a no-key profile succeeds and contains a "keys:" section.
    let out = paksmith_table(cfg.path())
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
    let _assert = paksmith_table(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
}

/// The fixture key, by REFERENCE to the shared constant — re-spelling the
/// 64 hex bytes here is how the two drift.
const KEY: &str = common::FIXTURE_AES_KEY_HEX;

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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // show redacts by default
    let red = paksmith_table(cfg.path())
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
    let rev = paksmith_table(cfg.path())
        .args(["profile", "show", "g", "--show-keys"])
        .assert()
        .success();
    let vtxt = String::from_utf8(rev.get_output().stdout.clone()).unwrap();
    assert!(vtxt.contains(KEY), "--show-keys reveals: {vtxt}");
}

#[test]
fn profile_test_reports_verified_for_correct_key() {
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", "nothex"])
        .assert()
        .code(2);
}

// ── key remove ────────────────────────────────────────────────────────────────

#[test]
fn key_remove_happy_path() {
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // add a default (zero-guid) key
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // remove by zero guid (32 zeros)
    let _ = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // profile has no keys; attempt to remove a non-existent GUID → NoKeyForGuid → exit 2
    let _ = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // 64 hex zeros = a valid AES key that is NOT the correct key for the fixture
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    // Add the correct key but under a NON-zero GUID only — no zero-default entry.
    // The fixture's GUID is all-zero, so resolve_key will find no entry → NoKeyForGuid → exit 2.
    let _ = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "test", "g"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

// ── --game global flag ────────────────────────────────────────────────────────

#[test]
fn game_flag_opens_encrypted_pak_via_profile() {
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", KEY])
        .assert()
        .success();
    // --game resolves the key and `list` succeeds on the encrypted-index fixture
    let out = paksmith_unpinned(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["--game", "nope", "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(2);
}

#[test]
fn aes_key_overrides_game() {
    let cfg = tempdir().unwrap();
    // profile `g` has the WRONG key; --aes-key supplies the RIGHT one and wins.
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let _ = paksmith_unpinned(cfg.path())
        .args(["--game", "g", "--aes-key", KEY, "list"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
}

// ── key add --guid bad-hex ────────────────────────────────────────────────────

#[test]
fn key_add_bad_guid_exits_2() {
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
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
        .args(["--format", "table", "profile", "fetch"])
        .assert()
        .success();

    assert!(
        base.join("registry-cache.json").exists(),
        "cache file must exist after a successful fetch"
    );
}

/// `profile fetch --registry <url>` overrides the configured URL for that one
/// fetch (issue #659 — the flag had zero test occurrences).
///
/// Self-controlled: the config points at a path the server does NOT mount, so
/// the no-flag fetch fails and leaves no cache — proving the configured URL
/// alone cannot succeed — and the `--registry` fetch against the mounted path
/// succeeds, caches, and surfaces the profile in `list`.
#[tokio::test]
async fn profile_fetch_registry_flag_overrides_configured_url() {
    use wiremock::matchers::{method, path as wpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let cfg = tempdir().unwrap();
    let (sk, pk) = test_keypair();
    let body = r#"[{"id":"ovr","name":"Override","keys":{}}]"#;
    let sig = sk.sign(body.as_bytes()).to_bytes().to_vec();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wpath("/override/r.json"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.as_bytes()))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(wpath("/override/r.json.sig"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(sig))
        .mount(&server)
        .await;

    let base = cfg.path().join("paksmith");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(
        base.join("config.toml"),
        format!(
            "[registry]\nurl = \"{}/unmounted.json\"\npublic_key = \"{pk}\"\n",
            server.uri()
        ),
    )
    .unwrap();

    // Control: without the flag, the configured URL 404s and the fetch fails.
    let _ = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["--format", "table", "profile", "fetch"])
        .assert()
        .code(2);
    assert!(
        !base.join("registry-cache.json").exists(),
        "a failed fetch must not leave a cache file"
    );

    let _ = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["--format", "table", "profile", "fetch", "--registry"])
        .arg(format!("{}/override/r.json", server.uri()))
        .assert()
        .success();

    let listed = paksmith_table(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    assert!(
        String::from_utf8(listed.get_output().stdout.clone())
            .unwrap()
            .contains("ovr"),
        "the overridden fetch must land the registry profile in the cache"
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
        // The URL carries a raw ESC (TOML `\u001B`) because `InsecureUrl`
        // interpolates it: this test therefore also pins that the fetch-failure
        // warn ESCAPES its untrusted field. `url` is the one attacker-influenced
        // value among that warn's inputs and needs no signature to reach.
        format!(
            "[registry]\nurl=\"http://127.0.0.1:1/dead\\u001B[2JPWNED.json\"\npublic_key=\"{pk}\"\n"
        ),
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
        .env("NO_COLOR", "1")
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
    // The warn binds its fault as a plain `String`, so `record_str` escapes the
    // URL. Re-applying the `%` sigil there would emit a live screen-clear.
    assert!(
        stderr.contains("\\u{1b}"),
        "the ESC in the config URL must appear escaped: {stderr}"
    );
    // Scoped deliberately: this holds only because `NO_COLOR=1` is set above,
    // since the subscriber emits its own ANSI level tag otherwise. What it pins
    // is that the INTERPOLATED field contributes no raw ESC.
    assert!(
        !stderr.contains('\u{1b}'),
        "no raw ESC from the interpolated field: {stderr}"
    );
}

/// `profile list` includes cached registry profiles tagged `[registry]` alongside
/// local ones tagged `[local]`. When the same id appears locally and in the cache,
/// only the local entry (tagged `[local]`) is shown.
#[test]
fn profile_list_shows_cached_registry_profiles() {
    let cfg = tempfile::tempdir().unwrap();

    // One local profile.
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "local-game", "--name", "Local"])
        .assert()
        .success();

    // Two cache entries: one unique registry-only, one shadowed by local.
    seed_registry_cache_json(
        cfg.path(),
        &format!(
            r#"{{"id":"reg-only","name":"RegOnly","keys":{{"00000000000000000000000000000000":"{KEY}"}}}},
               {{"id":"local-game","name":"Shadowed","keys":{{}}}}"#
        ),
    );

    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "my-local", "--name", "MyLocal"])
        .assert()
        .success();

    // Write a deliberately corrupt cache file (not valid JSON).
    std::fs::write(base.join("registry-cache.json"), b"not json {{{").unwrap();

    // `profile list` must succeed and still show the local profile.
    let out = paksmith_table(cfg.path())
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
    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
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
        .args(["--format", "table", "profile", "fetch"])
        .assert()
        .success();

    // Second fetch WITHOUT --force on a fresh cache should print "fresh" and skip.
    let skip_out = assert_cmd::Command::cargo_bin("paksmith")
        .unwrap()
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .env("PAKSMITH_ALLOW_HTTP", "1")
        .args(["--format", "table", "profile", "fetch"])
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
        // `--format table` like its two siblings: under JSON,
        // `contains("fetched")` would match the document's KEY NAME rather
        // than the table's "fetched N profiles", and the `!a.force` guard
        // this test pins could be elided with both assertions still passing.
        .args(["--format", "table", "profile", "fetch", "--force"])
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
        .args(["--format", "table", "profile", "fetch"])
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
    seed_registry_cache_with_key(config_dir, id, name, KEY);
}

/// As above, with an explicit key — lets a test seed a WRONG registry key,
/// which is the only way to reach `test`'s stale-cache note.
fn seed_registry_cache_with_key(config_dir: &std::path::Path, id: &str, name: &str, key: &str) {
    seed_registry_cache_json(
        config_dir,
        &format!(
            r#"{{"id":"{id}","name":"{name}","engine_version":"5.3","keys":{{"00000000000000000000000000000000":"{key}"}}}}"#
        ),
    );
}

/// `profile show` resolves a registry-cached id and reports its provenance.
#[test]
fn show_resolves_cached_registry_profile() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let out = paksmith_table(cfg.path())
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
    // The FULL line, not the bare word: renaming the label to `origin:` would
    // still satisfy `contains("registry")`.
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

    let out = paksmith_table(cfg.path())
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

    let out = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "dual", "--name", "LocalWins"])
        .assert()
        .success();
    seed_registry_cache(cfg.path(), "dual", "RegistryLoses");

    let out = paksmith_table(cfg.path())
        .args(["profile", "show", "dual"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("LocalWins"), "local must win: {txt}");
    // Pins the OTHER arm's literal: without this, swapping the two source
    // strings passes the whole suite.
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

    let _ = paksmith_table(cfg.path())
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

    let out = paksmith_table(cfg.path())
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
    // Negates the stale-cache note's OUTCOME term: a registry key that WORKS
    // must not be blamed on a stale cache. Without this, the note firing on
    // every registry `test` goes unnoticed.
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("cached registry document"),
        "a working registry key must not be called stale: {err}"
    );
}

/// `profile test` on an id present nowhere stays `ProfileNotFound` (exit 2),
/// distinct from the exit-1 "key didn't work" outcome.
#[test]
fn test_unknown_id_still_not_found_with_a_cache_present() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    let _ = paksmith_table(cfg.path())
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
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "mine", "--name", "Mine"])
        .assert()
        .success();
    std::fs::write(base.join("registry-cache.json"), b"not json {{{").unwrap();

    let out = paksmith_table(cfg.path())
        .args(["profile", "show", "mine"])
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("source: local"), "{txt}");

    // Give the profile the fixture's key so the degraded path exits 0. A hard
    // `RegistryCache::load()?` would fail with `CacheCorrupt` — ALSO exit 2 —
    // so asserting `.code(2)` here would pass against the very regression this
    // test documents.
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "mine", "--key", KEY])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
        .args(["profile", "test", "mine"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .success();
    let txt = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(txt.contains("verified"), "{txt}");
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
        vec!["profile", "key", "add", "reg-only", "--key", KEY],
    ] {
        let out = paksmith_table(cfg.path()).args(&args).assert().code(2);
        let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
        assert!(
            err.contains("signed registry document") && err.contains("cannot"),
            "{args:?} must explain the id cannot be edited locally: {err}"
        );
    }

    // An id in NEITHER layer gets no such hint — the plain not-found stands.
    let out = paksmith_table(cfg.path())
        .args(["profile", "remove", "nowhere"])
        .assert()
        .code(2);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("signed registry document"),
        "an absent id must not be described as a registry profile: {err}"
    );
}

/// `--quiet` is documented as "no advisory notes". All three `note:` lines
/// added for #658 route through the same guarded helper as the pre-existing
/// one, so they gate too — errors still print, since those are not notes.
/// (The third, `test`'s stale-cache note, is covered in
/// `test_warns_only_when_a_wrong_key_came_from_the_registry`.)
#[test]
fn quiet_suppresses_the_advisory_notes_but_not_the_error() {
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "reg-only", "RegOnly");

    // The read-only hint on a mutating command.
    let out = paksmith_table(cfg.path())
        .args(["--quiet", "profile", "remove", "reg-only"])
        .assert()
        .code(2);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("note:"),
        "advisory note must be silenced: {err}"
    );
    assert!(
        err.contains("paksmith: error:"),
        "the error itself must still print: {err}"
    );

    // The `profile fetch` hint on an unresolvable id.
    let out = paksmith_table(cfg.path())
        .args(["--quiet", "profile", "show", "absent"])
        .assert()
        .code(2);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("note:"),
        "advisory note must be silenced: {err}"
    );

    // Without --quiet both notes appear (otherwise the gate proves nothing).
    let out = paksmith_table(cfg.path())
        .args(["profile", "show", "absent"])
        .assert()
        .code(2);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("note:"),
        "the note must appear unquieted: {err}"
    );
}

/// `test` warns that a REGISTRY-sourced key came from a cache these commands
/// never refresh — the disclosure that stops `profile test` contradicting
/// `extract --game` inside the staleness window.
///
/// Fires for registry+wrong; silent for local+wrong, where `profile fetch`
/// would be useless advice pointing away from the real cause; silenced by
/// `--quiet`. The remaining term — a registry key that WORKS — is negated in
/// `test_resolves_cached_registry_profile`.
#[test]
fn test_warns_only_when_a_wrong_key_came_from_the_registry() {
    let wrong = "00".repeat(32);

    // (a) registry + wrong key → exit 1, note present.
    let cfg = tempdir().unwrap();
    seed_registry_cache_with_key(cfg.path(), "reg-bad", "RegBad", &wrong);
    let out = paksmith_table(cfg.path())
        .args(["profile", "test", "reg-bad"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(1);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        err.contains("cached registry document"),
        "a registry-sourced wrong key must name the stale cache: {err}"
    );

    // (b) local + wrong key → exit 1, note ABSENT. `profile fetch` cannot help
    // a local profile, so firing here would send the user the wrong way.
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "loc", "--name", "Loc"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "loc", "--key", &wrong])
        .assert()
        .success();
    let out = paksmith_table(cfg.path())
        .args(["profile", "test", "loc"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(1);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(
        !err.contains("cached registry document"),
        "a LOCAL wrong key must not be blamed on the registry cache: {err}"
    );

    // (c) --quiet silences it; the exit code is unchanged.
    let cfg = tempdir().unwrap();
    seed_registry_cache_with_key(cfg.path(), "reg-bad", "RegBad", &wrong);
    let out = paksmith_table(cfg.path())
        .args(["--quiet", "profile", "test", "reg-bad"])
        .arg(fixture("real_v8b_encrypted_index.pak"))
        .assert()
        .code(1);
    let err = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(!err.contains("cached registry document"), "{err}");
}

// ---------------------------------------------------------------------------
// #658: `--format json` for the profile subcommands
// ---------------------------------------------------------------------------

/// Seed one local profile with an engine version and a key, so the JSON
/// shapes below have every optional field populated.
fn seed_one(cfg: &std::path::Path) {
    let _ = paksmith_table(cfg)
        .args([
            "profile",
            "add",
            "hero",
            "--name",
            "Hero",
            "--engine-version",
            "5.3",
        ])
        .assert()
        .success();
    let _ = paksmith_table(cfg)
        .args(["profile", "key", "add", "hero", "--key", KEY])
        .assert()
        .success();
}

#[test]
fn profile_list_json_carries_envelope_and_rows() {
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());
    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "profiles", "list");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["schema_version"], 1);
    assert_eq!(
        v.as_object().unwrap().len(),
        2,
        "envelope is exactly 2 keys"
    );
    let row = &v["profiles"][0];
    assert_eq!(row["id"], "hero");
    assert_eq!(row["name"], "Hero");
    assert_eq!(row["engine_version"], "5.3");
    assert_eq!(row["key_count"], 1);
    assert_eq!(row["source"], "local");
}

#[test]
fn profile_show_json_redacts_keys_unless_asked() {
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());
    // Default: the guid is listed, the key material is NOT present anywhere.
    let out = paksmith_json(cfg.path())
        .args(["profile", "show", "hero"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "id", "show");
    assert!(
        !stdout.contains(&KEY[..8]),
        "key material must not appear without --show-keys: {stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // BY VALUE, not merely first: `assert_envelope_first` pins POSITION, so
    // SHOW_SCHEMA_VERSION could ship as any number and stay green.
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["source"], "local");
    assert_eq!(v["engine_version"], "5.3");
    assert!(v["keys"][0]["guid"].is_string(), "guid is always listed");
    // OMITTED, not null: presence of the field IS the `--show-keys` signal,
    // so a consumer tests `"key" in row` and needs no separate flag.
    assert!(
        v["keys"][0].get("key").is_none(),
        "key field must be ABSENT when redacted, not null: {stdout}"
    );

    // `--show-keys` is the deliberate reveal, mirroring the human path.
    let out = paksmith_json(cfg.path())
        .args(["profile", "show", "hero", "--show-keys"])
        .assert()
        .success();
    let shown = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        shown.contains(KEY),
        "--show-keys must reveal the key: {shown}"
    );
}

#[test]
fn profile_test_json_uses_a_stable_outcome_token() {
    // The human label is prose ("decrypted (no index hash to verify)", "wrong
    // key"); the JSON token must be a stable machine value.
    //
    // Both legs are here because ONE is not enough: a test that only exercises
    // the success path asserts nothing about the failure tokens, and a probe
    // rewriting `wrong_key` to the prose `"wrong key"` survives it. Each leg
    // pins the exact token for the outcome it produces.
    let pak = fixture("real_v8b_encrypted_index.pak");

    // Correct key -> "verified", ok: true, exit 0.
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());
    let out = paksmith_json(cfg.path())
        .args(["profile", "test", "hero"])
        .arg(&pak)
        .assert()
        .code(0);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "id", "test/ok");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["schema_version"], 1,
        "TEST_SCHEMA_VERSION pinned by value"
    );
    assert_eq!(v["id"], "hero");
    assert_eq!(
        v["outcome"], "verified",
        "exact token, not merely one of a set"
    );
    assert_eq!(v["ok"], true);

    // Wrong key -> "wrong_key" (underscored token, NOT the table's "wrong
    // key"), ok: false, exit 1.
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "g", "--name", "G"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "g", "--key", &"00".repeat(32)])
        .assert()
        .success();
    let out = paksmith_json(cfg.path())
        .args(["profile", "test", "g"])
        .arg(&pak)
        .assert()
        .code(1);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["outcome"], "wrong_key",
        "stable token, not the prose label"
    );
    assert_eq!(v["ok"], false, "ok mirrors the non-zero exit");
}

/// The all-zero default encryption-key GUID, as `key remove` spells it.
const ZERO_GUID: &str = "00000000000000000000000000000000";

/// A second key slot, so a `keys` array has more than one entry to lose.
const SECOND_GUID: &str = "11111111111111111111111111111111";

#[test]
fn profile_mutations_emit_a_receipt_under_json() {
    // All four store mutations return a MutationOutput document. Each leg
    // pins the EXACT `action` token and the EXACT prose that must NOT
    // accompany it, on either stream.
    let cfg = tempdir().unwrap();
    let key = KEY;
    // Each case carries the EXACT prose its subcommand would have printed —
    // per case, because the two `key` sentences ("added key for GUID … to
    // `hero`") share no substring with the two profile ones.
    let cases: [(&[&str], &str, Option<&str>, &str); 4] = [
        (
            &["profile", "add", "hero", "--name", "Hero"],
            "added",
            None,
            "added profile `hero`",
        ),
        (
            &["profile", "key", "add", "hero", "--key", key],
            "key_added",
            Some(ZERO_GUID),
            "added key for GUID",
        ),
        (
            &["profile", "key", "remove", "hero", "--guid", ZERO_GUID],
            "key_removed",
            Some(ZERO_GUID),
            "removed key for GUID",
        ),
        (
            &["profile", "remove", "hero"],
            "removed",
            None,
            "removed profile `hero`",
        ),
    ];

    for (args, action, guid, prose) in cases {
        let out = paksmith_json(cfg.path()).args(args).assert().success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();

        assert_envelope_first(&stdout, "action", action);
        let v: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{action}: stdout must be a JSON document ({e}): {stdout}"));
        assert_eq!(v["schema_version"], 1, "{action}");
        assert_eq!(v["action"], action, "exact token, not the prose sentence");
        assert_eq!(v["id"], "hero", "{action}");
        // The key subcommands name the slot they acted on; add/remove omit it
        // rather than emitting null, so `"guid" in receipt` is the signal.
        match guid {
            Some(g) => assert_eq!(v["guid"], g, "{action} must report its key slot: {stdout}"),
            None => assert!(
                v.get("guid").is_none(),
                "{action} has no key slot, so `guid` must be ABSENT: {stdout}"
            ),
        }
        assert_eq!(
            v.as_object().unwrap().len(),
            if guid.is_some() { 4 } else { 3 },
            "{action}: receipt carries exactly the documented keys"
        );

        // The human sentence must not ALSO appear — neither stream carries it
        // under --format json, or a consumer teeing both gets both shapes.
        assert!(
            !stdout.contains(prose) && !stderr.contains(prose),
            "{action}: the prose confirmation ({prose:?}) must not accompany the receipt.\
             \nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

#[test]
fn profile_list_json_applies_local_wins_precedence() {
    // The local-wins rule lived in BOTH arms before `rows()`; the table copy
    // was pinned and the JSON copy was not, so dropping the JSON `filter`
    // emitted a shadowed id TWICE in an array consumers key by id.
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "hero", "Hero From Registry");
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero Local"])
        .assert()
        .success();

    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rows = v["profiles"].as_array().unwrap();

    let heroes: Vec<_> = rows.iter().filter(|r| r["id"] == "hero").collect();
    assert_eq!(
        heroes.len(),
        1,
        "a locally-shadowed registry id must appear ONCE: {stdout}"
    );
    assert_eq!(
        heroes[0]["name"], "Hero Local",
        "the LOCAL profile must win: {stdout}"
    );
    assert_eq!(heroes[0]["source"], "local");
}

#[test]
fn profile_list_json_labels_registry_only_rows() {
    // Pins the `"registry"` token itself — `source` is a wire vocabulary
    // shared with the table's `[registry]` label, so rewriting it is a
    // breaking change to the document, not a rename.
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "fromreg", "From Registry");

    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let row = &v["profiles"][0];
    assert_eq!(row["id"], "fromreg");
    assert_eq!(row["source"], "registry", "exact token: {stdout}");
}

#[test]
fn profile_show_json_reports_the_registry_layer() {
    // The registry arm of `show`'s JSON hardcodes source/mappings/pak_paths in
    // a match arm no JSON test reached. `RegistryProfile` structurally carries
    // neither mappings nor pak_paths, so the asymmetry (null vs []) is
    // deliberate and pinned here rather than left to drift.
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "fromreg", "From Registry");

    let out = paksmith_json(cfg.path())
        .args(["profile", "show", "fromreg"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "id", "show/registry");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["id"], "fromreg");
    assert_eq!(v["source"], "registry", "exact token: {stdout}");
    // `seed_registry_cache` seeds a KEY-BEARING profile, so the redaction gate
    // must hold on this arm too. The table arm and the LOCAL JSON arm each had
    // this pin; the registry JSON arm did not.
    assert!(
        !stdout.contains(KEY),
        "registry key material must not appear without --show-keys: {stdout}"
    );
    assert!(
        v["keys"][0].get("key").is_none(),
        "key field must be ABSENT when redacted: {stdout}"
    );
    assert!(
        v["mappings"].is_null(),
        "registry profiles carry no mappings"
    );
    assert_eq!(
        v["pak_paths"].as_array().map(Vec::len),
        Some(0),
        "registry profiles carry no pak_paths"
    );

    // …and the deliberate reveal works on this arm too, so the assertion above
    // pins the GATE rather than an arm that simply never emits keys.
    let shown = paksmith_json(cfg.path())
        .args(["profile", "show", "fromreg", "--show-keys"])
        .assert()
        .success();
    let shown = String::from_utf8(shown.get_output().stdout.clone()).unwrap();
    assert!(
        shown.contains(KEY),
        "--show-keys must reveal a registry profile's key: {shown}"
    );
}

#[test]
fn profile_auto_format_resolves_to_json_off_tty_and_says_so() {
    // The ONLY test exercising `--format auto` on this family: every other
    // one now passes an explicit format, so deleting the `format.resolve()` /
    // `note_auto_resolved_to_json` wiring in `run()` was invisible.
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());

    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let out = cmd
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .args(["profile", "list"]) // no --format: auto, and stdout is a pipe
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();

    assert_envelope_first(&stdout, "profiles", "auto");
    assert!(
        stderr.contains("stdout is not a terminal"),
        "auto-resolution to JSON must be announced on stderr: {stderr}"
    );

    // --quiet suppresses the advisory note but NOT the document.
    let mut cmd = Command::cargo_bin("paksmith").unwrap();
    let out = cmd
        .env("PAKSMITH_CONFIG_DIR", cfg.path())
        .args(["--quiet", "profile", "list"])
        .assert()
        .success();
    let q_stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let q_stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert_envelope_first(&q_stdout, "profiles", "auto/quiet");
    assert!(
        !q_stderr.contains("stdout is not a terminal"),
        "--quiet must silence the advisory note: {q_stderr}"
    );
}

/// Spawn `paksmith` with `args`, close the read end of stdout BEFORE the child
/// writes, and assert it exits 0 without panicking.
///
/// Dropping the reader first makes the result independent of payload size —
/// the real defect only shows past the 64 KiB pipe buffer, so a small-fixture
/// test would pass on the broken code.
fn assert_closed_stdout_exits_clean(cfg: &std::path::Path, args: &[&str]) {
    use std::io::Read;
    use std::process::{Command as StdCommand, Stdio};
    use std::thread;

    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_paksmith"))
        .env("PAKSMITH_CONFIG_DIR", cfg)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let mut stderr = child.stderr.take().unwrap();
    let handle = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });
    let status = child.wait().unwrap();
    let stderr_text = handle.join().unwrap();
    assert!(
        !stderr_text.contains("panicked"),
        "{args:?} panicked on a closed stdout: {stderr_text}"
    );
    assert_eq!(
        status.code(),
        Some(0),
        "{args:?} must exit 0 on BrokenPipe, got {status:?}"
    );
}

#[test]
fn profile_json_with_closed_stdout_exits_cleanly() {
    // `println!` panics (exit 101) when the reader closes the pipe; the shared
    // writers route BrokenPipe to main.rs's clean exit instead.
    // SPEC: "0 success, including BrokenPipe on stdout".
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());
    for args in [
        ["--format", "json", "profile", "list"],
        ["--format", "table", "profile", "list"],
    ] {
        assert_closed_stdout_exits_clean(cfg.path(), &args);
    }
}

/// `test`'s third token, `decrypted` — the one whose whole reason for
/// existing is that the table renders "decrypted (no index hash to verify)",
/// prose no script can match on. Reached exactly as core's
/// `test_key_zeroed_index_hash_returns_decrypted` does: zero the footer's
/// index_hash so the index decrypts but integrity cannot be confirmed.
///
/// The fourth outcome, `unsupported`, is not reachable from this command with
/// the current corpus — measured: a non-pak file and an oversized index_size
/// both fail in `read_footer_guid` and exit 2 before an outcome exists, and
/// corrupting the encrypted index body yields `wrong_key` because garbage
/// plaintext surfaces as a `Decryption` error.
///
/// That is a limit of the FIXTURES, not of the coverage. Its token, label and
/// `ok`/exit-1 contract are pinned on the pure `outcome_report` seam
/// (`commands/profile.rs`), which is why that match was extracted.
#[test]
fn profile_test_json_reports_decrypted_when_the_hash_slot_is_zeroed() {
    let cfg = tempdir().unwrap();
    seed_one(cfg.path());

    // V8B+ footer: magic(4) version(4) index_offset(8) index_size(8)
    // index_hash(20) — the hash field starts at footer_start + 24.
    let src = std::fs::read(fixture("real_v8b_encrypted_index.pak")).unwrap();
    let magic = b"\xe1\x12\x6f\x5a";
    let footer = src
        .windows(4)
        .rposition(|w| w == magic)
        .expect("footer magic present in fixture");
    let mut patched = src.clone();
    patched[footer + 24..footer + 44].fill(0);
    assert_ne!(patched, src, "the patch must actually change the fixture");

    let pak = cfg.path().join("zeroed_hash.pak");
    std::fs::write(&pak, &patched).unwrap();

    let out = paksmith_json(cfg.path())
        .args(["profile", "test", "hero"])
        .arg(&pak)
        .assert()
        .code(0);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        v["outcome"], "decrypted",
        "exact token, not the table's prose: {stdout}"
    );
    assert_eq!(
        v["ok"], true,
        "decrypted still opened the archive, so ok/exit stay 0"
    );

    // The TABLE label for the same outcome. Only `wrong key`'s prose was
    // pinned, so rewriting this one to any other string — including another
    // outcome's — survived the suite. Both spellings now come from one
    // exhaustive match, which makes a single edit able to change either.
    let out = paksmith_table(cfg.path())
        .args(["profile", "test", "hero"])
        .arg(&pak)
        .assert()
        .code(0);
    let table = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(
        table.trim_end(),
        "hero: decrypted (no index hash to verify)",
        "the human label must stay the prose the JSON token exists to replace"
    );
}

#[test]
fn profile_show_json_carries_mappings_pak_paths_name_and_every_key() {
    // The local arm of `show --format json` could blank `name`, `mappings` and
    // `pak_paths` with the whole suite green: `seed_one` sets none of them, and
    // this PR pinned every mappings/pak_paths test to `--format table`. The
    // registry test cannot cover it either — there `null`/`[]` are the CORRECT
    // values, so it cannot tell "registry has none" from "the local arm
    // dropped them". Silent data loss on a machine interface.
    let cfg = tempdir().unwrap();
    let usmap = cfg.path().join("hero.usmap");
    std::fs::write(&usmap, b"not a real usmap").unwrap();

    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero Display Name"])
        .args(["--engine-version", "5.3"])
        .arg("--mappings")
        .arg(&usmap)
        .args(["--pak-path", "/games/hero/Paks/*.pak"])
        .args(["--pak-path", "/games/hero/Extra/*.pak"])
        .assert()
        .success();
    // TWO keys: with one, `keys` survives a `.take(1)`-shaped truncation.
    for guid in [ZERO_GUID, SECOND_GUID] {
        let _ = paksmith_table(cfg.path())
            .args(["profile", "key", "add", "hero", "--guid", guid])
            .args(["--key", KEY])
            .assert()
            .success();
    }

    let out = paksmith_json(cfg.path())
        .args(["profile", "show", "hero"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(
        v["name"], "Hero Display Name",
        "name must survive: {stdout}"
    );
    assert_eq!(
        v["mappings"],
        usmap.display().to_string(),
        "mappings must survive: {stdout}"
    );
    assert_eq!(
        v["pak_paths"],
        serde_json::json!(["/games/hero/Paks/*.pak", "/games/hero/Extra/*.pak"]),
        "every pak_path, in order: {stdout}"
    );
    // BY VALUE, not just count: `guid: guid.to_hex()` could be blanked to
    // `String::new()` and a length check would not notice — while the GUID is
    // exactly what a consumer needs to call `key remove --guid`.
    let guids: Vec<&str> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["guid"].as_str().unwrap())
        .collect();
    assert_eq!(
        guids,
        vec![ZERO_GUID, SECOND_GUID],
        "every key slot is listed, by GUID, BTreeMap-ordered: {stdout}"
    );
}

#[test]
fn profile_list_json_reports_registry_row_details_not_just_the_id() {
    // `profile_rows`'s registry branch could blank name/engine_version/
    // key_count and stay green: the JSON test asserted only id+source, and the
    // table test's `!contains("Shadowed")` still holds when the name is blank.
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "fromreg", "From Registry");

    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let row = &v["profiles"][0];
    assert_eq!(row["name"], "From Registry", "registry name: {stdout}");
    assert_eq!(row["engine_version"], "5.3", "registry engine: {stdout}");
    assert_eq!(row["key_count"], 1, "registry key count: {stdout}");
}

#[test]
fn profile_list_json_emits_a_duplicated_registry_id_once() {
    // A registry document may repeat an id — `validate_caps` bounds the profile
    // count and string lengths but never checks uniqueness. `RegistryCache::get`
    // is a `.find()`, so `show` answers with the FIRST. `list` must agree, or
    // the two surfaces disagree about the same store and the array gains a
    // duplicate key.
    let cfg = tempdir().unwrap();
    seed_registry_cache_json(
        cfg.path(),
        r#"
             {"id":"dup","name":"First","keys":{}},
             {"id":"dup","name":"Second","keys":{}}"#,
    );

    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let dups: Vec<_> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["id"] == "dup")
        .collect();
    assert_eq!(
        dups.len(),
        1,
        "a repeated registry id appears once: {stdout}"
    );
    assert_eq!(
        dups[0]["name"], "First",
        "first occurrence wins, as `show` does"
    );

    // The agreement itself, not just the count.
    let shown = paksmith_json(cfg.path())
        .args(["profile", "show", "dup"])
        .assert()
        .success();
    let sv: serde_json::Value =
        serde_json::from_str(&String::from_utf8(shown.get_output().stdout.clone()).unwrap())
            .unwrap();
    assert_eq!(sv["name"], dups[0]["name"], "`list` and `show` must agree");
}

#[test]
fn profile_mutations_print_their_confirmation_under_table() {
    // The Table arm of `confirm()`: the four confirmation sentences, verbatim,
    // and no receipt. Without this, `--format table profile add` could emit
    // the JSON document instead.
    let cfg = tempdir().unwrap();
    let key = KEY;
    let cases: [(&[&str], &str); 4] = [
        (
            &["profile", "add", "hero", "--name", "Hero"],
            "added profile `hero`",
        ),
        // A NON-default slot. With only the all-zero GUID here, hardcoding the
        // sentence's guid to zeros survived the suite — the JSON receipt's
        // ALT_GUID coverage does not reach the table arm.
        (
            &[
                "profile", "key", "add", "hero", "--guid", ALT_GUID, "--key", key,
            ],
            "added key for GUID 1a2b3c4d5e6f708192a3b4c5d6e7f809 to `hero`",
        ),
        (
            &["profile", "key", "remove", "hero", "--guid", ALT_GUID],
            "removed key for GUID 1a2b3c4d5e6f708192a3b4c5d6e7f809 from `hero`",
        ),
        (&["profile", "remove", "hero"], "removed profile `hero`"),
    ];

    for (args, prose) in cases {
        let out = paksmith_table(cfg.path()).args(args).assert().success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        assert_eq!(
            stdout.trim_end(),
            prose,
            "the table arm must print the human sentence verbatim"
        );
        assert!(
            !stdout.contains("schema_version"),
            "the table arm must NOT emit the receipt: {stdout}"
        );
    }
}

#[test]
fn profile_single_line_table_output_survives_a_closed_stdout() {
    // `print_line` is the sole writer for the SINGLE-LINE human messages —
    // "no profiles", "no profiles matched <dir>", "registry cache is fresh …",
    // "fetched N profiles", test's result line, and confirm's Table arm.
    //
    // An EMPTY config dir is the point: it forces the `no profiles` path.
    // With rows, `list()` writes through its own BufWriter and this helper is
    // never reached. Table only — the JSON arm has no empty-store branch, so
    // that leg would duplicate the seeded test's `print_json` coverage.
    let cfg = tempdir().unwrap();
    assert_closed_stdout_exits_clean(cfg.path(), &["--format", "table", "profile", "list"]);
}

/// A non-default key slot, so tests exercise a GUID that is not the all-zero
/// default every code path already produces.
const ALT_GUID: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f809";

#[test]
fn profile_key_receipts_report_the_slot_they_acted_on() {
    // `MutationOutput.guid` could be hardcoded to the all-zero GUID and stay
    // green: `key add` in the other tests omits `--guid` (so the default is
    // what's expected anyway) and `key remove` passes the zero GUID. Neither
    // exercises a non-default slot, so a receipt that always claims the
    // default would misreport which key was touched.
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "hero", "--name", "Hero"])
        .assert()
        .success();

    for (args, action) in [
        (
            vec![
                "profile", "key", "add", "hero", "--guid", ALT_GUID, "--key", KEY,
            ],
            "key_added",
        ),
        (
            vec!["profile", "key", "remove", "hero", "--guid", ALT_GUID],
            "key_removed",
        ),
    ] {
        let out = paksmith_json(cfg.path()).args(&args).assert().success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(v["action"], action);
        assert_eq!(
            v["guid"], ALT_GUID,
            "{action} must report the slot it acted on, not the default: {stdout}"
        );
    }
}

#[test]
fn profile_test_masks_its_wrong_key_exit_when_stdout_closes() {
    // SPEC states BrokenPipe takes precedence over `test`'s wrong-key 1. That
    // claim had NO coverage: both closed-stdout tests run `profile list`,
    // which exits 0 regardless of pipe state, so neither can tell "BrokenPipe
    // wins over 1" from "this command returns 0 anyway". `test` is the only
    // command in the family where 0-vs-1 discriminates.
    let cfg = tempdir().unwrap();
    let pak = fixture("real_v8b_encrypted_index.pak");
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "wrong", "--name", "Wrong"])
        .assert()
        .success();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "wrong", "--key", &"00".repeat(32)])
        .assert()
        .success();

    // Open stdout: the wrong key is a 1. This is the control — without it the
    // assertions below would pass on a command that simply succeeds.
    for fmt in ["json", "table"] {
        let _ = paksmith_unpinned(cfg.path())
            .args(["--format", fmt, "profile", "test", "wrong"])
            .arg(&pak)
            .assert()
            .code(1);
    }

    // Closed stdout: BrokenPipe wins and the 1 is masked as 0.
    let pak_s = pak.to_str().unwrap();
    for fmt in ["json", "table"] {
        assert_closed_stdout_exits_clean(
            cfg.path(),
            &["--format", fmt, "profile", "test", "wrong", pak_s],
        );
    }
}

#[test]
fn profile_list_table_also_dedupes_a_repeated_registry_id() {
    // The dedupe changed the HUMAN arm too, not just JSON — `profile_rows`
    // feeds both. That makes the table output NOT byte-identical to pre-#658
    // for this one input (three rows became two), which is deliberate but was
    // documented as a JSON-only concern and pinned only on the JSON side.
    let cfg = tempdir().unwrap();
    seed_registry_cache_json(
        cfg.path(),
        r#"
             {"id":"dup","name":"First","keys":{}},
             {"id":"dup","name":"Second","keys":{}},
             {"id":"uniq","name":"Unique","keys":{}}"#,
    );

    let out = paksmith_table(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let dup_rows = stdout.lines().filter(|l| l.starts_with("dup\t")).count();
    assert_eq!(dup_rows, 1, "one row for a repeated id: {stdout}");
    assert!(
        stdout.contains("First") && !stdout.contains("Second"),
        "first occurrence wins in the table too: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.starts_with("uniq\t")),
        "unrelated registry rows still render: {stdout}"
    );
}

/// `fetch`'s JSON `fetched` flag, BOTH legs. Its own doc says it exists "so a
/// script can tell 'already current' from 'downloaded'" — and neither leg had
/// a test, so hardcoding it to either value survived the suite.
#[tokio::test]
async fn profile_fetch_json_distinguishes_downloaded_from_fresh() {
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

    let run = |args: &'static [&'static str]| {
        let out = assert_cmd::Command::cargo_bin("paksmith")
            .unwrap()
            .env("PAKSMITH_CONFIG_DIR", cfg.path())
            .env("PAKSMITH_ALLOW_HTTP", "1")
            .args(args)
            .assert()
            .success();
        String::from_utf8(out.get_output().stdout.clone()).unwrap()
    };

    // Cold cache -> a real download.
    let first = run(&["--format", "json", "profile", "fetch"]);
    assert_envelope_first(&first, "fetched", "fetch/downloaded");
    let v: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(
        v["schema_version"], 1,
        "FETCH_SCHEMA_VERSION pinned by value"
    );
    assert_eq!(v["fetched"], true, "a cold fetch downloaded: {first}");
    assert_eq!(v["profile_count"], 1);

    // Fresh cache -> the network is short-circuited; same shape, fetched=false.
    let second = run(&["--format", "json", "profile", "fetch"]);
    let v: serde_json::Value = serde_json::from_str(&second).unwrap();
    assert_eq!(
        v["fetched"], false,
        "a fresh cache must report fetched=false: {second}"
    );
    assert_eq!(v["profile_count"], 1);

    // --force bypasses freshness and downloads again.
    let forced = run(&["--format", "json", "profile", "fetch", "--force"]);
    let v: serde_json::Value = serde_json::from_str(&forced).unwrap();
    assert_eq!(
        v["fetched"], true,
        "--force must re-download even on a fresh cache: {forced}"
    );
}

#[test]
fn profile_list_json_on_an_empty_store_is_an_empty_array_not_a_message() {
    // The highest-value gap the panel found, and the mirror of a test that
    // WAS written for `detect`. Hoisting `list`'s `is_empty` check above the
    // JSON branch survived the suite — and that mutation makes a fresh
    // install piping `profile list` emit `no profiles`: zero JSON bytes,
    // which `serde_json::from_reader` rejects. That is exactly the failure
    // `MutationOutput`'s doc says this whole design exists to prevent, and
    // every other JSON list test seeds the store first.
    let cfg = tempdir().unwrap();
    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_envelope_first(&stdout, "profiles", "list/empty");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("an empty store must still emit JSON ({e}): {stdout}"));
    assert_eq!(
        v["profiles"].as_array().map(Vec::len),
        Some(0),
        "an empty store is an empty array, not a message: {stdout}"
    );
    assert!(
        !stdout.contains("no profiles"),
        "the human message must not leak into the document: {stdout}"
    );
}

#[test]
fn profile_list_json_emits_local_rows_before_registry_only_rows() {
    // Emission order is a documented property of `profile_rows` and feeds BOTH
    // arms, but no test had a local row and an UNSHADOWED registry row
    // coexisting — the local-wins test shares one id, so nothing ever observed
    // relative position. Ids are chosen so alphabetical order would REVERSE
    // the expected result, making the assertion discriminate.
    let cfg = tempdir().unwrap();
    seed_registry_cache(cfg.path(), "aaa_reg", "Registry Row");
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "zzz_local", "--name", "Local Row"])
        .assert()
        .success();

    let out = paksmith_json(cfg.path())
        .args(["profile", "list"])
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rows: Vec<(&str, &str)> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["id"].as_str().unwrap(), r["source"].as_str().unwrap()))
        .collect();
    assert_eq!(
        rows,
        vec![("zzz_local", "local"), ("aaa_reg", "registry")],
        "local rows first despite `zzz_local` sorting after `aaa_reg`: {stdout}"
    );
}

#[test]
fn profile_json_reports_a_missing_engine_version_as_null() {
    // `ProfileRow.engine_version`'s doc calls `null` a deliberate wire choice
    // over the table's `-` sentinel — but every JSON list/show test seeded
    // `5.3`, so emitting the sentinel string into JSON survived the suite.
    let cfg = tempdir().unwrap();
    let _ = paksmith_table(cfg.path())
        .args(["profile", "add", "bare", "--name", "Bare"])
        .assert()
        .success();

    for (args, ctx) in [
        (vec!["profile", "list"], "list"),
        (vec!["profile", "show", "bare"], "show"),
    ] {
        let out = paksmith_json(cfg.path()).args(&args).assert().success();
        let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let ev = if ctx == "list" {
            &v["profiles"][0]["engine_version"]
        } else {
            &v["engine_version"]
        };
        assert!(
            ev.is_null(),
            "{ctx}: an unset engine_version must be null, not the table's `-`: {stdout}"
        );
    }
}
