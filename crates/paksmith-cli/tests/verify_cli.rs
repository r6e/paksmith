//! Integration tests for `paksmith verify`.
#![allow(missing_docs)]

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

mod common;
use common::{
    HOSTILE_ENTRY, add_pak_path_profile, assert_closed_stdout_exits_clean, assert_envelope_first,
    assert_neutralized, assert_no_raw_json_hazards, finish_v5_pak, fixture_path, paksmith_table,
    paksmith_unpinned, v5_record_with,
};

/// Run `verify` on `paths` with `--format format`, expecting `code`.
fn verify(paths: &[PathBuf], format: &str, code: i32) -> String {
    let cfg = tempfile::tempdir().unwrap();
    let out = paksmith_unpinned(cfg.path())
        .args(["--format", format, "verify"])
        .args(paths)
        .assert()
        .code(code);
    String::from_utf8(out.get_output().stdout.clone()).unwrap()
}

/// The `archives` of `verify`'s JSON document for `paths`.
fn archives(paths: &[PathBuf], code: i32) -> Vec<Value> {
    let doc: Value = serde_json::from_str(&verify(paths, "json", code)).unwrap();
    assert_eq!(doc["schema_version"], 1, "{doc}");
    doc["archives"].as_array().unwrap().clone()
}

/// The one archive of `verify`'s JSON document for `path`.
fn only_archive(path: PathBuf, code: i32) -> Value {
    let [archive]: [Value; 1] = archives(&[path], code).try_into().unwrap();
    archive
}

/// `bytes` written to `name` in `dir`.
fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

/// `real_v8b_multi.pak` with its first payload byte flipped. Its first
/// record sits at offset 0 and is 53 bytes long.
fn flipped_v8b(dir: &Path) -> PathBuf {
    let mut pak = std::fs::read(fixture_path("real_v8b_multi.pak")).unwrap();
    pak[53] ^= 0xFF;
    write(dir, "flipped.pak", &pak)
}

/// `real_v11_multi.pak` with no index hash and its PHI's hash slot zeroed,
/// so its FDI verifies and its PHI is skipped.
fn unhashed_phi_v11(dir: &Path) -> PathBuf {
    let mut pak = std::fs::read(fixture_path("real_v11_multi.pak")).unwrap();
    // A v11 footer ends with the index offset and size, the index hash,
    // then five 32-byte method names.
    let hash_end = pak.len() - 5 * 32;
    pak[hash_end - 20..hash_end].fill(0);
    let le_u64 = |at: usize| u64::from_le_bytes(pak[at..at + 8].try_into().unwrap());
    let index = usize::try_from(le_u64(hash_end - 36)).unwrap();
    let mount = u32::from_le_bytes(pak[index..index + 4].try_into().unwrap());
    // After the mount point: entry count, path hash seed, has-PHI flag,
    // then the PHI's offset, size and hash.
    let flag = index + 4 + usize::try_from(mount).unwrap() + 4 + 8;
    assert_eq!(pak[flag..flag + 4], 1u32.to_le_bytes());
    pak[flag + 20..flag + 40].fill(0);
    write(dir, "phi.pak", &pak)
}

/// A v5 pak whose one entry, `name`, is a plaintext Oodle record carrying
/// a non-zero SHA-1, which verify refuses to hash because paksmith doesn't
/// decode Oodle.
fn hashed_oodle_pak(name: &str) -> Vec<u8> {
    const OODLE: u32 = 4;
    const PAYLOAD: [u8; 16] = [7; 16];
    let size = u64::try_from(PAYLOAD.len()).unwrap();
    let start = paksmith_core::testing::wire::pak_entry_wire_size(1);
    let record = v5_record_with(0, size, OODLE, &[0xAB; 20], &[(start, start + size)]);
    let mut pak = record.clone();
    pak.extend_from_slice(&PAYLOAD);
    finish_v5_pak(pak, &[(name, &record)])
}

#[test]
fn a_hashed_archive_is_fully_verified() {
    let archive = only_archive(fixture_path("real_v8b_multi.pak"), 0);
    assert_eq!(
        (&archive["ok"], &archive["code"]),
        (&json!(true), &json!(0))
    );
    assert_eq!(archive["fully_verified"], true);
    assert_eq!(
        archive["index"],
        json!({"main": "verified", "fdi": "not_present", "phi": "not_present"})
    );
    assert_eq!(
        archive["counts"],
        json!({"verified": 3, "skipped_no_hash": 0})
    );
    assert_eq!(archive["integrity"]["claim"], 3);
}

#[test]
fn an_archive_whose_listing_has_no_hashes_verifies_with_skips() {
    let archive = only_archive(fixture_path("real_v11_multi.pak"), 0);
    assert_eq!(archive["ok"], true);
    assert_eq!(archive["fully_verified"], false);
    assert_eq!(
        archive["index"],
        json!({"main": "verified", "fdi": "verified", "phi": "verified"})
    );
    assert_eq!(
        archive["counts"],
        json!({"verified": 0, "skipped_no_hash": 3})
    );
    assert_eq!(
        archive["integrity"],
        json!({
            "claim": 0,
            "not_in_index": 3,
            "no_claim": 0,
            "stripped": 0,
            "mixes_hash_presence": false,
        })
    );
}

/// The FDI's state and the PHI's each come from their own region.
#[test]
fn the_index_states_tell_the_fdi_from_the_phi() {
    let dir = tempfile::tempdir().unwrap();
    let archive = only_archive(unhashed_phi_v11(dir.path()), 0);
    assert_eq!(
        archive["index"],
        json!({"main": "skipped_no_hash", "fdi": "verified", "phi": "skipped_no_hash"})
    );
}

#[test]
fn an_archive_mixing_hash_presence_verifies_with_a_listing_line() {
    use paksmith_core::testing::v10::hash_presence_v11_pak;

    let dir = tempfile::tempdir().unwrap();
    let pak = write(dir.path(), "a.pak", &hash_presence_v11_pak(true));
    let archive = only_archive(pak.clone(), 0);
    assert_eq!(archive["ok"], true);
    assert_eq!(
        archive["index"],
        json!({"main": "skipped_no_hash", "fdi": "skipped_no_hash", "phi": "skipped_no_hash"})
    );
    assert_eq!(
        archive["counts"],
        json!({"verified": 1, "skipped_no_hash": 1})
    );
    assert_eq!(archive["integrity"]["mixes_hash_presence"], true);
    assert_eq!(
        verify(std::slice::from_ref(&pak), "table", 0),
        format!(
            "{}: ok; index skipped no hash, fdi skipped no hash, phi skipped no hash; \
             1 of 2 entries with a hash in the listing, 1 without (1 with no hash in the \
             index, 0 zeroed)\n  listing: records a non-zero hash for 1 of this archive's 2 \
             entries\n",
            pak.display()
        )
    );
    let uniform = write(dir.path(), "b.pak", &hash_presence_v11_pak(false));
    assert!(!verify(&[uniform], "table", 0).contains("listing:"));
}

/// An archive that opens, mixes hash presence and fails its verify prints
/// its failure line and then the listing line.
#[test]
fn a_failed_archive_mixing_hash_presence_keeps_its_listing_line() {
    let mut pak = paksmith_core::testing::v10::hash_presence_v11_pak(true);
    let payload = b"alpha payload";
    let at: Vec<usize> = (0..=pak.len() - payload.len())
        .filter(|&i| pak[i..i + payload.len()] == payload[..])
        .collect();
    assert_eq!(at.len(), 1, "entry a's payload");
    pak[at[0]] ^= 0xFF;
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "a.pak", &pak);
    let table = verify(std::slice::from_ref(&path), "table", 1);
    let [failed, listing]: [&str; 2] = table.lines().collect::<Vec<_>>().try_into().unwrap();
    let failure = format!("{}: failed: SHA1 mismatch: entry `a`", path.display());
    assert!(failed.starts_with(&failure), "{table}");
    assert_eq!(
        listing,
        "  listing: records a non-zero hash for 1 of this archive's 2 entries"
    );
}

/// The table has a line per archive: its index regions' states and the
/// entry listing's counts, or why it failed.
#[test]
fn the_table_says_what_each_archive_verified() {
    let dir = tempfile::tempdir().unwrap();
    let paths = [
        fixture_path("real_v8b_multi.pak"),
        fixture_path("real_v11_multi.pak"),
        write(dir.path(), "not.pak", b"not a pak"),
    ];
    let [hashed, unhashed, not_pak] = paths.each_ref().map(|p| p.display());
    assert_eq!(
        verify(&paths, "table", 2),
        format!(
            "{hashed}: ok, fully verified; index verified, fdi not present, phi not present; \
             3 of 3 entries with a hash in the listing, 0 without (0 with no hash in the \
             index, 0 zeroed)\n\
             {unhashed}: ok; index verified, fdi verified, phi verified; \
             0 of 3 entries with a hash in the listing, 3 without (3 with no hash in the \
             index, 0 zeroed)\n\
             {not_pak}: failed: invalid pak footer: file too small (9 bytes) for any pak footer\n"
        )
    );
}

/// `real_v5_multi.pak` with no index hash, and its first entry's hash
/// zeroed in the listing and in the entry's own record, so that entry is
/// `no_claim` beside two with a hash.
fn zeroed_entry_v5(dir: &Path) -> PathBuf {
    let mut pak = std::fs::read(fixture_path("real_v5_multi.pak")).unwrap();
    // The first record sits at offset 0, its SHA-1 after the offset, both
    // sizes and the method.
    let sha1 = pak[28..48].to_vec();
    let at: Vec<usize> = (0..=pak.len() - 20)
        .filter(|&i| pak[i..i + 20] == sha1[..])
        .collect();
    assert_eq!(at.len(), 2, "the record and its listing copy");
    for i in at {
        pak[i..i + 20].fill(0);
    }
    // A v5 footer ends with the index hash.
    let end = pak.len();
    pak[end - 20..].fill(0);
    write(dir, "zeroed.pak", &pak)
}

/// The table tells the FDI's state from the PHI's, and an entry with no
/// hash in the index from one whose hash is zeroed, and a zeroed hash
/// beside hashed entries gets the listing line.
#[test]
fn the_table_tells_regions_and_skips_apart() {
    let dir = tempfile::tempdir().unwrap();
    let paths = [zeroed_entry_v5(dir.path()), unhashed_phi_v11(dir.path())];
    let [zeroed, phi] = paths.each_ref().map(|p| p.display());
    assert_eq!(
        verify(&paths, "table", 0),
        format!(
            "{zeroed}: ok; index skipped no hash, fdi not present, phi not present; \
             2 of 3 entries with a hash in the listing, 1 without (0 with no hash in the \
             index, 1 zeroed)\n  listing: records a non-zero hash for 2 of this archive's 3 \
             entries\n\
             {phi}: ok; index skipped no hash, fdi verified, phi skipped no hash; \
             0 of 3 entries with a hash in the listing, 3 without (3 with no hash in the \
             index, 0 zeroed)\n"
        )
    );
}

#[test]
fn a_flipped_payload_byte_exits_1_and_keeps_the_survey() {
    let dir = tempfile::tempdir().unwrap();
    let archive = only_archive(flipped_v8b(dir.path()), 1);
    assert_eq!(
        (&archive["ok"], &archive["code"]),
        (&json!(false), &json!(1))
    );
    let error = archive["error"].as_str().unwrap();
    assert!(error.starts_with("SHA1 mismatch: entry"), "{archive}");
    assert_eq!(archive["integrity"]["claim"], 3);
    for key in ["index", "counts", "fully_verified"] {
        assert!(archive.get(key).is_none(), "{key}: {archive}");
    }
}

#[test]
fn a_plaintext_entry_verify_cannot_hash_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let pak = write(dir.path(), "oodle.pak", &hashed_oodle_pak("Content/a.bin"));
    let archive = only_archive(pak, 2);
    assert_eq!(
        (&archive["ok"], &archive["code"]),
        (&json!(false), &json!(2))
    );
    assert_eq!(archive["integrity"]["claim"], 1);
    let error = archive["error"].as_str().unwrap();
    assert!(
        error.ends_with("unsupported compression method Oodle"),
        "{archive}"
    );
}

/// Every archive is reported, in order, and the exit code is the highest
/// any of them produced. A file that isn't a pak exits 2, with no survey.
#[test]
fn several_archives_exit_with_the_highest_code() {
    let dir = tempfile::tempdir().unwrap();
    let good = fixture_path("real_v8b_multi.pak");
    let flipped = flipped_v8b(dir.path());
    let not_pak = write(dir.path(), "not.pak", b"not a pak");
    let codes =
        |archives: &[Value]| -> Vec<Value> { archives.iter().map(|a| a["code"].clone()).collect() };
    assert_eq!(
        codes(&archives(&[flipped.clone(), good.clone()], 1)),
        [1, 0]
    );
    let three = archives(&[not_pak.clone(), flipped, good], 2);
    assert_eq!(codes(&three), [2, 1, 0]);
    assert_eq!(three[0]["archive"], not_pak.display().to_string());
    assert!(three[0].get("integrity").is_none(), "{}", three[0]);
    assert!(three[0]["error"].as_str().is_some(), "{}", three[0]);
}

/// `schema_version` comes first, and an archive's keys come in a fixed
/// order.
#[test]
fn the_document_keys_come_in_order() {
    let ok = verify(&[fixture_path("real_v8b_multi.pak")], "json", 0);
    assert_envelope_first(&ok, "archives", "verify");
    let dir = tempfile::tempdir().unwrap();
    let failed = verify(&[flipped_v8b(dir.path())], "json", 1);
    let ok_keys = [
        "archive",
        "ok",
        "code",
        "index",
        "counts",
        "integrity",
        "fully_verified",
    ];
    for (doc, keys) in [
        (&ok, &ok_keys[..]),
        (
            &failed,
            &["archive", "ok", "code", "integrity", "error"][..],
        ),
    ] {
        let at: Vec<_> = keys
            .iter()
            .map(|key| doc.find(&format!("\"{key}\":")).unwrap())
            .collect();
        assert!(at.is_sorted(), "{keys:?} at {at:?} in {doc}");
    }
}

/// With no path, `--game` verifies the profile's `pak_paths` archives. One
/// with no key for its GUID, or whose footer can't be read, is that
/// archive's failure, and the run goes on.
#[test]
fn a_profile_archive_whose_key_or_footer_fails_fails_alone() {
    let cfg = tempfile::tempdir().unwrap();
    let paks = tempfile::tempdir().unwrap();
    let pak = std::fs::read(fixture_path("real_v8b_multi.pak")).unwrap();
    // A v8b footer is 221 bytes and starts with the key GUID.
    let mut keyed = pak.clone();
    let footer = keyed.len() - 221;
    keyed[footer..footer + 16].fill(0x11);
    let _ = write(paks.path(), "a.pak", &keyed);
    let _ = write(paks.path(), "b.pak", &pak);
    let _ = write(paks.path(), "c.pak", b"not a pak");
    let pattern = paks.path().join("*.pak").display().to_string();
    add_pak_path_profile(cfg.path(), "hero", &pattern);
    let _ = paksmith_table(cfg.path())
        .args(["profile", "key", "add", "hero", "--key", &"ab".repeat(32)])
        .args(["--guid", &"11".repeat(16)])
        .assert()
        .success();
    let out = paksmith_unpinned(cfg.path())
        .args(["--format", "json", "--game", "hero", "verify"])
        .assert()
        .code(2);
    let doc: Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    let [good, no_key, not_pak]: [Value; 3] = doc["archives"]
        .as_array()
        .unwrap()
        .clone()
        .try_into()
        .unwrap();
    assert_eq!(
        (&good["code"], &good["fully_verified"]),
        (&json!(0), &json!(true))
    );
    for (archive, error) in [
        (no_key, "profile error: profile `hero` has no key for GUID"),
        (not_pak, "invalid pak footer"),
    ] {
        assert_eq!(
            (&archive["ok"], &archive["code"]),
            (&json!(false), &json!(2))
        );
        assert!(
            archive["error"].as_str().unwrap().starts_with(error),
            "{doc}"
        );
    }
}

/// An unknown `--game` fails before any archive is verified, as it does
/// for `list`: exit 2, the same `paksmith: error:` line, and no document.
/// It does so too when an archive before a readable one has a footer that
/// can't be read, since that archive's failure doesn't end the run.
#[test]
fn an_unknown_game_fails_the_run_as_it_does_for_list() {
    let cfg = tempfile::tempdir().unwrap();
    let run = |command: &str, paths: &[PathBuf]| {
        let out = paksmith_unpinned(cfg.path())
            .args(["--quiet", "--format", "json", "--game", "nope", command])
            .args(paths)
            .assert()
            .code(2);
        let out = out.get_output();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.is_empty(), "{command}: {stdout}");
        String::from_utf8(out.stderr.clone()).unwrap()
    };
    let good = fixture_path("real_v8b_multi.pak");
    let stderr = run("verify", std::slice::from_ref(&good));
    assert!(stderr.starts_with("paksmith: error:"), "{stderr}");
    assert_eq!(stderr, run("list", std::slice::from_ref(&good)));
    let dir = tempfile::tempdir().unwrap();
    let not_pak = write(dir.path(), "not.pak", b"not a pak");
    assert_eq!(run("verify", &[not_pak, good]), stderr);
}

/// An archive path's bidi override, and an entry path's DEL, C1 and bidi
/// characters quoted in the archive's error, come out as U+FFFD in the
/// table and as JSON escapes in the document, which still decodes to both.
#[test]
fn hostile_paths_are_escaped() {
    let name = std::str::from_utf8(HOSTILE_ENTRY).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pak = write(dir.path(), "hostile\u{202e}.pak", &hashed_oodle_pak(name));
    let paths = std::slice::from_ref(&pak);
    let shown = [
        "hostile\u{FFFD}.pak",
        "C/\u{FFFD}\u{FFFD}\u{FFFD}xxxxxxxxxx.bin",
    ];
    assert_neutralized(&verify(paths, "table", 2), &shown);
    let json = verify(paths, "json", 2);
    assert_no_raw_json_hazards(json.as_bytes());
    let doc: Value = serde_json::from_str(&json).unwrap();
    let archive = &doc["archives"][0];
    assert_eq!(archive["archive"], pak.display().to_string());
    assert!(archive["error"].as_str().unwrap().contains(name), "{doc}");
}

/// An archive's 1 or 2 comes with the document and no `paksmith: error:`
/// line, and a stdout closed before the document is written masks it as 0.
#[test]
fn a_closed_stdout_masks_an_archives_code() {
    let cfg = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let flipped = flipped_v8b(dir.path());
    let not_pak = write(dir.path(), "not.pak", b"not a pak");
    for (pak, code) in [(&flipped, 1), (&not_pak, 2)] {
        for format in ["json", "table"] {
            let args = ["--format", format, "verify", pak.to_str().unwrap()];
            // The control: with stdout open the code stands.
            let out = paksmith_unpinned(cfg.path()).args(args).assert().code(code);
            let stderr = String::from_utf8_lossy(&out.get_output().stderr);
            assert!(!stderr.contains("paksmith: error:"), "{stderr}");
            assert_closed_stdout_exits_clean(cfg.path(), &args);
        }
    }
}

#[test]
fn help_states_the_exit_codes() {
    let cfg = tempfile::tempdir().unwrap();
    let out = paksmith_unpinned(cfg.path())
        .args(["verify", "--help"])
        .assert()
        .success();
    let help = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    for clause in [
        "The exit code is the highest any archive produced",
        "0 when it verified",
        "1 when a stored hash didn't match",
        "2 when it couldn't be opened or verified",
        "A stdout closed before the report is written exits 0",
    ] {
        assert!(help.contains(clause), "{clause:?} missing from {help}");
    }
}
