//! Generates ground-truth pak fixtures using the third-party `repak`
//! crate (trumank/repak, MIT/Apache).
//!
//! Run with: `cargo run -p paksmith-fixture-gen`
//!
//! Lives in this dedicated crate (rather than as a `paksmith-core` example)
//! so the `repak` git dependency is only resolved when this crate is
//! explicitly built. Default `cargo build` / `cargo test` from the repo
//! root skips this crate (see workspace `default-members` in the root
//! `Cargo.toml`); CI uses `cargo test --workspace` to include it.
//!
//! # Why a separate generator from `generate.rs`?
//!
//! `generate.rs` produces synthetic paks via hand-rolled byte writes. Those
//! fixtures are fully under our control — we use them for unit-test edge
//! cases (DoS bounds, malformed-input rejection, specific corruption
//! shapes). The risk is generator/parser drift: if both sides share a bug
//! about the wire format, no test catches it.
//!
//! This file produces ground-truth fixtures via a *different* implementation
//! (trumank/repak). If paksmith reads a repak-written archive identically
//! to repak itself, both implementations agree on the format — that
//! independent agreement is the cross-parser anchor #14 calls for.
//!
//! # Coverage gaps repak imposes
//!
//! repak v0.2.3 only writes a subset of the format:
//! - **No compression**: the `allow_compress` flag on `write_file` is
//!   honored only if `PakBuilder::compression(...)` declares supported
//!   methods up front; even then, repak's writer hasn't been observed to
//!   emit zlib output for our test inputs. We generate only uncompressed
//!   fixtures here. Compressed-entry coverage stays in `generate.rs`.
//! - **No UTF-16 filenames**: API takes `&str`, encodes as positive-length
//!   FString (UTF-8 with null terminator). Synthetic generator covers this.
//! - **Always-real SHA1**: repak computes hashes; we can't simulate the
//!   "no integrity claim recorded" zero-hash case. Synthetic covers it.
//! - **v6 (DeleteRecords) untested upstream**: repak's README marks v6
//!   write support as `❔`. We try it anyway in this generator and let
//!   the cross-validation test catch any divergence; if it fails, drop
//!   v6 from the matrix.
//!
//! # Fixture matrix
//!
//! Three versions (v3, v6, v7) × three variants (minimal / multi /
//! mixed_paths). Total ~9 fixtures, each well under 1 KiB. v6 may be
//! dropped if the cross-validation test surfaces issues.

use std::fs::File;

use repak::{PakBuilder, Version};

/// One entry to embed in a fixture: path inside the archive, payload
/// bytes. Kept tiny — these fixtures are for shape coverage, not
/// performance testing.
struct Entry<'a> {
    path: &'a str,
    payload: &'a [u8],
}

/// Description of a fixture to generate.
struct Fixture<'a> {
    name: &'static str,
    version: Version,
    /// Mount point as written into the index. Real UE archives commonly
    /// use `"../../../"`; matching that exercises the same FString length
    /// branch real archives do.
    mount_point: &'static str,
    entries: &'a [Entry<'a>],
}

fn write_fixture(fixture: &Fixture<'_>) {
    let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(fixture.name);
    std::fs::create_dir_all(out_path.parent().unwrap()).unwrap();

    // Write to a sibling .tmp file then atomic-rename onto the final
    // path. Guarantees that a panic mid-write (e.g., a future repak
    // version that fails after writing some bytes) leaves the previously
    // committed fixture intact rather than a truncated/half-written one
    // that would silently pass downstream tests until the next CI run.
    let tmp_path = out_path.with_extension("pak.tmp");
    {
        let file = File::create(&tmp_path).unwrap();
        let mut writer =
            PakBuilder::new().writer(file, fixture.version, fixture.mount_point.to_string(), None);
        for entry in fixture.entries {
            writer
                .write_file(entry.path, false, entry.payload)
                .expect("repak write_file");
        }
        let _ = writer.write_index().expect("repak write_index");
    } // writer dropped here, file flushed and closed before rename
    std::fs::rename(&tmp_path, &out_path).expect("atomic rename onto final fixture path");

    let size = std::fs::metadata(&out_path).unwrap().len();
    println!(
        "  {:<28} {:?} mount={:?} entries={} size={}B",
        fixture.name,
        fixture.version,
        fixture.mount_point,
        fixture.entries.len(),
        size
    );
}

fn main() {
    println!("Generating cross-parser ground-truth fixtures via trumank/repak...");

    let minimal_entries: &[Entry<'_>] = &[Entry {
        path: "Content/Example.uasset",
        payload: b"EXAMPLE_PAYLOAD_BYTES",
    }];

    let multi_entries: &[Entry<'_>] = &[
        Entry {
            path: "Content/Textures/icon.uasset",
            payload: b"ICON_TEXTURE_DATA",
        },
        Entry {
            path: "Content/Maps/level.umap",
            payload: b"LEVEL_MAP_BYTES",
        },
        Entry {
            path: "Content/Sounds/click.uasset",
            payload: b"CLICK_SOUND_PCM",
        },
    ];

    let mixed_path_entries: &[Entry<'_>] = &[
        Entry {
            path: "root.txt",
            payload: b"depth-zero file",
        },
        Entry {
            path: "Content/a.uasset",
            payload: b"depth-one file",
        },
        Entry {
            path: "Content/Subdir/Deep/nested.uasset",
            payload: b"depth-three file",
        },
    ];

    let mount = "../../../";
    let fixtures = [
        // v3 — oldest version we support; legacy footer (no encryption GUID).
        Fixture {
            name: "real_v3_minimal.pak",
            version: Version::V3,
            mount_point: mount,
            entries: minimal_entries,
        },
        Fixture {
            name: "real_v3_multi.pak",
            version: Version::V3,
            mount_point: mount,
            entries: multi_entries,
        },
        Fixture {
            name: "real_v3_mixed_paths.pak",
            version: Version::V3,
            mount_point: mount,
            entries: mixed_path_entries,
        },
        // v6 — DeleteRecords. Marked untested in repak's README but the
        // enum variant exists; if cross-validation passes, it works.
        Fixture {
            name: "real_v6_minimal.pak",
            version: Version::V6,
            mount_point: mount,
            entries: minimal_entries,
        },
        Fixture {
            name: "real_v6_multi.pak",
            version: Version::V6,
            mount_point: mount,
            entries: multi_entries,
        },
        Fixture {
            name: "real_v6_mixed_paths.pak",
            version: Version::V6,
            mount_point: mount,
            entries: mixed_path_entries,
        },
        // v7 — first to introduce the encryption_key_guid footer field.
        Fixture {
            name: "real_v7_minimal.pak",
            version: Version::V7,
            mount_point: mount,
            entries: minimal_entries,
        },
        Fixture {
            name: "real_v7_multi.pak",
            version: Version::V7,
            mount_point: mount,
            entries: multi_entries,
        },
        Fixture {
            name: "real_v7_mixed_paths.pak",
            version: Version::V7,
            mount_point: mount,
            entries: mixed_path_entries,
        },
    ];

    for fixture in &fixtures {
        write_fixture(fixture);
    }

    println!("\nGenerated {} fixtures.", fixtures.len());
}
