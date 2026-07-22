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
//! # What bounds the fixture corpus
//!
//! The corpus is shaped by two distinct things — repak v0.2.3's writer
//! (some shapes it genuinely cannot produce) and our own deliberate matrix
//! choices (shapes repak *can* write but we don't generate). The first
//! bullet is the latter; the rest are the former:
//! - **Compressed fixtures are v8+ only (a matrix choice, not a repak
//!   limit).** Issue #69 added zlib-compressed fixtures
//!   (`real_v{8a,8b,9,10,11}_compressed.pak`) and issue #636 added
//!   LZ4-compressed fixtures (`real_v{8b,11}_lz4.pak`). repak CAN emit
//!   compressed output at any compression-capable version (v3+; compression
//!   is a v3 wire feature) — v3-v7 via the numeric compression IDs (repak's
//!   own test corpus ships `pack_v5_compress.pak` / `pack_v7_compress.pak`),
//!   v8+ via the FName slot table (exercised by our cross-validation). The
//!   corpus stays v8+ deliberately: pre-v5 compressed reads use
//!   absolute-offset blocks paksmith doesn't implement (#637), and v5-v7
//!   compressed exercises the same entry-relative read path the v8+
//!   fixtures already cover. repak ships compressed v8+ output when
//!   `PakBuilder::compression([...])` declares the method and the input
//!   compresses non-trivially.
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
//! Ten versions (v3, v4, v5, v6, v7, v8a, v8b, v9, v10, v11) × three
//! shape variants (minimal / multi / mixed_paths) + five
//! zlib-compressed variants (v8a/v8b/v9/v10/v11) + two
//! LZ4-compressed variants (v8b/v11, #636). Total 37 fixtures, each
//! well under 1 KiB. (v4/v5 are uncompressed/unencrypted, added by
//! issue #637 to make the "v3-v11" claim literal for the flat path.)

use std::fs::File;

use repak::{Compression, PakBuilder, Version};

// Re-route `uasset` from the sibling lib target (added in #244 for the
// differential proptest's reach into `cross_validate_with_unreal_asset`).
// The module's body lives once at `src/uasset.rs` and is owned by the
// lib; the bin imports it under the same `uasset::*` name so call sites
// below don't change. Avoids compiling `uasset.rs`'s `#[cfg(test)]
// inline tests twice (once per target).
use paksmith_fixture_gen::external_usmap;
use paksmith_fixture_gen::uasset;

// MOUNT_POINT moved to the lib (`paksmith_fixture_gen::MOUNT_POINT`)
// in #244 so the lib-bin split has a single source of truth. Re-
// import locally so the body of `main` keeps using bare `MOUNT_POINT`.
use paksmith_fixture_gen::MOUNT_POINT;

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
    /// Issue #69 (Zlib) / #636 (LZ4): when `Some(method)`, configure
    /// repak with that compression method (the FName slot table for v8+,
    /// or the pre-populated numeric slots for v3-v7) and pass
    /// `allow_compress: true` per entry. This matrix only sets compression
    /// on v8+ fixtures — repak CAN compress pre-v8 too (see the module doc),
    /// but the corpus stays v8+ by choice. The fixture's payloads must
    /// compress well — repak always stores compressed output, even when
    /// larger than uncompressed, so any non-empty compressible input trips
    /// the compressed path.
    compression: Option<Compression>,
}

fn write_fixture(fixture: &Fixture<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(fixture.name);
    std::fs::create_dir_all(out_path.parent().ok_or("fixture out_path has no parent")?)?;

    // Write to a sibling .pak.tmp file then atomic-rename onto the
    // final path. Guarantees that a panic mid-write (e.g., a future
    // repak version that fails after writing some bytes) leaves the
    // previously committed fixture intact rather than a truncated /
    // half-written one that would silently pass downstream tests until
    // the next CI run.
    //
    // Construct the temp path by appending `.tmp` to the full filename
    // rather than swapping extensions. The two-extension approach
    // (`with_extension("pak.tmp")`) happens to produce the right name
    // here, but Rust's `Path::with_extension` strips the existing
    // extension before appending, which makes the relationship between
    // the input and output non-obvious to a future reader. Explicit
    // string concat keeps the intent at the call site.
    let name = fixture.name;
    let tmp_path = out_path.with_file_name(format!("{name}.tmp"));
    {
        let file =
            File::create(&tmp_path).map_err(|e| format!("creating tempfile for `{name}`: {e}"))?;
        // For compressed fixtures, declare the method in the FName
        // slot table; repak's writer requires this BEFORE write_file
        // can honor allow_compress=true.
        let builder = match fixture.compression {
            Some(method) => PakBuilder::new().compression([method]),
            None => PakBuilder::new(),
        };
        let mut writer =
            builder.writer(file, fixture.version, fixture.mount_point.to_string(), None);
        for entry in fixture.entries {
            writer
                .write_file(entry.path, fixture.compression.is_some(), entry.payload)
                .map_err(|e| {
                    format!("repak write_file in `{name}` (entry `{}`): {e}", entry.path)
                })?;
        }
        // write_index returns the underlying File; discarded — the
        // block drops `writer` to flush/close before atomic-rename.
        let _ = writer
            .write_index()
            .map_err(|e| format!("repak write_index for `{name}`: {e}"))?;
    } // writer dropped here, file flushed and closed before rename
    std::fs::rename(&tmp_path, &out_path)
        .map_err(|e| format!("atomic rename for `{name}`: {e}"))?;

    let size = std::fs::metadata(&out_path)?.len();
    println!(
        "  {:<28} {:?} mount={:?} entries={} size={}B",
        fixture.name,
        fixture.version,
        fixture.mount_point,
        fixture.entries.len(),
        size
    );
    Ok(())
}

// `main` is long because the fixture matrix is data-driven; refactoring
// into helpers would obscure the fact that the array IS the spec.
#[allow(clippy::too_many_lines)]
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

    // Issue #69 compressed-fixture corpus. Single entry with a
    // payload that compresses well (highly-repetitive ASCII), so
    // repak's writer always emits a non-empty zlib block. v8+ only:
    // the FName-based compression slot table didn't exist before v8.
    //
    // The payload is intentionally NOT one of repak's no-compress
    // sentinels (empty vec) — repak's `build_partial_entry`
    // explicitly bypasses compression for empty data.
    let compressible_payload: &[u8] = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
                                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let compressed_entries: &[Entry<'_>] = &[Entry {
        path: "Content/Compressed.uasset",
        payload: compressible_payload,
    }];

    let mount = MOUNT_POINT;
    let fixtures = [
        // v3 — oldest version we support; legacy footer (no encryption GUID).
        Fixture {
            name: "real_v3_minimal.pak",
            version: Version::V3,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v3_multi.pak",
            version: Version::V3,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v3_mixed_paths.pak",
            version: Version::V3,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // v4 — IndexEncryption. Adds the index-encryption capability; these
        // fixtures are uncompressed + unencrypted, so the flat-entry layout
        // is identical to v3 and they pin paksmith's v4 version dispatch
        // (issue #637 legacy-version coverage).
        Fixture {
            name: "real_v4_minimal.pak",
            version: Version::V4,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v4_multi.pak",
            version: Version::V4,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v4_mixed_paths.pak",
            version: Version::V4,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // v5 — RelativeChunkOffsets. Compression-block offsets become
        // relative to the entry record; these fixtures are uncompressed so
        // they don't exercise that path, but pin v5 version dispatch (#637).
        Fixture {
            name: "real_v5_minimal.pak",
            version: Version::V5,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v5_multi.pak",
            version: Version::V5,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v5_mixed_paths.pak",
            version: Version::V5,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // v6 — DeleteRecords. Marked untested in repak's README but the
        // enum variant exists; if cross-validation passes, it works.
        Fixture {
            name: "real_v6_minimal.pak",
            version: Version::V6,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v6_multi.pak",
            version: Version::V6,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v6_mixed_paths.pak",
            version: Version::V6,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // v7 — first to introduce the encryption_key_guid footer field.
        Fixture {
            name: "real_v7_minimal.pak",
            version: Version::V7,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v7_multi.pak",
            version: Version::V7,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v7_mixed_paths.pak",
            version: Version::V7,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // V8A — UE 4.22 only. 4-slot FName compression table; per-entry
        // compression byte is u8.
        Fixture {
            name: "real_v8a_minimal.pak",
            version: Version::V8A,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v8a_multi.pak",
            version: Version::V8A,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v8a_mixed_paths.pak",
            version: Version::V8A,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // V8B — UE 4.23-4.24. 5-slot FName compression table; per-entry
        // compression byte is u32 (back to v7 width).
        Fixture {
            name: "real_v8b_minimal.pak",
            version: Version::V8B,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v8b_multi.pak",
            version: Version::V8B,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v8b_mixed_paths.pak",
            version: Version::V8B,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // V9 — UE 4.25. V8B layout + 1 frozen-index byte in the footer.
        Fixture {
            name: "real_v9_minimal.pak",
            version: Version::V9,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v9_multi.pak",
            version: Version::V9,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v9_mixed_paths.pak",
            version: Version::V9,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // V10 — UE 4.26. PathHashIndex: wholly new index format
        // (mount + count + seed + path-hash table + full directory
        // index + encoded entries blob). V10 had an FNV-64 bug that
        // mishandled non-ASCII lowercasing — irrelevant for ASCII
        // asset paths, which is all real UE paks use.
        Fixture {
            name: "real_v10_minimal.pak",
            version: Version::V10,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v10_multi.pak",
            version: Version::V10,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v10_mixed_paths.pak",
            version: Version::V10,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // V11 — UE 4.27+. Same shape as V10, with the FNV-64 bug fixed.
        // For ASCII paths the two are hash-identical, so the cross-
        // parser tests cover both via the same code path.
        Fixture {
            name: "real_v11_minimal.pak",
            version: Version::V11,
            mount_point: mount,
            entries: minimal_entries,
            compression: None,
        },
        Fixture {
            name: "real_v11_multi.pak",
            version: Version::V11,
            mount_point: mount,
            entries: multi_entries,
            compression: None,
        },
        Fixture {
            name: "real_v11_mixed_paths.pak",
            version: Version::V11,
            mount_point: mount,
            entries: mixed_path_entries,
            compression: None,
        },
        // Issue #69 compressed-entry coverage. v8+ only — earlier
        // versions don't have the FName slot table required for
        // repak's compression dispatch. These fixtures make the
        // layer-3 oracle's `is_compressed == true` branch actually
        // fire (the rest of the corpus is uncompressed and would
        // leave the assertion vacuous).
        Fixture {
            name: "real_v8a_compressed.pak",
            version: Version::V8A,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::Zlib),
        },
        Fixture {
            name: "real_v8b_compressed.pak",
            version: Version::V8B,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::Zlib),
        },
        Fixture {
            name: "real_v9_compressed.pak",
            version: Version::V9,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::Zlib),
        },
        // Issue #90 (sev 7 / pr-test H3): compressed-entry coverage
        // for the v10+ encoded-blob path. The v3-v9 layer-3 oracle
        // returns `None` for v10+ (deferred to issue #81 / closed by
        // #83's proptest), so layer-1+2 cross-parser agreement is the
        // only signal — but it IS a signal, and was missing for the
        // encoded-blob compressed path.
        Fixture {
            name: "real_v10_compressed.pak",
            version: Version::V10,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::Zlib),
        },
        Fixture {
            name: "real_v11_compressed.pak",
            version: Version::V11,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::Zlib),
        },
        // Issue #636 LZ4 corpus. Same compressible single-entry shape
        // as the zlib fixtures; repak writes raw LZ4 blocks via
        // lz4_flex::block::compress — the same block form CUE4Parse
        // decodes (K4os LZ4Codec.Decode) and paksmith's reader
        // implements. v8b anchors the earliest 5-slot/u32-index
        // FName-table layout (v8a's 4-slot/u8-index variant is covered
        // by real_v8a_compressed.pak above; slot resolution is
        // method-agnostic), v11 the current one.
        Fixture {
            name: "real_v8b_lz4.pak",
            version: Version::V8B,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::LZ4),
        },
        Fixture {
            name: "real_v11_lz4.pak",
            version: Version::V11,
            mount_point: mount,
            entries: compressed_entries,
            compression: Some(Compression::LZ4),
        },
    ];

    // Aggregate per-fixture failures rather than panicking on the
    // first one — when a repak upgrade or wire-format change breaks
    // multiple fixtures simultaneously, the user wants to see the
    // full damage report in a single run, not iterate-and-fix.
    let mut failures: Vec<(&str, Box<dyn std::error::Error>)> = Vec::new();
    for fixture in &fixtures {
        if let Err(e) = write_fixture(fixture) {
            failures.push((fixture.name, e));
        }
    }
    // Snapshot the repak-phase failure count BEFORE the uasset block
    // appends to `failures`. Pinning the temporal dependency in a
    // named variable makes the order-sensitive read explicit and
    // immune to future refactor reordering.
    let repak_failures = failures.len();
    let repak_total = fixtures.len();
    let repak_written = repak_total - repak_failures;
    println!("\nGenerated {repak_written} of {repak_total} repak fixtures.");

    println!(
        "\nGenerating UAsset fixtures (paksmith-synthesized, cross-validated via unreal_asset)..."
    );
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut uasset_written = 0;
    let uasset_total = 8;

    let uasset_path = out_dir.join("minimal_uasset_v5.uasset");
    if let Err(e) = uasset::write_minimal_ue4_27(&uasset_path) {
        failures.push(("minimal_uasset_v5.uasset", e.to_string().into()));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            uasset_path.display(),
            std::fs::metadata(&uasset_path).map_or(0, |m| m.len())
        );
    }

    let pak_path = out_dir.join("real_v8b_uasset.pak");
    if let Err(e) = uasset::write_minimal_pak_with_uasset(&pak_path) {
        failures.push(("real_v8b_uasset.pak", e.to_string().into()));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            pak_path.display(),
            std::fs::metadata(&pak_path).map_or(0, |m| m.len())
        );
    }

    let split_pak_path = out_dir.join("real_v8b_split.pak");
    if let Err(e) = uasset::write_minimal_pak_with_split_uasset(&split_pak_path) {
        failures.push(("real_v8b_split.pak", e.to_string().into()));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            split_pak_path.display(),
            std::fs::metadata(&split_pak_path).map_or(0, |m| m.len())
        );
    }

    // Phase 3b Task 7: `.ubulk` and `.uptnl` companion fixtures.
    // Sentinel-byte payloads (`BULK_COMPANION_SENTINEL`) so
    // integration tests in `paksmith-core-tests` can pin
    // `Package::resolve_bulk_for_export` output against a known
    // byte sequence routed through `BulkDataResolver`'s
    // streaming / optional-streaming tier dispatch.
    let ubulk_pak_path = out_dir.join("real_v8b_ubulk.pak");
    if let Err(e) = uasset::write_minimal_pak_with_ubulk(&ubulk_pak_path) {
        failures.push(("real_v8b_ubulk.pak", e.to_string().into()));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            ubulk_pak_path.display(),
            std::fs::metadata(&ubulk_pak_path).map_or(0, |m| m.len())
        );
    }

    let uptnl_pak_path = out_dir.join("real_v8b_uptnl.pak");
    if let Err(e) = uasset::write_minimal_pak_with_uptnl(&uptnl_pak_path) {
        failures.push(("real_v8b_uptnl.pak", e.to_string().into()));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            uptnl_pak_path.display(),
            std::fs::metadata(&uptnl_pak_path).map_or(0, |m| m.len())
        );
    }

    let props_path = out_dir.join("minimal_uasset_v5_with_properties.uasset");
    if let Err(e) = uasset::write_minimal_ue4_27_with_properties(&props_path) {
        failures.push((
            "minimal_uasset_v5_with_properties.uasset",
            e.to_string().into(),
        ));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            props_path.display(),
            std::fs::metadata(&props_path).map_or(0, |m| m.len())
        );
    }

    let containers_path = out_dir.join("minimal_uasset_v5_with_containers.uasset");
    if let Err(e) = uasset::write_minimal_ue4_27_with_containers(&containers_path) {
        failures.push((
            "minimal_uasset_v5_with_containers.uasset",
            e.to_string().into(),
        ));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            containers_path.display(),
            std::fs::metadata(&containers_path).map_or(0, |m| m.len())
        );
    }

    let extended_path = out_dir.join("minimal_uasset_v5_with_extended_types.uasset");
    if let Err(e) = uasset::write_minimal_ue4_27_with_extended_types(&extended_path) {
        failures.push((
            "minimal_uasset_v5_with_extended_types.uasset",
            e.to_string().into(),
        ));
    } else {
        uasset_written += 1;
        println!(
            "  {} ({} bytes)",
            extended_path.display(),
            std::fs::metadata(&extended_path).map_or(0, |m| m.len())
        );
    }
    println!("\nGenerated {uasset_written} of {uasset_total} uasset fixtures.");

    // Externally-produced `.usmap` fixtures (issue #376). Built by raw
    // byte writes following CUE4Parse's wire-format spec, NOT by
    // `paksmith-core::testing::usmap`'s builders. Catches writer/reader
    // shared bugs that round-trip silently against the in-tree builder.
    println!("\nGenerating external .usmap fixtures (issue #376)...");
    let external_v0_path = out_dir.join("external_minimal_v0.usmap");
    if let Err(e) = external_usmap::write_external_minimal_v0_usmap(&external_v0_path) {
        failures.push(("external_minimal_v0.usmap", e.to_string().into()));
    } else {
        println!(
            "  {} ({} bytes)",
            external_v0_path.display(),
            std::fs::metadata(&external_v0_path).map_or(0, |m| m.len())
        );
    }
    let external_v4_path = out_dir.join("external_minimal_v4.usmap");
    if let Err(e) = external_usmap::write_external_minimal_v4_usmap(&external_v4_path) {
        failures.push(("external_minimal_v4.usmap", e.to_string().into()));
    } else {
        println!(
            "  {} ({} bytes)",
            external_v4_path.display(),
            std::fs::metadata(&external_v4_path).map_or(0, |m| m.len())
        );
    }

    // Phase 2f cross-validation against `unreal_asset` was removed:
    // the oracle shares paksmith's pre-fix usmap bugs (byte-inverted
    // magic + name-length off-by-one), so "parity" was agreement on
    // broken bytes. CUE4Parse-spec parity is now enforced by the
    // external fixtures generated above plus
    // `external_usmap_integration.rs` in paksmith-core.

    // Phase 2g cross-validation: Array<Struct> decoder smoke test
    // (paksmith property-tree + oracle table-level agreement). In-
    // memory only (no on-disk fixture).
    println!("\nValidating Phase 2g Array<Struct> decoder fixture...");
    if let Err(e) = uasset::validate_array_of_struct_fixture() {
        failures.push(("phase-2g Array<Struct>", e.to_string().into()));
    } else {
        println!(
            "  array_of_struct_fixture: paksmith decoded Inventory[2] of \
             InventorySlot{{ItemId, Count}}; oracle accepts the wire bytes \
             (table-level)"
        );
    }

    // Phase 5a AES-encrypted pak fixtures are VENDORED-STATIC: committed to
    // tests/fixtures/ and excluded from the CI rm+regenerate cycle. They are
    // NOT written by this generator. See tests/fixtures/PROVENANCE-encrypted.md
    // and crates/paksmith-fixture-gen/src/encryption.rs for attribution + key.

    if !failures.is_empty() {
        eprintln!("\n{} fixture(s) failed:", failures.len());
        for (name, err) in &failures {
            eprintln!("  {name}: {err}");
        }
        std::process::exit(1);
    }
}
