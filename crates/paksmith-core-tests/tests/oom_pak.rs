//! Integration tests for the typed OOM-failure variants
//! [`DecompressionFault::CompressedBlockReserveFailed`] and
//! [`DecompressionFault::ZlibScratchReserveFailed`] (issue #124).
//!
//! These variants fire only on real allocator pressure in production,
//! which integration tests can't reliably induce. Instead, we exercise
//! the production code paths through `__test_utils`-feature-gated
//! injection seams that synthesize a `TryReserveError` at the two
//! `try_reserve*` sites in `stream_zlib_to`. See
//! `paksmith_core::testing::oom` for the seam API.
//!
//! The Display unit tests for these variants live in
//! `crates/paksmith-core/src/error.rs::tests` (added in PR #123 R3) and
//! protect the wire-stable string contract; the tests here protect the
//! production-path construction contract — that the typed errors
//! actually surface from `read_entry` with the right `block_index` and
//! (for `ZlibScratchReserveFailed`) `already_committed` values.
//!
//! **Naming convention:** existing decompression-failure tests in
//! `pak_integration.rs` use `read_<scope>_rejects_<failure>` (e.g.
//! `read_zlib_rejects_decompression_bomb`). The tests here use
//! `read_entry_surfaces_<failure>_under_oom` instead — the input
//! isn't malformed and isn't being "rejected"; it's a valid pak
//! whose typed-error path we're surfacing through an injected
//! allocator failure. `surfaces` is more semantically accurate for
//! the seam-driven case.

// Integration test: synthesizes pak bytes with `usize → u32` length
// casts on test-controlled inputs.
#![allow(clippy::cast_possible_truncation)]

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PAK_MAGIC;
use paksmith_core::error::{AllocationContext, DecompressionFault, IndexParseFault};
use paksmith_core::testing::oom::{SeamSite, arm_at};
use paksmith_core::testing::v10::{V10Fixture, build_v10_buffer};
// Issue #140: shared v3+ wire-format synthesizers.
use paksmith_core::testing::wire::{write_fstring, write_fstring_utf16, write_pak_entry};

/// Build a single-entry v6 pak with a zlib-compressed payload.
/// Returns the assembled bytes for routing through
/// `PakReader::from_bytes` (issue #255).
///
/// `decompressed: &[u8]` is what the entry should decompress to;
/// it's encoded as a single zlib block at default compression level
/// and packaged with the appropriate v6 wire structure.
fn build_v6_zlib_pak(decompressed: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(decompressed).unwrap();
    let compressed = enc.finish().unwrap();

    let compressed_size = compressed.len() as u64;
    let uncompressed_size = decompressed.len() as u64;
    let block_size = decompressed.len() as u32;
    let sha1 = [0u8; 20];

    // Block offsets are stored relative to the entry header start;
    // the per-block read in `stream_zlib_to` adds them to the
    // entry's absolute offset. The in-data header sits between
    // entry start and the payload, so `block_start = header_size`.
    let header_size: u64 = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4; // 1 block
    let blocks: [(u64, u64); 1] = [(header_size, header_size + compressed_size)];

    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        compressed_size,
        uncompressed_size,
        1, // zlib
        &sha1,
        &blocks,
        block_size,
        false, // not encrypted
    );
    data_section.extend_from_slice(&compressed);

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/x.uasset");
    write_pak_entry(
        &mut index_section,
        0,
        compressed_size,
        uncompressed_size,
        1, // zlib
        &sha1,
        &blocks,
        block_size,
        false, // not encrypted
    );

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    let mut pak = data_section;
    pak.extend_from_slice(&index_section);

    // Legacy 44-byte v6 footer.
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]); // index hash

    pak
}

/// Arm the OOM seam at the `try_reserve_exact(block_len_usize)` site
/// (pre-decode), call `read_entry`, and assert the typed
/// `CompressedBlockReserveFailed` error surfaces with the expected
/// `block_index`.
///
/// This is the pre-decode reserve path: `already_committed` does not
/// exist on this variant because no decompression has happened yet at
/// the failure point.
#[test]
fn read_entry_surfaces_compressed_block_reserve_failed_under_oom() {
    let bytes = build_v6_zlib_pak(b"some payload that will never get decoded");
    let reader = PakReader::from_bytes(bytes).unwrap();

    // RAII guard: arm returns a DisarmGuard whose Drop clears thread-
    // local arm state, so a panic between arm and assertion can't
    // leak state into the next test on this thread.
    let _guard = arm_at(SeamSite::CompressedReserve, 0); // fail the very next try_reserve_exact
    let err = reader.read_entry("Content/x.uasset").unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::Decompression {
                fault: DecompressionFault::CompressedBlockReserveFailed { block_index: 0, .. },
                ..
            }
        ),
        "expected Decompression{{CompressedBlockReserveFailed {{ block_index: 0 }}}}; got {err:?}"
    );
}

/// Arm the OOM seam at the `try_reserve(n)` site (mid-decode loop),
/// skip the first invocation so iteration 1 succeeds and commits
/// bytes to `block_out`, then fail iteration 2's reservation.
///
/// The R2 sev-3 finding from PR #123 required pinning
/// `already_committed` to a known concrete value to prove the
/// mid-decode path is structurally distinguished from the pre-decode
/// path. We pin `already_committed > 0` (rather than an exact value)
/// because the per-iteration `n` returned by `flate2`'s
/// `ZlibDecoder::read` isn't part of the wire-stability contract and
/// can vary across `flate2`/`libz` versions. A `> 0` assertion is
/// sufficient: it proves the second-iteration path was taken (which
/// `CompressedBlockReserveFailed` cannot satisfy by construction —
/// that variant has no `already_committed` field at all).
#[test]
fn read_entry_surfaces_zlib_scratch_reserve_failed_with_committed_bytes_under_oom() {
    // 64 KiB payload — larger than the 32 KiB scratch buffer in
    // `stream_zlib_to`, so the decode loop runs more than once.
    let payload = vec![0u8; 64 * 1024];
    let bytes = build_v6_zlib_pak(&payload);
    let reader = PakReader::from_bytes(bytes).unwrap();

    let _guard = arm_at(SeamSite::ScratchReserve, 1); // skip iter 1, fail iter 2
    let err = reader.read_entry("Content/x.uasset").unwrap_err();

    let already_committed = match &err {
        PaksmithError::Decompression {
            fault:
                DecompressionFault::ZlibScratchReserveFailed {
                    block_index: 0,
                    already_committed,
                    ..
                },
            ..
        } => *already_committed,
        other => panic!(
            "expected Decompression{{ZlibScratchReserveFailed {{ block_index: 0 }}}}; got {other:?}"
        ),
    };

    assert!(
        already_committed > 0,
        "ZlibScratchReserveFailed must report already_committed > 0 on iter-2 \
         failure (proves the mid-decode-with-prior-commit path, structurally \
         distinct from CompressedBlockReserveFailed which has no \
         already_committed field by construction); got already_committed = {already_committed}"
    );
    // Upper bound: after exactly one successful iteration, committed
    // bytes can't exceed the 32 KiB scratch buffer in
    // `stream_zlib_to`. A regression that resized the scratch buffer,
    // accumulated multiple iterations before failing, or somehow
    // double-counted would trip this. The `> 0` assertion above is
    // the structurally-important one (proves iter-2 path); this just
    // adds a cheap upper-bound sanity check.
    assert!(
        already_committed <= 32 * 1024,
        "already_committed ({already_committed}) exceeded scratch-buffer upper bound (32 KiB) \
         after exactly one successful iteration — investigate whether scratch sizing changed \
         or the seam fired on a later iteration than expected"
    );
}

/// Sanity check: with no OOM seam armed, `read_entry` succeeds and
/// returns the original payload. Ensures the seam is actually inert
/// in the pass-through case (i.e. the `#[cfg(feature = "__test_utils")]`
/// gating doesn't accidentally fail closed).
#[test]
fn read_entry_succeeds_when_oom_seam_unarmed() {
    let payload = b"the seam is inert when unarmed";
    let bytes = build_v6_zlib_pak(payload);
    let reader = PakReader::from_bytes(bytes).unwrap();

    let bytes = reader.read_entry("Content/x.uasset").unwrap();
    assert_eq!(bytes, payload);
}

// ----------------------------------------------------------------------
// Issue #191: parser-OOM seam tests.
//
// These exercise the three `try_reserve_exact` sites added to
// `read_fstring` (UTF-16 + UTF-8 branches) and the FDI walk's
// full-path concat in `path_hash.rs`. The decompression-OOM tests
// above go through `PakReader::open` end-to-end because the seam
// fires inside `read_entry`/`stream_zlib_to`; these parser seams
// fire during index parsing, so we drive `PakIndex::read_from`
// directly for a tighter test boundary.
// ----------------------------------------------------------------------

use paksmith_core::container::pak::index::{PakEntryHeader, PakIndex};
use paksmith_core::container::pak::version::PakVersion;
use std::io::Cursor;

/// Arm the UTF-8 FString OOM seam and call `PakIndex::read_from`
/// with v3-v9 wire bytes whose first FString (the mount) is
/// UTF-8-encoded. The seam fires on the mount's try_reserve;
/// downstream parser work is unreachable. Asserts the typed
/// `AllocationFailed { context: FStringUtf8Bytes }` surfaces.
#[test]
fn read_fstring_utf8_surfaces_allocation_failed_under_oom() {
    let mut buf: Vec<u8> = Vec::new();
    // UTF-8 mount (positive length); contents don't matter — the
    // seam fires before the bytes are consumed.
    write_fstring(&mut buf, "/Mount/");
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::FstringUtf8, 0); // fail the first try_reserve
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::FrozenIndex, // v9 — dispatches to flat parser
        0,
        u64::MAX,
        u64::MAX,
        &[],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FStringUtf8Bytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{FStringUtf8Bytes}}; got {err:?}"
    );
}

/// Arm the UTF-16 FString OOM seam and call `PakIndex::read_from`
/// with wire bytes whose first FString (the mount) is UTF-16-
/// encoded (negative length per the FString sign convention).
/// Asserts the typed `AllocationFailed { context:
/// FStringUtf16CodeUnits }` surfaces.
#[test]
fn read_fstring_utf16_surfaces_allocation_failed_under_oom() {
    let mut buf: Vec<u8> = Vec::new();
    // UTF-16 mount (negative length sign). Contents don't matter.
    write_fstring_utf16(&mut buf, "/Mount/");
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::FstringUtf16, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::FrozenIndex,
        0,
        u64::MAX,
        u64::MAX,
        &[],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FStringUtf16CodeUnits,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{FStringUtf16CodeUnits}}; got {err:?}"
    );
}

/// Arm the FDI full-path OOM seam and parse a v10+ index buffer
/// with a non-empty FDI. The seam fires on the FIRST FDI entry's
/// `dir_prefix + file_name` concat reservation, before
/// downstream PHI cross-check work. Asserts the typed
/// `AllocationFailed { context: FdiFullPathBytes }` surfaces.
#[test]
fn read_fdi_full_path_surfaces_allocation_failed_under_oom() {
    // v10+ buffer with one FDI entry; mount and per-entry FStrings
    // both succeed (the seam is armed on a SPECIFIC site, not all
    // try_reserves). The FDI walk reaches the full-path concat
    // and the seam fires there.
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        fdi: vec![("Content/".into(), vec![("hero.uasset".into(), 0)])],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::FdiFullPath, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FdiFullPathBytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{FdiFullPathBytes}}; got {err:?}"
    );
}

// --- #270 seams routed through `try_reserve_index` ---------------------
//
// The 9 tests below cover the new SeamSite variants introduced by
// the #270 seam-composition refactor, where `try_reserve_index`
// gained an `Option<SeamSite>` parameter. Each arms the named seam,
// drives the production parser, and asserts the typed
// `AllocationFailed { context: ... }` fault surfaces with the
// expected `AllocationContext` discriminant.

/// Arm the flat-index entries reserve and drive a v3-v9 PakIndex
/// parse with mount + entry_count=1. The seam fires on the entries
/// vec reservation in `read_flat_from`, before the per-entry
/// records would be read.
#[test]
fn read_flat_index_entries_surfaces_allocation_failed_under_oom() {
    let mut buf: Vec<u8> = Vec::new();
    write_fstring(&mut buf, "/Mount/");
    buf.write_u32::<LittleEndian>(1).unwrap();
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::FlatIndexEntries, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::FrozenIndex,
        0,
        u64::MAX,
        u64::MAX,
        &[],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FlatIndexEntries,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{FlatIndexEntries}}; got {err:?}"
    );
}

/// Arm the inline compression-blocks reserve and drive
/// `PakEntryHeader::read_from` (v3-v9 layout) with a zlib-compressed
/// entry header carrying `block_count=1`. The seam fires on the
/// blocks vec reservation, before the per-block u64 pairs would be
/// read.
#[test]
fn read_inline_compression_blocks_surfaces_allocation_failed_under_oom() {
    let mut buf: Vec<u8> = Vec::new();
    let sha1 = [0u8; 20];
    write_pak_entry(
        &mut buf,
        0, // offset_field
        0, // compressed_size
        0, // uncompressed_size
        1, // compression_method: zlib (raw v3-v7 ID)
        &sha1,
        &[(0, 0)], // 1 block
        0x10000,
        false,
    );
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::InlineCompressionBlocks, 0);
    let err = PakEntryHeader::read_from(&mut cursor, PakVersion::IndexEncryption, &[]).unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::InlineCompressionBlocks,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{InlineCompressionBlocks}}; got {err:?}"
    );
}

/// Arm the encoded compression-blocks reserve and drive
/// `PakEntryHeader::read_encoded` with a bit-packed header
/// representing a 2-block zlib entry (block_count > 1 forces the
/// non-trivial multi-block path that reserves the blocks vec). The
/// seam fires on the blocks vec reservation.
///
/// `bits` layout: `compression_method=1 (zlib)` at bits 23-28
/// (`0x0080_0000`), `block_count=2` at bits 6-21 (`0x0000_0080`),
/// `block_size_field=0x10` at bits 0-5 (→ block_size = 32 KiB), and
/// the variable-width bits 29/30/31 set so `compressed_size`,
/// `uncompressed_size`, and `offset` read as u32 (= 0 each) rather
/// than u64. Total wire: 4-byte `bits` + 12 bytes (three u32 zeros).
#[test]
fn read_encoded_compression_blocks_surfaces_allocation_failed_under_oom() {
    let bits: u32 = 0xE080_0090;
    let mut buf: Vec<u8> = Vec::new();
    buf.write_u32::<LittleEndian>(bits).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap(); // offset (u32, bit 31)
    buf.write_u32::<LittleEndian>(0).unwrap(); // uncompressed_size (u32, bit 30)
    buf.write_u32::<LittleEndian>(0).unwrap(); // compressed_size (u32, bit 29)
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::EncodedCompressionBlocks, 0);
    let err = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::EncodedCompressionBlocks,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{EncodedCompressionBlocks}}; got {err:?}"
    );
}

/// Arm the v10+ main-index bytes reserve and drive a v10+ parse.
/// The seam fires on the first try_reserve_index in
/// `read_v10_plus_from`, before any wire bytes are consumed from
/// the main-index region.
#[test]
fn read_v10_main_index_bytes_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture::default());
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10MainIndexBytes, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10MainIndexBytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10MainIndexBytes}}; got {err:?}"
    );
}

/// Arm the v10+ encoded-entries blob reserve and drive a v10+ parse
/// with a non-empty `encoded_entries` payload (so
/// `encoded_entries_size > 0` and the corresponding reservation is
/// reached). The seam fires on the encoded-entries vec reservation.
#[test]
fn read_v10_encoded_entries_bytes_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        encoded_entries: vec![0u8; 32],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10EncodedEntriesBytes, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10EncodedEntriesBytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10EncodedEntriesBytes}}; got {err:?}"
    );
}

/// Arm the v10+ non-encoded entries vec reserve and drive a v10+
/// parse with `non_encoded_count > 0`. The seam fires on the
/// non-encoded entries vec reservation.
#[test]
fn read_v10_non_encoded_entries_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        non_encoded_count: 1,
        non_encoded_records: vec![0u8; 64],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10NonEncodedEntries, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10NonEncodedEntries,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10NonEncodedEntries}}; got {err:?}"
    );
}

/// Arm the v10+ FDI bytes reserve and drive a v10+ parse with a
/// non-empty `fdi` so `fdi_size > 0`. The seam fires on the FDI
/// bytes vec reservation, before any FDI entries are walked.
#[test]
fn read_v10_fdi_bytes_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        fdi: vec![("Content/".into(), vec![("hero.uasset".into(), 0)])],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10FdiBytes, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10FdiBytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10FdiBytes}}; got {err:?}"
    );
}

/// Arm the v10+ PHI bytes reserve and drive a v10+ parse with a PHI
/// region present (`has_path_hash_index: true` by default and a
/// non-empty fdi so the auto-derived PHI entries make
/// `phi_size > 0`). The seam fires on the PHI bytes vec
/// reservation.
#[test]
fn read_v10_phi_bytes_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        fdi: vec![("Content/".into(), vec![("hero.uasset".into(), 0)])],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10PhiBytes, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10PhiBytes,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10PhiBytes}}; got {err:?}"
    );
}

/// Arm the v10+ flat-index entries vec reserve and drive a v10+
/// parse with `file_count > 0` and a non-empty FDI that satisfies
/// the `file_count <= fdi_size / MIN_FDI_FILE_RECORD_BYTES` bound
/// check immediately preceding the reservation. The seam fires on
/// the entries vec reservation in the v10+ code path (parallel to
/// `FlatIndexEntries` but reached via the v10+ index parser).
#[test]
fn read_v10_index_entries_surfaces_allocation_failed_under_oom() {
    let (buf, main_size) = build_v10_buffer(V10Fixture {
        file_count: 1,
        fdi: vec![("Content/".into(), vec![("hero.uasset".into(), 0)])],
        ..V10Fixture::default()
    });
    let file_size = buf.len() as u64;
    let mut cursor = Cursor::new(buf);

    let _guard = arm_at(SeamSite::V10IndexEntries, 0);
    let err = PakIndex::read_from(
        &mut cursor,
        PakVersion::PathHashIndex,
        0,
        main_size,
        file_size,
        &[None],
    )
    .unwrap_err();

    assert!(
        matches!(
            &err,
            PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::V10IndexEntries,
                    ..
                },
            }
        ),
        "expected AllocationFailed{{V10IndexEntries}}; got {err:?}"
    );
}
