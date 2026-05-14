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

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use paksmith_core::PaksmithError;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PAK_MAGIC;
use paksmith_core::error::DecompressionFault;
use paksmith_core::testing::oom::{arm_compressed_reserve_oom, arm_scratch_reserve_oom};

/// Build a single-entry v6 pak with a zlib-compressed payload.
/// Returns the tempfile and the entry path.
///
/// `decompressed: &[u8]` is what the entry should decompress to;
/// it's encoded as a single zlib block at default compression level
/// and packaged with the appropriate v6 wire structure.
fn build_v6_zlib_pak(decompressed: &[u8]) -> tempfile::NamedTempFile {
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

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();
    tmp
}

fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

#[allow(clippy::too_many_arguments)]
fn write_pak_entry(
    buf: &mut Vec<u8>,
    offset_field: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    sha1: &[u8; 20],
    blocks: &[(u64, u64)],
    block_size: u32,
) {
    buf.write_u64::<LittleEndian>(offset_field).unwrap();
    buf.write_u64::<LittleEndian>(compressed_size).unwrap();
    buf.write_u64::<LittleEndian>(uncompressed_size).unwrap();
    buf.write_u32::<LittleEndian>(compression_method).unwrap();
    buf.extend_from_slice(sha1);
    if compression_method != 0 {
        buf.write_u32::<LittleEndian>(blocks.len() as u32).unwrap();
        for (start, end) in blocks {
            buf.write_u64::<LittleEndian>(*start).unwrap();
            buf.write_u64::<LittleEndian>(*end).unwrap();
        }
    }
    buf.push(0); // not encrypted
    buf.write_u32::<LittleEndian>(block_size).unwrap();
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
    let tmp = build_v6_zlib_pak(b"some payload that will never get decoded");
    let reader = PakReader::open(tmp.path()).unwrap();

    // RAII guard: arm returns a DisarmGuard whose Drop clears thread-
    // local arm state, so a panic between arm and assertion can't
    // leak state into the next test on this thread.
    let _guard = arm_compressed_reserve_oom(0); // fail the very next try_reserve_exact
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
    let tmp = build_v6_zlib_pak(&payload);
    let reader = PakReader::open(tmp.path()).unwrap();

    let _guard = arm_scratch_reserve_oom(1); // skip iter 1, fail iter 2
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
    let tmp = build_v6_zlib_pak(payload);
    let reader = PakReader::open(tmp.path()).unwrap();

    let bytes = reader.read_entry("Content/x.uasset").unwrap();
    assert_eq!(bytes, payload);
}
