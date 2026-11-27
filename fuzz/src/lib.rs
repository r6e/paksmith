//! The harness the pak block-codec fuzz targets share.

use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;
use paksmith_core::testing::wire::{
    GZIP_SYNTH_PATH, LZ4_SYNTH_PATH, ZSTD_SYNTH_PATH, build_v8b_gzip_pak, build_v8b_lz4_pak,
    build_v8b_zstd_pak,
};

/// Cap on the wire-claimed sizes (both `uncompressed_size` and
/// `compression_block_size` stay below ~1 MiB) so a fuzz iteration's
/// honest work (output buffer + `Vec` writer) stays small and
/// iterations stay fast.
pub const MAX_CLAIMED_BYTES: u32 = 1 << 20;

/// A `paksmith_core::testing::wire` builder of a v8b pak with one entry
/// in a block codec, paired with the path of the entry it writes.
#[derive(Debug, Clone, Copy)]
pub struct BlockPak {
    build: fn(&[Vec<u8>], u64, u32) -> Vec<u8>,
    path: &'static str,
}

/// A pak of one LZ4 entry.
pub const LZ4: BlockPak = BlockPak {
    build: build_v8b_lz4_pak,
    path: LZ4_SYNTH_PATH,
};

/// A pak of one Zstd entry.
pub const ZSTD: BlockPak = BlockPak {
    build: build_v8b_zstd_pak,
    path: ZSTD_SYNTH_PATH,
};

/// A pak of one Gzip entry.
pub const GZIP: BlockPak = BlockPak {
    build: build_v8b_gzip_pak,
    path: GZIP_SYNTH_PATH,
};

/// Wrap `data` in the v8b pak `pak` builds and read its entry back
/// through [`PakReader`].
///
/// `data` is
/// `[4-byte LE uncompressed_size][4-byte LE block_size][split byte][block bytes]`,
/// with both claims taken modulo [`MAX_CLAIMED_BYTES`]. Shorter input is
/// ignored. The split byte picks where the block bytes divide into one or
/// two blocks.
///
/// The pak is structurally valid (real footer, slot table, legacy index +
/// entry SHA1), so iterations spend their budget in the decode loop
/// rather than bouncing off footer/index validation, and the read takes
/// the REAL public path (`PakReader::from_bytes` → `read_entry_to`), not a
/// bench seam.
///
/// The targets have no committed seed corpus: a fixture file wouldn't be
/// well-formed for this layout, so the fuzzer starts from scratch.
///
/// A fuzz run sees a panic, an abort, an ASan fault, a timeout or an
/// allocation at libFuzzer's malloc limit. The panics include a read that
/// succeeds with a size other than the claimed `uncompressed_size`, or
/// with output other than the size it returns. Every claim stays below
/// 1 MiB, so a reservation bounded by the claim stays under the malloc
/// limit and goes unseen. One that reaches the limit is reported, such as
/// the `compressed_len × 32768` a Zstd cap that lost its budget term
/// would reserve for a block of 64 KiB or more. Each target names the
/// codec unit tests that pin its output bounds.
pub fn fuzz_v8b_block_codec_pak(data: &[u8], pak: &BlockPak) {
    if data.len() < 9 {
        return;
    }
    let uncompressed_size =
        u64::from(u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) % MAX_CLAIMED_BYTES);
    let block_size =
        u32::from_le_bytes(data[4..8].try_into().expect("4 bytes")) % MAX_CLAIMED_BYTES;
    let split = u64::from(data[8]);
    let rest = &data[9..];

    // One or two compression blocks: a mid-payload pivot derived from
    // the split byte exercises the non-final block-size invariant and
    // the multi-block accounting; a pivot of 0 / len degenerates to a
    // single block. The multiply is widened to u64 so it can't
    // overflow usize on a 32-bit target with a pathologically large
    // input (fuzz builds carry overflow checks); the quotient is
    // <= rest.len(), so the narrowing cast back is lossless.
    let pivot = (split * rest.len() as u64 / 256) as usize;
    let streams: Vec<Vec<u8>> = if pivot > 0 && pivot < rest.len() {
        vec![rest[..pivot].to_vec(), rest[pivot..].to_vec()]
    } else {
        vec![rest.to_vec()]
    };

    let bytes = (pak.build)(&streams, uncompressed_size, block_size);
    let Ok(reader) = PakReader::from_bytes(bytes) else {
        return;
    };
    let mut out = Vec::new();
    if let Ok(n) = reader.read_entry_to(pak.path, &mut out) {
        assert_eq!(n, uncompressed_size, "read size isn't the claimed size");
        assert_eq!(out.len() as u64, n, "output size isn't the read size");
    }
}
