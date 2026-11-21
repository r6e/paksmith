//! Block decoders the containers share: one compressed block in, its
//! output in a caller's buffer, with every output reservation made
//! through the caller so the caller attributes a failure.

use std::collections::TryReserveError;

/// Maximum factor by which one raw LZ4 block can inflate: a block of
/// N compressed bytes decodes to at most `N × 255` output bytes.
/// Literals copy 1:1; the only amplifying construct is a match-length
/// extension byte, and each 0xFF extension byte contributes at most
/// 255 output bytes (LZ4 Block Format). The true supremum is strictly
/// below 255 (offset/token overhead is never zero), so `N × 255` is a
/// safe over-estimate that never under-sizes a valid decode.
const MAX_LZ4_BLOCK_EXPANSION_RATIO: u64 = 255;

/// A block format [`decode_block`] decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    /// A raw LZ4 block, with no frame header or size prefix.
    Lz4,
}

impl Codec {
    /// The codec's name in operator logs.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Lz4 => "lz4",
        }
    }
}

/// Why [`decode_block`] failed.
#[derive(Debug)]
pub(crate) enum CodecError {
    /// The output buffer the block needs, this many bytes, is larger than
    /// a `usize` holds on this platform.
    BoundExceedsPlatformUsize(u64),
    /// The caller's `reserve` failed with this error.
    Reserve(crate::PaksmithError),
    /// `src` is not a block that decodes within the budget: the decoder's
    /// message.
    Decode(String),
}

/// Decode the block `src` and append its output, at most `budget` bytes,
/// to `out`. On success the bytes `out` gained are exactly the block's
/// output; on error `out` is left as it was.
///
/// Each output reservation is one `try_reserve_exact`, handed to `reserve`
/// with the bytes it requests; `reserve` must fail when the reservation
/// did.
pub(crate) fn decode_block(
    codec: Codec,
    src: &[u8],
    out: &mut Vec<u8>,
    budget: u64,
    mut reserve: impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<(), CodecError> {
    let start = out.len();
    let decoded = match codec {
        Codec::Lz4 => decode_lz4(src, out, budget, &mut reserve),
    };
    if decoded.is_err() {
        out.truncate(start);
    }
    decoded
}

/// Decode a raw LZ4 block into a zero-filled tail of
/// [`lz4_block_output_cap`] bytes. The tail is also the bomb cap: the
/// decoder fails a block that would expand past it.
fn decode_lz4(
    src: &[u8],
    out: &mut Vec<u8>,
    budget: u64,
    reserve: &mut impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<(), CodecError> {
    let start = out.len();
    let bound = lz4_block_output_cap(budget, src.len() as u64);
    let cap = usize::try_from(bound).map_err(|_| CodecError::BoundExceedsPlatformUsize(bound))?;
    reserve(out.try_reserve_exact(cap), cap).map_err(CodecError::Reserve)?;
    out.resize(start + cap, 0);
    let produced = lz4_flex::block::decompress_into(src, &mut out[start..])
        .map_err(|e| CodecError::Decode(e.to_string()))?;
    out.truncate(start + produced);
    Ok(())
}

/// Bound the pre-decode output reservation for one LZ4 block.
///
/// `budget` can be entry-scale rather than block-scale (a pak entry's
/// final block is budgeted at the entry's whole remaining output, bounded
/// upstream by the 8 GiB `MAX_UNCOMPRESSED_ENTRY_BYTES` open-time cap):
/// pre-allocating it verbatim would let a tiny crafted block force a
/// multi-gigabyte eager allocation (memory-amplification DoS, #636).
/// Intersecting with `compressed_len` × [`MAX_LZ4_BLOCK_EXPANSION_RATIO`]
/// keeps the reservation input-proportional: a valid block's real output
/// is always `≤ compressed_len × 255`, so the cap is transparent for
/// well-formed blocks and only bites the crafted case.
fn lz4_block_output_cap(budget: u64, compressed_len: u64) -> u64 {
    budget.min(compressed_len.saturating_mul(MAX_LZ4_BLOCK_EXPANSION_RATIO))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output already in `out` when a block is decoded onto it.
    const EARLIER: &[u8] = b"an earlier block";

    /// Varied bytes with repeats for LZ4 to match, so a decode that skips
    /// writing leaves output that differs from them.
    fn plaintext() -> Vec<u8> {
        (0..4096u32).map(|i| (i * 7 % 251) as u8).collect()
    }

    /// `src` decoded as LZ4 within `budget` onto [`EARLIER`], with every
    /// reservation's size.
    fn decode_lz4(src: &[u8], budget: u64) -> (Result<(), CodecError>, Vec<u8>, Vec<usize>) {
        let mut out = EARLIER.to_vec();
        let mut requests = Vec::new();
        let decoded = decode_block(Codec::Lz4, src, &mut out, budget, |reserved, n| {
            requests.push(n);
            reserved.map_err(|e| crate::PaksmithError::Io(e.into()))
        });
        (decoded, out, requests)
    }

    #[test]
    fn lz4_decode_block_known_answer() {
        let plaintext = plaintext();
        let src = lz4_flex::block::compress(&plaintext);
        for budget in [plaintext.len() as u64, u64::MAX] {
            let (decoded, out, _) = decode_lz4(&src, budget);
            assert!(decoded.is_ok(), "budget {budget}: {decoded:?}");
            assert_eq!(out, [EARLIER, &plaintext].concat(), "budget {budget}");
        }
    }

    #[test]
    fn lz4_is_labelled_lz4() {
        assert_eq!(Codec::Lz4.label(), "lz4");
    }

    #[test]
    fn lz4_reserve_requests_min_budget_and_255x() {
        let plaintext = plaintext();
        let src = lz4_flex::block::compress(&plaintext);
        for (budget, requested) in [
            (plaintext.len() as u64, plaintext.len()),
            (u64::MAX, src.len() * 255),
        ] {
            let (decoded, _, requests) = decode_lz4(&src, budget);
            assert!(decoded.is_ok(), "budget {budget}: {decoded:?}");
            assert_eq!(requests, [requested], "budget {budget}");
        }
    }

    #[test]
    fn lz4_output_past_budget_is_corrupt() {
        let plaintext = plaintext();
        let src = lz4_flex::block::compress(&plaintext);
        let (decoded, out, _) = decode_lz4(&src, plaintext.len() as u64 - 1);
        assert!(matches!(decoded, Err(CodecError::Decode(_))), "{decoded:?}");
        assert_eq!(out, EARLIER);
    }

    /// A well-formed LZ4 block: a 64 KiB output derived from ~300
    /// compressed bytes. `compressed_len × 255` (76_500) exceeds the
    /// pak-derived budget, so the cap is transparent — it
    /// returns the budget unchanged and never under-sizes a valid
    /// decode.
    #[test]
    fn lz4_block_output_cap_passes_through_valid_block() {
        assert_eq!(lz4_block_output_cap(65_536, 300), 65_536);
    }

    /// The security property (#636): a 400-byte compressed block that
    /// claims a 4 GiB `compression_block_size` must NOT force a 4 GiB
    /// eager allocation. The cap clamps the reservation to
    /// input-proportional size (`400 × 255`), so the crafted claim
    /// cannot amplify.
    #[test]
    fn lz4_block_output_cap_bounds_crafted_oversized_claim() {
        assert_eq!(lz4_block_output_cap(4 * 1024 * 1024 * 1024, 400), 102_000);
    }

    /// `compressed_len × 255` must saturate (not overflow/panic) for a
    /// pathological length, in which case the budget wins the
    /// `min`. Pins the `saturating_mul` against a `checked`/wrapping
    /// mutant: `0x0101_0101_0101_0102 × 255` wraps to 254.
    #[test]
    fn lz4_block_output_cap_saturates_without_overflow() {
        assert_eq!(lz4_block_output_cap(1_000, u64::MAX), 1_000);
        assert_eq!(lz4_block_output_cap(1_000, 0x0101_0101_0101_0102), 1_000);
    }
}
