//! Block decoders the containers share, and the zstd v1-frame gate the zstd
//! decoder and the `.usmap` parser apply to their input. A block decoder takes one
//! compressed block in and appends its output to a caller's buffer, with
//! every output reservation made through the caller so the caller
//! attributes a failure.

use std::collections::TryReserveError;
use std::io::{Cursor, Read};

use flate2::bufread::GzDecoder;
use zstd::zstd_safe::{self, DCtx};

use crate::fallible_read;

/// Maximum factor by which one raw LZ4 block can inflate: a block of
/// N compressed bytes decodes to at most `N × 255` output bytes.
/// Literals copy 1:1; the only amplifying construct is a match-length
/// extension byte, and each 0xFF extension byte contributes at most
/// 255 output bytes (LZ4 Block Format). The true supremum is strictly
/// below 255 (offset/token overhead is never zero), so `N × 255` is a
/// safe over-estimate that never under-sizes a valid decode.
const MAX_LZ4_BLOCK_EXPANSION_RATIO: u64 = 255;

/// Maximum factor by which zstd v1 and skippable frames can inflate:
/// N compressed bytes decode to fewer than `N × 32768` output bytes
/// (RFC 8878). A block's output is at most its frame's
/// Block_Maximum_Size, the smaller of Window_Size and 128 KiB, and the
/// block with the most output per byte is an RLE block of a 3-byte
/// Block_Header and one byte: 131072 / 4. A raw block copies its bytes
/// 1:1, a compressed block carries literals and sequences section
/// headers on top of its Block_Header, and frame headers (at least six
/// bytes with the magic) and skippable frames add input with no output.
const MAX_ZSTD_BLOCK_EXPANSION_RATIO: u64 = 32_768;

/// Test-only accessor for `MAX_ZSTD_BLOCK_EXPANSION_RATIO`, gated behind
/// the `__test_utils` feature like
/// [`crate::container::pak::max_uncompressed_entry_bytes`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_zstd_block_expansion_ratio() -> u64 {
    MAX_ZSTD_BLOCK_EXPANSION_RATIO
}

// zstd frame magics: the v1 frame's, and the range of sixteen that mark a
// skippable frame.
const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;
const ZSTD_SKIPPABLE_MAGIC_FIRST: u32 = 0x184D_2A50;
const ZSTD_SKIPPABLE_MAGIC_LAST: u32 = 0x184D_2A5F;

const NOT_ZSTD_V1_FRAMES: &str = "not zstd v1 or skippable frames";
const FRAME_PAST_STREAM: &str = "zstd frame runs past the block";
const PAST_OUTPUT_CAP: &str = "output past the block's bound";

/// A block format [`decode_block`] decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    /// A raw LZ4 block, with no frame header or size prefix.
    Lz4,
    /// One or more zstd v1 or skippable frames.
    Zstd,
    /// One gzip member, and any bytes after it, which are ignored.
    Gzip,
}

impl Codec {
    /// The codec's name in operator logs.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
            Self::Gzip => "gzip",
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
    /// The decoder could not allocate its state.
    ContextUnavailable,
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
        Codec::Zstd => decode_zstd(src, out, budget, &mut reserve),
        Codec::Gzip => decode_gzip(src, out, budget, &mut reserve),
    };
    if decoded.is_err() {
        out.truncate(start);
    }
    decoded
}

/// Decode a raw LZ4 block into a zero-filled tail of [`block_output_cap`]
/// bytes. The tail is also the bomb cap: the decoder fails a block that
/// would expand past it.
fn decode_lz4(
    src: &[u8],
    out: &mut Vec<u8>,
    budget: u64,
    reserve: &mut impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<(), CodecError> {
    let start = out.len();
    let bound = block_output_cap(budget, src.len() as u64, MAX_LZ4_BLOCK_EXPANSION_RATIO);
    let cap = reserve_output(out, bound, reserve)?;
    out.resize(start + cap, 0);
    let produced = lz4_flex::block::decompress_into(src, &mut out[start..])
        .map_err(|e| CodecError::Decode(e.to_string()))?;
    out.truncate(start + produced);
    Ok(())
}

/// Bound the pre-decode output reservation for one block of
/// `compressed_len` bytes in a codec that inflates by at most `ratio`.
///
/// `budget` can be entry-scale rather than block-scale (a pak entry's
/// final block is budgeted at the entry's whole remaining output, bounded
/// upstream by the 8 GiB `MAX_UNCOMPRESSED_ENTRY_BYTES` open-time cap):
/// pre-allocating it verbatim would let a tiny crafted block force a
/// multi-gigabyte eager allocation (memory-amplification DoS, #636).
/// Intersecting with `compressed_len × ratio` keeps the reservation
/// input-proportional: a valid block's real output is always within it,
/// so the cap is transparent for well-formed blocks and only bites the
/// crafted case.
fn block_output_cap(budget: u64, compressed_len: u64, ratio: u64) -> u64 {
    budget.min(compressed_len.saturating_mul(ratio))
}

/// Reserve `bound` bytes past `out`'s length, through `reserve`, and
/// return the bound as a `usize`.
fn reserve_output(
    out: &mut Vec<u8>,
    bound: u64,
    reserve: &mut impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<usize, CodecError> {
    let cap = usize::try_from(bound).map_err(|_| CodecError::BoundExceedsPlatformUsize(bound))?;
    reserve(out.try_reserve_exact(cap), cap).map_err(CodecError::Reserve)?;
    Ok(cap)
}

/// Decode `src`, one or more zstd v1 or skippable frames, one-shot into
/// `out`'s spare capacity: no zero-fill, and no window buffer sized by the
/// frame. libzstd fails a frame that needs more than the capacity, and
/// since capacity an earlier, larger block left in `out` can exceed this
/// block's reservation, output past the reservation fails here.
fn decode_zstd(
    src: &[u8],
    out: &mut Vec<u8>,
    budget: u64,
    reserve: &mut impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<(), CodecError> {
    zstd_v1_frames(src).map_err(|why| CodecError::Decode(why.to_owned()))?;
    let start = out.len();
    let bound = block_output_cap(budget, src.len() as u64, MAX_ZSTD_BLOCK_EXPANSION_RATIO);
    let cap = reserve_output(out, bound, reserve)?;
    let mut spare = Cursor::new(&mut *out);
    spare.set_position(start as u64);
    let produced = zstd_context(DCtx::try_create())?
        .decompress(&mut spare, src)
        .map_err(|code| CodecError::Decode(zstd_safe::get_error_name(code).to_owned()))?;
    if produced > cap {
        return Err(CodecError::Decode(PAST_OUTPUT_CAP.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    /// gzip decoders [`gzip_decoder`] has built on this thread.
    pub(crate) static GZIP_DECODERS_BUILT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Decode the gzip member that opens `src` onto `out`, with a decoder of
/// its own. It reserves only as output arrives and never grows `out`
/// past `budget + 1` bytes beyond its starting length, and a byte past
/// `budget` fails the block. flate2 checks the member's CRC-32 and
/// length trailer and leaves the bytes after it unread.
fn decode_gzip(
    src: &[u8],
    out: &mut Vec<u8>,
    budget: u64,
    reserve: &mut impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
) -> Result<(), CodecError> {
    let limit = budget.saturating_add(1);
    let ceiling =
        usize::try_from(limit).map_or(usize::MAX, |limit| out.len().saturating_add(limit));
    let produced = fallible_read::read_to_end_within(
        &mut gzip_decoder(src).take(limit),
        out,
        ceiling,
        |reserved, requested| reserve(reserved, requested).map_err(CodecError::Reserve),
        |e| CodecError::Decode(e.to_string()),
    )?;
    if produced as u64 > budget {
        return Err(CodecError::Decode(PAST_OUTPUT_CAP.to_owned()));
    }
    Ok(())
}

fn gzip_decoder(src: &[u8]) -> GzDecoder<&[u8]> {
    #[cfg(test)]
    GZIP_DECODERS_BUILT.with(|built| built.update(|n| n + 1));
    GzDecoder::new(src)
}

fn zstd_context(created: Option<DCtx<'static>>) -> Result<DCtx<'static>, CodecError> {
    created.ok_or(CodecError::ContextUnavailable)
}

/// Whether `stream` is one or more zstd v1 or skippable frames. Any crate in
/// the build can turn on zstd's `legacy` feature, which builds libzstd's
/// pre-v1 decoders, and a one-shot decode hands each frame to whichever
/// decoder its magic names.
pub(crate) fn is_zstd_v1_stream(stream: &[u8]) -> bool {
    zstd_v1_frames(stream).is_ok()
}

/// [`is_zstd_v1_stream`], with why not: [`NOT_ZSTD_V1_FRAMES`] for an empty
/// stream or a frame whose magic is neither, and libzstd's error name for
/// a frame of either magic that does not parse.
fn zstd_v1_frames(mut stream: &[u8]) -> Result<(), &'static str> {
    if stream.is_empty() {
        return Err(NOT_ZSTD_V1_FRAMES);
    }
    while !stream.is_empty() {
        let Some(magic) = stream.first_chunk::<4>().map(|m| u32::from_le_bytes(*m)) else {
            return Err(NOT_ZSTD_V1_FRAMES);
        };
        if !matches!(
            magic,
            ZSTD_FRAME_MAGIC | ZSTD_SKIPPABLE_MAGIC_FIRST..=ZSTD_SKIPPABLE_MAGIC_LAST
        ) {
            return Err(NOT_ZSTD_V1_FRAMES);
        }
        let len =
            zstd_safe::find_frame_compressed_size(stream).map_err(zstd_safe::get_error_name)?;
        stream = stream.get(len..).ok_or(FRAME_PAST_STREAM)?;
    }
    Ok(())
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

    /// `src` decoded as `codec` within `budget` onto `out`, with every
    /// reservation's size.
    fn decode_onto(
        codec: Codec,
        mut out: Vec<u8>,
        src: &[u8],
        budget: u64,
    ) -> (Result<(), CodecError>, Vec<u8>, Vec<usize>) {
        let mut requests = Vec::new();
        let decoded = decode_block(codec, src, &mut out, budget, |reserved, n| {
            requests.push(n);
            reserved.map_err(|e| crate::PaksmithError::Io(e.into()))
        });
        (decoded, out, requests)
    }

    /// `src` decoded as LZ4 within `budget` onto [`EARLIER`].
    fn decode_lz4(src: &[u8], budget: u64) -> (Result<(), CodecError>, Vec<u8>, Vec<usize>) {
        decode_onto(Codec::Lz4, EARLIER.to_vec(), src, budget)
    }

    /// The message a failed decode carries.
    #[cfg(feature = "__test_utils")]
    fn decode_message(decoded: &Result<(), CodecError>) -> Option<&str> {
        match decoded {
            Err(CodecError::Decode(message)) => Some(message),
            _ => None,
        }
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
    fn gzip_is_labelled_gzip() {
        assert_eq!(Codec::Gzip.label(), "gzip");
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
        assert_eq!(
            block_output_cap(65_536, 300, MAX_LZ4_BLOCK_EXPANSION_RATIO),
            65_536
        );
    }

    /// The security property (#636): a 400-byte compressed block that
    /// claims a 4 GiB `compression_block_size` must NOT force a 4 GiB
    /// eager allocation. The cap clamps the reservation to
    /// input-proportional size (`400 × 255`), so the crafted claim
    /// cannot amplify.
    #[test]
    fn lz4_block_output_cap_bounds_crafted_oversized_claim() {
        assert_eq!(
            block_output_cap(4 * 1024 * 1024 * 1024, 400, MAX_LZ4_BLOCK_EXPANSION_RATIO),
            102_000
        );
    }

    /// `compressed_len × ratio` must saturate (not overflow/panic) for a
    /// pathological length, in which case the budget wins the
    /// `min`. Pins the `saturating_mul` against a `checked`/wrapping
    /// mutant: each length times its ratio wraps to below its budget,
    /// `0x0101_0101_0101_0102 × 255` to 254 and
    /// `0x0002_0000_0000_0001 × 32768` to 32768.
    #[test]
    fn block_output_cap_saturates_without_overflow() {
        for (ratio, wraps, budget) in [
            (MAX_LZ4_BLOCK_EXPANSION_RATIO, 0x0101_0101_0101_0102, 1_000),
            (
                MAX_ZSTD_BLOCK_EXPANSION_RATIO,
                0x0002_0000_0000_0001,
                1_000_000,
            ),
        ] {
            assert_eq!(block_output_cap(budget, u64::MAX, ratio), budget, "{ratio}");
            assert_eq!(block_output_cap(budget, wraps, ratio), budget, "{ratio}");
        }
    }

    #[cfg(feature = "__test_utils")]
    mod zstd_arm {
        use super::*;
        use crate::testing::bench::{zstd_legacy_frame, zstd_stream};

        /// `src` decoded as zstd within `budget` onto [`EARLIER`].
        fn decode_zstd(src: &[u8], budget: u64) -> (Result<(), CodecError>, Vec<u8>, Vec<usize>) {
            decode_onto(Codec::Zstd, EARLIER.to_vec(), src, budget)
        }

        #[test]
        fn zstd_decode_block_known_answer() {
            let plaintext = plaintext();
            let src = zstd_stream(&plaintext);
            for budget in [plaintext.len() as u64, u64::MAX] {
                let (decoded, out, _) = decode_zstd(&src, budget);
                assert!(decoded.is_ok(), "budget {budget}: {decoded:?}");
                assert_eq!(out, [EARLIER, &plaintext].concat(), "budget {budget}");
            }
        }

        /// One reservation of `min(budget, src.len() × 32768)`, and `out`
        /// grows by the decoded bytes, not by the reservation.
        #[test]
        fn zstd_reservation_is_exact_and_len_matches_produced() {
            let plaintext = plaintext();
            let src = zstd_stream(&plaintext);
            for (budget, requested) in [
                (plaintext.len() as u64 + 1, plaintext.len() + 1),
                (u64::MAX, src.len() * 32_768),
            ] {
                let (decoded, out, requests) = decode_zstd(&src, budget);
                assert!(decoded.is_ok(), "budget {budget}: {decoded:?}");
                assert_eq!(requests, [requested], "budget {budget}");
                assert_eq!(
                    out.len(),
                    EARLIER.len() + plaintext.len(),
                    "budget {budget}"
                );
            }
        }

        /// Output past the budget fails whether libzstd runs out of
        /// capacity, with its own error name, or `out` already had room
        /// for it.
        #[test]
        fn zstd_output_past_budget_is_corrupt() {
            let plaintext = plaintext();
            let src = zstd_stream(&plaintext);
            let too_small = zstd_safe::get_error_name(
                zstd_safe::decompress(&mut Vec::new(), &src).unwrap_err(),
            );
            let mut roomy = Vec::with_capacity(EARLIER.len() + plaintext.len());
            roomy.extend_from_slice(EARLIER);
            for (out, cause) in [(EARLIER.to_vec(), too_small), (roomy, PAST_OUTPUT_CAP)] {
                let budget = plaintext.len() as u64 - 1;
                let (decoded, out, _) = decode_onto(Codec::Zstd, out, &src, budget);
                assert_eq!(decode_message(&decoded), Some(cause), "{decoded:?}");
                assert_eq!(out, EARLIER, "{cause}");
            }
        }

        /// An empty block, pre-v1 frames, and bytes after the last frame
        /// are refused before anything is reserved. The v0.2 frame is first
        /// shown to decode, so the refusal is the gate's. A truncated v1
        /// frame is refused there too, with libzstd's reason.
        #[test]
        fn zstd_refuses_what_is_not_v1_or_skippable_frames() {
            let plaintext = plaintext();
            let payload = &plaintext[..200];
            let v02 = zstd_legacy_frame(0xFD2F_B522, &[], payload);
            assert_eq!(
                ::zstd::bulk::decompress(&v02, payload.len()).unwrap(),
                payload
            );
            let frame = zstd_stream(&plaintext);
            let truncated = frame[..frame.len() - 1].to_vec();
            let unparsable = zstd_safe::get_error_name(
                zstd_safe::find_frame_compressed_size(&truncated).unwrap_err(),
            );
            assert_ne!(unparsable, NOT_ZSTD_V1_FRAMES);
            let mut cases = vec![
                ("empty".to_owned(), Vec::new(), NOT_ZSTD_V1_FRAMES),
                (
                    "v1 then v0.2".to_owned(),
                    [frame.as_slice(), &v02].concat(),
                    NOT_ZSTD_V1_FRAMES,
                ),
                (
                    "trailing bytes".to_owned(),
                    [frame.as_slice(), b"tail"].concat(),
                    NOT_ZSTD_V1_FRAMES,
                ),
                ("truncated".to_owned(), truncated, unparsable),
            ];
            for magic in 0xFD2F_B522..=0xFD2F_B527_u32 {
                let legacy = zstd_legacy_frame(magic, &[], payload);
                cases.push((format!("{magic:#x}"), legacy, NOT_ZSTD_V1_FRAMES));
            }
            for (label, src, cause) in cases {
                let (decoded, out, requests) = decode_zstd(&src, u64::MAX);
                assert_eq!(
                    decode_message(&decoded),
                    Some(cause),
                    "{label}: {decoded:?}"
                );
                assert_eq!(out, EARLIER, "{label}");
                assert!(requests.is_empty(), "{label}: {requests:?}");
            }
        }

        #[test]
        fn zstd_skippable_and_empty_frames_add_no_output() {
            let plaintext = plaintext();
            let skippable = [
                &0x184D_2A5F_u32.to_le_bytes()[..],
                &4u32.to_le_bytes(),
                b"skip",
            ]
            .concat();
            let src = [
                skippable.as_slice(),
                &zstd_stream(&[]),
                &zstd_stream(&plaintext),
                &skippable,
            ]
            .concat();
            let (decoded, out, _) = decode_zstd(&src, plaintext.len() as u64);
            assert!(decoded.is_ok(), "{decoded:?}");
            assert_eq!(out, [EARLIER, &plaintext].concat());
        }

        #[test]
        fn a_zstd_context_libzstd_could_not_create_is_context_unavailable() {
            assert!(matches!(
                zstd_context(None),
                Err(CodecError::ContextUnavailable)
            ));
            assert!(zstd_context(DCtx::try_create()).is_ok());
        }

        /// Two RLE blocks of 128 KiB in a 14-byte frame, at the RFC's
        /// Block_Maximum_Size and past half the ratio, decode.
        #[test]
        fn zstd_rle_frame_near_the_ratio_decodes() {
            let mut src = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x38];
            src.extend_from_slice(&[0x02, 0x00, 0x10, 0x5A, 0x03, 0x00, 0x10, 0xA5]);
            let produced = 2 * 128 * 1024;
            assert!(produced > src.len() as u64 * MAX_ZSTD_BLOCK_EXPANSION_RATIO / 2);
            let (decoded, out, requests) = decode_zstd(&src, produced);
            assert!(decoded.is_ok(), "{decoded:?}");
            assert_eq!(requests, [262_144]);
            let expected = [EARLIER, &vec![0x5A; 131_072], &vec![0xA5; 131_072]].concat();
            assert_eq!(out, expected);
        }

        #[test]
        fn accessor_reads_the_live_cap() {
            assert_eq!(
                max_zstd_block_expansion_ratio(),
                MAX_ZSTD_BLOCK_EXPANSION_RATIO
            );
        }
    }

    #[cfg(feature = "__test_utils")]
    mod gzip_arm {
        use super::*;
        use crate::testing::bench::gzip_stream;

        /// `src` decoded as gzip within `budget` onto [`EARLIER`].
        fn decode_gzip(src: &[u8], budget: u64) -> (Result<(), CodecError>, Vec<u8>, Vec<usize>) {
            decode_onto(Codec::Gzip, EARLIER.to_vec(), src, budget)
        }

        #[test]
        fn gzip_decode_block_known_answer() {
            let plaintext = plaintext();
            let src = gzip_stream(&plaintext);
            for budget in [plaintext.len() as u64, u64::MAX] {
                let (decoded, out, _) = decode_gzip(&src, budget);
                assert!(decoded.is_ok(), "budget {budget}: {decoded:?}");
                assert_eq!(out, [EARLIER, &plaintext].concat(), "budget {budget}");
            }
        }

        #[test]
        fn gzip_output_past_budget_is_corrupt() {
            let plaintext = plaintext();
            let src = gzip_stream(&plaintext);
            let (decoded, out, _) = decode_gzip(&src, plaintext.len() as u64 - 1);
            assert_eq!(
                decode_message(&decoded),
                Some(PAST_OUTPUT_CAP),
                "{decoded:?}"
            );
            assert_eq!(out, EARLIER);
        }
    }
}
