//! `FPakEntry` record parsing — both inline (v3+) and bit-packed
//! encoded (v10+) variants.
//!
//! [`PakEntryHeader`] is the parser output; [`EntryCommon`] holds the
//! fields shared by both variants. The variant split (Inline vs
//! Encoded) carries the SHA1-presence distinction at the type level —
//! see issue #28's history in `PakEntryHeader`'s docstring.

use std::io::Read;
use std::num::NonZeroU32;

use byteorder::{LittleEndian, ReadBytesExt};

use super::compression::{CompressionBlock, CompressionMethod};
use crate::container::pak::version::PakVersion;
use crate::digest::Sha1Digest;
use crate::error::{BoundsUnit, IndexParseFault, OverflowSite, PaksmithError};

/// Sanity ceiling on compression block count per entry (~16M blocks of
/// 64KiB would be a 1TiB entry).
const MAX_BLOCKS_PER_ENTRY: u32 = 16_777_216;

/// Compute the on-disk size of the in-data FPakEntry record that
/// precedes an entry's payload bytes, given whether it's compressed and
/// the number of compression blocks. Used by [`PakEntryHeader::read_encoded`]
/// to compute block-start offsets relative to the in-data record (which
/// is otherwise reconstructed lazily).
///
/// V8B+/V10/V11 all use the same in-data record layout: u64 offset + u64
/// compressed + u64 uncompressed + u32 method + 20-byte sha1 + (optional
/// u32 block_count + N×16 blocks) + u8 encrypted + u32 block_size = 53
/// bytes uncompressed, or 53 + 4 + 16N compressed.
pub(super) const fn encoded_entry_in_data_record_size(compressed: bool, block_count: usize) -> u64 {
    let mut size: u64 = 8 + 8 + 8 + 4 + 20 + 1 + 4;
    if compressed {
        size += 4 + (block_count as u64) * 16;
    }
    size
}

/// Fields common to every parsed pak entry header, regardless of whether
/// it came from the inline FPakEntry record or the v10+ bit-packed encoded
/// blob. Sits inside both [`PakEntryHeader`] variants so accessors can
/// delegate without duplicating the field set.
///
/// Marked `#[non_exhaustive]` so future fields can be added without a
/// breaking change to external consumers (which reach these fields only
/// via [`PakEntryHeader`]'s accessors).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EntryCommon {
    // Fields are `pub(super)` (not private) to support the
    // `EntryCommon { offset: 0, ..make_common(...) }` spread idiom in
    // `mod.rs`'s tests. Don't tighten without first removing those
    // call sites — `#[non_exhaustive]` already blocks construction
    // from outside `crate::container::pak::index`.
    pub(super) offset: u64,
    pub(super) compressed_size: u64,
    pub(super) uncompressed_size: u64,
    pub(super) compression_method: CompressionMethod,
    pub(super) is_encrypted: bool,
    pub(super) compression_blocks: Vec<CompressionBlock>,
    pub(super) compression_block_size: u32,
}

/// A parsed pak entry header.
///
/// Variants encode the on-disk distinction that previously lived in a
/// runtime `omits_sha1: bool` flag:
///
/// - [`PakEntryHeader::Inline`] — the v3+ FPakEntry record. Carries an
///   explicit SHA1 digest plus a [`PakVersion`] so [`Self::wire_size`]
///   can dispatch on the V8A vs V8B+ compression-byte width (V8A has a
///   u8 compression field; v3-v7 and V8B+ have u32). Appears both in
///   the v3-v9 index (after the entry's filename FString) and in every
///   entry's data section immediately before the payload (the
///   "in-data" copy). The in-data copy's `offset` field is written as
///   `0` (a self-reference convention — the header IS at that offset),
///   which is why cross-validation [`Self::matches_payload`] skips it.
///
/// - [`PakEntryHeader::Encoded`] — the v10+ bit-packed `FPakEntry::EncodeTo`
///   record from the encoded-entries blob. SHA1 is omitted from the wire
///   format entirely; only the in-data Inline copy carries one. The
///   variant carries no `version` field because v10+ encoded entries
///   share a single bit-packed layout with no V8A-style sub-variant —
///   eliminating that field removes a placeholder lie that the prior
///   shape encoded as `version: PakVersion::PathHashIndex` regardless
///   of the actual archive version.
///
/// Eliminating the SHA1-presence distinction at the type level (rather
/// than carrying a zeroed sha1 + `omits_sha1: bool` flag) makes it
/// impossible to accidentally compare a placeholder zero digest against
/// a real one — the bug that motivated the v3-v9 integrity-strip
/// detection (issue #28).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PakEntryHeader {
    /// v3+ inline FPakEntry record with explicit SHA1.
    Inline {
        /// Fields shared with [`PakEntryHeader::Encoded`].
        common: EntryCommon,
        /// SHA1 digest of the entry's stored bytes, as recorded on the
        /// wire. May be [`Sha1Digest::ZERO`] for v3-v9 archives that
        /// did not opt into per-entry integrity hashing — that case
        /// is a legitimate tampering signal, not a placeholder.
        sha1: Sha1Digest,
        /// Source archive version. The only consumer is
        /// [`PakEntryHeader::wire_size`], which dispatches on
        /// [`PakVersion::V8A`] (u8 compression field) vs everything else
        /// (u32). Encoded entries don't carry this — they have no V8A
        /// sub-variant and `wire_size` doesn't apply to the encoded
        /// blob's bit-packed layout.
        version: PakVersion,
    },
    /// v10+ bit-packed encoded entry. No on-wire SHA1.
    Encoded {
        /// Fields shared with [`PakEntryHeader::Inline`].
        common: EntryCommon,
    },
}

impl PakEntryHeader {
    /// Read the FPakEntry struct from the current reader position.
    ///
    /// Wire format (v3–v7):
    /// - `offset: u64`
    /// - `compressed_size: u64`
    /// - `uncompressed_size: u64`
    /// - `compression_method: u32`
    /// - `sha1: [u8; 20]`
    /// - if `compression_method != None`:
    ///     - `block_count: u32`, then `block_count` × `(start: u64, end: u64)`
    /// - `is_encrypted: u8`
    /// - **`compression_block_size: u32`** — present for ALL v3+ entries,
    ///   not just compressed ones. Real UE writers emit this field
    ///   unconditionally (with value 0 for uncompressed). Until #14's
    ///   cross-parser fixtures landed, this code skipped this field for
    ///   uncompressed entries — bug shared with the synthetic generator
    ///   and invisible to round-trip tests.
    ///
    /// v1/v2 archives use a different shape (with a `timestamp: u64` field
    /// pre-v2 and without the trailing `flags + block_size`).
    /// [`crate::container::pak::PakReader`] rejects them at `open()`;
    /// this function assumes v3+ layout.
    pub fn read_from<R: Read>(
        reader: &mut R,
        version: PakVersion,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let offset = reader.read_u64::<LittleEndian>()?;
        let compressed_size = reader.read_u64::<LittleEndian>()?;
        let uncompressed_size = reader.read_u64::<LittleEndian>()?;
        // Compression byte width is per-version:
        // - v3-v7: u32, value is the raw compression-method ID.
        // - V8A:   u8,  value is a 1-based index into `compression_methods`
        //          (4 slots).
        // - V8B+:  u32, value is a 1-based index into `compression_methods`
        //          (5 slots).
        // The footer parser already disambiguated V8A from V8B (using the
        // FName-table slot count); we trust the resolved variant here.
        let is_v8a = version == PakVersion::V8A;
        let compression_raw = if is_v8a {
            u32::from(reader.read_u8()?)
        } else {
            reader.read_u32::<LittleEndian>()?
        };
        let compression_method = if compression_methods.is_empty() {
            // v3-v7: raw method ID, decoded inline.
            CompressionMethod::from_u32(compression_raw)
        } else {
            // v8+: 1-based table index. 0 = no compression. Out-of-range
            // indices and `None` slots resolve to Unknown so the entry's
            // downstream lookup surfaces a typed Decompression error
            // rather than silently treating the data as uncompressed.
            match NonZeroU32::new(compression_raw) {
                None => CompressionMethod::None,
                Some(n) => compression_methods
                    .get((n.get() - 1) as usize)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or(CompressionMethod::Unknown(n)),
            }
        };

        let mut sha1_bytes = [0u8; 20];
        reader.read_exact(&mut sha1_bytes)?;
        let sha1 = Sha1Digest::from(sha1_bytes);

        let has_blocks = compression_method != CompressionMethod::None;
        let compression_blocks = if has_blocks {
            let block_count = reader.read_u32::<LittleEndian>()?;
            if block_count > MAX_BLOCKS_PER_ENTRY {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: "block_count",
                        value: u64::from(block_count),
                        limit: u64::from(MAX_BLOCKS_PER_ENTRY),
                        unit: BoundsUnit::Items,
                        path: None,
                    },
                });
            }
            // Fallible reservation: block_count is bounded only by
            // MAX_BLOCKS_PER_ENTRY = 16M, and CompressionBlock is 16
            // bytes, so a header at the cap drives a 256 MiB alloc.
            // Multiplied across entries, even a "small" pak with
            // bounded-but-extreme block counts can exhaust memory.
            // try_reserve_exact surfaces alloc failure as a typed error
            // instead of an `alloc::handle_alloc_error` abort.
            let mut blocks: Vec<CompressionBlock> = Vec::new();
            blocks
                .try_reserve_exact(block_count as usize)
                .map_err(|source| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::AllocationFailed {
                        context: "compression blocks",
                        requested: block_count as usize,
                        source,
                        path: None,
                    },
                })?;
            for _ in 0..block_count {
                let start = reader.read_u64::<LittleEndian>()?;
                let end = reader.read_u64::<LittleEndian>()?;
                blocks.push(CompressionBlock::new(start, end)?);
            }
            blocks
        } else {
            Vec::new()
        };

        let is_encrypted = reader.read_u8()? != 0;

        // Always present in v3+, regardless of compression. Stored as 0 for
        // uncompressed entries.
        let compression_block_size = reader.read_u32::<LittleEndian>()?;

        Ok(Self::Inline {
            common: EntryCommon {
                offset,
                compressed_size,
                uncompressed_size,
                compression_method,
                is_encrypted,
                compression_blocks,
                compression_block_size,
            },
            sha1,
            version,
        })
    }

    /// Decode a v10+ bit-packed encoded FPakEntry from the encoded-entries
    /// blob.
    ///
    /// Wire format (per Epic's `FPakEntry::EncodeTo`):
    /// - `bits: u32` — flags byte that packs:
    ///   - `bits[31]`: offset is u32 (0 = u64)
    ///   - `bits[30]`: uncompressed_size is u32 (0 = u64)
    ///   - `bits[29]`: compressed_size is u32 (0 = u64)
    ///   - `bits[28..=23]` (6 bits): compression-method 1-based table index
    ///     (0 = no compression)
    ///   - `bits[22]`: encrypted flag
    ///   - `bits[21..=6]` (16 bits): compression-block count
    ///   - `bits[5..=0]` (5 bits): compression-block size, scaled left by 11
    ///     (so a stored value `n` means `n << 11` bytes); the sentinel `0x3f`
    ///     means "doesn't fit in 5 bits, read the next u32 verbatim."
    /// - then variable-width offset / uncompressed / compressed (per the bits)
    /// - then `block_count` × u32 per-block compressed size IFF the block
    ///   layout doesn't fit the "single uncompressed-block-trivially-derivable"
    ///   shortcut.
    ///
    /// Encoded entries **don't carry SHA1** — only the in-data FPakEntry
    /// record (which sits in the data section and is parsed by
    /// [`PakEntryHeader::read_from`]) does. The decoded header is the
    /// [`PakEntryHeader::Encoded`] variant, which has no `sha1` field;
    /// `sha1()` returns `None`. [`crate::container::pak::PakReader::verify_entry`]
    /// short-circuits on that signal and surfaces v10+ entries as
    /// `SkippedNoHash`. The two "skip" paths (encoded-no-digest vs.
    /// inline-with-zero-digest-on-no-integrity-archive) are now
    /// structurally distinct rather than sharing a placeholder zero.
    // Bit-packed wire format with multiple branches (compression-slot
    // resolution, varint-width dispatch, single-vs-multi-block layout,
    // checked arithmetic on every offset add) — splitting just hides
    // the branching, doesn't reduce it.
    #[allow(clippy::too_many_lines)]
    pub fn read_encoded<R: Read>(
        reader: &mut R,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let bits = reader.read_u32::<LittleEndian>()?;

        // Compression slot — same 1-based-index-into-FName-table convention
        // as v8+ inline (just 6 bits instead of u32). 0 means none.
        let compression_method = match NonZeroU32::new((bits >> 23) & 0x3f) {
            None => CompressionMethod::None,
            Some(n) => compression_methods
                .get((n.get() - 1) as usize)
                .and_then(Option::as_ref)
                .cloned()
                .unwrap_or(CompressionMethod::Unknown(n)),
        };
        let is_encrypted = (bits & (1 << 22)) != 0;
        // 16-bit field by construction (`(bits >> 6) & 0xffff` masks to
        // u16 range = 0..=65_535), so MAX_BLOCKS_PER_ENTRY (16M) is
        // unreachable here. The check that exists in
        // `PakEntryHeader::read_from` (where block_count is a raw u32
        // off the wire) doesn't apply.
        let block_count: u32 = (bits >> 6) & 0xffff;

        // Compression-block size: 5-bit field shifted left by 11. Sentinel
        // 0x3f means "doesn't fit; read the actual size as the next u32."
        let block_size_field = bits & 0x3f;
        let compression_block_size = if block_size_field == 0x3f {
            reader.read_u32::<LittleEndian>()?
        } else {
            block_size_field << 11
        };

        // Variable-width offset/sizes: each is u32 if the corresponding bit
        // is set, else u64.
        let read_var = |reader: &mut R, bit: u32| -> crate::Result<u64> {
            Ok(if (bits & (1 << bit)) != 0 {
                u64::from(reader.read_u32::<LittleEndian>()?)
            } else {
                reader.read_u64::<LittleEndian>()?
            })
        };

        let offset = read_var(reader, 31)?;
        let uncompressed_size = read_var(reader, 30)?;
        let compressed_size = if matches!(compression_method, CompressionMethod::None) {
            uncompressed_size
        } else {
            read_var(reader, 29)?
        };

        // Block layout: encoded entries reconstruct block boundaries from
        // (a) the in-data FPakEntry record's wire size as the base offset,
        // and (b) for multi-block or encrypted entries, an explicit list of
        // u32 per-block sizes.
        //
        // For a single uncompressed-or-non-encrypted block, the layout is
        // trivial: one block from offset_base to offset_base + compressed.
        // No per-block sizes needed in the wire stream.
        let in_data_record_size = encoded_entry_in_data_record_size(
            compression_method != CompressionMethod::None,
            block_count as usize,
        );
        // checked_add throughout the encoded-block walk (issue #44).
        //
        // Three add sites:
        //
        // - **Load-bearing**: the single-block trivial path
        //   `in_data_record_size + compressed_size`. `compressed_size`
        //   came from `read_var` and can be a full u64 when the
        //   u32-fits bit is cleared on the wire. An attacker-crafted
        //   entry with `compressed: u64::MAX` wraps this add silently —
        //   producing a `CompressionBlock { start: ~73, end: ~73 }`
        //   that points at the start of the archive instead of the
        //   entry's payload. Downstream reads then silently grab bytes
        //   from offset 0.
        //
        // - **Defensive** (loop body): `cursor + block_compressed_size`
        //   and `start + advance`. Per-block sizes are `u64::from(u32)`
        //   and `block_count` is masked to 16 bits, so the cumulative
        //   sum is bounded by `65 535 * u32::MAX ≈ 280 GiB` — under
        //   `u64::MAX` by three orders of magnitude. These sites
        //   cannot overflow with valid-shaped wire input today, but
        //   `checked_add` is uniform with every other offset add in
        //   the module and guards against future wire-format changes
        //   (e.g., a u32 → u64 widening on the per-block size field).
        //
        // `path: None` here: encoded entries are parsed before the
        // FDI walk resolves their virtual paths. Issue #57 tracks
        // enriching these errors at the FDI-walk caller so the
        // `None` arm becomes unreachable in practice.
        let overflow_err = |site: OverflowSite| PaksmithError::InvalidIndex {
            fault: IndexParseFault::U64ArithmeticOverflow {
                path: None,
                operation: site,
            },
        };
        let compression_blocks = if block_count == 1 && !is_encrypted {
            let end = in_data_record_size
                .checked_add(compressed_size)
                .ok_or_else(|| overflow_err(OverflowSite::EncodedSingleBlockEnd))?;
            vec![CompressionBlock::new(in_data_record_size, end)?]
        } else if block_count > 0 {
            // Same fallible-reservation idiom as PakEntryHeader::read_from.
            // The encoded format masks block_count to 16 bits (max
            // 65 535 from `(bits >> 6) & 0xffff`), so the worst-case
            // alloc is ~1 MiB — smaller than the v3-v9 path but still
            // converted for consistency.
            let mut blocks: Vec<CompressionBlock> = Vec::new();
            blocks
                .try_reserve_exact(block_count as usize)
                .map_err(|source| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::AllocationFailed {
                        context: "encoded compression blocks",
                        requested: block_count as usize,
                        source,
                        path: None,
                    },
                })?;
            let mut cursor = in_data_record_size;
            // Accumulate the UNALIGNED per-block size sum so we can
            // cross-check the wire `compressed_size` claim after the
            // loop. The cursor walk uses the aligned advance for
            // encrypted entries; `compressed_total` tracks the
            // logical (unaligned) payload size that the wire
            // `compressed_size` field represents.
            let mut compressed_total: u64 = 0;
            for _ in 0..block_count {
                let block_compressed_size = u64::from(reader.read_u32::<LittleEndian>()?);
                let start = cursor;
                let end = cursor
                    .checked_add(block_compressed_size)
                    .ok_or_else(|| overflow_err(OverflowSite::EncodedBlockEnd))?;
                blocks.push(CompressionBlock::new(start, end)?);
                // Bounded by `65 535 * u32::MAX ≈ 280 GiB ≪ u64::MAX`,
                // matching the cursor-walk overflow reasoning above —
                // a checked_add would never trip with valid wire
                // shapes, but defensive_discipline says keep it
                // uniform with the surrounding adds.
                compressed_total = compressed_total
                    .checked_add(block_compressed_size)
                    .ok_or_else(|| overflow_err(OverflowSite::EncodedBlockEnd))?;
                // Encrypted blocks are padded to AES-block-aligned sizes
                // on disk; the next block's start advances by the aligned
                // size, not the unaligned size. AES block = 16 bytes.
                // The alignment math itself is bounded (block_compressed_size
                // is `u64::from(u32)`, so `+ 15` cannot overflow u64). The
                // subsequent `start + advance` carries attacker-supplied
                // values but is cumulatively bounded under u64::MAX — see
                // the function-header comment for why the checked_add
                // there is defensive-discipline rather than load-bearing.
                let advance = if is_encrypted {
                    (block_compressed_size + 15) & !15
                } else {
                    block_compressed_size
                };
                cursor = start
                    .checked_add(advance)
                    .ok_or_else(|| overflow_err(OverflowSite::EncodedBlockCursor))?;
            }
            // Issue #58: cross-check the wire `compressed_size` against
            // the actual sum of per-block sizes. Without this check, an
            // attacker can claim e.g. `compressed_size = u64::MAX - 1`
            // (the u64 varint width is wire-attacker-controlled via
            // bit-29) while the per-block sizes sum to a few KiB —
            // and the lie propagates to `compressed_size()` and any
            // downstream consumer reporting the entry's payload size.
            if compressed_total != compressed_size {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::EncodedCompressedSizeMismatch {
                        claimed: compressed_size,
                        computed: compressed_total,
                        path: None,
                    },
                });
            }
            blocks
        } else {
            Vec::new()
        };

        Ok(Self::Encoded {
            common: EntryCommon {
                offset,
                compressed_size,
                uncompressed_size,
                compression_method,
                is_encrypted,
                compression_blocks,
                compression_block_size,
            },
        })
    }

    /// Borrow the [`EntryCommon`] payload regardless of variant. Internal
    /// helper for accessors that don't need to discriminate on the SHA1
    /// presence.
    fn common(&self) -> &EntryCommon {
        match self {
            Self::Inline { common, .. } | Self::Encoded { common } => common,
        }
    }

    /// Cross-validate this header (parsed from the entry's data section)
    /// against the index entry's header. Returns `Err(InvalidIndex)` if any
    /// integrity-relevant field disagrees.
    ///
    /// Skips the `offset` field — UE writes the in-data copy's offset as `0`
    /// (self-reference), so it intentionally won't match the index value.
    /// Every other field, including the full compression-block layout, must
    /// agree. Block layout matters because the reader relies on it to seek
    /// past the in-data record into the payload region; a mismatch here would
    /// silently shift the payload boundary.
    pub fn matches_payload(&self, payload: &Self, path: &str) -> crate::Result<()> {
        let mismatch =
            |field: &'static str, idx: String, dat: String| PaksmithError::InvalidIndex {
                fault: IndexParseFault::FieldMismatch {
                    path: path.to_string(),
                    field,
                    index_value: idx,
                    payload_value: dat,
                },
            };
        let lhs = self.common();
        let rhs = payload.common();
        if lhs.compressed_size != rhs.compressed_size {
            return Err(mismatch(
                "compressed_size",
                lhs.compressed_size.to_string(),
                rhs.compressed_size.to_string(),
            ));
        }
        if lhs.uncompressed_size != rhs.uncompressed_size {
            return Err(mismatch(
                "uncompressed_size",
                lhs.uncompressed_size.to_string(),
                rhs.uncompressed_size.to_string(),
            ));
        }
        if lhs.compression_method != rhs.compression_method {
            return Err(mismatch(
                "compression_method",
                format!("{:?}", lhs.compression_method),
                format!("{:?}", rhs.compression_method),
            ));
        }
        if lhs.is_encrypted != rhs.is_encrypted {
            return Err(mismatch(
                "is_encrypted",
                lhs.is_encrypted.to_string(),
                rhs.is_encrypted.to_string(),
            ));
        }
        // SHA1 comparison is skipped ONLY for v10+ encoded entries —
        // they omit SHA1 entirely in the bit-packed wire format, so the
        // index header has no SHA1 to compare while the in-data record
        // carries the real one. Treating that as a mismatch would reject
        // every v10+ entry.
        //
        // The variant (Inline vs Encoded) carries this information at the
        // type level: if `self.sha1()` returns `Some`, this is an inline
        // header and the digest is genuine — including the all-zeros case,
        // which is a real tampering signal we want to preserve for v3-v9
        // archives. The bug from issue #28 (`is_zero_sha1(sha1)` instead
        // of consulting an `omits_sha1` flag) is structurally impossible
        // here: there's no zero-filled placeholder for an Encoded entry
        // to be confused with a real digest.
        if let (Some(lhs_sha), Some(rhs_sha)) = (self.sha1(), payload.sha1()) {
            if lhs_sha != rhs_sha {
                return Err(mismatch(
                    "sha1",
                    lhs_sha.short().to_string(),
                    rhs_sha.short().to_string(),
                ));
            }
        }
        if lhs.compression_blocks != rhs.compression_blocks {
            // Surface enough detail to debug the mismatch: count first, then
            // the first differing block when counts agree.
            let (lhs_desc, rhs_desc) = match lhs
                .compression_blocks
                .len()
                .cmp(&rhs.compression_blocks.len())
            {
                std::cmp::Ordering::Equal => {
                    let first_diff = lhs
                        .compression_blocks
                        .iter()
                        .zip(rhs.compression_blocks.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    let lhs_block = lhs.compression_blocks[first_diff];
                    let rhs_block = rhs.compression_blocks[first_diff];
                    (
                        format!(
                            "block[{first_diff}]={}..{}",
                            lhs_block.start(),
                            lhs_block.end()
                        ),
                        format!(
                            "block[{first_diff}]={}..{}",
                            rhs_block.start(),
                            rhs_block.end()
                        ),
                    )
                }
                _ => (
                    format!("{} blocks", lhs.compression_blocks.len()),
                    format!("{} blocks", rhs.compression_blocks.len()),
                ),
            };
            return Err(mismatch("compression_blocks", lhs_desc, rhs_desc));
        }
        if lhs.compression_block_size != rhs.compression_block_size {
            return Err(mismatch(
                "compression_block_size",
                lhs.compression_block_size.to_string(),
                rhs.compression_block_size.to_string(),
            ));
        }
        Ok(())
    }

    /// On-disk wire size of this FPakEntry record in bytes — i.e., the number
    /// of bytes that [`PakEntryHeader::read_from`] consumed when producing
    /// `self`. Single source of truth for both producers (fixture generator)
    /// and consumers (payload-offset arithmetic in `PakReader::read_entry`).
    ///
    /// Layout (v3-v7 and V8B+):
    /// - 48 bytes common: offset(8) + compressed(8) + uncompressed(8) +
    ///   compression_method(4) + sha1(20)
    /// - if compressed: block_count(4) + N × (start(8) + end(8))
    /// - 5 bytes always-present trailer: is_encrypted(1) + block_size(4)
    ///
    /// V8A is 3 bytes shorter — the compression_method field is u8 instead
    /// of u32. Only [`PakEntryHeader::Inline`] carries a [`PakVersion`]
    /// (set at parse time); the V8A check fires only on Inline. Encoded
    /// entries fall through to the V8B+/v3-v7 branch — they are v10+ only
    /// and were never V8A, and `wire_size` is in practice only called on
    /// in-data records (always Inline) anyway.
    pub fn wire_size(&self) -> u64 {
        let compression_field_bytes: u64 = match self {
            Self::Inline {
                version: PakVersion::V8A,
                ..
            } => 1,
            _ => 4,
        };
        let common = self.common();
        let mut size: u64 = 8 + 8 + 8 + compression_field_bytes + 20;
        if common.compression_method != CompressionMethod::None {
            size += 4 + (common.compression_blocks.len() as u64) * 16;
        }
        // Trailer: is_encrypted u8 + compression_block_size u32. The block
        // size is always written (with value 0 for uncompressed entries),
        // not just when compression_blocks is non-empty.
        size += 1 + 4;
        size
    }

    /// Byte offset stored in this header. For index headers this is the file
    /// offset of the entry's record. For in-data headers UE writes it as `0`
    /// (self-reference), so callers should not rely on it for in-data copies.
    pub fn offset(&self) -> u64 {
        self.common().offset
    }

    /// Compressed size in bytes (equals `uncompressed_size` when uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.common().compressed_size
    }

    /// Uncompressed size in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.common().uncompressed_size
    }

    /// Compression method applied to this entry.
    pub fn compression_method(&self) -> &CompressionMethod {
        &self.common().compression_method
    }

    /// Whether this entry's data is AES-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.common().is_encrypted
    }

    /// SHA1 hash of the entry's stored bytes, when one is recorded on the
    /// wire.
    ///
    /// Returns `Some` for inline FPakEntry records (v3-v9 index headers
    /// and every in-data record) — including the all-zeros case, which
    /// is a legitimate tampering signal for v3-v9 archives that opted
    /// into integrity hashing.
    ///
    /// Returns `None` for v10+ encoded entries: their bit-packed wire
    /// format omits the SHA1 field entirely. Callers deciding between
    /// "no integrity claim was made" and "an integrity claim was zeroed"
    /// pattern-match on this `Option` directly — there is no way to
    /// confuse a placeholder zero digest with a real one because the
    /// Encoded variant has no `sha1` field to read.
    pub fn sha1(&self) -> Option<Sha1Digest> {
        match self {
            Self::Inline { sha1, .. } => Some(*sha1),
            Self::Encoded { .. } => None,
        }
    }

    /// Compression block boundaries (empty when uncompressed).
    pub fn compression_blocks(&self) -> &[CompressionBlock] {
        &self.common().compression_blocks
    }

    /// Compression block size in bytes (0 when uncompressed).
    pub fn compression_block_size(&self) -> u32 {
        self.common().compression_block_size
    }
}
