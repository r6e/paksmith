//! Pak file index and entry parsing.

use std::fmt::Write as _;
use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use tracing::warn;

use crate::container::pak::version::PakVersion;
use crate::error::{BoundsUnit, FStringEncoding, FStringFault, IndexParseFault, PaksmithError};

/// Maximum length (in bytes for UTF-8, code units for UTF-16) accepted for an
/// FString. Sized to comfortably exceed any realistic UE virtual path while
/// rejecting attacker-controlled multi-GB allocations.
const FSTRING_MAX_LEN: i32 = 65_536;

/// Minimum on-disk size of an index entry record (FString header + offset +
/// sizes + compression + sha1 + encrypted flag, with the shortest-possible
/// FString of 5 bytes for `length(4) + null(1)`). Used to bound `entry_count`.
const ENTRY_MIN_RECORD_BYTES: u64 = 5 + 8 + 8 + 8 + 4 + 20 + 1;

/// Sanity ceiling on compression block count per entry (~16M blocks of 64KiB
/// would be a 1TiB entry).
const MAX_BLOCKS_PER_ENTRY: u32 = 16_777_216;

/// Cap on how many duplicate filenames we sample for the dedupe warning.
/// Prevents the warn-log payload from growing with `dup_count`.
const MAX_SAMPLED_DUPS: usize = 5;

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
const fn encoded_entry_in_data_record_size(compressed: bool, block_count: usize) -> u64 {
    let mut size: u64 = 8 + 8 + 8 + 4 + 20 + 1 + 4;
    if compressed {
        size += 4 + (block_count as u64) * 16;
    }
    size
}

/// FNV-1a 64-bit offset basis (canonical constant). Cfg-gated to
/// `cfg(test)` alongside `fnv64_path` (see below); non-test builds
/// don't carry it.
#[cfg(test)]
const FNV1A_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime (canonical constant). Cfg-gated to
/// `cfg(test)` alongside `fnv64_path` (see below); non-test builds
/// don't carry it.
#[cfg(test)]
const FNV1A_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64-bit hash of a UE virtual path, used by v10+ archives'
/// path-hash index for O(1) entry lookup.
///
/// Per UE convention, the path is lowercased and re-encoded as UTF-16
/// little-endian before hashing. The seed is added (`wrapping_add`) into
/// the offset basis at init time so different archives with the same
/// paths produce different hashes (avoids a hash-collision attack
/// across multiple archives).
///
/// # ASCII-only lowercasing — known limitation for non-ASCII paths
///
/// We use `to_ascii_lowercase`, which only folds the 26 ASCII letters.
/// UE itself uses Unicode-aware case folding. **For ASCII-only paths
/// — which is all real UE asset paths use (`Content/Foo.uasset`) —
/// this matches both v10 (UE's old buggy lowercasing) and v11
/// (Unicode-aware lowercasing) byte-for-byte.** For non-ASCII paths
/// our hash will disagree with both UE versions; we accept this
/// because:
///
/// 1. paksmith does not currently use `fnv64_path` for primary lookup
///    (`PakIndex::find` uses our `by_path` HashMap built from the full
///    directory index walk — string-equality based, not hash based).
/// 2. Real UE pak content has ASCII paths. A v10/v11 archive containing
///    non-ASCII paths would still resolve via the directory-walk path,
///    just not via the path-hash optimization (which we don't yet
///    leverage anyway).
///
/// Switching to genuine Unicode-aware lowercasing would require pulling
/// in a Unicode-handling crate (we currently have none); deferred until
/// a real-world non-ASCII v10/v11 fixture forces the issue.
///
/// # v10 vs v11 (the `Fnv64BugFix` distinction)
///
/// v10 had a Unicode-lowercasing bug that mishandled non-ASCII
/// codepoints; v11 fixed it. Both produce identical hashes on ASCII
/// inputs, so our ASCII-only implementation is interchangeable for
/// both versions in practice.
#[must_use]
// Forward-looking scaffolding for the v10/v11 path-hash table lookup
// optimization. paksmith currently resolves entries via the FDI walk
// + by_path HashMap; fnv64_path will be wired up when the path-hash
// table is consulted as a fast-path.
//
// Cfg-gated to `cfg(test)` only (NOT the `__test_utils` feature) —
// no integration test in `tests/` currently consumes it, so there's
// no need to pay the public-API surface cost of the feature flag.
// When the production call site lands, drop this attribute. Tracked
// at issue #30.
#[cfg(test)]
fn fnv64_path(path: &str, seed: u64) -> u64 {
    let lower = path.to_ascii_lowercase();
    let mut hash = FNV1A_OFFSET_BASIS.wrapping_add(seed);
    for unit in lower.encode_utf16() {
        for byte in unit.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV1A_PRIME);
        }
    }
    hash
}

/// Compression method used for a pak entry.
///
/// On disk, the per-entry compression byte means different things by
/// version:
/// - **v3-v7**: a raw method ID (0=None, 1=Zlib, 2=Gzip, 4=Oodle).
///   Resolved via [`CompressionMethod::from_u32`].
/// - **v8+**: a 1-based index into the footer's compression-methods FName
///   table (0 = no compression, N = `compression_methods[N-1]`). The
///   table itself contains FName strings — `"Zlib"`, `"Oodle"`, etc. —
///   resolved via [`CompressionMethod::from_name`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression applied.
    None,
    /// Zlib (deflate) compression.
    Zlib,
    /// Gzip compression.
    Gzip,
    /// Oodle compression (Epic proprietary).
    Oodle,
    /// Zstandard compression (Epic added v8+).
    Zstd,
    /// LZ4 compression (Epic added v8+).
    Lz4,
    /// Unrecognized v3-v7 compression method ID, preserved for diagnostics.
    Unknown(u32),
    /// Unrecognized v8+ compression FName, preserved verbatim so error
    /// messages can name the slot's actual contents (e.g.,
    /// `"OodleNetwork"`, `"LZMA"`) rather than collapsing every unknown
    /// name to a single sentinel.
    UnknownByName(String),
}

impl CompressionMethod {
    /// Parse a raw `u32` compression method identifier (v3-v7 wire format).
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Zlib,
            2 => Self::Gzip,
            4 => Self::Oodle,
            other => Self::Unknown(other),
        }
    }

    /// Parse a compression method by name (v8+ FName-table entry). Match
    /// is case-insensitive against the canonical UE names. Unrecognized
    /// names return [`CompressionMethod::UnknownByName`] preserving the
    /// raw name so the entry's downstream lookup surfaces as a typed
    /// `Decompression` error that names the actual slot contents.
    ///
    /// Callers must not pass an empty string — the slot reader handles
    /// empty slots upstream by emitting `None` directly.
    pub fn from_name(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "zlib" => Self::Zlib,
            "gzip" => Self::Gzip,
            "oodle" => Self::Oodle,
            "zstd" => Self::Zstd,
            "lz4" => Self::Lz4,
            _ => Self::UnknownByName(name.to_owned()),
        }
    }
}

/// Byte offset range of a single compression block within the entry payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionBlock {
    start: u64,
    end: u64,
}

impl CompressionBlock {
    /// Construct a block, rejecting `start > end` as malformed.
    pub fn new(start: u64, end: u64) -> crate::Result<Self> {
        if start > end {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::CompressionBlockInvalid { start, end },
            });
        }
        Ok(Self { start, end })
    }

    /// Start offset (inclusive) of the compressed block.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// End offset (exclusive) of the compressed block.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Length of the block in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// The serialized `FPakEntry` record (offset, sizes, compression metadata,
/// SHA1, encrypted flag, compression-block layout).
///
/// This struct appears in two places on disk:
/// 1. In the index, after the entry's filename FString.
/// 2. In the entry's data section, immediately before the payload bytes (the
///    "in-data" copy). The in-data copy's `offset` field is written as `0`
///    (a self-reference convention — the header IS at that offset), which is
///    why cross-validation [`PakEntryHeader::matches_payload`] skips it.
///
/// Both copies have an identical wire format; they are parsed by the same
/// [`PakEntryHeader::read_from`].
#[derive(Debug, Clone)]
pub struct PakEntryHeader {
    offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: CompressionMethod,
    is_encrypted: bool,
    sha1: [u8; 20],
    compression_blocks: Vec<CompressionBlock>,
    compression_block_size: u32,
    /// Version of the pak this header was parsed from. Stored so
    /// [`Self::wire_size`] can dispatch on the V8A/V8B variant
    /// distinction (V8A has a u8 compression byte, V8B+ has u32) without
    /// a runtime flag — replaced the prior `is_v8a_layout: bool` per
    /// issue #32 sub-PR B's "discriminator-as-flag" cleanup.
    version: PakVersion,
    /// V10+ encoded entries (parsed by [`PakEntryHeader::read_encoded`])
    /// don't carry SHA1 in the wire format, so `sha1` is always
    /// `[0u8; 20]` for them. [`PakEntryHeader::matches_payload`] consults
    /// this flag to skip the SHA1 cross-check ONLY for encoded entries —
    /// preserving the legitimate-tampering signal for v3-v9 archives
    /// where a zero index hash with a non-zero in-data hash is real
    /// evidence of an attacker stripping the integrity tag.
    omits_sha1: bool,
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
        //          (which has 4 slots in V8A — that's how we know we're V8A).
        // - V8B+:  u32, value is a 1-based index into `compression_methods`
        //          (which has 5 slots).
        // Detect V8A by version variant directly (footer parser
        // post-corrected V8B → V8A based on slot count, so the
        // version variant is now authoritative).
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
            match compression_raw {
                0 => CompressionMethod::None,
                n => compression_methods
                    .get((n - 1) as usize)
                    .and_then(Option::as_ref)
                    .cloned()
                    .unwrap_or(CompressionMethod::Unknown(n)),
            }
        };

        let mut sha1 = [0u8; 20];
        reader.read_exact(&mut sha1)?;

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

        Ok(Self {
            offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            is_encrypted,
            sha1,
            compression_blocks,
            compression_block_size,
            version,
            omits_sha1: false,
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
    /// [`PakEntryHeader::read_from`]) does. We populate `sha1: [0; 20]` here
    /// so [`crate::container::pak::PakReader::verify_entry`] surfaces v10+
    /// entries as `SkippedNoHash` (consistent with the existing zero-hash
    /// no-integrity-claim pathway).
    pub fn read_encoded<R: Read>(
        reader: &mut R,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let bits = reader.read_u32::<LittleEndian>()?;

        // Compression slot — same 1-based-index-into-FName-table convention
        // as v8+ inline (just 6 bits instead of u32). 0 means none.
        let compression_method = match (bits >> 23) & 0x3f {
            0 => CompressionMethod::None,
            n => compression_methods
                .get(n as usize - 1)
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
        let compression_blocks = if block_count == 1 && !is_encrypted {
            vec![CompressionBlock::new(
                in_data_record_size,
                in_data_record_size + compressed_size,
            )?]
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
            for _ in 0..block_count {
                let block_compressed_size = u64::from(reader.read_u32::<LittleEndian>()?);
                let start = cursor;
                let end = cursor + block_compressed_size;
                blocks.push(CompressionBlock::new(start, end)?);
                // Encrypted blocks are padded to AES-block-aligned sizes
                // on disk; the next block's start advances by the aligned
                // size, not the unaligned size. AES block = 16 bytes.
                let advance = if is_encrypted {
                    (block_compressed_size + 15) & !15
                } else {
                    block_compressed_size
                };
                cursor = start + advance;
            }
            blocks
        } else {
            Vec::new()
        };

        Ok(Self {
            offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            is_encrypted,
            sha1: [0u8; 20], // encoded entries omit SHA1
            compression_blocks,
            compression_block_size,
            // Encoded entries are v10+ only; record the appropriate
            // variant. The exact v10 vs v11 distinction doesn't
            // matter for `wire_size` (only V8A is special there) so
            // either variant works; pick PathHashIndex (the lower
            // version) as the conservative default.
            version: PakVersion::PathHashIndex,
            omits_sha1: true,
        })
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
        if self.compressed_size != payload.compressed_size {
            return Err(mismatch(
                "compressed_size",
                self.compressed_size.to_string(),
                payload.compressed_size.to_string(),
            ));
        }
        if self.uncompressed_size != payload.uncompressed_size {
            return Err(mismatch(
                "uncompressed_size",
                self.uncompressed_size.to_string(),
                payload.uncompressed_size.to_string(),
            ));
        }
        if self.compression_method != payload.compression_method {
            return Err(mismatch(
                "compression_method",
                format!("{:?}", self.compression_method),
                format!("{:?}", payload.compression_method),
            ));
        }
        if self.is_encrypted != payload.is_encrypted {
            return Err(mismatch(
                "is_encrypted",
                self.is_encrypted.to_string(),
                payload.is_encrypted.to_string(),
            ));
        }
        // SHA1 comparison is skipped ONLY for v10+ encoded entries —
        // they omit SHA1 entirely in the bit-packed wire format, so the
        // index header always has a zero digest while the in-data record
        // carries the real one. Treating that as a mismatch would reject
        // every v10+ entry.
        //
        // Critically, the skip is gated on `omits_sha1` (set by
        // `read_encoded` only), NOT on `self.sha1 == [0u8; 20]`. Doing
        // the latter would silently accept a v3-v9 archive where an
        // attacker zeroed the index SHA1 to bypass the cross-check —
        // the in-data record's real SHA1 would no longer be verified
        // against the index's claim. That's the exact tampering signal
        // we want to preserve for v3-v9.
        if !self.omits_sha1 && self.sha1 != payload.sha1 {
            return Err(mismatch(
                "sha1",
                hex_short(&self.sha1),
                hex_short(&payload.sha1),
            ));
        }
        if self.compression_blocks != payload.compression_blocks {
            // Surface enough detail to debug the mismatch: count first, then
            // the first differing block when counts agree.
            let (lhs_desc, rhs_desc) = match self
                .compression_blocks
                .len()
                .cmp(&payload.compression_blocks.len())
            {
                std::cmp::Ordering::Equal => {
                    let first_diff = self
                        .compression_blocks
                        .iter()
                        .zip(payload.compression_blocks.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    let lhs_block = self.compression_blocks[first_diff];
                    let rhs_block = payload.compression_blocks[first_diff];
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
                    format!("{} blocks", self.compression_blocks.len()),
                    format!("{} blocks", payload.compression_blocks.len()),
                ),
            };
            return Err(mismatch("compression_blocks", lhs_desc, rhs_desc));
        }
        if self.compression_block_size != payload.compression_block_size {
            return Err(mismatch(
                "compression_block_size",
                self.compression_block_size.to_string(),
                payload.compression_block_size.to_string(),
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
    /// of u32. The `version` variant (recorded at parse time) carries the
    /// V8A vs V8B+ distinction; this method dispatches on it directly.
    pub fn wire_size(&self) -> u64 {
        let compression_field_bytes: u64 = if self.version == PakVersion::V8A {
            1
        } else {
            4
        };
        let mut size: u64 = 8 + 8 + 8 + compression_field_bytes + 20;
        if self.compression_method != CompressionMethod::None {
            size += 4 + (self.compression_blocks.len() as u64) * 16;
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
        self.offset
    }

    /// Compressed size in bytes (equals `uncompressed_size` when uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Uncompressed size in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Compression method applied to this entry.
    pub fn compression_method(&self) -> &CompressionMethod {
        &self.compression_method
    }

    /// Whether this entry's data is AES-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// SHA1 hash of the entry's stored bytes (kept for future verification).
    pub fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }

    /// Whether this entry's wire format does NOT carry a SHA1 hash.
    /// True for v10+ encoded entries (the bit-packed format omits the
    /// SHA1 field entirely; only the in-data record carries it). False
    /// for every v3-v9 inline entry, even those whose recorded SHA1
    /// happens to be all zeros — the latter is a legitimate tampering
    /// signal we want to surface.
    ///
    /// Callers that need to decide between "no integrity claim was
    /// made" and "an integrity claim was zeroed" must consult this
    /// flag, NOT `sha1() == &[0u8; 20]`. See the gating in
    /// [`crate::container::pak::PakReader::verify_entry`] for the
    /// canonical use.
    pub fn omits_sha1(&self) -> bool {
        self.omits_sha1
    }

    /// Compression block boundaries (empty when uncompressed).
    pub fn compression_blocks(&self) -> &[CompressionBlock] {
        &self.compression_blocks
    }

    /// Compression block size in bytes (0 when uncompressed).
    pub fn compression_block_size(&self) -> u32 {
        self.compression_block_size
    }
}

fn hex_short(bytes: &[u8; 20]) -> String {
    let mut s = String::with_capacity(20);
    for b in bytes.iter().take(8) {
        // Infallible — String's Write impl never errors.
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("...");
    s
}

/// A single entry in the pak index: filename plus the FPakEntry header.
#[derive(Debug, Clone)]
pub struct PakIndexEntry {
    filename: String,
    header: PakEntryHeader,
}

impl PakIndexEntry {
    /// Path of this entry within the archive.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// The FPakEntry record metadata for this entry. Field accessors
    /// (offset, sha1, compression_method, ...) live on the inner
    /// [`PakEntryHeader`]; reach them via `entry.header().X()`.
    pub fn header(&self) -> &PakEntryHeader {
        &self.header
    }
}

/// The full pak index: mount point plus all entries.
///
/// `by_path` is a path → index lookup table built once at parse time so
/// [`PakIndex::find`] is O(1) instead of an O(n) linear scan. Memory cost
/// is one `String` clone + one `usize` per entry — for a 100k-entry
/// archive that's ~10 MB on top of the entry vec, trading bytes for
/// reads on a structure consulted on every `read_entry` call.
#[derive(Debug, Clone)]
pub struct PakIndex {
    mount_point: String,
    entries: Vec<PakIndexEntry>,
    by_path: std::collections::HashMap<String, usize>,
}

impl PakIndex {
    /// Virtual mount point for paths in this archive.
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// All entries in the archive.
    pub fn entries(&self) -> &[PakIndexEntry] {
        &self.entries
    }

    /// Find an entry by filename in O(1).
    pub fn find(&self, path: &str) -> Option<&PakIndexEntry> {
        self.by_path.get(path).map(|&i| &self.entries[i])
    }

    /// Read and parse the index from a reader positioned at `index_offset`.
    ///
    /// `index_size` is the byte budget the caller knows the index occupies;
    /// allocations are bounded against it to prevent untrusted-input DoS.
    ///
    /// `compression_methods` is the FName compression-method table from the
    /// footer (empty for v3-v7; 4 entries for V8A; 5 entries for V8B+).
    /// Each entry's per-record compression byte is resolved against it for
    /// v8+ archives. v3-v7 entries store raw method IDs and ignore this
    /// slice.
    ///
    /// # Note on version-handling
    ///
    /// Read and parse the pak index. Dispatches on version.
    ///
    /// **v3-v9** use the flat-entry layout (mount + count + N entries of
    /// filename + FPakEntry record). Parsed inline against a
    /// `take(index_size)` sub-reader.
    ///
    /// **v10+** use the path-hash + encoded-directory layout (mount +
    /// count + seed + path-hash-index header + full-directory-index
    /// header + encoded-entries blob + non-encoded entries). The
    /// path-hash index and full directory index are stored at arbitrary
    /// positions in the parent file (referenced by the headers in the
    /// main index region), so the v10+ path requires the file reader's
    /// seek capability.
    ///
    /// `index_offset` is the file offset at which the main index region
    /// begins; the reader is seeked there before parsing.
    pub fn read_from<R: Read + Seek>(
        reader: &mut R,
        version: PakVersion,
        index_offset: u64,
        index_size: u64,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let _ = reader.seek(SeekFrom::Start(index_offset))?;
        if version.has_path_hash_index() {
            Self::read_v10_plus_from(reader, index_size, compression_methods)
        } else {
            Self::read_flat_from(reader, version, index_size, compression_methods)
        }
    }

    fn read_flat_from<R: Read>(
        reader: &mut R,
        version: PakVersion,
        index_size: u64,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let mut bounded = reader.take(index_size);
        let mount_point = read_fstring(&mut bounded)?;
        let entry_count = bounded.read_u32::<LittleEndian>()?;

        // Bound entry_count against the actual byte budget so a malicious
        // header claiming u32::MAX entries doesn't trigger an OOM at the
        // try_reserve_exact call below. The bound check stops obvious
        // header forgeries; the fallible reservation guards against the
        // residual case where index_size itself is legitimately huge
        // (multi-GB pak) and entry_count fits the budget but exceeds
        // available memory.
        let max_entries = index_size / ENTRY_MIN_RECORD_BYTES;
        if u64::from(entry_count) > max_entries {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "entry_count",
                    value: u64::from(entry_count),
                    limit: max_entries,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }

        // Matches the v10+ pattern in `read_v10_plus_from` (line 1041) —
        // both code paths now surface OOM at the entries reservation as
        // a typed `InvalidIndex` rather than an `alloc::handle_alloc_error`
        // abort.
        let mut entries: Vec<PakIndexEntry> = Vec::new();
        entries
            .try_reserve_exact(entry_count as usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "entries",
                    requested: entry_count as usize,
                    source,
                    path: None,
                },
            })?;
        for _ in 0..entry_count {
            entries.push(PakIndexEntry::read_from(
                &mut bounded,
                version,
                compression_methods,
            )?);
        }

        Self::from_entries(mount_point, entries)
    }

    /// V10+ index parser. The main index region carries headers + the
    /// encoded entries blob; the full directory index (which we use to
    /// recover paths) lives at a separate offset in the parent file.
    #[allow(clippy::too_many_lines)] // bounded by the multi-section index layout
    fn read_v10_plus_from<R: Read + Seek>(
        reader: &mut R,
        index_size: u64,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        // Sane standalone ceiling for the FDI alloc — a real-world full
        // directory index for a 100k-file pak is typically a few MB;
        // 256 MB is comfortably larger than anything legitimate while
        // still rejecting a u64::MAX alloc-bomb. The footer's
        // index_offset+index_size budget DOESN'T bound the FDI (it
        // lives at an arbitrary offset elsewhere in the file).
        const MAX_FDI_BYTES: u64 = 256 * 1024 * 1024;
        // Minimum on-disk shape per file inside the FDI: `FString
        // filename (5 bytes: 4 length + 1 null) + i32 offset (4 bytes)
        // = 9 bytes`. Used to bound the entries-vec pre-alloc against
        // the FDI byte budget, so a u32::MAX file_count claim can't
        // trigger a ~96 GiB `Vec::with_capacity`.
        const MIN_FDI_FILE_RECORD_BYTES: u64 = 5 + 4;

        // Slurp the main index region into memory so we can parse it
        // independently of the file reader's cursor (which we'll seek
        // elsewhere for the full directory index and path-hash index).
        let index_size_usize =
            usize::try_from(index_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: "index_size",
                    value: index_size,
                    path: None,
                },
            })?;
        let mut index_bytes = Vec::new();
        index_bytes
            .try_reserve_exact(index_size_usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "bytes for v10+ index",
                    requested: index_size_usize,
                    source,
                    path: None,
                },
            })?;
        index_bytes.resize(index_size_usize, 0);
        reader.read_exact(&mut index_bytes)?;
        let mut idx = Cursor::new(&index_bytes);

        let mount_point = read_fstring(&mut idx)?;
        let file_count = idx.read_u32::<LittleEndian>()?;
        let _path_hash_seed = idx.read_u64::<LittleEndian>()?; // used by the
        // path-hash table for cross-archive collision resistance; we don't
        // verify hashes today, so the seed is recorded only via comment.

        // Path-hash index header — optional region elsewhere in the file
        // mapping hash → encoded_entry_offset. We skip the table itself
        // because the full directory index gives us full paths, which we
        // hash into our own O(1) HashMap. Reading the header keeps the
        // index-size budget accurate.
        let has_path_hash_index = idx.read_u32::<LittleEndian>()? != 0;
        if has_path_hash_index {
            let _phi_offset = idx.read_u64::<LittleEndian>()?;
            let _phi_size = idx.read_u64::<LittleEndian>()?;
            let mut _phi_hash = [0u8; 20];
            idx.read_exact(&mut _phi_hash)?;
        }

        // Full directory index header. We MUST process this — it's how
        // we recover the (full_path, encoded_entry_offset) pairs.
        let has_full_directory_index = idx.read_u32::<LittleEndian>()? != 0;
        if !has_full_directory_index {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::MissingFullDirectoryIndex,
            });
        }
        let fdi_offset = idx.read_u64::<LittleEndian>()?;
        let fdi_size = idx.read_u64::<LittleEndian>()?;
        let mut _fdi_hash = [0u8; 20];
        idx.read_exact(&mut _fdi_hash)?;

        // Encoded entries blob: size prefix + N bytes of bit-packed records.
        let encoded_entries_size = idx.read_u32::<LittleEndian>()?;
        let encoded_entries_size_usize =
            usize::try_from(encoded_entries_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: "encoded_entries_size",
                    value: u64::from(encoded_entries_size),
                    path: None,
                },
            })?;
        // Bound against index_size — the encoded blob lives inside the
        // main index region. A malicious header claiming a multi-GB blob
        // would otherwise drive an unbounded `vec![0u8; N]` allocation.
        if u64::from(encoded_entries_size) > index_size {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "encoded_entries_size",
                    value: u64::from(encoded_entries_size),
                    limit: index_size,
                    unit: BoundsUnit::Bytes,
                    path: None,
                },
            });
        }
        let mut encoded_entries_blob: Vec<u8> = Vec::new();
        encoded_entries_blob
            .try_reserve_exact(encoded_entries_size_usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "bytes for v10+ encoded entries",
                    requested: encoded_entries_size_usize,
                    source,
                    path: None,
                },
            })?;
        encoded_entries_blob.resize(encoded_entries_size_usize, 0);
        idx.read_exact(&mut encoded_entries_blob)?;

        // Non-encoded entries: a fallback for FPakEntry records that don't
        // fit the bit-packed format. Stored as regular v8b-shape FPakEntry
        // records.
        let non_encoded_count = idx.read_u32::<LittleEndian>()?;
        let max_non_encoded = index_size / ENTRY_MIN_RECORD_BYTES;
        if u64::from(non_encoded_count) > max_non_encoded {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "non_encoded_count",
                    value: u64::from(non_encoded_count),
                    limit: max_non_encoded,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }
        let mut non_encoded_entries: Vec<PakEntryHeader> = Vec::new();
        non_encoded_entries
            .try_reserve_exact(non_encoded_count as usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "non-encoded entries for v10+ index",
                    requested: non_encoded_count as usize,
                    source,
                    path: None,
                },
            })?;
        for _ in 0..non_encoded_count {
            non_encoded_entries.push(PakEntryHeader::read_from(
                &mut idx,
                PakVersion::PathHashIndex,
                compression_methods,
            )?);
        }

        // Now seek to the full directory index in the file and read it.
        // The cap is the function-scoped MAX_FDI_BYTES.
        if fdi_size > MAX_FDI_BYTES {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "fdi_size",
                    value: fdi_size,
                    limit: MAX_FDI_BYTES,
                    unit: BoundsUnit::Bytes,
                    path: None,
                },
            });
        }
        let _ = reader.seek(SeekFrom::Start(fdi_offset))?;
        let fdi_size_usize =
            usize::try_from(fdi_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: "fdi_size",
                    value: fdi_size,
                    path: None,
                },
            })?;
        let mut fdi_bytes: Vec<u8> = Vec::new();
        fdi_bytes
            .try_reserve_exact(fdi_size_usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "bytes for v10+ full directory index",
                    requested: fdi_size_usize,
                    source,
                    path: None,
                },
            })?;
        fdi_bytes.resize(fdi_size_usize, 0);
        reader.read_exact(&mut fdi_bytes)?;
        let mut fdi = Cursor::new(&fdi_bytes);

        let dir_count = fdi.read_u32::<LittleEndian>()?;
        // Bound `file_count` against the FDI byte budget BEFORE allocating
        // the entries vec — file_count comes from the (untrusted) main
        // index header. Cap derives from the function-scoped
        // MIN_FDI_FILE_RECORD_BYTES (no FDI can carry more than
        // `fdi_size / 9` files regardless of what file_count claims).
        let max_files_for_fdi = fdi_size / MIN_FDI_FILE_RECORD_BYTES;
        if u64::from(file_count) > max_files_for_fdi {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "file_count",
                    value: u64::from(file_count),
                    limit: max_files_for_fdi,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }
        let mut entries: Vec<PakIndexEntry> = Vec::new();
        entries
            .try_reserve_exact(file_count as usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "entries for v10+ index",
                    requested: file_count as usize,
                    source,
                    path: None,
                },
            })?;
        for _ in 0..dir_count {
            let dir_name = read_fstring(&mut fdi)?;
            let dir_file_count = fdi.read_u32::<LittleEndian>()?;
            // Directory names are stored with a leading `/`; the joined
            // virtual path is `dir_name_without_leading_slash + file_name`.
            let dir_prefix = dir_name.strip_prefix('/').unwrap_or(&dir_name);
            for _ in 0..dir_file_count {
                let file_name = read_fstring(&mut fdi)?;
                let encoded_offset = fdi.read_i32::<LittleEndian>()?;
                let header = if encoded_offset >= 0 {
                    // Decode the bit-packed entry from the encoded blob.
                    let off_usize = usize::try_from(encoded_offset).map_err(|_| {
                        PaksmithError::InvalidIndex {
                            fault: IndexParseFault::EncodedOffsetUsizeOverflow {
                                offset: encoded_offset,
                            },
                        }
                    })?;
                    if off_usize >= encoded_entries_blob.len() {
                        return Err(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::EncodedOffsetOob {
                                offset: off_usize,
                                blob_size: encoded_entries_blob.len(),
                            },
                        });
                    }
                    let mut blob_cursor = Cursor::new(&encoded_entries_blob[off_usize..]);
                    PakEntryHeader::read_encoded(&mut blob_cursor, compression_methods)?
                } else {
                    // Negative offset: 1-based index into non-encoded entries.
                    let idx = usize::try_from(-i64::from(encoded_offset) - 1).map_err(|_| {
                        PaksmithError::InvalidIndex {
                            fault: IndexParseFault::EncodedOffsetUsizeOverflow {
                                offset: encoded_offset,
                            },
                        }
                    })?;
                    let count = non_encoded_entries.len();
                    non_encoded_entries
                        .get(idx)
                        .ok_or(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::NonEncodedIndexOob { index: idx, count },
                        })?
                        .clone()
                };
                let full_path = format!("{dir_prefix}{file_name}");
                // Per-push budget guard: the FDI's `dir_count × dir_file_count`
                // must agree with the main-index `file_count`. A malformed
                // FDI claiming more entries than file_count would silently
                // overflow the `try_reserve_exact` allocation and weaken
                // the round-1 file_count bound. The fdi_size cap still
                // bounds total work, but enforcing this here catches the
                // discrepancy at the wire-format layer.
                if entries.len() >= file_count as usize {
                    return Err(PaksmithError::InvalidIndex {
                        fault: IndexParseFault::FdiFileCountOverflow { file_count },
                    });
                }
                entries.push(PakIndexEntry {
                    filename: full_path,
                    header,
                });
            }
        }

        Self::from_entries(mount_point, entries)
    }

    /// Build a `PakIndex` from already-parsed mount + entries, populating
    /// the by-path HashMap and emitting the duplicate-filename warning.
    /// Common to both the flat (v3-v9) and path-hash (v10+) parsers.
    ///
    /// Fallible because `entries.len()` is bounded by the parsers'
    /// per-path `try_reserve_exact`, which can legitimately accept
    /// tens of millions of entries on a multi-GB pak. Actual HashMap
    /// memory is roughly `entries.len() / load_factor *
    /// sizeof(bucket) + sum(filename_bytes)`; hashbrown's load factor
    /// is ~7/8 so a 1M-entry index over-reserves to ~1.14M buckets,
    /// totalling hundreds of MiB at high entry counts. The
    /// `try_reserve` (NOT `try_reserve_exact`) call below preserves
    /// the prior `with_capacity(N)` behavior exactly — switching to
    /// `try_reserve_exact` would more tightly bound memory but would
    /// require pre-tuning the hint to account for the load factor or
    /// risk a reallocation during `insert`.
    ///
    /// **Test-coverage note:** the `try_reserve` failure path itself
    /// is unreachable in any portable test — triggering it would
    /// require either an injectable allocator harness or raising the
    /// per-path bounds enough to actually exhaust the test runner's
    /// memory. The bound checks at the call sites provide the
    /// user-facing protection; this function's role is to surface
    /// alloc failure as a typed error rather than `handle_alloc_error`.
    fn from_entries(mount_point: String, entries: Vec<PakIndexEntry>) -> crate::Result<Self> {
        // Build the path → index lookup. **Last-wins** on duplicate
        // paths — a deliberate divergence from the previous linear-scan
        // `find` (which was first-wins). UE writers don't emit duplicate
        // filenames in normal flow, so a pak that contains them is
        // either deliberately shadowing (some mod tools do this to
        // override base assets — last-wins is the right semantic for
        // that case) or malformed. We surface duplicates via a single
        // aggregated `warn!` (rather than one log line per duplicate) so
        // a pathological pak with N duplicates can't flood operator
        // logs by O(N).
        let mut by_path: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let entries_len = entries.len();
        by_path
            .try_reserve(entries_len)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "by-path lookup entries",
                    requested: entries_len,
                    source,
                    path: None,
                },
            })?;
        let mut dup_count: usize = 0;
        let mut sampled_dups: Vec<&str> = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            if by_path.insert(entry.filename.clone(), i).is_some() {
                dup_count += 1;
                if sampled_dups.len() < MAX_SAMPLED_DUPS {
                    sampled_dups.push(&entry.filename);
                }
            }
        }
        if dup_count > 0 {
            warn!(
                dup_count,
                samples = ?sampled_dups,
                "pak index contains {dup_count} duplicate filename(s) — last entry wins for each; \
                 first {} shown",
                sampled_dups.len()
            );
        }

        Ok(Self {
            mount_point,
            entries,
            by_path,
        })
    }
}

impl PakIndexEntry {
    fn read_from<R: Read>(
        reader: &mut R,
        version: PakVersion,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let filename = read_fstring(reader)?;
        let header = PakEntryHeader::read_from(reader, version, compression_methods)?;
        Ok(Self { filename, header })
    }
}

/// Read an Unreal `FString`.
///
/// Length encoding: a signed `i32` where the sign selects encoding —
/// positive = UTF-8 byte count (including null terminator),
/// negative = UTF-16 code-unit count (including null terminator), absolute value.
/// A value of `0` denotes the empty string.
///
/// Errors out (rather than silently truncating) when the trailing null
/// terminator is missing or when the length exceeds [`FSTRING_MAX_LEN`].
fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    if len == 0 {
        return Ok(String::new());
    }

    let Some(abs_len) = len.checked_abs() else {
        // i32::MIN has no positive counterpart; reject.
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::LengthIsI32Min,
            },
        });
    };
    if abs_len > FSTRING_MAX_LEN {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::LengthExceedsMaximum {
                    length: abs_len as u32,
                    maximum: FSTRING_MAX_LEN as u32,
                },
            },
        });
    }
    let abs_len = abs_len as usize;

    if len < 0 {
        let mut buf = vec![0u16; abs_len];
        for item in &mut buf {
            *item = reader.read_u16::<LittleEndian>()?;
        }
        match buf.last() {
            Some(&0) => {
                let _ = buf.pop();
            }
            _ => {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::FStringMalformed {
                        kind: FStringFault::MissingNullTerminator {
                            encoding: FStringEncoding::Utf16,
                        },
                    },
                });
            }
        }
        return String::from_utf16(&buf).map_err(|_| PaksmithError::InvalidIndex {
            fault: IndexParseFault::FStringMalformed {
                kind: FStringFault::InvalidEncoding {
                    encoding: FStringEncoding::Utf16,
                },
            },
        });
    }

    let mut buf = vec![0u8; abs_len];
    reader.read_exact(&mut buf)?;
    match buf.last() {
        Some(&0) => {
            let _ = buf.pop();
        }
        _ => {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::FStringMalformed {
                    kind: FStringFault::MissingNullTerminator {
                        encoding: FStringEncoding::Utf8,
                    },
                },
            });
        }
    }
    String::from_utf8(buf).map_err(|_| PaksmithError::InvalidIndex {
        fault: IndexParseFault::FStringMalformed {
            kind: FStringFault::InvalidEncoding {
                encoding: FStringEncoding::Utf8,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::WriteBytesExt;

    use super::*;

    /// FNV1A path hash baseline: an empty path with seed 0 is the
    /// canonical FNV-1a 64-bit offset basis (no bytes are mixed in).
    /// Seed 1 produces a hash exactly 1 higher (the seed is added to
    /// the offset basis at init).
    #[test]
    fn fnv64_path_baseline_known_vectors() {
        assert_eq!(fnv64_path("", 0), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv64_path("", 1), 0xcbf2_9ce4_8422_2326);
        // Different seeds always shift the output even for the empty input.
        assert_ne!(fnv64_path("", 0), fnv64_path("", u64::MAX));
    }

    /// FNV1A path hash determinism + case-insensitivity. UE's path-hash
    /// index lookup relies on consistent hashing across writers, and
    /// case folding (`Foo` == `foo` == `FOO`) is what makes the hash
    /// usable for the case-insensitive UE path semantics.
    #[test]
    fn fnv64_path_is_deterministic_and_case_insensitive_ascii() {
        let a = fnv64_path("Content/Foo.uasset", 0);
        let b = fnv64_path("Content/Foo.uasset", 0);
        assert_eq!(a, b, "fnv64_path must be deterministic");

        let lower = fnv64_path("content/foo.uasset", 0);
        let upper = fnv64_path("CONTENT/FOO.UASSET", 0);
        let mixed = fnv64_path("Content/Foo.uasset", 0);
        assert_eq!(lower, mixed);
        assert_eq!(upper, mixed);
    }

    /// FNV1A path hash actually mixes input bytes (i.e., different paths
    /// produce different hashes — sanity-check we're not always returning
    /// the offset basis).
    #[test]
    fn fnv64_path_distinguishes_different_inputs() {
        let h1 = fnv64_path("Content/Foo.uasset", 0);
        let h2 = fnv64_path("Content/Bar.uasset", 0);
        assert_ne!(h1, h2);
    }

    /// Pin the documented ASCII-only-lowercasing limitation: a non-
    /// ASCII upper/lower pair that UE's Unicode-aware lowercasing
    /// would fold to the same hash. Our `to_ascii_lowercase` skips
    /// the non-ASCII codepoint, so the two inputs hash differently.
    /// This test exists solely to surface a behavior change if we
    /// ever swap in a Unicode-aware lowercaser — at which point this
    /// test should flip its assertion to `assert_eq!`.
    #[test]
    fn fnv64_path_ascii_only_lowercase_diverges_for_non_ascii() {
        // U+00C9 LATIN CAPITAL LETTER E WITH ACUTE vs U+00E9 lowercase
        // counterpart. UE folds these together; we don't.
        let upper = fnv64_path("Content/Caf\u{00C9}.uasset", 0);
        let lower = fnv64_path("Content/Caf\u{00E9}.uasset", 0);
        assert_ne!(
            upper, lower,
            "ASCII-only lowercasing should leave non-ASCII codepoints distinct; \
             flip this assertion if Unicode-aware folding is added"
        );
    }

    /// `CompressionMethod::from_name` resolution: known FName names
    /// resolve to their canonical variant (case-insensitive); unknown
    /// names preserve the raw string in `UnknownByName`.
    #[test]
    fn from_name_resolves_known_and_preserves_unknown() {
        assert_eq!(
            CompressionMethod::from_name("Zlib"),
            CompressionMethod::Zlib
        );
        assert_eq!(
            CompressionMethod::from_name("zlib"),
            CompressionMethod::Zlib
        );
        assert_eq!(
            CompressionMethod::from_name("ZLIB"),
            CompressionMethod::Zlib
        );
        assert_eq!(
            CompressionMethod::from_name("Gzip"),
            CompressionMethod::Gzip
        );
        assert_eq!(
            CompressionMethod::from_name("Oodle"),
            CompressionMethod::Oodle
        );
        assert_eq!(
            CompressionMethod::from_name("Zstd"),
            CompressionMethod::Zstd
        );
        assert_eq!(CompressionMethod::from_name("LZ4"), CompressionMethod::Lz4);

        // Unknown names preserve the raw string so the operator-visible
        // error names what the slot actually held.
        match CompressionMethod::from_name("OodleNetwork") {
            CompressionMethod::UnknownByName(name) => assert_eq!(name, "OodleNetwork"),
            other => panic!("expected UnknownByName, got {other:?}"),
        }
    }

    fn write_fstring(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
            .unwrap();
        buf.extend_from_slice(bytes);
        buf.push(0);
    }

    fn write_fstring_utf16(buf: &mut Vec<u8>, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let total_units = units.len() + 1; // include null terminator
        buf.write_i32::<LittleEndian>(-(total_units as i32))
            .unwrap();
        for u in units {
            buf.write_u16::<LittleEndian>(u).unwrap();
        }
        buf.write_u16::<LittleEndian>(0).unwrap();
    }

    fn write_uncompressed_entry(buf: &mut Vec<u8>, filename: &str, offset: u64, size: u64) {
        write_fstring(buf, filename);
        buf.write_u64::<LittleEndian>(offset).unwrap();
        buf.write_u64::<LittleEndian>(size).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // no compression
        buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
        buf.push(0); // not encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_compressed_entry(
        buf: &mut Vec<u8>,
        filename: &str,
        offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        blocks: &[(u64, u64)],
        block_size: u32,
        encrypted: bool,
    ) {
        write_fstring(buf, filename);
        buf.write_u64::<LittleEndian>(offset).unwrap();
        buf.write_u64::<LittleEndian>(compressed_size).unwrap();
        buf.write_u64::<LittleEndian>(uncompressed_size).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
        buf.write_u32::<LittleEndian>(blocks.len() as u32).unwrap();
        for (start, end) in blocks {
            buf.write_u64::<LittleEndian>(*start).unwrap();
            buf.write_u64::<LittleEndian>(*end).unwrap();
        }
        buf.push(u8::from(encrypted));
        buf.write_u32::<LittleEndian>(block_size).unwrap();
    }

    fn build_index_bytes(mount: &str, entries_writer: impl FnOnce(&mut Vec<u8>) -> u32) -> Vec<u8> {
        let mut data = Vec::new();
        write_fstring(&mut data, mount);
        // Reserve space for entry_count, fill in after.
        let count_pos = data.len();
        data.write_u32::<LittleEndian>(0).unwrap();
        let count = entries_writer(&mut data);
        data[count_pos..count_pos + 4].copy_from_slice(&count.to_le_bytes());
        data
    }

    #[test]
    fn parse_index_single_entry() {
        let data = build_index_bytes("../../../", |buf| {
            write_uncompressed_entry(buf, "Content/Textures/hero.uasset", 0, 1024);
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        assert_eq!(index.mount_point(), "../../../");
        assert_eq!(index.entries().len(), 1);
        let e = &index.entries()[0];
        assert_eq!(e.filename(), "Content/Textures/hero.uasset");
        assert_eq!(e.header().uncompressed_size(), 1024);
        assert_eq!(e.header().compression_method(), &CompressionMethod::None);
        assert!(!e.header().is_encrypted());
        assert!(e.header().compression_blocks().is_empty());
        assert_eq!(e.header().compression_block_size(), 0);
    }

    #[test]
    fn parse_index_multiple_entries() {
        let data = build_index_bytes("../../../", |buf| {
            write_uncompressed_entry(buf, "Content/a.uasset", 0, 100);
            write_uncompressed_entry(buf, "Content/b.uasset", 100, 200);
            write_uncompressed_entry(buf, "Content/c.uasset", 300, 50);
            3
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        assert_eq!(index.entries().len(), 3);
        assert_eq!(index.entries()[0].filename(), "Content/a.uasset");
        assert_eq!(index.entries()[1].filename(), "Content/b.uasset");
        assert_eq!(index.entries()[2].filename(), "Content/c.uasset");
        assert_eq!(index.entries()[2].header().uncompressed_size(), 50);
    }

    /// Pin the last-wins semantic on duplicate filenames. UE writers
    /// don't normally emit duplicates, but some mod tools deliberately
    /// shadow base assets that way and `find()` must resolve to the
    /// shadowing entry. This is a deliberate divergence from the
    /// pre-HashMap linear-scan `find` (which was first-wins) — locking
    /// it down so a future "let's switch back" change has to update
    /// this test consciously.
    #[test]
    fn duplicate_filename_resolves_to_last_entry() {
        let data = build_index_bytes("../../../", |buf| {
            // Two entries with the same filename, different sizes so
            // we can tell which one `find` returned.
            write_uncompressed_entry(buf, "Content/dup.uasset", 0, 10);
            write_uncompressed_entry(buf, "Content/dup.uasset", 10, 999);
            2
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        assert_eq!(
            index.entries().len(),
            2,
            "both entries kept in the entries vec"
        );
        let found = index
            .find("Content/dup.uasset")
            .expect("duplicate path must resolve");
        assert_eq!(
            found.header().uncompressed_size(),
            999,
            "find() must return the LAST entry on duplicate filenames (shadowing semantic)"
        );
    }

    #[test]
    fn parse_empty_index() {
        let data = build_index_bytes("../../../", |_| 0);
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        assert_eq!(index.entries().len(), 0);
        assert_eq!(index.mount_point(), "../../../");
    }

    #[test]
    fn parse_compressed_entry_preserves_blocks() {
        let data = build_index_bytes("../../../", |buf| {
            write_compressed_entry(
                buf,
                "Content/big.uasset",
                100,
                4096,
                8192,
                &[(0, 2048), (2048, 4096)],
                65_536,
                false,
            );
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        let entry = &index.entries()[0];
        assert_eq!(
            entry.header().compression_method(),
            &CompressionMethod::Zlib
        );
        assert_eq!(entry.header().compressed_size(), 4096);
        assert_eq!(entry.header().uncompressed_size(), 8192);
        assert_eq!(
            entry.header().compression_blocks(),
            &[
                CompressionBlock::new(0, 2048).unwrap(),
                CompressionBlock::new(2048, 4096).unwrap(),
            ]
        );
        assert_eq!(entry.header().compression_block_size(), 65_536);
        assert!(!entry.header().is_encrypted());
    }

    #[test]
    fn parse_encrypted_entry_flag() {
        let data = build_index_bytes("../../../", |buf| {
            write_compressed_entry(
                buf,
                "Content/secret.uasset",
                0,
                512,
                512,
                &[(0, 512)],
                65_536,
                true,
            );
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();
        assert!(index.entries()[0].header().is_encrypted());
    }

    #[test]
    fn parse_utf16_fstring_roundtrip() {
        let data = build_index_bytes("../../../", |buf| {
            write_fstring_utf16(buf, "Content/Maps/レベル.umap");
            buf.write_u64::<LittleEndian>(0).unwrap();
            buf.write_u64::<LittleEndian>(64).unwrap();
            buf.write_u64::<LittleEndian>(64).unwrap();
            buf.write_u32::<LittleEndian>(0).unwrap();
            buf.extend_from_slice(&[0u8; 20]);
            buf.push(0); // is_encrypted
            buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();
        assert_eq!(index.entries()[0].filename(), "Content/Maps/レベル.umap");
    }

    #[test]
    fn reject_oversized_fstring() {
        let mut data = Vec::new();
        // Mount point: claim length of 1MB, but provide nothing.
        data.write_i32::<LittleEndian>(1_000_000).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                // Pin the size-cap branch specifically.
                assert!(
                    reason.contains("FString length") && reason.contains("maximum"),
                    "expected FString length cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn reject_fstring_missing_null_terminator() {
        let mut data = Vec::new();
        // Length 4 (claims null-terminated 3-byte string), bytes are not null-terminated.
        data.write_i32::<LittleEndian>(4).unwrap();
        data.extend_from_slice(b"abcd"); // last byte is 'd', not 0
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("null terminator"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn reject_oversized_entry_count() {
        // Tiny budget, claim huge entry_count.
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(u32::MAX).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(
                    reason.contains("entry_count"),
                    "expected entry_count cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn reject_compression_block_start_after_end() {
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(1).unwrap();
        write_fstring(&mut data, "x");
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u32::<LittleEndian>(1).unwrap(); // zlib
        data.extend_from_slice(&[0u8; 20]);
        data.write_u32::<LittleEndian>(1).unwrap(); // 1 block
        data.write_u64::<LittleEndian>(100).unwrap(); // start
        data.write_u64::<LittleEndian>(50).unwrap(); // end < start
        data.push(0); // not encrypted
        data.write_u32::<LittleEndian>(65_536).unwrap(); // block size
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("start"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn compression_block_constructor_rejects_inverted_range() {
        let err = CompressionBlock::new(100, 50).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidIndex { .. }));
    }

    #[test]
    fn compression_block_len_and_is_empty() {
        let b = CompressionBlock::new(10, 30).unwrap();
        assert_eq!(b.len(), 20);
        assert!(!b.is_empty());

        let empty = CompressionBlock::new(5, 5).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn reject_oversized_block_count() {
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(1).unwrap();
        write_fstring(&mut data, "x");
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u32::<LittleEndian>(1).unwrap(); // zlib
        data.extend_from_slice(&[0u8; 20]);
        data.write_u32::<LittleEndian>(u32::MAX).unwrap(); // huge block count
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(
                    reason.contains("block_count"),
                    "expected block_count cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn compression_method_from_u32() {
        assert_eq!(CompressionMethod::from_u32(0), CompressionMethod::None);
        assert_eq!(CompressionMethod::from_u32(1), CompressionMethod::Zlib);
        assert_eq!(CompressionMethod::from_u32(4), CompressionMethod::Oodle);
        assert_eq!(
            CompressionMethod::from_u32(99),
            CompressionMethod::Unknown(99)
        );
    }

    #[test]
    fn pak_entry_header_round_trip_uncompressed() {
        let mut buf = Vec::new();
        // Inline (no helper — keep this test self-contained).
        buf.write_u64::<LittleEndian>(0).unwrap(); // offset
        buf.write_u64::<LittleEndian>(100).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(100).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // none
        buf.extend_from_slice(&[0xABu8; 20]); // sha1
        buf.push(0); // not encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)

        let mut cursor = Cursor::new(buf);
        let header =
            PakEntryHeader::read_from(&mut cursor, PakVersion::CompressionEncryption, &[]).unwrap();

        assert_eq!(header.offset(), 0);
        assert_eq!(header.compressed_size(), 100);
        assert_eq!(header.uncompressed_size(), 100);
        assert_eq!(header.compression_method(), &CompressionMethod::None);
        assert_eq!(header.sha1(), &[0xABu8; 20]);
        assert!(!header.is_encrypted());
        assert!(header.compression_blocks().is_empty());
        assert_eq!(header.compression_block_size(), 0);
    }

    #[test]
    fn pak_entry_header_round_trip_compressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(50).unwrap();
        buf.write_u64::<LittleEndian>(200).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(2).unwrap(); // 2 blocks
        buf.write_u64::<LittleEndian>(73).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(123).unwrap();
        buf.push(1); // encrypted
        buf.write_u32::<LittleEndian>(100).unwrap(); // block size

        let mut cursor = Cursor::new(buf);
        let header =
            PakEntryHeader::read_from(&mut cursor, PakVersion::CompressionEncryption, &[]).unwrap();

        assert_eq!(header.compression_method(), &CompressionMethod::Zlib);
        assert!(header.is_encrypted());
        assert_eq!(header.compression_blocks().len(), 2);
        assert_eq!(
            header.compression_blocks()[0],
            CompressionBlock::new(73, 98).unwrap()
        );
        assert_eq!(header.compression_block_size(), 100);
    }

    fn make_header(compressed_size: u64, uncompressed_size: u64, sha1: [u8; 20]) -> PakEntryHeader {
        PakEntryHeader {
            offset: 0,
            compressed_size,
            uncompressed_size,
            compression_method: CompressionMethod::None,
            is_encrypted: false,
            sha1,
            omits_sha1: false,
            compression_blocks: Vec::new(),
            compression_block_size: 0,
            // Default to a non-V8A version so wire_size returns the
            // standard 53-byte size; tests that need the V8A layout
            // construct directly with `version: PakVersion::V8A`.
            version: PakVersion::DeleteRecords,
        }
    }

    /// V8+ entry referencing a `None` slot in the compression-method
    /// table must resolve to `UnknownByName` (or in-range-but-empty:
    /// `Unknown(slot_index)`) rather than `None`. The previous
    /// implementation silently treated empty slots as "no compression"
    /// — that was the round-1 silent-failure-hunter HIGH (H1):
    /// downstream `read_entry` would happily return raw bytes from a
    /// compressed entry as if uncompressed.
    #[test]
    fn v8plus_entry_referencing_none_slot_resolves_to_unknown() {
        // Build a v8b+ entry with compression byte = 1 (1-based table
        // index — references slot 0).
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap(); // offset
        buf.write_u64::<LittleEndian>(100).unwrap(); // compressed_size
        buf.write_u64::<LittleEndian>(100).unwrap(); // uncompressed_size
        buf.write_u32::<LittleEndian>(1).unwrap(); // compression byte = slot 1 (1-based)
        buf.extend_from_slice(&[0u8; 20]); // sha1
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_count = 0 because compression IS set
        buf.push(0); // is_encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size

        // Compression-methods table with slot 0 = None (slot was empty
        // in the source pak).
        let methods = vec![None, None, None, None, None];
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor, PakVersion::V8B, &methods).unwrap();

        // Resolution: byte=1 → table[0] = None → unwrap_or to Unknown(1).
        assert_eq!(
            header.compression_method(),
            &CompressionMethod::Unknown(1),
            "byte references a None slot — must resolve to Unknown(slot_index), not silently coerce to None"
        );
    }

    /// V8+ entry referencing a slot containing an unrecognized FName
    /// must surface as `UnknownByName(name)` so the operator can see
    /// what the slot held.
    #[test]
    fn v8plus_entry_referencing_unknown_name_surfaces_name() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u32::<LittleEndian>(2).unwrap(); // byte = 2 → slot 1
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.push(0);
        buf.write_u32::<LittleEndian>(0).unwrap();

        // Slot 1 contains a real-but-unsupported method (UE has used
        // names like "OodleNetwork" historically). Must round-trip the
        // string into the diagnostic.
        let methods = vec![
            None,
            Some(CompressionMethod::UnknownByName("OodleNetwork".into())),
            None,
            None,
            None,
        ];
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor, PakVersion::V8B, &methods).unwrap();

        match header.compression_method() {
            CompressionMethod::UnknownByName(name) => {
                assert_eq!(name, "OodleNetwork");
            }
            other => panic!("expected UnknownByName(\"OodleNetwork\"), got {other:?}"),
        }
    }

    /// V8+ entry with compression byte = 0 always means "no compression"
    /// regardless of table contents. This is the load-bearing UE
    /// convention that lets uncompressed entries skip the table lookup.
    #[test]
    fn v8plus_entry_compression_byte_zero_resolves_to_none() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap(); // byte = 0 → no compression
        buf.extend_from_slice(&[0u8; 20]);
        buf.push(0);
        buf.write_u32::<LittleEndian>(0).unwrap();

        // Even with all slots populated, byte=0 must not consult the table.
        let methods = vec![Some(CompressionMethod::Zlib); 5];
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor, PakVersion::V8B, &methods).unwrap();

        assert_eq!(header.compression_method(), &CompressionMethod::None);
    }

    /// Args for [`encode_entry_bytes`]. Consolidated into a struct so a
    /// new field doesn't require touching every call site, and to keep
    /// the function under clippy's argument-count limit. `Copy` so the
    /// helper takes by value without a needless-pass-by-value lint.
    #[derive(Copy, Clone)]
    struct EncodeArgs<'a> {
        offset: u64,
        uncompressed: u64,
        compressed: u64,
        compression_slot_1based: u32,
        encrypted: bool,
        block_count: u32,
        block_size: u32,
        per_block_sizes: &'a [u32],
    }

    /// Append `value` to `buf` as a u32-LE if it fits, else u64-LE.
    /// Mirrors the wire-format var-int encoding used by encoded entries
    /// for offset/uncompressed/compressed.
    fn push_var_int(buf: &mut Vec<u8>, value: u64) {
        match u32::try_from(value) {
            Ok(v) => buf.extend_from_slice(&v.to_le_bytes()),
            Err(_) => buf.extend_from_slice(&value.to_le_bytes()),
        }
    }

    /// Build a v10+ bit-packed encoded-entry buffer from the parameters
    /// the parser's bit-shift logic should round-trip. Mirrors UE's
    /// `FPakEntry::EncodeTo` (and repak's `Entry::write_encoded`) so a
    /// future change to either encoder/decoder side surfaces here.
    fn encode_entry_bytes(args: EncodeArgs<'_>) -> Vec<u8> {
        // Encode block_size: stored as 5 bits left-shifted by 11, with
        // sentinel 0x3f meaning "doesn't fit; read u32 verbatim."
        let (block_size_bits, write_block_size_extra) = {
            let candidate = args.block_size >> 11;
            if (candidate << 11) == args.block_size && candidate < 0x3f {
                (candidate, false)
            } else {
                (0x3f, true)
            }
        };
        let offset_fits_u32 = u32::try_from(args.offset).is_ok();
        let uncompressed_fits_u32 = u32::try_from(args.uncompressed).is_ok();
        let compressed_fits_u32 = u32::try_from(args.compressed).is_ok();

        let mut bits: u32 = block_size_bits;
        bits |= (args.block_count & 0xffff) << 6;
        bits |= u32::from(args.encrypted) << 22;
        bits |= (args.compression_slot_1based & 0x3f) << 23;
        // u32-fits flags: set if value fits in u32.
        bits |= u32::from(compressed_fits_u32) << 29;
        bits |= u32::from(uncompressed_fits_u32) << 30;
        bits |= u32::from(offset_fits_u32) << 31;

        let mut buf = Vec::new();
        buf.extend_from_slice(&bits.to_le_bytes());
        if write_block_size_extra {
            buf.extend_from_slice(&args.block_size.to_le_bytes());
        }
        // var_int(31) — offset; var_int(30) — uncompressed.
        push_var_int(&mut buf, args.offset);
        push_var_int(&mut buf, args.uncompressed);
        // var_int(29) — compressed, only present when compression slot != 0.
        if args.compression_slot_1based != 0 {
            push_var_int(&mut buf, args.compressed);
        }
        // Per-block sizes for the non-trivial layouts (multi-block, or
        // single-block-but-encrypted). The single-uncompressed-block case
        // is reconstructed by the decoder from the in-data record size,
        // so no per-block sizes appear in the wire stream.
        let needs_per_block_sizes =
            args.block_count > 0 && (args.block_count != 1 || args.encrypted);
        if needs_per_block_sizes {
            assert_eq!(
                args.per_block_sizes.len(),
                args.block_count as usize,
                "test must supply N block sizes for non-trivial block layout"
            );
            for &s in args.per_block_sizes {
                buf.extend_from_slice(&s.to_le_bytes());
            }
        }
        buf
    }

    /// V10+ encoded entry: trivial uncompressed case (byte=0, no blocks).
    #[test]
    fn read_encoded_uncompressed_no_blocks() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0x100,
            uncompressed: 0x4000,
            compressed: 0x4000,
            compression_slot_1based: 0,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();

        assert_eq!(header.compression_method(), &CompressionMethod::None);
        assert_eq!(header.offset(), 0x100);
        assert_eq!(header.uncompressed_size(), 0x4000);
        assert_eq!(header.compressed_size(), 0x4000);
        assert!(header.compression_blocks().is_empty());
        assert!(!header.is_encrypted());
        assert_eq!(header.sha1(), &[0u8; 20]);
    }

    /// V10+ encoded entry: u64-width offset/uncompressed/compressed
    /// (values that don't fit in u32). Exercises the variable-width
    /// branches in the decoder.
    #[test]
    fn read_encoded_u64_widths() {
        let huge_offset: u64 = u64::from(u32::MAX) + 1;
        let huge_uncompressed: u64 = u64::from(u32::MAX) + 100;
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: huge_offset,
            uncompressed: huge_uncompressed,
            compressed: huge_uncompressed,
            compression_slot_1based: 0,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();

        assert_eq!(header.offset(), huge_offset);
        assert_eq!(header.uncompressed_size(), huge_uncompressed);
        assert_eq!(header.compressed_size(), huge_uncompressed);
    }

    /// V10+ encoded entry: single zlib block, !encrypted. Exercises the
    /// "trivial single-block-derivable" shortcut where no per-block
    /// sizes appear in the wire stream.
    #[test]
    fn read_encoded_single_block_zlib() {
        let methods = vec![Some(CompressionMethod::Zlib)];
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0x200,
            uncompressed: 0x4000,
            compressed: 0x1234,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 1,
            block_size: 0x10000,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap();

        assert_eq!(header.compression_method(), &CompressionMethod::Zlib);
        assert_eq!(header.compression_blocks().len(), 1);
        // Single-block layout: start = in_data_record_size; end = start + compressed.
        let header_size = encoded_entry_in_data_record_size(true, 1);
        assert_eq!(header.compression_blocks()[0].start(), header_size);
        assert_eq!(header.compression_blocks()[0].end(), header_size + 0x1234);
    }

    /// V10+ encoded entry: multi-block zlib. Exercises the per-block
    /// u32 size stream + cursor advance.
    #[test]
    fn read_encoded_multi_block_zlib() {
        let methods = vec![Some(CompressionMethod::Zlib)];
        let block_sizes = [0x100u32, 0x200, 0x300];
        let total_compressed: u64 = block_sizes.iter().map(|&s| u64::from(s)).sum();
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x4000,
            compressed: total_compressed,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 3,
            block_size: 0x10000,
            per_block_sizes: &block_sizes,
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap();

        assert_eq!(header.compression_blocks().len(), 3);
        let header_size = encoded_entry_in_data_record_size(true, 3);
        // Block 0: [header_size, header_size + 0x100)
        assert_eq!(header.compression_blocks()[0].start(), header_size);
        assert_eq!(header.compression_blocks()[0].end(), header_size + 0x100);
        // Block 1: [header_size + 0x100, header_size + 0x300)
        assert_eq!(header.compression_blocks()[1].start(), header_size + 0x100);
        assert_eq!(header.compression_blocks()[1].end(), header_size + 0x300);
        // Block 2: [header_size + 0x300, header_size + 0x600)
        assert_eq!(header.compression_blocks()[2].start(), header_size + 0x300);
        assert_eq!(header.compression_blocks()[2].end(), header_size + 0x600);
    }

    /// V10+ encoded entry: encrypted multi-block. Each block's cursor
    /// advance pads to AES-16-byte alignment, so block N+1's `start`
    /// reflects the aligned (not raw) end of block N. Pinning this
    /// catches a regression that drops the alignment.
    #[test]
    fn read_encoded_encrypted_multi_block_aes_aligned() {
        let methods = vec![Some(CompressionMethod::Zlib)];
        // Pick sizes that aren't already 16-byte-aligned to actually
        // exercise the alignment math.
        let block_sizes = [0x101u32, 0x103, 0x10F]; // 257, 259, 271 bytes
        let total_compressed: u64 = block_sizes.iter().map(|&s| u64::from(s)).sum();
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x4000,
            compressed: total_compressed,
            compression_slot_1based: 1,
            encrypted: true,
            block_count: 3,
            block_size: 0x10000,
            per_block_sizes: &block_sizes,
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap();

        assert!(header.is_encrypted());
        let header_size = encoded_entry_in_data_record_size(true, 3);
        let aligned = |n: u64| (n + 15) & !15;

        // Block 0 starts at header_size; ends at header_size + 0x101 (raw, not aligned).
        assert_eq!(header.compression_blocks()[0].start(), header_size);
        assert_eq!(header.compression_blocks()[0].end(), header_size + 0x101);
        // Block 1 starts at header_size + aligned(0x101) = header_size + 0x110.
        let block1_start = header_size + aligned(0x101);
        assert_eq!(header.compression_blocks()[1].start(), block1_start);
        assert_eq!(header.compression_blocks()[1].end(), block1_start + 0x103);
        // Block 2 starts at block1_start + aligned(0x103) = block1_start + 0x110.
        let block2_start = block1_start + aligned(0x103);
        assert_eq!(header.compression_blocks()[2].start(), block2_start);
        assert_eq!(header.compression_blocks()[2].end(), block2_start + 0x10F);
    }

    /// V10+ encoded entry: block_size = 0x3f sentinel means "doesn't
    /// fit in 5 bits scaled by 11; read the next u32 verbatim."
    /// Exercise an unusual block size like 12345 that won't compress
    /// into the bit-packed form.
    #[test]
    fn read_encoded_block_size_sentinel() {
        let methods = vec![Some(CompressionMethod::Zlib)];
        let weird_block_size: u32 = 12_345; // not divisible by 2048 (= 1 << 11)
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x4000,
            compressed: 0x100,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 1,
            block_size: weird_block_size,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap();

        assert_eq!(
            header.compression_block_size(),
            weird_block_size,
            "0x3f sentinel must read the explicit u32 block_size"
        );
    }

    /// V10+ encoded entry: zero blocks but a non-`None` compression
    /// slot. The else-branch of the per-block-sizes if/else chain
    /// (`block_count > 0 && (block_count != 1 || encrypted)` is false
    /// when `block_count == 0`) returns `Vec::new()` — pin that the
    /// compression method is still resolved from the slot table even
    /// without any blocks present.
    #[test]
    fn read_encoded_zero_blocks_with_compression_slot() {
        let methods = vec![Some(CompressionMethod::Zlib)];
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x100,
            compressed: 0x100,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap();

        assert_eq!(header.compression_method(), &CompressionMethod::Zlib);
        assert!(
            header.compression_blocks().is_empty(),
            "block_count = 0 must yield an empty blocks vec"
        );
    }

    /// `PakIndexEntry::omits_sha1` is a one-hop delegator over
    /// `PakEntryHeader::omits_sha1`. Pin both polarities directly so a
    /// stub bug like `pub fn omits_sha1(&self) -> bool { false }`
    /// would fail HERE rather than only being caught by integration
    /// tests where `archive_claims_integrity()` happens to be true.
    /// (The negative-branch integration test
    /// `verify_v10_with_zero_index_hash_still_skips_encoded_entries`
    /// would NOT catch a stub-to-false: with `false && X = false`,
    /// the gate skips correctly anyway.)
    #[test]
    fn pak_index_entry_omits_sha1_delegates_to_header() {
        let mut header = make_header(0, 0, [0u8; 20]);
        header.omits_sha1 = true;
        let entry = PakIndexEntry {
            filename: "x".to_string(),
            header,
        };
        assert!(entry.header().omits_sha1());

        let mut header = make_header(0, 0, [0u8; 20]);
        header.omits_sha1 = false;
        let entry = PakIndexEntry {
            filename: "y".to_string(),
            header,
        };
        assert!(!entry.header().omits_sha1());
    }

    /// V10+ encoded entries always set `omits_sha1 = true` so
    /// `matches_payload` skips the SHA1 cross-check (encoded entries
    /// never carry SHA1 in the wire format).
    #[test]
    fn read_encoded_marks_omits_sha1() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x100,
            compressed: 0x100,
            compression_slot_1based: 0,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();
        assert!(header.omits_sha1, "encoded entries must mark omits_sha1");
        assert_eq!(header.sha1, [0u8; 20]);
    }

    /// `matches_payload`'s SHA1 skip ONLY fires for encoded entries
    /// (omits_sha1=true). For a v3-v9 entry where the index claims a
    /// zero SHA1 but the in-data record has a real SHA1, the mismatch
    /// must still surface as InvalidIndex — that's the tampering
    /// signal we preserve from the pre-PR-#27 behavior.
    #[test]
    fn matches_payload_keeps_zero_sha1_check_for_v3_v9() {
        // Index entry: zero sha1, omits_sha1=false (v3-v9 default).
        let index = make_header(100, 100, [0u8; 20]);
        // In-data record: non-zero sha1. Pre-PR this surfaced as a
        // tampering signal; gating the skip on omits_sha1 preserves it.
        let in_data = make_header(100, 100, [0xBB; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("sha1")),
            "got: {err:?}"
        );
    }

    /// `matches_payload`'s SHA1 skip DOES fire for v10+ encoded entries
    /// (omits_sha1=true). The in-data record carries a real SHA1, the
    /// index header has zero, and the check is skipped — without this
    /// every v10+ entry would fail to extract.
    #[test]
    fn matches_payload_skips_sha1_for_encoded_entries() {
        let mut index = make_header(100, 100, [0u8; 20]);
        index.omits_sha1 = true; // simulate a v10+ encoded entry
        let in_data = make_header(100, 100, [0xBB; 20]);
        assert!(
            index.matches_payload(&in_data, "x").is_ok(),
            "encoded entries must skip the SHA1 cross-check"
        );
    }

    /// Append an FDI ("full directory index") body to `buf` from a flat
    /// (dir_name, [(file_name, encoded_offset_i32)]) spec. The wire shape
    /// is `dir_count u32` followed by per-dir `FString name + file_count
    /// u32 + per-file FString filename + i32 encoded_offset`.
    fn write_fdi_body(buf: &mut Vec<u8>, dirs: &[(&str, &[(&str, i32)])]) {
        buf.write_u32::<LittleEndian>(dirs.len() as u32).unwrap();
        for (dir_name, files) in dirs {
            write_fstring(buf, dir_name);
            buf.write_u32::<LittleEndian>(files.len() as u32).unwrap();
            for (file_name, encoded_offset) in *files {
                write_fstring(buf, file_name);
                buf.write_i32::<LittleEndian>(*encoded_offset).unwrap();
            }
        }
    }

    /// Write a v10+ non-encoded (FPakEntry-shape) record. The record is
    /// uncompressed and unencrypted, totalling 53 bytes — it must
    /// round-trip through
    /// `PakEntryHeader::read_from(reader, PathHashIndex, &[])`.
    fn write_v10_non_encoded_uncompressed(buf: &mut Vec<u8>, offset: u64, size: u64) {
        buf.write_u64::<LittleEndian>(offset).unwrap();
        buf.write_u64::<LittleEndian>(size).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // compression_method = None
        buf.extend_from_slice(&[0u8; 20]); // SHA1
        buf.push(0); // not encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size
    }

    /// Spec for assembling a v10+ test fixture. Each `*_override` field
    /// substitutes a forged value in place of the natural one — the
    /// natural value is computed from the structural fields (e.g.,
    /// `encoded_entries.len()`). This is what lets a single helper drive
    /// both happy-path and "header lies about size" negative tests.
    struct V10Fixture<'a> {
        mount: &'a str,
        file_count: u32,
        has_full_directory_index: bool,
        encoded_entries: Vec<u8>,
        encoded_entries_size_override: Option<u32>,
        non_encoded_records: Vec<u8>, // pre-serialized PakEntryHeader bytes
        non_encoded_count_override: Option<u32>,
        non_encoded_count: u32,
        fdi: Vec<(&'a str, &'a [(&'a str, i32)])>,
        fdi_size_override: Option<u64>,
    }

    impl Default for V10Fixture<'_> {
        fn default() -> Self {
            Self {
                mount: "../../../",
                file_count: 0,
                has_full_directory_index: true,
                encoded_entries: Vec::new(),
                encoded_entries_size_override: None,
                non_encoded_records: Vec::new(),
                non_encoded_count_override: None,
                non_encoded_count: 0,
                fdi: Vec::new(),
                fdi_size_override: None,
            }
        }
    }

    /// Assemble a v10+ buffer with `[main_index][fdi]` layout starting
    /// at offset 0. Returns `(buffer, main_index_size)` so the test can
    /// pass `main_index_size` as `index_size` to `PakIndex::read_from`.
    /// `spec` is consumed by destructure-move so its `Vec` fields don't
    /// have to be cloned.
    fn build_v10_buffer(spec: V10Fixture<'_>) -> (Vec<u8>, u64) {
        let V10Fixture {
            mount,
            file_count,
            has_full_directory_index,
            encoded_entries,
            encoded_entries_size_override,
            non_encoded_records,
            non_encoded_count_override,
            non_encoded_count,
            fdi,
            fdi_size_override,
        } = spec;

        let mut main = Vec::new();
        write_fstring(&mut main, mount);
        main.write_u32::<LittleEndian>(file_count).unwrap();
        main.write_u64::<LittleEndian>(0).unwrap(); // path_hash_seed
        main.write_u32::<LittleEndian>(0).unwrap(); // has_path_hash_index = false

        main.write_u32::<LittleEndian>(u32::from(has_full_directory_index))
            .unwrap();
        let fdi_header_pos = if has_full_directory_index {
            let p = main.len();
            main.write_u64::<LittleEndian>(0).unwrap(); // fdi_offset placeholder
            main.write_u64::<LittleEndian>(0).unwrap(); // fdi_size placeholder
            main.extend_from_slice(&[0u8; 20]); // fdi_hash
            Some(p)
        } else {
            None
        };

        let natural_encoded_size = u32::try_from(encoded_entries.len()).unwrap();
        let encoded_size = encoded_entries_size_override.unwrap_or(natural_encoded_size);
        main.write_u32::<LittleEndian>(encoded_size).unwrap();
        main.extend_from_slice(&encoded_entries);

        let non_enc_count = non_encoded_count_override.unwrap_or(non_encoded_count);
        main.write_u32::<LittleEndian>(non_enc_count).unwrap();
        main.extend_from_slice(&non_encoded_records);

        let main_size = main.len() as u64;
        let fdi_offset = main_size;

        let mut fdi_bytes = Vec::new();
        write_fdi_body(&mut fdi_bytes, &fdi);
        let natural_fdi_size = fdi_bytes.len() as u64;
        let fdi_size = fdi_size_override.unwrap_or(natural_fdi_size);

        if let Some(p) = fdi_header_pos {
            main[p..p + 8].copy_from_slice(&fdi_offset.to_le_bytes());
            main[p + 8..p + 16].copy_from_slice(&fdi_size.to_le_bytes());
        }

        let mut buf = main;
        buf.extend_from_slice(&fdi_bytes);
        (buf, main_size)
    }

    /// V10+ archives MUST advertise a full directory index — paksmith
    /// derives the `(filename, encoded_offset)` mapping from the FDI
    /// (we don't consume the path-hash table). A header that sets
    /// `has_full_directory_index = false` would leave us with no way
    /// to recover filenames, so reject it explicitly.
    #[test]
    fn read_v10_plus_rejects_missing_full_directory_index() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            has_full_directory_index: false,
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("full directory index")),
            "got: {err:?}"
        );
    }

    /// FDI references an `encoded_offset` past the end of the encoded-
    /// entries blob. Without the bounds check this would panic with an
    /// out-of-range slice; with it we surface a typed InvalidIndex.
    #[test]
    fn read_v10_plus_rejects_encoded_offset_oob() {
        // Encoded blob is empty; FDI claims offset 1000 → must reject.
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            fdi: vec![("/Content/", &[("a.uasset", 1000)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        // Pin the SPECIFIC OOB rejection by matching on the comparison
        // operator in the message — the alternative usize-conversion
        // error path also contains "encoded_offset" but a different
        // shape, and we want this test to fail if the wrong rejection
        // path fires.
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains(">= encoded_entries_size")),
            "got: {err:?}"
        );
    }

    /// FDI carries a NEGATIVE encoded_offset (-1 = first non-encoded
    /// entry, 1-based). Pin the happy path: the parser must look up
    /// the in-line `PakEntryHeader` record from `non_encoded_entries`
    /// and use it as the entry's header. Real UE writers use this
    /// fallback for entries that don't fit the bit-packed format.
    #[test]
    fn read_v10_plus_accepts_negative_offset_to_non_encoded() {
        let mut non_enc = Vec::new();
        write_v10_non_encoded_uncompressed(
            &mut non_enc,
            /*offset*/ 0x100,
            /*size*/ 0x4000,
        );
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            non_encoded_records: non_enc,
            non_encoded_count: 1,
            fdi: vec![("/Content/", &[("a.uasset", -1)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[]).unwrap();
        assert_eq!(index.entries().len(), 1);
        let e = &index.entries()[0];
        assert_eq!(e.filename(), "Content/a.uasset");
        assert_eq!(e.header().offset(), 0x100);
        assert_eq!(e.header().uncompressed_size(), 0x4000);
        assert_eq!(e.header().compression_method(), &CompressionMethod::None);
    }

    /// FDI claims a negative encoded_offset whose 1-based index is
    /// past the end of the non-encoded entries vec. Surface as
    /// InvalidIndex (not panic).
    #[test]
    fn read_v10_plus_rejects_negative_offset_past_non_encoded() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            // No non-encoded entries; FDI references -1 → 1-based idx 0
            // → fails because non_encoded is empty.
            fdi: vec![("/Content/", &[("a.uasset", -1)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("non-encoded index")),
            "got: {err:?}"
        );
    }

    /// Header forges `encoded_entries_size > index_size` — without the
    /// bound, parser would `Vec::resize` to a multi-GB allocation and
    /// then `read_exact` against a truncated buffer. The bound rejects
    /// before the alloc.
    #[test]
    fn read_v10_plus_rejects_encoded_size_exceeding_index() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            encoded_entries_size_override: Some(u32::MAX),
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("encoded_entries_size")),
            "got: {err:?}"
        );
    }

    /// Header forges `fdi_size > 256 MiB` — caps the FDI alloc so a
    /// malicious header can't drive a multi-GB `Vec::resize` even when
    /// the FDI offset itself is well-formed.
    ///
    /// Boundary-pinned at `MAX_FDI_BYTES + 1`: a value far above the
    /// cap (e.g., 512 MiB) would still reject if the cap were loosened
    /// to anywhere below 512 MiB but tightened past 257 MiB; using
    /// the immediate boundary catches a one-byte regression in either
    /// direction.
    #[test]
    fn read_v10_plus_rejects_fdi_size_above_cap() {
        const MAX_FDI_BYTES: u64 = 256 * 1024 * 1024; // mirror production cap
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            fdi_size_override: Some(MAX_FDI_BYTES + 1),
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: "fdi_size",
                        ..
                    }
                }
            ),
            "got: {err:?}"
        );
    }

    /// Header forges `file_count` larger than the FDI byte budget can
    /// possibly carry (`fdi_size / 9` is the upper bound, since each
    /// FDI file record is at least `5-byte FString filename + 4-byte
    /// i32 offset = 9 bytes`). Caps the entries-vec pre-alloc.
    #[test]
    fn read_v10_plus_rejects_file_count_exceeding_fdi_budget() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: u32::MAX, // claim 4B files
            // FDI is empty / dir_count = 0, so max files = 0.
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("file_count")),
            "got: {err:?}"
        );
    }

    /// Header forges `non_encoded_count` larger than the index byte
    /// budget can possibly carry. Caps the non-encoded entries
    /// pre-alloc.
    #[test]
    fn read_v10_plus_rejects_non_encoded_count_exceeding_budget() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            non_encoded_count_override: Some(u32::MAX),
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: "non_encoded_count",
                        ..
                    }
                }
            ),
            "got: {err:?}"
        );
    }

    /// `encoded_entry_in_data_record_size` must compute the wire-format
    /// in-data record size for an encoded entry. The base overhead is
    /// 53 bytes (PakEntryHeader: 8+8+8+4+20+1+4); compressed entries add
    /// 4 bytes for `block_count` and 16 per block (`u64 start + u64 end`).
    /// Pinning these makes a future encoder/decoder change surface here
    /// instead of breaking the cross-parser tests silently.
    #[test]
    fn encoded_entry_in_data_record_size_pin() {
        // Uncompressed: just the 53-byte base.
        assert_eq!(encoded_entry_in_data_record_size(false, 0), 53);
        // Compressed, 0 blocks: base + block_count u32.
        assert_eq!(encoded_entry_in_data_record_size(true, 0), 53 + 4);
        // Compressed, 1 block: base + 4 + 16.
        assert_eq!(encoded_entry_in_data_record_size(true, 1), 53 + 4 + 16);
        // Compressed, 7 blocks: base + 4 + 16*7.
        assert_eq!(encoded_entry_in_data_record_size(true, 7), 53 + 4 + 16 * 7);
    }

    /// End-to-end roundtrip pin for the `omits_sha1` glue: a v10+
    /// encoded entry decoded by `read_encoded` must skip the SHA1
    /// cross-check when `matches_payload` is later called against an
    /// in-data record carrying a real SHA1. This is what cross-parser
    /// fixtures exercise implicitly; doing it as a unit test ensures
    /// that a refactor splitting `omits_sha1` between read_encoded
    /// (set) and matches_payload (read) doesn't silently break the
    /// glue without surfacing a regression — the decoder unit tests
    /// alone wouldn't catch it.
    #[test]
    fn matches_payload_roundtrip_for_encoded_entry() {
        // Decode a real encoded entry: zero SHA1 + omits_sha1=true.
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0x100,
            uncompressed: 0x4000,
            compressed: 0x4000,
            compression_slot_1based: 0,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let index_header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();

        // In-data record carries a real SHA1 (as a real payload would).
        let in_data = PakEntryHeader {
            offset: 0,
            ..make_header(0x4000, 0x4000, [0xCC; 20])
        };

        // Without the omits_sha1 gate this would fail with a sha1
        // mismatch error.
        assert!(index_header.matches_payload(&in_data, "x").is_ok());
    }

    /// FDI carries MORE files than the main-index `file_count`
    /// claims. Without the per-push budget guard the parser would
    /// silently grow the `entries` vec past the `try_reserve_exact`
    /// reservation, weakening the round-1 file_count bound. Surface
    /// this as InvalidIndex naming the field.
    #[test]
    fn read_v10_plus_rejects_fdi_overflowing_file_count() {
        // file_count = 1, but FDI carries 2 files in one directory.
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            fdi: vec![("/Content/", &[("a.uasset", -1), ("b.uasset", -1)])],
            non_encoded_records: {
                let mut v = Vec::new();
                write_v10_non_encoded_uncompressed(&mut v, 0, 0x100);
                v
            },
            non_encoded_count: 1,
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("file_count")),
            "got: {err:?}"
        );
    }

    #[test]
    fn matches_payload_accepts_identical_modulo_offset() {
        // The offset field intentionally differs (index = real, in-data = 0)
        // and matches_payload should not flag it.
        let index = PakEntryHeader {
            offset: 1024,
            ..make_header(50, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            offset: 0,
            ..make_header(50, 100, [0xAA; 20])
        };
        assert!(index.matches_payload(&in_data, "x").is_ok());
    }

    #[test]
    fn matches_payload_rejects_size_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = make_header(50, 999, [0xAA; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("uncompressed_size"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_sha1_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = make_header(50, 100, [0xBB; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("sha1"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_method_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::None,
            ..make_header(100, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            ..make_header(100, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("compression_method"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_is_encrypted_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = PakEntryHeader {
            is_encrypted: true,
            ..make_header(50, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("is_encrypted"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_blocks_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![
                CompressionBlock::new(73, 86).unwrap(),
                CompressionBlock::new(86, 100).unwrap(),
            ],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("compression_blocks"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_block_size_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 65_536,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("compression_block_size"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn wire_size_uncompressed_is_53() {
        let h = make_header(100, 100, [0; 20]);
        // 48 common + 5 trailer (encrypted u8 + block_size u32, both
        // always present in v3+) = 53.
        assert_eq!(h.wire_size(), 53);
    }

    #[test]
    fn wire_size_compressed_includes_blocks() {
        let h = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![
                CompressionBlock::new(0, 50).unwrap(),
                CompressionBlock::new(50, 100).unwrap(),
            ],
            compression_block_size: 100,
            ..make_header(100, 200, [0; 20])
        };
        // 48 common + 4 (block_count) + 2 * 16 (blocks) + 5 trailer = 89
        assert_eq!(h.wire_size(), 89);
    }

    /// Invariant: `wire_size()` must equal the number of bytes `read_from`
    /// actually consumes from the reader. This is the load-bearing property
    /// the rest of the parser relies on for payload-offset arithmetic; if
    /// these two formulas drift, every multi-block decompression silently
    /// reads from the wrong file position.
    #[test]
    fn wire_size_matches_bytes_consumed_by_read_from_uncompressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        buf.push(0); // is_encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)

        let total = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let header =
            PakEntryHeader::read_from(&mut cursor, PakVersion::CompressionEncryption, &[]).unwrap();
        assert_eq!(
            cursor.position(),
            total,
            "read_from did not consume all bytes"
        );
        assert_eq!(
            header.wire_size(),
            total,
            "wire_size disagrees with read_from's actual consumption"
        );
    }

    #[test]
    fn wire_size_matches_bytes_consumed_by_read_from_compressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(50).unwrap();
        buf.write_u64::<LittleEndian>(200).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(2).unwrap();
        buf.write_u64::<LittleEndian>(73).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(123).unwrap();
        buf.push(0);
        buf.write_u32::<LittleEndian>(100).unwrap();

        let total = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let header =
            PakEntryHeader::read_from(&mut cursor, PakVersion::CompressionEncryption, &[]).unwrap();
        assert_eq!(cursor.position(), total);
        assert_eq!(header.wire_size(), total);
    }

    /// Tighter regression test for `compression_blocks` mismatch detection.
    /// The previous test only varied length; this one keeps length identical
    /// and varies a single block's `end`. A `len()`-only comparison would
    /// silently pass this case.
    #[test]
    fn matches_payload_rejects_compression_blocks_content_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            // Same count, different end offset.
            compression_blocks: vec![CompressionBlock::new(73, 99).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(reason.contains("compression_blocks"), "got: {reason}");
                // The improved error message includes the block index and
                // both offsets — pin that detail so future changes preserve
                // the diagnostic.
                assert!(reason.contains("block[0]"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }
}
