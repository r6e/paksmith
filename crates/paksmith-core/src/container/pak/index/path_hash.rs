//! v10+ path-hash + encoded-entries-blob + full-directory-index
//! parser.
//!
//! Compared to the [`super::flat`] v3-v9 layout, v10+ paks split the
//! index into three regions:
//!
//! 1. **Main index** (the region [`PakIndex::read_from`] points at):
//!    mount FString, file_count, path_hash_seed, optional path-hash
//!    index header, **required** full-directory-index header, encoded
//!    entries blob (size + N bytes), non-encoded entries fallback.
//! 2. **Path-hash index** (optional, at a separate file offset):
//!    `(fnv64(path), encoded_offset)` table for O(1) lookup.
//!    Paksmith does not consult the PHI for primary lookup (the FDI
//!    walk + our `by_path` HashMap is the resolution path), but
//!    issue #131 wired PHI parsing into open-time as a
//!    cross-validation source: every FDI-walked path computes
//!    `fnv64_path(seed, path)` and must round-trip to the same
//!    `encoded_offset` the PHI stores. Mismatches surface as
//!    `IndexParseFault::PhiFdiInconsistency`. Without this check,
//!    an attacker who rewrites the PHI's main-index hash slot could
//!    redirect a known asset-name hash to a different offset.
//! 3. **Full directory index** (required, at a separate file offset):
//!    `(dir_name, [(file_name, encoded_offset)])` walk. Paksmith
//!    consults this to recover full paths since the encoded entries
//!    blob doesn't carry filenames.
//!
//! `encoded_offset >= 0` indexes into the encoded blob; negative
//! values (1-based, negated) index into the non-encoded entries
//! fallback.

use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use super::compression::CompressionMethod;
use super::entry_header::PakEntryHeader;
use super::fstring::read_fstring;
use super::{ENTRY_MIN_RECORD_BYTES, PakIndex, PakIndexEntry, fnv64_path};
use crate::container::pak::version::PakVersion;
use crate::error::{
    AllocationContext, BoundsUnit, EncodedFault, IndexParseFault, IndexRegionKind, PaksmithError,
    PhiFdiInconsistencyKind, WireField, check_region_bounds, try_reserve_index,
};

/// Standalone ceiling on the v10+ FDI region byte size. A real-world
/// full directory index for a 100k-file pak is typically a few MB;
/// 256 MB is comfortably larger than anything legitimate while still
/// rejecting a u64::MAX alloc-bomb. The footer's `index_offset +
/// index_size` budget DOESN'T bound the FDI (it lives at an arbitrary
/// offset elsewhere in the file), so this cap is the only line of
/// defense against an adversarial header inflating `fdi_size`.
///
/// Exposed to integration tests via [`max_fdi_bytes`] (issue #94) so
/// boundary tests don't hard-code the literal and stay correct if
/// the cap is ever tuned.
pub(super) const MAX_FDI_BYTES: u64 = 256 * 1024 * 1024;

/// Standalone ceiling on the v10+ main-index region byte size. The
/// footer's `index_size` is already bounded by `file_size` (the
/// archive can't claim more than it holds), but a 50 GB legitimate
/// archive declaring its full size as the index would still drive a
/// 50 GB upfront `Vec::resize` at open time, even for a `paksmith
/// list` consumer. 1 GiB is well beyond any realistic UE ship — the
/// main-index encoded blob is ~30 bytes/entry, so 1 GiB covers a
/// >30M-entry archive.
///
/// Exposed to integration tests via [`max_index_bytes`] so boundary
/// tests don't hard-code the literal and stay correct if the cap is
/// ever tuned.
pub(super) const MAX_INDEX_BYTES: u64 = 1024 * 1024 * 1024;

/// Test-only accessor for `MAX_FDI_BYTES`. Same convention as
/// [`crate::container::pak::max_uncompressed_entry_bytes`] — the cap
/// is an implementation detail of the v10+ FDI parser, but boundary
/// tests legitimately need the value. Gated behind the `__test_utils`
/// feature so it's not part of the stable public API.
#[cfg(feature = "__test_utils")]
pub fn max_fdi_bytes() -> u64 {
    MAX_FDI_BYTES
}

/// Test-only accessor for `MAX_INDEX_BYTES`. Same convention as
/// [`max_fdi_bytes`].
#[cfg(feature = "__test_utils")]
pub fn max_index_bytes() -> u64 {
    MAX_INDEX_BYTES
}

/// Parse a v10+ Path-Hash Index body into a `(fnv64_hash →
/// encoded_offset)` lookup map. Wire format (per repak's writer
/// in `generate_path_hash_index`):
///
/// ```text
/// count: u32 LE
/// for each entry:
///   hash: u64 LE
///   encoded_offset: i32 LE
/// trailing: 0u32 LE  (sentinel — repak's reader ignores it)
/// ```
///
/// **Wire-format claim verification:** the `(u64 hash, i32
/// encoded_offset)` shape is verified against the
/// `trumank/repak` reference implementation
/// (`generate_path_hash_index` at `repak/src/pak.rs:682-687`).
/// NOT verified against a first-party UE-authored v10+ fixture
/// — the project has no PHI-bearing synthetic fixtures today.
/// If a UE-authored archive ever fails here, audit this
/// assumption first (per the memory note on empirical
/// wire-format verification).
///
/// **Duplicate-hash rejection:** UE's writer emits one entry
/// per source path; FNV-64 collisions over realistic UE path
/// counts (~10⁻¹⁰ for 100K paths) are astronomical. A
/// duplicate is structural malformation — surface as
/// `PhiFdiInconsistencyKind::DuplicateHash` rather than
/// silently last-write-wins via the HashMap. Issue #131.
fn parse_phi_body(bytes: &[u8]) -> crate::Result<HashMap<u64, i32>> {
    // Issue #131 R1 security finding: an empty PHI body
    // (`phi_size == 0` — bounds-check accepts this since 0 <=
    // file_size) would otherwise drive `read_u32` to bare
    // `Io(UnexpectedEof)`, breaking the codebase's "all
    // wire-format faults are typed" discipline. Reject upfront
    // with a typed `BoundsExceeded { PhiSize }` — UE writers
    // always emit at least the 4-byte count prefix + 4-byte
    // trailing sentinel.
    if bytes.len() < 4 {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: WireField::PhiSize,
                value: bytes.len() as u64,
                limit: 4,
                unit: BoundsUnit::Bytes,
                path: None,
            },
        });
    }
    let mut cursor = Cursor::new(bytes);
    let count = cursor.read_u32::<LittleEndian>()?;
    let count_usize = count as usize;
    // Per-entry on-disk shape: 8 (hash) + 4 (offset) = 12 bytes.
    // Bound `count` against the byte budget so a forged
    // `count = u32::MAX` doesn't drive an unbounded
    // `HashMap::try_reserve_exact`. Subtract the count prefix
    // (4 bytes) from the available budget.
    let max_entries_for_phi = bytes.len().saturating_sub(4) / 12;
    if count_usize > max_entries_for_phi {
        return Err(PaksmithError::InvalidIndex {
            fault: IndexParseFault::BoundsExceeded {
                field: WireField::PhiEntryCount,
                value: u64::from(count),
                limit: max_entries_for_phi as u64,
                unit: BoundsUnit::Items,
                path: None,
            },
        });
    }
    let mut map: HashMap<u64, i32> = HashMap::new();
    map.try_reserve(count_usize)
        .map_err(|source| PaksmithError::InvalidIndex {
            fault: IndexParseFault::AllocationFailed {
                // Items (not bytes) — the HashMap reservation is
                // count-keyed. Distinct from the V10PhiBytes
                // byte-buffer slurp at the other call site.
                context: AllocationContext::V10PhiEntries,
                requested: count_usize,
                source,
                path: None,
            },
        })?;
    for _ in 0..count {
        let hash = cursor.read_u64::<LittleEndian>()?;
        let off = cursor.read_i32::<LittleEndian>()?;
        if map.insert(hash, off).is_some() {
            // Second occurrence of the same hash — surface as
            // structural malformation per the doc comment.
            // `phi_offset` carries the duplicate's offset so the
            // operator can see at least one of the two values; the
            // first occurrence's offset is dropped by the failing
            // `insert` and not surfaced (knowing both wouldn't help
            // — UE writers shouldn't emit this shape at all).
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::PhiFdiInconsistency {
                    path: String::new(),
                    kind: PhiFdiInconsistencyKind::DuplicateHash,
                    expected_hash: hash,
                    fdi_offset: 0,
                    phi_offset: off,
                },
            });
        }
    }
    Ok(map)
}

// Cross-file `impl PakIndex` block: adds the v10+ parser entry point.
// The type itself, the version dispatcher, and the shared `from_entries`
// builder live in `mod.rs`; the v3-v9 counterpart lives in `flat.rs`.
impl PakIndex {
    /// V10+ index parser. The main index region carries headers + the
    /// encoded entries blob; the full directory index (which we use to
    /// recover paths) lives at a separate offset in the parent file.
    #[allow(clippy::too_many_lines)] // bounded by the multi-section index layout
    pub(super) fn read_v10_plus_from<R: Read + Seek>(
        reader: &mut R,
        index_size: u64,
        file_size: u64,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        // Minimum on-disk shape per file inside the FDI: `FString
        // filename (5 bytes: 4 length + 1 null) + i32 offset (4 bytes)
        // = 9 bytes`. Used to bound the entries-vec pre-alloc against
        // the FDI byte budget, so a u32::MAX file_count claim can't
        // trigger a ~96 GiB `Vec::with_capacity`.
        const MIN_FDI_FILE_RECORD_BYTES: u64 = 5 + 4;
        // Minimum on-disk shape per directory inside the FDI: `FString
        // dir_name (5 bytes: 4 length + 1 null) + u32 file_count (4 bytes)
        // = 9 bytes`. Used to bound `dir_count` against `fdi_size`
        // upfront, mirroring the per-file cap above. Issue #87.
        const MIN_FDI_DIR_RECORD_BYTES: u64 = 5 + 4;

        // Cap `index_size` before allocating. The footer parser already
        // proved `index_size <= file_size`, but a legitimate-but-bloated
        // archive (or one whose footer claims `index_size == file_size`)
        // would otherwise drive a multi-GB `Vec::resize` at open time
        // even when the consumer only wants `paksmith list`. Issue #128.
        if index_size > MAX_INDEX_BYTES {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::IndexSize,
                    value: index_size,
                    limit: MAX_INDEX_BYTES,
                    unit: BoundsUnit::Bytes,
                    path: None,
                },
            });
        }
        // Slurp the main index region into memory so we can parse it
        // independently of the file reader's cursor (which we'll seek
        // elsewhere for the full directory index and path-hash index).
        let index_size_usize =
            usize::try_from(index_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::IndexSize,
                    value: index_size,
                    path: None,
                },
            })?;
        let mut index_bytes = Vec::new();
        try_reserve_index(
            &mut index_bytes,
            index_size_usize,
            AllocationContext::V10MainIndexBytes,
        )?;
        index_bytes.resize(index_size_usize, 0);
        reader.read_exact(&mut index_bytes)?;
        let mut idx = Cursor::new(&index_bytes);

        let mount_point = read_fstring(&mut idx)?;
        let file_count = idx.read_u32::<LittleEndian>()?;
        // Path-hash-table FNV-64 seed — always present in v10+ even
        // when the PHI region itself is omitted. Consumed by the
        // PHI/FDI cross-validation loop below (issue #131): every
        // FDI-walked path computes `fnv64_path(path, path_hash_seed)`
        // and the result is cross-checked against the PHI's
        // `(hash → encoded_offset)` mapping. Also retained on
        // `EncodedRegions` for downstream consumers.
        let path_hash_seed = super::PathHashSeed::new(idx.read_u64::<LittleEndian>()?);

        // Path-hash index header — optional region elsewhere in the
        // file mapping hash → encoded_entry_offset. We retain the
        // (offset, size, SHA1) descriptor so `PakReader::verify_index`
        // can hash the region for tamper detection (issue #86).
        let has_path_hash_index = idx.read_u32::<LittleEndian>()? != 0;
        let phi_region = if has_path_hash_index {
            let phi_offset = idx.read_u64::<LittleEndian>()?;
            let phi_size = idx.read_u64::<LittleEndian>()?;
            let mut phi_hash_bytes = [0u8; 20];
            idx.read_exact(&mut phi_hash_bytes)?;
            Some(super::RegionDescriptor {
                offset: phi_offset,
                size: phi_size,
                hash: phi_hash_bytes.into(),
            })
        } else {
            None
        };

        // Full directory index header. We MUST process this — it's how
        // we recover the (full_path, encoded_entry_offset) pairs. Same
        // (offset, size, SHA1) descriptor shape as PHI; retained for
        // post-parse tamper verification (issue #86).
        let has_full_directory_index = idx.read_u32::<LittleEndian>()? != 0;
        if !has_full_directory_index {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::MissingFullDirectoryIndex,
            });
        }
        let fdi_offset = idx.read_u64::<LittleEndian>()?;
        let fdi_size = idx.read_u64::<LittleEndian>()?;
        let mut fdi_hash_bytes = [0u8; 20];
        idx.read_exact(&mut fdi_hash_bytes)?;
        let fdi_region = super::RegionDescriptor {
            offset: fdi_offset,
            size: fdi_size,
            hash: fdi_hash_bytes.into(),
        };
        let encoded_regions = Some(super::EncodedRegions {
            fdi: fdi_region,
            phi: phi_region,
            path_hash_seed,
        });

        // Encoded entries blob: size prefix + N bytes of bit-packed records.
        let encoded_entries_size = idx.read_u32::<LittleEndian>()?;
        let encoded_entries_size_usize =
            usize::try_from(encoded_entries_size).map_err(|_| PaksmithError::InvalidIndex {
                fault: IndexParseFault::U64ExceedsPlatformUsize {
                    field: WireField::V10EncodedEntriesSize,
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
                    field: WireField::V10EncodedEntriesSize,
                    value: u64::from(encoded_entries_size),
                    limit: index_size,
                    unit: BoundsUnit::Bytes,
                    path: None,
                },
            });
        }
        let mut encoded_entries_blob: Vec<u8> = Vec::new();
        try_reserve_index(
            &mut encoded_entries_blob,
            encoded_entries_size_usize,
            AllocationContext::V10EncodedEntriesBytes,
        )?;
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
                    field: WireField::V10NonEncodedCount,
                    value: u64::from(non_encoded_count),
                    limit: max_non_encoded,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }
        let mut non_encoded_entries: Vec<PakEntryHeader> = Vec::new();
        try_reserve_index(
            &mut non_encoded_entries,
            non_encoded_count as usize,
            AllocationContext::V10NonEncodedEntries,
        )?;
        for _ in 0..non_encoded_count {
            non_encoded_entries.push(PakEntryHeader::read_from(
                &mut idx,
                PakVersion::PathHashIndex,
                compression_methods,
            )?);
        }

        // Issue #127: pre-validate the FDI region's offset+size
        // against `file_size` BEFORE the `MAX_FDI_BYTES` cap below.
        // Order matters: without this, an archive declaring `fdi_size
        // == MAX_FDI_BYTES` (cap accepts) with `fdi_offset` past EOF
        // would still drive a 256 MiB `Vec::resize` per
        // `PakReader::open` call. The comparator + fault shape is
        // shared with `verify_region` via `check_region_bounds`.
        check_region_bounds(IndexRegionKind::Fdi, fdi_offset, fdi_size, file_size)
            .map_err(|fault| PaksmithError::InvalidIndex { fault })?;
        // Now seek to the full directory index in the file and read it.
        if fdi_size > MAX_FDI_BYTES {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::FdiSize,
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
                    field: WireField::FdiSize,
                    value: fdi_size,
                    path: None,
                },
            })?;
        let mut fdi_bytes: Vec<u8> = Vec::new();
        try_reserve_index(
            &mut fdi_bytes,
            fdi_size_usize,
            AllocationContext::V10FdiBytes,
        )?;
        fdi_bytes.resize(fdi_size_usize, 0);
        reader.read_exact(&mut fdi_bytes)?;

        // Issue #131: if the archive declared a PHI region, read its
        // bytes now (immediately after the FDI seek+read so the
        // reader cursor is in a known state). The parsed hash-map
        // is used in the FDI walk below to cross-check each
        // path's `fnv64(seed, path) → encoded_offset` mapping.
        // `None` when `has_path_hash_index = false` — the cross-
        // check is skipped (PHI absence is legal in v10+).
        let mut phi_map: Option<HashMap<u64, i32>> = if let Some(phi) = phi_region.as_ref() {
            check_region_bounds(IndexRegionKind::Phi, phi.offset, phi.size, file_size)
                .map_err(|fault| PaksmithError::InvalidIndex { fault })?;
            if phi.size > MAX_FDI_BYTES {
                return Err(PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: WireField::PhiSize,
                        value: phi.size,
                        limit: MAX_FDI_BYTES,
                        unit: BoundsUnit::Bytes,
                        path: None,
                    },
                });
            }
            let phi_size_usize =
                usize::try_from(phi.size).map_err(|_| PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ExceedsPlatformUsize {
                        field: WireField::PhiSize,
                        value: phi.size,
                        path: None,
                    },
                })?;
            let _ = reader.seek(SeekFrom::Start(phi.offset))?;
            let mut phi_bytes: Vec<u8> = Vec::new();
            try_reserve_index(
                &mut phi_bytes,
                phi_size_usize,
                AllocationContext::V10PhiBytes,
            )?;
            phi_bytes.resize(phi_size_usize, 0);
            reader.read_exact(&mut phi_bytes)?;
            Some(parse_phi_body(&phi_bytes)?)
        } else {
            None
        };

        let mut fdi = Cursor::new(&fdi_bytes);

        let dir_count = fdi.read_u32::<LittleEndian>()?;
        // Issue #87: bound `dir_count` against the FDI byte budget
        // upfront, symmetric with the `file_count` cap below. Without
        // this, a malicious `dir_count = u32::MAX` would loop ~4 billion
        // times before each iteration's `read_fstring` failed via the
        // bounded `Cursor` — bounded total work, but wasted CPU.
        let max_dirs_for_fdi = fdi_size / MIN_FDI_DIR_RECORD_BYTES;
        if u64::from(dir_count) > max_dirs_for_fdi {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::FdiDirCount,
                    value: u64::from(dir_count),
                    limit: max_dirs_for_fdi,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }
        // Bound `file_count` against the FDI byte budget BEFORE allocating
        // the entries vec — file_count comes from the (untrusted) main
        // index header. Cap derives from the function-scoped
        // MIN_FDI_FILE_RECORD_BYTES (no FDI can carry more than
        // `fdi_size / 9` files regardless of what file_count claims).
        let max_files_for_fdi = fdi_size / MIN_FDI_FILE_RECORD_BYTES;
        if u64::from(file_count) > max_files_for_fdi {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::FdiFileCount,
                    value: u64::from(file_count),
                    limit: max_files_for_fdi,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }
        let mut entries: Vec<PakIndexEntry> = Vec::new();
        try_reserve_index(
            &mut entries,
            file_count as usize,
            AllocationContext::V10IndexEntries,
        )?;
        for _ in 0..dir_count {
            let dir_name = read_fstring(&mut fdi)?;
            let dir_file_count = fdi.read_u32::<LittleEndian>()?;
            // Directory names MAY have a leading `/`: the root directory uses
            // `/`, while subdirectories typically omit it (e.g. `Content/`).
            // Empirical evidence from real UE/repak archives is in issue #46.
            // The `unwrap_or` correctly handles both forms — joined virtual
            // path is `(dir_name minus optional leading slash) + file_name`.
            let dir_prefix = dir_name.strip_prefix('/').unwrap_or(&dir_name);
            for _ in 0..dir_file_count {
                let file_name = read_fstring(&mut fdi)?;
                let encoded_offset = fdi.read_i32::<LittleEndian>()?;
                // Build the full path BEFORE decoding the entry so the
                // `read_encoded` map_err below can fold it into the
                // resulting `BoundsExceeded` / `AllocationFailed` /
                // `U64ExceedsPlatformUsize` / `U64ArithmeticOverflow`
                // fault. The encoded-entries blob walk doesn't know
                // the FDI-derived path on its own — that's the
                // enrichment opportunity issue #57 closes.
                // Issue #132 item 3: fallible allocation — same
                // discipline as the surrounding parser. Bounded
                // transitively by `read_fstring`'s per-string cap
                // (each segment ≤ FSTRING_MAX_LEN bytes, so the
                // sum ≤ 128 KiB).
                let full_path = {
                    let total = dir_prefix.len() + file_name.len();
                    let mut s = String::new();
                    let reserve_res = s.try_reserve_exact(total);
                    // Issue #191: cfg-gated OOM-injection seam.
                    #[cfg(feature = "__test_utils")]
                    let reserve_res = reserve_res
                        .and_then(|()| crate::testing::oom::maybe_fail_fdi_full_path_reserve());
                    reserve_res.map_err(|source| PaksmithError::InvalidIndex {
                        fault: IndexParseFault::AllocationFailed {
                            context: AllocationContext::FdiFullPathBytes,
                            requested: total,
                            source,
                            path: None,
                        },
                    })?;
                    s.push_str(dir_prefix);
                    s.push_str(&file_name);
                    s
                };

                // Issue #131: PHI ↔ FDI cross-check. The PHI table
                // claims `(fnv64_path(seed, full_path) →
                // encoded_offset)` mappings; the FDI walk
                // independently produces `(full_path → encoded_offset)`.
                // For a well-formed archive the two must agree on
                // every path. Use `remove` rather than `get` so that
                // after the walk we can detect Extra entries
                // (anything left in the map is a PHI entry that
                // doesn't correspond to any FDI path — the "stuff
                // PHI with extras" amplification vector).
                if let Some(map) = phi_map.as_mut() {
                    let expected_hash = fnv64_path(&full_path, path_hash_seed);
                    match map.remove(&expected_hash) {
                        None => {
                            return Err(PaksmithError::InvalidIndex {
                                fault: IndexParseFault::PhiFdiInconsistency {
                                    path: full_path.clone(),
                                    kind: PhiFdiInconsistencyKind::MissingPhiEntry,
                                    expected_hash,
                                    fdi_offset: encoded_offset,
                                    phi_offset: 0,
                                },
                            });
                        }
                        Some(phi_off) if phi_off != encoded_offset => {
                            return Err(PaksmithError::InvalidIndex {
                                fault: IndexParseFault::PhiFdiInconsistency {
                                    path: full_path.clone(),
                                    kind: PhiFdiInconsistencyKind::OffsetMismatch,
                                    expected_hash,
                                    fdi_offset: encoded_offset,
                                    phi_offset: phi_off,
                                },
                            });
                        }
                        Some(_) => { /* matched — PHI agrees with FDI */ }
                    }
                }

                let header = if encoded_offset >= 0 {
                    // Decode the bit-packed entry from the encoded blob.
                    //
                    // SAFETY: `usize::try_from(positive i32)` is
                    // structurally infallible on every Rust target where
                    // `usize >= 32 bits` (i.e. all supported platforms —
                    // 16-bit `usize` is theoretical only). The
                    // `OffsetUsizeOverflow` Err branch is dead code on
                    // those platforms but kept as a typed-error
                    // safety net for any future hypothetical 16-bit
                    // target (cheaper than a `// panic-impossible`
                    // unwrap that would violate the no-panics-in-core
                    // policy). Issue #92.
                    let off_usize = usize::try_from(encoded_offset).map_err(|_| {
                        PaksmithError::InvalidIndex {
                            fault: IndexParseFault::Encoded {
                                kind: EncodedFault::OffsetUsizeOverflow {
                                    path: full_path.clone(),
                                    offset: encoded_offset,
                                },
                            },
                        }
                    })?;
                    if off_usize >= encoded_entries_blob.len() {
                        return Err(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::Encoded {
                                kind: EncodedFault::OffsetOob {
                                    path: full_path.clone(),
                                    offset: off_usize,
                                    blob_size: encoded_entries_blob.len(),
                                },
                            },
                        });
                    }
                    let mut blob_cursor = Cursor::new(&encoded_entries_blob[off_usize..]);
                    PakEntryHeader::read_encoded(&mut blob_cursor, compression_methods)
                        .map_err(|e| e.with_index_path(&full_path))?
                } else {
                    // Negative offset: 1-based index into non-encoded entries.
                    //
                    // SAFETY: same dead-on-32-bit+ argument as the
                    // positive-offset branch above. Worst-case input is
                    // `encoded_offset = i32::MIN`, giving
                    // `-i64::from(i32::MIN) - 1 = i32::MAX = 2_147_483_647`,
                    // which fits in `usize` on every supported platform.
                    // Kept as a typed-error safety net rather than an
                    // unwrap. Issue #92.
                    let idx = usize::try_from(-i64::from(encoded_offset) - 1).map_err(|_| {
                        PaksmithError::InvalidIndex {
                            fault: IndexParseFault::Encoded {
                                kind: EncodedFault::OffsetUsizeOverflow {
                                    path: full_path.clone(),
                                    offset: encoded_offset,
                                },
                            },
                        }
                    })?;
                    let count = non_encoded_entries.len();
                    non_encoded_entries
                        .get(idx)
                        .ok_or(PaksmithError::InvalidIndex {
                            fault: IndexParseFault::Encoded {
                                kind: EncodedFault::NonEncodedIndexOob {
                                    path: full_path.clone(),
                                    index: idx,
                                    count,
                                },
                            },
                        })?
                        .clone()
                };
                // Per-push budget guard: the FDI's `dir_count × dir_file_count`
                // must agree with the main-index `file_count`. A malformed
                // FDI claiming more entries than file_count would silently
                // overflow the `try_reserve_exact` allocation and weaken
                // the round-1 file_count bound. The fdi_size cap still
                // bounds total work, but enforcing this here catches the
                // discrepancy at the wire-format layer.
                if entries.len() >= file_count as usize {
                    return Err(PaksmithError::InvalidIndex {
                        fault: IndexParseFault::Encoded {
                            kind: EncodedFault::FdiFileCountExceeded {
                                claimed: file_count,
                            },
                        },
                    });
                }
                entries.push(PakIndexEntry::from_parts(full_path, header));
            }
        }

        // Issue #87: symmetric underrun guard. The per-push check
        // above catches FDI overruns (`entries.len() >= file_count`);
        // this catches the inverse — a truncated FDI claiming
        // `file_count = N` but yielding fewer than N entries after
        // the walk completes (writer crash, bit-flip in a dir_count,
        // hand-crafted truncated FDI). Without this, the parser
        // succeeds with a partial set; downstream consumers see a
        // smaller archive than UE would.
        //
        // Side-effect ordering note: in practice `entries.len()` can
        // only be `< file_count` here — the per-push guard rejects
        // before any `>` case could land. The `!=` form is defensive:
        // if a future refactor relaxes the per-push guard, this stays
        // a correctness backstop rather than silently allowing overrun.
        if entries.len() != file_count as usize {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::Encoded {
                    kind: EncodedFault::FdiFileCountShort {
                        claimed: file_count,
                        actual: entries.len() as u64,
                    },
                },
            });
        }

        // Issue #131 (final cross-check): any PHI entries that
        // remained in `phi_map` after the FDI walk had no
        // corresponding FDI path. UE writers populate PHI and FDI
        // from the same source map, so a leftover is the "stuff
        // PHI with extras" amplification vector. We surface the
        // FIRST leftover hash so the operator has a concrete
        // pointer; subsequent leftovers (if any) would surface
        // on a re-parse after the fix.
        if let Some(map) = phi_map.as_ref()
            && let Some((&extra_hash, &extra_off)) = map.iter().next()
        {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::PhiFdiInconsistency {
                    path: String::new(),
                    kind: PhiFdiInconsistencyKind::ExtraPhiEntries,
                    expected_hash: extra_hash,
                    fdi_offset: 0,
                    phi_offset: extra_off,
                },
            });
        }

        Self::from_entries(mount_point, entries, encoded_regions)
    }
}
