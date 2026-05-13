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
//!    `(fnv64(path), encoded_offset)` table for O(1) lookup. Paksmith
//!    skips this region today — we use the FDI for path recovery and
//!    build our own `by_path` HashMap. Header is read for budget
//!    accounting; the table itself is not.
//! 3. **Full directory index** (required, at a separate file offset):
//!    `(dir_name, [(file_name, encoded_offset)])` walk. Paksmith
//!    consults this to recover full paths since the encoded entries
//!    blob doesn't carry filenames.
//!
//! `encoded_offset >= 0` indexes into the encoded blob; negative
//! values (1-based, negated) index into the non-encoded entries
//! fallback.

use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use super::compression::CompressionMethod;
use super::entry_header::PakEntryHeader;
use super::fstring::read_fstring;
use super::{ENTRY_MIN_RECORD_BYTES, PakIndex, PakIndexEntry};
use crate::container::pak::version::PakVersion;
use crate::error::{BoundsUnit, EncodedFault, IndexParseFault, PaksmithError};

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
        // Minimum on-disk shape per directory inside the FDI: `FString
        // dir_name (5 bytes: 4 length + 1 null) + u32 file_count (4 bytes)
        // = 9 bytes`. Used to bound `dir_count` against `fdi_size`
        // upfront, mirroring the per-file cap above. Issue #87.
        const MIN_FDI_DIR_RECORD_BYTES: u64 = 5 + 4;

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
        // Issue #87: bound `dir_count` against the FDI byte budget
        // upfront, symmetric with the `file_count` cap below. Without
        // this, a malicious `dir_count = u32::MAX` would loop ~4 billion
        // times before each iteration's `read_fstring` failed via the
        // bounded `Cursor` — bounded total work, but wasted CPU.
        let max_dirs_for_fdi = fdi_size / MIN_FDI_DIR_RECORD_BYTES;
        if u64::from(dir_count) > max_dirs_for_fdi {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: "dir_count",
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
                let full_path = format!("{dir_prefix}{file_name}");
                let header = if encoded_offset >= 0 {
                    // Decode the bit-packed entry from the encoded blob.
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
                            kind: EncodedFault::FdiFileCountExceeded { file_count },
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
                        file_count,
                        actual: entries.len() as u32,
                    },
                },
            });
        }

        Self::from_entries(mount_point, entries)
    }
}
