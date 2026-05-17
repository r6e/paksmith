//! v3-v9 flat-entry index parser.
//!
//! The pre-v10 pak index is a simple table: mount FString, entry
//! count, then `entry_count` consecutive `(FString filename,
//! FPakEntry record)` pairs. No path-hash table, no encoded blob, no
//! FDI — paths are read directly off the wire.
//!
//! Lives in its own submodule to keep [`PakIndex::read_from`]
//! (mod.rs) a thin dispatcher that picks the right parser for the
//! version. The v10+ shape is in [`super::path_hash`].

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use super::compression::CompressionMethod;
use super::fstring::read_fstring;
use super::{ENTRY_MIN_RECORD_BYTES, PakIndex, PakIndexEntry};
use crate::container::pak::version::PakVersion;
use crate::error::{AllocationContext, BoundsUnit, IndexParseFault, PaksmithError, WireField};

/// Hard ceiling on `entry_count` for v3-v9 flat-layout pak indexes.
/// Issue #181 (#128 follow-up): the prior `entry_count > index_size /
/// ENTRY_MIN_RECORD_BYTES` byte-budget check still allowed up to
/// ~946M entries against a 50 GB archive — `try_reserve_exact` would
/// fail soft on any real machine, but the attempt itself thrashes
/// the allocator on constrained runners. 10M is well above any
/// realistic UE ship (typical: 100K-1M); a future tuning can raise
/// it if archives in the wild grow past this. Symmetric in role to
/// v10+'s [`super::path_hash::MAX_INDEX_BYTES`] — both are
/// hard ceilings layered above the byte-budget check.
///
/// Exposed to integration tests via [`max_flat_index_entries`] so
/// boundary tests don't hard-code the literal.
pub(super) const MAX_FLAT_INDEX_ENTRIES: u32 = 10_000_000;

/// Test-only accessor for `MAX_FLAT_INDEX_ENTRIES`. Same convention
/// as [`super::path_hash::max_index_bytes`].
#[cfg(feature = "__test_utils")]
pub fn max_flat_index_entries() -> u32 {
    MAX_FLAT_INDEX_ENTRIES
}

// Cross-file `impl PakIndex` block: adds the v3-v9 parser entry point.
// The type itself, the version dispatcher, and the shared `from_entries`
// builder live in `mod.rs`; the v10+ counterpart lives in `path_hash.rs`.
impl PakIndex {
    /// v3-v9 flat-layout index parser. Called by [`PakIndex::read_from`]
    /// when [`PakVersion::has_path_hash_index`] is false.
    pub(super) fn read_flat_from<R: Read>(
        reader: &mut R,
        version: PakVersion,
        index_size: u64,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let mut bounded = reader.take(index_size);
        let mount_point = read_fstring(&mut bounded)?;
        let entry_count = bounded.read_u32::<LittleEndian>()?;

        // Issue #181 (#128 follow-up): hard ceiling on entry_count.
        // The byte-budget check below allowed up to ~946M entries
        // against a 50 GB archive — the per-entry try_reserve_exact
        // would fail soft, but the attempt itself thrashes the
        // allocator on constrained runners. Strict `>` so an entry
        // count sitting EXACTLY at the cap stays accepted.
        if entry_count > MAX_FLAT_INDEX_ENTRIES {
            return Err(PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::EntryCount,
                    value: u64::from(entry_count),
                    limit: u64::from(MAX_FLAT_INDEX_ENTRIES),
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }

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
                    field: WireField::EntryCount,
                    value: u64::from(entry_count),
                    limit: max_entries,
                    unit: BoundsUnit::Items,
                    path: None,
                },
            });
        }

        // Matches the v10+ pattern in `read_v10_plus_from` — both code
        // paths surface OOM at the entries reservation as a typed
        // `InvalidIndex` rather than an `alloc::handle_alloc_error` abort.
        let mut entries: Vec<PakIndexEntry> = Vec::new();
        entries
            .try_reserve_exact(entry_count as usize)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: AllocationContext::FlatIndexEntries,
                    requested: entry_count as usize,
                    unit: BoundsUnit::Items,
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

        Self::from_entries(mount_point, entries, None)
    }
}
