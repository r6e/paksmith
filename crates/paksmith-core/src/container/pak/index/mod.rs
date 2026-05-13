//! Pak file index and entry parsing.
//!
//! Submodules carve out the natural seams of the pak index parser
//! (issue #53): each handles one concern with its own tests.
//! `mod.rs` retains [`PakIndex`] / [`PakIndexEntry`] / the version
//! dispatcher, plus shared types and the cross-cutting tests that
//! stress multiple submodules together.

mod compression;
mod entry_header;
mod flat;
mod fstring;
mod path_hash;

pub use compression::{CompressionBlock, CompressionMethod};
pub use entry_header::PakEntryHeader;
// Issue #94 test-utils accessor for the v10+ FDI byte ceiling.
// Same `__test_utils`-feature-gated pattern as
// `paksmith_core::container::pak::max_uncompressed_entry_bytes` —
// boundary tests read the cap from here rather than re-declaring
// the literal, eliminating the drift hazard #45/#58 already fixed
// for the entry-bytes cap.
#[cfg(feature = "__test_utils")]
pub use path_hash::max_fdi_bytes;
// `EntryCommon` was previously in the `pub` re-export, but it's dead
// external surface (issue #91): consumers can't construct it
// (`#[non_exhaustive]` + `pub(super)` fields) and can't pattern-match
// on fields (private). Every accessor a consumer would want is on
// `PakEntryHeader` directly. Re-export gated to `#[cfg(test)]` so the
// in-crate `tests` submodule below (which builds many `EntryCommon`
// fixtures via the `EntryCommon { ..make_common(...) }` spread idiom)
// still resolves `super::EntryCommon`, without exposing it to
// downstream crates as a name they could mistakenly think is reachable.
#[cfg(test)]
pub(crate) use entry_header::EntryCommon;

use std::io::{Read, Seek, SeekFrom};

use tracing::warn;

use crate::container::pak::version::PakVersion;
use crate::error::{IndexParseFault, PaksmithError};

use fstring::read_fstring;

/// Minimum on-disk size of an index entry record (FString header + offset +
/// sizes + compression + sha1 + encrypted flag, with the shortest-possible
/// FString of 5 bytes for `length(4) + null(1)`). Used to bound `entry_count`.
pub(super) const ENTRY_MIN_RECORD_BYTES: u64 = 5 + 8 + 8 + 8 + 4 + 20 + 1;

/// Cap on how many duplicate filenames we sample for the dedupe warning.
/// Prevents the warn-log payload from growing with `dup_count`.
const MAX_SAMPLED_DUPS: usize = 5;

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

/// Descriptor for a v10+ encoded-index region that lives at an
/// arbitrary file offset outside the main-index byte range.
///
/// Both the full directory index (FDI) and the optional path hash
/// index (PHI) have this same shape on the wire: a `(offset, size,
/// hash)` triple in the main-index header pointing into the parent
/// file. Retaining the descriptor on [`PakIndex`] is what lets
/// [`crate::container::pak::PakReader::verify_index`] hash the
/// regions for tamper detection (issue #86).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionDescriptor {
    pub(super) offset: u64,
    pub(super) size: u64,
    pub(super) hash: crate::digest::Sha1Digest,
}

impl RegionDescriptor {
    /// Absolute file offset where the region starts.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Length of the region in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Stored SHA1 of the region bytes. `Sha1Digest::ZERO` is the
    /// "no integrity claim recorded at write time" sentinel (same
    /// convention as the main-index hash and per-entry hashes).
    pub fn hash(&self) -> crate::digest::Sha1Digest {
        self.hash
    }
}

/// V10+ region descriptors. The full directory index is mandatory
/// for v10+ archives (the parser rejects archives without one via
/// [`crate::error::IndexParseFault::MissingFullDirectoryIndex`]),
/// so `fdi` is always present. The path hash index is optional —
/// when the main-index header recorded `has_path_hash_index = false`,
/// `phi` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedRegions {
    pub(super) fdi: RegionDescriptor,
    pub(super) phi: Option<RegionDescriptor>,
}

impl EncodedRegions {
    /// Full directory index descriptor — always present in v10+.
    /// Returned by value because `RegionDescriptor` is `Copy` and
    /// the type is small (36 bytes); matches the by-value shape of
    /// `RegionDescriptor::hash() -> Sha1Digest`.
    pub fn fdi(&self) -> RegionDescriptor {
        self.fdi
    }

    /// Path hash index descriptor — present when the archive's
    /// main-index header recorded `has_path_hash_index = true`.
    pub fn phi(&self) -> Option<RegionDescriptor> {
        self.phi
    }
}

/// The full pak index: mount point plus all entries.
///
/// `by_path` is a path → index lookup table built once at parse time so
/// [`PakIndex::find`] is O(1) instead of an O(n) linear scan. Memory cost
/// is one `String` clone + one `usize` per entry — for a 100k-entry
/// archive that's ~10 MB on top of the entry vec, trading bytes for
/// reads on a structure consulted on every `read_entry` call.
///
/// `encoded_regions` is `Some` for v10+ archives and `None` for v3-v9
/// flat-index archives. Used by `PakReader::verify_index` to extend
/// hash coverage past the main-index byte range (issue #86).
#[derive(Debug, Clone)]
pub struct PakIndex {
    mount_point: String,
    entries: Vec<PakIndexEntry>,
    by_path: std::collections::HashMap<String, usize>,
    encoded_regions: Option<EncodedRegions>,
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

    /// V10+ region descriptors (FDI and optional PHI) parsed from
    /// the main-index header. `None` for v3-v9 flat-index archives.
    /// Used by [`crate::container::pak::PakReader::verify_index`] to
    /// hash the encoded-index regions for tamper detection.
    pub fn encoded_regions(&self) -> Option<&EncodedRegions> {
        self.encoded_regions.as_ref()
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
    pub(super) fn from_entries(
        mount_point: String,
        entries: Vec<PakIndexEntry>,
        encoded_regions: Option<EncodedRegions>,
    ) -> crate::Result<Self> {
        // **Last-wins dedup**. UE writers may emit duplicate filenames
        // for shadowing (mod patches override base assets); on a
        // duplicate, the last occurrence wins.
        //
        // Issue #88: pre-fix, `self.entries` retained every duplicate
        // while `by_path` (and therefore `find()`) returned only the
        // last — so `entries()` and `find()` disagreed on which
        // entries existed. A consumer summing `entries().map(|e|
        // e.uncompressed_size())` over a duplicate-pathed archive
        // would over-count; calling `read_entry(path)` once per
        // entry would re-read the surviving entry per duplicate.
        // Now both views agree: shadowed entries are dropped from
        // `self.entries` to match `by_path`'s last-wins shape. The
        // single aggregated `warn!` documents the dropped count + a
        // sample so no information is lost in the operator log.
        //
        // Implementation: reverse-walk + skip-if-seen yields the
        // last occurrence of each filename (the survivor); reverse
        // again to restore original wire order.
        let entries_len = entries.len();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        seen.try_reserve(entries_len)
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "dedup tracker for entries",
                    requested: entries_len,
                    source,
                    path: None,
                },
            })?;
        let mut sampled_dups: Vec<String> = Vec::new();
        let mut deduped_rev: Vec<PakIndexEntry> = Vec::with_capacity(entries_len);
        for entry in entries.into_iter().rev() {
            if seen.insert(entry.filename.clone()) {
                deduped_rev.push(entry);
            } else if sampled_dups.len() < MAX_SAMPLED_DUPS {
                sampled_dups.push(entry.filename.clone());
            }
        }
        let dup_count = entries_len - deduped_rev.len();
        deduped_rev.reverse();
        let entries = deduped_rev;

        if dup_count > 0 {
            warn!(
                dup_count,
                samples = ?sampled_dups,
                "pak index contains {dup_count} duplicate filename(s) — last entry wins for each; \
                 first {} shown",
                sampled_dups.len()
            );
        }

        // Build by_path against the deduped entries. No collisions
        // possible at this point — the dedup loop above used `seen`
        // as the same-shape uniqueness oracle.
        let mut by_path: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        by_path
            .try_reserve(entries.len())
            .map_err(|source| PaksmithError::InvalidIndex {
                fault: IndexParseFault::AllocationFailed {
                    context: "by-path lookup entries",
                    requested: entries.len(),
                    source,
                    path: None,
                },
            })?;
        for (i, entry) in entries.iter().enumerate() {
            // Guaranteed-fresh insert — `seen` already enforced
            // uniqueness in the dedup loop above. The discarded
            // `Option<usize>` is `None` for every iteration here.
            let _ = by_path.insert(entry.filename.clone(), i);
        }

        Ok(Self {
            mount_point,
            entries,
            by_path,
            encoded_regions,
        })
    }
}

impl PakIndexEntry {
    /// Construct from already-parsed parts. Used by the v10+ FDI walk
    /// in [`super::path_hash`] when filenames are recovered from the
    /// directory index rather than read inline.
    pub(super) fn from_parts(filename: String, header: PakEntryHeader) -> Self {
        Self { filename, header }
    }

    /// Read a single (filename FString + FPakEntry record) pair off
    /// the wire. Used by the v3-v9 flat-index walk in
    /// [`super::flat`].
    pub(super) fn read_from<R: Read>(
        reader: &mut R,
        version: PakVersion,
        compression_methods: &[Option<CompressionMethod>],
    ) -> crate::Result<Self> {
        let filename = read_fstring(reader)?;
        let header = PakEntryHeader::read_from(reader, version, compression_methods)?;
        Ok(Self { filename, header })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::num::NonZeroU32;

    use byteorder::{LittleEndian, WriteBytesExt};

    use super::entry_header::encoded_entry_in_data_record_size;
    use super::*;
    use crate::digest::Sha1Digest;
    use crate::error::{BoundsUnit, EncodedFault, OverflowSite};
    // Issue #68: V10+ fixture builder shared with the integration
    // proptest under `tests/index_proptest.rs`. Gated behind
    // `__test_utils`, which is auto-enabled during `cargo test` via
    // paksmith-core's dev-deps on itself. The lower-level helpers
    // (`write_fdi_body`, `write_fstring`) stay imported locally
    // because the in-source test mod has its own non-v10 helpers
    // (`write_compressed_entry`, etc.) using a private
    // `write_fstring` already.
    use crate::testing::v10::{
        EncodeArgs, V10Fixture, build_v10_buffer, encode_entry_bytes,
        write_v10_non_encoded_uncompressed,
    };

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
    ///
    /// Issue #88: post-fix `entries()` and `find()` agree on which
    /// entries exist. Both views show 1 entry (the last one) for a
    /// duplicate-pathed archive; `entries().len()` is now `1`, not `2`.
    #[test]
    fn duplicate_filename_resolves_to_last_entry() {
        let data = build_index_bytes("../../../", |buf| {
            // Two entries with the same filename, different sizes so
            // we can tell which one survived dedup.
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
            1,
            "post-#88 dedup: shadowed entry dropped from entries vec",
        );
        let found = index
            .find("Content/dup.uasset")
            .expect("duplicate path must resolve");
        assert_eq!(
            found.header().uncompressed_size(),
            999,
            "find() must return the LAST entry on duplicate filenames (shadowing semantic)",
        );
        assert_eq!(
            index.entries()[0].header().uncompressed_size(),
            999,
            "entries()[0] must be the same survivor as find() (issue #88)",
        );
    }

    /// Issue #88 explicit pinning: `entries()` and `find()` MUST agree
    /// on which entries exist for any duplicate-pathed archive. The
    /// `duplicate_filename_resolves_to_last_entry` test above checks
    /// the count + the survivor's size for a 2-duplicate case; this
    /// test stresses a 3-duplicate case + a non-dup neighbor to pin
    /// the broader invariant.
    ///
    /// Without this test, a future regression that re-introduced the
    /// pre-#88 split (entries() yields all, find() yields last) would
    /// pass `read_entry_returns_last_entry_bytes_on_duplicate_path`
    /// but silently produce inflated sums in any consumer that
    /// iterates `entries()` and aggregates per-entry stats.
    #[test]
    fn entries_and_find_agree_on_duplicate_pathed_archive() {
        let data = build_index_bytes("../../../", |buf| {
            write_uncompressed_entry(buf, "Content/dup.uasset", 0, 10);
            write_uncompressed_entry(buf, "Content/dup.uasset", 10, 20);
            write_uncompressed_entry(buf, "Content/dup.uasset", 30, 999);
            write_uncompressed_entry(buf, "Content/unique.uasset", 1029, 100);
            4
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap();

        // Two unique paths in the archive: dup (3x → 1 survivor) +
        // unique (1x). entries() count must reflect the deduped view.
        assert_eq!(
            index.entries().len(),
            2,
            "3 duplicates collapse to 1 + 1 unique = 2 surviving entries",
        );

        // Every entry returned by entries() must be reachable via
        // find() AND find() must return that exact entry (same
        // pointer / same fields).
        for entry in index.entries() {
            let by_find = index
                .find(entry.filename())
                .expect("entries() yielded an entry that find() can't resolve");
            assert_eq!(
                by_find.header().uncompressed_size(),
                entry.header().uncompressed_size(),
                "entries() vs find() disagree on uncompressed_size for `{}`",
                entry.filename(),
            );
        }

        // Survivor for the duplicate path is the LAST occurrence
        // (size 999, not 10 or 20).
        assert_eq!(
            index
                .find("Content/dup.uasset")
                .unwrap()
                .header()
                .uncompressed_size(),
            999,
        );
        // Non-duplicate path is unaffected.
        assert_eq!(
            index
                .find("Content/unique.uasset")
                .unwrap()
                .header()
                .uncompressed_size(),
            100,
        );
        // Symmetric direction of the agreement invariant: a path NOT
        // planted must not surface in find() either. Catches a
        // hypothetical regression where `by_path` retained a phantom
        // key that `entries()` no longer reflects.
        assert!(
            index.find("Content/never_planted.uasset").is_none(),
            "find() must not surface paths absent from entries()",
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

    /// Issue #90 (sev 4 / pr-test M1): the `LengthIsI32Min` arm at
    /// `fstring.rs:43` has only Display coverage. A length of
    /// `i32::MIN` cannot be `checked_abs`'d (no positive counterpart)
    /// and must reject as `FStringMalformed::LengthIsI32Min`. Without
    /// this, a regression that swapped the guard order (e.g. capping
    /// before `checked_abs`) could silently misroute the rejection.
    #[test]
    fn reject_fstring_length_is_i32_min() {
        let mut data = Vec::new();
        data.extend_from_slice(&i32::MIN.to_le_bytes());
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(
                    reason.contains("FString length") && reason.contains("i32::MIN"),
                    "expected LengthIsI32Min message, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    /// Issue #90 (sev 3 / pr-test M5): UTF-16 missing-null arm at
    /// `fstring.rs:71` had Display coverage but no behavioral test —
    /// asymmetric with the UTF-8 case which `reject_fstring_missing_null_terminator`
    /// covers. Negative `len` triggers UTF-16; a non-zero last u16
    /// surfaces as `MissingNullTerminator { encoding: Utf16 }`.
    #[test]
    fn reject_fstring_utf16_missing_null_terminator() {
        let mut data = Vec::new();
        // Length -3 = 3 u16 codepoints, no nul; bytes = 6 (3 * 2).
        data.write_i32::<LittleEndian>(-3).unwrap();
        // 3 valid ASCII u16s, none zero.
        data.write_u16::<LittleEndian>(u16::from(b'a')).unwrap();
        data.write_u16::<LittleEndian>(u16::from(b'b')).unwrap();
        data.write_u16::<LittleEndian>(u16::from(b'c')).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(
                    reason.contains("null terminator") && reason.contains("UTF-16"),
                    "expected UTF-16 missing-null message, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    /// Issue #90 (sev 3 / pr-test M5): UTF-16 invalid-encoding arm
    /// at `fstring.rs:80` had Display coverage but no behavioral
    /// test. Trigger: an unpaired high surrogate (`0xD800`) followed
    /// by a non-surrogate u16 — `String::from_utf16` rejects this.
    /// Negative len + valid trailing nul gets us past the
    /// missing-null gate, leaving `InvalidEncoding { Utf16 }` as
    /// the only possible exit.
    #[test]
    fn reject_fstring_utf16_invalid_encoding() {
        let mut data = Vec::new();
        // Length -3 = 3 u16 codepoints (incl. trailing nul).
        data.write_i32::<LittleEndian>(-3).unwrap();
        // High surrogate (0xD800) without a paired low surrogate, then 'a', then nul.
        data.write_u16::<LittleEndian>(0xD800).unwrap();
        data.write_u16::<LittleEndian>(u16::from(b'a')).unwrap();
        data.write_u16::<LittleEndian>(0).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err =
            PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, 0, len, &[]).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { fault } => {
                let reason = fault.to_string();
                assert!(
                    reason.contains("invalid") && reason.contains("UTF-16"),
                    "expected UTF-16 invalid-encoding message, got: {reason}"
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
            CompressionMethod::Unknown(NonZeroU32::new(99).unwrap())
        );
    }

    /// `Unknown(0)` is structurally impossible since the variant carries
    /// `NonZeroU32`. Pin that `from_u32(0)` returns `None` (the no-
    /// compression sentinel), not an attempt to construct
    /// `Unknown(0)`.
    #[test]
    fn compression_method_from_u32_zero_is_none_not_unknown() {
        assert_eq!(CompressionMethod::from_u32(0), CompressionMethod::None);
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
        assert_eq!(header.sha1(), Some(Sha1Digest::from([0xABu8; 20])));
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

    /// Default `EntryCommon` for tests. Spread with
    /// `EntryCommon { field_to_override: ..., ..make_common(c, u) }` to
    /// build a customized common payload for both Inline and Encoded
    /// variants.
    fn make_common(compressed_size: u64, uncompressed_size: u64) -> EntryCommon {
        EntryCommon {
            offset: 0,
            compressed_size,
            uncompressed_size,
            compression_method: CompressionMethod::None,
            is_encrypted: false,
            compression_blocks: Vec::new(),
            compression_block_size: 0,
        }
    }

    /// Default `version` for `Inline` test headers. Non-V8A so
    /// `wire_size` returns the standard 53-byte size; tests that need
    /// the V8A layout pass `PakVersion::V8A` to [`make_inline`] or
    /// construct the variant inline.
    const TEST_INLINE_VERSION: PakVersion = PakVersion::DeleteRecords;

    /// Build an `Inline` header with the supplied `common`, `sha1`, and
    /// the default test version. Use this in place of writing the
    /// `PakEntryHeader::Inline { ... }` literal directly so tests don't
    /// have to repeat the `version` boilerplate (most tests don't care
    /// about the V8A vs V8B+ distinction).
    fn make_inline(common: EntryCommon, sha1: [u8; 20]) -> PakEntryHeader {
        PakEntryHeader::Inline {
            common,
            sha1: Sha1Digest::from(sha1),
            version: TEST_INLINE_VERSION,
        }
    }

    /// Build an `Inline` header with default common fields. Use the
    /// `EntryCommon { ..make_common(...) }` spread pattern to override
    /// individual fields.
    fn make_header(compressed_size: u64, uncompressed_size: u64, sha1: [u8; 20]) -> PakEntryHeader {
        make_inline(make_common(compressed_size, uncompressed_size), sha1)
    }

    /// Build an `Encoded` header with default common fields (no SHA1 on
    /// the wire). Mirrors `make_header` for tests that need to construct
    /// a v10+ encoded entry directly.
    fn make_encoded_header(compressed_size: u64, uncompressed_size: u64) -> PakEntryHeader {
        PakEntryHeader::Encoded {
            common: make_common(compressed_size, uncompressed_size),
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
            &CompressionMethod::Unknown(NonZeroU32::new(1).unwrap()),
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
        assert_eq!(
            header.sha1(),
            None,
            "encoded entries omit SHA1 — sha1() returns None"
        );
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
        // `uncompressed <= block_count * block_size` per the issue #58
        // sibling cap. Single block × 12_345-byte chunk → uncompressed
        // must fit in one chunk.
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 12_000,
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

    /// Issue #59: a zero-block encoded entry with a non-`None`
    /// compression slot is structurally nonsensical — there are no
    /// blocks to back the `compressed_size` claim, and the Zlib
    /// stream path would walk an empty `compression_blocks` vec
    /// silently. UE never writes this shape; reject it at parse
    /// time so an attacker can't slip a fabricated `compressed_size`
    /// past consumers that read it without extracting (CLI list,
    /// JSON output).
    ///
    /// Pre-#59 this test pinned the silent-accept; the assertion is
    /// inverted to pin the rejection. The compression-method-slot
    /// resolution itself is still exercised by
    /// `read_encoded_zero_blocks_no_compression`.
    #[test]
    fn read_encoded_rejects_zero_blocks_with_compression_slot() {
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
        let err = PakEntryHeader::read_encoded(&mut cursor, &methods).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::InvariantViolated { reason }
                } if reason.contains("block_count == 0")
            ),
            "expected InvariantViolated for zero-block compressed entry, got: {err:?}"
        );
    }

    /// Companion to `read_encoded_rejects_zero_blocks_with_compression_slot`:
    /// a zero-block entry with `compression_method = None` IS a
    /// legitimate shape (an empty uncompressed entry) and must
    /// continue to parse successfully. Pin so the #59 rejection
    /// doesn't accidentally generalize.
    #[test]
    fn read_encoded_zero_blocks_no_compression() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0,
            compressed: 0,
            compression_slot_1based: 0,
            encrypted: false,
            block_count: 0,
            block_size: 0,
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();
        assert_eq!(header.compression_method(), &CompressionMethod::None);
        assert!(header.compression_blocks().is_empty());
        assert_eq!(header.uncompressed_size(), 0);
    }

    /// `PakEntryHeader::sha1()` returns `Some` for inline headers and
    /// `None` for encoded ones. Pin both polarities so a stub bug like
    /// `pub fn sha1(&self) -> Option<Sha1Digest> { None }` (or always
    /// `Some`) would fail HERE rather than only being caught by
    /// integration tests where `archive_claims_integrity()` happens to
    /// be true. (The negative-branch integration test
    /// `verify_v10_with_zero_index_hash_still_skips_encoded_entries`
    /// would NOT catch a stub-to-Some-zero: the archive doesn't claim
    /// integrity, so the gate skips correctly anyway.)
    ///
    /// This test replaces the prior `omits_sha1` delegator pin — the
    /// flag itself was retired in favour of the variant-discriminated
    /// `Option<Sha1Digest>` return type, so the corresponding regression
    /// is now "stub `sha1()` to the wrong polarity."
    #[test]
    fn sha1_accessor_distinguishes_inline_from_encoded() {
        let inline = make_header(0, 0, [0xAA; 20]);
        let inline_entry = PakIndexEntry {
            filename: "x".to_string(),
            header: inline,
        };
        assert_eq!(
            inline_entry.header().sha1(),
            Some(Sha1Digest::from([0xAA; 20]))
        );

        let encoded = make_encoded_header(0, 0);
        let encoded_entry = PakIndexEntry {
            filename: "y".to_string(),
            header: encoded,
        };
        assert_eq!(encoded_entry.header().sha1(), None);
    }

    /// Issue #44 regression: an attacker-crafted single-block encoded
    /// entry with a `compressed_size` near `u64::MAX` must surface as
    /// `U64ArithmeticOverflow { operation: OverflowSite::EncodedSingleBlockEnd, .. }`
    /// rather than silently wrapping `in_data_record_size + compressed_size`.
    ///
    /// Pre-fix code at index.rs:537 used a raw `+` and produced a
    /// `CompressionBlock { start, end }` pair where `end` was a tiny
    /// wrapped value pointing at the start of the file — every
    /// downstream read against this entry would silently grab bytes
    /// from offset 0 of the archive, not from the entry's payload.
    ///
    /// Triggering inputs: `compression_slot_1based: 1` to enter the
    /// "compressed_size is a separate wire varint" path; bit 29 cleared
    /// (compressed doesn't fit u32) to widen the varint to u64;
    /// `compressed: u64::MAX`; single block, not encrypted, so the
    /// trivial-single-block branch fires.
    #[test]
    fn read_encoded_rejects_single_block_end_overflow() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: u64::MAX,
            compressed: u64::MAX,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 1,
            block_size: 0,
            per_block_sizes: &[],
        });
        // Slot 1 = None — resolves to Unknown(NonZeroU32::new(1)),
        // which is compression_method != None, so the single-block
        // trivial path takes the in_data_record_size + compressed
        // route.
        let mut cursor = Cursor::new(bytes);
        let err = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap_err();
        // matches! with the OverflowSite variant gives compile-time
        // exhaustiveness — a typo or stale variant name would fail
        // compilation, not silently pass the test.
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        path: None,
                        operation: OverflowSite::EncodedSingleBlockEnd,
                    },
                }
            ),
            "expected EncodedSingleBlockEnd overflow, got: {err:?}"
        );
    }

    /// Issue #57 regression: when the same single-block end-overflow as
    /// `read_encoded_rejects_single_block_end_overflow` arrives via the
    /// v10+ FDI walk (rather than a direct `read_encoded` call), the
    /// FDI-walk caller MUST fold the recovered virtual path into the
    /// `U64ArithmeticOverflow` fault. Pre-#57, the overflow surfaced
    /// with `path: None` because `read_encoded` doesn't know the path —
    /// PR #56's fix made `path: Option<String>` to accommodate that.
    /// Issue #57's fix adds enrichment at the FDI-walk boundary so
    /// operators get the full `Content/foo.uasset` in the error.
    #[test]
    fn read_v10_plus_enriches_encoded_entry_overflow_with_fdi_path() {
        // Same overflow trigger as `read_encoded_rejects_single_block_end_overflow`.
        let encoded = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: u64::MAX,
            compressed: u64::MAX,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 1,
            block_size: 0,
            per_block_sizes: &[],
        });
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            encoded_entries: encoded,
            // FDI carries one entry pointing at offset 0 of the encoded
            // blob with path "Content/foo.uasset". Subdirectories
            // typically omit the leading slash, so the joined virtual
            // path is `dir_name + file_name` verbatim.
            fdi: vec![("Content/".into(), vec![("foo.uasset".into(), 0)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            main_size,
            &[None],
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::U64ArithmeticOverflow {
                        path: Some(p),
                        operation: OverflowSite::EncodedSingleBlockEnd,
                    },
                } if p == "Content/foo.uasset"
            ),
            "expected EncodedSingleBlockEnd overflow with path Some(\"Content/foo.uasset\"), got: {err:?}"
        );
    }

    /// Issue #90 (sev 7 / pr-test H2): companion to
    /// `read_v10_plus_enriches_encoded_entry_overflow_with_fdi_path`
    /// — exercises the same FDI-walk `with_index_path` enrichment
    /// boundary (`path_hash.rs::read_v10_plus_index`) for the
    /// `CompressedSizeMismatch` variant. Without this test, a future
    /// regression that drops `EncodedFault::CompressedSizeMismatch`
    /// from `set_path_if_unset`'s enriching arm would silently drop
    /// the path on this fault while leaving the `U64ArithmeticOverflow`
    /// path covered.
    #[test]
    fn read_v10_plus_enriches_encoded_entry_compressed_size_mismatch_with_fdi_path() {
        // Same trigger as `read_encoded_rejects_compressed_size_block_sum_mismatch`:
        // wire `compressed_size = u64::MAX - 1` but per-block sizes
        // sum to 0x3000.
        let encoded = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x3000,
            compressed: u64::MAX - 1,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 3,
            block_size: 0x1000,
            per_block_sizes: &[0x1000, 0x1000, 0x1000],
        });
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            encoded_entries: encoded,
            fdi: vec![("Content/".into(), vec![("bar.uasset".into(), 0)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            main_size,
            &[None],
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::Encoded {
                        kind: EncodedFault::CompressedSizeMismatch {
                            claimed,
                            computed: 0x3000,
                            path: Some(p),
                        },
                    },
                } if *claimed == u64::MAX - 1 && p == "Content/bar.uasset"
            ),
            "expected CompressedSizeMismatch with path Some(\"Content/bar.uasset\"), got: {err:?}"
        );
    }

    /// Issue #58 regression: a multi-block encoded entry whose wire
    /// `compressed_size` doesn't match the sum of its per-block sizes
    /// MUST be rejected. Without the cross-check, an attacker can
    /// claim `compressed_size = u64::MAX - 1` (via the u64-width
    /// varint, gated by bit-29 cleared) while the per-block sizes
    /// sum to a few KiB — and the lie propagates to
    /// `PakEntryHeader::compressed_size()` and any downstream
    /// consumer reporting the entry's payload size.
    ///
    /// Triggering inputs: block_count=3, per_block_sizes summing to
    /// 0x3000, but `compressed: u64::MAX - 1`. The bit-29-cleared
    /// width is forced by `compressed > u32::MAX`, so the parser
    /// reads the full u64 from the wire and the mismatch fires.
    #[test]
    fn read_encoded_rejects_compressed_size_block_sum_mismatch() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x3000,
            compressed: u64::MAX - 1, // wire claim — diverges from sum
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 3,
            block_size: 0x1000,
            per_block_sizes: &[0x1000, 0x1000, 0x1000], // actual sum = 0x3000
        });
        let mut cursor = Cursor::new(bytes);
        let err = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::Encoded { kind: EncodedFault::CompressedSizeMismatch {
                        claimed,
                        computed: 0x3000,
                        path: None,
                    } },
                } if *claimed == u64::MAX - 1
            ),
            "expected EncodedFault::CompressedSizeMismatch claimed=u64::MAX-1 computed=0x3000, got: {err:?}"
        );
    }

    /// Issue #58: a multi-block encoded entry whose wire
    /// `uncompressed_size` claim exceeds the structural cap
    /// `block_count × compression_block_size` is rejected. Without
    /// this check, an attacker can claim e.g. `uncompressed_size =
    /// MAX_UNCOMPRESSED_ENTRY_BYTES` (8 GiB) on a payload that
    /// actually fits in 4 KiB, and consumers reading
    /// `uncompressed_size()` (CLI list, JSON output, alloc
    /// estimators) would see the lie. The cap is the structural
    /// upper bound: each block decompresses to AT MOST
    /// `compression_block_size`, and there are exactly `block_count`
    /// of them — final block may be shorter, never longer.
    #[test]
    fn read_encoded_rejects_uncompressed_size_exceeding_block_capacity() {
        // 3 blocks × 0x1000 block_size = 0x3000 cap. Wire claim is
        // 0x100000 (1 MiB) — well above the cap.
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x10_0000,
            compressed: 0x3000,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 3,
            block_size: 0x1000,
            per_block_sizes: &[0x1000, 0x1000, 0x1000],
        });
        let mut cursor = Cursor::new(bytes);
        let err = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap_err();
        let PaksmithError::InvalidIndex {
            fault:
                IndexParseFault::BoundsExceeded {
                    field,
                    value,
                    limit,
                    unit: BoundsUnit::Bytes,
                    path: None,
                },
        } = &err
        else {
            panic!("expected InvalidIndex BoundsExceeded with Bytes unit and no path, got: {err:?}")
        };
        assert_eq!(*field, "uncompressed_size");
        assert_eq!(*value, 0x10_0000_u64);
        // 3 blocks × 0x1000 each = 0x3000 cap.
        assert_eq!(*limit, 0x3000_u64);
    }

    /// Issue #58: the single-block trivial path is structurally
    /// exempt from the multi-block compressed_size cross-check —
    /// the sole block is constructed *from* `compressed_size` —
    /// they're trivially equal by construction. Pin that a
    /// single-block entry with a moderate `compressed` doesn't
    /// trip either the (skipped) cross-check or the unrelated
    /// `EncodedSingleBlockEnd` overflow guard.
    ///
    /// Note: the issue #58 sibling `uncompressed_size` cap DOES
    /// apply to this path (not just the multi-block branch), so
    /// `block_size` must be set to a value that accommodates the
    /// `uncompressed` claim.
    #[test]
    fn read_encoded_single_block_path_skips_cross_check() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x4000,
            compressed: 0x4000,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 1,
            block_size: 0x4000, // satisfies uncompressed <= 1 * block_size
            per_block_sizes: &[],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap();
        assert_eq!(header.compressed_size(), 0x4000);
        assert_eq!(header.compression_blocks().len(), 1);
    }

    /// Issue #58 sibling-fix boundary pin: `uncompressed_size ==
    /// max_uncompressed` (equality) MUST be accepted (the cap uses
    /// `>`, not `>=`). A regression flipping the operator would
    /// reject this. Companion to
    /// `read_encoded_rejects_uncompressed_size_exceeding_block_capacity`
    /// which pins the strict-greater rejection side.
    #[test]
    fn read_encoded_accepts_uncompressed_size_at_block_capacity() {
        // 4 blocks × 0x1000 each = 0x4000 cap; uncompressed = 0x4000.
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x4000,
            compressed: 0x4000,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 4,
            block_size: 0x1000,
            per_block_sizes: &[0x1000, 0x1000, 0x1000, 0x1000],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap();
        assert_eq!(header.uncompressed_size(), 0x4000);
        assert_eq!(header.compression_blocks().len(), 4);
    }

    /// Issue #58 sibling-fix false-positive guard: an encoded entry
    /// with `compression_method == None` and `block_count > 0` MUST
    /// skip the `block_count * compression_block_size` cap, because
    /// uncompressed entries don't chunk and typically have
    /// `compression_block_size == 0`. Without the guard,
    /// `block_count * 0 = 0` would reject any non-zero
    /// `uncompressed_size`. The open-time
    /// `MAX_UNCOMPRESSED_ENTRY_BYTES` backstop in `PakReader::open`
    /// catches the gross-lie case for these.
    #[test]
    fn read_encoded_skips_uncompressed_cap_for_uncompressed_method() {
        // Single-block-encrypted entry (enters the multi-block branch)
        // with compression_slot_1based = 0 (CompressionMethod::None).
        // For None, compressed_size = uncompressed_size by line ~327.
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x1000,
            compressed: 0x1000,
            compression_slot_1based: 0,
            encrypted: true,
            block_count: 1,
            block_size: 0, // typical for uncompressed
            per_block_sizes: &[0x1000],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[]).unwrap();
        assert_eq!(header.compression_method(), &CompressionMethod::None);
        assert_eq!(header.uncompressed_size(), 0x1000);
    }

    /// Issue #44 defensive-discipline pin: a malicious multi-block
    /// encoded entry triggers checked_add for `cursor + block_compressed_size`
    /// and `start + advance`. With the u32 wire width on per-block
    /// sizes, no realistic input can actually overflow these adds
    /// (max cumulative ≈ 65 535 × 4 GiB ≪ u64::MAX), so this test
    /// pins the happy path — a normal-bounds multi-block walk
    /// completes successfully. Together with
    /// `read_encoded_rejects_single_block_end_overflow`, the test
    /// suite documents: (a) the practically-triggerable overflow is
    /// caught with a typed error, (b) the defensive checked_adds on
    /// the loop body don't accidentally reject valid inputs.
    #[test]
    fn read_encoded_multi_block_cursor_walk_succeeds_on_valid_input() {
        let bytes = encode_entry_bytes(EncodeArgs {
            offset: 0,
            uncompressed: 0x3000,
            compressed: 0x3000,
            compression_slot_1based: 1,
            encrypted: false,
            block_count: 3,
            block_size: 0x1000,
            per_block_sizes: &[0x1000, 0x1000, 0x1000],
        });
        let mut cursor = Cursor::new(bytes);
        let header = PakEntryHeader::read_encoded(&mut cursor, &[None]).unwrap();
        assert_eq!(header.compression_blocks().len(), 3);
    }

    /// V10+ encoded entries decode to the `Encoded` variant and carry
    /// no SHA1 on the wire — `sha1()` returns `None`.
    #[test]
    fn read_encoded_produces_encoded_variant_with_no_sha1() {
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
        assert!(
            matches!(header, PakEntryHeader::Encoded { .. }),
            "read_encoded must produce the Encoded variant"
        );
        assert_eq!(header.sha1(), None, "encoded entries omit SHA1");
    }

    /// `matches_payload`'s SHA1 cross-check fires for two Inline
    /// entries even when the index-side SHA1 is all zeros. For a v3-v9
    /// entry where the index claims a zero SHA1 but the in-data record
    /// has a real SHA1, the mismatch must still surface as InvalidIndex
    /// — that's the tampering signal we preserve from the pre-PR-#27
    /// behavior.
    #[test]
    fn matches_payload_keeps_zero_sha1_check_for_v3_v9() {
        // Index entry: Inline with zero sha1 (v3-v9 default).
        let index = make_header(100, 100, [0u8; 20]);
        // In-data record: Inline with non-zero sha1. Pre-PR this
        // surfaced as a tampering signal; the cross-check still
        // fires because both sides are Inline.
        let in_data = make_header(100, 100, [0xBB; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        assert!(
            matches!(&err, PaksmithError::InvalidIndex { fault } if fault.to_string().contains("sha1")),
            "got: {err:?}"
        );
    }

    /// `matches_payload`'s SHA1 cross-check is skipped when the index
    /// side is an Encoded variant (no SHA1 on the wire). The in-data
    /// record carries a real SHA1, the encoded index header has none,
    /// and the check is skipped — without this every v10+ entry would
    /// fail to extract.
    #[test]
    fn matches_payload_skips_sha1_for_encoded_entries() {
        let index = make_encoded_header(100, 100);
        let in_data = make_header(100, 100, [0xBB; 20]);
        assert!(
            index.matches_payload(&in_data, "x").is_ok(),
            "encoded entries must skip the SHA1 cross-check"
        );
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
            fdi: vec![("/Content/".into(), vec![("a.uasset".into(), 1000)])],
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
            fdi: vec![("/Content/".into(), vec![("a.uasset".into(), -1)])],
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
            fdi: vec![("/Content/".into(), vec![("a.uasset".into(), -1)])],
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
        // Issue #94: read the cap from production via the
        // `pub(super) const MAX_FDI_BYTES` in `path_hash` rather than
        // re-declaring the literal here. Drift between the test's
        // mirror and the production cap would have been silent before;
        // now a cap change updates one place.
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            fdi_size_override: Some(path_hash::MAX_FDI_BYTES + 1),
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

    /// End-to-end roundtrip pin for the Inline/Encoded variant glue:
    /// a v10+ encoded entry decoded by `read_encoded` must skip the
    /// SHA1 cross-check when `matches_payload` is later called against
    /// an in-data Inline record carrying a real SHA1. This is what
    /// cross-parser fixtures exercise implicitly; doing it as a unit
    /// test ensures that a refactor changing the variant produced by
    /// `read_encoded` (or the `Option`-pattern in `matches_payload`)
    /// doesn't silently break the glue — the decoder unit tests alone
    /// wouldn't catch it.
    #[test]
    fn matches_payload_roundtrip_for_encoded_entry() {
        // Decode a real encoded entry: produces the Encoded variant,
        // sha1() returns None.
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
        let in_data = make_inline(
            EntryCommon {
                offset: 0,
                ..make_common(0x4000, 0x4000)
            },
            [0xCC; 20],
        );

        // Without the variant-discriminated SHA1 skip in matches_payload
        // this would fail with a sha1 mismatch error.
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
            fdi: vec![(
                "/Content/".into(),
                vec![("a.uasset".into(), -1), ("b.uasset".into(), -1)],
            )],
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

    /// Issue #87 regression: a v10+ FDI claiming `file_count = N`
    /// but yielding fewer than N entries (truncated FDI, writer
    /// crash, bit-flip in a `dir_count`) must reject with the typed
    /// `EncodedFault::FdiFileCountShort` variant. Symmetric
    /// counterpart to `read_v10_plus_rejects_fdi_overflowing_file_count`.
    #[test]
    fn read_v10_plus_rejects_fdi_underflowing_file_count() {
        // file_count = 3, but FDI carries only 1 entry. The walk
        // completes with fewer entries than claimed.
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 3,
            fdi: vec![("/Content/".into(), vec![("a.uasset".into(), -1)])],
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
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::Encoded {
                        kind: EncodedFault::FdiFileCountShort {
                            file_count: 3,
                            actual: 1,
                        },
                    },
                }
            ),
            "expected EncodedFault::FdiFileCountShort {{ file_count: 3, actual: 1 }}; got: {err:?}"
        );
    }

    /// Issue #87 regression: a forged `dir_count` exceeding what
    /// `fdi_size` could carry (at the 9-byte minimum per-dir wire
    /// record) must reject upfront via `BoundsExceeded { field:
    /// "dir_count" }`, before the loop iterates billions of times.
    #[test]
    fn read_v10_plus_rejects_dir_count_exceeding_fdi_size() {
        let (mut buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 0,
            fdi: vec![("/".into(), vec![])],
            ..V10Fixture::default()
        });
        // FDI body starts at `main_size`; first 4 bytes are dir_count.
        // V10Fixture has no dir_count override, so hand-patch.
        let main_size_usize = main_size as usize;
        buf[main_size_usize..main_size_usize + 4].copy_from_slice(&u32::MAX.to_le_bytes());

        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: "dir_count",
                        ..
                    },
                }
            ),
            "expected BoundsExceeded {{ field: \"dir_count\" }}; got: {err:?}"
        );
    }

    /// Issue #87 boundary pin: an empty archive (`file_count = 0` with
    /// an FDI body that is just a `dir_count = 0` header) must parse
    /// cleanly. Guards against an off-by-one in the underrun check
    /// that would have rejected the legitimate zero case.
    #[test]
    fn read_v10_plus_accepts_empty_archive() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 0,
            fdi: Vec::new(),
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let index = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .expect("empty v10+ archive must parse");
        assert!(index.entries().is_empty());
    }

    /// Issue #87 boundary pin: `dir_count` exactly at the cap
    /// (`fdi_size / 9`) must be accepted. Constructs a single minimal
    /// dir record (empty FString name + zero files = 9 bytes) giving
    /// `fdi_size = 4 + 9 = 13`, `max_dirs = 1`, `dir_count = 1`. The
    /// `+1` rejection case is covered by the sibling
    /// `..._plus_one_rejects` test.
    #[test]
    fn read_v10_plus_accepts_dir_count_at_cap_boundary() {
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 0,
            fdi: vec![(String::new(), Vec::new())],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let _ = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .expect("dir_count == max_dirs_for_fdi must be accepted");
    }

    /// Issue #87 boundary pin: bumping `dir_count` by exactly 1 past
    /// the cap (same fixture as `..._at_cap_boundary`) must reject.
    /// Confirms the comparison is `>` (strict), not `>=`.
    #[test]
    fn read_v10_plus_rejects_dir_count_at_cap_plus_one() {
        let (mut buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 0,
            fdi: vec![(String::new(), Vec::new())],
            ..V10Fixture::default()
        });
        // Same hand-patch as the u32::MAX test, but forge cap+1 = 2
        // to pin the strict-greater-than boundary.
        let main_size_usize = main_size as usize;
        buf[main_size_usize..main_size_usize + 4].copy_from_slice(&2u32.to_le_bytes());

        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::BoundsExceeded {
                        field: "dir_count",
                        value: 2,
                        limit: 1,
                        ..
                    },
                }
            ),
            "expected BoundsExceeded {{ field: \"dir_count\", value: 2, limit: 1 }}; got: {err:?}"
        );
    }

    /// Issue #87 regression: the underrun guard must fire when the
    /// walk yields zero entries against a positive `file_count`. The
    /// `..._underflowing_file_count` test covers `actual = 1`; this
    /// pins the `actual = 0` extreme.
    #[test]
    fn read_v10_plus_rejects_fdi_yielding_zero_entries() {
        // file_count = 1 but the FDI carries 1 dir with 0 files.
        // fdi_size = 4 (dir_count) + 6 (FString "/") + 4 (file_count) = 14,
        // so max_files = 14/9 = 1 — file_count cap allows this and the
        // underrun guard is what fires.
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            file_count: 1,
            fdi: vec![("/".into(), Vec::new())],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let err = PakIndex::read_from(&mut cursor, PakVersion::PathHashIndex, 0, main_size, &[])
            .unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidIndex {
                    fault: IndexParseFault::Encoded {
                        kind: EncodedFault::FdiFileCountShort {
                            file_count: 1,
                            actual: 0,
                        },
                    },
                }
            ),
            "expected EncodedFault::FdiFileCountShort {{ file_count: 1, actual: 0 }}; got: {err:?}"
        );
    }

    #[test]
    fn matches_payload_accepts_identical_modulo_offset() {
        // The offset field intentionally differs (index = real, in-data = 0)
        // and matches_payload should not flag it.
        let index = make_inline(
            EntryCommon {
                offset: 1024,
                ..make_common(50, 100)
            },
            [0xAA; 20],
        );
        let in_data = make_inline(
            EntryCommon {
                offset: 0,
                ..make_common(50, 100)
            },
            [0xAA; 20],
        );
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
        let index = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::None,
                ..make_common(100, 100)
            },
            [0xAA; 20],
        );
        let in_data = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                ..make_common(100, 100)
            },
            [0xAA; 20],
        );
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
        let in_data = make_inline(
            EntryCommon {
                is_encrypted: true,
                ..make_common(50, 100)
            },
            [0xAA; 20],
        );
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
        let index = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
                compression_block_size: 100,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
        let in_data = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![
                    CompressionBlock::new(73, 86).unwrap(),
                    CompressionBlock::new(86, 100).unwrap(),
                ],
                compression_block_size: 100,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
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
        let index = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
                compression_block_size: 100,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
        let in_data = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
                compression_block_size: 65_536,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
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
        let h = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![
                    CompressionBlock::new(0, 50).unwrap(),
                    CompressionBlock::new(50, 100).unwrap(),
                ],
                compression_block_size: 100,
                ..make_common(100, 200)
            },
            [0; 20],
        );
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

    /// V8A counterpart to `wire_size_matches_bytes_consumed_by_read_from_*`.
    /// V8A is the only variant whose compression-method field is u8 (vs u32
    /// for every other version), making it a 3-byte-shorter wire layout.
    /// Without this test, a regression in either `read_from`'s u8 read or
    /// `wire_size`'s `version == V8A` dispatch would slide every multi-block
    /// V8A read by 3 bytes and the existing CompressionEncryption-only
    /// invariant tests would not notice.
    #[test]
    fn wire_size_matches_bytes_consumed_by_read_from_v8a_compressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(50).unwrap();
        buf.write_u64::<LittleEndian>(200).unwrap();
        buf.push(1); // V8A: u8 compression index → slot 0 (zlib)
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(2).unwrap();
        buf.write_u64::<LittleEndian>(70).unwrap();
        buf.write_u64::<LittleEndian>(95).unwrap();
        buf.write_u64::<LittleEndian>(95).unwrap();
        buf.write_u64::<LittleEndian>(120).unwrap();
        buf.push(0);
        buf.write_u32::<LittleEndian>(100).unwrap();

        let total = buf.len() as u64;
        let methods = [Some(CompressionMethod::Zlib), None, None, None];
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor, PakVersion::V8A, &methods).unwrap();
        assert_eq!(
            cursor.position(),
            total,
            "V8A read_from did not consume all bytes"
        );
        assert_eq!(
            header.wire_size(),
            total,
            "V8A wire_size disagrees with read_from's actual consumption"
        );
    }

    /// Tighter regression test for `compression_blocks` mismatch detection.
    /// The previous test only varied length; this one keeps length identical
    /// and varies a single block's `end`. A `len()`-only comparison would
    /// silently pass this case.
    #[test]
    fn matches_payload_rejects_compression_blocks_content_mismatch() {
        let index = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
                compression_block_size: 100,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
        let in_data = make_inline(
            EntryCommon {
                compression_method: CompressionMethod::Zlib,
                // Same count, different end offset.
                compression_blocks: vec![CompressionBlock::new(73, 99).unwrap()],
                compression_block_size: 100,
                ..make_common(27, 100)
            },
            [0xAA; 20],
        );
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
