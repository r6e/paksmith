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
pub use entry_header::{EntryCommon, PakEntryHeader};

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
    ) -> crate::Result<Self> {
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
            fdi: vec![("Content/", &[("foo.uasset", 0)])],
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
            "expected EncodedCompressedSizeMismatch claimed=u64::MAX-1 computed=0x3000, got: {err:?}"
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
