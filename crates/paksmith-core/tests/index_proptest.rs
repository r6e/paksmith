//! Property-based tests for v10+ index parsing.
//!
//! Three properties:
//!
//! 1. **Garbage bytes never panic**: random bytes fed into
//!    `PakIndex::read_from` (with a v10+ version) never panic — they
//!    either return `Ok(...)` (vanishingly rare given the structured
//!    wire format) or `Err(...)` (typical). Validates the "no panics
//!    in core" rule from CLAUDE.md against the most complex parser
//!    in the codebase.
//!
//! 2. **Deep-structured-input never panics**: plants a minimal-valid
//!    v10+ main-index prefix that gets the parser past the FString
//!    and structural-flag reads, then randomizes the bounds-relevant
//!    numeric fields AND biases `fdi_offset` to land inside the
//!    buffer so the FDI walk actually runs (the deepest, most fragile
//!    parser code: `dir_count`, `dir_name` FString reads, per-file
//!    FString reads, file_count cross-check). Optionally plants a
//!    path-hash-index header so the PHI-present arm is reachable.
//!
//! 3. **Structural round-trip oracle (issue #68)**: builds a
//!    well-formed v10+ archive via the shared `V10Fixture` /
//!    `build_v10_buffer` helpers (paksmith-core's `__test_utils`
//!    surface) with strategy-generated `mount`, `file_count`, and
//!    FDI directory entries; parses it; asserts the recovered
//!    fields match what was planted. Catches silent-corruption
//!    regressions (off-by-one entry counts, mount-point truncation,
//!    FDI path mangling) that the no-panic-only properties cannot.
//!
//! Issues #51 and #68.

#![allow(missing_docs)]

use std::io::Cursor;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::index::{CompressionMethod, PakIndex, PakIndexEntry};
use paksmith_core::container::pak::version::PakVersion;
use paksmith_core::testing::v10::{EncodeArgs, V10Fixture, build_v10_buffer, encode_entry_bytes};
use proptest::prelude::*;

/// Write an FString (length-prefixed, null-terminated ASCII).
/// Length sign convention: positive = ASCII, length includes null.
///
/// Local copy because the deep-structured property below builds a
/// minimal main-index prefix BY HAND (with caller-controlled
/// bounds-relevant fields) rather than going through
/// `build_v10_buffer` — we need to be able to plant lying values
/// for `fdi_offset`/`fdi_size` independently of the buffer
/// structure, which the fixture builder won't let us do.
fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let len = (s.len() + 1) as i32;
    buf.write_i32::<LittleEndian>(len).unwrap();
    buf.extend_from_slice(s.as_bytes());
    buf.push(0);
}

/// Plant a minimal valid v10+ main-index prefix that passes the
/// FString + path_hash_seed + has_path_hash_index reads. The caller
/// chooses bounds-relevant field values to drive the parser's
/// bounds-check arms. See the doc-comment in
/// `read_v10_plus_planted_frame_with_in_bounds_fdi_never_panics`
/// for why this lives here rather than going through
/// `build_v10_buffer` (the fixture builder enforces internal
/// consistency that this property explicitly wants to violate).
#[allow(clippy::too_many_arguments)]
fn plant_v10_main_index(
    file_count: u32,
    has_phi: bool,
    fdi_offset: u64,
    fdi_size: u64,
    encoded_entries_size: u32,
    encoded_blob: &[u8],
    non_encoded_count: u32,
    non_encoded_tail: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_fstring(&mut buf, "/");
    buf.write_u32::<LittleEndian>(file_count).unwrap();
    buf.write_u64::<LittleEndian>(0).unwrap(); // path_hash_seed
    buf.write_u32::<LittleEndian>(u32::from(has_phi)).unwrap();
    if has_phi {
        buf.write_u64::<LittleEndian>(0).unwrap(); // phi_offset
        buf.write_u64::<LittleEndian>(0).unwrap(); // phi_size (zero so the
        // parser doesn't try to read PHI bytes outside the buffer)
        buf.extend_from_slice(&[0u8; 20]); // phi_hash
    }
    buf.write_u32::<LittleEndian>(1).unwrap(); // has_full_directory_index = true
    buf.write_u64::<LittleEndian>(fdi_offset).unwrap();
    buf.write_u64::<LittleEndian>(fdi_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // fdi_hash
    buf.write_u32::<LittleEndian>(encoded_entries_size).unwrap();
    buf.extend_from_slice(encoded_blob);
    buf.write_u32::<LittleEndian>(non_encoded_count).unwrap();
    buf.extend_from_slice(non_encoded_tail);
    buf
}

/// Strategy for an ASCII path segment safe to use as an FDI dir
/// name or file name. Avoids `\0` (would terminate the FString
/// early), `/` (would interact with the dir-prefix strip logic),
/// and high-bit bytes (would not round-trip cleanly through
/// `as_bytes()`/`from_utf8`). Length 1..16 keeps the per-entry
/// budget bounded.
fn ascii_segment() -> impl Strategy<Value = String> {
    proptest::collection::vec(b'a'..=b'z', 1..16)
        .prop_map(|bytes| String::from_utf8(bytes).expect("ascii is utf-8"))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Garbage bytes fed into the v10+ parser never panic. Uses
    /// `PakVersion::PathHashIndex` so `read_from` dispatches to
    /// `read_v10_plus_from` rather than the flat v3-v9 path.
    /// Most random byte sequences fail the initial FString
    /// length-prefix check; this property guards the early-reject
    /// paths.
    #[test]
    fn read_v10_plus_garbage_bytes_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
        index_size_kind in 0u8..3,
        index_size_random in 0u64..u64::MAX,
    ) {
        // Stratify `index_size` across three buckets so the shrinker
        // collapses to discrete cases rather than fighting two
        // independently-shrinking integers: zero, exactly-buffer-length
        // (the "honest" header), and unbounded random (mostly larger
        // than buffer, triggers the truncated-read path). Without this,
        // a discovered regression shrinks to an arbitrary middle value.
        let index_size = match index_size_kind {
            0 => 0,
            1 => bytes.len() as u64,
            _ => index_size_random,
        };
        let mut cursor = Cursor::new(bytes);
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            index_size,
            &[],
        );
    }

    /// Deep-structured property: plant a v10+ main-index prefix that
    /// gets the parser past the FString and structural-flag reads,
    /// then drive the FDI walk by biasing `fdi_offset` to land inside
    /// the buffer most of the time. The FDI walk itself
    /// (`dir_count`, per-dir `dir_name` FString + per-file FString +
    /// `i32 encoded_offset`, plus the file_count cross-check at
    /// `read_v10_plus_from`'s end) is the deepest parser code in the
    /// codebase; random bytes from the property above almost never
    /// reach it because of the early FString-length reject.
    ///
    /// `has_path_hash_index` is randomized: when true, the PHI header
    /// (offset/size/hash) is planted with zero size so the parser
    /// doesn't try to read PHI bytes outside the buffer — but the
    /// "PHI is present" branch is still exercised, which the
    /// previous version of this property never reached.
    ///
    /// **Why this can't use `V10Fixture`**: `build_v10_buffer`
    /// computes `fdi_offset`/`fdi_size` from the buffer structure —
    /// they're always honest. This property wants to drive the
    /// bounds-check arms by planting *lying* values, which means
    /// hand-rolling the prefix.
    #[test]
    fn read_v10_plus_planted_frame_with_in_bounds_fdi_never_panics(
        file_count in 0u32..1024,
        has_phi in any::<bool>(),
        fdi_offset_kind in 0u8..3,
        fdi_offset_random in 0u64..u64::MAX,
        fdi_size_kind in 0u8..3,
        fdi_size_random in 0u64..u64::MAX,
        encoded_blob in proptest::collection::vec(any::<u8>(), 0..512),
        encoded_size_lies in any::<bool>(),
        non_encoded_count in 0u32..1024,
        non_encoded_tail in proptest::collection::vec(any::<u8>(), 0..512),
        fdi_tail in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let encoded_size = if encoded_size_lies {
            // Lie about the encoded blob size — exercises the bounds
            // check in `path_hash::read_v10_plus_from` against
            // `encoded_entries_size`.
            (encoded_blob.len() as u32).saturating_add(1024)
        } else {
            encoded_blob.len() as u32
        };
        let main_prefix = plant_v10_main_index(
            file_count,
            has_phi,
            0, // fdi_offset placeholder — patched below
            0, // fdi_size placeholder — patched below
            encoded_size,
            &encoded_blob,
            non_encoded_count,
            &non_encoded_tail,
        );
        let main_len = main_prefix.len() as u64;

        // Bias fdi_offset to land in-bounds (kind 0 + 1 = inside the
        // buffer, kind 2 = fully random — overwhelmingly out of bounds).
        // Out-of-bounds is fine to test, but without the in-bounds
        // bias the FDI parser is unreachable for ~99.99% of cases.
        let fdi_offset = match fdi_offset_kind {
            0 => main_len, // FDI directly follows main index — the canonical layout.
            1 => fdi_offset_random.checked_rem(main_len.saturating_mul(2).max(1)).unwrap_or(0),
            _ => fdi_offset_random,
        };
        let fdi_size = match fdi_size_kind {
            0 => fdi_tail.len() as u64,
            1 => 0,
            _ => fdi_size_random,
        };

        // Concatenate main + fdi_tail; patch the fdi_offset/fdi_size
        // fields in the prefix. The PHI header occupies 36 bytes
        // (8 offset + 8 size + 20 hash) when has_phi is true.
        let phi_bytes: u64 = if has_phi { 36 } else { 0 };
        // Locate the FDI header in the prefix: mount FString
        // (4 length + 2 bytes "/\0") + file_count(4) + path_hash_seed(8)
        // + has_path_hash_index(4) + [phi_bytes if PHI] +
        // has_full_directory_index(4) = 26 + phi_bytes.
        let fdi_header_pos = (4 + 2 + 4 + 8 + 4 + phi_bytes + 4) as usize;
        let mut buf = main_prefix;
        if buf.len() >= fdi_header_pos + 16 {
            buf[fdi_header_pos..fdi_header_pos + 8]
                .copy_from_slice(&fdi_offset.to_le_bytes());
            buf[fdi_header_pos + 8..fdi_header_pos + 16]
                .copy_from_slice(&fdi_size.to_le_bytes());
        }
        // Pad to fdi_offset so the FDI seek lands inside the buffer
        // for kind-0 / kind-1 cases.
        if (fdi_offset as usize) > buf.len() && (fdi_offset as usize) < 8 * 1024 {
            buf.resize(fdi_offset as usize, 0);
        }
        buf.extend_from_slice(&fdi_tail);

        let total_len = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let _ = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            // `index_size` is the main-index length, not the whole
            // buffer — the parser uses it to bound the main-index
            // reads before seeking to the FDI.
            main_len.min(total_len),
            &[],
        );
    }

    /// Issue #68 structural round-trip oracle: build a well-formed
    /// v10+ archive via `V10Fixture` (random `mount`, `file_count`
    /// from FDI structure, FDI dirs/files), parse it, assert the
    /// recovered fields match the planted ones.
    ///
    /// Catches silent-corruption regressions a no-panic-only suite
    /// can't see: off-by-one in entry counts, mount-point
    /// truncation, FDI path mangling, dir-prefix strip drift, and
    /// `by_path` HashMap key drift (Oracle 4 — added per
    /// pr-test-analyzer round-1 review).
    ///
    /// The encoded_offset values are all negative (1-based,
    /// negated) so the entries route through `non_encoded_entries`
    /// rather than the encoded-entries-blob decoder — that lets us
    /// supply `PakEntryHeader::Inline` records via
    /// `write_v10_non_encoded_uncompressed` instead of having to
    /// synthesize a bit-packed encoded blob. The encoded-blob arm
    /// is covered by hand-written tests in `mod.rs`'s test module
    /// and is filed as a follow-up for proptest coverage.
    #[test]
    fn read_v10_plus_round_trip_recovers_planted_fields(
        mount in ascii_segment(),
        // Bounded: each (dir, file) costs ~63 bytes in the FDI body
        // + 53 bytes in the non-encoded-records section. Caps keep
        // the per-property-case work bounded. `0..4` outer allows
        // the empty-archive boundary case (zero dirs, zero entries
        // — issue #68 follow-up).
        dirs in proptest::collection::vec(
            (ascii_segment(), proptest::collection::vec(ascii_segment(), 1..4)),
            0..4,
        ),
        // Per-dir leading-slash variation. The parser explicitly
        // handles both "/Content/" (root, leading slash) and
        // "Content/" (subdir, no leading slash) per the empirical
        // evidence in issue #46. Randomize to exercise both arms
        // of the `strip_prefix('/').unwrap_or(&dir_name)` logic
        // in path_hash.rs's FDI walk.
        leading_slash_per_dir in proptest::collection::vec(any::<bool>(), 0..4),
    ) {
        use paksmith_core::testing::v10::write_v10_non_encoded_uncompressed;

        // Compute the natural file_count from the dirs spec.
        let total_files: u32 = dirs.iter()
            .map(|(_, files)| files.len() as u32)
            .sum();

        // Synthesize one non-encoded record per file (uncompressed,
        // unencrypted) at offsets that don't collide. The offsets
        // don't have to point at real bytes — `PakIndex::read_from`
        // doesn't open entries, just parses headers.
        let mut non_encoded_records = Vec::new();
        for i in 0..total_files {
            let offset = 0x1000_u64 + u64::from(i) * 0x100;
            write_v10_non_encoded_uncompressed(&mut non_encoded_records, offset, 16);
        }

        // Build the FDI spec with negative encoded_offset values
        // (1-based negated) so each file routes through
        // non_encoded_entries[i]. Issue #80: V10Fixture::fdi now
        // takes owned `Vec<(String, Vec<(String, i32)>)>`, so the
        // strategy output drops straight in — no parallel borrowed
        // view, no zip dance.
        let mut idx = 0_i32;
        let fdi: Vec<(String, Vec<(String, i32)>)> = dirs
            .iter()
            .enumerate()
            .map(|(d, (dir, files))| {
                // Apply per-dir leading-slash variation when we have
                // a strategy bool for this index; default to
                // no-leading-slash for the rest.
                let dir_name = if leading_slash_per_dir.get(d).copied().unwrap_or(false) {
                    format!("/{dir}/")
                } else {
                    format!("{dir}/")
                };
                let entries: Vec<(String, i32)> = files
                    .iter()
                    .map(|f| {
                        idx += 1;
                        (f.clone(), -idx) // negative = 1-based index into non_encoded
                    })
                    .collect();
                (dir_name, entries)
            })
            .collect();

        // `fdi.clone()` here so the post-parse assertion loop below
        // can still iterate the planted spec; mount cloned for the
        // same reason. Both clones are bounded by the strategy's
        // tight cap (≤ 4 dirs × ≤ 4 files × ≤ 16 ASCII chars per
        // segment ≈ a few hundred bytes per case).
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            mount: mount.clone(),
            file_count: total_files,
            non_encoded_records,
            non_encoded_count: total_files,
            fdi: fdi.clone(),
            ..V10Fixture::default()
        });

        let mut cursor = Cursor::new(buf);
        let index = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            main_size,
            &[],
        ).expect("well-formed V10Fixture must parse cleanly");

        // Oracle 1: mount round-trips byte-for-byte.
        prop_assert_eq!(index.mount_point(), mount.as_str());

        // Build the expected post-dedup path list. The strategy
        // generates random `(dir, [files])` tuples without uniqueness
        // constraints, so two `(dir, file)` pairs can collide on full
        // path (issue #88: `from_entries` last-wins-dedups them).
        // Apply the same dedup the production code does (reverse-walk
        // + skip-if-seen + reverse) so oracles 2/3 don't false-fail
        // on collision-shrunk inputs. Issue #88 follow-through.
        let expected_paths_full_walk: Vec<String> = fdi
            .iter()
            .flat_map(|(dir_name, files)| {
                let dir_prefix = dir_name
                    .strip_prefix('/')
                    .unwrap_or(dir_name)
                    .to_string();
                files
                    .iter()
                    .map(move |(f, _)| format!("{dir_prefix}{f}"))
            })
            .collect();
        let mut seen: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut deduped_rev: Vec<String> = Vec::new();
        for p in expected_paths_full_walk.iter().rev() {
            if seen.insert(p.clone()) {
                deduped_rev.push(p.clone());
            }
        }
        deduped_rev.reverse();
        let expected_deduped = deduped_rev;

        // Oracle 2: entries count matches the deduped path count
        // (NOT `total_files` — that's the pre-dedup wire-format
        // header value, which can exceed the survivor count when
        // the random strategy collides on full paths).
        prop_assert_eq!(index.entries().len(), expected_deduped.len());

        // Oracle 3: positional entries() match against the deduped
        // expectation. Pre-dedup positions are scrambled by the
        // last-wins fold; the deduped walk preserves original wire
        // order minus shadows, which is what `from_entries` produces.
        for (k, expected) in expected_deduped.iter().enumerate() {
            prop_assert_eq!(
                index.entries()[k].filename(),
                expected.as_str(),
                "entry {} mount={} expected={}",
                k, mount, expected
            );
        }

        // Oracle 4: find() lookup roundtrip — exercises the by_path
        // HashMap built by from_entries(). Walk the planted FDI
        // (NOT the deduped list) so collisions still exercise the
        // last-wins resolution path: every planted full_path must
        // resolve to ITSELF (find returns the survivor with that
        // filename, which is the same path string by construction).
        // Joins use `strip_prefix('/').unwrap_or(&dir_name)` to mirror
        // path_hash.rs's leading-slash handling — issue #46 empirical
        // doc.
        for (dir_name, files) in &fdi {
            let dir_prefix = dir_name.strip_prefix('/').unwrap_or(dir_name);
            for (file_name, _offset) in files {
                let expected = format!("{dir_prefix}{file_name}");
                prop_assert_eq!(
                    index.find(&expected).map(PakIndexEntry::filename),
                    Some(expected.as_str()),
                    "find() lookup mount={} expected={}",
                    mount, expected
                );
            }
        }
    }

    /// Issue #79 sister property: round-trip the v10+ ENCODED-BLOB
    /// decoder path, complementing
    /// `read_v10_plus_round_trip_recovers_planted_fields` (which
    /// only routes through the non-encoded fallback).
    ///
    /// Builds a single bit-packed encoded entry with strategy-
    /// chosen `(offset, uncompressed, block_count, block_size)`
    /// satisfying the wire-format invariants the parser checks
    /// (issues #58/#59):
    /// - `compressed == sum(per_block_sizes)` (issue #58)
    /// - `uncompressed <= block_count * block_size` when
    ///   `compression_method != None` (issue #58 sibling)
    /// - `block_count > 0 || compression_method == None`
    ///   (issue #59)
    ///
    /// Routes through `path_hash.rs`'s positive-`encoded_offset`
    /// arm by planting an FDI entry that points at offset 0 of the
    /// encoded blob. The single-block encrypted case is excluded
    /// (would need explicit per_block_sizes for the multi-block
    /// path); the property covers (a) single-block-uncompressed
    /// trivial path, (b) single-block-compressed trivial path,
    /// (c) multi-block compressed path.
    #[test]
    fn read_v10_plus_encoded_blob_round_trip(
        // Bias offset to mostly fit in u32 (the common UE case)
        // with occasional u64 sweep to exercise the bit-31-cleared
        // varint width.
        offset_kind in 0u8..2,
        offset_random in 0u64..u64::MAX,
        // 1..=5 blocks keeps per_block_sizes bounded; trips both
        // the trivial-single-block branch (block_count==1) and
        // the multi-block cursor walk (block_count>=2).
        block_count in 1u32..=5,
        // Mostly the canonical 4 KiB chunking; occasional larger
        // sizes via the 0x3f sentinel-and-extra-u32 encoding path.
        block_size_kind in 0u8..3,
        // Per-block compressed sizes capped at 2048 (1/2 the
        // smallest block_size of 0x1000 = 4096) so `compressed`
        // is always strictly less than `max_uncompressed`. Without
        // this gap, an unlucky combination (per_block_size ==
        // block_size, uncompressed_kind == 0 picks max_uncompressed)
        // would make `compressed == uncompressed`, hiding a
        // hypothetical decoder regression that swapped the
        // compressed/uncompressed varint reads — pr-test-analyzer
        // round-1 finding 1.
        per_block_size in 1u32..=2048,
        // uncompressed_kind dispatches across the cap-bound
        // (uncompressed == block_count * block_size, max valid),
        // a typical fraction, and 1 byte (minimum).
        uncompressed_kind in 0u8..3,
        // Encrypted multi-block path exercises the AES-16-aligned
        // cursor advance branch in `read_encoded` (encrypted
        // entries pad each block to 16-byte alignment on disk,
        // so the cursor walk uses (size + 15) & !15 instead of
        // raw size). Round-1 finding 2 noted this branch was only
        // covered by one hand-written unit test; randomizing
        // here exercises the alignment math across the full range
        // of per-block sizes.
        encrypted in any::<bool>(),
    ) {
        // Off-by-one fix: `% u32::MAX` excludes u32::MAX itself
        // from the bias bucket. Use `% (u32::MAX + 1)` (computed
        // via the wider u64) so the boundary value is reachable.
        let offset: u64 = match offset_kind {
            0 => offset_random % (u64::from(u32::MAX) + 1),
            _ => offset_random,
        };
        let block_size: u32 = match block_size_kind {
            0 => 0x1000,                // canonical 4 KiB, fits 5-bit field
            1 => 0x3e * 0x800,          // largest non-sentinel 5-bit value
            _ => 0x1234,                // forces sentinel + extra u32 (not a multiple of 0x800)
        };
        // All blocks the same size (simplest valid). Sum
        // = block_count * per_block_size, which is `compressed`.
        let per_block_sizes: Vec<u32> = vec![per_block_size; block_count as usize];
        let compressed: u64 = u64::from(per_block_size) * u64::from(block_count);
        // uncompressed bounded by block_count * block_size per
        // issue #58 sibling cap.
        let max_uncompressed: u64 = u64::from(block_count) * u64::from(block_size);
        let uncompressed: u64 = match uncompressed_kind {
            0 => max_uncompressed,
            1 => max_uncompressed / 2 + 1,
            _ => 1,
        };
        // Slot 1 = Zlib. Always compressed (slot != 0) so the
        // `compressed` varint is emitted and the per-block-sizes
        // path runs for block_count > 1 OR encrypted.
        let compression_methods = vec![Some(CompressionMethod::Zlib)];
        let encoded = encode_entry_bytes(EncodeArgs {
            offset,
            uncompressed,
            compressed,
            compression_slot_1based: 1,
            encrypted,
            block_count,
            block_size,
            per_block_sizes: &per_block_sizes,
        });

        // Wrap in a V10Fixture with one FDI entry pointing at
        // offset 0 of the encoded blob (positive encoded_offset
        // routes through the encoded-blob decoder, NOT the
        // non-encoded fallback the existing round-trip property
        // exercises).
        let (buf, main_size) = build_v10_buffer(V10Fixture {
            mount: "/".into(),
            file_count: 1,
            encoded_entries: encoded,
            fdi: vec![("Content/".into(), vec![("entry.uasset".into(), 0)])],
            ..V10Fixture::default()
        });
        let mut cursor = Cursor::new(buf);
        let index = PakIndex::read_from(
            &mut cursor,
            PakVersion::PathHashIndex,
            0,
            main_size,
            &compression_methods,
        )
        .expect("well-formed encoded entry must parse cleanly");

        // Single entry should appear at the FDI-derived path.
        prop_assert_eq!(index.entries().len(), 1);
        let recovered = index.entries()[0].header();

        // Oracles for the encoded-blob decoder round-trip:
        prop_assert_eq!(recovered.offset(), offset, "offset round-trip");
        prop_assert_eq!(
            recovered.uncompressed_size(),
            uncompressed,
            "uncompressed_size round-trip"
        );
        prop_assert_eq!(
            recovered.compressed_size(),
            compressed,
            "compressed_size round-trip"
        );
        prop_assert_eq!(
            recovered.compression_method(),
            &CompressionMethod::Zlib,
            "compression_method should resolve to Zlib via slot=1 + table[0]=Some(Zlib)"
        );
        prop_assert_eq!(
            recovered.compression_blocks().len(),
            block_count as usize,
            "compression_blocks count"
        );
        prop_assert_eq!(
            recovered.compression_block_size(),
            block_size,
            "compression_block_size round-trip (covers both 5-bit field and 0x3f sentinel)"
        );
        prop_assert_eq!(
            recovered.is_encrypted(),
            encrypted,
            "is_encrypted round-trip"
        );
        // Encoded entries omit SHA1 on the wire.
        prop_assert_eq!(
            recovered.sha1(),
            None,
            "encoded entries omit SHA1"
        );
    }
}
