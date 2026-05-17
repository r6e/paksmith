#![allow(missing_docs)]

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::{
    FOOTER_SIZE_LEGACY, FOOTER_SIZE_V8B_PLUS, FOOTER_SIZE_V9, PAK_MAGIC, PakVersion,
};
use paksmith_core::container::{ContainerFormat, ContainerReader, EntryMetadata};
// Issue #95: error variants used by typed `matches!` assertions.
// Hoisted to file scope so individual tests don't trip
// `clippy::items_after_statements` on per-test `use` statements
// added below their `let err = ...` lines.
use paksmith_core::container::pak::index::CompressionMethod;
use paksmith_core::error::{
    BlockBoundsKind, BoundsUnit, DecompressionFault, IndexParseFault, OffsetPastFileSizeKind,
    OverflowSite, WireField,
};
// Issue #140: shared v3+ wire-format synthesizers, lifted out of
// the per-file copies that used to live below this import block.
use paksmith_core::testing::wire::{write_fstring, write_pak_entry};
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::num::NonZeroU32;

/// Read `index_offset` and `index_size` from a v6 legacy footer (44
/// bytes). Avoids hard-coded offset constants that go stale whenever
/// the fixture's entry sizes change. Asserts the magic so this won't
/// silently misread a v7+ footer (which is 61 bytes and shifts every
/// field) — it's a test helper, not a generic footer parser.
fn read_legacy_v6_index_bounds(file_bytes: &[u8]) -> (usize, usize) {
    let footer_size = usize::try_from(FOOTER_SIZE_LEGACY).unwrap();
    let footer_start = file_bytes.len() - footer_size;
    let magic = u32::from_le_bytes(
        file_bytes[footer_start..footer_start + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        magic, PAK_MAGIC,
        "legacy v6 footer magic must match (helper rejects v7+ footers)"
    );
    let version = u32::from_le_bytes(
        file_bytes[footer_start + 4..footer_start + 8]
            .try_into()
            .unwrap(),
    );
    assert_eq!(version, 6, "helper only supports v6; got v{version}");
    let offset = u64::from_le_bytes(
        file_bytes[footer_start + 8..footer_start + 16]
            .try_into()
            .unwrap(),
    ) as usize;
    let size = u64::from_le_bytes(
        file_bytes[footer_start + 16..footer_start + 24]
            .try_into()
            .unwrap(),
    ) as usize;
    (offset, size)
}

/// File offset of byte `byte_in_payload` within the payload of `entry_path`
/// in the fixture, derived from the parsed index. Replaces hand-rolled
/// arithmetic that bit-rots whenever the in-data FPakEntry header layout
/// changes (e.g., the v3+ "always-present `compression_block_size`" fix
/// that bumped uncompressed in-data headers from 49 to 53 bytes).
fn payload_byte_offset(fixture_name: &str, entry_path: &str, byte_in_payload: u64) -> usize {
    let reader = PakReader::open(fixture_path(fixture_name))
        .unwrap_or_else(|e| panic!("opening fixture `{fixture_name}`: {e}"));
    let entry = reader
        .index_entry(entry_path)
        .unwrap_or_else(|| panic!("no entry `{entry_path}` in fixture `{fixture_name}`"));
    let abs = entry.header().offset() + entry.header().wire_size() + byte_in_payload;
    usize::try_from(abs).unwrap_or_else(|_| {
        panic!("payload offset {abs} for `{entry_path}` in `{fixture_name}` exceeds usize")
    })
}

/// SHA1 of `bytes` as 40 hex chars; used by tests that strengthen
/// "different from expected" assertions into "equals an independent
/// digest" assertions.
fn independent_sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(bytes);
    let digest: [u8; 20] = h.finalize().into();
    digest.iter().fold(String::with_capacity(40), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

/// Build a synthetic v7 (`EncryptionKeyGuid`) pak with one uncompressed entry,
/// not actually encrypted, written to a tempfile. Exercises the end-to-end
/// v7+ dispatch path through `PakReader::open` that the v6 fixture skips.
fn build_v7_tempfile(payload: &[u8]) -> tempfile::NamedTempFile {
    let sha1 = [0u8; 20];
    let payload_size = payload.len() as u64;

    // In-data record: FPakEntry header + payload bytes. UE writes the offset
    // field as 0 (self-reference) in the in-data copy.
    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        payload_size,
        payload_size,
        0,
        &sha1,
        &[],
        0,
        false,
    );
    data_section.extend_from_slice(payload);

    // Index: mount point + entry_count + (filename + FPakEntry per entry).
    // The index FPakEntry's offset field is the actual file offset (0 here).
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/v7.uasset");
    write_pak_entry(
        &mut index_section,
        0,
        payload_size,
        payload_size,
        0,
        &sha1,
        &[],
        0,
        false,
    );

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    let mut pak = data_section;
    pak.extend_from_slice(&index_section);

    // v7+ footer (real UE wire layout: uuid + encrypted come BEFORE
    // magic, NOT after the hash).
    pak.extend_from_slice(&[0u8; 16]); // encryption GUID
    pak.push(0); // not encrypted
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(7).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]); // index hash

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();
    tmp
}

#[test]
fn open_minimal_v6_pak() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    assert_eq!(reader.version(), PakVersion::DeleteRecords);
    assert_eq!(reader.format(), ContainerFormat::Pak);
    assert_eq!(reader.mount_point(), "../../../");
}

#[test]
fn index_entry_returns_some_for_known_path_and_none_for_unknown() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let known = reader.index_entry("Content/Textures/hero.uasset");
    assert!(known.is_some(), "known entry must resolve");
    assert_eq!(
        known.unwrap().filename(),
        "Content/Textures/hero.uasset",
        "returned entry must match the queried path"
    );
    assert!(
        reader
            .index_entry("Content/does/not/exist.uasset")
            .is_none(),
        "unknown path must return None, not panic or empty entry"
    );
}

#[test]
fn list_entries_minimal_v6() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let entries: Vec<_> = reader.entries().collect();

    assert_eq!(entries.len(), 5);
    let paths: Vec<&str> = entries.iter().map(EntryMetadata::path).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
    assert!(paths.contains(&"Content/Text/lorem.txt"));
    assert!(paths.contains(&"Content/Text/lorem_multi.txt"));
}

#[test]
fn entry_metadata_correct_for_all_entries() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let entries: Vec<_> = reader.entries().collect();

    let by_path = |needle: &str| entries.iter().find(|e| e.path().contains(needle)).unwrap();

    let hero = by_path("hero");
    assert_eq!(hero.uncompressed_size(), 22); // b"HERO_TEXTURE_DATA_HERE".len()
    assert_eq!(hero.compressed_size(), 22);
    assert!(!hero.is_compressed());
    assert!(!hero.is_encrypted());

    let level = by_path("level01");
    assert_eq!(level.uncompressed_size(), 16);
    assert_eq!(level.compressed_size(), 16);
    assert!(!level.is_compressed());

    let bgm = by_path("bgm");
    assert_eq!(bgm.uncompressed_size(), 26);
    assert_eq!(bgm.compressed_size(), 26);
    assert!(!bgm.is_compressed());

    let lorem = by_path("lorem.txt");
    assert_eq!(lorem.uncompressed_size(), 27 * 64);
    assert!(lorem.is_compressed());
    assert!(lorem.compressed_size() < lorem.uncompressed_size());
    assert!(!lorem.is_encrypted());

    let lorem_multi = by_path("lorem_multi");
    assert_eq!(lorem_multi.uncompressed_size(), 27 * 64);
    assert!(lorem_multi.is_compressed());
    // Multi-block has worse compression than single-block (zlib overhead per
    // block) but is still smaller than uncompressed.
    assert!(lorem_multi.compressed_size() < lorem_multi.uncompressed_size());
    assert!(lorem_multi.compressed_size() > lorem.compressed_size());
}

#[test]
fn read_entry_data() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let data = reader.read_entry("Content/Textures/hero.uasset").unwrap();
    assert_eq!(data, b"HERO_TEXTURE_DATA_HERE");
}

#[test]
fn read_entry_twice_in_a_row() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let first = reader.read_entry("Content/Maps/level01.umap").unwrap();
    let second = reader.read_entry("Content/Maps/level01.umap").unwrap();
    assert_eq!(first, second);
    assert_eq!(first, b"LEVEL01_MAP_DATA");
}

/// Pin the streaming primitive's contract directly (not just indirectly via
/// the `read_entry` wrapper): the returned u64 equals the bytes actually
/// written to the writer AND equals the entry's `uncompressed_size`.
/// Zero-byte entry must round-trip through `read_entry_to` returning
/// `Ok(0)` with the writer untouched. The `ContainerReader::read_entry_to`
/// trait docstring promises "the number of bytes written" without a
/// non-zero precondition; with the existing `written != size`
/// short-write check (`pak/mod.rs`), an entry that legitimately has
/// `uncompressed_size = 0` and produces 0 bytes must satisfy
/// `written == size == 0`. A future refactor that swaps `io::copy` for
/// a manual loop with a "skip if size==0" early-return WITHOUT
/// returning `Ok(0)` would not be caught by the existing >0-byte
/// tests above. Issue #31.
#[test]
fn read_entry_to_zero_byte_entry_returns_ok_zero() {
    // Build a synthetic v6 pak with a single entry whose payload is
    // empty. The build helper uses `payload.len() as u64` for both
    // compressed and uncompressed sizes, so this constructs the
    // legitimate "claims 0 bytes, contains 0 bytes" shape.
    let tmp = build_single_entry_pak(6, 0, [0; 20], &[], 0, b"", None);
    let reader = PakReader::open(tmp.path()).unwrap();

    // Use a fixed-size sentinel buffer (`&mut [u8; N]` impls `Write`
    // by copying via the slice's cursor — see std::io::Write for
    // &mut [u8]). Pre-fill with 0xCC so that a wrongly-not-skipped
    // write surfaces as a 0xCC byte being overwritten. Unlike a
    // `Vec<u8>` approach where `Vec::clear` immediately makes the
    // sentinel bytes unobservable via len(), the slice keeps every
    // byte addressable for the post-call assertion.
    let mut sentinel = [0xCCu8; 16];
    let mut writer: &mut [u8] = &mut sentinel;
    let written = reader
        .read_entry_to("Content/x.uasset", &mut writer)
        .unwrap_or_else(|e| panic!("read_entry_to on zero-byte entry: {e}"));
    assert_eq!(written, 0, "zero-byte entry must return Ok(0)");
    // After a zero-byte write, every byte of the sentinel must remain
    // at its pre-fill value. A wrongly-not-skipped write (e.g., a
    // future refactor that always copies at least one byte) would
    // overwrite sentinel[0] and surface here.
    assert_eq!(
        sentinel, [0xCCu8; 16],
        "writer must receive zero bytes — sentinel must be untouched"
    );
}

/// Catches a future refactor that drops the short-write check or returns
/// the wrong counter.
#[test]
fn read_entry_to_returns_exact_bytes_written() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    // Cover both branches: uncompressed (hero) and zlib (lorem).
    for (path, expected) in [
        (
            "Content/Textures/hero.uasset",
            &b"HERO_TEXTURE_DATA_HERE"[..],
        ),
        // lorem.txt's uncompressed payload is 27*64 = 1728 bytes — too long
        // to inline; just verify the size relationship below.
        ("Content/Text/lorem.txt", &b""[..]),
    ] {
        let mut buf: Vec<u8> = Vec::new();
        let written = reader
            .read_entry_to(path, &mut buf)
            .unwrap_or_else(|e| panic!("read_entry_to({path}): {e}"));
        assert_eq!(
            written as usize,
            buf.len(),
            "{path}: returned u64 must equal bytes written to the writer"
        );
        if !expected.is_empty() {
            assert_eq!(buf, expected, "{path}: bytes match expected payload");
        }
        // Cross-check against the index entry's uncompressed_size.
        let entry = reader.index_entry(path).unwrap();
        assert_eq!(
            written,
            entry.header().uncompressed_size(),
            "{path}: returned u64 must equal entry.uncompressed_size()"
        );
    }
}

/// A `Write` impl that fails after writing N bytes, used to exercise
/// `read_entry_to`'s error propagation path.
struct FailAfterN {
    written: usize,
    fail_after: usize,
}

impl std::io::Write for FailAfterN {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.fail_after.saturating_sub(self.written);
        if remaining == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "synthetic writer failure after N bytes",
            ));
        }
        let take = buf.len().min(remaining);
        self.written += take;
        Ok(take)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// End-to-end partner for the unit-level
/// `duplicate_filename_resolves_to_last_entry` in `index/mod.rs`'s
/// `tests` submodule. The unit test
/// proves `find()` returns the last index; this test proves `read_entry`
/// actually serves the LAST entry's bytes — would fail if a future
/// refactor swapped the find() to a first-wins linear scan, even if the
/// HashMap-level test still passed.
/// Hash `bytes` with SHA1, returning the 20-byte digest. Local helper
/// for the duplicate-path integration test below.
fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().into()
}

#[test]
fn read_entry_returns_last_entry_bytes_on_duplicate_path() {
    // Build a pak with two entries at the same path but different
    // payloads. Hand-roll the bytes (rather than using the single-entry
    // helper) so both entries are well-formed: each has its own in-data
    // FPakEntry record with the correct SHA1 of its own payload.
    let path_in_archive = "Content/dup.uasset";
    let payload_first = b"FIRST_PAYLOAD";
    let payload_last = b"LAST_PAYLOAD_WINS";

    let sha_first = sha1_digest(payload_first);
    let sha_last = sha1_digest(payload_last);

    // Data section: two records, each [in-data FPakEntry header | payload].
    let mut data = Vec::new();
    write_pak_entry(
        &mut data,
        0,
        payload_first.len() as u64,
        payload_first.len() as u64,
        0,
        &sha_first,
        &[],
        0,
        false,
    );
    let payload_first_offset = data.len();
    let _ = payload_first_offset;
    data.extend_from_slice(payload_first);
    let last_record_offset = data.len() as u64;
    write_pak_entry(
        &mut data,
        0,
        payload_last.len() as u64,
        payload_last.len() as u64,
        0,
        &sha_last,
        &[],
        0,
        false,
    );
    data.extend_from_slice(payload_last);

    // Index: mount + entry_count + (filename + FPakEntry) per entry. Both
    // index entries share the same filename; their `offset` fields point
    // at their respective in-data records.
    let mut index = Vec::new();
    write_fstring(&mut index, "../../../");
    index.write_u32::<LittleEndian>(2).unwrap();
    write_fstring(&mut index, path_in_archive);
    write_pak_entry(
        &mut index,
        0, // first record sits at file offset 0
        payload_first.len() as u64,
        payload_first.len() as u64,
        0,
        &sha_first,
        &[],
        0,
        false,
    );
    write_fstring(&mut index, path_in_archive);
    write_pak_entry(
        &mut index,
        last_record_offset,
        payload_last.len() as u64,
        payload_last.len() as u64,
        0,
        &sha_last,
        &[],
        0,
        false,
    );

    let index_offset = data.len() as u64;
    let index_size = index.len() as u64;

    let mut pak = data;
    pak.extend_from_slice(&index);
    // v6 legacy footer.
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]); // index hash zeroed (no integrity claim)

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let bytes = reader.read_entry(path_in_archive).unwrap();
    assert_eq!(
        bytes, payload_last,
        "duplicate-path read_entry must serve the LAST entry's bytes \
         (locks the last-wins semantic end-to-end, not just at the index level)"
    );
    // Issue #88 post-fix: `entries()` yields the deduped survivors,
    // matching `find()`. Pre-fix this assertion was `== 2` (entries
    // retained every duplicate while find returned only the last
    // — an internal-consistency hole).
    let entries: Vec<_> = reader.entries().collect();
    assert_eq!(
        entries.len(),
        1,
        "post-#88 dedup: shadowed entry dropped to match find()'s last-wins shape",
    );
    assert_eq!(
        entries[0].path(),
        path_in_archive,
        "the survivor must be the duplicate path (last occurrence)",
    );
}

/// A failing writer must surface as `PaksmithError::Io`, not be silently
/// swallowed. Exercises the trait's contract that streaming downstream
/// errors propagate (e.g., for stdout pipes that close mid-extraction).
#[test]
fn read_entry_to_propagates_writer_failure() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    // Use the zlib entry — the streaming write happens block-by-block
    // through the per-block buffer; this tests the path most likely to
    // mask a writer error.
    let mut writer = FailAfterN {
        written: 0,
        fail_after: 8, // fail well before lorem's 1728-byte payload finishes
    };
    let err = reader
        .read_entry_to("Content/Text/lorem.txt", &mut writer)
        .unwrap_err();
    match err {
        paksmith_core::PaksmithError::Io(io_err) => {
            assert_eq!(
                io_err.kind(),
                std::io::ErrorKind::BrokenPipe,
                "writer's BrokenPipe must surface as the wrapped Io kind"
            );
        }
        other => panic!("expected Io, got {other:?}"),
    }
}

/// Verifies the zlib decompression path end-to-end: the lorem entry is stored
/// as a single zlib-compressed block whose offsets are relative to the entry
/// record (v5+ convention).
#[test]
fn read_zlib_compressed_entry() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let data = reader.read_entry("Content/Text/lorem.txt").unwrap();
    let expected: Vec<u8> = b"lorem ipsum dolor sit amet ".repeat(64);
    assert_eq!(data, expected);
}

/// Multi-block zlib: the lorem_multi entry has 7 independent zlib blocks
/// (256-byte uncompressed chunks). Exercises the cross-block invariants in
/// `stream_zlib_to` — the cumulative output check, the non-final-block size
/// check, and the per-block seek logic.
#[test]
fn read_zlib_multiblock_entry() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let data = reader.read_entry("Content/Text/lorem_multi.txt").unwrap();
    let expected: Vec<u8> = b"lorem ipsum dolor sit amet ".repeat(64);
    assert_eq!(data, expected);
}

/// Corrupting the in-data FPakEntry's compressed_size field (without touching
/// the index) must surface as a typed `InvalidIndex` error rather than silent
/// data corruption.
#[test]
fn read_entry_rejects_in_data_index_mismatch() {
    use std::fs;

    let original = fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // The hero entry is the first one in the data section. Its in-data
    // FPakEntry starts at offset 0; the compressed_size field is bytes 8..16.
    // Flip the high byte to a clearly-wrong value.
    corrupted[8] = 0xFF;
    corrupted[15] = 0xFF;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader
        .read_entry("Content/Textures/hero.uasset")
        .unwrap_err();
    // Issue #95: typed match on `FieldMismatch { field:
    // "compressed_size" }`. Pre-#48 substring ("in-data header
    // mismatch" + "compressed_size") would silently rot if the
    // wording changed.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::FieldMismatch {
                    field: WireField::CompressedSize,
                    ..
                },
            }
        ),
        "expected FieldMismatch {{ field: \"compressed_size\" }}; got {err:?}"
    );
}

// --- SHA1 verification (#9) ---------------------------------------------

use paksmith_core::container::pak::VerifyOutcome;

#[test]
fn verify_index_succeeds_on_valid_fixture() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    assert_eq!(reader.verify_index().unwrap(), VerifyOutcome::Verified);
}

#[test]
fn verify_entry_uncompressed_succeeds() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    assert_eq!(
        reader.verify_entry("Content/Textures/hero.uasset").unwrap(),
        VerifyOutcome::Verified
    );
}

#[test]
fn verify_entry_zlib_single_block_succeeds() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    assert_eq!(
        reader.verify_entry("Content/Text/lorem.txt").unwrap(),
        VerifyOutcome::Verified
    );
}

#[test]
fn verify_entry_zlib_multi_block_succeeds() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    assert_eq!(
        reader.verify_entry("Content/Text/lorem_multi.txt").unwrap(),
        VerifyOutcome::Verified
    );
}

#[test]
fn verify_succeeds_on_valid_fixture_with_full_counts() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let stats = reader.verify().unwrap();
    // VerifyStats is #[non_exhaustive] (downstream crates can't construct
    // it via struct literal). Assert field-by-field instead — this also
    // means future fields default to 0/false and don't break the test.
    assert!(stats.index_verified(), "index should have been verified");
    assert!(!stats.index_skipped_no_hash());
    assert_eq!(stats.entries_verified(), 5);
    assert_eq!(stats.entries_skipped_no_hash(), 0);
    assert_eq!(stats.entries_skipped_encrypted(), 0);
    // v3-v9 archives have no FDI/PHI regions (flat layout); both
    // must surface as `NotPresent`, NOT silently as `Verified`.
    // Issue #86.
    assert_eq!(
        stats.fdi(),
        paksmith_core::container::pak::RegionVerifyState::NotPresent
    );
    assert_eq!(
        stats.phi(),
        paksmith_core::container::pak::RegionVerifyState::NotPresent
    );
    assert!(stats.is_fully_verified());
}

/// Encrypted entries return `Ok(SkippedEncrypted)` from verify_entry —
/// the policy is "we have no key, so we can't verify; report the skip
/// rather than misclassifying it as tampered."
#[test]
fn verify_entry_returns_skipped_for_encrypted_entry() {
    let payload = b"ciphertext-stand-in";
    let tmp = build_single_entry_pak_with_flags(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        None,
        true, // encrypted
        None,
    );
    let reader = PakReader::open(tmp.path()).unwrap();
    assert_eq!(
        reader.verify_entry("Content/x.uasset").unwrap(),
        VerifyOutcome::SkippedEncrypted
    );
}

/// Archive-wide integrity policy: when the index hash IS recorded but a
/// per-entry hash slot was zeroed (attacker signature — UE writers either
/// hash everything or nothing), `verify_entry` must surface this as
/// HashMismatch rather than silently SkippedNoHash. This closes the
/// silent bypass path that would let an attacker strip a single entry's
/// integrity tag without detection.
#[test]
fn verify_entry_rejects_mixed_zero_entry_hash_when_index_has_hash() {
    // The fixture's index has a real hash (per the generator running
    // sha1_of(&index_section)). Open it, then bytes-corrupt one entry's
    // SHA1 field in the index to all zeros. matches_payload would fire
    // for in-data/index disagreement, so we also need to zero the
    // corresponding in-data SHA1 — but doing that defeats the test's
    // intent. Build a single-entry pak from scratch with a real index
    // hash and a zero entry hash to isolate the policy.
    use sha1::{Digest, Sha1};

    // Hand-build a minimal v6 pak: one uncompressed entry with sha1 = [0; 20]
    // for both index and in-data records, BUT with a real (non-zero) index hash
    // computed over the index section.
    let payload = b"unhashed-but-archive-claims-integrity";
    let payload_size = payload.len() as u64;
    let entry_sha1 = [0u8; 20]; // attacker-zeroed

    // In-data record + payload.
    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        payload_size,
        payload_size,
        0,
        &entry_sha1,
        &[],
        0,
        false,
    );
    data_section.extend_from_slice(payload);

    // Index.
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/x.uasset");
    write_pak_entry(
        &mut index_section,
        0,
        payload_size,
        payload_size,
        0,
        &entry_sha1,
        &[],
        0,
        false,
    );

    // REAL hash of the index — this is the key part: archive claims integrity.
    let mut h = Sha1::new();
    h.update(&index_section);
    let index_hash: [u8; 20] = h.finalize().into();

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;
    let mut pak = data_section;
    pak.extend_from_slice(&index_section);
    // v6 legacy footer.
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&index_hash);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    // Index hash matches.
    assert_eq!(reader.verify_index().unwrap(), VerifyOutcome::Verified);
    // But the entry's hash is zeroed → tampering signal via the
    // dedicated IntegrityStripped variant (NOT HashMismatch — there's
    // no digest to compare against, the tag was removed).
    let err = reader.verify_entry("Content/x.uasset").unwrap_err();
    match err {
        paksmith_core::PaksmithError::IntegrityStripped { target } => match target {
            paksmith_core::error::HashTarget::Entry { path } => {
                assert_eq!(path, "Content/x.uasset");
            }
            other => panic!("expected Entry target, got {other:?}"),
        },
        other => panic!("expected IntegrityStripped, got {other:?}"),
    }
}

/// Encryption takes priority over the zero-hash-with-archive-integrity
/// check: an entry that's BOTH encrypted AND has a zero hash slot in an
/// integrity-claiming archive must report SkippedEncrypted, not
/// IntegrityStripped. Pins the documented priority so a future refactor
/// reordering the checks fails loudly.
#[test]
fn verify_entry_encrypted_takes_priority_over_integrity_strip_check() {
    use sha1::{Digest, Sha1};

    let payload = b"ciphertext-stand-in";
    let payload_size = payload.len() as u64;
    let entry_sha1 = [0u8; 20];

    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        payload_size,
        payload_size,
        0,
        &entry_sha1,
        &[],
        0,
        true, // encrypted
    );
    data_section.extend_from_slice(payload);

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/x.uasset");
    write_pak_entry(
        &mut index_section,
        0,
        payload_size,
        payload_size,
        0,
        &entry_sha1,
        &[],
        0,
        true,
    );

    // Real index hash — archive claims integrity.
    let mut h = Sha1::new();
    h.update(&index_section);
    let index_hash: [u8; 20] = h.finalize().into();

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;
    let mut pak = data_section;
    pak.extend_from_slice(&index_section);
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&index_hash);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    // Encryption check fires first; the integrity-strip check never runs.
    assert_eq!(
        reader.verify_entry("Content/x.uasset").unwrap(),
        VerifyOutcome::SkippedEncrypted
    );
}

/// Entries whose stored SHA1 is the all-zero sentinel return
/// `Ok(SkippedNoHash)` rather than failing — UE writers leave this slot
/// zero-filled when integrity hashing is not enabled at write time. Only
/// applies when the index hash is ALSO zero (whole-archive policy); the
/// mixed case is tested separately above.
#[test]
fn verify_entry_returns_skipped_for_zero_hash() {
    let payload = b"unhashed";
    let tmp = build_single_entry_pak(6, 0, [0u8; 20], &[], 0, payload, None);
    let reader = PakReader::open(tmp.path()).unwrap();
    assert_eq!(
        reader.verify_entry("Content/x.uasset").unwrap(),
        VerifyOutcome::SkippedNoHash
    );
}

/// verify_index returns `Ok(SkippedNoHash)` when the footer's stored
/// index hash is zeroed.
#[test]
fn verify_index_returns_skipped_for_zero_hash() {
    // build_single_entry_pak writes a v6 footer with an all-zero index_hash
    // (the footer hash field is also zero-filled in the helper). So the
    // baseline fixture from this helper has a no-hash index.
    let tmp = build_single_entry_pak(6, 0, [0u8; 20], &[], 0, b"x", None);
    let reader = PakReader::open(tmp.path()).unwrap();
    assert_eq!(reader.verify_index().unwrap(), VerifyOutcome::SkippedNoHash);
}

/// verify_entry on Gzip / Oodle / Unknown compression methods returns
/// `Decompression` rather than silently hashing arbitrary on-disk bytes.
///
/// Issue #112: post-promotion to `DecompressionFault` typed sub-enum,
/// the test now matches `UnsupportedMethod { method }` structurally
/// rather than substring-grepping the Display string. The original
/// design-note (deferred to #112) is removed since #112 is closed.
#[test]
fn verify_entry_rejects_unsupported_compression_methods() {
    for (method_id, expected_method) in [
        (2u32, CompressionMethod::Gzip),
        (4u32, CompressionMethod::Oodle),
        (
            99u32,
            CompressionMethod::Unknown(NonZeroU32::new(99).unwrap()),
        ),
    ] {
        // Use the same single-block layout as the read_entry_rejects_*
        // test, but exercise verify_entry instead of read_entry.
        let payload = b"x";
        let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4;
        let blocks = [(
            header_size as u64,
            header_size as u64 + payload.len() as u64,
        )];
        let tmp = build_single_entry_pak(6, method_id, [0xAA; 20], &blocks, 1, payload, Some(1));
        let reader = PakReader::open(tmp.path()).unwrap();
        let err = reader.verify_entry("Content/x.uasset").unwrap_err();
        match err {
            paksmith_core::PaksmithError::Decompression {
                fault: DecompressionFault::UnsupportedMethod { method },
                ..
            } => {
                assert_eq!(
                    method, expected_method,
                    "method mismatch for method_id={method_id}"
                );
            }
            other => panic!(
                "expected Decompression{{UnsupportedMethod {{ method: {expected_method:?} }}}} \
                 for method_id={method_id}, got {other:?}"
            ),
        }
    }
}

/// Corrupting a byte mid-compressed-bytes of a zlib entry must surface
/// as HashMismatch — exercises the more complex zlib block-by-block
/// hashing path.
#[test]
fn verify_entry_zlib_fails_when_compressed_byte_corrupted() {
    use std::fs;
    let original = fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // Flip a byte 10 bytes into lorem's compressed payload. Offset derived
    // from the parsed index so the test stays correct if entry sequence,
    // sizes, or in-data header layout change.
    let target = payload_byte_offset("minimal_v6.pak", "Content/Text/lorem.txt", 10);
    corrupted[target] ^= 0xFF;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_entry("Content/Text/lorem.txt").unwrap_err();
    match err {
        paksmith_core::PaksmithError::HashMismatch { target, .. } => match target {
            paksmith_core::error::HashTarget::Entry { path } => {
                assert_eq!(path, "Content/Text/lorem.txt");
            }
            other => panic!("expected Entry target, got {other:?}"),
        },
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

/// verify() on an archive with an encrypted entry returns Ok and
/// reports the skip in VerifyStats. This pins the policy that the
/// continue arm in verify() exists for: don't fail-fast on encrypted
/// entries, but DO surface them so callers know they weren't checked.
#[test]
fn verify_reports_encrypted_skip_in_stats() {
    let payload = b"ciphertext";
    let tmp = build_single_entry_pak_with_flags(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        None,
        true, // encrypted
        None,
    );
    let reader = PakReader::open(tmp.path()).unwrap();
    let stats = reader.verify().unwrap();
    assert_eq!(stats.entries_verified(), 0);
    assert_eq!(stats.entries_skipped_encrypted(), 1);
    assert_eq!(stats.entries_skipped_no_hash(), 0);
    // Index hash slot in this synthetic pak is also zero, so index is
    // also skipped — that's expected behavior, not a bug.
    assert!(stats.index_skipped_no_hash());
    // is_fully_verified must report false: nothing was actually hashed,
    // and either skip class alone disqualifies the archive.
    assert!(!stats.is_fully_verified());
}

/// `is_fully_verified()` requires `entries_verified > 0` to defend
/// against the "empty-but-hashed shell" substitution attack: an
/// attacker who replaces a populated archive with a zero-entry archive
/// whose index correctly hashes still fails the strict-mode check.
#[test]
fn is_fully_verified_requires_at_least_one_verified_entry() {
    use sha1::{Digest, Sha1};

    // Build a zero-entry pak with a real (matching) index hash. This
    // would naively pass "index_verified && no skips" — entries_verified
    // would be 0 and no entries means no skips either.
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(0).unwrap(); // zero entries
    let mut h = Sha1::new();
    h.update(&index_section);
    let index_hash: [u8; 20] = h.finalize().into();

    let mut pak = Vec::new();
    pak.extend_from_slice(&index_section);
    let index_offset = 0u64;
    let index_size = index_section.len() as u64;
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&index_hash);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let stats = reader.verify().unwrap();
    assert!(stats.index_verified(), "index hash matches");
    assert_eq!(stats.entries_verified(), 0);
    // Without the entries_verified > 0 check, this would naively be true.
    // The strict-mode assertion: zero entries means we can't claim "fully
    // verified" because there's nothing meaningful to verify.
    assert!(
        !stats.is_fully_verified(),
        "an empty-but-hashed archive should not pass strict verification"
    );
}

#[test]
fn verify_entry_unknown_path_returns_entry_not_found() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let err = reader.verify_entry("Content/DoesNotExist").unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::EntryNotFound { .. }
    ));
}

/// All 30 committed fixtures use `mount_point = "../../../"` (UE's
/// stock writer convention). Real-world paks from other UE projects
/// or mod tools use a variety of mount strings — `/Game/`,
/// `/Engine/`, `""`, etc. The FString length encoding handles all of
/// these uniformly, but no test pins that paksmith doesn't somehow
/// special-case the canonical UE prefix. Issue #31.
#[test]
fn open_handles_non_canonical_mount_points() {
    use sha1::{Digest, Sha1};
    for mount in ["/Game/", "/Engine/Content/", ""] {
        // Zero-entry pak with custom mount_point + matching index_hash.
        let mut index_section = Vec::new();
        write_fstring(&mut index_section, mount);
        index_section.write_u32::<LittleEndian>(0).unwrap();

        let mut h = Sha1::new();
        h.update(&index_section);
        let index_hash: [u8; 20] = h.finalize().into();

        let mut pak = Vec::new();
        pak.extend_from_slice(&index_section);
        let index_size = index_section.len() as u64;
        pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        pak.write_u32::<LittleEndian>(6).unwrap();
        pak.write_u64::<LittleEndian>(0).unwrap();
        pak.write_u64::<LittleEndian>(index_size).unwrap();
        pak.extend_from_slice(&index_hash);

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pak).unwrap();
        tmp.flush().unwrap();

        let reader = PakReader::open(tmp.path()).unwrap_or_else(|e| {
            panic!("PakReader::open failed for mount_point=\"{mount}\": {e:?}")
        });
        assert_eq!(
            reader.mount_point(),
            mount,
            "mount_point round-trip mismatch for \"{mount}\""
        );
    }
}

/// End-to-end coverage of the zero-entry archive shape across the
/// public `entries()` / `read_entry` / `read_entry_to` /
/// `index_entry` surface. Today
/// `is_fully_verified_requires_at_least_one_verified_entry` builds a
/// zero-entry pak but only exercises `verify()` semantics; the read
/// path was not pinned. A future regression that, for example,
/// `unwrap()`-ed a zero-entries vec or short-circuited differently
/// for empty archives would surface here. Issue #31.
#[test]
fn zero_entry_archive_read_paths_are_well_behaved() {
    use sha1::{Digest, Sha1};

    // Same shape as the verify test above: zero-entry index with a
    // matching SHA1.
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(0).unwrap();
    let mut h = Sha1::new();
    h.update(&index_section);
    let index_hash: [u8; 20] = h.finalize().into();

    let mut pak = Vec::new();
    pak.extend_from_slice(&index_section);
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(6).unwrap();
    pak.write_u64::<LittleEndian>(0).unwrap();
    pak.write_u64::<LittleEndian>(index_section.len() as u64)
        .unwrap();
    pak.extend_from_slice(&index_hash);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();

    // entries() must yield an empty iterator (not panic, not stall).
    assert_eq!(
        reader.entries().count(),
        0,
        "zero-entry archive must yield no EntryMetadata"
    );

    // index_entry on any path must return None — there are no entries
    // to find.
    assert!(
        reader.index_entry("Content/anything.uasset").is_none(),
        "index_entry on zero-entry archive must return None"
    );

    // read_entry on any path must return EntryNotFound, not
    // out-of-bounds-on-empty-vec.
    let err = reader
        .read_entry("Content/anything.uasset")
        .expect_err("read_entry on zero-entry archive must error");
    assert!(
        matches!(err, paksmith_core::PaksmithError::EntryNotFound { .. }),
        "got: {err:?}"
    );

    // read_entry_to similarly.
    let mut buf: Vec<u8> = Vec::new();
    let err = reader
        .read_entry_to("Content/anything.uasset", &mut buf)
        .expect_err("read_entry_to on zero-entry archive must error");
    assert!(
        matches!(err, paksmith_core::PaksmithError::EntryNotFound { .. }),
        "got: {err:?}"
    );
    // (Intentionally do NOT assert buf.len() == 0 here — the trait
    // doesn't promise the writer is untouched on error, and pinning
    // it would overspecify. EntryNotFound fires before any write
    // attempt today, so buf would be empty anyway, but a future
    // implementation that buffered before the lookup is free to
    // change that without breaking this test.)
}

/// Flip a byte in the footer's stored `index_hash` and verify that
/// [`PakReader::verify_index`] surfaces the tampering. Mutating the index
/// itself would also work but tends to trip the FString parser in
/// `PakIndex::read_from` before we ever reach `verify_index` — the footer's
/// hash bytes, by contrast, are read opaquely and only consulted by
/// `verify_index`, so flipping one of them is the cleanest "stored hash
/// disagrees with index bytes" trigger.
#[test]
fn verify_index_fails_when_stored_hash_corrupted() {
    let original = std::fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // v6 legacy footer is 44 bytes; the index_hash is the trailing 20 bytes,
    // so byte (file_size - 20 + 5) is mid-hash.
    let target = corrupted.len() - 20 + 5;
    corrupted[target] ^= 0xFF;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_index().unwrap_err();
    match err {
        paksmith_core::PaksmithError::HashMismatch {
            target,
            expected,
            actual,
        } => {
            assert_eq!(target, paksmith_core::error::HashTarget::Index);
            assert_ne!(expected, actual, "mismatch must report different digests");
            assert_eq!(expected.len(), 40, "SHA1 hex is 40 chars");
            assert_eq!(actual.len(), 40);

            // Strengthen the assertion: prove `actual` is the actual SHA1
            // of the corrupted file's index region, not a hardcoded value
            // a buggy "always returns mismatch" impl would also produce.
            let (index_offset, index_size) = read_legacy_v6_index_bounds(&corrupted);
            let independent_hex =
                independent_sha1_hex(&corrupted[index_offset..index_offset + index_size]);
            assert_eq!(
                actual, independent_hex,
                "actual digest must equal an independent SHA1 of the index bytes"
            );
        }
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

/// Flip a byte inside an entry's payload region and verify that
/// [`PakReader::verify_entry`] surfaces the tampering with `path` set.
#[test]
fn verify_entry_fails_when_payload_byte_corrupted() {
    let original = std::fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // Flip a byte mid-payload of the first uncompressed entry. Offset
    // derived from the parsed index — no fixture-layout assumptions baked
    // into the test.
    let target = payload_byte_offset("minimal_v6.pak", "Content/Textures/hero.uasset", 5);
    corrupted[target] ^= 0xFF;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader
        .verify_entry("Content/Textures/hero.uasset")
        .unwrap_err();
    match err {
        paksmith_core::PaksmithError::HashMismatch {
            target,
            expected,
            actual,
        } => {
            match target {
                paksmith_core::error::HashTarget::Entry { path } => {
                    assert_eq!(path, "Content/Textures/hero.uasset");
                }
                other => panic!("expected Entry target, got {other:?}"),
            }
            assert_ne!(expected, actual);
        }
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

/// `verify()` runs verify_index first, so a corrupt-stored-hash produces an
/// "index" mismatch even when entries are also corrupt — failing fast on
/// the higher-impact error before walking every entry.
#[test]
fn verify_reports_index_mismatch_first() {
    let original = std::fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // Corrupt both the footer's stored index_hash AND an entry's payload.
    let payload_byte = payload_byte_offset("minimal_v6.pak", "Content/Textures/hero.uasset", 5);
    corrupted[payload_byte] ^= 0xFF;
    let hash_byte = corrupted.len() - 20 + 5; // mid index_hash byte
    corrupted[hash_byte] ^= 0xFF;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify().unwrap_err();
    match err {
        paksmith_core::PaksmithError::HashMismatch { target, .. } => {
            assert_eq!(
                target,
                paksmith_core::error::HashTarget::Index,
                "verify() must report index mismatch first"
            );
        }
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

#[test]
fn read_entry_not_found() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let err = reader
        .read_entry("Content/DoesNotExist.uasset")
        .unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::EntryNotFound { .. }
    ));
}

#[test]
fn open_nonexistent_file() {
    let err = PakReader::open("/tmp/this_does_not_exist.pak").unwrap_err();
    assert!(matches!(err, paksmith_core::PaksmithError::Io(_)));
}

/// Build a single-entry pak in a tempfile with an arbitrary footer version
/// and FPakEntry header. Used by the malformed-input regression tests below.
#[allow(clippy::too_many_arguments)]
fn build_single_entry_pak(
    footer_version: u32,
    compression_method: u32,
    sha1: [u8; 20],
    blocks: &[(u64, u64)],
    block_size: u32,
    payload: &[u8],
    uncompressed_size_override: Option<u64>,
) -> tempfile::NamedTempFile {
    build_single_entry_pak_with_flags(
        footer_version,
        compression_method,
        sha1,
        blocks,
        block_size,
        payload,
        uncompressed_size_override,
        false,
        None,
    )
}

/// Like [`build_single_entry_pak`] but with explicit control over the
/// encrypted flag and an `index_offset_override` knob that injects an
/// arbitrary offset into the index entry's `offset` field — used to test
/// `PakReader::open_entry_into`'s bounds check against `file_size`.
///
/// `index_offset_override = None` writes 0 (the actual in-data record
/// position, since the synthetic data section starts at file offset 0).
/// `Some(o)` writes `o` regardless of where the in-data record sits.
///
/// **Pre-v7 only (v1-v6)**: this helper writes a legacy 44-byte
/// footer. v1/v2 are accepted because the wire layout is identical
/// to v3-v6 (the version byte just routes downstream); the
/// `open_rejects_pre_v3_versions` test below relies on this to
/// trigger `PakReader::open`'s pre-v3 rejection at the version
/// gate without needing a separate helper.
///
/// Issue #97 removed a buggy `footer_version >= 7` branch that wrote
/// the v7+ fields in the wrong order (`magic + version + offset +
/// size + hash + uuid + encrypted` instead of the correct `uuid +
/// encrypted + magic + version + offset + size + hash`). No caller
/// used it; v7+ entry construction is covered by
/// [`build_v7_tempfile`] family. Asserts at runtime to fail loudly
/// if a future caller passes `footer_version >= 7` by mistake.
#[allow(clippy::too_many_arguments)]
fn build_single_entry_pak_with_flags(
    footer_version: u32,
    compression_method: u32,
    sha1: [u8; 20],
    blocks: &[(u64, u64)],
    block_size: u32,
    payload: &[u8],
    uncompressed_size_override: Option<u64>,
    encrypted: bool,
    index_offset_override: Option<u64>,
) -> tempfile::NamedTempFile {
    // Issue #97: this helper only emits the legacy 44-byte footer
    // (v1-v6 — same wire layout). Fail loudly if a caller asks for
    // v7+ — see the doc comment for the wire-layout bug history;
    // use `build_v7_tempfile` for v7+ entries.
    assert!(
        footer_version <= 6,
        "build_single_entry_pak_with_flags only supports v1-v6 (pre-v7) footers; \
         got v{footer_version}. Use build_v7_tempfile for v7+ entries."
    );
    let compressed_size = payload.len() as u64;
    let uncompressed_size = uncompressed_size_override.unwrap_or(compressed_size);

    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        compressed_size,
        uncompressed_size,
        compression_method,
        &sha1,
        blocks,
        block_size,
        encrypted,
    );
    data_section.extend_from_slice(payload);

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/x.uasset");
    write_pak_entry(
        &mut index_section,
        index_offset_override.unwrap_or(0),
        compressed_size,
        uncompressed_size,
        compression_method,
        &sha1,
        blocks,
        block_size,
        encrypted,
    );

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    let mut pak = data_section;
    pak.extend_from_slice(&index_section);

    // Legacy 44-byte footer (v1-v6): magic + version + index_offset
    // + index_size + index_hash. v7+ requires a different layout
    // (uuid + encrypted prefix BEFORE magic); this helper rejects
    // v7+ at the assertion above. Issue #97 — see doc comment for
    // the wire-layout bug history that motivated removing the
    // pre-existing buggy v7+ branch.
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(footer_version).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();
    tmp
}

/// Compress `payload` as a single zlib block; return the compressed bytes.
fn zlib_compress(payload: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(payload).unwrap();
    enc.finish().unwrap()
}

/// `PakReader::open` bounds-checks each index-recorded entry's
/// `offset + in_data_header_size + compressed_size` against
/// `file_size` upfront (issue #58 open-time check, corrected by
/// #85 to include `in_data_header_size = wire_size()`), surfacing
/// a malformed pak as `InvalidIndex` rather than waiting for
/// `read_entry` to trip the per-entry check later. The pre-#58
/// entry-time check still exists at `open_entry_into` as a
/// defense-in-depth fallback, but the open-time check fires
/// FIRST and is what consumers like `paksmith list` (which never
/// opens entries) now rely on.
///
/// We exercise three boundary cases:
/// - `offset == file_size`: the smallest invalid value with payload
///   bytes. `payload_end = file_size + 1 > file_size` rejects via
///   `OffsetPastFileSize { kind: PayloadEndBounds }`.
/// - `offset == file_size + 1`: just past EOF; same `PayloadEndBounds`
///   path with a slightly larger observed value.
/// - `offset == u64::MAX`: `offset + compressed_size` overflows u64,
///   surfacing as `U64ArithmeticOverflow { operation: PayloadEnd }`.
#[test]
fn open_rejects_index_offset_past_eof() {
    let payload = b"x";

    // Build once with no override to discover file_size — the override
    // only changes the index entry's offset field, not the file length,
    // so file_size is constant across all three cases.
    let base = build_single_entry_pak_with_flags(6, 0, [0; 20], &[], 0, payload, None, false, None);
    let file_size = std::fs::metadata(base.path()).unwrap().len();
    drop(base);

    for &bad_offset in &[file_size, file_size + 1, u64::MAX] {
        let tmp = build_single_entry_pak_with_flags(
            6,
            0,
            [0; 20],
            &[],
            0,
            payload,
            None,
            false,
            Some(bad_offset),
        );
        let err = PakReader::open(tmp.path()).unwrap_err();
        // Issue #95: per-input typed discrimination. The three test
        // offsets deterministically split between two variants:
        // `file_size` and `file_size + 1` surface as
        // `OffsetPastFileSize { PayloadEndBounds }` (arithmetic
        // succeeds, result exceeds file_size); `u64::MAX` surfaces
        // as `U64ArithmeticOverflow { PayloadEnd }` (offset +
        // payload overflows u64 in `checked_add`). A single match-or
        // arm would silently pass if a future regression funneled
        // all 3 cases through one variant — pin per-input here.
        if bad_offset == u64::MAX {
            assert!(
                matches!(
                    &err,
                    paksmith_core::PaksmithError::InvalidIndex {
                        fault: IndexParseFault::U64ArithmeticOverflow {
                            operation: OverflowSite::PayloadEnd,
                            ..
                        },
                    }
                ),
                "offset u64::MAX: expected U64ArithmeticOverflow{{PayloadEnd}}; got: {err:?}"
            );
        } else {
            assert!(
                matches!(
                    &err,
                    paksmith_core::PaksmithError::InvalidIndex {
                        fault: IndexParseFault::OffsetPastFileSize {
                            kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                            ..
                        },
                    }
                ),
                "offset {bad_offset}: expected OffsetPastFileSize{{PayloadEndBounds}}; got: {err:?}"
            );
        }
    }
}

/// Issue #85 regression: a v6 inline entry whose `offset + payload_size`
/// fits within `file_size` (so the pre-fix open-time check passed) but
/// whose `offset + in_data_header_size + payload_size` exceeds
/// `file_size` (so the corrected check fires). Pre-#85 such an entry
/// reached the read path before being caught — surfacing as a bare
/// `Io::UnexpectedEof` partway through `read_exact` instead of the
/// typed `OffsetPastFileSize { kind: PayloadEndBounds }` the open-time
/// check is supposed to provide.
///
/// Construction: payload is 1 byte. v6 inline FPakEntry in-data record
/// is 53 bytes (8 offset, 8 compressed, 8 uncompressed, 4 method,
/// 20 sha1, 1 encrypted, 4 block_size). With
/// `index_offset_override = file_size - 1`:
///
/// - Pre-fix:  `(file_size - 1) + 1 = file_size  <= file_size`  → passes (BUG)
/// - Post-fix: `(file_size - 1) + 53 + 1 > file_size`           → rejects (FIX)
#[test]
fn open_rejects_offset_in_wire_size_band() {
    let payload = b"x";
    // Discover file_size by building once with a sane offset.
    let base = build_single_entry_pak_with_flags(6, 0, [0; 20], &[], 0, payload, None, false, None);
    let file_size = std::fs::metadata(base.path()).unwrap().len();
    drop(base);

    let bad_offset = file_size - 1;
    let tmp = build_single_entry_pak_with_flags(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        None,
        false,
        Some(bad_offset),
    );
    let err = PakReader::open(tmp.path())
        .expect_err("entry with offset in the wire-size band MUST reject at open time post-#85");
    match err {
        paksmith_core::PaksmithError::InvalidIndex {
            fault:
                IndexParseFault::OffsetPastFileSize {
                    kind:
                        OffsetPastFileSizeKind::PayloadEndBounds {
                            payload_end,
                            file_size_max,
                        },
                    ..
                },
        } => {
            assert!(
                payload_end > file_size_max,
                "OffsetPastFileSize must report payload_end > file_size_max; got payload_end={payload_end}, file_size_max={file_size_max}"
            );
            assert_eq!(
                file_size_max, file_size,
                "file_size_max should be the actual file_size"
            );
        }
        other => panic!(
            "expected typed OffsetPastFileSize::PayloadEndBounds (NOT Io::UnexpectedEof); got: {other:?}"
        ),
    }
}

/// Issue #85 boundary pin: the smallest `offset` in the rejection
/// band — `offset = file_size - in_data_header_size` (53 for v6
/// uncompressed). Locks down the comparison operator (`>` vs `>=`)
/// in the open-time check at the upper edge of the rejection band:
///
/// - `offset = file_size - 53`: post-fix `(file_size - 53) + 53 + 1 = file_size + 1 > file_size` → rejects (smallest rejected offset)
/// - `offset = file_size - 54`: post-fix `(file_size - 54) + 53 + 1 = file_size <= file_size` → would pass, but the entry would be malformed (in-data record at file_size - 54 then payload at file_size - 1 would actually fit; not testable cleanly here)
///
/// Companion to `open_rejects_offset_in_wire_size_band` which
/// covers the band's middle (`offset = file_size - 1`).
#[test]
fn open_rejects_offset_at_wire_size_band_lower_edge() {
    let payload = b"x";
    let base = build_single_entry_pak_with_flags(6, 0, [0; 20], &[], 0, payload, None, false, None);
    let file_size = std::fs::metadata(base.path()).unwrap().len();
    drop(base);

    // 53 = v6 inline FPakEntry wire_size for uncompressed entry.
    // file_size - 53 is the smallest offset for which the post-fix
    // check rejects (and the largest offset the pre-fix check would
    // have accepted, since (file_size - 53) + 1 = file_size - 52
    // < file_size).
    let bad_offset = file_size - 53;
    let tmp = build_single_entry_pak_with_flags(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        None,
        false,
        Some(bad_offset),
    );
    let err = PakReader::open(tmp.path())
        .expect_err("offset = file_size - 53 (smallest band-rejected) MUST reject post-#85");
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                    ..
                },
            }
        ),
        "expected typed OffsetPastFileSize::PayloadEndBounds; got: {err:?}"
    );
}

/// v1 (Initial) and v2 (NoTimestamps) have a different in-data FPakEntry
/// shape than v3+ (notably, no trailing flags+block_size and a leading
/// timestamp pre-v2). `PakEntryHeader::read_from` assumes the v3+ layout,
/// so v1/v2 must be rejected at open() before any entry parsing — silent
/// misparse would cascade into bogus offsets and meaningless errors.
#[test]
fn open_rejects_pre_v3_versions() {
    for footer_version in [1u32, 2u32] {
        // The data/index sections use the v3+ shape (we never get past
        // the version check), but the footer claims v1 or v2 — that's
        // what we're rejecting on.
        let tmp = build_single_entry_pak(footer_version, 0, [0; 20], &[], 0, b"x", None);
        let err = PakReader::open(tmp.path()).unwrap_err();
        assert!(
            matches!(
                err,
                paksmith_core::PaksmithError::UnsupportedVersion { version }
                    if version == footer_version
            ),
            "v{footer_version}: expected UnsupportedVersion, got {err:?}"
        );
    }
}

/// End-to-end coverage of the `PakReader::open` rejection path for
/// future engine versions (v12+). Today this is covered piecemeal:
/// `version_try_from_invalid` (in `version.rs` test mod) covers raw
/// version rejection at the version layer, and the footer parser has
/// its own size-vs-version dispatch — but no test threads a v12+
/// claim end-to-end through `PakReader::open` and asserts the
/// resulting error type is `UnsupportedVersion` (not `InvalidFooter`).
/// A regression that swapped the dispatch ordering or category
/// wouldn't be caught. Issue #31.
///
/// Use the canonical v7 wire layout (via `build_v7_tempfile`, which
/// places `uuid + encrypted` BEFORE `magic` per the actual UE
/// format), then byte-patch the version field to 12 — the
/// size-then-version dispatcher matches the v7 shape, recognizes the
/// version is outside the expected list, and surfaces
/// `UnsupportedVersion`.
#[test]
fn open_rejects_future_version_claim() {
    let tmp = build_v7_tempfile(b"X");
    let mut bytes = std::fs::read(tmp.path()).unwrap();

    // v7+ footer (61 bytes) layout: encryption_uuid(16) +
    // encrypted(1) + magic(4) + version(4) + index_offset(8) +
    // index_size(8) + index_hash(20). Version field starts at
    // footer offset 21 → file offset `file_size - 61 + 21 = file_size - 40`.
    let version_offset = bytes.len() - 40;
    bytes[version_offset..version_offset + 4].copy_from_slice(&12u32.to_le_bytes());
    let mut tmp2 = tempfile::NamedTempFile::new().unwrap();
    tmp2.write_all(&bytes).unwrap();
    tmp2.flush().unwrap();

    let err = PakReader::open(tmp2.path()).unwrap_err();
    assert!(
        matches!(
            err,
            paksmith_core::PaksmithError::UnsupportedVersion { version: 12 }
        ),
        "expected UnsupportedVersion(12), got {err:?}"
    );
}

/// `PakReader::open` must reject paks whose footer's encrypted byte
/// is set to 1 (archive-wide index encryption) with a typed
/// `Decryption` error. Today `verify_entry_returns_skipped_for_encrypted_entry`
/// flips the per-entry encrypted flag, NOT the footer's. A refactor
/// that moved the check below the index parse (where it'd hit
/// `InvalidIndex` on ciphertext bytes) would not be caught. Issue #31.
///
/// Use a canonical v7 pak then byte-patch the encrypted byte to 1.
#[test]
fn open_rejects_pak_with_encrypted_index() {
    let tmp = build_v7_tempfile(b"X");
    let mut bytes = std::fs::read(tmp.path()).unwrap();

    // v7+ footer (61 bytes) places encrypted at footer offset 16
    // → file offset `file_size - 61 + 16 = file_size - 45`.
    let encrypted_offset = bytes.len() - 45;
    bytes[encrypted_offset] = 1;
    let mut tmp2 = tempfile::NamedTempFile::new().unwrap();
    tmp2.write_all(&bytes).unwrap();
    tmp2.flush().unwrap();

    let err = PakReader::open(tmp2.path()).unwrap_err();
    assert!(
        matches!(err, paksmith_core::PaksmithError::Decryption { .. }),
        "expected Decryption, got {err:?}"
    );
}

/// Pre-v5 archives use absolute file offsets in compression_blocks rather than
/// the v5+ relative-offset convention. We reject explicitly with
/// UnsupportedVersion rather than silently reading garbage.
#[test]
fn read_zlib_rejects_pre_v5_compressed_entry() {
    // Build a v4 pak with a zlib-compressed entry. The actual compressed bytes
    // don't matter — we expect rejection before decompression runs.
    let payload = zlib_compress(b"some payload");
    let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4; // 1 block compressed
    let blocks = [(
        header_size as u64,
        header_size as u64 + payload.len() as u64,
    )];
    let tmp = build_single_entry_pak(4, 1, [0; 20], &blocks, 12, &payload, Some(12));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::UnsupportedVersion { version: 4 }
    ));
}

/// V8B+ paks index compression methods via a 5-slot FName table in
/// the footer; entries reference slots by 1-based index. Reading an
/// entry whose slot resolves to `Lz4` (or `Zstd`, or `UnknownByName`)
/// must surface a `Decompression` error naming the slot's content.
/// Today `read_entry_rejects_unsupported_compression_methods` only
/// covers v3-v7 raw-id rejection (Gzip, Oodle, Unknown(99)) — the
/// v8+ FName-resolution arms in `index/entry_header.rs::PakEntryHeader::read_from`
/// (the `compression_method` resolution against the footer's compression-
/// methods table) are unexercised.
/// Issue #31.
#[test]
fn read_entry_rejects_v8b_lz4_named_compression_slot() {
    // Build a v8B pak with `compression_methods[0] = "Lz4"` and one
    // entry referencing slot 1 (1-based). v8B footer layout:
    //   uuid(16) + encrypted(1) + magic(4) + version(4=8) +
    //   index_offset(8) + index_size(8) + index_hash(20) +
    //   5 × 32-byte FName slots = 221 bytes.
    let payload = b"x";
    let sha1 = [0u8; 20];

    let mut data_section = Vec::new();
    write_pak_entry(
        &mut data_section,
        0,
        payload.len() as u64,
        payload.len() as u64,
        1, // slot 1 (1-based) = compression_methods[0]
        &sha1,
        &[(53, 53 + payload.len() as u64)], // one block; size doesn't matter, error fires before read
        1,
        false,
    );
    data_section.extend_from_slice(payload);

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_fstring(&mut index_section, "Content/x.uasset");
    write_pak_entry(
        &mut index_section,
        0,
        payload.len() as u64,
        payload.len() as u64,
        1,
        &sha1,
        &[(53, 53 + payload.len() as u64)],
        1,
        false,
    );

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    let mut pak = data_section;
    pak.extend_from_slice(&index_section);

    // V8B footer: uuid + encrypted + magic + version=8 + offset/size/hash
    // + 5 slots.
    pak.extend_from_slice(&[0u8; 16]); // encryption GUID
    pak.push(0); // not encrypted
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(8).unwrap(); // version
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]); // index hash

    // Compression slots: 5 × 32 bytes, zero-padded UTF-8.
    let mut slot0 = [0u8; 32];
    slot0[..3].copy_from_slice(b"Lz4"); // 1-based slot 1 → index 0
    pak.extend_from_slice(&slot0);
    for _ in 1..5 {
        pak.extend_from_slice(&[0u8; 32]); // empty slots
    }

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&pak).unwrap();
    tmp.flush().unwrap();

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::Decompression {
                fault: DecompressionFault::UnsupportedMethod {
                    method: CompressionMethod::Lz4,
                },
                ..
            }
        ),
        "expected Decompression{{UnsupportedMethod {{ Lz4 }}}}; got {err:?}"
    );
}

/// Gzip and Oodle and Unknown compression methods are rejected with a typed
/// Decompression error before any I/O happens. Verify each branch surfaces
/// with a descriptive reason.
#[test]
fn read_entry_rejects_unsupported_compression_methods() {
    for (method_id, expected_method) in [
        (2u32, CompressionMethod::Gzip),
        (4u32, CompressionMethod::Oodle),
        (
            99u32,
            CompressionMethod::Unknown(NonZeroU32::new(99).unwrap()),
        ),
    ] {
        let payload = b"x".to_vec();
        let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4;
        let blocks = [(
            header_size as u64,
            header_size as u64 + payload.len() as u64,
        )];
        let tmp = build_single_entry_pak(6, method_id, [0; 20], &blocks, 1, &payload, Some(1));

        let reader = PakReader::open(tmp.path()).unwrap();
        let err = reader.read_entry("Content/x.uasset").unwrap_err();
        match err {
            paksmith_core::PaksmithError::Decompression {
                fault: DecompressionFault::UnsupportedMethod { method },
                ..
            } => {
                assert_eq!(
                    method, expected_method,
                    "method mismatch for method_id={method_id}"
                );
            }
            other => panic!(
                "expected Decompression{{UnsupportedMethod {{ method: {expected_method:?} }}}} \
                 for method_id={method_id}, got {other:?}"
            ),
        }
    }
}

/// Decompression bomb: in-data and index agree on uncompressed_size = N, but
/// the compressed bytes actually decompress to more than N. Must surface as
/// Decompression rather than OOM or silent truncation.
#[test]
fn read_zlib_rejects_decompression_bomb() {
    // Compress a 1MB payload but lie that uncompressed_size is 100 bytes.
    let real_payload = vec![0u8; 1024 * 1024];
    let compressed = zlib_compress(&real_payload);
    let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4; // 1 block compressed
    let blocks = [(
        header_size as u64,
        header_size as u64 + compressed.len() as u64,
    )];
    let tmp = build_single_entry_pak(
        6,
        1, // zlib
        [0; 20],
        &blocks,
        100,
        &compressed,
        Some(100), // lie: claim 100 bytes when it's really 1MB
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Pin the actually-reached branch: the in-loop bomb check fires
    // on iteration 0 because `take(remaining + 1)` caps `out.len()` at
    // exactly uncompressed_size + 1, which trips `out.len() >
    // uncompressed_size` BEFORE the loop continues. The post-loop
    // SizeUnderrun check at the end of stream_zlib_to never runs in
    // this case.
    // Pin block_index: 0 — single-block fixture, the bomb fires on the
    // first (only) block. If the bomb path ever reorders to a later
    // block, we want a hard failure rather than a silent shape drift.
    match &err {
        paksmith_core::PaksmithError::Decompression {
            fault: DecompressionFault::DecompressionBomb { block_index: 0, .. },
            ..
        } => {}
        other => panic!(
            "expected Decompression{{DecompressionBomb {{ block_index: 0 }}}}; got {other:?}"
        ),
    }
}

/// Multi-block: a non-final block that decompresses to a size other than
/// `compression_block_size` must be rejected. Without this check, a malicious
/// pak could deliver truncated payloads that still summed to the claimed
/// uncompressed_size by padding the final block.
#[test]
fn read_zlib_rejects_non_final_block_size_mismatch() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    // Two blocks: claim block_size = 100 (so non-final must produce exactly
    // 100 bytes), but the first block actually decompresses to only 50.
    // Final block decompresses to 150 — total still = 200 = uncompressed_size,
    // so the only thing that catches the lie is the per-block check.
    let mut enc1 = ZlibEncoder::new(Vec::new(), Compression::default());
    enc1.write_all(&[0u8; 50]).unwrap();
    let block1 = enc1.finish().unwrap();

    let mut enc2 = ZlibEncoder::new(Vec::new(), Compression::default());
    enc2.write_all(&[0u8; 150]).unwrap();
    let block2 = enc2.finish().unwrap();

    let header_size: u64 = 8 + 8 + 8 + 4 + 20 + 4 + 2 * 16 + 1 + 4; // 2 blocks
    let block_offsets = [
        (header_size, header_size + block1.len() as u64),
        (
            header_size + block1.len() as u64,
            header_size + block1.len() as u64 + block2.len() as u64,
        ),
    ];
    let mut payload = block1;
    payload.extend_from_slice(&block2);

    let tmp = build_single_entry_pak(6, 1, [0; 20], &block_offsets, 100, &payload, Some(200));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Pin block_index: 0 (the first non-final block, which decompresses
    // to 50 bytes against the claimed 100) and actual: 50 (the actual
    // decompressed length). Pinning both fields ensures a regression
    // that fires on the wrong block, or reports the wrong size, fails
    // loudly rather than passing on shape alone.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::Decompression {
                fault: DecompressionFault::NonFinalBlockSizeMismatch {
                    block_index: 0,
                    expected: 100,
                    actual: 50,
                },
                ..
            }
        ),
        "expected Decompression{{NonFinalBlockSizeMismatch {{ block_index: 0, expected: 100, actual: 50 }}}}; got {err:?}"
    );
}

/// Single block: payload decompresses to fewer bytes than the entry's
/// claimed `uncompressed_size`. The per-block bomb check catches the
/// `actual > claimed` direction; this test pins the post-loop
/// `actual < claimed` underrun branch in `stream_zlib_to`.
///
/// Issue #124: covers the `DecompressionFault::SizeUnderrun` variant.
/// The two `*ReserveFailed` variants in the same issue need a custom
/// allocator harness and live in `tests/oom_pak.rs`.
#[test]
fn read_zlib_rejects_size_underrun() {
    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    // One block that decompresses to exactly 50 bytes, but the entry
    // claims `uncompressed_size = 100`. Single-block layout means the
    // non-final-size check never fires (it gates on `i < num_blocks - 1`).
    // The bomb check sees `new_total = 50 <= 100` and lets it through.
    // Only the post-loop `bytes_written < uncompressed_size` branch
    // remains as the catcher.
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(&[0u8; 50]).unwrap();
    let block = enc.finish().unwrap();

    let header_size: u64 = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4; // 1 block
    let block_offsets = [(header_size, header_size + block.len() as u64)];

    // `block_size = 100` matches the lie about uncompressed_size so the
    // non-final-size invariant doesn't accidentally trip first if a
    // future refactor relaxes the `i < num_blocks - 1` gate.
    let tmp = build_single_entry_pak(6, 1, [0; 20], &block_offsets, 100, &block, Some(100));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Pin both fields: `actual: 50` (the real decompressed length) and
    // `expected: 100` (the wire-claimed size). A regression that
    // reported the wrong direction or off-by-one would fail loudly.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::Decompression {
                fault: DecompressionFault::SizeUnderrun {
                    actual: 50,
                    expected: 100,
                },
                ..
            }
        ),
        "expected Decompression{{SizeUnderrun {{ actual: 50, expected: 100 }}}}; got {err:?}"
    );
}

/// `read_entry` rejects encrypted entries before any I/O, with a typed
/// Decryption error rather than a misleading "in-data header mismatch".
#[test]
fn read_entry_rejects_encrypted_entry() {
    let payload = b"ciphertext-stand-in";
    let tmp = build_single_entry_pak_with_flags(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        None,
        true, // encrypted
        None,
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::Decryption { .. }
    ));
}

/// Issue #48 round-1 F1 regression: `verify_entry` on an uncompressed
/// entry whose payload extends past EOF must surface as the structured
/// `OffsetPastFileSize { kind: PayloadEndBounds }`, not as a bare
/// `Io::UnexpectedEof` from `read_exact` partway through hashing.
///
/// Pre-fix: the verify path called `sha1_of_reader` without the
/// payload-end precheck `stream_uncompressed_to` does, so the same
/// anomaly was reported in two different shapes depending on which
/// path encountered it. The PR added the precheck to the verify path
/// for uniform diagnostics.
#[test]
fn verify_entry_uncompressed_rejects_payload_past_eof_with_typed_variant() {
    let payload = b"only 7!";
    let tmp = build_single_entry_pak(
        6,
        0,
        // Non-zero SHA1 so verify_entry actually attempts verification
        // (a zero digest would short-circuit to SkippedNoHash before
        // ever reaching the new precheck).
        [0xAA; 20],
        &[],
        0,
        payload,
        // Same shape as `read_uncompressed_rejects_payload_past_eof`:
        // claim 1 MB uncompressed_size against a 7-byte payload.
        // The verify path now hits the new precheck before reaching
        // `sha1_of_reader`.
        Some(1_000_000),
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_entry("Content/x.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                    ..
                }
            }
        ),
        "verify_entry must surface payload-past-EOF as PayloadEndBounds, got: {err:?}"
    );
}

/// `stream_uncompressed_to` rejects an entry whose payload extends past EOF.
/// Constructed by claiming a much larger uncompressed_size than the actual
/// file's payload region can hold.
#[test]
fn read_uncompressed_rejects_payload_past_eof() {
    let payload = b"only 7!"; // 7 bytes
    let tmp = build_single_entry_pak(
        6,
        0,
        [0; 20],
        &[],
        0,
        payload,
        // Lie that it's 1MB. The in-data and index agree (build_single_entry_pak
        // writes both from the same args), so matches_payload passes; the
        // payload-past-EOF check in stream_uncompressed_to catches it.
        Some(1_000_000),
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Issue #95: typed match on the structured variant rather than a
    // substring scan of Display. Pinning `kind: PayloadEndBounds`
    // distinguishes this from the `EntryHeaderOffset` sister case.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::OffsetPastFileSize {
                    kind: OffsetPastFileSizeKind::PayloadEndBounds { .. },
                    ..
                },
            }
        ),
        "expected OffsetPastFileSize {{ PayloadEndBounds }}; got {err:?}"
    );
}

/// Block end past file_size is rejected with InvalidIndex (defensive bounds
/// check at `stream_zlib_to` block-bounds validation).
#[test]
fn read_zlib_rejects_block_past_eof() {
    // Compress some data then claim the block extends way past the file.
    let payload = zlib_compress(b"actual data");
    let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4;
    // block.end is 1MB past the file end.
    let blocks = [(header_size as u64, header_size as u64 + 1_000_000)];
    let tmp = build_single_entry_pak(6, 1, [0; 20], &blocks, 11, &payload, Some(11));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Issue #95: ONLY `BlockBoundsViolation { EndPastFileSize }`
    // fires here. Open-time accepts because `compressed_size`
    // (`payload.len()`) is honest — `offset + in_data + compressed`
    // is well within `file_size`. The lie is exclusively in
    // `block.end` (1MB past file), which the per-block check at
    // `stream_zlib_to`'s block-bounds validation catches.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    kind: BlockBoundsKind::EndPastFileSize { .. },
                    ..
                },
            }
        ),
        "expected BlockBoundsViolation{{EndPastFileSize}}; got {err:?}"
    );
}

/// Issue #129: compression_blocks declared out of file order (or
/// overlapping each other) must surface as
/// `BlockBoundsViolation { OutOfOrder }`. Each block passes the
/// independent `abs_start >= payload_start` / `abs_end <= file_size`
/// per-block checks, but `block[1].start < block[0].end` means the
/// payload would be served from a different file region than the
/// declared layout implies. The decoder doesn't care — but the
/// "same archive ⇒ same hash" invariant `verify_entry` advertises
/// to downstream consumers does.
#[test]
fn read_zlib_rejects_out_of_order_blocks() {
    // Both uncompressed payloads must be the same length so the
    // first-encountered block can satisfy the non-final-block
    // `uncompressed_size == compression_block_size` constraint
    // (otherwise paksmith's `NonFinalBlockSizeMismatch` check
    // fires inside block 0's decompression BEFORE block 1's
    // OutOfOrder check can run). Two 16-char strings keep the
    // arithmetic clean.
    let payload_a = zlib_compress(b"AAAA_block_a_AAA");
    let payload_b = zlib_compress(b"BBBB_block_b_BBB");
    let uncompressed_per_block = 16u32;
    // In-data header for v6 TWO-block entry:
    // offset(8) + compressed_size(8) + uncompressed_size(8) +
    // compression_method(4) + sha1(20) + block_count(4) +
    // 2 * block(8+8) + is_encrypted(1) + compression_block_size(4) = 89.
    // Distinct from the 1-block fixtures elsewhere in this file
    // (which use 73). The 16-byte difference is the second block's
    // start/end pair in the in-data block table.
    let header_size = 8u64 + 8 + 8 + 4 + 20 + 4 + (2 * 16) + 1 + 4;
    // Declare block[1] BEFORE block[0] in file order — both regions
    // are individually in-range, but `block[1].start (=header_size)
    // < block[0].end (=header_size + payload_a.len())` violates the
    // monotonic-order invariant.
    let first_decoded_start = header_size + payload_b.len() as u64;
    let first_decoded_end = first_decoded_start + payload_a.len() as u64;
    let second_decoded_start = header_size;
    let second_decoded_end = second_decoded_start + payload_b.len() as u64;
    let blocks = [
        (first_decoded_start, first_decoded_end),
        (second_decoded_start, second_decoded_end),
    ];
    let mut combined_payload = payload_b.clone();
    combined_payload.extend_from_slice(&payload_a);
    let tmp = build_single_entry_pak(
        6,
        1,
        [0; 20],
        &blocks,
        uncompressed_per_block,
        &combined_payload,
        // Total uncompressed size is two blocks worth (the final
        // block is allowed to be smaller than compression_block_size,
        // but ours is exactly the same here).
        Some(u64::from(uncompressed_per_block) * 2),
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Explicit field asserts (no `..` mask): pin `observed` and
    // `limit` so a regression that emits the variant with swapped or
    // zeroed values trips the test. `observed` is block[1]'s
    // `abs_start` (header_size, since entry header offset is 0);
    // `limit` is block[0]'s `abs_end` (header_size + payload_b len +
    // payload_a len) — the lower bound `abs_start` must equal or
    // exceed.
    let expected_observed = second_decoded_start;
    let expected_limit = first_decoded_end;
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    kind: BlockBoundsKind::OutOfOrder {
                        block_start,
                        prev_block_end_min,
                    },
                    block_index: 1,
                    path,
                },
            } if path == "Content/x.uasset"
                && *block_start == expected_observed
                && *prev_block_end_min == expected_limit
        ),
        "expected BlockBoundsViolation {{ OutOfOrder {{ block_start: {expected_observed}, prev_block_end_min: {expected_limit} }}, block_index: 1 }}; got {err:?}"
    );
}

/// Issue #129 architect R1 finding: `verify_entry`'s Zlib arm has
/// the same per-block loop as `stream_zlib_to` and was also missing
/// the ordering check (the comment claimed it was "already enforced
/// in stream_zlib_to" — wrong, since verify_entry walks the same
/// `compression_blocks` array independently). After the helper
/// extraction, both paths route through `validate_block_bounds` and
/// reject the same forged archive. Without this test, a regression
/// that drops the helper call from `verify_entry`'s loop would
/// silently re-introduce the verify/read divergence.
#[test]
fn verify_entry_rejects_out_of_order_zlib_blocks() {
    let payload_a = zlib_compress(b"AAAA_block_a_AAA");
    let payload_b = zlib_compress(b"BBBB_block_b_BBB");
    let uncompressed_per_block = 16u32;
    let header_size = 8u64 + 8 + 8 + 4 + 20 + 4 + (2 * 16) + 1 + 4;
    let first_decoded_start = header_size + payload_b.len() as u64;
    let first_decoded_end = first_decoded_start + payload_a.len() as u64;
    let second_decoded_start = header_size;
    let second_decoded_end = second_decoded_start + payload_b.len() as u64;
    let blocks = [
        (first_decoded_start, first_decoded_end),
        (second_decoded_start, second_decoded_end),
    ];
    let mut combined_payload = payload_b.clone();
    combined_payload.extend_from_slice(&payload_a);
    // Non-zero SHA1 so `verify_entry` doesn't short-circuit with
    // `SkippedNoHash` — we need to reach the per-block loop where
    // the new check fires. The actual hash value doesn't matter:
    // `OutOfOrder` fires at block 1's iteration before any hashing
    // completes, so the eventual mismatch never surfaces.
    let tmp = build_single_entry_pak(
        6,
        1,
        [1; 20],
        &blocks,
        uncompressed_per_block,
        &combined_payload,
        Some(u64::from(uncompressed_per_block) * 2),
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_entry("Content/x.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    kind: BlockBoundsKind::OutOfOrder { .. },
                    block_index: 1,
                    ..
                },
            }
        ),
        "verify_entry must reject out-of-order blocks symmetrically with read_entry; got {err:?}"
    );
}

/// Issue #129 test-coverage R2 finding: pin that `prev_abs_end`
/// updates on EVERY iteration, not just the first. A regression
/// like `if i == 0 { prev_abs_end = Some(abs_end); }` would still
/// hold `prev = a_end` at i=2; for the test to discriminate, c's
/// start must land in the gap `(a_end, b_end)` so:
/// * Correct impl (`prev = b_end`): `c_start < b_end` → fires
///   `OutOfOrder` at `block_index: 2`.
/// * Buggy impl (`prev = a_end`): `c_start > a_end` → no fire,
///   falls through to decompression of garbage bytes (test fails
///   with a Decompression error instead of the expected variant).
///
/// A `c_start = a_start` form would fire at i=2 under BOTH the
/// correct impl AND the regression — masking the bug we're
/// trying to pin (R2 advisor catch).
#[test]
fn read_zlib_rejects_out_of_order_third_block() {
    let payload_a = zlib_compress(b"AAAA_block_a_AAA");
    let payload_b = zlib_compress(b"BBBB_block_b_BBB");
    let payload_c = zlib_compress(b"CCCC_block_c_CCC");
    let uncompressed_per_block = 16u32;
    // 3-block in-data header: base + 3*16 bytes of block table.
    let header_size = 8u64 + 8 + 8 + 4 + 20 + 4 + (3 * 16) + 1 + 4;
    // File layout: [header][payload_a][payload_b][payload_c].
    let a_start = header_size;
    let a_end = a_start + payload_a.len() as u64;
    let b_start = a_end; // touching block 0/1 — must be accepted.
    let b_end = b_start + payload_b.len() as u64;
    // c_start lands one byte past a_end (inside block b's range).
    // Strictly greater than a_end so a stale-prev (= a_end)
    // regression's `c_start < prev` check is FALSE → no fire →
    // test catches it. Strictly less than b_end so the correct
    // impl's `c_start < prev (= b_end)` is TRUE → fires at i=2.
    let c_start = a_end + 1;
    let c_end = c_start + payload_c.len() as u64;
    let blocks = [(a_start, a_end), (b_start, b_end), (c_start, c_end)];

    let mut combined_payload = payload_a.clone();
    combined_payload.extend_from_slice(&payload_b);
    combined_payload.extend_from_slice(&payload_c);
    let tmp = build_single_entry_pak(
        6,
        1,
        [0; 20],
        &blocks,
        uncompressed_per_block,
        &combined_payload,
        Some(u64::from(uncompressed_per_block) * 3),
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    kind: BlockBoundsKind::OutOfOrder { .. },
                    block_index: 2,
                    ..
                },
            }
        ),
        "expected BlockBoundsViolation {{ OutOfOrder, block_index: 2 }} — proves prev_abs_end propagates past iter 0; got {err:?}"
    );
}

/// Block start before payload_start (overlapping the in-data header) is
/// rejected with InvalidIndex.
#[test]
fn read_zlib_rejects_block_overlapping_header() {
    let payload = zlib_compress(b"data");
    // Claim block starts at offset 10 (well inside the in-data header).
    let blocks = [(10u64, 10u64 + payload.len() as u64)];
    let tmp = build_single_entry_pak(6, 1, [0; 20], &blocks, 4, &payload, Some(4));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    // Issue #95: typed match on `BlockBoundsViolation { kind:
    // StartOverlapsHeader }`. Pre-#48 substring scan caught the
    // wording but a reword would silently rot.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BlockBoundsViolation {
                    kind: BlockBoundsKind::StartOverlapsHeader { .. },
                    ..
                },
            }
        ),
        "expected BlockBoundsViolation {{ StartOverlapsHeader }}; got {err:?}"
    );
}

/// `uncompressed_size` beyond the per-entry ceiling is rejected at
/// `PakReader::open` time — protects against attacker-controlled OOM
/// via the index AND ensures `paksmith list`-style consumers never
/// see the lie. Pre-#58 the check fired at read time; #58's open-time
/// iteration moved it earlier so it also covers consumers that surface
/// the header field without extracting. Uses the public accessor so
/// the test stays correct if the cap changes.
#[test]
fn open_rejects_oversized_uncompressed_size() {
    let huge = paksmith_core::container::pak::max_uncompressed_entry_bytes() + 1;
    let tmp = build_single_entry_pak(6, 0, [0; 20], &[], 0, b"x", Some(huge));

    let err = PakReader::open(tmp.path()).unwrap_err();
    // Issue #95: typed match on `BoundsExceeded { field:
    // "uncompressed_size", unit: Bytes }`. The companion
    // `cap_uncompressed_size_boundary_text_couples_both_sides` test
    // below intentionally couples on the literal Display token
    // ("exceeds maximum") to anchor the absence-of-token assertion;
    // here we use the typed shape since it's not paired.
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::BoundsExceeded {
                    field: WireField::UncompressedSize,
                    unit: BoundsUnit::Bytes,
                    ..
                },
            }
        ),
        "expected BoundsExceeded {{ uncompressed_size, Bytes }}; got {err:?}"
    );
}

/// The complementary boundary to `read_entry_rejects_oversized_uncompressed_size`:
/// exactly `MAX_UNCOMPRESSED_ENTRY_BYTES` must be ACCEPTED by the cap
/// check. Without this, a future regression that flipped the cap from
/// `>` to `>=` would silently reject valid-sized entries while the
/// existing `+1`-rejected test would still pass. Issue #31.
///
/// Run BOTH boundary cases in one test so they couple: we forge MAX
/// (must NOT trip the cap text) AND MAX+1 (must trip the cap text).
/// If a future refactor changed the cap's reason text, both halves
/// fail in lockstep — the negative-presence assertion can't silently
/// rot because its text is anchored by the positive-presence
/// assertion in the same test.
///
/// The MAX case can't actually decompress to MAX bytes (the synthetic
/// pak only has 1 byte of payload), so SOME downstream error fires
/// — try_reserve_exact failing on the MAX-byte allocation, or the
/// `payload_end > file_size` bound check, or the in-data record
/// cross-check. The assertion is that whatever surfaces is NOT the
/// cap's specific message.
#[test]
fn cap_uncompressed_size_boundary_text_couples_both_sides() {
    let max = paksmith_core::container::pak::max_uncompressed_entry_bytes();

    // Pin the cap-error text by exercising MAX+1 (rejected) FIRST.
    // Post-#58 the cap fires at `PakReader::open` time, not at
    // `read_entry` time. This proves the cap is alive and asserts
    // the literal text our MAX-accepted assertion will check the
    // absence of. If the text changes, this assertion fails
    // immediately.
    let tmp_over = build_single_entry_pak(6, 0, [0; 20], &[], 0, b"x", Some(max + 1));
    let err = PakReader::open(tmp_over.path()).expect_err("MAX+1 must trip the cap at open");
    let cap_text = match &err {
        paksmith_core::PaksmithError::InvalidIndex { fault }
            if fault.to_string().contains("exceeds maximum") =>
        {
            // Capture the literal text the cap actually emits, so the
            // MAX-accepted assertion below is anchored to today's
            // wording rather than a stale assumption.
            "exceeds maximum"
        }
        _ => panic!("MAX+1 must trip the cap with `exceeds maximum` text; got: {err:?}"),
    };

    // Now the MAX case: cap must NOT fire at open. The synthetic
    // pak's `payload_end > file_size` open-time check WILL fire
    // (claimed uncompressed_size = MAX vastly exceeds the actual
    // single-byte payload region), but it must not contain
    // `cap_text`. If `open` somehow succeeds, the read_entry path
    // exercises further downstream cross-checks; either way the
    // failure must not be the cap.
    let tmp_exact = build_single_entry_pak(6, 0, [0; 20], &[], 0, b"x", Some(max));
    let open_result = PakReader::open(tmp_exact.path());
    let reason: String = match open_result {
        Err(paksmith_core::PaksmithError::InvalidIndex { fault }) => fault.to_string(),
        Err(other) => panic!("MAX boundary open() surfaced unexpected variant: {other:?}"),
        Ok(reader) => {
            let read_err = reader.read_entry("Content/x.uasset").expect_err(
                "synthetic MAX pak cannot satisfy downstream cross-checks, so SOME error must surface",
            );
            match &read_err {
                paksmith_core::PaksmithError::InvalidIndex { fault } => fault.to_string(),
                // Issue #112: post-typed-promotion, Decompression's
                // payload is `fault: DecompressionFault`; render via
                // its Display for the substring-comparison-coupler
                // semantics (this test deliberately substring-couples
                // on the literal "exceeds maximum" token to anchor an
                // absence-of-token assertion).
                paksmith_core::PaksmithError::Decompression { fault, .. } => fault.to_string(),
                other => panic!("MAX boundary surfaced unexpected error variant: {other:?}"),
            }
        }
    };
    assert!(
        !reason.contains(cap_text),
        "cap fired at exact MAX boundary; should only fire at MAX+1. got: {reason}"
    );
}

#[test]
fn open_pak_with_v7_footer_round_trip() {
    let payload = b"V7_PAYLOAD_BYTES";
    let tmp = build_v7_tempfile(payload);

    let reader = PakReader::open(tmp.path()).unwrap();
    assert_eq!(reader.version(), PakVersion::EncryptionKeyGuid);
    assert_eq!(reader.format(), ContainerFormat::Pak);

    let entries: Vec<_> = reader.entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), "Content/v7.uasset");
    assert_eq!(entries[0].uncompressed_size(), payload.len() as u64);

    let data = reader.read_entry("Content/v7.uasset").unwrap();
    assert_eq!(data, payload);
}

/// V10+ encoded entries must surface as `Ok(SkippedNoHash)` from
/// `verify_entry`/`verify`, NOT as `Err(IntegrityStripped)`, even when
/// the archive's footer claims integrity (non-zero `index_hash`).
///
/// Bug history: encoded entries decode to the
/// [`paksmith_core::container::pak::index::PakEntryHeader::Encoded`]
/// variant — `sha1()` returns `None` because the bit-packed wire
/// format omits the SHA1 field entirely (see `FPakEntry::EncodeTo`
/// mirror in
/// [`paksmith_core::container::pak::index::PakEntryHeader::read_encoded`]).
/// The pre-fix `verify_entry` only checked
/// `is_zero_sha1(entry.header().sha1())` against a zero-filled
/// placeholder digest and routed every encoded entry on an
/// integrity-claiming archive into the `IntegrityStripped` branch —
/// false-positive across the whole archive, with the alarming message
/// "possible integrity-strip attack". The placeholder is now
/// structurally absent (the Encoded variant has no `sha1` field), so
/// the bug is not just fixed but unrepresentable. See issue #28.
///
/// This test fails on the pre-fix code (would observe `IntegrityStripped`
/// for entries on `real_v10_minimal.pak` if the fixture's
/// `index_hash` is non-zero, which repak-generated fixtures are).
fn assert_v10_plus_verify_skips_no_hash_for_encoded_entries(fixture_name: &str) {
    let path = fixture_path(fixture_name);

    // Defensive precondition: this test only exercises the regression
    // when the fixture's footer carries a non-zero index_hash. If a
    // future repak version stops writing one, the test would silently
    // pass (both pre- and post-fix code return SkippedNoHash when the
    // archive claims no integrity). Assert the precondition so a
    // fixture-shape change fails loudly with maintainer guidance.
    let mut file_for_footer = std::fs::File::open(&path).unwrap();
    let footer = paksmith_core::container::pak::footer::PakFooter::read_from(&mut file_for_footer)
        .expect("fixture must parse");
    assert!(
        !footer.index_hash().is_zero(),
        "{fixture_name}: footer index_hash is all zeros, so this test cannot \
         exercise the integrity-strip false-positive path. If repak's writer \
         stopped emitting an index_hash, replace this fixture with one that \
         carries one (or synthesize a v10+ pak with non-zero index_hash and \
         encoded entries). See issue #28."
    );

    let reader = PakReader::open(&path).unwrap();
    assert!(
        matches!(
            reader.version(),
            PakVersion::PathHashIndex | PakVersion::Fnv64BugFix
        ),
        "{fixture_name}: expected v10/v11, got {:?}",
        reader.version()
    );

    // Every entry in a repak-written v10+ pak goes through the encoded
    // wire format (no fallback non-encoded entries), so every entry
    // must report SkippedNoHash. If even one returns IntegrityStripped,
    // the bug is back.
    let entries: Vec<_> = reader.entries().collect();
    assert!(
        !entries.is_empty(),
        "fixture must contain at least one entry"
    );

    for meta in &entries {
        let outcome = reader
            .verify_entry(meta.path())
            .unwrap_or_else(|e| panic!("verify_entry({}) errored: {e:?}", meta.path()));
        assert_eq!(
            outcome,
            VerifyOutcome::SkippedNoHash,
            "{fixture_name}: entry `{}` returned {:?}; encoded entries on \
             integrity-claiming archives must surface as SkippedNoHash",
            meta.path(),
            outcome,
        );
    }

    // Aggregate verify() should also report no IntegrityStripped errors.
    // VerifyStats fields confirm everything was bucketed as
    // entries_skipped_no_hash.
    let stats = reader.verify().unwrap();
    assert_eq!(
        stats.entries_skipped_no_hash(),
        entries.len(),
        "{fixture_name}: every entry should bucket as skipped_no_hash"
    );
    assert_eq!(stats.entries_verified(), 0);
    assert_eq!(stats.entries_skipped_encrypted(), 0);
}

#[test]
fn verify_v10_minimal_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v10_minimal.pak");
}

#[test]
fn verify_v11_minimal_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v11_minimal.pak");
}

#[test]
fn verify_v10_multi_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v10_multi.pak");
}

#[test]
fn verify_v11_multi_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v11_multi.pak");
}

#[test]
fn verify_v10_mixed_paths_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v10_mixed_paths.pak");
}

#[test]
fn verify_v11_mixed_paths_skips_no_hash_for_encoded_entries() {
    assert_v10_plus_verify_skips_no_hash_for_encoded_entries("real_v11_mixed_paths.pak");
}

/// Issue #86 happy-path: a clean v10+ archive must report both the
/// FDI region and the PHI region as `Verified` in `VerifyStats`.
/// Pre-fix, these fields didn't exist and the regions were never
/// hashed — `is_fully_verified` could return true on a partially-
/// covered archive. Locks in that the new region accessors return
/// the right state for every committed v10/v11 fixture (which all
/// carry non-zero region hashes).
#[test]
fn verify_v10_plus_reports_both_regions_verified_on_clean_fixture() {
    use paksmith_core::container::pak::RegionVerifyState;
    for fixture in [
        "real_v10_minimal.pak",
        "real_v10_multi.pak",
        "real_v10_mixed_paths.pak",
        "real_v11_minimal.pak",
        "real_v11_multi.pak",
        "real_v11_mixed_paths.pak",
    ] {
        let reader = PakReader::open(fixture_path(fixture))
            .unwrap_or_else(|e| panic!("opening {fixture}: {e}"));
        // verify_index alone covers all three regions post-#86; ensure
        // it returns Ok rather than the pre-fix silent partial coverage.
        let outcome = reader
            .verify_index()
            .unwrap_or_else(|e| panic!("{fixture}: verify_index errored: {e:?}"));
        assert!(
            matches!(
                outcome,
                paksmith_core::container::pak::VerifyOutcome::Verified
            ),
            "{fixture}: verify_index outcome {outcome:?}",
        );
        let stats = reader
            .verify()
            .unwrap_or_else(|e| panic!("{fixture}: verify errored: {e:?}"));
        assert_eq!(
            stats.fdi(),
            RegionVerifyState::Verified,
            "{fixture}: FDI should have been hashed and verified",
        );
        assert_eq!(
            stats.phi(),
            RegionVerifyState::Verified,
            "{fixture}: PHI should have been hashed and verified",
        );
        // Pin the policy: v10+ archives have all-encoded entries
        // which surface as `entries_skipped_no_hash`, so
        // `is_fully_verified()` is FALSE here. The assertion isn't
        // a test of the bug fix — it's a guard against a future
        // policy regression that ignored `entries_skipped_no_hash`
        // for full-verified, which would silently weaken the
        // security claim across every existing v10/v11 test.
        assert!(
            !stats.is_fully_verified(),
            "{fixture}: encoded-entry skips must disqualify is_fully_verified()",
        );
    }
}

/// Negative-branch coverage for the "encoded entry on a no-integrity
/// archive" path: a v10+ archive whose footer index_hash IS all
/// zeros (no archive-wide integrity claim). Encoded entries must
/// still surface as `SkippedNoHash` here. Without this test, a
/// future regression in the early-return ordering inside
/// `verify_entry` (e.g. checking `archive_claims_integrity()` before
/// the `sha1().is_none()` short-circuit) would still pass the four
/// integrity-claiming tests above while regressing this path.
///
/// Synthesizes the no-claim case by copying the real v10 fixture and
/// zeroing the 20-byte index_hash field within the v8B+/v10/v11
/// 221-byte footer. Field offset within the footer is 41
/// (encryption_uuid 16 + encrypted 1 + magic 4 + version 4 +
/// index_offset 8 + index_size 8 = 41), so the absolute file offset
/// is `file_size - 221 + 41 = file_size - 180`.
// Hoisted out of `verify_v10_with_zero_index_hash_*` so clippy's
// `items-after-statements` lint doesn't fire on function-local consts.
// `FOOTER_SIZE_V8B_PLUS` is imported from production to keep the test
// in sync with whatever the parser thinks the v8B+/v10/v11 footer
// shape is — see the `FOOTER_SIZE_V8B_PLUS` const in
// `container/pak/version.rs`. The two below are derived locally
// because production doesn't currently expose the field-internal
// offset; if a v12 footer adds a field at the front, both this offset
// AND `FOOTER_SIZE_V8B_PLUS` would change in the parser, and only the
// hardcoded offset here would silently mis-zero.
const INDEX_HASH_OFFSET_IN_FOOTER: usize = 41;
const INDEX_HASH_LEN: usize = 20;
// V8B+ footer field offsets: encryption_uuid(16) + encrypted(1) +
// magic(4) + version(4) + index_offset(8) + index_size(8) +
// index_hash(20). Named so a future v12 footer that adds bytes at
// the front updates ONE place rather than silently mis-reading
// across helpers.
const MAGIC_OFFSET_IN_FOOTER: usize = 17;
const INDEX_OFFSET_OFFSET_IN_FOOTER: usize = 25;
const INDEX_SIZE_OFFSET_IN_FOOTER: usize = 33;

// Hoisted out of the `concurrent_read_entry_*` tests for the same
// clippy::items_after_statements reason. Counts sized to surface a
// cursor-leak race with non-trivial probability — round-1 review of
// PR #34 flagged the original 16/32 as too low to be more than a
// smoke test. Both tests still complete in under a second on the CI
// runners. The different-paths test does N reads per iteration (N =
// fixture entry count), so its iteration count is lower than the
// same-path test's at equal total-reads.
const CONCURRENT_THREAD_COUNT: usize = 4;
const CONCURRENT_ITERATIONS_PER_THREAD: usize = 256;
const CONCURRENT_SAME_PATH_ITERATIONS_PER_THREAD: usize = 1024;

#[test]
fn verify_v10_with_zero_index_hash_still_skips_encoded_entries() {
    let src = fixture_path("real_v10_minimal.pak");
    let bytes = std::fs::read(&src).unwrap();

    // Sanity-check the source's footer is the v8B+/v10/v11 shape we
    // expect. If repak ever changes footer size, this test needs to
    // be reworked rather than silently zeroing the wrong bytes.
    let footer_size_v8b_plus = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    assert!(
        bytes.len() > footer_size_v8b_plus,
        "fixture too small to contain a v8B+ footer"
    );

    let mut patched = bytes.clone();
    let zero_at = patched.len() - footer_size_v8b_plus + INDEX_HASH_OFFSET_IN_FOOTER;
    patched[zero_at..zero_at + INDEX_HASH_LEN].fill(0);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&patched).unwrap();
    tmp.flush().unwrap();

    // Confirm the patch took: re-parse the footer and assert the hash
    // is now zero. Makes the precondition explicit; if we ever patched
    // the wrong bytes (footer-shape drift), we'd see a confusing
    // failure downstream rather than here.
    let mut file_for_footer = std::fs::File::open(tmp.path()).unwrap();
    let footer = paksmith_core::container::pak::footer::PakFooter::read_from(&mut file_for_footer)
        .expect("patched fixture must still parse");
    assert!(
        footer.index_hash().is_zero(),
        "patch should have zeroed index_hash, got {}",
        footer.index_hash()
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    for meta in reader.entries().collect::<Vec<_>>() {
        let outcome = reader.verify_entry(meta.path()).unwrap_or_else(|e| {
            panic!(
                "verify_entry({}) errored under !claims_integrity: {e:?}",
                meta.path()
            )
        });
        assert_eq!(
            outcome,
            VerifyOutcome::SkippedNoHash,
            "encoded entry `{}` must SkippedNoHash even when archive claims no integrity",
            meta.path()
        );
    }
}

/// Direct `verify_index()` coverage for v10/v11. The path-hash index
/// format on v10+ is structurally distinct from the flat v3-v9 index,
/// so a regression in path-hash-format index hashing wouldn't be
/// caught by the existing v6 verify_index tests.
fn assert_v10_plus_verify_index_succeeds(fixture_name: &str) {
    let reader = PakReader::open(fixture_path(fixture_name)).unwrap();
    assert_eq!(
        reader.verify_index().unwrap(),
        VerifyOutcome::Verified,
        "{fixture_name}: verify_index must report Verified for a real repak fixture"
    );
}

#[test]
fn verify_index_succeeds_for_v10_minimal() {
    assert_v10_plus_verify_index_succeeds("real_v10_minimal.pak");
}

#[test]
fn verify_index_succeeds_for_v11_minimal() {
    assert_v10_plus_verify_index_succeeds("real_v11_minimal.pak");
}

#[test]
fn verify_index_succeeds_for_v10_multi() {
    assert_v10_plus_verify_index_succeeds("real_v10_multi.pak");
}

#[test]
fn verify_index_succeeds_for_v11_multi() {
    assert_v10_plus_verify_index_succeeds("real_v11_multi.pak");
}

/// Multi-threaded read of one `PakReader` via different paths.
/// PR #24 introduced the `Mutex<File>` + `locked()` helper with a
/// load-bearing safety contract ("every caller MUST seek before its
/// first read"). The contract is upheld today, but no test exercised
/// concurrent reads — a future change that adds a `locked()` caller
/// reusing the cursor position would compile and silently corrupt
/// under load. This test pins concurrent correctness against the
/// single-threaded baseline.
#[test]
fn concurrent_read_entry_different_paths_matches_serial() {
    use std::sync::Arc;
    use std::thread;

    let reader = Arc::new(PakReader::open(fixture_path("real_v11_multi.pak")).unwrap());
    let paths: Vec<String> = reader.entries().map(|m| m.path().to_string()).collect();
    assert!(paths.len() >= 2, "fixture must have multiple entries");

    // Single-threaded baseline.
    let expected: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| reader.read_entry(p).unwrap())
        .collect();

    // Hammer the reader from N threads, each cycling through ALL
    // paths in a tight loop. Concurrent reads on the same handle
    // through different paths must produce bytes-identical output to
    // the serial baseline; any cursor-reuse bug in `locked()`-using
    // call sites would surface as a corrupted read.
    //
    // CONCURRENT_THREAD_COUNT and CONCURRENT_ITERATIONS_PER_THREAD are
    // declared at file scope (see below `concurrent_read_entry_*`
    // test) so clippy::items_after_statements doesn't fire.
    let handles: Vec<_> = (0..CONCURRENT_THREAD_COUNT)
        .map(|tid| {
            let reader = Arc::clone(&reader);
            let paths = paths.clone();
            let expected = expected.clone();
            thread::spawn(move || {
                for iter in 0..CONCURRENT_ITERATIONS_PER_THREAD {
                    for (i, p) in paths.iter().enumerate() {
                        let actual = reader.read_entry(p).unwrap_or_else(|e| {
                            panic!("thread {tid} iter {iter} read_entry({p}): {e:?}")
                        });
                        assert_eq!(
                            actual, expected[i],
                            "thread {tid} iter {iter} path {p}: bytes diverged from serial baseline"
                        );
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// Multi-threaded read of the SAME path on one `PakReader`.
///
/// Catches a narrower bug class than
/// [`concurrent_read_entry_different_paths_matches_serial`]: this
/// test would NOT surface a race where the cursor drifts to a
/// neighboring entry between threads (both expected and actual would
/// be bytes of the same offset). It WOULD surface a race where a
/// `locked()` caller leaves the cursor past the entry's payload
/// boundary and another thread fails to re-seek — the second thread
/// would read past the entry into trailing bytes (footer, padding, or
/// EOF), which diverges from `expected`. Kept because the
/// different-paths test depends on having multiple entries with
/// distinct content; the same-path test pins concurrent correctness
/// against the most pathological lock-contention case (every thread
/// targets the same offset).
#[test]
fn concurrent_read_entry_same_path_matches_serial() {
    use std::sync::Arc;
    use std::thread;

    let reader = Arc::new(PakReader::open(fixture_path("real_v11_minimal.pak")).unwrap());
    let path = reader.entries().next().unwrap().path().to_string();
    let expected = reader.read_entry(&path).unwrap();

    let handles: Vec<_> = (0..CONCURRENT_THREAD_COUNT)
        .map(|tid| {
            let reader = Arc::clone(&reader);
            let path = path.clone();
            let expected = expected.clone();
            thread::spawn(move || {
                for iter in 0..CONCURRENT_SAME_PATH_ITERATIONS_PER_THREAD {
                    let actual = reader
                        .read_entry(&path)
                        .unwrap_or_else(|e| panic!("thread {tid} iter {iter}: {e:?}"));
                    assert_eq!(
                        actual, expected,
                        "thread {tid} iter {iter}: same-path read diverged from serial baseline"
                    );
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// Issue #90 (sev L5 / pr-test L5): the cursor-leak hazard the
/// `concurrent_read_entry_*` tests exist to detect could equally
/// bite `verify_entry` (also acquires `locked()`). Pin concurrent
/// `verify_entry` correctness so a future change to verify's lock-
/// using path doesn't silently regress under load.
///
/// Uses `minimal_v6.pak` (NOT `real_v11_multi.pak` like the sibling
/// `concurrent_read_entry_*` tests) deliberately: v10+ encoded
/// entries' verify path early-returns `SkippedNoHash` before ever
/// calling `self.locked()` (the SHA1 is structurally absent from
/// the encoded wire format), so a v11 fixture wouldn't exercise the
/// lock-acquisition surface this test exists to cover. v6's mix of
/// uncompressed and zlib entries with non-zero SHA1s drives both
/// the inline-payload-read and decompress-then-hash paths through
/// `locked()`.
#[test]
fn concurrent_verify_entry_matches_serial() {
    use std::sync::Arc;
    use std::thread;

    let reader = Arc::new(PakReader::open(fixture_path("minimal_v6.pak")).unwrap());
    let paths: Vec<String> = reader.entries().map(|m| m.path().to_string()).collect();
    assert!(paths.len() >= 2, "fixture must have multiple entries");
    // Serial baseline: each entry's verify outcome should be reproducible
    // across calls. minimal_v6 is a mix of uncompressed and zlib
    // entries; both kinds hash with non-zero stored SHA1s and match.
    let expected: Vec<paksmith_core::container::pak::VerifyOutcome> = paths
        .iter()
        .map(|p| reader.verify_entry(p).unwrap())
        .collect();

    let handles: Vec<_> = (0..CONCURRENT_THREAD_COUNT)
        .map(|tid| {
            let reader = Arc::clone(&reader);
            let paths = paths.clone();
            let expected = expected.clone();
            thread::spawn(move || {
                for iter in 0..CONCURRENT_ITERATIONS_PER_THREAD {
                    for (i, p) in paths.iter().enumerate() {
                        let actual = reader.verify_entry(p).unwrap_or_else(|e| {
                            panic!("thread {tid} iter {iter} verify_entry({p}): {e:?}")
                        });
                        assert_eq!(
                            actual, expected[i],
                            "thread {tid} iter {iter} path {p}: verify outcome diverged from serial baseline"
                        );
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

/// Locate the absolute file offsets of the v10+ main-index header's
/// 20-byte FDI hash slot and (when present) PHI hash slot. Used by
/// strip-detection regression tests to zero those slots without
/// hard-coding fixture-specific offsets. Returns
/// `(fdi_hash_slot_offset, Option<phi_hash_slot_offset>)`.
fn find_v10_plus_hash_slots(file_bytes: &[u8]) -> (usize, Option<usize>) {
    // Anchor from EOF using FOOTER_SIZE_V8B_PLUS, NOT `rfind(magic)` —
    // the magic byte sequence can legitimately appear inside FDI text
    // bytes or compressed payloads on larger archives. Asserts the
    // expected magic bytes so a v12 footer-shape change fails loudly.
    let footer_size = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    let footer_start = file_bytes.len() - footer_size;
    let magic_pos = footer_start + MAGIC_OFFSET_IN_FOOTER;
    let actual_magic = u32::from_le_bytes(file_bytes[magic_pos..magic_pos + 4].try_into().unwrap());
    assert_eq!(
        actual_magic, PAK_MAGIC,
        "v8b+ footer magic mismatch — fixture not v10/v11?"
    );
    let index_offset = u64::from_le_bytes(
        file_bytes[magic_pos + 8..magic_pos + 16]
            .try_into()
            .unwrap(),
    );

    let mut off = usize::try_from(index_offset).unwrap();
    let mount_len = i32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap());
    off += 4;
    if mount_len > 0 {
        off += mount_len as usize;
    } else if mount_len < 0 {
        off += (-mount_len) as usize * 2;
    }
    off += 12; // file_count u32 + path_hash_seed u64
    let has_phi = u32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap()) != 0;
    off += 4;
    let phi_hash_slot = if has_phi {
        off += 16; // phi_offset u64 + phi_size u64
        let slot = off;
        off += 20;
        Some(slot)
    } else {
        None
    };
    off += 4 + 16; // has_fdi u32 + fdi_offset u64 + fdi_size u64
    (off, phi_hash_slot)
}

/// Parse the v10+ main-index header off `file_bytes` to extract
/// `(fdi_offset, fdi_size)` and optional `(phi_offset, phi_size)`.
/// Used by the issue-#86 FDI/PHI tamper tests to flip bytes inside
/// those regions without hard-coding fixture-specific offsets.
///
/// Layout (v8b+ footer): magic anchors the footer, `index_offset`
/// lives 8 bytes after magic. Main-index header: mount FString +
/// file_count u32 + path_hash_seed u64 + has_phi u32 [+ phi_offset
/// u64 + phi_size u64 + phi_hash[20]] + has_fdi u32 + fdi_offset
/// u64 + fdi_size u64.
fn read_v10_plus_region_bounds(file_bytes: &[u8]) -> ((u64, u64), Option<(u64, u64)>) {
    // Anchor from EOF using FOOTER_SIZE_V8B_PLUS, NOT `rfind(magic)` —
    // the magic byte sequence can legitimately appear inside FDI text
    // bytes or compressed payloads on larger archives. Asserts the
    // expected magic bytes so a v12 footer-shape change fails loudly.
    let footer_size = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    let footer_start = file_bytes.len() - footer_size;
    let magic_pos = footer_start + MAGIC_OFFSET_IN_FOOTER;
    let actual_magic = u32::from_le_bytes(file_bytes[magic_pos..magic_pos + 4].try_into().unwrap());
    assert_eq!(
        actual_magic, PAK_MAGIC,
        "v8b+ footer magic mismatch — fixture not v10/v11?"
    );
    let index_offset = u64::from_le_bytes(
        file_bytes[magic_pos + 8..magic_pos + 16]
            .try_into()
            .unwrap(),
    );

    let mut off = usize::try_from(index_offset).unwrap();
    let mount_len = i32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap());
    off += 4;
    if mount_len > 0 {
        off += mount_len as usize;
    } else if mount_len < 0 {
        off += (-mount_len) as usize * 2;
    }
    off += 12; // file_count u32 + path_hash_seed u64
    let has_phi = u32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap()) != 0;
    off += 4;
    let phi = if has_phi {
        let phi_offset = u64::from_le_bytes(file_bytes[off..off + 8].try_into().unwrap());
        off += 8;
        let phi_size = u64::from_le_bytes(file_bytes[off..off + 8].try_into().unwrap());
        off += 8 + 20; // phi_size u64 + phi_hash[20]
        Some((phi_offset, phi_size))
    } else {
        None
    };
    off += 4; // has_fdi u32
    let fdi_offset = u64::from_le_bytes(file_bytes[off..off + 8].try_into().unwrap());
    off += 8;
    let fdi_size = u64::from_le_bytes(file_bytes[off..off + 8].try_into().unwrap());
    ((fdi_offset, fdi_size), phi)
}

/// Locate the wire byte offsets needed to tamper a v10+ archive's
/// PHI offset slot AND patch the main-index hash so the tampered
/// archive parses cleanly past `verify_main_index_region`. Returns
/// `(phi_offset_slot, index_offset, index_size, index_hash_slot)`.
/// Issue #127.
///
/// `phi_offset_slot` is the absolute file offset of the PHI's
/// 8-byte offset field in the main-index header (panics if the
/// archive has no PHI; callers should check the fixture first).
/// `index_hash_slot` is the absolute file offset of the footer's
/// 20-byte index_hash field — after recomputing the main-index
/// SHA1 over the tampered bytes, the test must patch this slot.
fn find_v10_plus_phi_tamper_anchors(file_bytes: &[u8]) -> (usize, u64, u64, usize) {
    let footer_size = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    let footer_start = file_bytes.len() - footer_size;
    let magic_pos = footer_start + MAGIC_OFFSET_IN_FOOTER;
    let actual_magic = u32::from_le_bytes(file_bytes[magic_pos..magic_pos + 4].try_into().unwrap());
    assert_eq!(actual_magic, PAK_MAGIC, "fixture is not v10+/v8b+");
    let index_offset = u64::from_le_bytes(
        file_bytes[magic_pos + 8..magic_pos + 16]
            .try_into()
            .unwrap(),
    );
    let index_size = u64::from_le_bytes(
        file_bytes[magic_pos + 16..magic_pos + 24]
            .try_into()
            .unwrap(),
    );
    let index_hash_slot = magic_pos + 24;

    let mut off = usize::try_from(index_offset).unwrap();
    let mount_len = i32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap());
    off += 4;
    if mount_len > 0 {
        off += mount_len as usize;
    } else if mount_len < 0 {
        off += (-mount_len) as usize * 2;
    }
    off += 12; // file_count u32 + path_hash_seed u64
    let has_phi = u32::from_le_bytes(file_bytes[off..off + 4].try_into().unwrap()) != 0;
    off += 4;
    assert!(has_phi, "fixture must have a PHI region for this test");
    let phi_offset_slot = off; // u64 phi_offset, then u64 phi_size, then [u8; 20] phi_hash
    (phi_offset_slot, index_offset, index_size, index_hash_slot)
}

/// Walk the FDI body to return an absolute file offset that's
/// guaranteed to be inside a filename's UTF-8 text (not a structural
/// field like FString length, file_count, nul terminator, or
/// `encoded_offset`). Picks the first text byte of the first file's
/// filename — flipping it changes the file's path on disk but the
/// parser reads filename bytes opaquely, so `PakReader::open` still
/// succeeds and only `verify_index`'s FDI hash check surfaces the
/// tamper.
fn find_safe_fdi_text_byte(file_bytes: &[u8], fdi_offset: u64, fdi_size: u64) -> usize {
    let fdi_start = usize::try_from(fdi_offset).unwrap();
    let fdi_end = usize::try_from(fdi_offset + fdi_size).unwrap();
    let fdi = &file_bytes[fdi_start..fdi_end];
    let mut off = 0usize;
    let dir_count = u32::from_le_bytes(fdi[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    for _ in 0..dir_count {
        let dn_len = i32::from_le_bytes(fdi[off..off + 4].try_into().unwrap());
        off += 4;
        off += if dn_len > 0 {
            dn_len as usize
        } else {
            (-dn_len) as usize * 2
        };
        let file_count = u32::from_le_bytes(fdi[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        // Walk every file in this dir — skipping after just the first
        // would panic on a fixture whose first non-empty dir starts
        // with an empty filename. Pick the first file whose filename
        // has at least one text byte (non-structural slot).
        for _ in 0..file_count {
            let fn_len = i32::from_le_bytes(fdi[off..off + 4].try_into().unwrap());
            off += 4;
            if fn_len > 1 {
                return fdi_start + off;
            }
            off += if fn_len > 0 {
                fn_len as usize
            } else {
                (-fn_len) as usize * 2
            };
            off += 4; // encoded_offset i32
        }
    }
    panic!("FDI walk found no filename text bytes — fixture has no non-empty filenames?");
}

/// Issue #86 regression: tampering a byte inside the v10+ FDI
/// region must surface as `HashMismatch { target: Fdi }`, not
/// silently return Ok. Pre-fix code discards the FDI hash slot
/// during parse and `verify_index` only covers the main-index
/// byte range — leaving the FDI tamper-detectable nowhere.
///
/// Picks a tamper byte inside the last filename's UTF-8 text by
/// walking the FDI body to find a known-opaque slot — flipping
/// structural bytes (FString length prefix, file_count, nul
/// terminator, encoded_offset) trips the parser before
/// `verify_index` runs, masking the bug. Filename text bytes are
/// read opaquely by the parser, so the tamper passes
/// `PakReader::open` and the bug is only exposed once `verify_index`
/// hashes the FDI region.
#[test]
fn verify_v10_fdi_tampered_surfaces_hash_mismatch() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let ((fdi_offset, fdi_size), _) = read_v10_plus_region_bounds(&original);
    let target = find_safe_fdi_text_byte(&original, fdi_offset, fdi_size);
    let mut corrupted = original.clone();
    // XOR 0x20 (case-swap for ASCII letters) so the byte stays a
    // valid UTF-8 character — a plain `^= 0xFF` flips ASCII into
    // the 0x80-0xFF range, which the FString parser rejects as
    // InvalidEncoding before `verify_index` ever runs, masking
    // the bug we're trying to exercise.
    corrupted[target] ^= 0x20;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let reader =
        PakReader::open(tmp.path()).expect("FDI text-byte tamper must not trip open-time parser");
    let err = reader.verify_index().unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::HashMismatch {
                target: paksmith_core::error::HashTarget::Fdi,
                ..
            }
        ),
        "expected HashMismatch{{ target: Fdi }} from verify_index; got {err:?}"
    );
    // Pin the high-level `verify()` codepath too — it re-uses the
    // same `verify_fdi_region` helper, but the `?` propagation
    // through `verify()`'s match arms isn't otherwise exercised.
    let err = reader.verify().unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::HashMismatch {
                target: paksmith_core::error::HashTarget::Fdi,
                ..
            }
        ),
        "expected HashMismatch{{ target: Fdi }} from verify(); got {err:?}"
    );
}

/// Issue #131 integration: swapping the `encoded_offset` field of
/// the FIRST PHI entry in a real fixture must surface as
/// `PhiFdiInconsistency { OffsetMismatch }` at open time. This is
/// the canonical "redirect a known asset-name hash to a different
/// offset" attack the issue's pathological-input section
/// describes.
///
/// PHI body layout (per repak's `generate_path_hash_index`):
/// `count: u32 LE` + N × `(hash: u64 LE, offset: i32 LE)` + `0u32`
/// sentinel. So the first entry's `offset` field lives at
/// `phi_offset + 4 (count) + 8 (first hash) = phi_offset + 12`.
#[test]
fn open_rejects_phi_entry_offset_swap() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let (_, phi) = read_v10_plus_region_bounds(&original);
    let (phi_offset, _phi_size) =
        phi.expect("real_v10_minimal.pak has a PHI region (repak writes one)");
    let mut corrupted = original.clone();
    // Land precisely on the FIRST PHI entry's `offset` field.
    let offset_field_start = usize::try_from(phi_offset).unwrap() + 4 + 8;
    // Forge an offset of `i32::MIN + 1` (= -2_147_483_647). Real
    // FDI offsets are in `1..N` (negative) or `0..encoded_blob_size`
    // (positive); i32::MIN+1 won't collide with any legitimate
    // value, guaranteeing the FDI-vs-PHI offset comparison
    // disagrees.
    let forged: i32 = i32::MIN + 1;
    corrupted[offset_field_start..offset_field_start + 4].copy_from_slice(&forged.to_le_bytes());

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let err = PakReader::open(tmp.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::PhiFdiInconsistency {
                    kind: paksmith_core::error::PhiFdiInconsistencyKind::OffsetMismatch,
                    phi_offset,
                    ..
                }
            } if *phi_offset == forged
        ),
        "expected open-time OffsetMismatch with phi_offset={forged}; got {err:?}"
    );
}

/// Issue #127 + #131: a v10+ archive's `phi_offset` field in the
/// main-index header is wire-attacker-controlled. Pre-#127 a
/// forged offset past EOF surfaced as bare `Io(UnexpectedEof)`
/// from `verify_phi_region`; PR #183 added a typed
/// `RegionPastFileSize` at `verify_region` time; issue #131 then
/// moved PHI consumption to OPEN time (so the cross-check can
/// run), which also moved this bounds check to open time via
/// the shared `check_region_bounds` helper.
///
/// Test tampers the PHI offset, recomputes the main-index SHA1,
/// and asserts `PakReader::open` fails at the open-time
/// bounds-check before any verify call.
#[test]
fn open_rejects_phi_offset_past_eof() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let original_len = original.len() as u64;
    let (phi_offset_slot, index_offset, index_size, index_hash_slot) =
        find_v10_plus_phi_tamper_anchors(&original);

    let mut corrupted = original.clone();
    let forged_phi_offset = original_len + 1;
    corrupted[phi_offset_slot..phi_offset_slot + 8]
        .copy_from_slice(&forged_phi_offset.to_le_bytes());

    // Recompute the main-index SHA1 over the corrupted bytes and
    // patch the footer's index_hash slot — even though the open-time
    // bounds check fires before main-index hash verification, we
    // want to keep the fixture "almost well-formed" to pin that
    // the failure is specifically the PHI bounds check, not a
    // secondary fault.
    let idx_start = usize::try_from(index_offset).unwrap();
    let idx_end = idx_start + usize::try_from(index_size).unwrap();
    let mut hasher = Sha1::new();
    hasher.update(&corrupted[idx_start..idx_end]);
    let new_hash = hasher.finalize();
    corrupted[index_hash_slot..index_hash_slot + 20].copy_from_slice(&new_hash);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let err = PakReader::open(tmp.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::RegionPastFileSize {
                    region: paksmith_core::error::IndexRegionKind::Phi,
                    kind: paksmith_core::error::RegionPastFileSizeKind::OffsetPastEof,
                    ..
                }
            }
        ),
        "expected open-time RegionPastFileSize {{ Phi, OffsetPastEof }}; got {err:?}"
    );
}

/// Issue #127 + #131: the open-time bounds check on PHI offset
/// must fire regardless of whether the PHI hash slot is zero
/// (zero-hash PHI was previously the "skip verification" code
/// path; PR #183 moved bounds-check above that branch in
/// `verify_region`, and issue #131 moved PHI consumption to OPEN
/// time entirely, so the check now fires at parse before any
/// verify-side path is consulted).
///
/// Fixture forges:
/// * `phi_offset` past EOF
/// * PHI hash slot zeroed (irrelevant under the new ordering,
///   but kept to mirror the PR #183 R2 fixture so a regression
///   that re-introduces zero-hash short-circuit semantics on
///   PHI parsing would still fail this test).
/// * Footer's `index_hash` zeroed (avoid `IntegrityStripped`
///   surfacing first).
#[test]
fn open_rejects_zero_hash_phi_offset_past_eof() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let original_len = original.len() as u64;
    let (phi_offset_slot, _index_offset, _index_size, index_hash_slot) =
        find_v10_plus_phi_tamper_anchors(&original);

    let mut corrupted = original.clone();
    let forged_phi_offset = original_len + 1;
    corrupted[phi_offset_slot..phi_offset_slot + 8]
        .copy_from_slice(&forged_phi_offset.to_le_bytes());
    let phi_hash_slot = phi_offset_slot + 16;
    corrupted[phi_hash_slot..phi_hash_slot + 20].fill(0);
    corrupted[index_hash_slot..index_hash_slot + 20].fill(0);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&corrupted).unwrap();
    tmp.flush().unwrap();

    let err = PakReader::open(tmp.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::InvalidIndex {
                fault: IndexParseFault::RegionPastFileSize {
                    region: paksmith_core::error::IndexRegionKind::Phi,
                    kind: paksmith_core::error::RegionPastFileSizeKind::OffsetPastEof,
                    ..
                }
            }
        ),
        "zero-hash PHI with forged offset must surface open-time RegionPastFileSize; got {err:?}"
    );
}

/// Issue #86 strip-detection: an integrity-claiming v10+ archive
/// (footer index_hash non-zero) with a zeroed FDI hash slot in its
/// main-index header is the FDI-region equivalent of the entry-level
/// `IntegrityStripped` signal — an attacker who can recompute the
/// footer hash can zero the FDI hash slot to downgrade the region
/// to `SkippedNoHash`, evading `verify_index() == Verified` callers
/// that don't go through `is_fully_verified()`. Mirrors the
/// `verify_entry_rejects_mixed_zero_entry_hash_when_index_has_hash`
/// test for the FDI region.
#[test]
fn verify_v10_fdi_zero_hash_with_integrity_claim_surfaces_integrity_stripped() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let (fdi_slot, _) = find_v10_plus_hash_slots(&original);
    let mut patched = original.clone();
    // Zero only the FDI hash slot. Footer index_hash stays non-zero,
    // but that includes the main-index bytes we just edited, so we
    // also need to recompute the footer's index_hash for the archive
    // to pass `verify_main_index_region`. Recompute by hashing the
    // new main-index bytes and writing them into the footer slot.
    patched[fdi_slot..fdi_slot + 20].fill(0);
    rehash_footer_index(&mut patched);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&patched).unwrap();
    tmp.flush().unwrap();
    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_index().unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::IntegrityStripped {
                target: paksmith_core::error::HashTarget::Fdi,
            }
        ),
        "expected IntegrityStripped{{ target: Fdi }}; got {err:?}"
    );
}

/// Issue #86 strip-detection: same shape for PHI. PHI is the more
/// dangerous of the two because paksmith never inspects PHI bytes
/// during parse — the hash slot is the only tamper signal.
#[test]
fn verify_v10_phi_zero_hash_with_integrity_claim_surfaces_integrity_stripped() {
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let (_, phi_slot) = find_v10_plus_hash_slots(&original);
    let phi_slot = phi_slot.expect("real_v10_minimal.pak has a PHI region");
    let mut patched = original.clone();
    patched[phi_slot..phi_slot + 20].fill(0);
    rehash_footer_index(&mut patched);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&patched).unwrap();
    tmp.flush().unwrap();
    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.verify_index().unwrap_err();
    assert!(
        matches!(
            &err,
            paksmith_core::PaksmithError::IntegrityStripped {
                target: paksmith_core::error::HashTarget::Phi,
            }
        ),
        "expected IntegrityStripped{{ target: Phi }}; got {err:?}"
    );
}

/// Issue #86 negative branch: when the archive does NOT claim
/// integrity (footer index_hash is also zero), a zeroed FDI hash
/// slot must surface as `SkippedNoHash` rather than
/// `IntegrityStripped` — no integrity claim to strip from. Confirms
/// that `is_fully_verified()` rejects this case (SkippedNoHash
/// counts against full coverage, matching the main-index policy).
#[test]
fn verify_v10_fdi_zero_hash_no_integrity_claim_surfaces_skipped_no_hash() {
    use paksmith_core::container::pak::RegionVerifyState;
    let original = std::fs::read(fixture_path("real_v10_minimal.pak")).unwrap();
    let (fdi_slot, _) = find_v10_plus_hash_slots(&original);
    let mut patched = original.clone();
    patched[fdi_slot..fdi_slot + 20].fill(0);
    // Zero the footer index_hash too — no archive-wide integrity
    // claim. Without this, the strip-detection branch fires instead.
    let footer_size_v8b_plus = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    let zero_at = patched.len() - footer_size_v8b_plus + INDEX_HASH_OFFSET_IN_FOOTER;
    patched[zero_at..zero_at + INDEX_HASH_LEN].fill(0);

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&patched).unwrap();
    tmp.flush().unwrap();
    let reader = PakReader::open(tmp.path()).unwrap();
    let stats = reader.verify().unwrap();
    assert_eq!(stats.fdi(), RegionVerifyState::SkippedNoHash);
    assert!(
        !stats.is_fully_verified(),
        "is_fully_verified must reject when fdi == SkippedNoHash"
    );
}

/// Recompute and write the v8b+ footer's `index_hash` field to match
/// the current main-index bytes. Used by strip-detection tests that
/// tamper bytes inside the main-index region (e.g. zeroing the FDI
/// hash slot) — without this, the main-index hash check fires first
/// and masks the strip-detection signal.
fn rehash_footer_index(file_bytes: &mut [u8]) {
    let footer_size = usize::try_from(FOOTER_SIZE_V8B_PLUS).unwrap();
    let footer_start = file_bytes.len() - footer_size;
    let index_offset = u64::from_le_bytes(
        file_bytes[footer_start + INDEX_OFFSET_OFFSET_IN_FOOTER
            ..footer_start + INDEX_OFFSET_OFFSET_IN_FOOTER + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let index_size = u64::from_le_bytes(
        file_bytes[footer_start + INDEX_SIZE_OFFSET_IN_FOOTER
            ..footer_start + INDEX_SIZE_OFFSET_IN_FOOTER + 8]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut hasher = Sha1::new();
    hasher.update(&file_bytes[index_offset..index_offset + index_size]);
    let digest: [u8; 20] = hasher.finalize().into();
    let hash_offset = footer_start + INDEX_HASH_OFFSET_IN_FOOTER;
    file_bytes[hash_offset..hash_offset + INDEX_HASH_LEN].copy_from_slice(&digest);
}

/// Issue #90 (sev 9 / pr-test H1): the V9 frozen-index rejection
/// gate at `PakReader::open` (`pak/mod.rs::open` — "if footer
/// `frozen_index` { return Err(UnsupportedVersion) }") has no
/// end-to-end test because repak's writer doesn't emit
/// `frozen=true`. Byte-patch the frozen flag on a real v9 fixture
/// and assert the gate fires with `UnsupportedVersion { version: 9 }`.
///
/// Frozen byte is at V9 footer offset 61 (after encryption_uuid(16) +
/// encrypted(1) + magic(4) + version(4) + index_offset(8) +
/// index_size(8) + index_hash(20) = 61). File offset:
/// `file_size - FOOTER_SIZE_V9 + 61`.
#[test]
fn open_rejects_v9_frozen_index() {
    let original = std::fs::read(fixture_path("real_v9_minimal.pak")).unwrap();
    let footer_size = usize::try_from(FOOTER_SIZE_V9).unwrap();
    let frozen_byte_offset = original.len() - footer_size + 61;
    let mut patched = original.clone();
    patched[frozen_byte_offset] = 1;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&patched).unwrap();
    tmp.flush().unwrap();
    let err = PakReader::open(tmp.path()).unwrap_err();
    assert!(
        matches!(
            err,
            paksmith_core::PaksmithError::UnsupportedVersion { version: 9 }
        ),
        "expected UnsupportedVersion {{ version: 9 }}; got {err:?}"
    );
}
