#![allow(missing_docs)]

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::{FOOTER_SIZE_LEGACY, PAK_MAGIC, PakVersion};
use paksmith_core::container::{ContainerFormat, ContainerReader};
use sha1::{Digest, Sha1};
use std::fmt::Write as _;

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
    let abs = entry.offset() + entry.header().wire_size() + byte_in_payload;
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

fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

/// Write a serialized FPakEntry struct (without leading filename). Mirrors
/// the wire format implemented by `PakEntryHeader::read_from`.
#[allow(clippy::too_many_arguments)]
fn write_pak_entry(
    buf: &mut Vec<u8>,
    offset_field: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    sha1: &[u8; 20],
    blocks: &[(u64, u64)],
    block_size: u32,
    encrypted: bool,
) {
    buf.write_u64::<LittleEndian>(offset_field).unwrap();
    buf.write_u64::<LittleEndian>(compressed_size).unwrap();
    buf.write_u64::<LittleEndian>(uncompressed_size).unwrap();
    buf.write_u32::<LittleEndian>(compression_method).unwrap();
    buf.extend_from_slice(sha1);
    if compression_method != 0 {
        buf.write_u32::<LittleEndian>(blocks.len() as u32).unwrap();
        for (start, end) in blocks {
            buf.write_u64::<LittleEndian>(*start).unwrap();
            buf.write_u64::<LittleEndian>(*end).unwrap();
        }
    }
    buf.push(u8::from(encrypted));
    // Always written for v3+ regardless of compression method (real UE
    // writers emit this; matches PakEntryHeader::read_from).
    buf.write_u32::<LittleEndian>(block_size).unwrap();
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

    // v7+ footer
    pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    pak.write_u32::<LittleEndian>(7).unwrap();
    pak.write_u64::<LittleEndian>(index_offset).unwrap();
    pak.write_u64::<LittleEndian>(index_size).unwrap();
    pak.extend_from_slice(&[0u8; 20]); // index hash
    pak.extend_from_slice(&[0u8; 16]); // encryption GUID
    pak.push(0); // not encrypted

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
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
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

    let by_path = |needle: &str| entries.iter().find(|e| e.path.contains(needle)).unwrap();

    let hero = by_path("hero");
    assert_eq!(hero.uncompressed_size, 22); // b"HERO_TEXTURE_DATA_HERE".len()
    assert_eq!(hero.compressed_size, 22);
    assert!(!hero.is_compressed);
    assert!(!hero.is_encrypted);

    let level = by_path("level01");
    assert_eq!(level.uncompressed_size, 16);
    assert_eq!(level.compressed_size, 16);
    assert!(!level.is_compressed);

    let bgm = by_path("bgm");
    assert_eq!(bgm.uncompressed_size, 26);
    assert_eq!(bgm.compressed_size, 26);
    assert!(!bgm.is_compressed);

    let lorem = by_path("lorem.txt");
    assert_eq!(lorem.uncompressed_size, 27 * 64);
    assert!(lorem.is_compressed);
    assert!(lorem.compressed_size < lorem.uncompressed_size);
    assert!(!lorem.is_encrypted);

    let lorem_multi = by_path("lorem_multi");
    assert_eq!(lorem_multi.uncompressed_size, 27 * 64);
    assert!(lorem_multi.is_compressed);
    // Multi-block has worse compression than single-block (zlib overhead per
    // block) but is still smaller than uncompressed.
    assert!(lorem_multi.compressed_size < lorem_multi.uncompressed_size);
    assert!(lorem_multi.compressed_size > lorem.compressed_size);
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
            entry.uncompressed_size(),
            "{path}: returned u64 must equal entry.uncompressed_size"
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
    match err {
        paksmith_core::PaksmithError::InvalidIndex { reason } => {
            assert!(
                reason.contains("in-data header mismatch") && reason.contains("compressed_size"),
                "unexpected reason: {reason}"
            );
        }
        other => panic!("expected InvalidIndex, got {other:?}"),
    }
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
    assert!(stats.index_verified, "index should have been verified");
    assert!(!stats.index_skipped_no_hash);
    assert_eq!(stats.entries_verified, 5);
    assert_eq!(stats.entries_skipped_no_hash, 0);
    assert_eq!(stats.entries_skipped_encrypted, 0);
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
            paksmith_core::error::HashTarget::Index => {
                panic!("expected Entry target, got Index")
            }
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
#[test]
fn verify_entry_rejects_unsupported_compression_methods() {
    for (method, expected_label) in [(2u32, "Gzip"), (4u32, "Oodle"), (99u32, "Unknown")] {
        // Use the same single-block layout as the read_entry_rejects_*
        // test, but exercise verify_entry instead of read_entry.
        let payload = b"x";
        let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4;
        let blocks = [(
            header_size as u64,
            header_size as u64 + payload.len() as u64,
        )];
        let tmp = build_single_entry_pak(6, method, [0xAA; 20], &blocks, 1, payload, Some(1));
        let reader = PakReader::open(tmp.path()).unwrap();
        let err = reader.verify_entry("Content/x.uasset").unwrap_err();
        match err {
            paksmith_core::PaksmithError::Decompression { reason, .. } => {
                assert!(
                    reason.contains(expected_label),
                    "expected {expected_label} in reason, got: {reason}"
                );
            }
            other => panic!("expected Decompression for method {method}, got {other:?}"),
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
            paksmith_core::error::HashTarget::Index => {
                panic!("expected Entry target, got Index")
            }
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
    assert_eq!(stats.entries_verified, 0);
    assert_eq!(stats.entries_skipped_encrypted, 1);
    assert_eq!(stats.entries_skipped_no_hash, 0);
    // Index hash slot in this synthetic pak is also zero, so index is
    // also skipped — that's expected behavior, not a bug.
    assert!(stats.index_skipped_no_hash);
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
    assert!(stats.index_verified, "index hash matches");
    assert_eq!(stats.entries_verified, 0);
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
                paksmith_core::error::HashTarget::Index => {
                    panic!("expected Entry target, got Index")
                }
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

    if footer_version >= 7 {
        pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        pak.write_u32::<LittleEndian>(footer_version).unwrap();
        pak.write_u64::<LittleEndian>(index_offset).unwrap();
        pak.write_u64::<LittleEndian>(index_size).unwrap();
        pak.extend_from_slice(&[0u8; 20]);
        pak.extend_from_slice(&[0u8; 16]);
        pak.push(0);
    } else {
        pak.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        pak.write_u32::<LittleEndian>(footer_version).unwrap();
        pak.write_u64::<LittleEndian>(index_offset).unwrap();
        pak.write_u64::<LittleEndian>(index_size).unwrap();
        pak.extend_from_slice(&[0u8; 20]);
    }

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

/// `PakReader::open_entry_into` (called transitively from `read_entry`)
/// bounds-checks the index-recorded offset against `file_size` before
/// allocating or seeking, surfacing a malformed pak as `InvalidIndex`
/// rather than a downstream `Io::UnexpectedEof`. The check uses `>=`,
/// so the smallest invalid value is `file_size` exactly.
///
/// We exercise three boundary cases:
/// - `offset == file_size`: the smallest invalid value. This is the
///   ONLY case that distinguishes `>=` from `>` — a regression flipping
///   the operator would pass on `file_size + 1` and `u64::MAX` but fail
///   here.
/// - `offset == file_size + 1`: just past EOF; covers the case the
///   acceptance criteria of #15 specified.
/// - `offset == u64::MAX`: obviously past EOF; covers any
///   integer-overflow-style regression.
#[test]
fn read_entry_rejects_index_offset_past_eof() {
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
        let reader = PakReader::open(tmp.path()).unwrap();
        let err = reader.read_entry("Content/x.uasset").unwrap_err();
        match err {
            paksmith_core::PaksmithError::InvalidIndex { reason } => {
                assert!(
                    reason.contains("offset"),
                    "offset {bad_offset}: reason should mention `offset`; got: {reason}"
                );
                assert!(
                    reason.contains("file_size"),
                    "offset {bad_offset}: reason should mention `file_size`; got: {reason}"
                );
            }
            other => panic!("offset {bad_offset}: expected InvalidIndex, got {other:?}"),
        }
    }
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

/// Gzip and Oodle and Unknown compression methods are rejected with a typed
/// Decompression error before any I/O happens. Verify each branch surfaces
/// with a descriptive reason.
#[test]
fn read_entry_rejects_unsupported_compression_methods() {
    for (method, expected_label) in [(2u32, "Gzip"), (4u32, "Oodle"), (99u32, "Unknown")] {
        let payload = b"x".to_vec();
        let header_size = 8 + 8 + 8 + 4 + 20 + 4 + 16 + 1 + 4;
        let blocks = [(
            header_size as u64,
            header_size as u64 + payload.len() as u64,
        )];
        let tmp = build_single_entry_pak(6, method, [0; 20], &blocks, 1, &payload, Some(1));

        let reader = PakReader::open(tmp.path()).unwrap();
        let err = reader.read_entry("Content/x.uasset").unwrap_err();
        match err {
            paksmith_core::PaksmithError::Decompression { reason, .. } => {
                assert!(
                    reason.contains(expected_label),
                    "expected {expected_label} in reason, got: {reason}"
                );
            }
            other => panic!("expected Decompression for method {method}, got {other:?}"),
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
    match err {
        paksmith_core::PaksmithError::Decompression { reason, .. } => {
            // Pin the actually-reached branch: the in-loop bomb check fires
            // on iteration 0 because `take(remaining + 1)` caps `out.len()` at
            // exactly uncompressed_size + 1, which trips `out.len() >
            // uncompressed_size` BEFORE the loop continues. The post-loop
            // length check at the end of stream_zlib_to never runs in this case.
            assert!(
                reason.contains("exceeding uncompressed_size"),
                "got: {reason}"
            );
        }
        other => panic!("expected Decompression, got {other:?}"),
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
    match err {
        paksmith_core::PaksmithError::Decompression { reason, .. } => {
            assert!(
                reason.contains("non-final block") && reason.contains("expected 100"),
                "got: {reason}"
            );
        }
        other => panic!("expected Decompression, got {other:?}"),
    }
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
    match err {
        paksmith_core::PaksmithError::InvalidIndex { reason } => {
            assert!(reason.contains("payload extends past EOF"), "got: {reason}");
        }
        other => panic!("expected InvalidIndex, got {other:?}"),
    }
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
    match err {
        paksmith_core::PaksmithError::InvalidIndex { reason } => {
            assert!(
                reason.contains("exceeds file_size") || reason.contains("past EOF"),
                "got: {reason}"
            );
        }
        other => panic!("expected InvalidIndex, got {other:?}"),
    }
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
    match err {
        paksmith_core::PaksmithError::InvalidIndex { reason } => {
            assert!(reason.contains("overlaps in-data header"), "got: {reason}");
        }
        other => panic!("expected InvalidIndex, got {other:?}"),
    }
}

/// uncompressed_size beyond the per-entry ceiling is rejected before any I/O
/// happens — protects against attacker-controlled OOM via the index. Uses
/// the public accessor so the test stays correct if the cap changes.
#[test]
fn read_entry_rejects_oversized_uncompressed_size() {
    let huge = paksmith_core::container::pak::max_uncompressed_entry_bytes() + 1;
    let tmp = build_single_entry_pak(6, 0, [0; 20], &[], 0, b"x", Some(huge));

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    match err {
        paksmith_core::PaksmithError::InvalidIndex { reason } => {
            assert!(reason.contains("exceeds maximum"), "got: {reason}");
        }
        other => panic!("expected InvalidIndex, got {other:?}"),
    }
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
    assert_eq!(entries[0].path, "Content/v7.uasset");
    assert_eq!(entries[0].uncompressed_size, payload.len() as u64);

    let data = reader.read_entry("Content/v7.uasset").unwrap();
    assert_eq!(data, payload);
}
