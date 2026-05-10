#![allow(missing_docs)]

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PakVersion;
use paksmith_core::container::{ContainerFormat, ContainerReader};
use sha1::{Digest, Sha1};
use std::fmt::Write as _;

const PAK_MAGIC: u32 = 0x5A6F_12E1;

/// Generator output for `tests/fixtures/minimal_v6.pak`. Re-run
/// `cargo run -p paksmith-core --example generate_fixtures` and check
/// the printed offsets if these ever drift.
const INDEX_OFFSET: usize = 818;
const INDEX_SIZE: usize = 560;

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
    if compression_method != 0 {
        buf.write_u32::<LittleEndian>(block_size).unwrap();
    }
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
fn list_entries_minimal_v6() {
    let reader = PakReader::open(fixture_path("minimal_v6.pak")).unwrap();
    let entries = reader.list_entries();

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
    let entries = reader.list_entries();

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
/// `read_zlib` — the cumulative output check, the non-final-block size
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

use paksmith_core::container::pak::{VerifyOutcome, VerifyStats};

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
    assert_eq!(
        stats,
        VerifyStats {
            index_verified: true,
            index_skipped_no_hash: false,
            entries_verified: 5,
            entries_skipped_no_hash: 0,
            entries_skipped_encrypted: 0,
        }
    );
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
    );
    let reader = PakReader::open(tmp.path()).unwrap();
    assert_eq!(
        reader.verify_entry("Content/x.uasset").unwrap(),
        VerifyOutcome::SkippedEncrypted
    );
}

/// Entries whose stored SHA1 is the all-zero sentinel return
/// `Ok(SkippedNoHash)` rather than failing — UE writers leave this slot
/// zero-filled when integrity hashing is not enabled at write time.
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
/// hashing path. The lorem entry's compressed bytes start at offset 49+24
/// (in-data header for a single-block entry is 49+4+16+4 = 73 bytes; we
/// offset into byte 80 of the file, well into the zlib stream).
#[test]
fn verify_entry_zlib_fails_when_compressed_byte_corrupted() {
    use std::fs;
    let original = fs::read(fixture_path("minimal_v6.pak")).unwrap();
    let mut corrupted = original.clone();

    // Find the lorem entry's offset by parsing the index — easier than
    // hard-coding. We know it's the fourth entry (3 uncompressed +
    // lorem.txt), so it sits after the first three payloads (22 + 16 + 26
    // = 64 bytes of payload + 3 * 49 = 147 bytes of in-data headers).
    let lorem_offset = 64 + 3 * 49;
    // The in-data header for a 1-block compressed entry is 73 bytes.
    // Flip a byte 10 bytes into the compressed payload.
    let target = lorem_offset + 73 + 10;
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
    );
    let reader = PakReader::open(tmp.path()).unwrap();
    let stats = reader.verify().unwrap();
    assert_eq!(stats.entries_verified, 0);
    assert_eq!(stats.entries_skipped_encrypted, 1);
    assert_eq!(stats.entries_skipped_no_hash, 0);
    // Index hash slot in this synthetic pak is also zero, so index is
    // also skipped — that's expected behavior, not a bug.
    assert!(stats.index_skipped_no_hash);
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
            let independent_hex =
                independent_sha1_hex(&corrupted[INDEX_OFFSET..INDEX_OFFSET + INDEX_SIZE]);
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

    // The hero entry is the first one in the data section. Its in-data header
    // is 49 bytes (uncompressed); the payload bytes start at offset 49 and
    // span 22 bytes. Flip a byte mid-payload.
    let target = 49 + 5;
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
    corrupted[49 + 5] ^= 0xFF; // hero entry payload (mid-payload byte)
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
    )
}

/// Like [`build_single_entry_pak`] but with explicit control over the
/// encrypted flag and an additional knob to override the index entry's
/// `offset` field independently of where the in-data record actually sits.
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
        0,
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
            // length check at the end of read_zlib never runs in this case.
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
    );

    let reader = PakReader::open(tmp.path()).unwrap();
    let err = reader.read_entry("Content/x.uasset").unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::Decryption { .. }
    ));
}

/// `read_uncompressed` rejects an entry whose payload extends past EOF.
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
        // payload-past-EOF check in read_uncompressed catches it.
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
/// check at `read_zlib` block-bounds validation).
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

    let entries = reader.list_entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path, "Content/v7.uasset");
    assert_eq!(entries[0].uncompressed_size, payload.len() as u64);

    let data = reader.read_entry("Content/v7.uasset").unwrap();
    assert_eq!(data, payload);
}
