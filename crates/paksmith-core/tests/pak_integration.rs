#![allow(missing_docs)]

use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PakVersion;
use paksmith_core::container::{ContainerFormat, ContainerReader};

const PAK_MAGIC: u32 = 0x5A6F_12E1;

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
    let compressed_size = payload.len() as u64;
    let uncompressed_size = uncompressed_size_override.unwrap_or(compressed_size);
    let encrypted = false;

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
            // Either "exceeding uncompressed_size" (post-loop check) or
            // "non-final block ... expected" (per-block sanity) is acceptable.
            assert!(
                reason.contains("exceeding") || reason.contains("decompressed"),
                "got: {reason}"
            );
        }
        other => panic!("expected Decompression, got {other:?}"),
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
/// happens — protects against attacker-controlled OOM via the index.
#[test]
fn read_entry_rejects_oversized_uncompressed_size() {
    // 8 GiB + 1, just past the cap.
    let huge = 8 * 1024 * 1024 * 1024 + 1;
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
