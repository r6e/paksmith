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

    assert_eq!(entries.len(), 4);
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
    assert!(paths.contains(&"Content/Text/lorem.txt"));
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

    let lorem = by_path("lorem");
    // 27 bytes * 64 repeats = 1728 bytes uncompressed.
    assert_eq!(lorem.uncompressed_size, 27 * 64);
    assert!(lorem.is_compressed);
    assert!(lorem.compressed_size < lorem.uncompressed_size);
    assert!(!lorem.is_encrypted);
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
