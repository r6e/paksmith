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

fn write_uncompressed_entry(buf: &mut Vec<u8>, filename: &str, offset: u64, size: u64) {
    write_fstring(buf, filename);
    buf.write_u64::<LittleEndian>(offset).unwrap();
    buf.write_u64::<LittleEndian>(size).unwrap();
    buf.write_u64::<LittleEndian>(size).unwrap();
    buf.write_u32::<LittleEndian>(0).unwrap();
    buf.extend_from_slice(&[0u8; 20]);
    buf.push(0);
}

/// Build a synthetic v7 (`EncryptionKeyGuid`) pak with one uncompressed entry,
/// not actually encrypted, written to a tempfile. Exercises the end-to-end
/// v7+ dispatch path through `PakReader::open` that the v6 fixture skips.
fn build_v7_tempfile(payload: &[u8]) -> tempfile::NamedTempFile {
    let mut data_section = Vec::new();
    data_section.extend_from_slice(payload);

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section.write_u32::<LittleEndian>(1).unwrap();
    write_uncompressed_entry(
        &mut index_section,
        "Content/v7.uasset",
        0,
        payload.len() as u64,
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

    assert_eq!(entries.len(), 3);
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
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
