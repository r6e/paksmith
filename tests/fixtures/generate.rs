//! Generates synthetic .pak files for testing.
//!
//! Run with: `cargo run -p paksmith-core --example generate_fixtures`
//!
//! Phase 1 only supports the flat-entry index layout used by pre-v7 archives.
//! The fixture is therefore written as v6 (DeleteRecords) with a legacy
//! footer. v7+ archives have an encryption-key GUID and v8+ change the entry
//! record format — neither is implemented yet.

use std::fs::File;
use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};

const PAK_MAGIC: u32 = 0x5A6F_12E1;

fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

fn write_entry_record(buf: &mut Vec<u8>, filename: &str, offset: u64, size: u64) {
    write_fstring(buf, filename);
    buf.write_u64::<LittleEndian>(offset).unwrap();
    buf.write_u64::<LittleEndian>(size).unwrap(); // compressed size
    buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed size
    buf.write_u32::<LittleEndian>(0).unwrap(); // compression: none
    buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
    buf.push(0); // not encrypted
}

fn write_v6_legacy_footer(buf: &mut Vec<u8>, index_offset: u64, index_size: u64) {
    buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    buf.write_u32::<LittleEndian>(6).unwrap();
    buf.write_u64::<LittleEndian>(index_offset).unwrap();
    buf.write_u64::<LittleEndian>(index_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // index hash
}

fn main() {
    let entries: Vec<(&str, &[u8])> = vec![
        (
            "Content/Textures/hero.uasset",
            b"HERO_TEXTURE_DATA_HERE" as &[u8],
        ),
        ("Content/Maps/level01.umap", b"LEVEL01_MAP_DATA"),
        ("Content/Sounds/bgm.uasset", b"BGM_SOUND_DATA_PLACEHOLDER"),
    ];

    let mut data_section = Vec::new();
    let mut offsets: Vec<(String, u64, u64)> = Vec::new();

    for (name, content) in &entries {
        let offset = data_section.len() as u64;
        data_section.extend_from_slice(content);
        offsets.push(((*name).to_string(), offset, content.len() as u64));
    }

    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section
        .write_u32::<LittleEndian>(entries.len() as u32)
        .unwrap();
    for (name, offset, size) in &offsets {
        write_entry_record(&mut index_section, name, *offset, *size);
    }

    let index_offset = data_section.len() as u64;
    let index_size = index_section.len() as u64;

    let mut pak_file = Vec::new();
    pak_file.extend_from_slice(&data_section);
    pak_file.extend_from_slice(&index_section);
    write_v6_legacy_footer(&mut pak_file, index_offset, index_size);

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/minimal_v6.pak");
    std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
    let mut f = File::create(&fixture_path).unwrap();
    f.write_all(&pak_file).unwrap();

    println!("Generated: {}", fixture_path.display());
    println!("  Data section: {} bytes", data_section.len());
    println!("  Index: {index_size} bytes at offset {index_offset}");
    println!("  Total: {} bytes", pak_file.len());
    println!("  Entries: {}", entries.len());
}
