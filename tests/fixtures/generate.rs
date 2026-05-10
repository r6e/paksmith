//! Generates synthetic .pak files for testing.
//!
//! Run with: `cargo run -p paksmith-core --example generate_fixtures`
//!
//! Phase 1.5 supports the flat-entry index layout used by pre-v8 archives plus
//! the in-data FPakEntry header that real archives write before each payload.
//! The fixture is written as v6 (DeleteRecords) with a legacy footer and
//! includes one zlib-compressed entry so the decompression code path is
//! exercised end-to-end.

use std::fs::File;
use std::io::Write;

use byteorder::{LittleEndian, WriteBytesExt};
use flate2::Compression;
use flate2::write::ZlibEncoder;

const PAK_MAGIC: u32 = 0x5A6F_12E1;

/// Wire size of an in-data FPakEntry record. Mirrors `in_data_header_size`
/// in `crates/paksmith-core/src/container/pak/mod.rs`.
fn in_data_header_size(compressed: bool, block_count: usize) -> u64 {
    let mut size: u64 = 8 + 8 + 8 + 4 + 20 + 1;
    if compressed {
        size += 4 + (block_count as u64) * 16 + 4;
    }
    size
}

fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

/// Write a serialized FPakEntry struct (no leading filename — that's
/// caller-supplied for index entries, omitted for in-data copies).
///
/// `offset_field` is what gets written into the FPakEntry's offset field. UE
/// writes 0 in the in-data copy (self-reference convention) and the actual
/// entry offset in the index copy.
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

fn write_v6_legacy_footer(buf: &mut Vec<u8>, index_offset: u64, index_size: u64) {
    buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    buf.write_u32::<LittleEndian>(6).unwrap();
    buf.write_u64::<LittleEndian>(index_offset).unwrap();
    buf.write_u64::<LittleEndian>(index_size).unwrap();
    buf.extend_from_slice(&[0u8; 20]); // index hash
}

/// Description of one entry to embed in the generated pak.
struct EntrySpec {
    name: &'static str,
    payload: Vec<u8>,
    compress: bool,
}

/// Built form of an entry, ready to splice into the data section.
struct PreparedEntry {
    name: &'static str,
    record_bytes: Vec<u8>, // in-data header + payload
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: u32,
    sha1: [u8; 20],
    blocks: Vec<(u64, u64)>,
    block_size: u32,
}

fn prepare(spec: &EntrySpec) -> PreparedEntry {
    let uncompressed_size = spec.payload.len() as u64;
    // Stable, distinguishable per-entry SHA1 for testing — first byte = entry
    // index proxy, rest derived from name length. Real paks use real SHA1.
    let sha1 = synthetic_sha1(spec.name, &spec.payload);

    if !spec.compress {
        let mut record = Vec::new();
        write_pak_entry(
            &mut record,
            0, // in-data offset = self-reference
            uncompressed_size,
            uncompressed_size,
            0, // no compression
            &sha1,
            &[],
            0,
            false,
        );
        record.extend_from_slice(&spec.payload);
        return PreparedEntry {
            name: spec.name,
            record_bytes: record,
            compressed_size: uncompressed_size,
            uncompressed_size,
            compression_method: 0,
            sha1,
            blocks: Vec::new(),
            block_size: 0,
        };
    }

    // Compress the entire payload as a single zlib block (block_size large
    // enough that we don't need multi-block logic in the generator).
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&spec.payload).unwrap();
    let compressed = encoder.finish().unwrap();
    let compressed_size = compressed.len() as u64;

    // 1-block header size; block.start = header_size, block.end = + compressed.
    let header_size = in_data_header_size(true, 1);
    let block_start = header_size;
    let block_end = header_size + compressed_size;
    let block_size = uncompressed_size as u32; // single block holds everything

    let mut record = Vec::new();
    write_pak_entry(
        &mut record,
        0,
        compressed_size,
        uncompressed_size,
        1, // zlib
        &sha1,
        &[(block_start, block_end)],
        block_size,
        false,
    );
    record.extend_from_slice(&compressed);

    PreparedEntry {
        name: spec.name,
        record_bytes: record,
        compressed_size,
        uncompressed_size,
        compression_method: 1,
        sha1,
        blocks: vec![(block_start, block_end)],
        block_size,
    }
}

fn synthetic_sha1(name: &str, payload: &[u8]) -> [u8; 20] {
    let mut sha = [0u8; 20];
    let nlen = name.len() as u8;
    let plen = payload.len() as u8;
    sha[0] = nlen;
    sha[1] = plen;
    sha[2..6].copy_from_slice(&(name.len() as u32).to_le_bytes());
    sha[6..14].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    sha
}

fn main() {
    let specs = [
        EntrySpec {
            name: "Content/Textures/hero.uasset",
            payload: b"HERO_TEXTURE_DATA_HERE".to_vec(),
            compress: false,
        },
        EntrySpec {
            name: "Content/Maps/level01.umap",
            payload: b"LEVEL01_MAP_DATA".to_vec(),
            compress: false,
        },
        EntrySpec {
            name: "Content/Sounds/bgm.uasset",
            payload: b"BGM_SOUND_DATA_PLACEHOLDER".to_vec(),
            compress: false,
        },
        EntrySpec {
            name: "Content/Text/lorem.txt",
            // Repetitive payload so zlib actually compresses it noticeably.
            payload: b"lorem ipsum dolor sit amet ".repeat(64),
            compress: true,
        },
    ];

    let prepared: Vec<PreparedEntry> = specs.iter().map(prepare).collect();

    // Lay out the data section: each entry's record (in-data header + payload)
    // gets a known offset, which is what the index records as
    // FPakEntry::offset.
    let mut data_section = Vec::new();
    let mut placements: Vec<(u64, &PreparedEntry)> = Vec::new();
    for entry in &prepared {
        let offset = data_section.len() as u64;
        data_section.extend_from_slice(&entry.record_bytes);
        placements.push((offset, entry));
    }

    // Build the index. Each entry record carries the FPakEntry struct again,
    // this time with offset = the actual file offset (not the 0 self-ref).
    let mut index_section = Vec::new();
    write_fstring(&mut index_section, "../../../");
    index_section
        .write_u32::<LittleEndian>(prepared.len() as u32)
        .unwrap();
    for (offset, entry) in &placements {
        write_fstring(&mut index_section, entry.name);
        write_pak_entry(
            &mut index_section,
            *offset,
            entry.compressed_size,
            entry.uncompressed_size,
            entry.compression_method,
            &entry.sha1,
            &entry.blocks,
            entry.block_size,
            false,
        );
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
    println!("  Entries: {} (1 zlib-compressed)", prepared.len());
}
