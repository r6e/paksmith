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
use sha1::{Digest, Sha1};

const PAK_MAGIC: u32 = 0x5A6F_12E1;

/// Wire size of an in-data FPakEntry record (v3+). Mirrors
/// `PakEntryHeader::wire_size` in
/// `crates/paksmith-core/src/container/pak/index.rs`. Kept as a duplicate
/// here so the generator doesn't need to construct a real header struct;
/// the `wire_size_matches_bytes_consumed_by_read_from` parser test would
/// catch any drift between the two formulas.
///
/// Layout:
/// - 48 bytes common: offset(8) + compressed(8) + uncompressed(8) +
///   method(4) + sha1(20)
/// - if compressed: block_count(4) + N × 16
/// - 5 bytes always-present trailer: is_encrypted(1) + block_size(4)
fn in_data_header_size(compressed: bool, block_count: usize) -> u64 {
    let mut size: u64 = 8 + 8 + 8 + 4 + 20;
    if compressed {
        size += 4 + (block_count as u64) * 16;
    }
    size += 1 + 4;
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
    // Always written for v3+ regardless of compression method (real UE
    // writers emit this; matches PakEntryHeader::read_from).
    buf.write_u32::<LittleEndian>(block_size).unwrap();
}

fn write_v6_legacy_footer(
    buf: &mut Vec<u8>,
    index_offset: u64,
    index_size: u64,
    index_hash: &[u8; 20],
) {
    buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    buf.write_u32::<LittleEndian>(6).unwrap();
    buf.write_u64::<LittleEndian>(index_offset).unwrap();
    buf.write_u64::<LittleEndian>(index_size).unwrap();
    buf.extend_from_slice(index_hash);
}

/// Description of one entry to embed in the generated pak.
struct EntrySpec {
    name: &'static str,
    payload: Vec<u8>,
    compress: bool,
    /// If `Some(N)` and `compress` is true, split the payload into N-byte
    /// uncompressed chunks before zlib-encoding each independently. This is
    /// what real UE writers do: one zlib stream per `compression_block_size`
    /// chunk so individual blocks can be decompressed without scanning the
    /// whole entry. `None` means a single block covering the whole payload.
    block_chunk_size: Option<u32>,
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

    if !spec.compress {
        // For uncompressed entries, the on-disk stored bytes ARE the payload.
        let sha1 = sha1_of(&spec.payload);
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

    // Compress one or more independent zlib blocks. Block layout matches what
    // real UE writers produce: each block decompresses to exactly
    // `compression_block_size` bytes (except possibly the last).
    let chunk_size = spec
        .block_chunk_size
        .unwrap_or(uncompressed_size as u32)
        .max(1);
    let mut compressed_blocks: Vec<Vec<u8>> = Vec::new();
    for chunk in spec.payload.chunks(chunk_size as usize) {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(chunk).unwrap();
        compressed_blocks.push(encoder.finish().unwrap());
    }

    // Compute block (start, end) pairs relative to entry.offset() (v5+
    // convention). The first block starts immediately after the in-data
    // header.
    let header_size = in_data_header_size(true, compressed_blocks.len());
    let mut blocks: Vec<(u64, u64)> = Vec::with_capacity(compressed_blocks.len());
    let mut cursor = header_size;
    let mut compressed_payload: Vec<u8> = Vec::new();
    for blk in &compressed_blocks {
        let start = cursor;
        let end = cursor + blk.len() as u64;
        blocks.push((start, end));
        compressed_payload.extend_from_slice(blk);
        cursor = end;
    }
    let compressed_size = compressed_payload.len() as u64;
    let block_size = chunk_size;

    // For compressed entries, UE stores the SHA1 of the on-disk compressed
    // bytes (the concatenated block bytes), NOT of the decompressed payload.
    let sha1 = sha1_of(&compressed_payload);

    let mut record = Vec::new();
    write_pak_entry(
        &mut record,
        0,
        compressed_size,
        uncompressed_size,
        1, // zlib
        &sha1,
        &blocks,
        block_size,
        false,
    );
    record.extend_from_slice(&compressed_payload);

    PreparedEntry {
        name: spec.name,
        record_bytes: record,
        compressed_size,
        uncompressed_size,
        compression_method: 1,
        sha1,
        blocks,
        block_size,
    }
}

fn sha1_of(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn main() {
    let specs = [
        EntrySpec {
            name: "Content/Textures/hero.uasset",
            payload: b"HERO_TEXTURE_DATA_HERE".to_vec(),
            compress: false,
            block_chunk_size: None,
        },
        EntrySpec {
            name: "Content/Maps/level01.umap",
            payload: b"LEVEL01_MAP_DATA".to_vec(),
            compress: false,
            block_chunk_size: None,
        },
        EntrySpec {
            name: "Content/Sounds/bgm.uasset",
            payload: b"BGM_SOUND_DATA_PLACEHOLDER".to_vec(),
            compress: false,
            block_chunk_size: None,
        },
        EntrySpec {
            name: "Content/Text/lorem.txt",
            // Repetitive payload so zlib actually compresses it noticeably.
            // Single-block (block_chunk_size = None means one block covers all).
            payload: b"lorem ipsum dolor sit amet ".repeat(64),
            compress: true,
            block_chunk_size: None,
        },
        EntrySpec {
            name: "Content/Text/lorem_multi.txt",
            // Same repetitive payload, but split into 256-byte uncompressed
            // chunks producing a 7-block zlib entry. Exercises the multi-block
            // decompression loop end-to-end.
            payload: b"lorem ipsum dolor sit amet ".repeat(64),
            compress: true,
            block_chunk_size: Some(256),
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
    let index_hash = sha1_of(&index_section);

    let mut pak_file = Vec::new();
    pak_file.extend_from_slice(&data_section);
    pak_file.extend_from_slice(&index_section);
    write_v6_legacy_footer(&mut pak_file, index_offset, index_size, &index_hash);

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/minimal_v6.pak");
    std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
    // Write to a sibling .tmp then atomic-rename. Same rationale as
    // gen_pak_fixtures.rs — a panic mid-write must not leave a
    // half-written fixture on disk that would silently pass the
    // determinism gate's git-diff check on the un-touched bytes.
    let tmp_path = fixture_path.with_extension("pak.tmp");
    {
        let mut f = File::create(&tmp_path).unwrap();
        f.write_all(&pak_file).unwrap();
        f.flush().unwrap();
    }
    std::fs::rename(&tmp_path, &fixture_path).expect("atomic rename onto final fixture path");

    println!("Generated: {}", fixture_path.display());
    println!("  Data section: {} bytes", data_section.len());
    println!("  Index: {index_size} bytes at offset {index_offset}");
    println!("  Total: {} bytes", pak_file.len());
    let zlib_count = prepared
        .iter()
        .filter(|e| e.compression_method == 1)
        .count();
    println!(
        "  Entries: {} ({zlib_count} zlib-compressed)",
        prepared.len()
    );
}
