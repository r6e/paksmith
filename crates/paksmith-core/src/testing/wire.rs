//! Shared wire-format synthesis helpers for tests.
//!
//! Issue #140 lifted these out of the duplicated copies across
//! `paksmith-core-tests/tests/{pak_integration,oom_pak,index_proptest}.rs`
//! and the in-source `pak/index/mod.rs` tests, where ~30 lines of
//! identical builders had been silently rotting whenever a wire
//! field changed. Mirrors the v3+ FPakEntry / FString format shared
//! across every pak version; v10+-specific helpers live in [`v10`].
//!
//! **Stability**: gated behind the `__test_utils` Cargo feature.
//! Anything `pub` here is a `cargo test`-only surface and may change
//! in any release.
//!
//! `Vec` writes are infallible (the only `unwrap()` panics in these
//! helpers come from `byteorder::WriteBytesExt` against a `Vec<u8>`
//! sink, which never fails). Suppressing the `missing_panics_doc`
//! lint module-wide rather than sprinkling `# Panics` sections that
//! would all say the same thing.
//!
//! [`v10`]: super::v10
#![allow(clippy::missing_panics_doc)]

use byteorder::{LittleEndian, WriteBytesExt};

/// Write an FString (length-prefixed ASCII, null-terminated) to
/// `buf`. Length sign convention: positive = UTF-8 bytes, negative
/// = UTF-16 code units (this helper only writes UTF-8). The length
/// includes the trailing null byte.
pub fn write_fstring(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    buf.write_i32::<LittleEndian>((bytes.len() + 1) as i32)
        .unwrap();
    buf.extend_from_slice(bytes);
    buf.push(0);
}

/// Write an FString as UTF-16 code units (negative-length sign
/// convention, null-terminated u16). The length is the negation of
/// `(code_units + 1)`.
pub fn write_fstring_utf16(buf: &mut Vec<u8>, s: &str) {
    let units: Vec<u16> = s.encode_utf16().collect();
    let total_units = units.len() + 1; // include null terminator
    buf.write_i32::<LittleEndian>(-(total_units as i32))
        .unwrap();
    for u in units {
        buf.write_u16::<LittleEndian>(u).unwrap();
    }
    buf.write_u16::<LittleEndian>(0).unwrap();
}

/// Write a serialized FPakEntry struct (without leading filename) to
/// `buf`. Mirrors the wire format implemented by
/// [`crate::container::pak::index::PakEntryHeader::read_from`] for
/// v3+ pak archives.
///
/// `offset_field` is what gets written into the FPakEntry's offset
/// field. UE writes `0` in the in-data copy (self-reference
/// convention) and the actual entry offset in the index copy.
///
/// `compression_method` follows the raw v3-v7 ID convention
/// (`0=None`, `1=Zlib`, etc.); v8+'s 1-based FName-table indexing is
/// caller's responsibility.
#[allow(clippy::too_many_arguments)]
pub fn write_pak_entry(
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
    // Always written for v3+ regardless of compression method (real
    // UE writers emit this; matches PakEntryHeader::read_from).
    buf.write_u32::<LittleEndian>(block_size).unwrap();
}
