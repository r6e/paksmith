//! Shared wire-format synthesis helpers for tests. Mirrors v3+
//! FPakEntry / FString format shared across every pak version;
//! v10+-specific helpers live in [`v10`].
//!
//! Gated behind `__test_utils`; `pub` items are a test-only surface.
//! `unwrap()`s are infallible (`WriteBytesExt` on `Vec<u8>` never
//! fails) — hence the module-wide `missing_panics_doc` allow.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Hex-pin write_fstring so an endianness or terminator regression
    /// surfaces here instead of cascading silently across every
    /// dependent test. "abc" → i32 len 4 (3 ASCII + null), LE → bytes
    /// `04 00 00 00 61 62 63 00`.
    #[test]
    fn write_fstring_byte_layout() {
        let mut buf = Vec::new();
        write_fstring(&mut buf, "abc");
        assert_eq!(buf, vec![0x04, 0x00, 0x00, 0x00, b'a', b'b', b'c', 0x00]);
    }

    /// UTF-16 variant: "ab" → i32 len -3 (2 code units + null) LE,
    /// then code units `61 00 62 00 00 00`.
    #[test]
    fn write_fstring_utf16_byte_layout() {
        let mut buf = Vec::new();
        write_fstring_utf16(&mut buf, "ab");
        assert_eq!(
            buf,
            vec![0xfd, 0xff, 0xff, 0xff, 0x61, 0x00, 0x62, 0x00, 0x00, 0x00]
        );
    }

    /// Hex-pin the uncompressed FPakEntry shape:
    /// u64 offset + u64 csize + u64 usize + u32 method + 20 sha1 +
    /// (no block list because method==0) + u8 encrypted + u32 block_size
    /// = 8+8+8+4+20+1+4 = 53 bytes.
    #[test]
    fn write_pak_entry_uncompressed_byte_layout() {
        let mut buf = Vec::new();
        let sha1 = [0xAAu8; 20];
        write_pak_entry(
            &mut buf,
            0x1234,
            0x100,
            0x200,
            0,
            &sha1,
            &[],
            0x10000,
            false,
        );
        assert_eq!(buf.len(), 53);
        // offset LE
        assert_eq!(&buf[0..8], &[0x34, 0x12, 0, 0, 0, 0, 0, 0]);
        // compressed_size LE
        assert_eq!(&buf[8..16], &[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        // uncompressed_size LE
        assert_eq!(&buf[16..24], &[0x00, 0x02, 0, 0, 0, 0, 0, 0]);
        // method
        assert_eq!(&buf[24..28], &[0, 0, 0, 0]);
        // sha1
        assert_eq!(&buf[28..48], &[0xAA; 20]);
        // encrypted flag + block_size LE
        assert_eq!(&buf[48..53], &[0, 0x00, 0x00, 0x01, 0x00]);
    }

    /// Compressed variant pins that the block list is present
    /// (`compression_method != 0` branch).
    #[test]
    fn write_pak_entry_compressed_includes_block_list() {
        let mut buf = Vec::new();
        let sha1 = [0u8; 20];
        let blocks = [(100u64, 200u64)];
        write_pak_entry(&mut buf, 0, 100, 100, 1, &sha1, &blocks, 0x10000, true);
        // 48 common + 4 block_count + 16 per block + 5 trailer = 73 bytes.
        assert_eq!(buf.len(), 73);
        // block_count LE at offset 48
        assert_eq!(&buf[48..52], &[1, 0, 0, 0]);
        // encrypted flag at offset 68
        assert_eq!(buf[68], 1);
    }
}
