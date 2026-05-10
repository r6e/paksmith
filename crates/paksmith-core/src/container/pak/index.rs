//! Pak file index and entry parsing.

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::container::pak::version::PakVersion;
use crate::error::PaksmithError;

/// Compression method used for a pak entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// No compression applied.
    None,
    /// Zlib (deflate) compression.
    Zlib,
    /// Gzip compression.
    Gzip,
    /// Oodle compression (Epic proprietary).
    Oodle,
    /// Unrecognized compression method ID.
    Unknown(u32),
}

impl CompressionMethod {
    /// Parse a raw `u32` compression method identifier.
    pub fn from_u32(value: u32) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Zlib,
            2 => Self::Gzip,
            4 => Self::Oodle,
            other => Self::Unknown(other),
        }
    }
}

/// A single entry in the pak index.
#[derive(Debug, Clone)]
pub struct PakIndexEntry {
    /// Path of this entry within the archive.
    pub filename: String,
    /// Byte offset of the entry data in the archive.
    pub offset: u64,
    /// Compressed size in bytes.
    pub compressed_size: u64,
    /// Uncompressed size in bytes.
    pub uncompressed_size: u64,
    /// Compression method applied to this entry.
    pub compression_method: CompressionMethod,
    /// Whether this entry's data is encrypted.
    pub is_encrypted: bool,
}

/// The full pak index: mount point plus all entries.
#[derive(Debug, Clone)]
pub struct PakIndex {
    /// Virtual mount point for paths in this archive.
    pub mount_point: String,
    /// All entries in the archive.
    pub entries: Vec<PakIndexEntry>,
}

impl PakIndex {
    /// Read and parse the index from a reader positioned at `index_offset`.
    pub fn read_from<R: Read>(reader: &mut R, _version: PakVersion) -> crate::Result<Self> {
        let mount_point = read_fstring(reader)?;
        let entry_count = reader.read_u32::<LittleEndian>()?;

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(PakIndexEntry::read_from(reader)?);
        }

        Ok(Self {
            mount_point,
            entries,
        })
    }
}

impl PakIndexEntry {
    fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let filename = read_fstring(reader)?;
        let offset = reader.read_u64::<LittleEndian>()?;
        let compressed_size = reader.read_u64::<LittleEndian>()?;
        let uncompressed_size = reader.read_u64::<LittleEndian>()?;
        let compression_raw = reader.read_u32::<LittleEndian>()?;
        let compression_method = CompressionMethod::from_u32(compression_raw);

        // 20-byte SHA1 hash
        let mut _hash = [0u8; 20];
        reader.read_exact(&mut _hash)?;

        // Compression blocks (if compressed)
        let has_blocks = compression_method != CompressionMethod::None;
        if has_blocks {
            let block_count = reader.read_u32::<LittleEndian>()?;
            for _ in 0..block_count {
                let _block_start = reader.read_u64::<LittleEndian>()?;
                let _block_end = reader.read_u64::<LittleEndian>()?;
            }
        }

        let is_encrypted = reader.read_u8()? != 0;

        // Compression block size (present when blocks exist)
        if has_blocks {
            let _block_size = reader.read_u32::<LittleEndian>()?;
        }

        Ok(Self {
            filename,
            offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            is_encrypted,
        })
    }
}

fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    if len == 0 {
        return Ok(String::new());
    }

    // Negative length means UTF-16 encoded
    if len < 0 {
        let char_count = (-len) as usize;
        let mut buf = vec![0u16; char_count];
        for item in &mut buf {
            *item = reader.read_u16::<LittleEndian>()?;
        }
        if buf.last() == Some(&0) {
            let _ = buf.pop();
        }
        return String::from_utf16(&buf).map_err(|_| PaksmithError::InvalidIndex {
            reason: "invalid UTF-16 string in index".into(),
        });
    }

    // Positive length: UTF-8 (with null terminator included in length)
    let len = len as usize;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    if buf.last() == Some(&0) {
        let _ = buf.pop();
    }
    String::from_utf8(buf).map_err(|_| PaksmithError::InvalidIndex {
        reason: "invalid UTF-8 string in index".into(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::WriteBytesExt;

    use super::*;

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
        buf.write_u64::<LittleEndian>(size).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(size).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // no compression
        buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
        buf.push(0); // not encrypted
    }

    #[test]
    fn parse_index_single_entry() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(1).unwrap();
        write_uncompressed_entry(&mut data, "Content/Textures/hero.uasset", 0, 1024);

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.mount_point, "../../../");
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].filename, "Content/Textures/hero.uasset");
        assert_eq!(index.entries[0].uncompressed_size, 1024);
        assert_eq!(index.entries[0].compression_method, CompressionMethod::None);
        assert!(!index.entries[0].is_encrypted);
    }

    #[test]
    fn parse_index_multiple_entries() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(3).unwrap();
        write_uncompressed_entry(&mut data, "Content/a.uasset", 0, 100);
        write_uncompressed_entry(&mut data, "Content/b.uasset", 100, 200);
        write_uncompressed_entry(&mut data, "Content/c.uasset", 300, 50);

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.entries.len(), 3);
        assert_eq!(index.entries[0].filename, "Content/a.uasset");
        assert_eq!(index.entries[1].filename, "Content/b.uasset");
        assert_eq!(index.entries[2].filename, "Content/c.uasset");
        assert_eq!(index.entries[2].uncompressed_size, 50);
    }

    #[test]
    fn parse_empty_index() {
        let mut data = Vec::new();
        write_fstring(&mut data, "../../../");
        data.write_u32::<LittleEndian>(0).unwrap();

        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix).unwrap();

        assert_eq!(index.entries.len(), 0);
        assert_eq!(index.mount_point, "../../../");
    }

    #[test]
    fn compression_method_from_u32() {
        assert_eq!(CompressionMethod::from_u32(0), CompressionMethod::None);
        assert_eq!(CompressionMethod::from_u32(1), CompressionMethod::Zlib);
        assert_eq!(CompressionMethod::from_u32(4), CompressionMethod::Oodle);
        assert_eq!(
            CompressionMethod::from_u32(99),
            CompressionMethod::Unknown(99)
        );
    }
}
