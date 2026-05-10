//! Pak file index and entry parsing.

use std::io::Read;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::container::pak::version::PakVersion;
use crate::error::PaksmithError;

/// Maximum length (in bytes for UTF-8, code units for UTF-16) accepted for an
/// FString. Sized to comfortably exceed any realistic UE virtual path while
/// rejecting attacker-controlled multi-GB allocations.
const FSTRING_MAX_LEN: i32 = 65_536;

/// Minimum on-disk size of an index entry record (FString header + offset +
/// sizes + compression + sha1 + encrypted flag, with the shortest-possible
/// FString of 5 bytes for `length(4) + null(1)`). Used to bound `entry_count`.
const ENTRY_MIN_RECORD_BYTES: u64 = 5 + 8 + 8 + 8 + 4 + 20 + 1;

/// Sanity ceiling on compression block count per entry (~16M blocks of 64KiB
/// would be a 1TiB entry).
const MAX_BLOCKS_PER_ENTRY: u32 = 16_777_216;

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
    /// Unrecognized compression method ID, preserved for round-tripping.
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

/// Byte offset range of a single compression block within the entry payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionBlock {
    /// Start offset (inclusive) of the compressed block.
    pub start: u64,
    /// End offset (exclusive) of the compressed block.
    pub end: u64,
}

/// A single entry in the pak index.
#[derive(Debug, Clone)]
pub struct PakIndexEntry {
    filename: String,
    offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: CompressionMethod,
    is_encrypted: bool,
    sha1: [u8; 20],
    compression_blocks: Vec<CompressionBlock>,
    compression_block_size: u32,
}

impl PakIndexEntry {
    /// Path of this entry within the archive.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// Byte offset of the entry record header in the archive.
    ///
    /// **Note:** in real `.pak` files the actual payload begins after the
    /// duplicate FPakEntry record header at this offset, not at the offset
    /// itself. Phase 1 only reads from synthetic fixtures that omit that
    /// header — see [`crate::container::pak::PakReader::read_entry`].
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Compressed size in bytes (equals `uncompressed_size` when uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Uncompressed size in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Compression method applied to this entry.
    pub fn compression_method(&self) -> CompressionMethod {
        self.compression_method
    }

    /// Whether this entry's data is AES-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.is_encrypted
    }

    /// SHA1 hash of the entry's stored bytes (kept for future verification).
    pub fn sha1(&self) -> &[u8; 20] {
        &self.sha1
    }

    /// Compression block boundaries (empty when uncompressed).
    pub fn compression_blocks(&self) -> &[CompressionBlock] {
        &self.compression_blocks
    }

    /// Compression block size in bytes (0 when uncompressed).
    pub fn compression_block_size(&self) -> u32 {
        self.compression_block_size
    }
}

/// The full pak index: mount point plus all entries.
#[derive(Debug, Clone)]
pub struct PakIndex {
    mount_point: String,
    entries: Vec<PakIndexEntry>,
}

impl PakIndex {
    /// Virtual mount point for paths in this archive.
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// All entries in the archive.
    pub fn entries(&self) -> &[PakIndexEntry] {
        &self.entries
    }

    /// Find an entry by filename.
    pub fn find(&self, path: &str) -> Option<&PakIndexEntry> {
        self.entries.iter().find(|e| e.filename == path)
    }

    /// Read and parse the index from a reader positioned at `index_offset`.
    ///
    /// `index_size` is the byte budget the caller knows the index occupies;
    /// allocations are bounded against it to prevent untrusted-input DoS.
    ///
    /// # Note on version-handling
    ///
    /// Phase 1 parses a flat-entry layout that matches v3-era paks. Real v8+
    /// archives use FName-based compression IDs and v10+ replace the layout
    /// entirely with a path-hash + encoded-directory index. Callers must not
    /// pass v8+ archives until those layouts are implemented; this is enforced
    /// at a higher level by [`crate::container::pak::PakReader::open`].
    pub fn read_from<R: Read>(
        reader: &mut R,
        _version: PakVersion,
        index_size: u64,
    ) -> crate::Result<Self> {
        let mut bounded = reader.take(index_size);
        let mount_point = read_fstring(&mut bounded)?;
        let entry_count = bounded.read_u32::<LittleEndian>()?;

        // Bound entry_count against the actual byte budget so a malicious
        // header claiming u32::MAX entries doesn't trigger an OOM at the
        // Vec::with_capacity call below.
        let max_entries = index_size / ENTRY_MIN_RECORD_BYTES;
        if u64::from(entry_count) > max_entries {
            return Err(PaksmithError::InvalidIndex {
                reason: format!(
                    "entry_count {entry_count} exceeds the maximum {max_entries} \
                     possible in a {index_size}-byte index"
                ),
            });
        }

        let mut entries = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(PakIndexEntry::read_from(&mut bounded)?);
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

        let mut sha1 = [0u8; 20];
        reader.read_exact(&mut sha1)?;

        let has_blocks = compression_method != CompressionMethod::None;
        let compression_blocks = if has_blocks {
            let block_count = reader.read_u32::<LittleEndian>()?;
            if block_count > MAX_BLOCKS_PER_ENTRY {
                return Err(PaksmithError::InvalidIndex {
                    reason: format!(
                        "block_count {block_count} exceeds maximum {MAX_BLOCKS_PER_ENTRY}"
                    ),
                });
            }
            let mut blocks = Vec::with_capacity(block_count as usize);
            for _ in 0..block_count {
                let start = reader.read_u64::<LittleEndian>()?;
                let end = reader.read_u64::<LittleEndian>()?;
                blocks.push(CompressionBlock { start, end });
            }
            blocks
        } else {
            Vec::new()
        };

        let is_encrypted = reader.read_u8()? != 0;

        let compression_block_size = if has_blocks {
            reader.read_u32::<LittleEndian>()?
        } else {
            0
        };

        Ok(Self {
            filename,
            offset,
            compressed_size,
            uncompressed_size,
            compression_method,
            is_encrypted,
            sha1,
            compression_blocks,
            compression_block_size,
        })
    }
}

/// Read an Unreal `FString`.
///
/// Length encoding: a signed `i32` where the sign selects encoding —
/// positive = UTF-8 byte count (including null terminator),
/// negative = UTF-16 code-unit count (including null terminator), absolute value.
/// A value of `0` denotes the empty string.
///
/// Errors out (rather than silently truncating) when the trailing null
/// terminator is missing or when the length exceeds [`FSTRING_MAX_LEN`].
fn read_fstring<R: Read>(reader: &mut R) -> crate::Result<String> {
    let len = reader.read_i32::<LittleEndian>()?;

    if len == 0 {
        return Ok(String::new());
    }

    let Some(abs_len) = len.checked_abs() else {
        // i32::MIN has no positive counterpart; reject.
        return Err(PaksmithError::InvalidIndex {
            reason: "FString length i32::MIN overflows".into(),
        });
    };
    if abs_len > FSTRING_MAX_LEN {
        return Err(PaksmithError::InvalidIndex {
            reason: format!("FString length {abs_len} exceeds maximum {FSTRING_MAX_LEN}"),
        });
    }
    let abs_len = abs_len as usize;

    if len < 0 {
        let mut buf = vec![0u16; abs_len];
        for item in &mut buf {
            *item = reader.read_u16::<LittleEndian>()?;
        }
        match buf.last() {
            Some(&0) => {
                let _ = buf.pop();
            }
            _ => {
                return Err(PaksmithError::InvalidIndex {
                    reason: "UTF-16 FString missing null terminator".into(),
                });
            }
        }
        return String::from_utf16(&buf).map_err(|_| PaksmithError::InvalidIndex {
            reason: "invalid UTF-16 string in index".into(),
        });
    }

    let mut buf = vec![0u8; abs_len];
    reader.read_exact(&mut buf)?;
    match buf.last() {
        Some(&0) => {
            let _ = buf.pop();
        }
        _ => {
            return Err(PaksmithError::InvalidIndex {
                reason: "UTF-8 FString missing null terminator".into(),
            });
        }
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

    fn write_fstring_utf16(buf: &mut Vec<u8>, s: &str) {
        let units: Vec<u16> = s.encode_utf16().collect();
        let total_units = units.len() + 1; // include null terminator
        buf.write_i32::<LittleEndian>(-(total_units as i32))
            .unwrap();
        for u in units {
            buf.write_u16::<LittleEndian>(u).unwrap();
        }
        buf.write_u16::<LittleEndian>(0).unwrap();
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

    #[allow(clippy::too_many_arguments)]
    fn write_compressed_entry(
        buf: &mut Vec<u8>,
        filename: &str,
        offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
        blocks: &[(u64, u64)],
        block_size: u32,
        encrypted: bool,
    ) {
        write_fstring(buf, filename);
        buf.write_u64::<LittleEndian>(offset).unwrap();
        buf.write_u64::<LittleEndian>(compressed_size).unwrap();
        buf.write_u64::<LittleEndian>(uncompressed_size).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]); // SHA1 hash
        buf.write_u32::<LittleEndian>(blocks.len() as u32).unwrap();
        for (start, end) in blocks {
            buf.write_u64::<LittleEndian>(*start).unwrap();
            buf.write_u64::<LittleEndian>(*end).unwrap();
        }
        buf.push(u8::from(encrypted));
        buf.write_u32::<LittleEndian>(block_size).unwrap();
    }

    fn build_index_bytes(mount: &str, entries_writer: impl FnOnce(&mut Vec<u8>) -> u32) -> Vec<u8> {
        let mut data = Vec::new();
        write_fstring(&mut data, mount);
        // Reserve space for entry_count, fill in after.
        let count_pos = data.len();
        data.write_u32::<LittleEndian>(0).unwrap();
        let count = entries_writer(&mut data);
        data[count_pos..count_pos + 4].copy_from_slice(&count.to_le_bytes());
        data
    }

    #[test]
    fn parse_index_single_entry() {
        let data = build_index_bytes("../../../", |buf| {
            write_uncompressed_entry(buf, "Content/Textures/hero.uasset", 0, 1024);
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();

        assert_eq!(index.mount_point(), "../../../");
        assert_eq!(index.entries().len(), 1);
        let e = &index.entries()[0];
        assert_eq!(e.filename(), "Content/Textures/hero.uasset");
        assert_eq!(e.uncompressed_size(), 1024);
        assert_eq!(e.compression_method(), CompressionMethod::None);
        assert!(!e.is_encrypted());
        assert!(e.compression_blocks().is_empty());
        assert_eq!(e.compression_block_size(), 0);
    }

    #[test]
    fn parse_index_multiple_entries() {
        let data = build_index_bytes("../../../", |buf| {
            write_uncompressed_entry(buf, "Content/a.uasset", 0, 100);
            write_uncompressed_entry(buf, "Content/b.uasset", 100, 200);
            write_uncompressed_entry(buf, "Content/c.uasset", 300, 50);
            3
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();

        assert_eq!(index.entries().len(), 3);
        assert_eq!(index.entries()[0].filename(), "Content/a.uasset");
        assert_eq!(index.entries()[1].filename(), "Content/b.uasset");
        assert_eq!(index.entries()[2].filename(), "Content/c.uasset");
        assert_eq!(index.entries()[2].uncompressed_size(), 50);
    }

    #[test]
    fn parse_empty_index() {
        let data = build_index_bytes("../../../", |_| 0);
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();

        assert_eq!(index.entries().len(), 0);
        assert_eq!(index.mount_point(), "../../../");
    }

    #[test]
    fn parse_compressed_entry_preserves_blocks() {
        let data = build_index_bytes("../../../", |buf| {
            write_compressed_entry(
                buf,
                "Content/big.uasset",
                100,
                4096,
                8192,
                &[(0, 2048), (2048, 4096)],
                65_536,
                false,
            );
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();

        let entry = &index.entries()[0];
        assert_eq!(entry.compression_method(), CompressionMethod::Zlib);
        assert_eq!(entry.compressed_size(), 4096);
        assert_eq!(entry.uncompressed_size(), 8192);
        assert_eq!(
            entry.compression_blocks(),
            &[
                CompressionBlock {
                    start: 0,
                    end: 2048
                },
                CompressionBlock {
                    start: 2048,
                    end: 4096
                },
            ]
        );
        assert_eq!(entry.compression_block_size(), 65_536);
        assert!(!entry.is_encrypted());
    }

    #[test]
    fn parse_encrypted_entry_flag() {
        let data = build_index_bytes("../../../", |buf| {
            write_compressed_entry(
                buf,
                "Content/secret.uasset",
                0,
                512,
                512,
                &[(0, 512)],
                65_536,
                true,
            );
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();
        assert!(index.entries()[0].is_encrypted());
    }

    #[test]
    fn parse_utf16_fstring_roundtrip() {
        let data = build_index_bytes("../../../", |buf| {
            write_fstring_utf16(buf, "Content/Maps/レベル.umap");
            buf.write_u64::<LittleEndian>(0).unwrap();
            buf.write_u64::<LittleEndian>(64).unwrap();
            buf.write_u64::<LittleEndian>(64).unwrap();
            buf.write_u32::<LittleEndian>(0).unwrap();
            buf.extend_from_slice(&[0u8; 20]);
            buf.push(0);
            1
        });
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let index = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap();
        assert_eq!(index.entries()[0].filename(), "Content/Maps/レベル.umap");
    }

    #[test]
    fn reject_oversized_fstring() {
        let mut data = Vec::new();
        // Mount point: claim length of 1MB, but provide nothing.
        data.write_i32::<LittleEndian>(1_000_000).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidIndex { .. }));
    }

    #[test]
    fn reject_fstring_missing_null_terminator() {
        let mut data = Vec::new();
        // Length 4 (claims null-terminated 3-byte string), bytes are not null-terminated.
        data.write_i32::<LittleEndian>(4).unwrap();
        data.extend_from_slice(b"abcd"); // last byte is 'd', not 0
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("null terminator"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn reject_oversized_entry_count() {
        // Tiny budget, claim huge entry_count.
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(u32::MAX).unwrap();
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidIndex { .. }));
    }

    #[test]
    fn reject_oversized_block_count() {
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(1).unwrap();
        write_fstring(&mut data, "x");
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u32::<LittleEndian>(1).unwrap(); // zlib
        data.extend_from_slice(&[0u8; 20]);
        data.write_u32::<LittleEndian>(u32::MAX).unwrap(); // huge block count
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err = PakIndex::read_from(&mut cursor, PakVersion::Fnv64BugFix, len).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidIndex { .. }));
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
