//! Pak file index and entry parsing.

use std::fmt::Write as _;
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
    start: u64,
    end: u64,
}

impl CompressionBlock {
    /// Construct a block, rejecting `start > end` as malformed.
    pub fn new(start: u64, end: u64) -> crate::Result<Self> {
        if start > end {
            return Err(PaksmithError::InvalidIndex {
                reason: format!("compression block start {start} exceeds end {end}"),
            });
        }
        Ok(Self { start, end })
    }

    /// Start offset (inclusive) of the compressed block.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// End offset (exclusive) of the compressed block.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Length of the block in bytes.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Whether the block is empty.
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// The serialized `FPakEntry` record (offset, sizes, compression metadata,
/// SHA1, encrypted flag, compression-block layout).
///
/// This struct appears in two places on disk:
/// 1. In the index, after the entry's filename FString.
/// 2. In the entry's data section, immediately before the payload bytes (the
///    "in-data" copy). The in-data copy's `offset` field is written as `0`
///    (a self-reference convention — the header IS at that offset), which is
///    why cross-validation [`PakEntryHeader::matches_payload`] skips it.
///
/// Both copies have an identical wire format; they are parsed by the same
/// [`PakEntryHeader::read_from`].
#[derive(Debug, Clone)]
pub struct PakEntryHeader {
    offset: u64,
    compressed_size: u64,
    uncompressed_size: u64,
    compression_method: CompressionMethod,
    is_encrypted: bool,
    sha1: [u8; 20],
    compression_blocks: Vec<CompressionBlock>,
    compression_block_size: u32,
}

impl PakEntryHeader {
    /// Read the FPakEntry struct from the current reader position.
    ///
    /// Wire format (v3–v7):
    /// - `offset: u64`
    /// - `compressed_size: u64`
    /// - `uncompressed_size: u64`
    /// - `compression_method: u32`
    /// - `sha1: [u8; 20]`
    /// - if `compression_method != None`:
    ///     - `block_count: u32`, then `block_count` × `(start: u64, end: u64)`
    /// - `is_encrypted: u8`
    /// - **`compression_block_size: u32`** — present for ALL v3+ entries,
    ///   not just compressed ones. Real UE writers emit this field
    ///   unconditionally (with value 0 for uncompressed). Until #14's
    ///   cross-parser fixtures landed, this code skipped this field for
    ///   uncompressed entries — bug shared with the synthetic generator
    ///   and invisible to round-trip tests.
    ///
    /// v1/v2 archives use a different shape (with a `timestamp: u64` field
    /// pre-v2 and without the trailing `flags + block_size`). [`PakReader`]
    /// rejects them at `open()`; this function assumes v3+ layout.
    pub fn read_from<R: Read>(reader: &mut R) -> crate::Result<Self> {
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
                blocks.push(CompressionBlock::new(start, end)?);
            }
            blocks
        } else {
            Vec::new()
        };

        let is_encrypted = reader.read_u8()? != 0;

        // Always present in v3+, regardless of compression. Stored as 0 for
        // uncompressed entries.
        let compression_block_size = reader.read_u32::<LittleEndian>()?;

        Ok(Self {
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

    /// Cross-validate this header (parsed from the entry's data section)
    /// against the index entry's header. Returns `Err(InvalidIndex)` if any
    /// integrity-relevant field disagrees.
    ///
    /// Skips the `offset` field — UE writes the in-data copy's offset as `0`
    /// (self-reference), so it intentionally won't match the index value.
    /// Every other field, including the full compression-block layout, must
    /// agree. Block layout matters because the reader relies on it to seek
    /// past the in-data record into the payload region; a mismatch here would
    /// silently shift the payload boundary.
    pub fn matches_payload(&self, payload: &Self, path: &str) -> crate::Result<()> {
        let mismatch = |field: &str, idx: String, dat: String| PaksmithError::InvalidIndex {
            reason: format!("in-data header mismatch for `{path}`: {field} index={idx} data={dat}"),
        };
        if self.compressed_size != payload.compressed_size {
            return Err(mismatch(
                "compressed_size",
                self.compressed_size.to_string(),
                payload.compressed_size.to_string(),
            ));
        }
        if self.uncompressed_size != payload.uncompressed_size {
            return Err(mismatch(
                "uncompressed_size",
                self.uncompressed_size.to_string(),
                payload.uncompressed_size.to_string(),
            ));
        }
        if self.compression_method != payload.compression_method {
            return Err(mismatch(
                "compression_method",
                format!("{:?}", self.compression_method),
                format!("{:?}", payload.compression_method),
            ));
        }
        if self.is_encrypted != payload.is_encrypted {
            return Err(mismatch(
                "is_encrypted",
                self.is_encrypted.to_string(),
                payload.is_encrypted.to_string(),
            ));
        }
        if self.sha1 != payload.sha1 {
            return Err(mismatch(
                "sha1",
                hex_short(&self.sha1),
                hex_short(&payload.sha1),
            ));
        }
        if self.compression_blocks != payload.compression_blocks {
            // Surface enough detail to debug the mismatch: count first, then
            // the first differing block when counts agree.
            let (lhs_desc, rhs_desc) = match self
                .compression_blocks
                .len()
                .cmp(&payload.compression_blocks.len())
            {
                std::cmp::Ordering::Equal => {
                    let first_diff = self
                        .compression_blocks
                        .iter()
                        .zip(payload.compression_blocks.iter())
                        .position(|(a, b)| a != b)
                        .unwrap_or(0);
                    let lhs_block = self.compression_blocks[first_diff];
                    let rhs_block = payload.compression_blocks[first_diff];
                    (
                        format!(
                            "block[{first_diff}]={}..{}",
                            lhs_block.start(),
                            lhs_block.end()
                        ),
                        format!(
                            "block[{first_diff}]={}..{}",
                            rhs_block.start(),
                            rhs_block.end()
                        ),
                    )
                }
                _ => (
                    format!("{} blocks", self.compression_blocks.len()),
                    format!("{} blocks", payload.compression_blocks.len()),
                ),
            };
            return Err(mismatch("compression_blocks", lhs_desc, rhs_desc));
        }
        if self.compression_block_size != payload.compression_block_size {
            return Err(mismatch(
                "compression_block_size",
                self.compression_block_size.to_string(),
                payload.compression_block_size.to_string(),
            ));
        }
        Ok(())
    }

    /// On-disk wire size of this FPakEntry record in bytes — i.e., the number
    /// of bytes that [`PakEntryHeader::read_from`] consumed when producing
    /// `self`. Single source of truth for both producers (fixture generator)
    /// and consumers (payload-offset arithmetic in `PakReader::read_entry`).
    ///
    /// Layout (v3+):
    /// - 48 bytes common: offset(8) + compressed(8) + uncompressed(8) +
    ///   compression_method(4) + sha1(20)
    /// - if compressed: block_count(4) + N × (start(8) + end(8))
    /// - 5 bytes always-present trailer: is_encrypted(1) + block_size(4)
    pub fn wire_size(&self) -> u64 {
        let mut size: u64 = 8 + 8 + 8 + 4 + 20;
        if self.compression_method != CompressionMethod::None {
            size += 4 + (self.compression_blocks.len() as u64) * 16;
        }
        // Trailer: is_encrypted u8 + compression_block_size u32. The block
        // size is always written (with value 0 for uncompressed entries),
        // not just when compression_blocks is non-empty.
        size += 1 + 4;
        size
    }

    /// Byte offset stored in this header. For index headers this is the file
    /// offset of the entry's record. For in-data headers UE writes it as `0`
    /// (self-reference), so callers should not rely on it for in-data copies.
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

fn hex_short(bytes: &[u8; 20]) -> String {
    let mut s = String::with_capacity(20);
    for b in bytes.iter().take(8) {
        // Infallible — String's Write impl never errors.
        let _ = write!(s, "{b:02x}");
    }
    s.push_str("...");
    s
}

/// A single entry in the pak index: filename plus the FPakEntry header.
#[derive(Debug, Clone)]
pub struct PakIndexEntry {
    filename: String,
    header: PakEntryHeader,
}

impl PakIndexEntry {
    /// Path of this entry within the archive.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// The FPakEntry record metadata for this entry.
    pub fn header(&self) -> &PakEntryHeader {
        &self.header
    }

    /// Byte offset of the entry record header in the archive.
    ///
    /// **Note:** the actual payload begins after the duplicate FPakEntry
    /// record at this offset, not at the offset itself. Use
    /// [`crate::container::pak::PakReader::read_entry`] to get payload bytes.
    pub fn offset(&self) -> u64 {
        self.header.offset
    }

    /// Compressed size in bytes (equals `uncompressed_size` when uncompressed).
    pub fn compressed_size(&self) -> u64 {
        self.header.compressed_size
    }

    /// Uncompressed size in bytes.
    pub fn uncompressed_size(&self) -> u64 {
        self.header.uncompressed_size
    }

    /// Compression method applied to this entry.
    pub fn compression_method(&self) -> CompressionMethod {
        self.header.compression_method
    }

    /// Whether this entry's data is AES-encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.header.is_encrypted
    }

    /// SHA1 hash of the entry's stored bytes (kept for future verification).
    pub fn sha1(&self) -> &[u8; 20] {
        &self.header.sha1
    }

    /// Compression block boundaries (empty when uncompressed).
    pub fn compression_blocks(&self) -> &[CompressionBlock] {
        &self.header.compression_blocks
    }

    /// Compression block size in bytes (0 when uncompressed).
    pub fn compression_block_size(&self) -> u32 {
        self.header.compression_block_size
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
        let header = PakEntryHeader::read_from(reader)?;
        Ok(Self { filename, header })
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
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)
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
                CompressionBlock::new(0, 2048).unwrap(),
                CompressionBlock::new(2048, 4096).unwrap(),
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
            buf.push(0); // is_encrypted
            buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)
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
        match err {
            PaksmithError::InvalidIndex { reason } => {
                // Pin the size-cap branch specifically.
                assert!(
                    reason.contains("FString length") && reason.contains("maximum"),
                    "expected FString length cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
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
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(
                    reason.contains("entry_count"),
                    "expected entry_count cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn reject_compression_block_start_after_end() {
        let mut data = Vec::new();
        write_fstring(&mut data, "/");
        data.write_u32::<LittleEndian>(1).unwrap();
        write_fstring(&mut data, "x");
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u64::<LittleEndian>(0).unwrap();
        data.write_u32::<LittleEndian>(1).unwrap(); // zlib
        data.extend_from_slice(&[0u8; 20]);
        data.write_u32::<LittleEndian>(1).unwrap(); // 1 block
        data.write_u64::<LittleEndian>(100).unwrap(); // start
        data.write_u64::<LittleEndian>(50).unwrap(); // end < start
        data.push(0); // not encrypted
        data.write_u32::<LittleEndian>(65_536).unwrap(); // block size
        let len = data.len() as u64;
        let mut cursor = Cursor::new(data);
        let err = PakIndex::read_from(&mut cursor, PakVersion::DeleteRecords, len).unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("start"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn compression_block_constructor_rejects_inverted_range() {
        let err = CompressionBlock::new(100, 50).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidIndex { .. }));
    }

    #[test]
    fn compression_block_len_and_is_empty() {
        let b = CompressionBlock::new(10, 30).unwrap();
        assert_eq!(b.len(), 20);
        assert!(!b.is_empty());

        let empty = CompressionBlock::new(5, 5).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
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
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(
                    reason.contains("block_count"),
                    "expected block_count cap error, got: {reason}"
                );
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
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

    #[test]
    fn pak_entry_header_round_trip_uncompressed() {
        let mut buf = Vec::new();
        // Inline (no helper — keep this test self-contained).
        buf.write_u64::<LittleEndian>(0).unwrap(); // offset
        buf.write_u64::<LittleEndian>(100).unwrap(); // compressed
        buf.write_u64::<LittleEndian>(100).unwrap(); // uncompressed
        buf.write_u32::<LittleEndian>(0).unwrap(); // none
        buf.extend_from_slice(&[0xABu8; 20]); // sha1
        buf.push(0); // not encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)

        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor).unwrap();

        assert_eq!(header.offset(), 0);
        assert_eq!(header.compressed_size(), 100);
        assert_eq!(header.uncompressed_size(), 100);
        assert_eq!(header.compression_method(), CompressionMethod::None);
        assert_eq!(header.sha1(), &[0xABu8; 20]);
        assert!(!header.is_encrypted());
        assert!(header.compression_blocks().is_empty());
        assert_eq!(header.compression_block_size(), 0);
    }

    #[test]
    fn pak_entry_header_round_trip_compressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(50).unwrap();
        buf.write_u64::<LittleEndian>(200).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(2).unwrap(); // 2 blocks
        buf.write_u64::<LittleEndian>(73).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(123).unwrap();
        buf.push(1); // encrypted
        buf.write_u32::<LittleEndian>(100).unwrap(); // block size

        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor).unwrap();

        assert_eq!(header.compression_method(), CompressionMethod::Zlib);
        assert!(header.is_encrypted());
        assert_eq!(header.compression_blocks().len(), 2);
        assert_eq!(
            header.compression_blocks()[0],
            CompressionBlock::new(73, 98).unwrap()
        );
        assert_eq!(header.compression_block_size(), 100);
    }

    fn make_header(compressed_size: u64, uncompressed_size: u64, sha1: [u8; 20]) -> PakEntryHeader {
        PakEntryHeader {
            offset: 0,
            compressed_size,
            uncompressed_size,
            compression_method: CompressionMethod::None,
            is_encrypted: false,
            sha1,
            compression_blocks: Vec::new(),
            compression_block_size: 0,
        }
    }

    #[test]
    fn matches_payload_accepts_identical_modulo_offset() {
        // The offset field intentionally differs (index = real, in-data = 0)
        // and matches_payload should not flag it.
        let index = PakEntryHeader {
            offset: 1024,
            ..make_header(50, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            offset: 0,
            ..make_header(50, 100, [0xAA; 20])
        };
        assert!(index.matches_payload(&in_data, "x").is_ok());
    }

    #[test]
    fn matches_payload_rejects_size_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = make_header(50, 999, [0xAA; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("uncompressed_size"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_sha1_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = make_header(50, 100, [0xBB; 20]);
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("sha1"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_method_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::None,
            ..make_header(100, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            ..make_header(100, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("compression_method"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_is_encrypted_mismatch() {
        let index = make_header(50, 100, [0xAA; 20]);
        let in_data = PakEntryHeader {
            is_encrypted: true,
            ..make_header(50, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("is_encrypted"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_blocks_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![
                CompressionBlock::new(73, 86).unwrap(),
                CompressionBlock::new(86, 100).unwrap(),
            ],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("compression_blocks"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn matches_payload_rejects_compression_block_size_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 65_536,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("compression_block_size"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }

    #[test]
    fn wire_size_uncompressed_is_53() {
        let h = make_header(100, 100, [0; 20]);
        // 48 common + 5 trailer (encrypted u8 + block_size u32, both
        // always present in v3+) = 53.
        assert_eq!(h.wire_size(), 53);
    }

    #[test]
    fn wire_size_compressed_includes_blocks() {
        let h = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![
                CompressionBlock::new(0, 50).unwrap(),
                CompressionBlock::new(50, 100).unwrap(),
            ],
            compression_block_size: 100,
            ..make_header(100, 200, [0; 20])
        };
        // 48 common + 4 (block_count) + 2 * 16 (blocks) + 5 trailer = 89
        assert_eq!(h.wire_size(), 89);
    }

    /// Invariant: `wire_size()` must equal the number of bytes `read_from`
    /// actually consumes from the reader. This is the load-bearing property
    /// the rest of the parser relies on for payload-offset arithmetic; if
    /// these two formulas drift, every multi-block decompression silently
    /// reads from the wrong file position.
    #[test]
    fn wire_size_matches_bytes_consumed_by_read_from_uncompressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u64::<LittleEndian>(100).unwrap();
        buf.write_u32::<LittleEndian>(0).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        buf.push(0); // is_encrypted
        buf.write_u32::<LittleEndian>(0).unwrap(); // block_size (always v3+)

        let total = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor).unwrap();
        assert_eq!(
            cursor.position(),
            total,
            "read_from did not consume all bytes"
        );
        assert_eq!(
            header.wire_size(),
            total,
            "wire_size disagrees with read_from's actual consumption"
        );
    }

    #[test]
    fn wire_size_matches_bytes_consumed_by_read_from_compressed() {
        let mut buf = Vec::new();
        buf.write_u64::<LittleEndian>(0).unwrap();
        buf.write_u64::<LittleEndian>(50).unwrap();
        buf.write_u64::<LittleEndian>(200).unwrap();
        buf.write_u32::<LittleEndian>(1).unwrap(); // zlib
        buf.extend_from_slice(&[0u8; 20]);
        buf.write_u32::<LittleEndian>(2).unwrap();
        buf.write_u64::<LittleEndian>(73).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(98).unwrap();
        buf.write_u64::<LittleEndian>(123).unwrap();
        buf.push(0);
        buf.write_u32::<LittleEndian>(100).unwrap();

        let total = buf.len() as u64;
        let mut cursor = Cursor::new(buf);
        let header = PakEntryHeader::read_from(&mut cursor).unwrap();
        assert_eq!(cursor.position(), total);
        assert_eq!(header.wire_size(), total);
    }

    /// Tighter regression test for `compression_blocks` mismatch detection.
    /// The previous test only varied length; this one keeps length identical
    /// and varies a single block's `end`. A `len()`-only comparison would
    /// silently pass this case.
    #[test]
    fn matches_payload_rejects_compression_blocks_content_mismatch() {
        let index = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            compression_blocks: vec![CompressionBlock::new(73, 100).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let in_data = PakEntryHeader {
            compression_method: CompressionMethod::Zlib,
            // Same count, different end offset.
            compression_blocks: vec![CompressionBlock::new(73, 99).unwrap()],
            compression_block_size: 100,
            ..make_header(27, 100, [0xAA; 20])
        };
        let err = index.matches_payload(&in_data, "x").unwrap_err();
        match err {
            PaksmithError::InvalidIndex { reason } => {
                assert!(reason.contains("compression_blocks"), "got: {reason}");
                // The improved error message includes the block index and
                // both offsets — pin that detail so future changes preserve
                // the diagnostic.
                assert!(reason.contains("block[0]"), "got: {reason}");
            }
            other => panic!("expected InvalidIndex, got {other:?}"),
        }
    }
}
