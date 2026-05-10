//! Pak file footer parsing.

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use tracing::debug;

use crate::container::pak::version::{
    FOOTER_SIZE_LEGACY, FOOTER_SIZE_V7_PLUS, PAK_MAGIC, PakVersion,
};
use crate::error::PaksmithError;

/// Parsed pak file footer containing archive metadata.
#[derive(Debug, Clone)]
pub struct PakFooter {
    version: PakVersion,
    index_offset: u64,
    index_size: u64,
    index_hash: [u8; 20],
    encrypted: bool,
    encryption_key_guid: Option<[u8; 16]>,
}

impl PakFooter {
    /// Format version of this pak file.
    pub fn version(&self) -> PakVersion {
        self.version
    }

    /// Byte offset where the index begins.
    pub fn index_offset(&self) -> u64 {
        self.index_offset
    }

    /// Size of the index in bytes.
    pub fn index_size(&self) -> u64 {
        self.index_size
    }

    /// SHA1 hash of the index data (kept for future verification).
    pub fn index_hash(&self) -> &[u8; 20] {
        &self.index_hash
    }

    /// Whether the index is encrypted.
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// Encryption key GUID (present in v7+ archives).
    pub fn encryption_key_guid(&self) -> Option<&[u8; 16]> {
        self.encryption_key_guid.as_ref()
    }

    /// Read and parse the footer from the end of a seekable stream.
    ///
    /// Dispatch is by version, not by trial-and-error: read the version field
    /// at the v7+ offset, dispatch to the v7+ parser if `version >= 7`,
    /// otherwise dispatch to the legacy parser. This avoids silently masking
    /// real v7+ parse errors as legacy failures.
    pub fn read_from<R: Read + Seek>(reader: &mut R) -> crate::Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;

        // Probe the version field at the v7+ offset (12 bytes from end of footer:
        // 4 magic + 4 version, where v7+ footer is 61 bytes).
        if file_size >= FOOTER_SIZE_V7_PLUS {
            let _ = reader.seek(SeekFrom::End(-(FOOTER_SIZE_V7_PLUS as i64)))?;
            let v7_magic = reader.read_u32::<LittleEndian>()?;
            let v7_version_raw = reader.read_u32::<LittleEndian>()?;
            if v7_magic == PAK_MAGIC {
                if let Ok(version) = PakVersion::try_from(v7_version_raw) {
                    if version.has_encryption_key_guid() {
                        debug!(?version, "dispatching to v7+ footer parser");
                        return Self::read_v7_plus(reader, version);
                    }
                }
                debug!(
                    v7_version_raw,
                    "v7+ offset matched magic but version is legacy; falling back"
                );
            }
        }

        if file_size < FOOTER_SIZE_LEGACY {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("file too small ({file_size} bytes) for any pak footer"),
            });
        }

        let _ = reader.seek(SeekFrom::End(-(FOOTER_SIZE_LEGACY as i64)))?;
        let footer = Self::read_legacy(reader)?;
        Self::validate_index_bounds(&footer, file_size)?;
        Ok(footer)
    }

    /// Read v7+ footer from the current reader position. The version field has
    /// already been validated and consumed by [`PakFooter::read_from`].
    fn read_v7_plus<R: Read + Seek>(reader: &mut R, version: PakVersion) -> crate::Result<Self> {
        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        let mut encryption_key_guid = [0u8; 16];
        reader.read_exact(&mut encryption_key_guid)?;

        let encrypted = reader.read_u8()? != 0;

        let footer = Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted,
            encryption_key_guid: Some(encryption_key_guid),
        };

        let file_size = reader.seek(SeekFrom::End(0))?;
        Self::validate_index_bounds(&footer, file_size)?;
        Ok(footer)
    }

    fn read_legacy<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"),
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version = PakVersion::try_from(version_raw)?;

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        Ok(Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted: false,
            encryption_key_guid: None,
        })
    }

    fn validate_index_bounds(footer: &Self, file_size: u64) -> crate::Result<()> {
        let end = footer.index_offset.checked_add(footer.index_size).ok_or(
            PaksmithError::InvalidFooter {
                reason: "index_offset + index_size overflows u64".into(),
            },
        )?;
        if end > file_size {
            return Err(PaksmithError::InvalidFooter {
                reason: format!(
                    "index extends past EOF: offset={} size={} file_size={}",
                    footer.index_offset, footer.index_size, file_size
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::WriteBytesExt;

    use super::*;

    fn build_v11_footer(index_offset: u64, index_size: u64, payload_bytes: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);

        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(11).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        buf.extend_from_slice(&[0u8; 16]);
        buf.push(0);
        buf
    }

    fn build_legacy_footer(
        version: u32,
        index_offset: u64,
        index_size: u64,
        payload_bytes: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);

        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(version).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        buf
    }

    #[test]
    fn parse_v11_footer() {
        let data = build_v11_footer(0, 0, 100);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::Fnv64BugFix);
        assert_eq!(footer.index_offset(), 0);
        assert_eq!(footer.index_size(), 0);
        assert!(!footer.is_encrypted());
        assert!(footer.encryption_key_guid().is_some());
    }

    #[test]
    fn parse_legacy_v3_footer() {
        let data = build_legacy_footer(3, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::CompressionEncryption);
        assert!(!footer.is_encrypted());
        assert!(footer.encryption_key_guid().is_none());
    }

    #[test]
    fn legacy_footer_in_file_large_enough_for_v7_is_not_misread() {
        // File >= 61 bytes (so v7+ probe runs) but actually a legacy v3 footer.
        // The v7+ probe reads bytes from `file_end - 61` through `file_end - 53`
        // looking for magic. For a legacy file, those bytes are payload, not magic.
        // The v7+ probe must reject and fall through to legacy.
        let data = build_legacy_footer(3, 0, 0, 200);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();
        assert_eq!(footer.version(), PakVersion::CompressionEncryption);
        assert!(footer.encryption_key_guid().is_none());
    }

    #[test]
    fn reject_bad_magic() {
        let mut data = build_v11_footer(0, 0, 100);
        let footer_start = data.len() - FOOTER_SIZE_V7_PLUS as usize;
        data[footer_start] = 0xFF;
        // Corrupt legacy magic too so neither parser accepts it.
        let legacy_start = data.len() - FOOTER_SIZE_LEGACY as usize;
        data[legacy_start] = 0xFF;

        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_unsupported_version_in_legacy_footer() {
        let data = build_legacy_footer(99, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(
            err,
            PaksmithError::UnsupportedVersion { version: 99 }
        ));
    }

    #[test]
    fn reject_file_too_small() {
        let data = vec![0u8; 10];
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_index_past_eof() {
        // File size 200 bytes, claim index extends beyond.
        let data = build_v11_footer(150, 1000, 100);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        match err {
            PaksmithError::InvalidFooter { reason } => {
                assert!(reason.contains("past EOF"), "got: {reason}");
            }
            other => panic!("expected InvalidFooter, got {other:?}"),
        }
    }

    #[test]
    fn reject_index_bounds_overflow() {
        // index_offset + index_size overflows u64.
        let data = build_v11_footer(u64::MAX - 10, 100, 100);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        match err {
            PaksmithError::InvalidFooter { reason } => {
                assert!(reason.contains("overflow"), "got: {reason}");
            }
            other => panic!("expected InvalidFooter, got {other:?}"),
        }
    }
}
