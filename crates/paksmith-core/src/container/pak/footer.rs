//! Pak file footer parsing.

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::container::pak::version::{PAK_MAGIC, PakVersion};
use crate::error::PaksmithError;

/// Parsed pak file footer containing archive metadata.
#[derive(Debug, Clone)]
pub struct PakFooter {
    /// Format version of this pak file.
    pub version: PakVersion,
    /// Byte offset where the index begins.
    pub index_offset: u64,
    /// Size of the index in bytes.
    pub index_size: u64,
    /// SHA1 hash of the index data.
    pub index_hash: [u8; 20],
    /// Whether the index is encrypted.
    pub encrypted: bool,
    /// Encryption key GUID (present in v7+).
    pub encryption_key_guid: Option<[u8; 16]>,
}

impl PakFooter {
    /// Read and parse the footer from the end of a seekable stream.
    pub fn read_from<R: Read + Seek>(reader: &mut R) -> crate::Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;

        // Try v7+ footer first (larger)
        let v7_footer_size = PakVersion::EncryptionKeyGuid.footer_size();
        if file_size >= v7_footer_size {
            let _ = reader.seek(SeekFrom::End(-(v7_footer_size as i64)))?;
            if let Ok(footer) = Self::try_read_v7_plus(reader) {
                return Ok(footer);
            }
        }

        // Fall back to legacy footer
        let legacy_footer_size = PakVersion::Initial.footer_size();
        if file_size < legacy_footer_size {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("file too small ({file_size} bytes) for pak footer"),
            });
        }

        let _ = reader.seek(SeekFrom::End(-(legacy_footer_size as i64)))?;
        Self::try_read_legacy(reader)
    }

    fn try_read_v7_plus<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"),
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version =
            PakVersion::from_u32(version_raw).ok_or(PaksmithError::UnsupportedVersion {
                version: version_raw,
            })?;

        if !version.has_encryption_key_guid() {
            return Err(PaksmithError::InvalidFooter {
                reason: "not a v7+ footer".into(),
            });
        }

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        let mut encryption_key_guid = [0u8; 16];
        reader.read_exact(&mut encryption_key_guid)?;

        let encrypted = reader.read_u8()? != 0;

        Ok(Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted,
            encryption_key_guid: Some(encryption_key_guid),
        })
    }

    fn try_read_legacy<R: Read>(reader: &mut R) -> crate::Result<Self> {
        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"),
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version =
            PakVersion::from_u32(version_raw).ok_or(PaksmithError::UnsupportedVersion {
                version: version_raw,
            })?;

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
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::WriteBytesExt;

    use super::*;

    fn build_v11_footer(index_offset: u64, index_size: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAA; 100]);

        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(11).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index hash
        buf.extend_from_slice(&[0u8; 16]); // encryption GUID
        buf.push(0); // not encrypted
        buf
    }

    fn build_legacy_footer(version: u32, index_offset: u64, index_size: u64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xAA; 100]);

        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(version).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index hash
        buf
    }

    #[test]
    fn parse_v11_footer() {
        let data = build_v11_footer(1024, 256);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version, PakVersion::Fnv64BugFix);
        assert_eq!(footer.index_offset, 1024);
        assert_eq!(footer.index_size, 256);
        assert!(!footer.encrypted);
        assert!(footer.encryption_key_guid.is_some());
    }

    #[test]
    fn parse_legacy_v3_footer() {
        let data = build_legacy_footer(3, 512, 128);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version, PakVersion::CompressionEncryption);
        assert_eq!(footer.index_offset, 512);
        assert_eq!(footer.index_size, 128);
        assert!(!footer.encrypted);
        assert!(footer.encryption_key_guid.is_none());
    }

    #[test]
    fn reject_bad_magic() {
        let mut data = build_v11_footer(0, 0);
        let footer_start = data.len() - 61;
        data[footer_start] = 0xFF;

        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_unsupported_version() {
        let mut data = build_legacy_footer(99, 0, 0);
        let footer_start = data.len() - 44;
        data[footer_start + 4] = 99;
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(
            matches!(err, PaksmithError::UnsupportedVersion { version: 99 })
                || matches!(err, PaksmithError::InvalidFooter { .. })
        );
    }

    #[test]
    fn reject_file_too_small() {
        let data = vec![0u8; 10];
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }
}
