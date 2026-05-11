//! Pak file footer parsing.

use std::io::{Read, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};
use tracing::debug;

use crate::container::pak::index::CompressionMethod;
use crate::container::pak::version::{
    COMPRESSION_SLOT_BYTES, COMPRESSION_SLOTS_V8A, COMPRESSION_SLOTS_V8B_PLUS, FOOTER_SIZE_LEGACY,
    FOOTER_SIZE_V7_PLUS, FOOTER_SIZE_V8A, FOOTER_SIZE_V8B_PLUS, FOOTER_SIZE_V9, PAK_MAGIC,
    PakVersion,
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
    /// V9 only: a writer flag indicating the index was frozen at archive
    /// creation. We surface it for round-trip introspection but the parser
    /// treats frozen identically to non-frozen.
    frozen_index: bool,
    /// V8+ compression-method FName table. Length is 0 (v3-v7), 4 (V8A),
    /// or 5 (V8B / V9 / V10 / V11). Slot index 0 in this vec maps to
    /// per-entry compression byte value 1 (the on-disk convention is
    /// 1-based; byte 0 means "no compression" and skips the table).
    /// Empty slots — and slots holding unrecognized FName strings — are
    /// `None`.
    compression_methods: Vec<Option<CompressionMethod>>,
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

    /// V9-only writer flag indicating the index was frozen at archive
    /// creation. Always `false` for v3-v8 and v10+.
    pub fn frozen_index(&self) -> bool {
        self.frozen_index
    }

    /// V8+ compression-method FName table. Empty for v3-v7. The on-disk
    /// per-entry compression byte is a 1-based index into this slice
    /// (with 0 meaning "no compression"); resolution lives in
    /// [`crate::container::pak::index::PakEntryHeader::read_from`].
    pub fn compression_methods(&self) -> &[Option<CompressionMethod>] {
        &self.compression_methods
    }

    /// Read and parse the footer from the end of a seekable stream.
    ///
    /// Dispatch is **size-then-version**: probe candidate footer sizes from
    /// largest to smallest, validate magic + version field at each, and
    /// dispatch to the appropriate parser on the first match. The size
    /// candidates are mutually exclusive given a version-field check, so
    /// the procedure is unambiguous despite v8 and v10/v11 sharing the
    /// 221-byte size (their version fields differ).
    ///
    /// Larger footers come first so a v9 file isn't misread as v8b
    /// (v9 = v8b + 1 frozen byte; if we tried v8b first the frozen byte
    /// would be parsed as part of the encryption_uuid in the next attempt).
    pub fn read_from<R: Read + Seek>(reader: &mut R) -> crate::Result<Self> {
        let file_size = reader.seek(SeekFrom::End(0))?;

        // Each candidate: (footer_size, expected_version_field_values, label).
        // Probed in this order; first matching size + version wins.
        let candidates: &[(u64, &[u32], &str)] = &[
            (FOOTER_SIZE_V9, &[9], "v9"),
            (FOOTER_SIZE_V8B_PLUS, &[8, 10, 11], "v8b/v10/v11"),
            (FOOTER_SIZE_V8A, &[8], "v8a"),
            (FOOTER_SIZE_V7_PLUS, &[7], "v7"),
            (FOOTER_SIZE_LEGACY, &[1, 2, 3, 4, 5, 6], "legacy"),
        ];

        for &(size, expected_versions, label) in candidates {
            if file_size < size {
                continue;
            }
            let _ = reader.seek(SeekFrom::End(-(size as i64)))?;
            // Legacy footer: magic at offset 0, version at offset 4.
            // V7+ footers: encryption_uuid(16) + encrypted(1) precedes magic
            // at offset 17, version at offset 21. Detect by candidate size.
            let (probe_offset_for_magic, is_v7_plus) = if size == FOOTER_SIZE_LEGACY {
                (0u64, false)
            } else {
                (17u64, true)
            };
            let _ = reader.seek(SeekFrom::End(
                -(size as i64 - probe_offset_for_magic as i64),
            ))?;
            let probe_magic = reader.read_u32::<LittleEndian>()?;
            let probe_version = reader.read_u32::<LittleEndian>()?;
            if probe_magic == PAK_MAGIC && expected_versions.contains(&probe_version) {
                debug!(label, version = probe_version, "matched footer candidate");
                let _ = reader.seek(SeekFrom::End(-(size as i64)))?;
                let footer = if is_v7_plus {
                    Self::read_v7_plus(reader, size)?
                } else {
                    Self::read_legacy(reader)?
                };
                Self::validate_index_bounds(&footer, file_size)?;
                return Ok(footer);
            }
        }

        if file_size < FOOTER_SIZE_LEGACY {
            return Err(PaksmithError::InvalidFooter {
                reason: format!("file too small ({file_size} bytes) for any pak footer"),
            });
        }
        Err(PaksmithError::InvalidFooter {
            reason: format!("no recognized footer at any candidate offset (file_size={file_size})"),
        })
    }

    /// Read a v7+ footer (any size variant) from the current reader
    /// position, which must be `EOF - footer_size`. The size argument
    /// determines whether to read v8+ extras (compression FName table,
    /// v9 frozen byte).
    fn read_v7_plus<R: Read>(reader: &mut R, footer_size: u64) -> crate::Result<Self> {
        let mut encryption_key_guid = [0u8; 16];
        reader.read_exact(&mut encryption_key_guid)?;
        let encrypted = reader.read_u8()? != 0;

        let magic = reader.read_u32::<LittleEndian>()?;
        if magic != PAK_MAGIC {
            return Err(PaksmithError::InvalidFooter {
                reason: format!(
                    "v7+ footer magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"
                ),
            });
        }
        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version = PakVersion::try_from(version_raw)?;

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash = [0u8; 20];
        reader.read_exact(&mut index_hash)?;

        // V9 footer has a frozen-index byte right after the hash.
        let frozen_index = footer_size == FOOTER_SIZE_V9 && reader.read_u8()? != 0;

        // V8+ footer has an FName compression-method table at the tail.
        // V7 (and any size we don't recognize) gets zero slots — the
        // dispatcher only routes here for sizes we know.
        let compression_slot_count = match footer_size {
            FOOTER_SIZE_V8A => COMPRESSION_SLOTS_V8A,
            FOOTER_SIZE_V8B_PLUS | FOOTER_SIZE_V9 => COMPRESSION_SLOTS_V8B_PLUS,
            _ => 0,
        };
        let compression_methods = read_compression_method_table(reader, compression_slot_count)?;

        Ok(Self {
            version,
            index_offset,
            index_size,
            index_hash,
            encrypted,
            encryption_key_guid: Some(encryption_key_guid),
            frozen_index,
            compression_methods,
        })
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
            frozen_index: false,
            compression_methods: Vec::new(),
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

/// Read the v8+ compression-method FName table — `slot_count` × 32-byte
/// blocks each holding a null- or whitespace-padded UTF-8 string. Empty
/// slots and unrecognized names parse as `None`; the entry parser
/// surfaces `Decompression` errors for any entry that references such a
/// slot.
fn read_compression_method_table<R: Read>(
    reader: &mut R,
    slot_count: usize,
) -> crate::Result<Vec<Option<CompressionMethod>>> {
    let mut out = Vec::with_capacity(slot_count);
    let mut buf = [0u8; COMPRESSION_SLOT_BYTES];
    for _ in 0..slot_count {
        reader.read_exact(&mut buf)?;
        // The slot is a 32-byte buffer holding an FName string padded to
        // length with nulls (and sometimes whitespace). Stop at the first
        // non-printable; downstream parser is case-insensitive.
        let end = buf
            .iter()
            .position(|&b| b == 0 || b == b' ')
            .unwrap_or(buf.len());
        let name = std::str::from_utf8(&buf[..end]).unwrap_or("");
        out.push(if name.is_empty() {
            None
        } else {
            Some(CompressionMethod::from_name(name))
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use byteorder::WriteBytesExt;

    use super::*;

    /// Build a V8B/V10/V11-shaped footer (221 bytes): real UE wire layout.
    /// `version` selects which version field value to write — 8 for V8B,
    /// 10 for V10, 11 for V11.
    fn build_v8b_plus_footer(
        version: u32,
        index_offset: u64,
        index_size: u64,
        payload_bytes: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);

        // v7+ wire layout: uuid + encrypted come BEFORE magic.
        buf.extend_from_slice(&[0u8; 16]); // encryption_key_guid
        buf.push(0); // encrypted
        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(version).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index_hash
        // 5 × 32-byte compression FName slots (all empty).
        buf.extend_from_slice(&[0u8; 5 * 32]);
        buf
    }

    /// Build a v7-shaped footer (61 bytes): real UE wire layout.
    fn build_v7_footer(index_offset: u64, index_size: u64, payload_bytes: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);
        buf.extend_from_slice(&[0u8; 16]); // encryption_key_guid
        buf.push(0); // encrypted
        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(7).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]); // index_hash
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
        let data = build_v8b_plus_footer(11, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::Fnv64BugFix);
        assert_eq!(footer.index_offset(), 0);
        assert_eq!(footer.index_size(), 0);
        assert!(!footer.is_encrypted());
        assert!(footer.encryption_key_guid().is_some());
        // V11 footer carries a 5-slot compression-method table (all empty here).
        assert_eq!(footer.compression_methods().len(), 5);
        assert!(footer.compression_methods().iter().all(Option::is_none));
    }

    /// V7 footers must parse via the v7 candidate (61 bytes), not be
    /// misread by the legacy candidate. The v7 layout puts magic at
    /// offset 17 from the footer start (after uuid + encrypted), but
    /// the trailing 44 bytes happen to look like a legacy footer if you
    /// squint — proving we still take the right path matters.
    #[test]
    fn parse_v7_footer_via_v7_candidate() {
        let data = build_v7_footer(0, 0, 100);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::EncryptionKeyGuid);
        assert!(footer.encryption_key_guid().is_some());
        assert!(footer.compression_methods().is_empty());
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
        let mut data = build_v8b_plus_footer(11, 0, 0, 100);
        // Corrupt the magic at every candidate's expected position so no
        // probe accepts. Magic in v8b+ sits at offset 17 from the footer
        // start; legacy candidate would look at offset 0 of the trailing
        // 44 bytes.
        let footer_start = data.len() - FOOTER_SIZE_V8B_PLUS as usize;
        data[footer_start + 17] = 0xFF;
        let legacy_start = data.len() - FOOTER_SIZE_LEGACY as usize;
        data[legacy_start] = 0xFF;
        // Also corrupt at the v7 candidate's magic position.
        let v7_start = data.len() - FOOTER_SIZE_V7_PLUS as usize;
        data[v7_start + 17] = 0xFF;

        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_unsupported_version_in_legacy_footer() {
        // A legacy-shaped footer claiming version=99 must surface as
        // InvalidFooter — no candidate's expected-version list contains
        // 99, so no probe accepts. This is a deliberate behavior change
        // from the prior version-first dispatcher (which would have
        // returned UnsupportedVersion); with size-then-version dispatch,
        // an unrecognized version on a known size is "the file isn't
        // any pak shape we know," which is structurally InvalidFooter.
        let data = build_legacy_footer(99, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(
            matches!(err, PaksmithError::InvalidFooter { .. }),
            "got: {err:?}"
        );
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
        let data = build_v8b_plus_footer(11, 150, 1000, 100);
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
    fn accepts_zero_size_index_at_eof() {
        // index_offset == file_size with index_size == 0 is the empty-archive
        // boundary; must be accepted (end == file_size, not >).
        let payload = 100usize;
        // file_size = payload + footer_size; place index_offset exactly at file_size.
        let file_size = payload as u64 + FOOTER_SIZE_V8B_PLUS;
        let data = build_v8b_plus_footer(11, file_size, 0, payload);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();
        assert_eq!(footer.index_size(), 0);
        assert_eq!(footer.index_offset(), file_size);
    }

    #[test]
    fn rejects_zero_size_index_past_eof() {
        // index_offset > file_size with index_size == 0 must still reject.
        let payload = 100usize;
        let file_size = payload as u64 + FOOTER_SIZE_V8B_PLUS;
        let data = build_v8b_plus_footer(11, file_size + 1, 0, payload);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, PaksmithError::InvalidFooter { .. }));
    }

    #[test]
    fn reject_index_bounds_overflow() {
        // index_offset + index_size overflows u64.
        let data = build_v8b_plus_footer(11, u64::MAX - 10, 100, 100);
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
