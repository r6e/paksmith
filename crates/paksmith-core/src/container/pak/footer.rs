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
use crate::digest::Sha1Digest;
use crate::error::{InvalidFooterFault, PaksmithError};

/// Parsed pak file footer containing archive metadata.
#[derive(Debug, Clone)]
pub struct PakFooter {
    version: PakVersion,
    index_offset: u64,
    index_size: u64,
    index_hash: Sha1Digest,
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

    /// SHA1 hash of the index data, used by
    /// [`crate::container::pak::PakReader::verify_index`] and as the
    /// integrity-claim signal in
    /// [`crate::container::pak::PakReader::archive_claims_integrity`]
    /// (via [`Sha1Digest::is_zero`]). `Copy` — returned by value.
    pub fn index_hash(&self) -> Sha1Digest {
        self.index_hash
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

        // Track the most-specific failure mode so we can return a typed
        // error that distinguishes:
        //   1. "no candidate even matched magic" → InvalidFooter (truly
        //      not any pak shape we know).
        //   2. "size + magic matched but version field is unrecognized
        //      OR doesn't match the candidate's expected list" →
        //      UnsupportedVersion (probably future engine, or a corrupt
        //      version field — but the file IS shaped like a pak).
        // Without this distinction, a CLI that pattern-matches
        // UnsupportedVersion to print "your engine version isn't
        // supported, try X" would miss the case the user actually hits.
        let mut size_magic_match_unknown_version: Option<u32> = None;

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
            let _ = reader.seek(SeekFrom::End(-((size - probe_offset_for_magic) as i64)))?;
            let probe_magic = reader.read_u32::<LittleEndian>()?;
            let probe_version = reader.read_u32::<LittleEndian>()?;
            if probe_magic != PAK_MAGIC {
                continue;
            }
            // Magic matched. Two sub-cases:
            //   a. Version is in the expected list for this size →
            //      proceed with full parse.
            //   b. Version not in the expected list → record it for the
            //      post-loop UnsupportedVersion fallback. Continue
            //      probing (a different candidate's size might still
            //      match for the corrupted-version case).
            if expected_versions.contains(&probe_version) {
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
            // Magic matched but version unexpected for this size. Keep
            // the FIRST such observation (largest candidate first) — it's
            // the most likely true intent.
            if size_magic_match_unknown_version.is_none() {
                debug!(
                    label,
                    version = probe_version,
                    "footer candidate matched magic but version is unexpected"
                );
                size_magic_match_unknown_version = Some(probe_version);
            }
        }

        if file_size < FOOTER_SIZE_LEGACY {
            return Err(PaksmithError::InvalidFooter {
                fault: InvalidFooterFault::Other {
                    reason: format!("file too small ({file_size} bytes) for any pak footer"),
                },
            });
        }
        if let Some(version_raw) = size_magic_match_unknown_version {
            return Err(PaksmithError::UnsupportedVersion {
                version: version_raw,
            });
        }
        Err(PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::Other {
                reason: format!(
                    "no recognized footer at any candidate offset (file_size={file_size})"
                ),
            },
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
                fault: InvalidFooterFault::Other {
                    reason: format!(
                        "v7+ footer magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"
                    ),
                },
            });
        }
        let version_raw = reader.read_u32::<LittleEndian>()?;
        let initial_version = PakVersion::try_from(version_raw)?;

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash_bytes = [0u8; 20];
        reader.read_exact(&mut index_hash_bytes)?;
        let index_hash = Sha1Digest::from(index_hash_bytes);

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

        // Wire version 8 is ambiguous between V8A and V8B (both write
        // `version = 8`). `TryFrom<u32>` returned `V8B` by default;
        // post-correct to `V8A` here when the FName table has 4 slots
        // (V8A's signature). This is the canonical disambiguation site
        // — the entry parser then dispatches on the variant directly
        // rather than on a runtime is_v8a flag.
        let version = if initial_version == PakVersion::V8B
            && compression_slot_count == COMPRESSION_SLOTS_V8A
        {
            PakVersion::V8A
        } else {
            initial_version
        };

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
                fault: InvalidFooterFault::Other {
                    reason: format!(
                        "magic mismatch: expected 0x{PAK_MAGIC:08X}, got 0x{magic:08X}"
                    ),
                },
            });
        }

        let version_raw = reader.read_u32::<LittleEndian>()?;
        let version = PakVersion::try_from(version_raw)?;

        let index_offset = reader.read_u64::<LittleEndian>()?;
        let index_size = reader.read_u64::<LittleEndian>()?;

        let mut index_hash_bytes = [0u8; 20];
        reader.read_exact(&mut index_hash_bytes)?;
        let index_hash = Sha1Digest::from(index_hash_bytes);

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
        // Issue #64 promoted both bounds-check sites to typed
        // `InvalidFooterFault` variants so consumers can match
        // exhaustively rather than substring-scan.
        let end = footer.index_offset.checked_add(footer.index_size).ok_or(
            PaksmithError::InvalidFooter {
                fault: InvalidFooterFault::IndexRegionOffsetOverflow {
                    offset: footer.index_offset,
                    size: footer.index_size,
                },
            },
        )?;
        if end > file_size {
            return Err(PaksmithError::InvalidFooter {
                fault: InvalidFooterFault::IndexRegionPastFileSize {
                    observed: end,
                    limit: file_size,
                },
            });
        }
        Ok(())
    }
}

/// Read the v8+ compression-method FName table — `slot_count` × 32-byte
/// blocks each holding a UTF-8 FName string padded with NULL or space
/// bytes. Empty slots parse as `None`; non-empty slots parse via
/// [`CompressionMethod::from_name`] (which preserves the raw name for
/// later operator-visible diagnostics if it's unrecognized).
///
/// Invalid UTF-8 in a non-empty slot is treated as `InvalidFooter`
/// rather than silently coerced to "empty / no compression" — a
/// malformed compression-name slot is structurally a corrupt footer,
/// and silently rewriting it to `None` would let an entry referencing
/// the slot be served as uncompressed garbage instead of failing
/// loudly.
fn read_compression_method_table<R: Read>(
    reader: &mut R,
    slot_count: usize,
) -> crate::Result<Vec<Option<CompressionMethod>>> {
    let mut out = Vec::with_capacity(slot_count);
    let mut buf = [0u8; COMPRESSION_SLOT_BYTES];
    for slot_index in 0..slot_count {
        reader.read_exact(&mut buf)?;
        // FName slots are padded with NULL or space; stop at the first.
        let end = buf
            .iter()
            .position(|&b| b == 0 || b == b' ')
            .unwrap_or(buf.len());
        if end == 0 {
            // Empty slot — UE writers leave unused FName positions zeroed.
            out.push(None);
            continue;
        }
        let name = std::str::from_utf8(&buf[..end]).map_err(|e| PaksmithError::InvalidFooter {
            fault: InvalidFooterFault::Other {
                reason: format!(
                    "compression slot {slot_index} contains non-UTF-8 bytes ({e}); \
                     a malformed FName slot can't be silently treated as empty \
                     because an entry referencing it would be misread as uncompressed"
                ),
            },
        })?;
        out.push(Some(CompressionMethod::from_name(name)));
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

    /// Build a V8A-shaped footer (189 bytes): v7 layout + 4 × 32-byte
    /// FName compression-method slots. Slots are zero-filled by default;
    /// `populated_slot_0` lets the caller fill the first slot to test
    /// downstream FName resolution.
    fn build_v8a_footer(
        index_offset: u64,
        index_size: u64,
        payload_bytes: usize,
        populated_slot_0: Option<&str>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);
        buf.extend_from_slice(&[0u8; 16]);
        buf.push(0);
        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(8).unwrap(); // V8A reports version=8
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        // 4 × 32-byte slots.
        let mut slot_bytes = [0u8; 32];
        if let Some(name) = populated_slot_0 {
            slot_bytes[..name.len()].copy_from_slice(name.as_bytes());
        }
        buf.extend_from_slice(&slot_bytes);
        buf.extend_from_slice(&[0u8; 32 * 3]);
        buf
    }

    /// Build a V9-shaped footer (222 bytes): V8B layout + 1 frozen-index
    /// byte right after the index hash.
    fn build_v9_footer(
        index_offset: u64,
        index_size: u64,
        payload_bytes: usize,
        frozen: bool,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&vec![0xAA; payload_bytes]);
        buf.extend_from_slice(&[0u8; 16]);
        buf.push(0);
        buf.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        buf.write_u32::<LittleEndian>(9).unwrap();
        buf.write_u64::<LittleEndian>(index_offset).unwrap();
        buf.write_u64::<LittleEndian>(index_size).unwrap();
        buf.extend_from_slice(&[0u8; 20]);
        buf.push(u8::from(frozen)); // frozen byte (V9-only)
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

    /// V11 footers (`PathHashIndex` v11 = `Fnv64BugFix`) share the
    /// 221-byte V8B+ shape — the version field is the only
    /// disambiguator. PakReader::open rejects v11 because the index
    /// format is Phase 2-B (#7), but the footer parser correctly
    /// returns the parsed footer with version + 5-slot table populated.
    #[test]
    fn parse_v8b_plus_footer_at_version_11() {
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

    /// V8A's 4-slot compression-method table is the disambiguation
    /// signal: the footer parser post-corrects wire-version-8 from
    /// the V8B default to V8A when this count is 4.
    #[test]
    fn parse_v8a_footer_has_4_compression_slots() {
        let data = build_v8a_footer(0, 0, 100, None);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(
            footer.version(),
            PakVersion::V8A,
            "footer parser must post-correct V8B (the TryFrom default for wire-version 8) to V8A when the FName table has 4 slots"
        );
        assert_eq!(
            footer.compression_methods().len(),
            4,
            "V8A footer must populate exactly 4 FName slots — disambiguation source for V8A vs V8B"
        );
        assert!(!footer.frozen_index());
    }

    /// V8A's first slot, when populated with `"Zlib"`, must resolve via
    /// `from_name` to `CompressionMethod::Zlib`.
    #[test]
    fn parse_v8a_footer_populates_named_compression_slot() {
        let data = build_v8a_footer(0, 0, 100, Some("Zlib"));
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(
            footer.compression_methods()[0],
            Some(CompressionMethod::Zlib),
            "FName slot containing `Zlib` must resolve to CompressionMethod::Zlib"
        );
        assert!(
            footer.compression_methods()[1..]
                .iter()
                .all(Option::is_none),
            "remaining slots must be None"
        );
    }

    /// V8B/V10/V11 share the 221-byte size; the version field decides
    /// which version is reported. V8B's 5-slot table is mandatory.
    #[test]
    fn parse_v8b_footer_has_5_slots_and_no_frozen() {
        let data = build_v8b_plus_footer(8, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::V8B);
        assert_eq!(footer.compression_methods().len(), 5);
        assert!(
            !footer.frozen_index(),
            "V8B has no frozen byte — `frozen_index` must always be false for v8b"
        );
    }

    /// V9 (222 bytes) carries both the frozen-index byte AND the 5-slot
    /// compression table. The dispatcher must probe V9 before V8B
    /// (otherwise the frozen byte would shift the V8B parse by 1).
    #[test]
    fn parse_v9_footer_populates_frozen_and_5_slots() {
        let data = build_v9_footer(0, 0, 100, true);
        let mut cursor = Cursor::new(data);
        let footer = PakFooter::read_from(&mut cursor).unwrap();

        assert_eq!(footer.version(), PakVersion::FrozenIndex);
        assert!(
            footer.frozen_index(),
            "frozen byte = 1 must surface as frozen_index() = true"
        );
        assert_eq!(footer.compression_methods().len(), 5);
    }

    /// `read_compression_method_table` must reject non-UTF-8 in a
    /// non-empty slot rather than silently coercing to None — the
    /// silent coercion was the round-1 silent-failure-hunter HIGH
    /// finding. A malformed slot is structurally a corrupt footer.
    #[test]
    fn reject_non_utf8_compression_slot() {
        let mut data = build_v8a_footer(0, 0, 100, None);
        // Overwrite the first byte of slot 0 with 0xFF (invalid as a
        // UTF-8 start byte). Slot 0 is at: payload(100) + uuid(16) +
        // encrypted(1) + magic(4) + version(4) + offset(8) + size(8) +
        // hash(20) = 161 bytes from start.
        data[161] = 0xFF;
        data[162] = b'X'; // make sure end-detection doesn't stop at 0
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        match err {
            PaksmithError::InvalidFooter {
                fault: InvalidFooterFault::Other { reason },
            } => {
                assert!(
                    reason.contains("non-UTF-8") || reason.contains("UTF-8"),
                    "got: {reason}"
                );
            }
            other => panic!("expected InvalidFooter::Other, got {other:?}"),
        }
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
        // UnsupportedVersion — the magic check at the legacy candidate
        // matches, the size matches, only the version field is unknown.
        // The dispatcher records this as a "size+magic match, version
        // unknown" outcome and returns the precise UnsupportedVersion
        // error rather than collapsing to a generic InvalidFooter.
        // Downstream callers (e.g. CLI) can pattern-match this to print
        // "engine version 99 isn't supported" rather than "the file
        // isn't a pak."
        let data = build_legacy_footer(99, 0, 0, 100);
        let mut cursor = Cursor::new(data);
        let err = PakFooter::read_from(&mut cursor).unwrap_err();
        assert!(
            matches!(err, PaksmithError::UnsupportedVersion { version: 99 }),
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
        // Issue #64: this used to be a substring scan against
        // `InvalidFooter { reason: String }`; now it pins the typed
        // variant via `matches!`. A regression that flips the
        // observed/limit ordering or changes the variant name fails
        // here at compile time, not at log-grep time.
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidFooter {
                    fault: InvalidFooterFault::IndexRegionPastFileSize { .. }
                }
            ),
            "expected InvalidFooter::IndexRegionPastFileSize, got: {err:?}"
        );
        // Display-text smoke check: operators/log greps still see the
        // "past EOF" token.
        assert!(err.to_string().contains("past EOF"), "got: {err}");
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
        // Issue #64: typed-variant pin (matches! on
        // `IndexRegionOffsetOverflow`); Display still emits "overflow"
        // for log greps.
        assert!(
            matches!(
                &err,
                PaksmithError::InvalidFooter {
                    fault: InvalidFooterFault::IndexRegionOffsetOverflow { .. }
                }
            ),
            "expected InvalidFooter::IndexRegionOffsetOverflow, got: {err:?}"
        );
        assert!(err.to_string().contains("overflow"), "got: {err}");
    }
}
