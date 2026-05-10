//! Property-based tests for footer parsing.
//!
//! Two properties:
//! 1. **Round-trip**: any valid v6/v11 footer we synthesise round-trips through
//!    `PakFooter::read_from` to the same field values.
//! 2. **No-panic on garbage**: random bytes never panic the parser; they either
//!    return `Ok(...)` (rare) or `Err(...)` (typical). Validates the
//!    "no panics in core" rule from CLAUDE.md.

#![allow(missing_docs)]

use std::io::Cursor;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::footer::PakFooter;
use proptest::prelude::*;

const PAK_MAGIC: u32 = 0x5A6F_12E1;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Round-trip property for v11 footers.
    #[test]
    fn v11_footer_roundtrip(
        index_offset in 0u64..1_000_000,
        index_size in 0u64..1_000_000,
        encrypted in any::<bool>(),
        index_hash in any::<[u8; 20]>(),
        encryption_key_guid in any::<[u8; 16]>(),
        prefix_len in 0usize..256,
    ) {
        // index_offset + index_size must fit within the file we construct.
        let payload_max = index_offset.saturating_add(index_size).max(prefix_len as u64);
        let payload = vec![0xAAu8; payload_max as usize];

        let mut data = payload;
        data.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        data.write_u32::<LittleEndian>(11).unwrap();
        data.write_u64::<LittleEndian>(index_offset).unwrap();
        data.write_u64::<LittleEndian>(index_size).unwrap();
        data.extend_from_slice(&index_hash);
        data.extend_from_slice(&encryption_key_guid);
        data.push(u8::from(encrypted));

        let mut cursor = Cursor::new(data);
        let parsed = PakFooter::read_from(&mut cursor).unwrap();
        prop_assert_eq!(parsed.index_offset(), index_offset);
        prop_assert_eq!(parsed.index_size(), index_size);
        prop_assert_eq!(parsed.is_encrypted(), encrypted);
        prop_assert_eq!(parsed.index_hash(), &index_hash);
        prop_assert_eq!(parsed.encryption_key_guid(), Some(&encryption_key_guid));
    }

    /// Round-trip property for legacy footers (versions 1-6).
    #[test]
    fn legacy_footer_roundtrip(
        version in 1u32..=6,
        index_offset in 0u64..1_000_000,
        index_size in 0u64..1_000_000,
        index_hash in any::<[u8; 20]>(),
        prefix_len in 0usize..256,
    ) {
        let payload_max = index_offset.saturating_add(index_size).max(prefix_len as u64);
        let payload = vec![0xAAu8; payload_max as usize];

        let mut data = payload;
        data.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        data.write_u32::<LittleEndian>(version).unwrap();
        data.write_u64::<LittleEndian>(index_offset).unwrap();
        data.write_u64::<LittleEndian>(index_size).unwrap();
        data.extend_from_slice(&index_hash);

        let mut cursor = Cursor::new(data);
        let parsed = PakFooter::read_from(&mut cursor).unwrap();
        prop_assert_eq!(parsed.version() as u32, version);
        prop_assert_eq!(parsed.index_offset(), index_offset);
        prop_assert_eq!(parsed.index_size(), index_size);
        prop_assert_eq!(parsed.is_encrypted(), false);
        prop_assert!(parsed.encryption_key_guid().is_none());
    }

    /// Garbage bytes never panic — they may parse or reject, but never abort.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut cursor = Cursor::new(bytes);
        // Result intentionally discarded — we only care that parsing returns.
        let _ = PakFooter::read_from(&mut cursor);
    }
}
