//! Property-based tests for footer parsing.
//!
//! Two properties:
//! 1. **Round-trip**: any valid v1-v3, v4-v6 or v11 footer we synthesise
//!    round-trips through `PakFooter::read_from` to the same field values.
//! 2. **No-panic on garbage**: random bytes never panic the parser; they either
//!    return `Ok(...)` (rare) or `Err(...)` (typical). Validates the
//!    "no panics in core" rule from CLAUDE.md.

#![allow(
    missing_docs,
    // Proptest harness: `usize → u32` length casts on bounded
    // generator inputs.
    clippy::cast_possible_truncation
)]

use std::io::Cursor;

use byteorder::{LittleEndian, WriteBytesExt};
use paksmith_core::container::pak::footer::PakFooter;
use paksmith_core::container::pak::version::PAK_MAGIC;
use proptest::prelude::*;

/// Append the v1-v3 footer layout (magic, version, index offset and size,
/// hash) to `prefix`. A v4-v6 caller pushes the flag byte onto `prefix` first.
fn append_legacy_footer(
    mut prefix: Vec<u8>,
    version: u32,
    index_offset: u64,
    index_size: u64,
    index_hash: &[u8; 20],
) -> Vec<u8> {
    prefix.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
    prefix.write_u32::<LittleEndian>(version).unwrap();
    prefix.write_u64::<LittleEndian>(index_offset).unwrap();
    prefix.write_u64::<LittleEndian>(index_size).unwrap();
    prefix.extend_from_slice(index_hash);
    prefix
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Round-trip property for V8B+ footers tested at version=11 (real
    /// V8B/V10/V11 wire layout: 221 bytes with uuid+encrypted before
    /// magic+version). The shape is identical for V8B and V10/V11; the
    /// version field is the only disambiguator.
    #[test]
    fn v8b_plus_footer_at_version_11_roundtrip(
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
        // Real v7+ wire layout: uuid + encrypted come BEFORE magic.
        data.extend_from_slice(&encryption_key_guid);
        data.push(u8::from(encrypted));
        data.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        data.write_u32::<LittleEndian>(11).unwrap();
        data.write_u64::<LittleEndian>(index_offset).unwrap();
        data.write_u64::<LittleEndian>(index_size).unwrap();
        data.extend_from_slice(&index_hash);
        // V11 footer carries a 5-slot compression-method FName table at the tail.
        data.extend_from_slice(&[0u8; 5 * 32]);

        let mut cursor = Cursor::new(data);
        let parsed = PakFooter::read_from(&mut cursor).unwrap();
        prop_assert_eq!(parsed.index_offset(), index_offset);
        prop_assert_eq!(parsed.index_size(), index_size);
        prop_assert_eq!(parsed.is_encrypted(), encrypted);
        prop_assert_eq!(parsed.index_hash(), paksmith_core::Sha1Digest::from(index_hash));
        prop_assert_eq!(parsed.encryption_key_guid(), Some(&encryption_key_guid));
    }

    /// Round-trip property for v1-v3 footers (44 bytes, no flag). A random
    /// nonzero payload fill makes any read of the byte at EOF-45 visible: it
    /// would flip `is_encrypted` or fail the strict flag check.
    #[test]
    fn v1_to_v3_footer_roundtrip(
        version in 1u32..=3,
        index_offset in 0u64..1_000_000,
        index_size in 0u64..1_000_000,
        index_hash in any::<[u8; 20]>(),
        prefix_len in 0usize..256,
        fill in 1u8..=u8::MAX,
    ) {
        let payload_max = index_offset.saturating_add(index_size).max(prefix_len as u64);
        let data = append_legacy_footer(
            vec![fill; payload_max as usize],
            version,
            index_offset,
            index_size,
            &index_hash,
        );

        let mut cursor = Cursor::new(data);
        let parsed = PakFooter::read_from(&mut cursor).unwrap();
        // PakVersion no longer derives `as u32` since the variant set
        // diverged from the wire-format mapping (V8A and V8B both
        // serialize to 8). Use the explicit `wire_version()` method.
        prop_assert_eq!(parsed.version().wire_version(), version);
        prop_assert_eq!(parsed.index_offset(), index_offset);
        prop_assert_eq!(parsed.index_size(), index_size);
        prop_assert_eq!(parsed.is_encrypted(), false);
        prop_assert!(parsed.encryption_key_guid().is_none());
    }

    /// Round-trip property for v4-v6 footers (45 bytes: the encrypted-index
    /// flag, then the v1-v3 layout).
    #[test]
    fn v4_to_v6_footer_roundtrip(
        version in 4u32..=6,
        index_offset in 0u64..1_000_000,
        index_size in 0u64..1_000_000,
        encrypted in any::<bool>(),
        index_hash in any::<[u8; 20]>(),
        prefix_len in 0usize..256,
    ) {
        let payload_max = index_offset.saturating_add(index_size).max(prefix_len as u64);
        let mut prefix = vec![0xAAu8; payload_max as usize];
        prefix.push(u8::from(encrypted));
        let data = append_legacy_footer(prefix, version, index_offset, index_size, &index_hash);

        let mut cursor = Cursor::new(data);
        let parsed = PakFooter::read_from(&mut cursor).unwrap();
        prop_assert_eq!(parsed.version().wire_version(), version);
        prop_assert_eq!(parsed.index_offset(), index_offset);
        prop_assert_eq!(parsed.index_size(), index_size);
        prop_assert_eq!(parsed.is_encrypted(), encrypted);
        prop_assert_eq!(parsed.index_hash(), paksmith_core::Sha1Digest::from(index_hash));
        prop_assert!(parsed.encryption_key_guid().is_none());
    }

    /// Garbage bytes never panic — they may parse or reject, but never abort.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let mut cursor = Cursor::new(bytes);
        // Result intentionally discarded — we only care that parsing returns.
        let _ = PakFooter::read_from(&mut cursor);
    }

    /// Bytes with the v7+ uuid+encrypted prefix + PAK_MAGIC + a valid
    /// version planted at the v7+ candidate position followed by random
    /// tail bytes never panic. Actively exercises `read_v7_plus`'s
    /// bounds validation under randomized field values, which the
    /// unbiased fuzz above can't reach (1-in-2^32 magic-collision
    /// probability per case).
    ///
    /// Tail size 220 = max footer payload after magic+version (V8B/V11):
    /// index_offset(8) + index_size(8) + hash(20) + 5×32 compression
    /// slots (160) + slack to cover the V8A/V8B size variance.
    #[test]
    fn planted_v7_magic_never_panics(
        prefix_len in 0usize..200,
        version in 7u32..=11,
        uuid in any::<[u8; 16]>(),
        encrypted_byte in any::<u8>(),
        tail in any::<[u8; 220]>(),
    ) {
        let mut data = vec![0xAAu8; prefix_len];
        data.extend_from_slice(&uuid);
        data.push(encrypted_byte);
        data.write_u32::<LittleEndian>(PAK_MAGIC).unwrap();
        data.write_u32::<LittleEndian>(version).unwrap();
        data.extend_from_slice(&tail);

        let mut cursor = Cursor::new(data);
        let _ = PakFooter::read_from(&mut cursor);
    }
}
