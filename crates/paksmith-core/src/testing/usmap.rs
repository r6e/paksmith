//! Test helpers for unversioned-property fixtures.
//!
//! Two paired helpers — the schema and the asset that uses it MUST
//! encode the same property names, types, and values. Co-located so
//! moving either without the other is structurally visible:
//!
//! - [`build_minimal_usmap_bytes`] — `.usmap` bytes for a single
//!   class `Hero` with two properties (`Health: IntProperty` at
//!   schema_index 0, `Speed: FloatProperty` at schema_index 1).
//!   This function is the single source of truth for the canonical
//!   minimal `.usmap` byte sequence; [`crate::asset::mappings`]'s
//!   in-source tests call it directly rather than maintain a copy.
//! - [`build_minimal_unversioned_uasset_bytes`] — a valid UE 4.27
//!   `.uasset` with `PKG_UnversionedProperties` set and one export
//!   whose serialised body is the unversioned encoding of
//!   `Health = 100i32, Speed = 600.0f32`.

/// `.usmap` bytes for a single class `Hero` with two properties:
/// `Health: IntProperty` (schema_index 0) and `Speed: FloatProperty`
/// (schema_index 1). Version = `Initial` (0), compression = `None`.
#[must_use]
pub fn build_minimal_usmap_bytes() -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // Name table: ["Hero", "", "Health", "Speed"]
    data.extend_from_slice(&4u32.to_le_bytes());
    for (s, name) in [(5u8, "Hero"), (1u8, ""), (7u8, "Health"), (6u8, "Speed")] {
        data.push(s);
        data.extend_from_slice(name.as_bytes());
    }
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: one class
    data.extend_from_slice(&1u32.to_le_bytes());
    // Schema "Hero"
    data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero" (idx 0)
    data.extend_from_slice(&1i32.to_le_bytes()); // super = "" (idx 1)
    data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&2u16.to_le_bytes()); // serial_count
    // Prop 0: Health IntProperty
    data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
    data.push(1u8); // array_size
    data.extend_from_slice(&2i32.to_le_bytes()); // name idx = "Health"
    data.push(2u8); // IntProperty
    // Prop 1: Speed FloatProperty
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&3i32.to_le_bytes()); // name idx = "Speed"
    data.push(3u8); // FloatProperty

    #[allow(
        clippy::cast_possible_truncation,
        reason = "test fixture builds a sub-256-byte schema block; data.len() fits in u32 trivially"
    )]
    let data_len = data.len() as u32;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0x30u8, 0xC4u8]); // magic LE
    out.push(0u8); // version = Initial
    out.push(0u8); // compression = None
    out.extend_from_slice(&data_len.to_le_bytes()); // compressed_size
    out.extend_from_slice(&data_len.to_le_bytes()); // decompressed_size
    out.extend_from_slice(&data);
    out
}

/// Hex-pinned bytes of the export payload that
/// [`build_minimal_unversioned_uasset_bytes`] emits.
///
/// **The community-derived anchor is the constant itself**, not the
/// pin-test. Each byte triple in the layout block below corresponds
/// to a separately-verifiable wire-format claim against TWO
/// reference implementations:
///
/// - `unreal_asset_base::unversioned::header::UnversionedHeaderFragment::write`
///   at the pinned `f4df5d8e` revision (the oracle's own writer).
/// - CUE4Parse's `FUnversionedHeader` writer (independent
///   implementation; same bit layout).
///
/// Any future encoder/decoder change that doesn't keep this constant
/// in sync with those two refs is wrong by definition; the
/// `unversioned_uasset_payload_matches_hex_pin` test pins drift in
/// the builder side, and the existing in-source decoder tests at
/// `unversioned.rs::tests` (no_zeros / skip / zero_mask shapes) pin
/// the decoder side. Single-fragment coverage only — Task 6 will add
/// multi-fragment / zero-mask asset-level corpus tests.
///
/// Layout:
/// - bytes 0..2: u16 LE `0x0500` = `IS_LAST(0x0100) | (value_num=2 << 9)`
/// - bytes 2..6: i32 LE `100`    = Health
/// - bytes 6..10: f32 LE `600.0` = `0x4416_0000`
pub const MINIMAL_UNVERSIONED_PAYLOAD_HEX: [u8; 10] = [
    0x00, 0x05, // FUnversionedHeader fragment
    0x64, 0x00, 0x00, 0x00, // Health = 100i32 LE
    0x00, 0x00, 0x16, 0x44, // Speed  = 600.0f32 LE
];

/// Returns a valid UE 4.27 `.uasset` binary with
/// `PKG_UnversionedProperties` set, one export of class `Hero` with
/// two serialised properties: `Health = 100i32, Speed = 600.0f32`.
///
/// The export's serialised body is exactly
/// [`MINIMAL_UNVERSIONED_PAYLOAD_HEX`] — 10 bytes. The asset bytes
/// themselves include the full UE 4.27 summary / name table /
/// import / export header preamble emitted by
/// [`build_minimal_ue4_27_unversioned`](crate::testing::uasset::build_minimal_ue4_27_unversioned).
#[must_use]
pub fn build_minimal_unversioned_uasset_bytes() -> Vec<u8> {
    let pkg = crate::testing::uasset::build_minimal_ue4_27_unversioned(
        "Hero",
        MINIMAL_UNVERSIONED_PAYLOAD_HEX.to_vec(),
    );
    pkg.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::asset::Package;
    use crate::asset::mappings::Usmap;
    use crate::asset::property::PropertyBag;
    use crate::asset::property::primitives::PropertyValue;

    /// Pins that the asset bytes emitted by
    /// [`build_minimal_unversioned_uasset_bytes`] terminate with the
    /// community-derived [`MINIMAL_UNVERSIONED_PAYLOAD_HEX`] sequence.
    /// The anchor is the constant (verified against two reference
    /// writers in its doc); this test catches builder-side drift
    /// (e.g., a future change that pads/truncates the payload's
    /// position within the asset bytes).
    ///
    /// `ends_with` rather than slice-math: if the builder ever
    /// regressed to producing fewer than 10 bytes, the slice form
    /// would panic with a generic underflow rather than the typed
    /// assertion failure here.
    #[test]
    fn unversioned_uasset_payload_matches_hex_pin() {
        let bytes = build_minimal_unversioned_uasset_bytes();
        assert!(
            bytes.ends_with(&MINIMAL_UNVERSIONED_PAYLOAD_HEX),
            "asset bytes don't end with MINIMAL_UNVERSIONED_PAYLOAD_HEX; \
             builder may be padding/truncating the payload (bytes.len() = {})",
            bytes.len()
        );
    }

    /// Paksmith-only round-trip self-test (oracle asset-level
    /// cross-parse is upstream-broken at the pinned `unreal_asset`
    /// revision — see `validate_unversioned_usmap_parser_parity` in
    /// fixture-gen for details). The hex-pin test above gives the
    /// independent wire-format anchor; this one verifies that
    /// paksmith's decoder produces the expected typed property tree
    /// on top of those pinned bytes.
    #[test]
    fn unversioned_asset_decodes_via_paksmith_self_test() {
        let usmap = Usmap::from_bytes(&build_minimal_usmap_bytes()).expect("Usmap parse");
        let asset_bytes = build_minimal_unversioned_uasset_bytes();
        let pkg = Package::read_from(&asset_bytes, None, Some(&usmap), "test/Hero.uasset")
            .expect("Package::read_from");
        let bag = pkg.payloads.first().expect("at least one payload");
        let props = match bag {
            PropertyBag::Tree { properties } => properties,
            other => panic!("expected PropertyBag::Tree, got {other:?}"),
        };
        assert_eq!(props.len(), 2, "expected 2 decoded properties");
        let health = props.iter().find(|p| p.name == "Health").expect("Health");
        let speed = props.iter().find(|p| p.name == "Speed").expect("Speed");
        assert!(
            matches!(health.value, PropertyValue::Int(100)),
            "Health should decode as Int(100), got {:?}",
            health.value
        );
        assert!(
            matches!(speed.value, PropertyValue::Float(v) if (v - 600.0f32).abs() < f32::EPSILON),
            "Speed should decode as Float(600.0), got {:?}",
            speed.value
        );
    }
}
