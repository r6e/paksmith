//! Test helpers for unversioned-property fixtures.
//!
//! Two helpers, used together by integration tests + fixture-gen
//! cross-validation:
//!
//! - [`build_minimal_usmap_bytes`] — `.usmap` bytes for a single
//!   class `Hero` with two properties (`Health: IntProperty` at
//!   schema_index 0, `Speed: FloatProperty` at schema_index 1).
//! - [`build_minimal_unversioned_uasset_bytes`] — a valid UE 4.27
//!   `.uasset` with `PKG_UnversionedProperties` set and one export
//!   whose serialised body is the unversioned encoding of
//!   `Health = 100i32, Speed = 600.0f32`.
//!
//! Wire layout for both is pinned by the unit tests at the bottom of
//! this file and by `mappings.rs::tests::minimal_usmap_none` (the
//! `.usmap` parser's own round-trip).

use byteorder::{LE, WriteBytesExt};

/// `.usmap` bytes for a single class `Hero` with two properties:
/// `Health: IntProperty` (schema_index 0) and `Speed: FloatProperty`
/// (schema_index 1). Version = `Initial` (0), compression = `None`.
///
/// Mirrors `mappings.rs::tests::minimal_usmap_none` byte-for-byte so
/// any drift between the two surfaces immediately in this module's
/// round-trip test.
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

/// Returns a valid UE 4.27 `.uasset` binary with
/// `PKG_UnversionedProperties` set, one export of class `Hero` with
/// two serialised properties: `Health = 100i32, Speed = 600.0f32`.
///
/// The export's serialised body is:
///
/// - `FUnversionedHeader` fragment: `skip=0, has_zeros=false,
///   is_last=true, value_num=2` → packed = `0x0500`, LE bytes
///   `[0x00, 0x05]`.
/// - `Health` = `100i32` LE: `[0x64, 0x00, 0x00, 0x00]`.
/// - `Speed` = `600.0f32` LE: `[0x00, 0x00, 0x16, 0x44]`.
///
/// Total payload = 10 bytes. The asset bytes themselves include the
/// full UE 4.27 summary / name table / import / export header
/// preamble emitted by
/// [`build_minimal_ue4_27_unversioned`](crate::testing::uasset::build_minimal_ue4_27_unversioned).
///
/// # Panics
///
/// Should never panic in practice: the byteorder `write_*` calls
/// target an in-memory `Vec<u8>` whose only failure mode is OOM,
/// which would already abort the process. Listed here only to
/// satisfy `clippy::missing_panics_doc` on the unwrap calls.
#[must_use]
pub fn build_minimal_unversioned_uasset_bytes() -> Vec<u8> {
    let payload: Vec<u8> = {
        let mut p = Vec::new();
        // FUnversionedHeader: one fragment, no zeros, 2 values, is_last
        // packed = IS_LAST(0x0100) | (value_num=2 << 9 = 0x0400) = 0x0500
        p.write_u16::<LE>(0x0500u16).unwrap();
        // Health = 100i32
        p.write_i32::<LE>(100).unwrap();
        // Speed = 600.0f32 = 0x44160000
        p.write_f32::<LE>(600.0f32).unwrap();
        p
    };

    let pkg = crate::testing::uasset::build_minimal_ue4_27_unversioned("Hero", payload);
    pkg.bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::asset::Package;
    use crate::asset::mappings::{MappedPropertyType, Usmap};
    use crate::asset::property::PropertyBag;
    use crate::asset::property::primitives::PropertyValue;

    #[test]
    fn usmap_bytes_round_trip_through_parser() {
        let bytes = build_minimal_usmap_bytes();
        let usmap = Usmap::from_bytes(&bytes).expect("paksmith Usmap::from_bytes");
        let hero = usmap.schemas.get("Hero").expect("Hero schema missing");
        assert_eq!(hero.super_type.as_deref(), Some(""));
        assert_eq!(hero.properties.len(), 2);
        assert_eq!(hero.properties[0].name, "Health");
        assert!(matches!(
            hero.properties[0].prop_type,
            MappedPropertyType::Int32
        ));
        assert_eq!(hero.properties[1].name, "Speed");
        assert!(matches!(
            hero.properties[1].prop_type,
            MappedPropertyType::Float
        ));
    }

    #[test]
    fn unversioned_uasset_decodes_against_usmap() {
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
