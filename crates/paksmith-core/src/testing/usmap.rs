//! Test helpers for unversioned-property fixtures.
//!
//! `.usmap` byte builders for the canonical `Hero { Health, Speed }`
//! shape, plus a paired `.uasset` builder. The schema and the asset
//! that uses it must encode the same property names; co-located so
//! moving either without the other is structurally visible.
//!
//! ### `.usmap` byte builders
//!
//! - [`build_hero_usmap_bytes`] — parameterized over Speed's
//!   `EPropertyType` byte. The canonical source of truth for the
//!   wire-format assembly; all other byte builders delegate here or
//!   share its private `wrap_usmap_header` tail. Use this for any
//!   shape where Speed is a primitive (Float, Int, Map, Set, etc.).
//! - [`build_minimal_usmap_bytes`] — named alias for
//!   `build_hero_usmap_bytes(3u8)` (FloatProperty); the canonical
//!   happy-path shape consumed by `paksmith-fixture-gen` and
//!   `asset::mappings`'s in-source tests.
//! - [`build_hero_usmap_with_enum_speed`] — `Speed: EnumProperty`
//!   with an enum table. Structurally distinct from the parameterized
//!   form (byte 26 needs an inner type byte + enum-name index in the
//!   schema entry + a non-empty enum-table entry).
//! - [`build_hero_usmap_with_struct_speed`] — `Speed:
//!   StructProperty(struct_name)` with NO matching `struct_name`
//!   schema in the table. Used to drive the depth-1
//!   `UnversionedSchemaMissing` error path.
//! - [`build_sparse_schema_usmap_bytes`] — arbitrary class with a
//!   user-supplied list of `(schema_index, name, type_byte)` triples
//!   for each serializable property. `prop_count` (total class
//!   properties including non-serializable) is decoupled from
//!   `serial_count` (the slice length). Used to exercise non-zero,
//!   non-contiguous, and out-of-order `schema_index` values that the
//!   Hero fixture's hard-coded indices `[0, 1]` cannot reach.
//!
//! ### `.uasset` byte builder
//!
//! - [`build_minimal_unversioned_uasset_bytes`] — a valid UE 4.27
//!   `.uasset` with `PKG_UnversionedProperties` set and one export
//!   whose serialised body is the unversioned encoding of
//!   `Health = 100i32, Speed = 600.0f32`. Pin-anchored by
//!   [`MINIMAL_UNVERSIONED_PAYLOAD_HEX`].

/// `.usmap` bytes for a single class `Hero` with two properties:
/// `Health: IntProperty` (schema_index 0) and `Speed: FloatProperty`
/// (schema_index 1). Version = `Initial` (0), compression = `None`.
///
/// Thin wrapper over [`build_hero_usmap_bytes`] for the canonical
/// happy-path shape; pass `3u8` (FloatProperty).
#[must_use]
pub fn build_minimal_usmap_bytes() -> Vec<u8> {
    build_hero_usmap_bytes(3u8)
}

/// `.usmap` bytes for class `Hero` with `Health: IntProperty` at
/// schema_index 0 and `Speed: <speed_type_byte>` at schema_index 1.
/// Version = `Initial` (0), compression = `None`, empty enum table.
///
/// Parameterized over Speed's `EPropertyType` byte so integration
/// tests can drive adversarial shapes without duplicating the
/// surrounding wire-format assembly. Examples:
/// - `3u8` (FloatProperty) — the canonical happy path; see
///   [`build_minimal_usmap_bytes`].
/// - `24u8` (MapProperty, unsupported) — exercises the
///   partial-tree-stop contract.
///
/// For EnumProperty (which needs an enum table entry + inner type
/// byte), see [`build_hero_usmap_with_enum_speed`] — the wire shape
/// is structurally different.
#[must_use]
pub fn build_hero_usmap_bytes(speed_type_byte: u8) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // Name table: ["Hero", "None", "Health", "Speed"]. "None" is UE's
    // sentinel for "no superclass" (see Usmap parser's super_type
    // handling); CUE4Parse accepts zero-length names but UE's wire-
    // format convention uses the literal "None" for the no-super slot.
    data.extend_from_slice(&4u32.to_le_bytes());
    for (len, name) in [
        (4u8, "Hero"),
        (4u8, "None"),
        (6u8, "Health"),
        (5u8, "Speed"),
    ] {
        data.push(len);
        data.extend_from_slice(name.as_bytes());
    }
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: one class
    data.extend_from_slice(&1u32.to_le_bytes());
    // Schema "Hero"
    data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero" (idx 0)
    data.extend_from_slice(&1i32.to_le_bytes()); // super = "None" (idx 1, no-super sentinel)
    data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&2u16.to_le_bytes()); // serial_count
    // Prop 0: Health IntProperty
    data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
    data.push(1u8); // array_size
    data.extend_from_slice(&2i32.to_le_bytes()); // name idx = "Health"
    data.push(2u8); // IntProperty
    // Prop 1: Speed <speed_type_byte>
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&3i32.to_le_bytes()); // name idx = "Speed"
    data.push(speed_type_byte);

    wrap_usmap_header(&data)
}

/// `.usmap` bytes for class `Hero` with `Health: IntProperty` at
/// schema_index 0 and `Speed: EnumProperty(enum_name)` at
/// schema_index 1. The enum table carries `enum_name → enum_values`.
///
/// Used to exercise the unversioned `MT::Enum` decode arm (which the
/// parameterized [`build_hero_usmap_bytes`] cannot cover: byte 26
/// requires an inner type byte + enum-name index in the schema
/// entry, plus a non-empty enum table entry to resolve the ordinal).
///
/// # Panics
///
/// - `enum_values.len()` exceeds `u8::MAX` (the on-wire value-count
///   field is a single byte).
/// - `enum_name` or any element of `enum_values` is longer than 255
///   bytes (the on-wire length prefix is a `u8`).
/// - Total name-table size exceeds `u32::MAX` entries (vacuously
///   unreachable for any plausible test).
///
/// All panics are precondition violations on test-controlled inputs;
/// they cannot fire on `.usmap` bytes read from disk.
#[must_use]
pub fn build_hero_usmap_with_enum_speed(enum_name: &str, enum_values: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // Name table layout:
    //   0: "Hero", 1: "None", 2: "Health", 3: "Speed", 4: enum_name,
    //   5..: enum_values (one entry each). "None" is UE's sentinel
    //   for the no-super slot.
    let total_names = 5 + enum_values.len();
    let total_names_u32 = u32::try_from(total_names).expect("name table within u32");
    data.extend_from_slice(&total_names_u32.to_le_bytes());
    for (len, name) in [
        (4u8, "Hero"),
        (4u8, "None"),
        (6u8, "Health"),
        (5u8, "Speed"),
    ] {
        data.push(len);
        data.extend_from_slice(name.as_bytes());
    }
    // enum_name + values: each gets a name-table entry. Length byte is
    // the exact byte length per CUE4Parse `ReadStringUnsafe(nameLength)`.
    let name_len_byte =
        |name: &str| -> u8 { u8::try_from(name.len()).expect("usmap name within u8 length") };
    data.push(name_len_byte(enum_name));
    data.extend_from_slice(enum_name.as_bytes());
    for value in enum_values {
        data.push(name_len_byte(value));
        data.extend_from_slice(value.as_bytes());
    }
    // Enum table: one enum
    data.extend_from_slice(&1u32.to_le_bytes());
    // Enum entry: name_idx = 4 (enum_name), then u8 value_count, then
    // value_count × i32 name_idx (values start at name idx 5).
    data.extend_from_slice(&4i32.to_le_bytes());
    let value_count_u8 = u8::try_from(enum_values.len()).expect("enum values fit in u8");
    data.push(value_count_u8);
    for i in 0..enum_values.len() {
        let value_name_idx = i32::try_from(5 + i).expect("value name idx fits in i32");
        data.extend_from_slice(&value_name_idx.to_le_bytes());
    }
    // Schema table: one class
    data.extend_from_slice(&1u32.to_le_bytes());
    // Schema "Hero"
    data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero"
    data.extend_from_slice(&1i32.to_le_bytes()); // super = "None"
    data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&2u16.to_le_bytes()); // serial_count
    // Prop 0: Health IntProperty
    data.extend_from_slice(&0u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&2i32.to_le_bytes()); // "Health"
    data.push(2u8);
    // Prop 1: Speed EnumProperty(enum_name)
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&3i32.to_le_bytes()); // "Speed"
    data.push(26u8); // EnumProperty
    data.push(0u8); // inner type byte = ByteProperty (always in practice)
    data.extend_from_slice(&4i32.to_le_bytes()); // enum_name idx = 4

    wrap_usmap_header(&data)
}

/// `.usmap` bytes for class `Hero` with `Health: IntProperty` at
/// schema_index 0 and `Speed: StructProperty(struct_name)` at
/// schema_index 1. The named `struct_name` schema is **deliberately
/// absent** from the schema table — used to drive the depth-1
/// `UnversionedSchemaMissing` error path.
///
/// When the decoder recurses into the Struct slot, the inner
/// `read_unversioned_properties(struct_name, ..., depth=1)` call
/// finds `all_props.is_empty()` and (because `depth > 0`) errors
/// with `UnversionedSchemaMissing` before consuming any struct
/// payload bytes. The error propagates to the outermost frame
/// (`depth == 0`), the `is_partial_tree_stop` catch arm fires, and
/// the decoder returns a partial tree containing whatever was
/// decoded before the Struct slot.
///
/// # Panics
///
/// - `struct_name` longer than 255 bytes (the on-wire length prefix
///   is a `u8`).
/// - Total `.usmap` data block exceeds `u32::MAX` bytes (vacuously
///   unreachable for any plausible test).
#[must_use]
pub fn build_hero_usmap_with_struct_speed(struct_name: &str) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    // Name table: ["Hero", "None", "Health", "Speed", struct_name] —
    // "None" is UE's sentinel for the no-super slot.
    data.extend_from_slice(&5u32.to_le_bytes());
    for (len, name) in [
        (4u8, "Hero"),
        (4u8, "None"),
        (6u8, "Health"),
        (5u8, "Speed"),
    ] {
        data.push(len);
        data.extend_from_slice(name.as_bytes());
    }
    let struct_name_len = u8::try_from(struct_name.len()).expect("struct_name within u8");
    data.push(struct_name_len);
    data.extend_from_slice(struct_name.as_bytes());
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: one class — Hero ONLY. struct_name has no schema
    // entry; that's the whole point.
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero"
    data.extend_from_slice(&1i32.to_le_bytes()); // super = "None"
    data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
    data.extend_from_slice(&2u16.to_le_bytes()); // serial_count
    // Prop 0: Health IntProperty
    data.extend_from_slice(&0u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&2i32.to_le_bytes()); // "Health"
    data.push(2u8); // IntProperty
    // Prop 1: Speed StructProperty(struct_name)
    data.extend_from_slice(&1u16.to_le_bytes());
    data.push(1u8);
    data.extend_from_slice(&3i32.to_le_bytes()); // "Speed"
    data.push(9u8); // StructProperty
    data.extend_from_slice(&4i32.to_le_bytes()); // struct_name idx = 4

    wrap_usmap_header(&data)
}

/// `.usmap` bytes for an arbitrary class with serializable properties
/// at user-supplied `schema_index` values. Unlike
/// [`build_hero_usmap_bytes`] (which hard-codes Health@0 + Speed@1),
/// this builder accepts a slice of `(schema_index, name, type_byte)`
/// triples and a separate `prop_count` (the total class-property
/// count including non-serializable filler).
///
/// Real UE classes routinely have `prop_count > serial_count` because
/// transient, editor-only, and deprecated properties count toward
/// `prop_count` but are excluded from the serialized stream. A schema
/// with three serializable slots at indices `[0, 2, 4]` is the common
/// shape this builder reproduces.
///
/// `properties` may be in any declaration order — the order they
/// appear here is the order
/// [`crate::asset::mappings::Usmap::get_all_properties`] returns
/// them. The decoder side defensively sorts by `absolute_index`
/// before iterating (see `read_unversioned_properties`), so an
/// adversarial schema with declaration order `[2, 0, 4]` must still
/// decode the wire correctly; the
/// `unversioned_property_with_non_increasing_index_decodes_correctly`
/// integration test pins that contract.
///
/// # Panics
///
/// - `properties.len()` exceeds `u16::MAX` (the on-wire `serial_count`
///   field is `u16`).
/// - Any `schema_index` >= `prop_count` (would be structurally
///   invalid).
/// - `class_name` or any property name longer than 255 bytes (`u8`
///   length prefix).
/// - Total name-table size exceeds `u32::MAX` entries.
#[must_use]
pub fn build_sparse_schema_usmap_bytes(
    class_name: &str,
    prop_count: u16,
    properties: &[(u16, &str, u8)],
) -> Vec<u8> {
    let serial_count = u16::try_from(properties.len()).expect("serial_count fits in u16");
    for (idx, _, _) in properties {
        assert!(
            *idx < prop_count,
            "schema_index {idx} must be < prop_count {prop_count}"
        );
    }

    // Name table: dedupe `[class_name, "None"]` + property names.
    // "None" is UE's sentinel for the no-super slot.
    let mut names: Vec<&str> = Vec::with_capacity(2 + properties.len());
    names.push(class_name);
    names.push("None");
    for (_, name, _) in properties {
        if !names.contains(name) {
            names.push(name);
        }
    }
    let name_idx = |needle: &str| -> i32 {
        let pos = names
            .iter()
            .position(|n| *n == needle)
            .expect("name was inserted above");
        i32::try_from(pos).expect("name idx fits in i32")
    };

    let mut data: Vec<u8> = Vec::new();
    let total_names_u32 = u32::try_from(names.len()).expect("name count fits in u32");
    data.extend_from_slice(&total_names_u32.to_le_bytes());
    for name in &names {
        let len_byte = u8::try_from(name.len()).expect("usmap name within u8 length");
        data.push(len_byte);
        data.extend_from_slice(name.as_bytes());
    }
    // Enum table: empty
    data.extend_from_slice(&0u32.to_le_bytes());
    // Schema table: one class
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&name_idx(class_name).to_le_bytes());
    data.extend_from_slice(&name_idx("None").to_le_bytes());
    data.extend_from_slice(&prop_count.to_le_bytes());
    data.extend_from_slice(&serial_count.to_le_bytes());
    for (schema_index, name, type_byte) in properties {
        data.extend_from_slice(&schema_index.to_le_bytes());
        data.push(1u8); // array_size
        data.extend_from_slice(&name_idx(name).to_le_bytes());
        data.push(*type_byte);
    }
    wrap_usmap_header(&data)
}

/// Wrap a `.usmap` data block in the magic + version + compression +
/// size header (`Initial` version, `None` compression). Shared by
/// the public byte builders.
fn wrap_usmap_header(data: &[u8]) -> Vec<u8> {
    let data_len = u32::try_from(data.len()).expect("usmap data within u32");
    let mut out: Vec<u8> = Vec::new();
    // CUE4Parse `FileMagic = 0x30C4` read via little-endian u16 → on-disk
    // bytes `C4 30`. The pre-fix paksmith builder wrote `30 C4` to match
    // a byte-inverted reader; #352 corrected the reader, so the writer
    // must also flip.
    out.extend_from_slice(&[0xC4u8, 0x30u8]); // magic LE → 0x30C4
    out.push(0u8); // version = Initial
    out.push(0u8); // compression = None
    out.extend_from_slice(&data_len.to_le_bytes()); // compressed_size
    out.extend_from_slice(&data_len.to_le_bytes()); // decompressed_size
    out.extend_from_slice(data);
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
/// the decoder side at the header level. The asset-level
/// partial-tree-stop contract is pinned by
/// `tests/unversioned_integration::partial_tree_stops_on_unsupported_type_byte`.
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
            crate::asset::Asset::Generic(PropertyBag::Tree { properties }) => properties,
            other => panic!("expected Asset::Generic(PropertyBag::Tree), got {other:?}"),
        };
        assert_eq!(props.len(), 2, "expected 2 decoded properties");
        let health = props
            .iter()
            .find(|p| p.name.as_ref() == "Health")
            .expect("Health");
        let speed = props
            .iter()
            .find(|p| p.name.as_ref() == "Speed")
            .expect("Speed");
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
