//! Externally-produced `.usmap` fixtures — built by raw byte writes
//! following the CUE4Parse wire-format spec, **without using
//! `paksmith-core::testing::usmap`'s builders**. This is the structural
//! defense from issue #376: if the same code that writes the fixture
//! is the code under test, shared bugs round-trip and slip through CI.
//!
//! All byte layouts here cite CUE4Parse@master `UsmapParser.cs` and
//! `UsmapArchiveExtensions.cs` verbatim. The fixtures emitted by this
//! module are SHA1-anchored in `paksmith-core/tests/fixture_anchor.rs`.
//!
//! Two fixtures:
//! - `external_minimal_v0.usmap` — version 0 (`Initial`): u8 name
//!   lengths, u8 enum-value counts, positional enum values. Catches
//!   #352 (magic inversion), #353 (name-length off-by-one).
//! - `external_minimal_v4.usmap` — version 4 (`ExplicitEnumValues`):
//!   u16 name lengths (LongFName), u16 enum-value counts
//!   (LargeEnums), `(u64 value, i32 name_idx)` enum entries
//!   (ExplicitEnumValues). Catches all of v2/v3/v4 wire-format
//!   branches at once.

use std::fs;
use std::io;
use std::path::Path;

// `EUsmapVersion` byte values, per CUE4Parse `EUsmapVersion.cs`.
const VERSION_INITIAL: u8 = 0;
const VERSION_EXPLICIT_ENUM_VALUES: u8 = 4;

// `EUsmapCompressionMethod::None`, per CUE4Parse.
const COMPRESSION_NONE: u8 = 0;

// `.usmap` file magic per `CUE4Parse/MappingsProvider/Usmap/UsmapParser.cs`:
// `private const ushort FileMagic = 0x30C4;` read via `archive.Read<ushort>()`
// (little-endian) → on-disk bytes `C4 30`.
const FILE_MAGIC_BYTES: [u8; 2] = [0xC4, 0x30];

// EPropertyType byte values consumed by `UsmapProperties.ParseStruct`:
// the only ones this module needs are IntProperty, FloatProperty, and
// EnumProperty (for the v4 fixture's `Color` field).
const EPROP_BYTE: u8 = 0;
const EPROP_INT32: u8 = 2;
const EPROP_FLOAT: u8 = 3;
const EPROP_ENUM: u8 = 26;

/// Write the v0 `Initial` external fixture to `path`.
///
/// Schema:
/// - class `Hero { Health: IntProperty, Speed: FloatProperty }`
/// - empty enum table
///
/// Name table layout (matches the in-tree
/// `paksmith-core::testing::usmap::build_minimal_usmap_bytes` so a
/// parser test can cross-check the external bytes against an
/// equivalent internal build):
/// index 0 = "Hero", 1 = "None" (super sentinel), 2 = "Health",
/// 3 = "Speed".
///
/// # Errors
///
/// Propagates any `io::Error` from the underlying `fs::write` call.
///
/// # Panics
///
/// Vacuously unreachable: the hard-coded payload is well under
/// `u32::MAX` bytes and every name fits in `u8`.
pub fn write_external_minimal_v0_usmap(path: &Path) -> io::Result<()> {
    let mut payload: Vec<u8> = Vec::new();

    // -- Name table (u32 count, then per-name { u8 len, bytes }).
    push_u32_le(&mut payload, 4);
    push_name_u8_len(&mut payload, "Hero");
    push_name_u8_len(&mut payload, "None");
    push_name_u8_len(&mut payload, "Health");
    push_name_u8_len(&mut payload, "Speed");

    // -- Enum table (u32 count = 0).
    push_u32_le(&mut payload, 0);

    // -- Schema table (u32 count = 1, then one ClassSchema).
    push_u32_le(&mut payload, 1);
    push_i32_le(&mut payload, 0); // name = "Hero" (idx 0)
    push_i32_le(&mut payload, 1); // super = "None" (idx 1) — UE sentinel for no superclass
    push_u16_le(&mut payload, 2); // prop_count
    push_u16_le(&mut payload, 2); // serial_count
    // Prop 0: Health IntProperty
    push_u16_le(&mut payload, 0); // schema_index
    payload.push(1); // array_size
    push_i32_le(&mut payload, 2); // name_idx = "Health"
    payload.push(EPROP_INT32);
    // Prop 1: Speed FloatProperty
    push_u16_le(&mut payload, 1); // schema_index
    payload.push(1); // array_size
    push_i32_le(&mut payload, 3); // name_idx = "Speed"
    payload.push(EPROP_FLOAT);

    // -- Wrap with the file header (version 0, no compression).
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&FILE_MAGIC_BYTES);
    out.push(VERSION_INITIAL);
    // v0 < PackageVersioning, so no has_versioning byte is read by CUE4Parse.
    out.push(COMPRESSION_NONE);
    let payload_len = u32::try_from(payload.len()).expect("payload fits in u32");
    push_u32_le(&mut out, payload_len); // compressed_size
    push_u32_le(&mut out, payload_len); // decompressed_size (None compression: equal)
    out.extend_from_slice(&payload);

    fs::write(path, &out)
}

/// Write the v4 `ExplicitEnumValues` external fixture to `path`.
///
/// Schema:
/// - class `Hero { Health: IntProperty, Color: EnumProperty(EColor) }`
/// - one enum `EColor { Red = 0, Blue = 2 }` — deliberately sparse so
///   any reader treating the values as positional (the v0-v3 layout)
///   mis-resolves Blue.
///
/// Name table layout:
/// 0 = "Hero", 1 = "None", 2 = "Health", 3 = "Color", 4 = "EColor",
/// 5 = "Red", 6 = "Blue".
///
/// # Errors
///
/// Propagates any `io::Error` from the underlying `fs::write` call.
///
/// # Panics
///
/// Vacuously unreachable: the hard-coded payload is well under
/// `u32::MAX` bytes and every name fits in `u16` (LongFName).
pub fn write_external_minimal_v4_usmap(path: &Path) -> io::Result<()> {
    let mut payload: Vec<u8> = Vec::new();

    // -- Name table (u32 count, then per-name { u16 len, bytes } at v >= 2).
    push_u32_le(&mut payload, 7);
    push_name_u16_len(&mut payload, "Hero");
    push_name_u16_len(&mut payload, "None");
    push_name_u16_len(&mut payload, "Health");
    push_name_u16_len(&mut payload, "Color");
    push_name_u16_len(&mut payload, "EColor");
    push_name_u16_len(&mut payload, "Red");
    push_name_u16_len(&mut payload, "Blue");

    // -- Enum table (u32 count = 1).
    push_u32_le(&mut payload, 1);
    push_i32_le(&mut payload, 4); // enum_name = "EColor" (idx 4)
    push_u16_le(&mut payload, 2); // num_values (u16 at v >= 3 LargeEnums)
    // ExplicitEnumValues (v >= 4): each entry is { u64 value, i32 name_idx }.
    push_u64_le(&mut payload, 0); // Red = 0
    push_i32_le(&mut payload, 5); // name_idx = "Red"
    push_u64_le(&mut payload, 2); // Blue = 2 (sparse — would mis-resolve positionally)
    push_i32_le(&mut payload, 6); // name_idx = "Blue"

    // -- Schema table (u32 count = 1).
    push_u32_le(&mut payload, 1);
    push_i32_le(&mut payload, 0); // name = "Hero"
    push_i32_le(&mut payload, 1); // super = "None"
    push_u16_le(&mut payload, 2); // prop_count
    push_u16_le(&mut payload, 2); // serial_count
    // Prop 0: Health IntProperty
    push_u16_le(&mut payload, 0); // schema_index
    payload.push(1); // array_size
    push_i32_le(&mut payload, 2); // name_idx = "Health"
    payload.push(EPROP_INT32);
    // Prop 1: Color EnumProperty(EColor) — wire shape per CUE4Parse
    // `UsmapProperties.ParseProperty` enum arm: type byte, then inner
    // property byte (always ByteProperty in practice), then enum-name
    // index.
    push_u16_le(&mut payload, 1); // schema_index
    payload.push(1); // array_size
    push_i32_le(&mut payload, 3); // name_idx = "Color"
    payload.push(EPROP_ENUM);
    payload.push(EPROP_BYTE); // inner = ByteProperty
    push_i32_le(&mut payload, 4); // enum_name idx = "EColor"

    // -- Wrap. v4 ≥ PackageVersioning so has_versioning byte IS read; we
    //    write it as 0 (no embedded versioning).
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&FILE_MAGIC_BYTES);
    out.push(VERSION_EXPLICIT_ENUM_VALUES);
    out.push(0); // has_versioning = false
    out.push(COMPRESSION_NONE);
    let payload_len = u32::try_from(payload.len()).expect("payload fits in u32");
    push_u32_le(&mut out, payload_len); // compressed_size
    push_u32_le(&mut out, payload_len); // decompressed_size
    out.extend_from_slice(&payload);

    fs::write(path, &out)
}

fn push_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_u64_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn push_i32_le(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

// v0-v1 name encoding: u8 length, then exactly `length` bytes (no null
// terminator), per CUE4Parse `ReadStringUnsafe`.
fn push_name_u8_len(buf: &mut Vec<u8>, name: &str) {
    let bytes = name.as_bytes();
    let len = u8::try_from(bytes.len()).expect("name fits in u8 length (v0/v1)");
    buf.push(len);
    buf.extend_from_slice(bytes);
}

// v2+ (LongFName): u16 length, otherwise identical.
fn push_name_u16_len(buf: &mut Vec<u8>, name: &str) {
    let bytes = name.as_bytes();
    let len = u16::try_from(bytes.len()).expect("name fits in u16 length (v2+)");
    push_u16_le(buf, len);
    buf.extend_from_slice(bytes);
}
