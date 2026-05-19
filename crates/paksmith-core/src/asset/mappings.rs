//! `.usmap` mappings file parser.
//!
//! A `.usmap` file is a registry of class schemas published alongside a
//! game build that lets a parser decode unversioned-property assets
//! (post UE 4.25 with `PKG_UnversionedProperties` set), where the wire
//! stream no longer carries `FPropertyTag` headers. Each schema lists
//! the class's properties in serialization order; the unversioned
//! reader walks the schema, advancing the cursor by each property's
//! type-sized payload.
//!
//! See `docs/plans/phase-2f-unversioned-properties.md` for the full
//! wire-format spec and the cross-validation against `unreal_asset`'s
//! oracle parser.

use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom};

use byteorder::{LE, ReadBytesExt};

use crate::PaksmithError;
use crate::error::MappingsParseFault;

const USMAP_MAGIC: u16 = 0xC430;
const MAX_USMAP_VERSION: u8 = 2; // EUsmapVersion::Latest

/// Hard cap on the wire-claimed `compressed_size` of a `.usmap` file.
/// Community-distributed usmaps are typically <1 MiB; 64 MiB gives huge
/// headroom while bounding allocation from a malicious header that
/// claims `u32::MAX` (~4 GiB).
pub const MAX_USMAP_COMPRESSED_SIZE: u32 = 64 * 1024 * 1024;

/// Hard cap on the wire-claimed `decompressed_size`. Same rationale —
/// prevent a decompression bomb from claiming a 4 GiB output buffer
/// and stalling allocation before the decoder even runs.
pub const MAX_USMAP_DECOMPRESSED_SIZE: u32 = 256 * 1024 * 1024;

/// Hard cap on the inheritance chain length when walking
/// `super_type` pointers. A malicious `.usmap` with a cycle (`A: B`,
/// `B: A`) would loop forever otherwise.
const MAX_INHERITANCE_DEPTH: usize = 64;

/// Compression method byte values from the .usmap wire format.
#[repr(u8)]
enum UsmapCompression {
    None = 0,
    Oodle = 1,
    Brotli = 2,
    ZStandard = 3,
}

/// The Rust-side property type derived from a usmap `EPropertyType` byte.
#[derive(Debug, Clone, PartialEq)]
pub enum MappedPropertyType {
    /// `BoolProperty` (single-bit on the wire, but materializes as a `bool`).
    Bool,
    /// `Int8Property` (signed 8-bit).
    Int8,
    /// `Int16Property` (signed 16-bit).
    Int16,
    /// `IntProperty` (signed 32-bit; the UE default integer width).
    Int32,
    /// `Int64Property` (signed 64-bit).
    Int64,
    /// `ByteProperty` (unsigned 8-bit; also used as enum storage on the wire).
    UInt8,
    /// `UInt16Property` (unsigned 16-bit).
    UInt16,
    /// `UInt32Property` (unsigned 32-bit).
    UInt32,
    /// `UInt64Property` (unsigned 64-bit).
    UInt64,
    /// `FloatProperty` (IEEE 754 single precision).
    Float,
    /// `DoubleProperty` (IEEE 754 double precision).
    Double,
    /// `StrProperty` — UTF-8 / UTF-16 `FString`.
    Str,
    /// `NameProperty` — `FName` (index + number into the asset's name pool).
    Name,
    /// `TextProperty` — localized `FText`.
    Text,
    /// `EnumProperty` — stores a `u8` ordinal on the wire; the resolved
    /// string comes from `Usmap::enums[enum_name]`.
    Enum {
        /// The enum's class name; key into [`Usmap::enums`].
        enum_name: String,
    },
    /// `StructProperty` — nested struct with its own schema.
    Struct {
        /// The struct's class name; key into [`Usmap::schemas`].
        struct_name: String,
    },
    /// `ObjectProperty` — strong reference (`FPackageIndex`).
    Object,
    /// `SoftObjectProperty` — `FSoftObjectPath` (lazy / unresolved reference).
    SoftObject,
    /// `ArrayProperty` — variable-length array with a single inner type.
    Array {
        /// The element type.
        inner: Box<MappedPropertyType>,
    },
    /// Unrecognised or unsupported type byte. Carries the raw byte for
    /// diagnostics so downstream readers can emit
    /// `UnversionedTypeNotSupported { type_byte }` rather than silently
    /// misparsing.
    Unknown(u8),
}

/// A single property entry from a `.usmap` schema.
#[derive(Debug, Clone)]
pub struct MappedProperty {
    /// The property's serialized name.
    pub name: String,
    /// 0-based index within the class's serialisation order.
    pub schema_index: u16,
    /// Per-slot expansion index when the schema declares `array_size > 1`
    /// (a C-style fixed-size array property). Each expanded slot keeps
    /// the same `name` but a distinct `array_index`, mapped 1:1 to
    /// `Property.array_index` (`i32`) on the decoded value.
    pub array_index: i32,
    /// The property's resolved type (with nested arrays / structs / enums
    /// expanded).
    pub prop_type: MappedPropertyType,
}

/// Schema for one class (or struct).
#[derive(Debug, Clone)]
pub struct ClassSchema {
    /// The class's name (key in [`Usmap::schemas`]).
    pub name: String,
    /// Empty string means no super class.
    pub super_type: Option<String>,
    /// Properties defined directly on this class (not inherited), in schema order.
    pub properties: Vec<MappedProperty>,
}

/// Parsed `.usmap` mappings file: a registry of class schemas plus the
/// enum-value tables needed to resolve unversioned `EnumProperty` reads.
#[derive(Debug, Clone, Default)]
pub struct Usmap {
    /// Class name -> [`ClassSchema`]. Schemas are stored flat (parent
    /// schemas are not inlined into child schemas); use
    /// [`Self::get_all_properties`] to walk the inheritance chain.
    pub schemas: HashMap<String, ClassSchema>,
    /// Enum name -> list of value names (indexed by `u8` ordinal in the
    /// wire stream). Required for unversioned `EnumProperty` reads:
    /// the asset stores only a byte index, and the resolved string
    /// comes from this table.
    pub enums: HashMap<String, Vec<String>>,
}

impl Usmap {
    /// Parse a `.usmap` binary blob.
    ///
    /// # Errors
    ///
    /// Returns [`PaksmithError::MappingsParse`] on any wire-format fault:
    /// invalid magic, unsupported version or compression method, size
    /// caps exceeded, decompression mismatch, or truncated data.
    #[allow(
        clippy::too_many_lines,
        reason = "single linear wire-format read: header + versioning block + three compression branches; \
                  splitting into helpers would shred the byte-stream flow and the cap-rejection logic that \
                  must run inline against the raw u32 values before any allocation"
    )]
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor::new(bytes);
        let magic = cur
            .read_u16::<LE>()
            .map_err(|_| fault(MappingsParseFault::Truncated { offset: 0 }))?;
        if magic != USMAP_MAGIC {
            return Err(fault(MappingsParseFault::InvalidMagic { found: magic }));
        }

        let version = cur
            .read_u8()
            .map_err(|_| fault(MappingsParseFault::Truncated { offset: 2 }))?;
        if version > MAX_USMAP_VERSION {
            return Err(fault(MappingsParseFault::UnsupportedVersion {
                found: version,
            }));
        }

        // PackageVersioning block (version >= 1)
        if version >= 1 {
            let has_versioning = cur.read_u8()? != 0;
            if has_versioning {
                // object_version + object_version_ue5 + custom_version array + net_cl
                let _obj_ver = cur.read_i32::<LE>()?;
                let _obj_ver_ue5 = cur.read_i32::<LE>()?;
                let cv_count = cur.read_u32::<LE>()?;
                // Each CustomVersion = 16-byte GUID + i32 version number = 20 bytes.
                // cv_count is u32; i64 widens losslessly via i64::from.
                let skip = i64::from(cv_count) * 20;
                let _ = cur.seek(SeekFrom::Current(skip))?;
                let _net_cl = cur.read_u32::<LE>()?;
            }
        }

        let compression_byte = cur.read_u8()?;
        let compressed_size = cur.read_u32::<LE>()?;
        let decompressed_size = cur.read_u32::<LE>()?;

        // Reject pathological sizes BEFORE allocating, so a malicious
        // header can't force a multi-GiB allocation.
        if compressed_size > MAX_USMAP_COMPRESSED_SIZE {
            return Err(fault(MappingsParseFault::CompressedSizeTooLarge {
                size: compressed_size,
                limit: MAX_USMAP_COMPRESSED_SIZE,
            }));
        }
        if decompressed_size > MAX_USMAP_DECOMPRESSED_SIZE {
            return Err(fault(MappingsParseFault::DecompressedSizeTooLarge {
                size: decompressed_size,
                limit: MAX_USMAP_DECOMPRESSED_SIZE,
            }));
        }

        let mut compressed: Vec<u8> = Vec::new();
        // compressed_size is u32, bounded above by MAX_USMAP_COMPRESSED_SIZE
        // (64 MiB) — well within usize on any supported target (16-bit
        // platforms aren't tier-1 for paksmith). On a 32-bit target, 64 MiB
        // fits comfortably in usize::MAX (~4 GiB).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "compressed_size <= 64 MiB cap, well within usize on 32-bit+"
        )]
        let compressed_size_usz = compressed_size as usize;
        compressed
            .try_reserve_exact(compressed_size_usz)
            .map_err(|_| {
                fault(MappingsParseFault::CompressedSizeTooLarge {
                    size: compressed_size,
                    limit: MAX_USMAP_COMPRESSED_SIZE,
                })
            })?;
        compressed.resize(compressed_size_usz, 0);
        cur.read_exact(&mut compressed)?;

        // decompressed_size is u32, bounded above by MAX_USMAP_DECOMPRESSED_SIZE
        // (256 MiB) — fits in usize on any supported target.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "decompressed_size <= 256 MiB cap, well within usize on 32-bit+"
        )]
        let decompressed_size_usz = decompressed_size as usize;

        let data = match compression_byte {
            x if x == UsmapCompression::None as u8 => {
                if compressed_size != decompressed_size {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: compressed_size_usz,
                    }));
                }
                compressed
            }
            x if x == UsmapCompression::Brotli as u8 => {
                // The `brotli` crate (v7) exposes `Decompressor::new` which
                // wraps a reader and produces decompressed bytes via `Read`.
                // Wrap with `Read::take(decompressed_size + 1)` so a
                // decompression bomb can't produce more than the header
                // claims (the +1 lets us detect over-production and error
                // out before the Vec grows past the declared size).
                let limit = u64::from(decompressed_size) + 1;
                let decoder = brotli::Decompressor::new(Cursor::new(compressed), 4096);
                let mut limited = std::io::Read::take(decoder, limit);
                let mut out: Vec<u8> = Vec::new();
                out.try_reserve_exact(decompressed_size_usz).map_err(|_| {
                    fault(MappingsParseFault::DecompressedSizeTooLarge {
                        size: decompressed_size,
                        limit: MAX_USMAP_DECOMPRESSED_SIZE,
                    })
                })?;
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "cur.position() bounded by input slice length (usize); cast back to usize is round-trip"
                )]
                let pos = cur.position() as usize;
                let _ = limited
                    .read_to_end(&mut out)
                    .map_err(|_| fault(MappingsParseFault::Truncated { offset: pos }))?;
                if out.len() != decompressed_size_usz {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: out.len(),
                    }));
                }
                out
            }
            x if x == UsmapCompression::ZStandard as u8 => {
                // Stream-decode through a Decoder + take(N) bound rather
                // than `decode_all`, so a zstd bomb can't produce GBs of
                // output beyond what the header claimed.
                let limit = u64::from(decompressed_size) + 1;
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "cur.position() bounded by input slice length (usize); cast back to usize is round-trip"
                )]
                let pos_at_decoder = cur.position() as usize;
                let decoder =
                    zstd::stream::Decoder::new(Cursor::new(compressed)).map_err(|_| {
                        fault(MappingsParseFault::Truncated {
                            offset: pos_at_decoder,
                        })
                    })?;
                let mut limited = std::io::Read::take(decoder, limit);
                let mut out: Vec<u8> = Vec::new();
                out.try_reserve_exact(decompressed_size_usz).map_err(|_| {
                    fault(MappingsParseFault::DecompressedSizeTooLarge {
                        size: decompressed_size,
                        limit: MAX_USMAP_DECOMPRESSED_SIZE,
                    })
                })?;
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "cur.position() bounded by input slice length (usize); cast back to usize is round-trip"
                )]
                let pos = cur.position() as usize;
                let _ = limited
                    .read_to_end(&mut out)
                    .map_err(|_| fault(MappingsParseFault::Truncated { offset: pos }))?;
                if out.len() != decompressed_size_usz {
                    return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                        expected: decompressed_size,
                        found: out.len(),
                    }));
                }
                out
            }
            x if x == UsmapCompression::Oodle as u8 => {
                return Err(fault(MappingsParseFault::UsmapCompressionUnsupported {
                    method: x,
                }));
            }
            x => {
                return Err(fault(MappingsParseFault::UsmapCompressionUnsupported {
                    method: x,
                }));
            }
        };

        Self::parse_schema_data(&data)
    }

    fn parse_schema_data(data: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor::new(data);

        // Name table.
        //
        // `name_count` is a wire-controlled u32 — a malicious .usmap can
        // claim up to 4_294_967_295 names. `Vec::with_capacity` would
        // abort the process on allocation failure; `try_reserve` returns
        // an Err we can map to a typed fault. (The MAX_USMAP_DECOMPRESSED_SIZE
        // = 256 MiB cap on the wire only bounds the total decompressed
        // byte stream, NOT the pre-allocation derived from a claimed
        // count field.)
        let name_count = cur.read_u32::<LE>()?;
        let mut names: Vec<String> = Vec::new();
        let pos_for_names = position_usize(&cur);
        names.try_reserve(name_count as usize).map_err(|_| {
            fault(MappingsParseFault::Truncated {
                offset: pos_for_names,
            })
        })?;
        for _ in 0..name_count {
            let name_length = cur.read_u8()?;
            if name_length == 0 {
                return Err(fault(MappingsParseFault::ZeroLengthName {
                    offset: position_usize(&cur),
                }));
            }
            let mut buf = vec![0u8; (name_length - 1) as usize];
            cur.read_exact(&mut buf)?;
            let name = String::from_utf8(buf).unwrap_or_else(|err| {
                tracing::warn!(
                    offset = position_usize(&cur),
                    error = %err,
                    "usmap name is not valid UTF-8; using empty string \
                     (downstream lookups will miss it)"
                );
                String::new()
            });
            names.push(name);
        }

        // Enum table — REQUIRED for unversioned `EnumProperty` reads
        // (per CUE4Parse's EnumProperty constructor for unversioned mode:
        // wire stream stores a u8 index; the resolved value name comes
        // from this table).
        let enum_count = cur.read_u32::<LE>()?;
        let mut enums: HashMap<String, Vec<String>> = HashMap::new();
        let pos_for_enums = position_usize(&cur);
        enums.try_reserve(enum_count as usize).map_err(|_| {
            fault(MappingsParseFault::Truncated {
                offset: pos_for_enums,
            })
        })?;
        for _ in 0..enum_count {
            let enum_name = read_name(&mut cur, &names)?;
            let value_count = cur.read_u8()?;
            let mut values: Vec<String> = Vec::with_capacity(value_count as usize);
            for _ in 0..value_count {
                let value_name = read_name(&mut cur, &names)?;
                values.push(value_name);
            }
            let _ = enums.insert(enum_name, values);
        }

        // Schema table.
        let schema_count = cur.read_u32::<LE>()?;
        let mut schemas: HashMap<String, ClassSchema> = HashMap::new();
        let pos_for_schemas = position_usize(&cur);
        schemas.try_reserve(schema_count as usize).map_err(|_| {
            fault(MappingsParseFault::Truncated {
                offset: pos_for_schemas,
            })
        })?;

        for _ in 0..schema_count {
            let name = read_name(&mut cur, &names)?;
            let super_type_str = read_name(&mut cur, &names)?;
            // UE's sentinel for "no superclass" is the literal name "None".
            // Empty strings are preserved as `Some("")` per the wire format —
            // the inheritance walk's `!parent.is_empty()` guard handles them
            // identically to `None` for traversal purposes.
            let super_type = if super_type_str == "None" {
                None
            } else {
                Some(super_type_str)
            };

            let _prop_count = cur.read_u16::<LE>()?;
            let serial_count = cur.read_u16::<LE>()?;

            let mut properties: Vec<MappedProperty> = Vec::with_capacity(serial_count as usize);
            for _ in 0..serial_count {
                let schema_index = cur.read_u16::<LE>()?;
                let array_size = cur.read_u8()?;
                let prop_name = read_name(&mut cur, &names)?;
                let prop_type = read_mapped_type(&mut cur, &names)?;

                // Expand array_size > 1 into consecutive slots. Keep the
                // name identical for every expanded slot; encode the C-style
                // fixed-array index on `array_index` instead so the decoded
                // `Property.array_index` matches the wire convention used by
                // the tagged-property path.
                for arr_idx in 0..array_size {
                    properties.push(MappedProperty {
                        name: prop_name.clone(),
                        schema_index: schema_index + u16::from(arr_idx),
                        array_index: i32::from(arr_idx),
                        prop_type: prop_type.clone(),
                    });
                }
            }

            let _ = schemas.insert(
                name.clone(),
                ClassSchema {
                    name,
                    super_type,
                    properties,
                },
            );
        }

        Ok(Usmap { schemas, enums })
    }

    /// Returns all properties for `class_name` in inheritance order
    /// (super-chain first, then own properties), ordered by `schema_index`
    /// within each level.
    ///
    /// **Cycle handling:** A malicious `.usmap` can craft a cyclic
    /// `super_type` chain (`A: B`, `B: A`). A naive walk would loop
    /// forever — DoS. We track visited classes and break on cycle, and
    /// additionally cap the chain at `MAX_INHERITANCE_DEPTH`.
    pub fn get_all_properties(&self, class_name: &str) -> Vec<&MappedProperty> {
        let mut chain: Vec<&str> = Vec::new();
        let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut current = class_name;
        for _ in 0..MAX_INHERITANCE_DEPTH {
            if !visited.insert(current) {
                // Cycle: `current` was already seen. Stop walking.
                // Log via `tracing::warn!` so operators see the malformed
                // usmap, but don't error — caller may still want the
                // properties we collected up to this point.
                tracing::warn!(
                    class = current,
                    "circular super_type chain in .usmap; truncating inheritance walk"
                );
                break;
            }
            chain.push(current);
            match self
                .schemas
                .get(current)
                .and_then(|s| s.super_type.as_deref())
            {
                Some(parent) if !parent.is_empty() => current = parent,
                _ => break,
            }
        }
        // Reverse so super-chain is first.
        chain.reverse();
        let mut result = Vec::new();
        for name in chain {
            if let Some(schema) = self.schemas.get(name) {
                result.extend(schema.properties.iter());
            }
        }
        result
    }
}

/// Resolve a name index against the parsed name table. Shared by the
/// schema-table walk, the enum-table walk, and `read_mapped_type`'s
/// inner-name reads.
fn read_name(cur: &mut Cursor<&[u8]>, names: &[String]) -> crate::Result<String> {
    let idx = cur.read_i32::<LE>()?;
    #[allow(
        clippy::cast_sign_loss,
        reason = "name indices are non-negative; out-of-range values fall through to the get() bounds check"
    )]
    let idx_usz = idx as usize;
    names.get(idx_usz).cloned().ok_or_else(|| {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "cur.position() bounded by input slice length (usize); cast back is round-trip"
        )]
        let pos = cur.position() as usize;
        fault(MappingsParseFault::Truncated { offset: pos })
    })
}

#[allow(
    clippy::match_same_arms,
    clippy::manual_range_patterns,
    reason = "each EPropertyType discriminant is documented per-byte against the oracle's enum; \
              merging Unknown arms or collapsing to ranges would erase the 1:1 wire-format table \
              that anchors the cross-validation in the plan doc"
)]
fn read_mapped_type(
    cur: &mut Cursor<&[u8]>,
    names: &[String],
) -> crate::Result<MappedPropertyType> {
    let type_byte = cur.read_u8()?;
    // EPropertyType discriminants per the oracle's `pub enum EPropertyType`
    // at `unreal_asset_base/src/unversioned/properties/mod.rs`. Pinned
    // revision `f4df5d8e` — re-verify if the oracle pin moves.
    Ok(match type_byte {
        0 => MappedPropertyType::UInt8,                        // ByteProperty
        1 => MappedPropertyType::Bool,                         // BoolProperty
        2 => MappedPropertyType::Int32,                        // IntProperty
        3 => MappedPropertyType::Float,                        // FloatProperty
        4 => MappedPropertyType::Object,                       // ObjectProperty
        5 => MappedPropertyType::Name,                         // NameProperty
        6 | 12 | 13 => MappedPropertyType::Unknown(type_byte), // Delegate/Interface/MulticastDelegate
        7 => MappedPropertyType::Double,                       // DoubleProperty
        8 => {
            // ArrayProperty
            let inner = read_mapped_type(cur, names)?;
            MappedPropertyType::Array {
                inner: Box::new(inner),
            }
        }
        9 => {
            // StructProperty
            let struct_name = read_name(cur, names)?;
            MappedPropertyType::Struct { struct_name }
        }
        10 => MappedPropertyType::Str,        // StrProperty
        11 => MappedPropertyType::Text,       // TextProperty
        17 => MappedPropertyType::SoftObject, // SoftObjectProperty (FSoftObjectPath: FName + FString)
        // WeakObject (14), LazyObject (15), AssetObject (16) have distinct
        // wire formats (LazyObject is a 16-byte FUniqueObjectGuid;
        // WeakObject and AssetObject differ from SoftObject in subtle ways).
        // Map them to Unknown so the reader emits UnversionedTypeNotSupported
        // rather than silently misparsing FSoftObjectPath bytes.
        14 | 15 | 16 => MappedPropertyType::Unknown(type_byte),
        18 => MappedPropertyType::UInt64, // UInt64Property
        19 => MappedPropertyType::UInt32, // UInt32Property
        20 => MappedPropertyType::UInt16, // UInt16Property
        21 => MappedPropertyType::Int64,  // Int64Property
        22 => MappedPropertyType::Int16,  // Int16Property
        23 => MappedPropertyType::Int8,   // Int8Property
        24 | 25 => MappedPropertyType::Unknown(type_byte), // Map/Set
        26 => {
            // EnumProperty: inner type byte then enum name
            let _inner_byte = cur.read_u8()?; // always ByteProperty (0) in practice
            let enum_name = read_name(cur, names)?;
            MappedPropertyType::Enum { enum_name }
        }
        27 => MappedPropertyType::Unknown(type_byte), // FieldPathProperty
        other => MappedPropertyType::Unknown(other),
    })
}

fn fault(f: MappingsParseFault) -> PaksmithError {
    PaksmithError::MappingsParse { fault: f }
}

/// Returns the cursor's byte offset as a `usize` for use in
/// `MappingsParseFault::*` `offset` fields. The cast is safe because
/// the cursor is constructed over an `&[u8]` whose length is bounded
/// by the source slice (and on every realistic target `usize` ≤ `u64`).
fn position_usize(cur: &Cursor<&[u8]>) -> usize {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "cursor position is bounded by the source slice length (usize); cast is round-trip on all paksmith targets"
    )]
    let pos = cur.position() as usize;
    pos
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_usmap_none() -> Vec<u8> {
        // Magic + version(0) + compression(0) + schema data with one class
        // "Hero" (name 0), "" (name 1), "Health" (name 2), "Speed" (name 3)
        // One schema: Hero, super="", 2 props: Health(Int32), Speed(Float)
        let mut data: Vec<u8> = Vec::new();
        // Name table
        data.extend_from_slice(&4u32.to_le_bytes()); // 4 names
        for (s, name) in [(5u8, "Hero"), (1u8, ""), (7u8, "Health"), (6u8, "Speed")] {
            data.push(s);
            data.extend_from_slice(name.as_bytes());
        }
        // Enum table
        data.extend_from_slice(&0u32.to_le_bytes());
        // Schema table
        data.extend_from_slice(&1u32.to_le_bytes());
        // Schema: name=0("Hero"), super=1(""), prop_count=2, serial_count=2
        data.extend_from_slice(&0i32.to_le_bytes()); // name idx
        data.extend_from_slice(&1i32.to_le_bytes()); // super idx
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
        data.extend_from_slice(&2u16.to_le_bytes()); // serial count
        // Prop 0: schema_index=0, array_size=1, name=2("Health"), type=IntProperty(2)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // name idx
        data.push(2u8); // IntProperty
        // Prop 1: schema_index=1, array_size=1, name=3("Speed"), type=FloatProperty(3)
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&3i32.to_le_bytes());
        data.push(3u8); // FloatProperty

        #[allow(
            clippy::cast_possible_truncation,
            reason = "test fixture builds a sub-256-byte schema block; data.len() fits in u32 trivially"
        )]
        let data_len = data.len() as u32;
        let mut usmap: Vec<u8> = Vec::new();
        usmap.extend_from_slice(&[0x30u8, 0xC4u8]); // magic LE
        usmap.push(0u8); // version = Initial
        usmap.push(0u8); // compression = None
        usmap.extend_from_slice(&data_len.to_le_bytes()); // compressed_size
        usmap.extend_from_slice(&data_len.to_le_bytes()); // decompressed_size
        usmap.extend_from_slice(&data);
        usmap
    }

    #[test]
    fn parse_minimal_usmap_none_schema() {
        let bytes = minimal_usmap_none();
        let usmap = Usmap::from_bytes(&bytes).unwrap();
        let schema = usmap.schemas.get("Hero").unwrap();
        assert_eq!(schema.super_type.as_deref(), Some(""));
        assert_eq!(schema.properties.len(), 2);
        assert_eq!(schema.properties[0].name, "Health");
        assert!(matches!(
            schema.properties[0].prop_type,
            MappedPropertyType::Int32
        ));
        assert_eq!(schema.properties[1].name, "Speed");
        assert!(matches!(
            schema.properties[1].prop_type,
            MappedPropertyType::Float
        ));
    }

    #[test]
    fn parse_usmap_invalid_magic() {
        let mut bytes = minimal_usmap_none();
        bytes[0] = 0xFF;
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::InvalidMagic { .. }
            }
        ));
    }

    #[test]
    fn parse_usmap_unsupported_version() {
        let mut bytes = minimal_usmap_none();
        bytes[2] = 9u8; // version byte
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::UnsupportedVersion { found: 9 }
            }
        ));
    }

    #[test]
    fn parse_usmap_oodle_rejected() {
        let mut bytes = minimal_usmap_none();
        bytes[3] = 1u8; // compression = Oodle
        let err = Usmap::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::UsmapCompressionUnsupported { method: 1 }
            }
        ));
    }

    #[test]
    fn get_all_properties_with_inheritance() {
        // Build a usmap with Parent(x: Int) and Child extends Parent(y: Float)
        let mut data: Vec<u8> = Vec::new();
        // Names: "Parent"(0), ""(1), "x"(2), "Child"(3), "y"(4)
        data.extend_from_slice(&5u32.to_le_bytes());
        for (s, name) in [
            (7u8, "Parent"),
            (1u8, ""),
            (2u8, "x"),
            (6u8, "Child"),
            (2u8, "y"),
        ] {
            data.push(s);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&2u32.to_le_bytes()); // 2 schemas
        // Schema Parent: name=0, super=1(""), prop_count=1, serial=1
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // schema_index=0
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "x"
        data.push(2u8); // IntProperty
        // Schema Child: name=3("Child"), super=0("Parent"), prop_count=2, serial=1
        data.extend_from_slice(&3i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // super = "Parent"
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count includes inherited
        data.extend_from_slice(&1u16.to_le_bytes()); // only 1 new prop serialized
        data.extend_from_slice(&1u16.to_le_bytes()); // schema_index=1
        data.push(1u8);
        data.extend_from_slice(&4i32.to_le_bytes()); // "y"
        data.push(3u8); // FloatProperty

        #[allow(
            clippy::cast_possible_truncation,
            reason = "test fixture builds a sub-256-byte schema block; data.len() fits in u32 trivially"
        )]
        let data_len = data.len() as u32;
        let mut usmap = vec![0x30u8, 0xC4, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let usmap = Usmap::from_bytes(&usmap).unwrap();
        let all = usmap.get_all_properties("Child");
        // inheritance order: Parent's props first, then Child's own
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "x");
        assert_eq!(all[1].name, "y");
    }
}
