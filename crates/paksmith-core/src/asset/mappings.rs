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

// `.usmap` file magic, per CUE4Parse `UsmapParser.cs`:
// `private const ushort FileMagic = 0x30C4;` read via the archive's
// little-endian `Read<ushort>()` — so on-disk bytes are `C4 30`.
const USMAP_MAGIC: u16 = 0x30C4;

// `EUsmapVersion` byte values, per CUE4Parse `EUsmapVersion.cs`. Each
// constant marks the FIRST version that introduces the named
// wire-format change.
const USMAP_VERSION_PACKAGE_VERSIONING: u8 = 1;
const USMAP_VERSION_LONG_FNAME: u8 = 2;
const USMAP_VERSION_LARGE_ENUMS: u8 = 3;
const USMAP_VERSION_EXPLICIT_ENUM_VALUES: u8 = 4;
const MAX_USMAP_VERSION: u8 = USMAP_VERSION_EXPLICIT_ENUM_VALUES; // EUsmapVersion::Latest

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

/// Hard cap on `enum_count` to bound the v3/v4 enum-table heap cost.
/// Per-enum `HashMap<u64, String>` overhead is ~5-8x the wire size,
/// so the global `MAX_USMAP_DECOMPRESSED_SIZE` cap alone allowed
/// ~1 GiB of heap growth on a maxed-out enum table. Realistic UE
/// mappings carry <1k enums (Fortnite tops out around a few hundred);
/// 4096 is a wide safety margin.
///
/// Exposed via [`max_usmap_enum_count`].
const MAX_USMAP_ENUM_COUNT: u32 = 4_096;

/// Hard cap on per-enum `value_count`. `LargeEnums` (v3) widened the
/// wire field to `u16` (65535 max); no real-world enum has that many
/// values — even unwieldy Unreal enums top out in the low hundreds.
/// 1024 leaves room for outliers while bounding the per-enum heap
/// to a few KiB.
///
/// Exposed via [`max_usmap_values_per_enum`].
const MAX_USMAP_VALUES_PER_ENUM: u32 = 1_024;

/// Hard cap on the post-expansion property count per schema. The
/// wire encodes `(schema_index, array_size, name, type)` rows where
/// `array_size` (u8) expands each row into up to 255 `MappedProperty`
/// entries; combined with the u16 `serial_count` the total expansion
/// reaches ~16.7M entries, ~1 GiB of heap per schema. Real game
/// schemas hold a few hundred properties even after C-style fixed-
/// array expansion (Fortnite's tops out around 1024); 65536 is a
/// wide safety margin.
///
/// Exposed via [`max_usmap_expanded_properties_per_schema`].
const MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA: u32 = 65_536;

/// Test-only accessor for `MAX_USMAP_ENUM_COUNT`. Boundary tests read
/// the live value rather than duplicating the literal, which would
/// silently drift if the cap ever changes. Gated behind `__test_utils`
/// so downstream consumers cannot pin against this value.
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_enum_count() -> u32 {
    MAX_USMAP_ENUM_COUNT
}

/// Test-only accessor for `MAX_USMAP_VALUES_PER_ENUM`. Same rationale
/// as [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_values_per_enum() -> u32 {
    MAX_USMAP_VALUES_PER_ENUM
}

/// Test-only accessor for `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA`.
/// Same rationale as [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_expanded_properties_per_schema() -> u32 {
    MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA
}

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
    /// Enum name -> `(u64 ordinal -> value name)` map. Required for
    /// unversioned `EnumProperty` reads: the asset stores a byte
    /// ordinal, and the resolved string comes from this table.
    ///
    /// Keyed by `u64` rather than positional `Vec` index because
    /// `.usmap` versions ≥ `ExplicitEnumValues` (4) store explicit
    /// ordinals on the wire, which may be sparse (e.g.,
    /// `enum E { A = 0, C = 2 }`). For pre-v4 fixtures the parser
    /// fills the map at positional ordinals so the lookup path is
    /// uniform across versions.
    pub enums: HashMap<String, HashMap<u64, String>>,
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
        if version >= USMAP_VERSION_PACKAGE_VERSIONING {
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

        Self::parse_schema_data(&data, version)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "single linear wire-format read: name table, enum table (with v2/v3/v4 \
                  version-gated branches), schema table; splitting into helpers would shred \
                  the shared `cur`/`names`/`enums` flow that each section feeds into the next"
    )]
    fn parse_schema_data(data: &[u8], version: u8) -> crate::Result<Self> {
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
            // CUE4Parse `UsmapParser.cs:95`:
            //   `var nameLength = Ar.Version >= EUsmapVersion.LongFName
            //                     ? Ar.Read<ushort>() : Ar.Read<byte>();`
            // followed by `Ar.ReadStringUnsafe(nameLength)` which reads
            // exactly `nameLength` bytes (no trailing null, no `-1`).
            let name_length: usize = if version >= USMAP_VERSION_LONG_FNAME {
                cur.read_u16::<LE>()? as usize
            } else {
                cur.read_u8()? as usize
            };
            let mut buf = vec![0u8; name_length];
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
        if enum_count > MAX_USMAP_ENUM_COUNT {
            return Err(fault(MappingsParseFault::EnumCountTooLarge {
                count: enum_count,
                limit: MAX_USMAP_ENUM_COUNT,
            }));
        }
        let mut enums: HashMap<String, HashMap<u64, String>> = HashMap::new();
        let pos_for_enums = position_usize(&cur);
        enums.try_reserve(enum_count as usize).map_err(|_| {
            fault(MappingsParseFault::Truncated {
                offset: pos_for_enums,
            })
        })?;
        for _ in 0..enum_count {
            let enum_name = read_name(&mut cur, &names)?;
            // CUE4Parse `UsmapParser.cs`:
            //   `enumNamesSize = Ar.Version >= EUsmapVersion.LargeEnums
            //                    ? Ar.Read<ushort>() : Ar.Read<byte>();`
            let value_count_u32: u32 = if version >= USMAP_VERSION_LARGE_ENUMS {
                u32::from(cur.read_u16::<LE>()?)
            } else {
                u32::from(cur.read_u8()?)
            };
            if value_count_u32 > MAX_USMAP_VALUES_PER_ENUM {
                return Err(fault(MappingsParseFault::EnumValueCountTooLarge {
                    count: value_count_u32,
                    limit: MAX_USMAP_VALUES_PER_ENUM,
                }));
            }
            let value_count = value_count_u32 as usize;
            let mut values: HashMap<u64, String> = HashMap::new();
            let pos_for_values = position_usize(&cur);
            values.try_reserve(value_count).map_err(|_| {
                fault(MappingsParseFault::Truncated {
                    offset: pos_for_values,
                })
            })?;
            if version >= USMAP_VERSION_EXPLICIT_ENUM_VALUES {
                // CUE4Parse: `value = Ar.Read<ulong>(); name = Ar.ReadName(...)`.
                for _ in 0..value_count {
                    let value = cur.read_u64::<LE>()?;
                    let value_name = read_name(&mut cur, &names)?;
                    let _ = values.insert(value, value_name);
                }
            } else {
                // Pre-v4 positional: ordinal = iteration index.
                for i in 0..value_count {
                    let value_name = read_name(&mut cur, &names)?;
                    let _ = values.insert(i as u64, value_name);
                }
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

            // `Vec::with_capacity(serial_count)` would mis-predict the
            // final size (the inner array-expansion loop can push up
            // to `serial_count × 255` entries) AND allocate
            // infallibly. Use `try_reserve` per-batch (mapped to
            // `Truncated` for consistency with the surrounding
            // table-reservation sites; #363 follow-up tracks routing
            // OOM through a dedicated `AllocationFailed` variant).
            let mut properties: Vec<MappedProperty> = Vec::new();
            for _ in 0..serial_count {
                let schema_index = cur.read_u16::<LE>()?;
                let array_size = cur.read_u8()?;
                let prop_name = read_name(&mut cur, &names)?;
                let prop_type = read_mapped_type(&mut cur, &names)?;

                // u32 arithmetic is sufficient: `properties.len()` is
                // bounded above by `serial_count × array_size` =
                // 65535 × 255 < u32::MAX, and `array_size` is u8.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "properties.len() bounded by serial_count × u8::MAX < u32::MAX"
                )]
                let current = properties.len() as u32;
                let new_total = current.saturating_add(u32::from(array_size));
                if new_total > MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA {
                    return Err(fault(MappingsParseFault::ExpandedPropertiesExceeded {
                        schema: name.clone(),
                        requested: new_total,
                        limit: MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA,
                    }));
                }
                let pos_for_expansion = position_usize(&cur);
                properties
                    .try_reserve(usize::from(array_size))
                    .map_err(|_| {
                        fault(MappingsParseFault::Truncated {
                            offset: pos_for_expansion,
                        })
                    })?;

                // Expand array_size > 1 into consecutive slots. Keep the
                // name identical for every expanded slot; encode the C-style
                // fixed-array index on `array_index` instead so the decoded
                // `Property.array_index` matches the wire convention used by
                // the tagged-property path.
                for arr_idx in 0..array_size {
                    properties.push(MappedProperty {
                        name: prop_name.clone(),
                        schema_index: schema_index.saturating_add(u16::from(arr_idx)),
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

// Tests are gated on `__test_utils` (rather than plain `#[cfg(test)]`)
// because they reuse `testing::usmap::build_minimal_usmap_bytes` — the
// canonical source for the minimal `.usmap` byte fixture, shared with
// fixture-gen + integration tests. Same precedent as `package.rs`. The
// trade-off: these four tests run only under `cargo test --workspace
// --all-features` (i.e., the CI invocation), not bare `cargo test`. The
// DRY win (≥45 lines of duplicate wire-format bytes) is worth the
// local-vs-CI signal gap; a future stand-alone reader-only test that
// doesn't need the helper can sit in a separate `#[cfg(test)]` module.
#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::testing::usmap::build_minimal_usmap_bytes as minimal_usmap_none;

    #[test]
    fn parse_minimal_usmap_none_schema() {
        let bytes = minimal_usmap_none();
        let usmap = Usmap::from_bytes(&bytes).unwrap();
        let schema = usmap.schemas.get("Hero").unwrap();
        // Builder uses "None" as the no-super sentinel, which the parser
        // maps to `super_type: None` (see parse_schema_data).
        assert_eq!(schema.super_type, None);
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
    fn parse_usmap_enum_count_too_large_rejected() {
        // Build a minimal v0 .usmap whose name table is empty and
        // whose enum_count claims one more than the cap. Anything past
        // the enum_count read should be irrelevant — the cap check
        // fires first.
        let cap = max_usmap_enum_count();
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // name_count = 0
        data.extend_from_slice(&(cap + 1).to_le_bytes()); // enum_count = cap + 1
        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0]; // magic + v0 + None compression
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::EnumCountTooLarge { count, limit },
            } => {
                assert_eq!(count, cap + 1);
                assert_eq!(limit, cap);
            }
            other => panic!("expected EnumCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_enum_value_count_too_large_rejected() {
        // Build a v3 .usmap (LargeEnums) with one enum claiming
        // (cap + 1) values via u16 wire-width. Triggers the per-enum
        // cap check.
        let cap = max_usmap_values_per_enum();
        let cap_plus_one_u16 = u16::try_from(cap + 1).expect("cap+1 fits in u16");
        let mut data: Vec<u8> = Vec::new();
        // Name table: one entry "E" so the enum name resolves.
        data.extend_from_slice(&1u32.to_le_bytes());
        // v3 = LongFName (u16 name length) — write u16.
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(b"E");
        // Enum table: one enum, name_idx = 0, value_count = cap + 1.
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // enum_name idx
        data.extend_from_slice(&cap_plus_one_u16.to_le_bytes()); // u16 LargeEnums width
        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 3, 0, 0]; // magic + v3 + has_versioning=0 + compression None
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::EnumValueCountTooLarge { count, limit },
            } => {
                assert_eq!(count, cap + 1);
                assert_eq!(limit, cap);
            }
            other => panic!("expected EnumValueCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_expanded_properties_exceeded_rejected() {
        // Craft a v0 .usmap with a schema whose `serial_count` × max
        // `array_size` (u8 = 255) blows past
        // `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA`. The cap check
        // must fire before any push into `properties`.
        let cap = max_usmap_expanded_properties_per_schema();
        // Choose serial_count so that even 1 expansion past the
        // declared rows would exceed the cap; setting
        // serial_count = ceil(cap / 255) + 1 with array_size = 255
        // overshoots by exactly one row's expansion.
        let rows = u16::try_from(cap.div_ceil(255) + 1).expect("rows fit in u16");
        let mut data: Vec<u8> = Vec::new();
        // Name table: "Hero" (schema), "None" (no-super), "P" (prop).
        data.extend_from_slice(&3u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (1u8, "P")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        // Enum table: empty.
        data.extend_from_slice(&0u32.to_le_bytes());
        // Schema table: one class.
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero"
        data.extend_from_slice(&1i32.to_le_bytes()); // super = "None"
        data.extend_from_slice(&rows.to_le_bytes()); // prop_count
        data.extend_from_slice(&rows.to_le_bytes()); // serial_count
        // Each row: schema_index=0, array_size=255, name_idx=2 (P), type=IntProperty.
        for _ in 0..rows {
            data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
            data.push(255u8); // array_size — maximal expansion
            data.extend_from_slice(&2i32.to_le_bytes()); // name idx = "P"
            data.push(2u8); // IntProperty
        }
        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0]; // magic + v0 + None compression
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault:
                    crate::error::MappingsParseFault::ExpandedPropertiesExceeded {
                        schema,
                        requested,
                        limit,
                    },
            } => {
                assert_eq!(schema, "Hero");
                assert!(
                    requested > cap,
                    "requested {requested} should exceed cap {cap}"
                );
                assert_eq!(limit, cap);
            }
            other => panic!("expected ExpandedPropertiesExceeded, got {other:?}"),
        }
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
        // Names: "Parent"(0), "None"(1, no-super sentinel), "x"(2),
        //        "Child"(3), "y"(4)
        data.extend_from_slice(&5u32.to_le_bytes());
        for (len, name) in [
            (6u8, "Parent"),
            (4u8, "None"),
            (1u8, "x"),
            (5u8, "Child"),
            (1u8, "y"),
        ] {
            data.push(len);
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
        // Magic bytes `C4 30` decode as little-endian u16 = 0x30C4.
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
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
