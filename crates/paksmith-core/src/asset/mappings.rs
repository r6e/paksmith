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
use std::sync::Arc;

use byteorder::{LE, ReadBytesExt};

use crate::PaksmithError;
use crate::error::{MappingsAllocationContext, MappingsParseFault, mappings_alloc_failed};

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

/// Hard cap on the wire-claimed `schema_count`. Each schema costs a
/// `String` key + `ClassSchema` struct (~110 bytes) in
/// `Usmap::schemas`; without this cap the 256 MiB
/// `MAX_USMAP_DECOMPRESSED_SIZE` budget alone permitted ~13M
/// schemas / ~1.4 GiB heap before any per-schema property
/// allocation fired. Real-world `.usmap` schema tables top out
/// around 500–2000 entries (Fortnite); 4096 leaves wide headroom
/// and matches the [`MAX_USMAP_ENUM_COUNT`] rationale.
///
/// Exposed via [`max_usmap_schema_count`].
const MAX_USMAP_SCHEMA_COUNT: u32 = 4_096;

/// Hard cap on the wire-claimed `name_count`. Without this cap the
/// 256 MiB `MAX_USMAP_DECOMPRESSED_SIZE` budget alone permitted a
/// `name_count` of ~4_294_967_295 (the u32 max) — the subsequent
/// `try_reserve` would surface as `MappingsAllocationContext::NameTable`
/// OOM rather than a typed wire-cap rejection. Real-world `.usmap`
/// name tables top out around 10k entries (very large games);
/// 131_072 (128k) leaves wide headroom and bounds the pre-allocation
/// to a single-digit-MiB `Vec<String>` slot reservation.
///
/// Exposed via [`max_usmap_name_count`].
const MAX_USMAP_NAME_COUNT: u32 = 131_072;

/// Hard cap on the total entry count in the flattened-property cache
/// (#370), summed across every class's flattened inheritance chain.
/// Each class's flat list concatenates its own properties with every
/// ancestor's properties up to `MAX_INHERITANCE_DEPTH = 64` levels;
/// without this cap the product of the per-class
/// (`MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA = 65_536`) and
/// schema-table (`MAX_USMAP_SCHEMA_COUNT = 4_096`) caps permits a
/// cache of ~17 G entries (~1 TB heap) against valid per-class wire
/// fixtures. Real-world `.usmap` files top out around ~30 k cache
/// entries; 4_194_304 (4 Mi) entries × ~64 bytes/`ResolvedProperty`
/// caps the cache at ~256 MiB worst case — matching the
/// `MAX_USMAP_DECOMPRESSED_SIZE` wire-input cap and leaving wide
/// headroom for legitimate `.usmap` schemas.
///
/// Surfaces as [`MappingsParseFault::FlattenedCacheTooLarge`] when
/// exceeded during `Usmap::from_bytes`'s cache build. Found by
/// security-review on PR #444 (R2 panel).
///
/// Exposed via [`max_usmap_flattened_total_entries`].
const MAX_USMAP_FLATTENED_TOTAL_ENTRIES: u64 = 4_194_304;

/// Hard cap on the wire-claimed `cv_count` in the .usmap versioning
/// block. Real-world `CustomVersionContainer`s top out in the low
/// tens (Fortnite ships `cv_count = 3`); 1_024 leaves wide headroom.
///
/// Without this cap an absurd `cv_count` would still terminate the
/// parse via a downstream `MappingsParseFault::Truncated` fault when
/// the post-seek `_net_cl` read overshoots the input slice — but the
/// triage signal would be "wire stream truncated" rather than the
/// wire-cap-specific `CvCountTooLarge`. The cap delivers the correct
/// typed fault BEFORE the seek runs.
///
/// Exposed via [`max_usmap_cv_count`].
const MAX_USMAP_CV_COUNT: u32 = 1_024;

/// Hard cap on the recursive nesting depth in `read_mapped_type`.
/// `ArrayProperty` type byte (`0x08`) recursively reads its inner
/// type, so a wire schema row with type bytes `08 08 08 ... <leaf>`
/// exercises one stack frame per byte. Without this cap a `.usmap`
/// claiming a few thousand `0x08` bytes inside the 256 MiB
/// `MAX_USMAP_DECOMPRESSED_SIZE` budget walks the default 8 MiB
/// runner stack to SIGSEGV.
///
/// Real-world UE arrays are at most a few levels deep (Array<Object>,
/// Array<Struct<Array<...>>> tops out around 3); 16 leaves
/// comfortable headroom while bounding the recursion.
///
/// Discovered by retroactive security-review on PR #443 (the fuzz
/// harness PR — `fuzz_usmap_parse` would find this on first run).
/// Exposed via [`max_usmap_array_nesting_depth`].
const MAX_USMAP_ARRAY_NESTING_DEPTH: usize = 16;

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

/// Test-only accessor for `MAX_USMAP_SCHEMA_COUNT`. Same rationale
/// as [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_schema_count() -> u32 {
    MAX_USMAP_SCHEMA_COUNT
}

/// Test-only accessor for `MAX_USMAP_FLATTENED_TOTAL_ENTRIES`. Same
/// rationale as [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_flattened_total_entries() -> u64 {
    MAX_USMAP_FLATTENED_TOTAL_ENTRIES
}

/// Test-only accessor for `MAX_USMAP_NAME_COUNT`. Same rationale as
/// [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_name_count() -> u32 {
    MAX_USMAP_NAME_COUNT
}

/// Test-only accessor for `MAX_USMAP_ARRAY_NESTING_DEPTH`. Same
/// rationale as [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_array_nesting_depth() -> usize {
    MAX_USMAP_ARRAY_NESTING_DEPTH
}

/// Test-only accessor for `MAX_USMAP_CV_COUNT`. Same rationale as
/// [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_cv_count() -> u32 {
    MAX_USMAP_CV_COUNT
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
///
/// `#[non_exhaustive]` so future variants (Map / Set / Delegate /
/// FieldPath, currently the `Unknown(byte)` catch-all) can land as
/// source-compatible additions. The enum is already semver-broken
/// by issue #397 sub-fix A's `String → Arc<str>` field-type change
/// on the `Enum` and `Struct` payloads — the attribute landed in the
/// same window so subsequent variant additions don't compound the
/// break.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
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
        ///
        /// `Arc<str>` rather than `String` to bound the
        /// **expansion-clone amplification** in the schema-property
        /// loop: `array_size` (u8) expands each row into up to 255
        /// `MappedProperty` entries, each previously String-cloning
        /// the name. Under `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA
        /// = 65,536` slots and maximal-LongFName names that's ~4 GiB
        /// of clone-only heap per schema — now one refcount bump per
        /// expanded slot. The TOTAL per-name heap (one alloc per
        /// wire row) is still bounded by `MAX_USMAP_DECOMPRESSED_SIZE
        /// = 256 MiB` on the input side. Issue #397 sub-fix A.
        enum_name: Arc<str>,
    },
    /// `StructProperty` — nested struct with its own schema.
    Struct {
        /// The struct's class name; key into [`Usmap::schemas`].
        ///
        /// `Arc<str>` for the same expansion-clone-bounding reason
        /// as [`Self::Enum::enum_name`].
        struct_name: Arc<str>,
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
///
/// `#[non_exhaustive]` so future wire-derived metadata additions
/// (e.g. editor-only / deprecation flags surfaced by later `.usmap`
/// versions) can land as source-compatible field additions. Per
/// issue #414 — bundled with [`Usmap`] in this PR; sibling
/// [`MappedPropertyType`] gained the attribute alongside the Arc
/// migration in #416 because its variant payloads also shifted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MappedProperty {
    /// The property's serialized name.
    ///
    /// `Arc<str>` so the `array_size` expansion loop in
    /// [`Usmap::from_bytes`] clones a refcount per expanded slot
    /// rather than a heap-allocated name buffer. Bounds the
    /// **expansion-clone amplification** specifically: pre-migration
    /// each clone allocated up to 65535 bytes (LongFName max) and
    /// the 65,536 `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA` cap
    /// permitted ~4 GiB of clone-only heap per schema. The TOTAL
    /// per-name heap (one alloc per wire row, independent of
    /// `array_size`) is still bounded by `MAX_USMAP_DECOMPRESSED_SIZE
    /// = 256 MiB` on the input side. Issue #397 sub-fix A.
    pub name: Arc<str>,
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
///
/// `#[non_exhaustive]` so future wire-derived metadata additions
/// (e.g. [`Self::prop_count`], which landed when issue #391
/// surfaced the child-first-concat inheritance-offset bug) are
/// source-compatible for downstream field additions.
///
/// **Note on the `#[non_exhaustive]` addition itself:** before this
/// attribute landed, downstream code could exhaustively match
/// `ClassSchema { name, super_type, properties }`. After, exhaustive
/// matches require `..` — this IS a semver-breaking change for any
/// such consumer (acceptable pre-crates.io, would warrant a major
/// bump post-publish). The field addition that motivated the attribute
/// is itself source-compatible only because the attribute landed in
/// the same PR.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClassSchema {
    /// The class's name (key in [`Usmap::schemas`]).
    pub name: String,
    /// Empty string means no super class.
    pub super_type: Option<String>,
    /// Wire-declared `PropertyCount` — total number of properties on
    /// this class (serializable + transient/editor-only/deprecated),
    /// **not** the size of [`Self::properties`] (which only carries the
    /// `serial_count` serializable entries).
    ///
    /// Required by [`Usmap::get_all_properties`] to compute the
    /// child-first-concat absolute slot indices for inherited classes:
    /// when walking from child → parent, each parent's per-class
    /// `schema_index` is shifted by the sum of preceding classes'
    /// `prop_count` (per CUE4Parse `MappingsProvider/Usmap/
    /// MappingsSchema.cs::Struct.TryGetValue`).
    pub prop_count: u16,
    /// Properties defined directly on this class (not inherited), in schema order.
    pub properties: Vec<MappedProperty>,
}

/// Parsed `.usmap` mappings file: a registry of class schemas plus the
/// enum-value tables needed to resolve unversioned `EnumProperty` reads.
///
/// **Thread safety:** `Usmap: Send + Sync`. Immutable after parse;
/// intended to be shared via `Arc<Usmap>` (see the `mappings` field
/// on [`crate::asset::AssetContext`]). Pinned by the
/// `send_sync_assertions` test in `lib.rs`.
///
/// `#[non_exhaustive]` so Phase 3+ field additions (e.g., the
/// per-class flattened-property cache tracked in #370, or
/// schema-by-version metadata as new `.usmap` versions ship) land
/// as source-compatible additions. Construct via
/// [`Self::from_bytes`] or [`Self::from_path`]; external
/// struct-literal construction is blocked at the public-API
/// boundary. Per issue #414 — bundled with [`MappedProperty`] in
/// this PR.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Usmap {
    /// Class name -> [`ClassSchema`]. Schemas are stored flat (parent
    /// schemas are not inlined into child schemas); use
    /// [`Self::get_all_properties`] to walk the inheritance chain.
    ///
    /// **Mutation invariant:** the per-class flattened-property cache
    /// (see [`Self::get_all_properties`]) is computed against the
    /// schemas as-loaded by [`Self::from_bytes`]. Mutating this field
    /// post-parse leaves the cache stale — `get_all_properties` will
    /// keep returning the pre-mutation answer. Don't mutate after
    /// load; treat `Usmap` as immutable.
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
    ///
    /// Both the outer key (enum class name) and the inner values
    /// (per-variant resolved names) are `Arc<str>` so `Usmap::clone()`
    /// refcount-shares the strings rather than deep-cloning the name
    /// buffers (issue #418). Lookup via `&str` still works through
    /// `Arc<str>: Borrow<str>` — `.get("EColor")` is unchanged at
    /// every call site.
    pub enums: HashMap<Arc<str>, HashMap<u64, Arc<str>>>,
    /// Per-class flattened property list (#370), pre-sorted by
    /// `absolute_index`. Computed once in [`Self::from_bytes`] so the
    /// inheritance walk and three Vec/HashSet allocations
    /// `get_all_properties` used to do per call are eliminated on the
    /// hot per-export path. `MappedProperty` clones are cheap (the
    /// name + type fields are `Arc<str>`), and the cache is bounded by
    /// the per-class caps already enforced upstream.
    flattened: HashMap<String, Vec<ResolvedProperty>>,
}

impl Usmap {
    /// Hard cap on `.usmap` file size that [`Usmap::from_path`] reads
    /// into memory. The parser itself caps `compressed_size` at 64 MiB
    /// and `decompressed_size` at 256 MiB, but both checks fire AFTER
    /// the bytes have been read. This filesystem-side cap defends
    /// against `--mappings /dev/urandom`-style attacks (or a multi-GiB
    /// regular file, or a symlink to either) where the parser's caps
    /// can't fire until the bytes are already in memory. 128 MiB is
    /// roughly 2× the compressed cap, leaving headroom for legitimate
    /// uncompressed `.usmap` files while rejecting clearly-pathological
    /// inputs.
    pub const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;

    /// Load a `.usmap` mappings file from disk.
    ///
    /// Defensive bounds:
    /// 1. Rejects non-regular-file paths (FIFOs / sockets / devices /
    ///    directories) via `fs::metadata().is_file()`.
    /// 2. Caps the read at [`Self::MAX_FILE_SIZE`] so an oversized
    ///    regular file fails fast instead of OOM-ing the process.
    ///
    /// Symlinks are followed (`fs::metadata` traverses, vs the
    /// non-traversing `symlink_metadata` used by [`PakReader::open`]).
    /// A symlink → regular file passes; a symlink → `/dev/urandom`
    /// fails the `is_file()` check. The looser-than-PakReader posture
    /// is fine for `.usmap` because game-mapping symlink trees are a
    /// common deployment pattern; the security boundary is held by
    /// the `is_file` + size-cap pair, not by symlink rejection.
    ///
    /// Both kinds of defensive failure surface as [`PaksmithError::Io`]
    /// with an `InvalidInput` `io::Error` that includes the offending
    /// path — callers wanting CLI-arg context can wrap the result in
    /// [`PaksmithError::InvalidArgument`].
    ///
    /// # Errors
    ///
    /// - [`PaksmithError::Io`] for filesystem failures or
    ///   non-regular-file / oversize rejections.
    /// - [`PaksmithError::MappingsParse`] for wire-format faults — see
    ///   [`Self::from_bytes`].
    ///
    /// [`PakReader::open`]: crate::container::pak::PakReader::open
    pub fn from_path(path: impl AsRef<std::path::Path>) -> crate::Result<Self> {
        Self::from_path_with_cap(path.as_ref(), Self::MAX_FILE_SIZE)
    }

    /// Inner implementation of [`Self::from_path`] with the file-size
    /// cap as a parameter so unit tests can exercise the boundary
    /// without writing 128 MiB to a tempfile.
    fn from_path_with_cap(path: &std::path::Path, cap: u64) -> crate::Result<Self> {
        use std::io::Read;
        let metadata = std::fs::metadata(path).map_err(|e| {
            PaksmithError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to stat `{}`: {e}", path.display()),
            ))
        })?;
        if !metadata.is_file() {
            return Err(PaksmithError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("`{}` is not a regular file", path.display()),
            )));
        }
        let mut buf = Vec::new();
        // `_ = …` discards the byte count from `read_to_end`; the cap
        // check below uses `buf.len()`, not the returned value, so a
        // named binding would falsely imply downstream use.
        let _ = std::fs::File::open(path)
            .map_err(|e| {
                PaksmithError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to open `{}`: {e}", path.display()),
                ))
            })?
            .take(cap + 1)
            .read_to_end(&mut buf)
            .map_err(|e| {
                PaksmithError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to read `{}`: {e}", path.display()),
                ))
            })?;
        if buf.len() as u64 > cap {
            return Err(PaksmithError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "`{}` exceeds the {} byte Usmap::MAX_FILE_SIZE limit",
                    path.display(),
                    cap
                ),
            )));
        }
        Self::from_bytes(&buf)
    }

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

        // PackageVersioning block (version >= 1). Short reads here are
        // wire-truncation errors, not generic I/O; surface as
        // `MappingsParseFault::Truncated` with the cursor position
        // matching the failing read, so triage lands on the right
        // variant instead of bare `PaksmithError::Io`.
        let trunc = |c: &Cursor<&[u8]>| {
            fault(MappingsParseFault::Truncated {
                offset: position_usize(c),
            })
        };
        if version >= USMAP_VERSION_PACKAGE_VERSIONING {
            let has_versioning = cur.read_u8().map_err(|_| trunc(&cur))? != 0;
            if has_versioning {
                // object_version + object_version_ue5 + custom_version array + net_cl
                let _obj_ver = cur.read_i32::<LE>().map_err(|_| trunc(&cur))?;
                let _obj_ver_ue5 = cur.read_i32::<LE>().map_err(|_| trunc(&cur))?;
                let cv_count = cur.read_u32::<LE>().map_err(|_| trunc(&cur))?;
                if cv_count > MAX_USMAP_CV_COUNT {
                    return Err(fault(MappingsParseFault::CvCountTooLarge {
                        count: cv_count,
                        limit: MAX_USMAP_CV_COUNT,
                    }));
                }
                // Each CustomVersion = 16-byte GUID + i32 version number = 20 bytes.
                // cv_count is u32; i64 widens losslessly via i64::from.
                let skip = i64::from(cv_count) * 20;
                let _ = cur.seek(SeekFrom::Current(skip)).map_err(|_| trunc(&cur))?;
                let _net_cl = cur.read_u32::<LE>().map_err(|_| trunc(&cur))?;
            }
        }

        let compression_byte = cur.read_u8().map_err(|_| trunc(&cur))?;
        let compressed_size = cur.read_u32::<LE>().map_err(|_| trunc(&cur))?;
        let decompressed_size = cur.read_u32::<LE>().map_err(|_| trunc(&cur))?;

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
                let pos = position_usize(&cur);
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
                let pos_at_decoder = position_usize(&cur);
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
                let pos = position_usize(&cur);
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
        // `name_count` is a wire-controlled u32 — without an explicit
        // cap a malicious header could claim `u32::MAX` names; the
        // subsequent `try_reserve` would surface as a
        // `MappingsAllocationContext::NameTable` OOM, burying the
        // wire-cap rejection inside an alloc-context fault. The
        // `MAX_USMAP_DECOMPRESSED_SIZE` (256 MiB) cap only bounds the
        // total decompressed byte stream, not the pre-allocation
        // derived from a claimed count field. Reject explicitly first;
        // the `try_reserve` below still defends against the
        // sub-cap-but-OOM case on memory-pressured platforms.
        let name_count = cur.read_u32::<LE>()?;
        if name_count > MAX_USMAP_NAME_COUNT {
            return Err(fault(MappingsParseFault::NameCountTooLarge {
                count: name_count,
                limit: MAX_USMAP_NAME_COUNT,
            }));
        }
        let mut names: Vec<String> = Vec::new();
        names.try_reserve(name_count as usize).map_err(|source| {
            mappings_alloc_failed(
                MappingsAllocationContext::NameTable,
                name_count as usize,
                source,
            )
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
        let mut enums: HashMap<Arc<str>, HashMap<u64, Arc<str>>> = HashMap::new();
        enums.try_reserve(enum_count as usize).map_err(|source| {
            mappings_alloc_failed(
                MappingsAllocationContext::EnumTable,
                enum_count as usize,
                source,
            )
        })?;
        for _ in 0..enum_count {
            // `Arc<str>` so a future `usmap.clone()` refcount-shares
            // the enum-name buffer rather than deep-cloning (#418).
            let enum_name = read_name_arc(&mut cur, &names)?;
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
            let mut values: HashMap<u64, Arc<str>> = HashMap::new();
            values.try_reserve(value_count).map_err(|source| {
                mappings_alloc_failed(MappingsAllocationContext::EnumValues, value_count, source)
            })?;
            if version >= USMAP_VERSION_EXPLICIT_ENUM_VALUES {
                // CUE4Parse: `value = Ar.Read<ulong>(); name = Ar.ReadName(...)`.
                for _ in 0..value_count {
                    let value = cur.read_u64::<LE>()?;
                    let value_name = read_name_arc(&mut cur, &names)?;
                    let _ = values.insert(value, value_name);
                }
            } else {
                // Pre-v4 positional: ordinal = iteration index.
                for i in 0..value_count {
                    let value_name = read_name_arc(&mut cur, &names)?;
                    let _ = values.insert(i as u64, value_name);
                }
            }
            let _ = enums.insert(enum_name, values);
        }

        // Schema table.
        let schema_count = cur.read_u32::<LE>()?;
        if schema_count > MAX_USMAP_SCHEMA_COUNT {
            return Err(fault(MappingsParseFault::SchemaCountTooLarge {
                count: schema_count,
                limit: MAX_USMAP_SCHEMA_COUNT,
            }));
        }
        let mut schemas: HashMap<String, ClassSchema> = HashMap::new();
        schemas
            .try_reserve(schema_count as usize)
            .map_err(|source| {
                mappings_alloc_failed(
                    MappingsAllocationContext::SchemaTable,
                    schema_count as usize,
                    source,
                )
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

            // `prop_count` is the wire-declared total property count
            // for this class (serializable + transient/editor-only/
            // deprecated). Required by `get_all_properties` to compute
            // the child-first-concat absolute slot indices for inherited
            // classes (issue #391).
            let prop_count = cur.read_u16::<LE>()?;
            let serial_count = cur.read_u16::<LE>()?;

            // Pre-row validation (issue #413): the wire-declared
            // `prop_count` must be at least the row-count `serial_count`
            // — a class can't have fewer total slots than serializable
            // rows. An adversarial `.usmap` declaring `prop_count = 0`
            // with `serial_count > 0` would re-introduce the #391
            // child/parent inheritance-offset collision by advancing
            // the offset by 0 past this class. Fast-fail before any
            // per-row allocation runs.
            if prop_count < serial_count {
                return Err(fault(MappingsParseFault::PropCountBelowSerialCount {
                    schema: name.clone(),
                    prop_count,
                    serial_count,
                }));
            }

            // `Vec::with_capacity(serial_count)` would mis-predict the
            // final size (the inner array-expansion loop can push up
            // to `serial_count × 255` entries) AND allocate
            // infallibly. Use `try_reserve` per-batch with the
            // typed `AllocationFailed` routing (issue #397 sub-fix C).
            let mut properties: Vec<MappedProperty> = Vec::new();
            for _ in 0..serial_count {
                let schema_index = cur.read_u16::<LE>()?;
                let array_size = cur.read_u8()?;
                // `prop_name`: read as `Arc<str>` ONCE per row so the
                // inner `array_size` expansion loop clones a refcount
                // per slot instead of a heap-allocated name buffer
                // (issue #397 sub-fix A; see `read_name_arc`).
                let prop_name = read_name_arc(&mut cur, &names)?;
                let prop_type = read_mapped_type(&mut cur, &names, 0)?;

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
                properties
                    .try_reserve(usize::from(array_size))
                    .map_err(|source| {
                        mappings_alloc_failed(
                            MappingsAllocationContext::SchemaProperties,
                            usize::from(array_size),
                            source,
                        )
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

            // Post-row validation (issue #413): every per-class
            // `schema_index` must fit inside `[0, prop_count)`, i.e.,
            // `prop_count > max(schema_index over declared rows)`.
            // Violating that would let an adversarial `.usmap`
            // declare a row at a slot beyond the per-class budget,
            // breaking the inheritance offset arithmetic in
            // `get_all_properties` even when `prop_count >=
            // serial_count` (the pre-row check) holds. Skip the
            // check on empty schemas; `max()` returns `None`.
            if let Some(max_schema_index) = properties.iter().map(|p| p.schema_index).max()
                && prop_count <= max_schema_index
            {
                return Err(fault(MappingsParseFault::PropCountBelowMaxSchemaIndex {
                    schema: name.clone(),
                    prop_count,
                    max_schema_index,
                }));
            }

            let _ = schemas.insert(
                name.clone(),
                ClassSchema {
                    name,
                    super_type,
                    prop_count,
                    properties,
                },
            );
        }

        // Pre-compute the flattened-property cache (#370). One walk
        // per class at parse time, then `get_all_properties` is a
        // HashMap lookup returning a borrowed slice. Eager (rather
        // than lazy/RwLock) trades a touch of upfront work for zero
        // synchronization on the per-export hot path.
        //
        // Fallible: returns `MappingsParseFault::FlattenedCacheTooLarge`
        // if the total entries summed across every class's flat list
        // would exceed `MAX_USMAP_FLATTENED_TOTAL_ENTRIES`, and routes
        // try_reserve failures through `MappingsAllocationContext::
        // FlattenedCache`. Without these guards the wire's per-class
        // cap × `MAX_INHERITANCE_DEPTH` × `MAX_USMAP_SCHEMA_COUNT`
        // permits a ~17 G-entry cache (~1 TB heap) before any wire
        // input exceeds the 256 MiB `MAX_USMAP_DECOMPRESSED_SIZE`.
        // Surfaced by security-review on PR #444.
        //
        // Cycle / depth-cap warnings emit here at parse time (once
        // per class) rather than on every `get_all_properties` call;
        // the wire fault is the same.
        let flattened = Self::build_flattened_cache(&schemas)?;

        Ok(Usmap {
            schemas,
            enums,
            flattened,
        })
    }

    /// Build the per-class flattened-property cache for `schemas`.
    /// Shared between the byte-level [`Self::from_bytes`] parse path
    /// and the in-source-test [`Self::from_parts`] constructor.
    ///
    /// Returns `MappingsParseFault::FlattenedCacheTooLarge` if the
    /// accumulated entry count exceeds the cap, and routes
    /// `try_reserve` failures via `MappingsAllocationContext::
    /// FlattenedCache`. The cap check fires BEFORE
    /// `compute_flattened` allocates the per-class flat list — a
    /// cheap chain walk gives the per-class size up front, so the
    /// peak transient heap stays at the documented bound rather than
    /// 2× it (R3 security review on PR #444).
    fn build_flattened_cache(
        schemas: &HashMap<String, ClassSchema>,
    ) -> crate::Result<HashMap<String, Vec<ResolvedProperty>>> {
        let mut flattened: HashMap<String, Vec<ResolvedProperty>> = HashMap::new();
        flattened.try_reserve(schemas.len()).map_err(|source| {
            mappings_alloc_failed(
                MappingsAllocationContext::FlattenedCache,
                schemas.len(),
                source,
            )
        })?;
        let mut total: u64 = 0;
        for class_name in schemas.keys() {
            // Cheap pre-allocation cap check: chain-walk + sum bounded
            // by MAX_INHERITANCE_DEPTH = 64. Refuse to call
            // compute_flattened (which would allocate the full flat
            // vec) when the running total would exceed the cap.
            let remaining = MAX_USMAP_FLATTENED_TOTAL_ENTRIES.saturating_sub(total);
            let flat = Self::compute_flattened(schemas, class_name, remaining)?;
            total = total.saturating_add(flat.len() as u64);
            let _ = flattened.insert(class_name.clone(), flat);
        }
        Ok(flattened)
    }

    /// Walks the super-type chain for `class_name` and returns the
    /// flattened, sorted property list. Shared between `from_bytes`'s
    /// cache population and any direct invocation; the caching path
    /// is what makes [`Self::get_all_properties`] a HashMap lookup
    /// rather than a chain walk.
    ///
    /// Per CUE4Parse `MappingsSchema.cs::Struct.TryGetValue` the wire
    /// absolute slot indices are **child-first concatenated**:
    /// child's per-class slots occupy `[0, Child.PropertyCount)`,
    /// parent's per-class slot `i` occupies absolute
    /// `Child.PropertyCount + i`, grand-parent's slot `i` occupies
    /// `Child.PropertyCount + Parent.PropertyCount + i`, and so on.
    ///
    /// **Cycle handling:** A malicious `.usmap` can craft a cyclic
    /// `super_type` chain (`A: B`, `B: A`). A naive walk would loop
    /// forever — DoS. We track visited classes and break on cycle,
    /// and additionally cap the chain at `MAX_INHERITANCE_DEPTH`.
    fn compute_flattened(
        schemas: &HashMap<String, ClassSchema>,
        class_name: &str,
        budget: u64,
    ) -> crate::Result<Vec<ResolvedProperty>> {
        // Walk child-first so the absolute-index offset accumulates
        // forward through the chain. `chain[0]` is `class_name`,
        // `chain[1]` is its parent, etc.
        let mut chain: Vec<&ClassSchema> = Vec::new();
        let mut visited: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut current = class_name;
        let mut truncated_by_depth = true;
        for _ in 0..MAX_INHERITANCE_DEPTH {
            if !visited.insert(current) {
                // Cycle: warn (the .usmap is operator-supplied — don't
                // abort the asset extraction over a malformed file) and
                // stop walking; caller still gets the properties
                // collected up to this point.
                tracing::warn!(
                    root_class = class_name,
                    repeated_class = current,
                    "circular super_type chain in .usmap; truncating inheritance walk"
                );
                truncated_by_depth = false;
                break;
            }
            let Some(schema) = schemas.get(current) else {
                truncated_by_depth = false;
                break;
            };
            chain.push(schema);
            match schema.super_type.as_deref() {
                Some(parent) if !parent.is_empty() => current = parent,
                _ => {
                    truncated_by_depth = false;
                    break;
                }
            }
        }
        if truncated_by_depth {
            // Loop hit `MAX_INHERITANCE_DEPTH` with the chain still
            // continuing — `.usmap` is malformed (or absurdly deep).
            // Warn but don't error; same operator-supplied-input
            // posture as the cycle arm.
            tracing::warn!(
                root_class = class_name,
                limit = MAX_INHERITANCE_DEPTH,
                "inheritance chain exceeds MAX_INHERITANCE_DEPTH; truncating walk"
            );
        }

        // Per-class size from the chain walk above (bounded by
        // MAX_INHERITANCE_DEPTH × per-class cap). Cheap to compute
        // — at most 64 reads — and used for both the running-total
        // budget check below and the `try_reserve` pre-allocation.
        let total: usize = chain.iter().map(|s| s.properties.len()).sum();
        // Cap check BEFORE allocating. `budget` is the remaining
        // FlattenedCacheTooLarge headroom passed by
        // `build_flattened_cache`; refusing to allocate this class
        // when the chain would push past it keeps the peak transient
        // heap at one in-flight flat list, not the previous-class +
        // this-class doubling that checking after allocation would
        // permit (R3 security review).
        if total as u64 > budget {
            return Err(crate::PaksmithError::MappingsParse {
                fault: MappingsParseFault::FlattenedCacheTooLarge {
                    total: MAX_USMAP_FLATTENED_TOTAL_ENTRIES
                        .saturating_sub(budget)
                        .saturating_add(total as u64),
                    limit: MAX_USMAP_FLATTENED_TOTAL_ENTRIES,
                },
            });
        }
        // Pre-reserve the result vec via `try_reserve` so an allocator
        // refusal under adversarial inputs surfaces as a typed
        // `MappingsAllocationContext::FlattenedCache` fault rather
        // than an `abort` from `Vec::push`'s infallible reserve.
        let mut result: Vec<ResolvedProperty> = Vec::new();
        result.try_reserve(total).map_err(|source| {
            mappings_alloc_failed(MappingsAllocationContext::FlattenedCache, total, source)
        })?;
        let mut offset: u32 = 0;
        for schema in &chain {
            for property in &schema.properties {
                // u32 arithmetic: the offset can exceed u16::MAX
                // across a deep chain (MAX_INHERITANCE_DEPTH = 64
                // classes × u16::MAX prop_count each), but the
                // absolute slot index `is_serialized` consumes is
                // u16. Saturating cast to u16 surfaces an obviously-
                // truncated index rather than wrapping silently —
                // such a class would already be unreachable through
                // the `FUnversionedHeader` (whose `value_num` is
                // u16-bounded) and decoding would fail downstream.
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "min(u16::MAX) clamps the u32 into u16 range; the cast is lossless after the clamp"
                )]
                let absolute_index = offset
                    .saturating_add(u32::from(property.schema_index))
                    .min(u32::from(u16::MAX)) as u16;
                result.push(ResolvedProperty {
                    absolute_index,
                    property: property.clone(),
                });
            }
            offset = offset.saturating_add(u32::from(schema.prop_count));
        }
        // Pre-sort by absolute_index so the unversioned decoder's
        // forward-only header cursor sees monotonic input without
        // running a defensive sort per export. Stable sort preserves
        // relative order on ties (`a.absolute_index == b.absolute_index`
        // is unreachable on legitimate `.usmap` inputs but possible
        // on adversarial ones via the saturating u16 clamp).
        result.sort_by_key(|rp| rp.absolute_index);
        Ok(result)
    }

    /// Returns every property for `class_name` paired with its wire
    /// **absolute slot index**, pre-sorted by that index. Backed by
    /// the eagerly-built cache in [`Self::from_bytes`] — a HashMap
    /// lookup, no chain walk per call. Empty slice if the class is
    /// not in the schema table.
    #[must_use]
    pub fn get_all_properties(&self, class_name: &str) -> &[ResolvedProperty] {
        self.flattened.get(class_name).map_or(&[], Vec::as_slice)
    }

    /// Build a `Usmap` from already-parsed in-memory schemas and
    /// enums, computing the flattened-property cache from the
    /// supplied schemas. Used by in-source tests that hand-construct
    /// `ClassSchema` values without going through the byte-level
    /// `from_bytes` parser.
    ///
    /// The byte-level entry points ([`Self::from_bytes`] /
    /// [`Self::from_path`]) populate the cache during parse. This
    /// in-memory entry point is the only other path that produces a
    /// `Usmap` with a populated cache — direct struct-literal
    /// construction is structurally prevented by the private
    /// `flattened` field.
    #[cfg(test)]
    pub(crate) fn from_parts(
        schemas: HashMap<String, ClassSchema>,
        enums: HashMap<Arc<str>, HashMap<u64, Arc<str>>>,
    ) -> crate::Result<Self> {
        let flattened = Self::build_flattened_cache(&schemas)?;
        Ok(Usmap {
            schemas,
            enums,
            flattened,
        })
    }
}

/// One property from [`Usmap::get_all_properties`], carrying an
/// owned [`MappedProperty`] paired with the **wire absolute slot
/// index** computed via the child-first-concat inheritance walk.
///
/// The unversioned property reader consumes `absolute_index` as the
/// monotonic key passed to `FUnversionedHeader::is_serialized`;
/// `property` carries everything else (name, type, array_index).
///
/// The owned-property form (vs a borrowed `&'a MappedProperty`) lets
/// `Usmap` store a pre-sorted flattened cache for every class
/// without self-referential-lifetime gymnastics — `MappedProperty`'s
/// `name` is `Arc<str>` and most `prop_type` variants are trivially-
/// sized, so most clones reduce to refcount bumps. The exception is
/// `MappedPropertyType::Array { inner: Box<...> }`, which deep-clones
/// the `Box` per cache slot; bounded by parse-time caps and only
/// paid once at parse, so the cost is structural and small.
///
/// `#[non_exhaustive]` matches the file-wide precedent
/// ([`Usmap`], [`MappedProperty`], [`ClassSchema`],
/// [`MappedPropertyType`]) so future derived-metadata additions
/// (e.g. owning class name for diagnostics) stay source-compatible.
/// As an output-only type the consumer impact is destructuring in
/// `for` loops, not construction. Per issue #414.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolvedProperty {
    /// Wire absolute slot index across the inheritance chain (child's
    /// slots first, then parent's offset by `Child.PropertyCount`,
    /// etc.). Matches `FUnversionedHeader`'s addressing convention.
    pub absolute_index: u16,
    /// Owned per-class property entry (cloned from
    /// [`ClassSchema::properties`] during the eager flattening pass).
    pub property: MappedProperty,
}

/// Resolve a name index against the parsed name table. Shared by the
/// schema-table walk, the enum-table walk, and `read_mapped_type`'s
/// inner-name reads.
///
/// An out-of-range index surfaces as
/// [`MappingsParseFault::NameIndexOutOfRange`] (issue #417 —
/// previously misnomered as `Truncated`, which implied a short read
/// even though the wire bytes were fully readable).
fn read_name(cur: &mut Cursor<&[u8]>, names: &[String]) -> crate::Result<String> {
    let idx = cur.read_i32::<LE>()?;
    #[allow(
        clippy::cast_sign_loss,
        reason = "negative indices wrap to a huge usize that fails the get() bounds check, surfacing as NameIndexOutOfRange"
    )]
    let idx_usz = idx as usize;
    names.get(idx_usz).cloned().ok_or_else(|| {
        fault(MappingsParseFault::NameIndexOutOfRange {
            idx,
            table_len: names.len(),
        })
    })
}

/// `read_name` + `Arc::from` in one step.
///
/// Materializes the looked-up name as `Arc<str>` so downstream
/// clones (e.g., the `array_size` expansion loop in
/// `Usmap::from_bytes` cloning a property name into every expanded
/// slot, or the `MappedPropertyType::Struct` / `Enum` variant
/// construction in `read_mapped_type`) bump a refcount instead of
/// allocating a fresh heap buffer. Bounds the per-schema heap
/// amplification surface flagged in issue #397 sub-fix A —
/// pre-migration a maximal-LongFName name multiplied by the
/// 65,536-entry `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA` cap
/// permitted ~4 GiB of name clones per schema.
fn read_name_arc(cur: &mut Cursor<&[u8]>, names: &[String]) -> crate::Result<Arc<str>> {
    Ok(Arc::from(read_name(cur, names)?))
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
    depth: usize,
) -> crate::Result<MappedPropertyType> {
    if depth > MAX_USMAP_ARRAY_NESTING_DEPTH {
        return Err(fault(MappingsParseFault::ArrayNestingTooDeep {
            depth,
            limit: MAX_USMAP_ARRAY_NESTING_DEPTH,
        }));
    }
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
            // ArrayProperty — recurse with incremented depth so a
            // wire like `08 08 08 ... <leaf>` is rejected before
            // the stack-overflow danger zone (security cap added
            // for #443; see MAX_USMAP_ARRAY_NESTING_DEPTH docstring).
            let inner = read_mapped_type(cur, names, depth + 1)?;
            MappedPropertyType::Array {
                inner: Box::new(inner),
            }
        }
        9 => {
            // StructProperty
            let struct_name = read_name_arc(cur, names)?;
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
            let enum_name = read_name_arc(cur, names)?;
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
        assert_eq!(schema.properties[0].name.as_ref(), "Health");
        assert!(matches!(
            schema.properties[0].prop_type,
            MappedPropertyType::Int32
        ));
        assert_eq!(schema.properties[1].name.as_ref(), "Speed");
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
    fn enums_table_keys_and_values_are_arc_str() {
        // Pin issue #418's type migration: `Usmap.enums` now stores
        // `Arc<str>` keys and `Arc<str>` values rather than `String`,
        // so `usmap.clone()` is refcount-cheap on every enum-name
        // and per-variant-name string. Without the migration this
        // would deep-clone every name buffer in the table.
        //
        // Test builds a v4 .usmap with one enum `Color` carrying one
        // explicit-ordinal value `Red`. After clone, the original
        // and the clone share the same Arc allocation for the enum
        // key and the variant value (`Arc::ptr_eq` proves the share;
        // `strong_count >= 2` documents the refcount).
        //
        // Names: "Color"(0), "Red"(1)
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // name_count
        // v4 uses LongFName (u16 lengths) — see USMAP_VERSION_LONG_FNAME
        for (len, name) in [(5u16, "Color"), (3u16, "Red")] {
            data.extend_from_slice(&len.to_le_bytes());
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 enum
        data.extend_from_slice(&0i32.to_le_bytes()); // enum_name idx → "Color"
        data.extend_from_slice(&1u16.to_le_bytes()); // value_count (LargeEnums u16)
        // v4 ExplicitEnumValues: u64 ordinal + i32 name idx
        data.extend_from_slice(&0u64.to_le_bytes()); // ordinal
        data.extend_from_slice(&1i32.to_le_bytes()); // "Red"
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 schemas

        let data_len = u32::try_from(data.len()).unwrap();
        // Magic + version=4 + has_versioning=0 + compression None
        let mut usmap_bytes = vec![0xC4u8, 0x30, 4, 0, 0];
        usmap_bytes.extend_from_slice(&data_len.to_le_bytes());
        usmap_bytes.extend_from_slice(&data_len.to_le_bytes());
        usmap_bytes.extend_from_slice(&data);

        let usmap = Usmap::from_bytes(&usmap_bytes).unwrap();
        let (color_key, color_values) = usmap.enums.iter().next().expect("one enum parsed");
        assert_eq!(color_key.as_ref(), "Color");
        let red_value = color_values.get(&0u64).expect("ordinal 0 = Red");
        assert_eq!(red_value.as_ref(), "Red");

        // Clone the Usmap — Arc keys/values must refcount-share, not
        // deep-clone. `Arc::ptr_eq` proves the allocation is the
        // same; `strong_count` increments past 1.
        let cloned = usmap.clone();
        let (cloned_color_key, cloned_color_values) =
            cloned.enums.iter().next().expect("clone has one enum");
        let cloned_red_value = cloned_color_values.get(&0u64).expect("clone has ordinal 0");
        assert!(
            Arc::ptr_eq(color_key, cloned_color_key),
            "enum-name Arc must be shared across Usmap clones, not deep-cloned"
        );
        assert!(
            Arc::ptr_eq(red_value, cloned_red_value),
            "enum-value Arc must be shared across Usmap clones, not deep-cloned"
        );
        assert!(
            Arc::strong_count(color_key) >= 2,
            "expected at least 2 refcounts on the shared key"
        );
    }

    #[test]
    fn array_size_expansion_shares_arc_str_for_name() {
        // Pin the heap-bounding property of sub-fix A (issue #397):
        // when a schema row declares `array_size > 1`, the inner
        // expansion loop must clone the property name as an
        // `Arc<str>` refcount, NOT as a heap-allocated `String`.
        // Without this, the 65,536 `MAX_USMAP_EXPANDED_PROPERTIES_PER_SCHEMA`
        // cap permitted ~4 GiB heap from name clones alone on
        // maximal LongFName inputs.
        //
        // Test wires a single schema row with `array_size = 4` and
        // asserts every expanded slot's `name` points at the same
        // Arc allocation via `Arc::ptr_eq`, then checks
        // `strong_count == 4` (one refcount per expanded slot;
        // the parse-loop's initial binding has been dropped).
        //
        // Names: "Hero"(0), "None"(1), "Stats"(2)
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes()); // name_count
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (5u8, "Stats")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 enums
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 schema
        // Schema Hero: super_type=None(1), prop_count=4, serial_count=1
        data.extend_from_slice(&0i32.to_le_bytes()); // name idx
        data.extend_from_slice(&1i32.to_le_bytes()); // super idx
        data.extend_from_slice(&4u16.to_le_bytes()); // prop_count
        data.extend_from_slice(&1u16.to_le_bytes()); // serial_count
        // One row: schema_index=0, array_size=4, name="Stats", type=Int32(2)
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(4u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "Stats"
        data.push(2u8); // IntProperty

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let usmap = Usmap::from_bytes(&usmap).unwrap();
        let hero = usmap.schemas.get("Hero").unwrap();
        assert_eq!(hero.properties.len(), 4, "array_size=4 expands to 4 slots");

        let first = &hero.properties[0].name;
        for (i, prop) in hero.properties.iter().enumerate().skip(1) {
            assert!(
                Arc::ptr_eq(first, &prop.name),
                "slot {i} must share the Arc allocation with slot 0; \
                 a String-cloning regression would fail this"
            );
        }
        // 8 = 4 (one per expanded slot in `schemas[..].properties`) +
        // 4 (one per slot in the eagerly-built `flattened` cache;
        // #370). The Arc is the same allocation across all sites —
        // `Arc::ptr_eq` above proves the sharing; this count just
        // sums the live refs. A regression to per-slot String cloning
        // (or per-cache MappedProperty deep-clone of `name`) would
        // drop the count to a smaller number AND make `ptr_eq` false.
        assert_eq!(
            Arc::strong_count(first),
            8,
            "expected 8 refcounts (4 schema slots + 4 flattened-cache slots)"
        );
    }

    /// Pin the `MAX_USMAP_FLATTENED_TOTAL_ENTRIES` accessor's return
    /// value. Without this test, the `__test_utils` accessor's
    /// return is unobserved — a regression that changed the cap
    /// constant (or the accessor's body) would survive `cargo test`
    /// silently. cargo-mutants surfaces such mutations as missed
    /// (`-> u64 with 1` / `-> u64 with 0` both survived without
    /// this pin).
    #[test]
    fn max_usmap_flattened_total_entries_accessor_returns_expected_value() {
        assert_eq!(max_usmap_flattened_total_entries(), 4_194_304);
    }

    /// Boundary test for the per-class cap check in
    /// `compute_flattened`. The current code uses `total > budget` —
    /// equality must NOT trigger the cap. Without this pin a mutation
    /// of `>` to `>=` survives `cargo test`.
    ///
    /// Setup: one class with N properties, budget = N. The chain
    /// walk returns `total = N`. `N > N` is false → no error,
    /// returns Ok with N entries.
    #[test]
    fn compute_flattened_passes_when_total_equals_budget_exactly() {
        let class_name = "Hero";
        let property = MappedProperty {
            name: Arc::from("Health"),
            schema_index: 0,
            array_index: 0,
            prop_type: MappedPropertyType::Int32,
        };
        let schema = ClassSchema {
            name: class_name.to_string(),
            super_type: None,
            prop_count: 1,
            properties: vec![property],
        };
        let mut schemas: HashMap<String, ClassSchema> = HashMap::new();
        let _ = schemas.insert(class_name.to_string(), schema);
        // budget = 1, class has 1 property → exactly at boundary.
        let result = Usmap::compute_flattened(&schemas, class_name, 1)
            .expect("budget=1 with total=1 must succeed (cap is total > budget, not >=)");
        assert_eq!(result.len(), 1);
    }

    /// Boundary test for the cap check firing. Without this pin a
    /// mutation of `>` to `==` survives `cargo test` (because
    /// `total == budget+1` doesn't equal `budget` → `==` would
    /// NOT fire even though the original `>` does).
    #[test]
    fn compute_flattened_errors_when_total_exceeds_budget() {
        let class_name = "Hero";
        let make_prop = |name: &str| MappedProperty {
            name: Arc::from(name),
            schema_index: 0,
            array_index: 0,
            prop_type: MappedPropertyType::Int32,
        };
        let schema = ClassSchema {
            name: class_name.to_string(),
            super_type: None,
            prop_count: 2,
            properties: vec![make_prop("Health"), make_prop("Speed")],
        };
        let mut schemas: HashMap<String, ClassSchema> = HashMap::new();
        let _ = schemas.insert(class_name.to_string(), schema);
        // budget = 1, class has 2 properties → `2 > 1` fires the cap.
        let err = Usmap::compute_flattened(&schemas, class_name, 1)
            .expect_err("total=2 over budget=1 must fire FlattenedCacheTooLarge");
        match err {
            crate::PaksmithError::MappingsParse {
                fault: MappingsParseFault::FlattenedCacheTooLarge { total, limit },
            } => {
                assert_eq!(limit, MAX_USMAP_FLATTENED_TOTAL_ENTRIES);
                // Projected total = limit - budget + this_class =
                // 4_194_304 - 1 + 2 = 4_194_305. Pins the
                // cumulative-projected diagnostic semantic (not the
                // raw `total = 2` actual).
                assert_eq!(total, MAX_USMAP_FLATTENED_TOTAL_ENTRIES + 1);
            }
            other => panic!("expected FlattenedCacheTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_prop_count_below_serial_count_rejected() {
        // Adversarial .usmap declares `prop_count = 0` while
        // emitting `serial_count = 1` row. Without validation this
        // would parse cleanly, then `get_all_properties` would
        // advance the inheritance offset by `prop_count = 0` past
        // this class — re-introducing the #391 child/parent
        // per-class-index collision on any inheriting class.
        //
        // Names: "Hero"(0), "None"(1), "Stats"(2)
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (5u8, "Stats")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 enums
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 schema
        // Schema Hero: super=None, prop_count=0 (LIES), serial_count=1
        data.extend_from_slice(&0i32.to_le_bytes()); // name idx
        data.extend_from_slice(&1i32.to_le_bytes()); // super idx
        data.extend_from_slice(&0u16.to_le_bytes()); // prop_count = 0 — bogus
        data.extend_from_slice(&1u16.to_le_bytes()); // serial_count = 1
        data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "Stats"
        data.push(2u8); // IntProperty

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault:
                    crate::error::MappingsParseFault::PropCountBelowSerialCount {
                        schema,
                        prop_count,
                        serial_count,
                    },
            } => {
                assert_eq!(schema, "Hero");
                assert_eq!(prop_count, 0);
                assert_eq!(serial_count, 1);
            }
            other => panic!("expected PropCountBelowSerialCount, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_prop_count_below_max_schema_index_rejected() {
        // Adversarial .usmap declares `prop_count = 2` but emits a
        // row with `schema_index = 5`. The per-class slot index must
        // be in `[0, prop_count)`; violating that breaks the
        // inheritance offset arithmetic in `get_all_properties`. The
        // post-row validation must fire (the pre-row
        // `prop_count >= serial_count` check passes: 2 >= 1).
        //
        // Names: "Hero"(0), "None"(1), "X"(2)
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (1u8, "X")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // 0 enums
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 schema
        // Schema Hero: super=None, prop_count=2, serial_count=1
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count = 2
        data.extend_from_slice(&1u16.to_le_bytes()); // serial_count = 1
        // Row with schema_index = 5 (out of [0, 2) range — lies)
        data.extend_from_slice(&5u16.to_le_bytes()); // schema_index = 5
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "X"
        data.push(2u8); // IntProperty

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault:
                    crate::error::MappingsParseFault::PropCountBelowMaxSchemaIndex {
                        schema,
                        prop_count,
                        max_schema_index,
                    },
            } => {
                assert_eq!(schema, "Hero");
                assert_eq!(prop_count, 2);
                assert_eq!(max_schema_index, 5);
            }
            other => panic!("expected PropCountBelowMaxSchemaIndex, got {other:?}"),
        }
    }

    /// Build a minimal v0 `.usmap` with a 2-name table (`"X"`, `"Y"`)
    /// and a single enum whose `enum_name_idx` is the given i32 wire
    /// value. The two name-index OOB tests share this shape — they
    /// differ only in the i32 they ship (99 positive-OOB vs -1
    /// negative-wraps-to-OOB).
    fn build_enum_oob_usmap(enum_name_idx: i32) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // name_count
        for (len, name) in [(1u8, "X"), (1u8, "Y")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 enum
        data.extend_from_slice(&enum_name_idx.to_le_bytes()); // adversarial idx

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0]; // magic + v0 + None compression
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);
        usmap
    }

    #[test]
    fn parse_usmap_name_index_out_of_range_rejected() {
        // Adversarial .usmap declares 1 enum whose `enum_name_idx`
        // references slot 99 in a name table of size 2. The lookup
        // should surface `NameIndexOutOfRange { idx: 99, table_len: 2 }`,
        // NOT `Truncated` (which historically misnomered the failure
        // as a short read — the wire stream is fully readable; only
        // the name reference is bogus).
        let usmap = build_enum_oob_usmap(99);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::NameIndexOutOfRange { idx, table_len },
            } => {
                assert_eq!(idx, 99);
                assert_eq!(table_len, 2);
            }
            other => panic!("expected NameIndexOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_name_index_negative_wire_value_rejected() {
        // Negative i32 wire value (-1, encoded as `0xFF FF FF FF` LE)
        // wraps to a huge `usize` on the cast and fails the
        // `names.get()` bounds check, surfacing through the same
        // `NameIndexOutOfRange` arm — but the variant payload
        // carries the raw signed `-1`, not the wrapped positive.
        // Pins the i32-carry design decision at the parser level
        // rather than only at Display.
        let usmap = build_enum_oob_usmap(-1);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::NameIndexOutOfRange { idx, table_len },
            } => {
                assert_eq!(idx, -1, "wire i32 must surface verbatim, not wrapped");
                assert_eq!(table_len, 2);
            }
            other => panic!("expected NameIndexOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_name_count_too_large_rejected() {
        // v0 .usmap with `name_count = MAX + 1`. The cap check fires
        // before the `try_reserve`, so the error surfaces as
        // `NameCountTooLarge` (wire-cap) instead of an
        // `AllocationFailed { context: NameTable }` (resource-cap).
        let cap = max_usmap_name_count();
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&(cap + 1).to_le_bytes()); // name_count = cap + 1
        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0]; // magic + v0 + None compression
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::NameCountTooLarge { count, limit },
            } => {
                assert_eq!(count, cap + 1);
                assert_eq!(limit, cap);
            }
            other => panic!("expected NameCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_cv_count_too_large_rejected() {
        // v1 .usmap with `has_versioning = 1`, valid obj_version /
        // obj_version_ue5, then `cv_count = MAX + 1`. The cap check
        // fires before the `cv_count * 20` seek skips arbitrary bytes.
        //
        // Wire layout (no compression header needed — cap check fires
        // mid-versioning-block, before `compression_byte` is read):
        //   magic(2) + version=1(1) + has_versioning=1(1) + obj_ver(4)
        //   + obj_ver_ue5(4) + cv_count=cap+1(4) → CAP REJECT
        let cap = max_usmap_cv_count();
        let mut usmap: Vec<u8> = vec![0xC4u8, 0x30, 1u8]; // magic + v1
        usmap.push(1u8); // has_versioning = true
        usmap.extend_from_slice(&0i32.to_le_bytes()); // obj_ver
        usmap.extend_from_slice(&0i32.to_le_bytes()); // obj_ver_ue5
        usmap.extend_from_slice(&(cap + 1).to_le_bytes()); // cv_count = cap + 1

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::CvCountTooLarge { count, limit },
            } => {
                assert_eq!(count, cap + 1);
                assert_eq!(limit, cap);
            }
            other => panic!("expected CvCountTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_usmap_schema_count_too_large_rejected() {
        // Build a minimal v0 .usmap with zero names, zero enums, and a
        // schema_count one past the cap. The cap check must fire
        // before the schema-table reservation grows the HashMap.
        let cap = max_usmap_schema_count();
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes()); // name_count = 0
        data.extend_from_slice(&0u32.to_le_bytes()); // enum_count = 0
        data.extend_from_slice(&(cap + 1).to_le_bytes()); // schema_count = cap + 1
        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0]; // magic + v0 + None compression
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::SchemaCountTooLarge { count, limit },
            } => {
                assert_eq!(count, cap + 1);
                assert_eq!(limit, cap);
            }
            other => panic!("expected SchemaCountTooLarge, got {other:?}"),
        }
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

    /// `read_mapped_type` recursion on the `ArrayProperty` type byte
    /// (`0x08`) must terminate at `MAX_USMAP_ARRAY_NESTING_DEPTH`,
    /// never recurse to stack overflow.
    ///
    /// Wire: one schema row whose `prop_type` field is
    /// `08 08 08 ... <leaf>` — every `0x08` byte triggers one
    /// `read_mapped_type` recursive call. With `limit + 2` bytes the
    /// recursion goes one step past the cap and fires the typed
    /// `ArrayNestingTooDeep` fault.
    #[test]
    fn parse_usmap_array_nesting_depth_exceeded_rejected() {
        let cap = max_usmap_array_nesting_depth();
        // `cap + 2` bytes: cap+1 `0x08` followed by a leaf type byte.
        // After unwinding the depth counter goes one past `cap` on
        // entry to the deepest frame, which triggers the check.
        let mut prop_type_bytes: Vec<u8> = vec![0x08u8; cap + 1];
        prop_type_bytes.push(2u8); // IntProperty leaf

        let mut data: Vec<u8> = Vec::new();
        // Name table: "Hero", "None", "P".
        data.extend_from_slice(&3u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (1u8, "P")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // empty enum table
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 schema
        data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero"
        data.extend_from_slice(&1i32.to_le_bytes()); // super = "None"
        data.extend_from_slice(&1u16.to_le_bytes()); // prop_count = 1
        data.extend_from_slice(&1u16.to_le_bytes()); // serial_count = 1
        // Row: schema_index=0, array_size=1, name=P, type=<deep stack>
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&prop_type_bytes);

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let err = Usmap::from_bytes(&usmap).unwrap_err();
        match err {
            crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::ArrayNestingTooDeep { depth, limit },
            } => {
                assert_eq!(limit, cap);
                assert!(depth > cap, "depth {depth} must exceed cap {cap}");
            }
            other => panic!("expected ArrayNestingTooDeep, got {other:?}"),
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
        // Build a usmap with `Parent(x: Int)` and `Child extends Parent(y: Float)`.
        //
        // Per CUE4Parse `MappingsSchema.cs::Struct.TryGetValue` each
        // class's `MappedProperty::schema_index` is **per-class**
        // (0-based within the class's own dictionary). The wire
        // absolute slot indices are child-first concatenated:
        //   - Child's `y` (per-class 0) → absolute 0
        //   - Parent's `x` (per-class 0) → absolute Child.PropertyCount = 1
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
        // Schema Parent: name=0, super=1("None"), prop_count=1, serial=1
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes()); // prop_count = own count only
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes()); // per-class schema_index=0
        data.push(1u8); // array_size
        data.extend_from_slice(&2i32.to_le_bytes()); // "x"
        data.push(2u8); // IntProperty
        // Schema Child: name=3("Child"), super=0("Parent"), prop_count=1, serial=1
        data.extend_from_slice(&3i32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // super = "Parent"
        data.extend_from_slice(&1u16.to_le_bytes()); // per-class count, NOT child+parent
        data.extend_from_slice(&1u16.to_le_bytes()); // only 1 new prop serialized
        data.extend_from_slice(&0u16.to_le_bytes()); // per-class schema_index=0
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
        // Child-first concat: Child's own slots first (`y`), then
        // Parent's properties offset by Child.PropertyCount (`x` at
        // absolute 1).
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].property.name.as_ref(), "y");
        assert_eq!(all[0].absolute_index, 0);
        assert_eq!(all[1].property.name.as_ref(), "x");
        assert_eq!(all[1].absolute_index, 1);
    }

    #[test]
    fn from_path_rejects_non_regular_file() {
        // A directory path fails `is_file()` and surfaces as Io with
        // `InvalidInput` kind. Same rejection covers FIFOs / sockets
        // / devices on platforms where they exist.
        let dir = std::env::temp_dir();
        let err = Usmap::from_path(&dir)
            .expect_err("non-regular-file path must be rejected before any read");
        match err {
            crate::PaksmithError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    io_err.to_string().contains("is not a regular file"),
                    "got: {io_err}"
                );
            }
            other => panic!("expected PaksmithError::Io, got {other:?}"),
        }
    }

    #[test]
    fn from_path_rejects_oversized_file() {
        // Use `from_path_with_cap` with cap = 10 so the test writes
        // 11 bytes to a tempfile instead of MAX_FILE_SIZE + 1 (~128 MiB).
        let mut path = std::env::temp_dir();
        path.push(format!(
            "paksmith-from-path-oversize-test-{}.usmap",
            std::process::id()
        ));
        std::fs::write(&path, [0u8; 11]).expect("write tempfile");
        let err =
            Usmap::from_path_with_cap(&path, 10).expect_err("oversized file must be rejected");
        let _ = std::fs::remove_file(&path);
        match err {
            crate::PaksmithError::Io(io_err) => {
                assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    io_err.to_string().contains("exceeds"),
                    "expected 'exceeds' in message; got: {io_err}"
                );
            }
            other => panic!("expected PaksmithError::Io, got {other:?}"),
        }
    }

    #[test]
    fn from_path_at_size_boundary_proceeds_to_parser() {
        // A file exactly at the cap (10 bytes here, sized down from
        // MAX_FILE_SIZE for test speed) is accepted by the size check
        // and falls through to `from_bytes`, which then errors on the
        // wire format (the 10 bytes aren't a valid .usmap header).
        // The point is to pin the `> cap` boundary as strict-greater.
        let mut path = std::env::temp_dir();
        path.push(format!(
            "paksmith-from-path-boundary-test-{}.usmap",
            std::process::id()
        ));
        std::fs::write(&path, [0u8; 10]).expect("write tempfile");
        let err = Usmap::from_path_with_cap(&path, 10)
            .expect_err("boundary file passes size check but fails wire-format parse");
        let _ = std::fs::remove_file(&path);
        // Specifically NOT the oversize Io error — must be a parse fault.
        match err {
            crate::PaksmithError::MappingsParse { .. } => {}
            other => panic!(
                "boundary file should reach the parser (MappingsParse), \
                 got {other:?}"
            ),
        }
    }

    // Pins the symlink-following contract documented on `from_path`:
    // a symlink pointing at a regular file is accepted (follows the
    // link via `fs::metadata`, not `symlink_metadata`). Unix-only;
    // Windows symlink creation needs elevated privileges and isn't
    // worth the test scaffolding here.
    #[cfg(unix)]
    #[test]
    fn from_path_follows_symlink_to_regular_file() {
        use std::os::unix::fs::symlink;
        let pid = std::process::id();
        let mut target = std::env::temp_dir();
        target.push(format!("paksmith-symlink-target-{pid}.usmap"));
        let mut link = std::env::temp_dir();
        link.push(format!("paksmith-symlink-link-{pid}.usmap"));
        let _ = std::fs::remove_file(&link);
        std::fs::write(&target, [0u8; 10]).expect("write target");
        symlink(&target, &link).expect("create symlink");

        let err = Usmap::from_path_with_cap(&link, 10)
            .expect_err("symlink to regular file should pass is_file and reach parser");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        // Reached the parser → MappingsParse, not Io.
        match err {
            crate::PaksmithError::MappingsParse { .. } => {}
            other => panic!(
                "symlink → regular file must follow through to the parser; \
                 got {other:?}"
            ),
        }
    }
}
