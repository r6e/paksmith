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
//! See `docs/formats/property/unversioned.md` (`.usmap` file format) for
//! the wire format.

use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Arc;

use byteorder::{LE, ReadBytesExt};
use zstd::zstd_safe::DCtx;

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

/// The large-window extension's first byte, whose window code RFC 7932 §9.1
/// leaves invalid. With its top bit set it is invalid to every decoder.
const BROTLI_LARGE_WINDOW_MARKER: u8 = 0x11;

// zstd frame magics: the v1 frame's, and the range of sixteen that mark a
// skippable frame.
const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;
const ZSTD_SKIPPABLE_MAGIC_FIRST: u32 = 0x184D_2A50;
const ZSTD_SKIPPABLE_MAGIC_LAST: u32 = 0x184D_2A5F;

/// Hard cap on the wire-claimed `compressed_size` of a `.usmap` file.
/// Community-distributed usmaps are typically <1 MiB; 64 MiB gives huge
/// headroom while refusing a malicious header that claims `u32::MAX`
/// (~4 GiB).
pub const MAX_USMAP_COMPRESSED_SIZE: u32 = 64 * 1024 * 1024;

/// Hard cap on the wire-claimed `decompressed_size`, and so on the output
/// buffer reserved for it: a header claiming `u32::MAX` would otherwise
/// reserve 4 GiB before the decoder runs.
pub const MAX_USMAP_DECOMPRESSED_SIZE: u32 = 256 * 1024 * 1024;

/// Hard cap on the inheritance chain length when walking
/// `super_type` pointers. A malicious `.usmap` with a cycle (`A: B`,
/// `B: A`) would loop forever otherwise.
const MAX_INHERITANCE_DEPTH: usize = 64;

/// Hard cap on `enum_count` to bound the enum-table heap cost. Each value
/// costs a map entry and a refcount on a shared name, so with the per-enum
/// value cap a maxed-out table stays near 200 MiB. Realistic UE
/// mappings carry <1k enums (Fortnite tops out around a few hundred);
/// 4096 is a wide safety margin.
///
/// Exposed via [`max_usmap_enum_count`].
const MAX_USMAP_ENUM_COUNT: u32 = 4_096;

/// Hard cap on per-enum `value_count`. `LargeEnums` (v3) widened the
/// wire field to `u16` (65535 max); no real-world enum has that many
/// values — even unwieldy Unreal enums top out in the low hundreds.
/// 1024 leaves room for outliers while bounding the per-enum map to
/// tens of KiB: each value is a key and a refcount on a shared name.
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
/// to a single-digit-MiB slot reservation.
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

/// Hard cap on type-tree nodes summed across a whole schema table. Every
/// node but a row's root is one `Arc` allocation of a few dozen bytes and
/// can cost a single wire byte, so the decompressed-size cap alone allowed gigabytes of type
/// trees. Real rows run to a few nodes each; 4 Mi nodes keeps the worst
/// case near 160 MiB.
///
/// Exposed via [`max_usmap_type_nodes`].
const MAX_USMAP_TYPE_NODES: u64 = 4_194_304;

/// Hard cap on the wire-claimed `cv_count` in the .usmap versioning
/// block. Real-world `CustomVersionContainer`s top out in the low
/// tens (Fortnite ships `cv_count = 3`); 1_024 leaves wide headroom.
///
/// Without this cap, an absurd `cv_count` whose array runs past the end
/// of the input would still end the parse as a
/// `MappingsParseFault::Truncated` at the custom-version array, but the
/// triage signal would be "wire stream truncated" rather than the
/// wire-cap-specific `CvCountTooLarge`. The cap delivers the typed fault
/// before the array is read.
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
/// so it is not part of the stable public API; downstream consumers
/// should not pin against this value.
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

/// Test-only accessor for `MAX_USMAP_TYPE_NODES`. Same rationale as
/// [`max_usmap_enum_count`].
#[cfg(feature = "__test_utils")]
#[must_use]
pub fn max_usmap_type_nodes() -> u64 {
    MAX_USMAP_TYPE_NODES
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
/// `#[non_exhaustive]` so future variants (Delegate / FieldPath,
/// currently the `Unknown(byte)` catch-all) can land as
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
        /// expanded slot. Issue #397 sub-fix A.
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
        /// The element type, shared by every slot and cache entry that
        /// holds this type.
        inner: Arc<MappedPropertyType>,
    },
    /// `SetProperty` — variable-length set with a single element type.
    /// Wire shape mirrors `Array` plus a leading `num_to_remove` prefix.
    Set {
        /// The element type, shared like [`Self::Array`]'s.
        inner: Arc<MappedPropertyType>,
    },
    /// `MapProperty` — key→value map. The `.usmap` schema encodes the
    /// key type first, then the value type (CUE4Parse `EPropertyType`
    /// `MapProperty` = byte 24, two recursive inner types).
    Map {
        /// The key type, shared like [`Self::Array`]'s element type.
        key: Arc<MappedPropertyType>,
        /// The value type, shared the same way.
        value: Arc<MappedPropertyType>,
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
    /// permitted ~4 GiB of clone-only heap per schema. Issue #397
    /// sub-fix A.
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
    /// hot per-export path. `MappedProperty` clones are cheap (the name
    /// and any nested type sit behind `Arc`), and the cache is bounded by
    /// [`MAX_USMAP_FLATTENED_TOTAL_ENTRIES`].
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
    ///    directories) twice: an ADVISORY `fs::metadata().is_file()`
    ///    pre-check before opening (rejects a stable FIFO path without
    ///    ever blocking in `open`), then an AUTHORITATIVE
    ///    `File::metadata()` fstat on the opened handle (race-free —
    ///    the same file object the read uses). Residual: a path swapped
    ///    for a FIFO in the stat→open race still blocks in `open`;
    ///    that race is same-trust-domain (the invoking user's own
    ///    profiles.toml / `--mappings` argument) and accepted.
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
        // ADVISORY pre-check: opening a FIFO for reading blocks until a
        // writer appears, so a stable FIFO path must be rejected BEFORE
        // `open` (the read cap bounds size, not blocking). This stat is
        // advisory only — the authoritative type/size check is the fstat
        // on the opened handle below, which is race-free.
        let pre = std::fs::metadata(path).map_err(|e| {
            PaksmithError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to stat `{}`: {e}", path.display()),
            ))
        })?;
        if !pre.is_file() {
            return Err(PaksmithError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("`{}` is not a regular file", path.display()),
            )));
        }
        // AUTHORITATIVE check: fstat the opened handle — the stat→open
        // pair above is a TOCTOU window in which the path can be swapped;
        // this metadata targets the same file object the read will use.
        // (A raced swap to a FIFO still blocks in `open` — accepted, see
        // `from_path`'s doc.)
        let file = std::fs::File::open(path).map_err(|e| {
            PaksmithError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to open `{}`: {e}", path.display()),
            ))
        })?;
        let metadata = file.metadata().map_err(|e| {
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
        let _ = file.take(cap + 1).read_to_end(&mut buf).map_err(|e| {
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
    /// caps exceeded, decompression mismatch, or truncated data; and on a
    /// refused allocation.
    #[allow(
        clippy::too_many_lines,
        reason = "single linear wire-format read: header + versioning block + three compression branches; \
                  splitting into helpers would shred the byte-stream flow and the cap-rejection logic that \
                  must run inline against the raw u32 values before any allocation"
    )]
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let mut cur = Cursor::new(bytes);
        let magic = read_or_truncated(&mut cur, |c| c.read_u16::<LE>())?;
        if magic != USMAP_MAGIC {
            return Err(fault(MappingsParseFault::InvalidMagic { found: magic }));
        }

        let version = read_or_truncated(&mut cur, |c| c.read_u8())?;
        if version > MAX_USMAP_VERSION {
            return Err(fault(MappingsParseFault::UnsupportedVersion {
                found: version,
            }));
        }

        if version >= USMAP_VERSION_PACKAGE_VERSIONING {
            // A bool32: CUE4Parse reads it with `ReadBoolean`, and UE4SS and
            // Dumper-7 write an int32. The pinned unreal_asset oracle reads
            // one byte here, and is not followed.
            let has_versioning = match read_or_truncated(&mut cur, |c| c.read_i32::<LE>())? {
                0 => false,
                1 => true,
                found => {
                    return Err(fault(MappingsParseFault::InvalidVersioningFlag { found }));
                }
            };
            if has_versioning {
                // object_version + object_version_ue5 + custom_version array + net_cl
                let _obj_ver = read_or_truncated(&mut cur, |c| c.read_i32::<LE>())?;
                let _obj_ver_ue5 = read_or_truncated(&mut cur, |c| c.read_i32::<LE>())?;
                let cv_count = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
                if cv_count > MAX_USMAP_CV_COUNT {
                    return Err(fault(MappingsParseFault::CvCountTooLarge {
                        count: cv_count,
                        limit: MAX_USMAP_CV_COUNT,
                    }));
                }
                // Each CustomVersion = 16-byte GUID + i32 version number = 20
                // bytes, read rather than seeked past: a seek past the end
                // would succeed.
                read_or_truncated(&mut cur, |c| {
                    (0..cv_count).try_for_each(|_| c.read_exact(&mut [0u8; 20]))
                })?;
                let _net_cl = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
            }
        }

        let compression_byte = read_or_truncated(&mut cur, |c| c.read_u8())?;
        let compressed_size = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
        let decompressed_size = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;

        // Reject pathological sizes up front, before the payload is sliced
        // or an output buffer is sized from them.
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

        // compressed_size is u32, bounded above by MAX_USMAP_COMPRESSED_SIZE
        // (64 MiB) — well within usize on any supported target (16-bit
        // platforms aren't tier-1 for paksmith). On a 32-bit target, 64 MiB
        // fits comfortably in usize::MAX (~4 GiB).
        #[allow(
            clippy::cast_possible_truncation,
            reason = "compressed_size <= 64 MiB cap, well within usize on 32-bit+"
        )]
        let compressed_size_usz = compressed_size as usize;
        let payload_offset = position_usize(&cur);
        let payload = bytes
            .get(payload_offset..)
            .and_then(|rest| rest.get(..compressed_size_usz))
            .ok_or_else(|| {
                fault(MappingsParseFault::Truncated {
                    offset: payload_offset,
                })
            })?;
        let payload_end = payload_offset + payload.len();
        let undecodable = || {
            fault(MappingsParseFault::Truncated {
                offset: payload_end,
            })
        };

        // decompressed_size is u32, bounded above by MAX_USMAP_DECOMPRESSED_SIZE
        // (256 MiB) — fits in usize on any supported target.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "decompressed_size <= 256 MiB cap, well within usize on 32-bit+"
        )]
        let decompressed_size_usz = decompressed_size as usize;
        // One spare byte, so an overshoot lands in place and reads as a
        // mismatch: without it, `read_to_end` doubles the buffer to fit one
        // byte, and a one-shot decode has nowhere to put it.
        let output_len = decompressed_size_usz + 1;

        let data: Cow<'_, [u8]> = match compression_byte {
            x if x == UsmapCompression::None as u8 => Cow::Borrowed(payload),
            x if x == UsmapCompression::Brotli as u8 => {
                // `Decompressor::new` accepts the large-window extension, and
                // the decoder allocates its ring buffer at the window the
                // stream header names before producing any output.
                if is_large_window_brotli(payload) {
                    return Err(fault(MappingsParseFault::BrotliLargeWindowUnsupported));
                }
                let limit = u64::from(decompressed_size) + 1;
                let decoder = brotli::Decompressor::new(payload, 4096);
                let mut out = reserve_decompressed(output_len)?;
                let _ = std::io::Read::take(decoder, limit)
                    .read_to_end(&mut out)
                    .map_err(|_| undecodable())?;
                Cow::Owned(out)
            }
            x if x == UsmapCompression::ZStandard as u8 => {
                // One-shot, straight into the reserved output. The streaming
                // decoder allocates a buffer up to the frame's declared window,
                // 128 MiB by default; a one-shot decode writes into `out`.
                if !is_zstd_v1_stream(payload) {
                    return Err(undecodable());
                }
                let mut out = reserve_decompressed(output_len)?;
                let _ = zstd_context(DCtx::try_create())?
                    .decompress(&mut out, payload)
                    .map_err(|_| undecodable())?;
                Cow::Owned(out)
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
        if data.len() != decompressed_size_usz {
            return Err(fault(MappingsParseFault::DecompressedSizeMismatch {
                expected: decompressed_size,
                found: data.len(),
            }));
        }

        Self::parse_schema_data(&data, version, SchemaBudgets::DEFAULT)
    }

    /// `budgets` caps totals across every schema row: expanded properties,
    /// which past [`MAX_USMAP_FLATTENED_TOTAL_ENTRIES`] cannot build the
    /// cache unless repeated schema names overwrite each other, and
    /// type-tree nodes. Both refuse during the walk, before the rest is
    /// allocated.
    #[allow(
        clippy::too_many_lines,
        reason = "single linear wire-format read: name table, enum table (with v2/v3/v4 \
                  version-gated branches), schema table; splitting into helpers would shred \
                  the shared `cur`/`names`/`enums` flow that each section feeds into the next"
    )]
    fn parse_schema_data(data: &[u8], version: u8, budgets: SchemaBudgets) -> crate::Result<Self> {
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
        let name_count = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
        if name_count > MAX_USMAP_NAME_COUNT {
            return Err(fault(MappingsParseFault::NameCountTooLarge {
                count: name_count,
                limit: MAX_USMAP_NAME_COUNT,
            }));
        }
        let mut names: Vec<Arc<str>> = Vec::new();
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
                read_or_truncated(&mut cur, |c| c.read_u16::<LE>())? as usize
            } else {
                read_or_truncated(&mut cur, |c| c.read_u8())? as usize
            };
            let mut buf = vec![0u8; name_length];
            read_or_truncated(&mut cur, |c| c.read_exact(&mut buf))?;
            let name = String::from_utf8(buf).unwrap_or_else(|err| {
                tracing::warn!(
                    offset = position_usize(&cur),
                    error = err.to_string(),
                    "usmap name is not valid UTF-8; using empty string \
                     (downstream lookups will miss it)"
                );
                String::new()
            });
            names.push(Arc::from(name));
        }

        // Enum table — REQUIRED for unversioned `EnumProperty` reads
        // (per CUE4Parse's EnumProperty constructor for unversioned mode:
        // wire stream stores a u8 index; the resolved value name comes
        // from this table).
        let enum_count = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
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
                u32::from(read_or_truncated(&mut cur, |c| c.read_u16::<LE>())?)
            } else {
                u32::from(read_or_truncated(&mut cur, |c| c.read_u8())?)
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
                    let value = read_or_truncated(&mut cur, |c| c.read_u64::<LE>())?;
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
        let schema_count = read_or_truncated(&mut cur, |c| c.read_u32::<LE>())?;
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

        let mut expanded = Tally::expanded_properties(budgets.expanded_properties);
        let mut type_nodes = Tally::type_nodes(budgets.type_nodes);
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
            let prop_count = read_or_truncated(&mut cur, |c| c.read_u16::<LE>())?;
            let serial_count = read_or_truncated(&mut cur, |c| c.read_u16::<LE>())?;

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
                let schema_index = read_or_truncated(&mut cur, |c| c.read_u16::<LE>())?;
                let array_size = read_or_truncated(&mut cur, |c| c.read_u8())?;
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
                expanded.charge(u64::from(array_size))?;
                // `prop_name`: read as `Arc<str>` ONCE per row so the
                // inner `array_size` expansion loop clones a refcount
                // per slot instead of a heap-allocated name buffer
                // (issue #397 sub-fix A; see `read_name_arc`).
                let prop_name = read_name_arc(&mut cur, &names)?;
                let prop_type = read_mapped_type(&mut cur, &names, 0, &mut type_nodes)?;
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
        let graph = SchemaGraph::new(schemas);
        let mut total: u64 = 0;
        for (index, (class_name, _)) in graph.classes.iter().enumerate() {
            // compute_flattened refuses before allocating when this class's
            // chain would exceed the remaining budget.
            let remaining = MAX_USMAP_FLATTENED_TOTAL_ENTRIES.saturating_sub(total);
            let flat = Self::compute_flattened(&graph, index, remaining)?;
            total = total.saturating_add(flat.len() as u64);
            let _ = flattened.insert((*class_name).clone(), flat);
        }
        Ok(flattened)
    }

    /// Walks the super-type chain of the class at `root` in `graph` and
    /// returns the flattened, sorted property list. The caching path in
    /// [`Self::build_flattened_cache`] is what makes
    /// [`Self::get_all_properties`] a HashMap lookup rather than a chain walk.
    ///
    /// Per CUE4Parse `MappingsSchema.cs::Struct.TryGetValue` the wire
    /// absolute slot indices are **child-first concatenated**:
    /// child's per-class slots occupy `[0, Child.PropertyCount)`,
    /// parent's per-class slot `i` occupies absolute
    /// `Child.PropertyCount + i`, grand-parent's slot `i` occupies
    /// `Child.PropertyCount + Parent.PropertyCount + i`, and so on.
    ///
    /// A malicious `.usmap` can make the chain cyclic (`A: B`, `B: A`) or
    /// deeper than `MAX_INHERITANCE_DEPTH`. Either one is warned about and
    /// truncated rather than failing the load: the `.usmap` is
    /// operator-supplied, and the properties collected so far still apply.
    fn compute_flattened(
        graph: &SchemaGraph<'_>,
        root: usize,
        budget: u64,
    ) -> crate::Result<Vec<ResolvedProperty>> {
        let class_name = |index: usize| crate::untrusted::clamp(graph.classes[index].0);
        // Child-first: `walked[0]` is `root`, `walked[1]` its parent, etc.
        let mut walked: Vec<usize> = Vec::new();
        let mut next = Some(root);
        while let Some(index) = next {
            if walked.len() == MAX_INHERITANCE_DEPTH {
                tracing::warn!(
                    root_class = &*class_name(root),
                    limit = MAX_INHERITANCE_DEPTH,
                    "inheritance chain exceeds MAX_INHERITANCE_DEPTH; truncating walk"
                );
                break;
            }
            if walked.contains(&index) {
                tracing::warn!(
                    root_class = &*class_name(root),
                    repeated_class = &*class_name(index),
                    "circular super_type chain in .usmap; truncating inheritance walk"
                );
                break;
            }
            walked.push(index);
            next = graph.parents[index];
        }
        let chain = || walked.iter().map(|&index| graph.classes[index].1);

        // Per-class size from the chain walk above (bounded by
        // MAX_INHERITANCE_DEPTH × per-class cap). Cheap to compute
        // — at most 64 reads — and used for both the running-total
        // budget check below and the `try_reserve` pre-allocation.
        let total: usize = chain().map(|s| s.properties.len()).sum();
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
        for schema in chain() {
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
/// `name` is `Arc<str>` and every nested `prop_type` sits behind an `Arc`,
/// so a clone is a handful of refcount bumps.
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
/// Returns the table's own entry, so every reference to one name shares
/// its allocation: a name referenced by thousands of enum values, rows or
/// type names costs a refcount each, not a copy.
///
/// An out-of-range index surfaces as
/// [`MappingsParseFault::NameIndexOutOfRange`] (issue #417 —
/// previously misnomered as `Truncated`, which implied a short read
/// even though the wire bytes were fully readable).
fn read_name_arc(cur: &mut Cursor<&[u8]>, names: &[Arc<str>]) -> crate::Result<Arc<str>> {
    let idx = read_or_truncated(cur, |c| c.read_i32::<LE>())?;
    #[allow(
        clippy::cast_sign_loss,
        reason = "negative indices wrap to a huge usize that fails the get() bounds check, surfacing as NameIndexOutOfRange"
    )]
    let idx_usz = idx as usize;
    names.get(idx_usz).map(Arc::clone).ok_or_else(|| {
        fault(MappingsParseFault::NameIndexOutOfRange {
            idx,
            table_len: names.len(),
        })
    })
}

/// [`read_name_arc`] as an owned `String`, for [`ClassSchema`]'s public
/// `String` fields.
fn read_name(cur: &mut Cursor<&[u8]>, names: &[Arc<str>]) -> crate::Result<String> {
    Ok(read_name_arc(cur, names)?.to_string())
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
    names: &[Arc<str>],
    depth: usize,
    nodes: &mut Tally,
) -> crate::Result<MappedPropertyType> {
    if depth > MAX_USMAP_ARRAY_NESTING_DEPTH {
        return Err(fault(MappingsParseFault::ArrayNestingTooDeep {
            depth,
            limit: MAX_USMAP_ARRAY_NESTING_DEPTH,
        }));
    }
    nodes.charge(1)?;
    let type_byte = read_or_truncated(cur, |c| c.read_u8())?;
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
            let inner = read_mapped_type(cur, names, depth + 1, nodes)?;
            MappedPropertyType::Array {
                inner: Arc::new(inner),
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
        24 => {
            // MapProperty — key inner type then value inner type. Both
            // recurse with incremented depth (nesting cap, #443). Reading
            // the two inners is load-bearing: mapping this byte to Unknown
            // WITHOUT consuming them desyncs the schema table for every
            // subsequent property (there is no per-property size to
            // resync on). #639.
            let key = read_mapped_type(cur, names, depth + 1, nodes)?;
            let value = read_mapped_type(cur, names, depth + 1, nodes)?;
            MappedPropertyType::Map {
                key: Arc::new(key),
                value: Arc::new(value),
            }
        }
        25 => {
            // SetProperty — single element inner type (same recursive
            // shape as ArrayProperty). #639.
            let inner = read_mapped_type(cur, names, depth + 1, nodes)?;
            MappedPropertyType::Set {
                inner: Arc::new(inner),
            }
        }
        26 => {
            // EnumProperty: inner type byte (always ByteProperty (0) in
            // practice), then enum name
            let _inner_byte = read_or_truncated(cur, |c| c.read_u8())?;
            let enum_name = read_name_arc(cur, names)?;
            MappedPropertyType::Enum { enum_name }
        }
        27 => MappedPropertyType::Unknown(type_byte), // FieldPathProperty
        other => MappedPropertyType::Unknown(other),
    })
}

/// The schema table as a list, each class's `super_type` resolved to its
/// parent's position once, so the inheritance walk compares positions
/// rather than hashing class names of up to 64 KiB at every step (#821).
struct SchemaGraph<'a> {
    classes: Vec<(&'a String, &'a ClassSchema)>,
    /// `parents[i]` is the position of class `i`'s parent, or `None` when its
    /// `super_type` is absent, empty, or names a class the table lacks.
    parents: Vec<Option<usize>>,
}

impl<'a> SchemaGraph<'a> {
    fn new(schemas: &'a HashMap<String, ClassSchema>) -> Self {
        let classes: Vec<(&String, &ClassSchema)> = schemas.iter().collect();
        let positions: HashMap<&str, usize> = classes
            .iter()
            .enumerate()
            .map(|(index, (name, _))| (name.as_str(), index))
            .collect();
        let parents = classes
            .iter()
            .map(|(_, schema)| {
                schema
                    .super_type
                    .as_deref()
                    .filter(|parent| !parent.is_empty())
                    .and_then(|parent| positions.get(parent).copied())
            })
            .collect();
        Self { classes, parents }
    }
}

/// Caps summed across a whole schema table rather than per schema.
#[derive(Clone, Copy)]
struct SchemaBudgets {
    expanded_properties: u64,
    type_nodes: u64,
}

impl SchemaBudgets {
    const DEFAULT: Self = Self {
        expanded_properties: MAX_USMAP_FLATTENED_TOTAL_ENTRIES,
        type_nodes: MAX_USMAP_TYPE_NODES,
    };
}

/// A total summed across the schema table, refused once it passes `limit`.
struct Tally {
    used: u64,
    limit: u64,
    exceeded: fn(u64, u64) -> MappingsParseFault,
}

impl Tally {
    fn expanded_properties(limit: u64) -> Self {
        Self {
            used: 0,
            limit,
            exceeded: |requested, limit| MappingsParseFault::ExpandedPropertiesTotalExceeded {
                requested,
                limit,
            },
        }
    }

    fn type_nodes(limit: u64) -> Self {
        Self {
            used: 0,
            limit,
            exceeded: |requested, limit| MappingsParseFault::TypeNodesExceeded { requested, limit },
        }
    }

    fn charge(&mut self, n: u64) -> crate::Result<()> {
        self.used += n;
        if self.used > self.limit {
            return Err(fault((self.exceeded)(self.used, self.limit)));
        }
        Ok(())
    }
}

fn is_large_window_brotli(stream: &[u8]) -> bool {
    stream.first() == Some(&BROTLI_LARGE_WINDOW_MARKER)
}

fn reserve_decompressed(len: usize) -> crate::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|source| {
        mappings_alloc_failed(
            MappingsAllocationContext::DecompressedDataBytes,
            len,
            source,
        )
    })?;
    Ok(out)
}

fn zstd_context(created: Option<DCtx<'static>>) -> crate::Result<DCtx<'static>> {
    created.ok_or_else(|| fault(MappingsParseFault::ZstdContextUnavailable))
}

/// Whether `stream` is one or more zstd v1 or skippable frames. libzstd is
/// built with its pre-v1 decoders, and a one-shot decode hands each frame to
/// whichever decoder its magic names.
fn is_zstd_v1_stream(mut stream: &[u8]) -> bool {
    if stream.is_empty() {
        return false;
    }
    while !stream.is_empty() {
        let Some(magic) = stream.first_chunk::<4>().map(|m| u32::from_le_bytes(*m)) else {
            return false;
        };
        if !matches!(
            magic,
            ZSTD_FRAME_MAGIC | ZSTD_SKIPPABLE_MAGIC_FIRST..=ZSTD_SKIPPABLE_MAGIC_LAST
        ) {
            return false;
        }
        let Some(rest) = zstd::zstd_safe::find_frame_compressed_size(stream)
            .ok()
            .and_then(|len| stream.get(len..))
        else {
            return false;
        };
        stream = rest;
    }
    true
}

fn fault(f: MappingsParseFault) -> PaksmithError {
    PaksmithError::MappingsParse { fault: f }
}

/// `read` from `cur`, a short read reported as
/// [`MappingsParseFault::Truncated`] at the offset where the read began.
fn read_or_truncated<T>(
    cur: &mut Cursor<&[u8]>,
    read: impl FnOnce(&mut Cursor<&[u8]>) -> std::io::Result<T>,
) -> crate::Result<T> {
    let start = position_usize(cur);
    read(cur).map_err(|_| fault(MappingsParseFault::Truncated { offset: start }))
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

/// The checked-in `.usmap` fixture whose `Hero` schema holds `Health` and
/// `Speed`, for tests outside the `__test_utils` gate.
#[cfg(test)]
pub(crate) fn hero_usmap_fixture() -> std::path::PathBuf {
    usmap_fixture("external_minimal_v0.usmap")
}

/// The checked-in `.usmap` fixture `name`.
#[cfg(test)]
fn usmap_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

// Tests are gated on `__test_utils` (rather than plain `#[cfg(test)]`)
// because they reuse `testing::usmap::build_minimal_usmap_bytes` — the
// canonical source for the minimal `.usmap` byte fixture, shared with
// fixture-gen + integration tests. Same precedent as `package.rs`. The
// trade-off: these tests do not run in the no-feature
// `cargo test -p paksmith-core` build. The DRY win (≥45 lines of
// duplicate wire-format bytes) is worth that gap; a future stand-alone
// reader-only test that doesn't need the helper can sit in a separate
// `#[cfg(test)]` module.
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
        // Magic + version=4 + has_versioning=0 (an i32) + compression None
        let mut usmap_bytes = vec![0xC4u8, 0x30, 4, 0, 0, 0, 0, 0];
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
        let result = flatten(&schemas, class_name, 1)
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
        let err = flatten(&schemas, class_name, 1)
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

    /// [`Usmap::compute_flattened`] for the class named `root` in `schemas`.
    fn flatten(
        schemas: &HashMap<String, ClassSchema>,
        root: &str,
        budget: u64,
    ) -> crate::Result<Vec<ResolvedProperty>> {
        let graph = SchemaGraph::new(schemas);
        let root = graph
            .classes
            .iter()
            .position(|(name, _)| name.as_str() == root)
            .expect("root is in the table");
        Usmap::compute_flattened(&graph, root, budget)
    }

    /// A class with one Int32 property named after the class, whose
    /// super_type is `parent`.
    fn chain_class(name: &str, parent: Option<&str>) -> (String, ClassSchema) {
        let schema = ClassSchema {
            name: name.to_string(),
            super_type: parent.map(str::to_string),
            prop_count: 1,
            properties: vec![MappedProperty {
                name: Arc::from(name),
                schema_index: 0,
                array_index: 0,
                prop_type: MappedPropertyType::Int32,
            }],
        };
        (name.to_string(), schema)
    }

    /// `n` classes, each the parent of the one before it; the last one's
    /// parent is `last_parent`.
    fn class_chain(
        n: usize,
        last_parent: Option<&str>,
    ) -> (Vec<String>, HashMap<String, ClassSchema>) {
        let names: Vec<String> = (0..n)
            .map(|i| format!("{}{i}", crate::untrusted::test_support::hostile_name("D")))
            .collect();
        let schemas = names
            .iter()
            .enumerate()
            .map(|(i, name)| {
                chain_class(name, names.get(i + 1).map(String::as_str).or(last_parent))
            })
            .collect();
        (names, schemas)
    }

    /// A cyclic super_type chain stops at the repeat with every class
    /// before it collected, and the warning names the root and the repeated
    /// class, both clamped.
    #[tracing_test::traced_test]
    #[test]
    fn cyclic_chain_stops_at_the_repeat_and_warns_with_clamped_names() {
        use crate::untrusted::test_support::{hostile_name, lines_clamped};

        let [root, a, b] = ["R", "A", "B"].map(hostile_name);
        let schemas: HashMap<String, ClassSchema> = [
            chain_class(&root, Some(&a)),
            chain_class(&a, Some(&b)),
            chain_class(&b, Some(&a)),
        ]
        .into_iter()
        .collect();

        let flat = flatten(&schemas, &root, u64::MAX).unwrap();

        let names: Vec<&str> = flat.iter().map(|p| p.property.name.as_ref()).collect();
        assert_eq!(names, [root.as_str(), a.as_str(), b.as_str()]);
        logs_assert(lines_clamped("circular super_type chain", "R"));
        logs_assert(lines_clamped("circular super_type chain", "A"));
        assert!(!logs_contain("BKEPT"));
    }

    /// A chain longer than `MAX_INHERITANCE_DEPTH` stops at the limit, and
    /// the warning names the root class clamped.
    #[tracing_test::traced_test]
    #[test]
    fn overlong_chain_stops_at_the_depth_limit_and_warns_with_a_clamped_root() {
        use crate::untrusted::test_support::lines_clamped;

        let (names, schemas) = class_chain(MAX_INHERITANCE_DEPTH + 2, None);

        let flat = flatten(&schemas, &names[0], u64::MAX).unwrap();

        assert_eq!(flat.len(), MAX_INHERITANCE_DEPTH);
        logs_assert(lines_clamped("exceeds MAX_INHERITANCE_DEPTH", "D"));
    }

    /// A chain that ends at exactly `MAX_INHERITANCE_DEPTH` classes, the
    /// last naming a parent the table does not have, is complete: no depth
    /// warning.
    #[tracing_test::traced_test]
    #[test]
    fn chain_ending_at_a_missing_parent_on_the_depth_limit_does_not_warn() {
        let (names, schemas) = class_chain(MAX_INHERITANCE_DEPTH, Some("Missing"));

        let flat = flatten(&schemas, &names[0], u64::MAX).unwrap();

        assert_eq!(flat.len(), MAX_INHERITANCE_DEPTH);
        assert!(!logs_contain("exceeds MAX_INHERITANCE_DEPTH"));
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
    fn parse_usmap_versioning_flag_must_be_0_or_1() {
        for found in [2, -1] {
            let mut usmap = vec![0xC4u8, 0x30, 1];
            usmap.extend_from_slice(&i32::to_le_bytes(found));
            assert_eq!(
                parse_fault(&usmap),
                crate::error::MappingsParseFault::InvalidVersioningFlag { found },
                "{found}"
            );
        }
    }

    #[test]
    fn parse_usmap_cv_count_too_large_rejected() {
        // v1 .usmap with `has_versioning = 1`, valid obj_version /
        // obj_version_ue5, then `cv_count = MAX + 1`. The cap check
        // fires before the custom-version array is read.
        //
        // Wire layout (no compression header needed — cap check fires
        // mid-versioning-block, before `compression_byte` is read):
        //   magic(2) + version=1(1) + has_versioning=1(4) + obj_ver(4)
        //   + obj_ver_ue5(4) + cv_count=cap+1(4) → CAP REJECT
        let cap = max_usmap_cv_count();
        let mut usmap: Vec<u8> = vec![0xC4u8, 0x30, 1u8]; // magic + v1
        usmap.extend_from_slice(&1i32.to_le_bytes()); // has_versioning = true
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
        // magic + v3 + has_versioning=0 (an i32) + compression None
        let mut usmap = vec![0xC4u8, 0x30, 3, 0, 0, 0, 0, 0];
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
        // The first row to overshoot names index 99, out of range, so the cap
        // must fire before the row's name is read.
        for row in 0..rows {
            let name_idx: i32 = if u32::from(row) == cap / 255 { 99 } else { 2 };
            data.extend_from_slice(&0u16.to_le_bytes()); // schema_index
            data.push(255u8); // array_size — maximal expansion
            data.extend_from_slice(&name_idx.to_le_bytes());
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

    /// A `.usmap` schema whose FIRST property is a `Map<Int32,Int32>`
    /// (type bytes `24, 2, 2`) followed by a plain `IntProperty` (`2`).
    /// `read_mapped_type` MUST consume the Map's two inner type bytes, or
    /// the second property desyncs and mis-parses (there is no per-property
    /// size to resync on). This is the real-`.usmap`-byte-parse coverage
    /// that the pre-#639 `24|25 => Unknown` (no inner consume) lacked. #639.
    #[test]
    fn parse_usmap_map_property_consumes_inners_no_desync() {
        let mut data: Vec<u8> = Vec::new();
        // Name table: 0="Hero", 1="None", 2="M", 3="H".
        data.extend_from_slice(&4u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (1u8, "M"), (1u8, "H")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes()); // empty enum table
        data.extend_from_slice(&1u32.to_le_bytes()); // 1 schema
        data.extend_from_slice(&0i32.to_le_bytes()); // name = "Hero"
        data.extend_from_slice(&1i32.to_le_bytes()); // super = "None"
        data.extend_from_slice(&2u16.to_le_bytes()); // prop_count = 2
        data.extend_from_slice(&2u16.to_le_bytes()); // serial_count = 2
        // Prop 0: schema_index=0, array_size=1, name="M", type=Map<Int32,Int32>.
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&[24u8, 2u8, 2u8]); // MapProperty, Int32 key, Int32 value
        // Prop 1: schema_index=1, array_size=1, name="H", type=IntProperty.
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&3i32.to_le_bytes());
        data.push(2u8); // IntProperty

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let parsed = Usmap::from_bytes(&usmap).expect("usmap parse");
        let hero = parsed.schemas.get("Hero").expect("Hero schema");
        let m = hero
            .properties
            .iter()
            .find(|p| p.name.as_ref() == "M")
            .expect("M prop");
        assert!(
            matches!(&m.prop_type, MappedPropertyType::Map { key, value }
                if matches!(**key, MappedPropertyType::Int32)
                    && matches!(**value, MappedPropertyType::Int32)),
            "M must be Map<Int32,Int32>, got {:?}",
            m.prop_type
        );
        // The desync-catcher: H is only correct if the Map's inners were consumed.
        let h = hero
            .properties
            .iter()
            .find(|p| p.name.as_ref() == "H")
            .expect("H prop — a desync would lose or corrupt this");
        assert!(
            matches!(h.prop_type, MappedPropertyType::Int32),
            "H must be Int32 (desync would mis-type it), got {:?}",
            h.prop_type
        );
    }

    /// Same as above but the first property is a `Set<Int32>` (`25, 2`):
    /// its single inner type byte must be consumed. #639.
    #[test]
    fn parse_usmap_set_property_consumes_inner_no_desync() {
        let mut data: Vec<u8> = Vec::new();
        data.extend_from_slice(&4u32.to_le_bytes());
        for (len, name) in [(4u8, "Hero"), (4u8, "None"), (1u8, "S"), (1u8, "H")] {
            data.push(len);
            data.extend_from_slice(name.as_bytes());
        }
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&[25u8, 2u8]); // SetProperty, Int32 element
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(1u8);
        data.extend_from_slice(&3i32.to_le_bytes());
        data.push(2u8); // IntProperty

        let data_len = u32::try_from(data.len()).unwrap();
        let mut usmap = vec![0xC4u8, 0x30, 0, 0];
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data_len.to_le_bytes());
        usmap.extend_from_slice(&data);

        let parsed = Usmap::from_bytes(&usmap).expect("usmap parse");
        let hero = parsed.schemas.get("Hero").expect("Hero schema");
        let s = hero
            .properties
            .iter()
            .find(|p| p.name.as_ref() == "S")
            .expect("S prop");
        assert!(
            matches!(&s.prop_type, MappedPropertyType::Set { inner }
                if matches!(**inner, MappedPropertyType::Int32)),
            "S must be Set<Int32>, got {:?}",
            s.prop_type
        );
        let h = hero
            .properties
            .iter()
            .find(|p| p.name.as_ref() == "H")
            .expect("H prop — a desync would lose or corrupt this");
        assert!(matches!(h.prop_type, MappedPropertyType::Int32));
    }

    /// Each of `read_mapped_type`'s recursive inner reads (Map key, Map
    /// value, Set element) must pass `depth + 1`, or a deeply-nested
    /// container escapes `MAX_USMAP_ARRAY_NESTING_DEPTH`. Called at the
    /// cap so a single further level trips it — isolating each `+ 1`
    /// increment (kills the `+ 1 -> * 1` mutants). #639.
    #[test]
    fn read_mapped_type_container_increments_depth() {
        let cap = MAX_USMAP_ARRAY_NESTING_DEPTH;
        let names: Vec<Arc<str>> = Vec::new();
        let is_too_deep = |bytes: &[u8], depth: usize| -> bool {
            let mut cur = Cursor::new(bytes);
            matches!(
                read_mapped_type(&mut cur, &names, depth, &mut Tally::type_nodes(u64::MAX)),
                Err(crate::PaksmithError::MappingsParse {
                    fault: MappingsParseFault::ArrayNestingTooDeep { .. },
                })
            )
        };
        // Set element: `Set<Int32>` at depth = cap → element read at cap+1.
        assert!(
            is_too_deep(&[25u8, 2u8], cap),
            "Set inner must increment depth"
        );
        // Map key: `Map<Array<Int32>, Int32>` at depth cap-1 → the key's
        // Array recurses one past the cap only if the Map key read added 1.
        assert!(
            is_too_deep(&[24u8, 8u8, 2u8, 2u8], cap - 1),
            "Map key must increment depth"
        );
        // Map value: `Map<Int32, Array<Int32>>` at depth cap-1 → same via value.
        assert!(
            is_too_deep(&[24u8, 2u8, 8u8, 2u8], cap - 1),
            "Map value must increment depth"
        );
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

    /// The minimal fixture's header with `method`, `stored` as its payload,
    /// and `declared` as its decompressed size.
    fn usmap_with(method: UsmapCompression, stored: &[u8], declared: usize) -> Vec<u8> {
        let mut bytes = minimal_usmap_none()[..4].to_vec();
        bytes[3] = method as u8;
        bytes.extend_from_slice(&u32::try_from(stored.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(declared).unwrap().to_le_bytes());
        bytes.extend_from_slice(stored);
        bytes
    }

    /// The fixture header's length: magic, version, compression, two sizes.
    const HEADER_LEN: usize = 12;

    fn schema_payload() -> Vec<u8> {
        minimal_usmap_none()[HEADER_LEN..].to_vec()
    }

    fn schema_fault(
        data: &[u8],
        version: u8,
        budgets: SchemaBudgets,
    ) -> crate::error::MappingsParseFault {
        match Usmap::parse_schema_data(data, version, budgets) {
            Err(crate::PaksmithError::MappingsParse { fault }) => fault,
            other => panic!("expected a mappings fault, got {other:?}"),
        }
    }

    /// The checked-in v4 fixture's schema data, after its header: the v0
    /// header plus the four-byte versioning flag.
    fn v4_schema_data() -> Vec<u8> {
        std::fs::read(usmap_fixture("external_minimal_v4.usmap")).unwrap()[HEADER_LEN + 4..]
            .to_vec()
    }

    /// A v1 file with `versioning` after its version byte, an uncompressed
    /// payload and the minimal schema.
    fn v1_usmap(versioning: &[u8]) -> Vec<u8> {
        let v0 = minimal_usmap_none();
        [&v0[..2], &[1], versioning, &v0[3..]].concat()
    }

    fn parse_fault(bytes: &[u8]) -> crate::error::MappingsParseFault {
        match Usmap::from_bytes(bytes) {
            Err(crate::PaksmithError::MappingsParse { fault }) => fault,
            other => panic!("expected a mappings fault, got {other:?}"),
        }
    }

    fn brotli_compress(payload: &[u8], large_window: bool, lgwin: i32) -> Vec<u8> {
        let params = brotli::enc::BrotliEncoderParams {
            large_window,
            lgwin,
            ..Default::default()
        };
        let mut out = Vec::new();
        let _ = brotli::BrotliCompress(&mut &payload[..], &mut out, &params).unwrap();
        out
    }

    fn zstd_compress(payload: &[u8], content_size: bool) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3).unwrap();
        if content_size {
            encoder
                .set_pledged_src_size(Some(u64::try_from(payload.len()).unwrap()))
                .unwrap();
        }
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    /// A pre-v1 zstd frame holding `payload` in one raw block: v0.2 has no
    /// frame header byte, v0.4 has one.
    fn zstd_legacy_frame(magic: u32, header: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut frame = magic.to_le_bytes().to_vec();
        frame.extend_from_slice(header);
        frame.extend_from_slice(&[0x40, 0, u8::try_from(payload.len()).unwrap()]);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&[0xC0, 0, 0]);
        frame
    }

    fn assert_matches_uncompressed(usmap: &Usmap) {
        let expected = Usmap::from_bytes(&minimal_usmap_none()).unwrap();
        assert_eq!(usmap.schemas.len(), expected.schemas.len());
        assert_eq!(
            format!("{:?}", usmap.schemas.get("Hero")),
            format!("{:?}", expected.schemas.get("Hero"))
        );
    }

    /// Today's encoders' output for the minimal schema payload, frozen so a
    /// codec bump that changes how an existing stream decodes fails a test.
    /// Brotli at the standard 22-bit window; zstd with its content size.
    const FROZEN_BROTLI: &[u8] = &[
        0x1b, 0x3e, 0x00, 0xf8, 0x87, 0xc0, 0x6e, 0xbf, 0x6d, 0xe4, 0x2c, 0x29, 0x4d, 0xe5, 0x0e,
        0x4c, 0xe4, 0xc0, 0xbd, 0xd0, 0x73, 0xff, 0xf6, 0x06, 0xc0, 0x01, 0x85, 0x3c, 0xf2, 0x1a,
        0xbd, 0xce, 0x7f, 0xbd, 0xdf, 0x3d, 0x73, 0x80, 0x1c, 0x09, 0x0a, 0x04, 0x9c, 0x29, 0x11,
        0x89, 0x0c, 0x51, 0x50,
    ];
    const FROZEN_ZSTD: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x3f, 0xdd, 0x01, 0x00, 0xd4, 0x02, 0x04, 0x00, 0x00, 0x00,
        0x04, 0x48, 0x65, 0x72, 0x6f, 0x04, 0x4e, 0x6f, 0x6e, 0x65, 0x06, 0x48, 0x65, 0x61, 0x6c,
        0x74, 0x68, 0x05, 0x53, 0x70, 0x65, 0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x01, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x03, 0x04, 0x00, 0x28, 0x01,
        0x6a, 0xc6, 0xac, 0x04, 0x90, 0x01, 0x3c, 0x01,
    ];

    #[test]
    fn a_refused_output_buffer_is_an_allocation_fault() {
        assert!(matches!(
            reserve_decompressed(usize::MAX),
            Err(crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::AllocationFailed {
                    context: MappingsAllocationContext::DecompressedDataBytes,
                    requested: usize::MAX,
                    ..
                },
            })
        ));
    }

    #[test]
    fn a_zstd_context_libzstd_could_not_create_is_a_typed_fault() {
        assert!(matches!(
            zstd_context(None).err(),
            Some(crate::PaksmithError::MappingsParse {
                fault: crate::error::MappingsParseFault::ZstdContextUnavailable,
            })
        ));
    }

    /// File bytes after the stored payload do not stop any method decoding
    /// it.
    #[test]
    fn bytes_past_the_payload_do_not_stop_decoding() {
        let payload = schema_payload();
        let n = payload.len();
        for (method, stored) in [
            (UsmapCompression::None, payload.as_slice()),
            (UsmapCompression::Brotli, FROZEN_BROTLI),
            (UsmapCompression::ZStandard, FROZEN_ZSTD),
        ] {
            let mut bytes = usmap_with(method, stored, n);
            bytes.extend_from_slice(b"past the payload");
            assert_matches_uncompressed(&Usmap::from_bytes(&bytes).unwrap());
        }
    }

    /// A payload that fails to decode is reported at its own end, and the
    /// file bytes after it are not read: for a cut stream they are the rest
    /// of the stream, which a decoder reading past the payload would finish.
    #[test]
    fn a_cut_payload_reports_its_own_end() {
        let payload = schema_payload();
        let n = payload.len();
        let (brotli, brotli_rest) = FROZEN_BROTLI.split_at(FROZEN_BROTLI.len() - 8);
        let (zstd, zstd_rest) = FROZEN_ZSTD.split_at(FROZEN_ZSTD.len() - 8);
        let whole_zstd = zstd_compress(&payload, false);
        for (label, method, stored, rest, declared) in [
            ("brotli", UsmapCompression::Brotli, brotli, brotli_rest, n),
            ("zstd", UsmapCompression::ZStandard, zstd, zstd_rest, n),
            // A whole zstd stream with no room for its output fails in the
            // decoder, past the frame check.
            (
                "zstd no room",
                UsmapCompression::ZStandard,
                whole_zstd.as_slice(),
                b"past the payload".as_slice(),
                n - 2,
            ),
        ] {
            let mut bytes = usmap_with(method, stored, declared);
            bytes.extend_from_slice(rest);
            assert_eq!(
                parse_fault(&bytes),
                crate::error::MappingsParseFault::Truncated {
                    offset: HEADER_LEN + stored.len()
                },
                "{label}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn assert_matches_uncompressed_rejects_a_different_schema() {
        let int_speed = crate::testing::usmap::build_hero_usmap_bytes(2);
        assert_matches_uncompressed(&Usmap::from_bytes(&int_speed).unwrap());
    }

    /// Every RFC 7932 window, including those whose first byte shares the
    /// large-window marker's low bits.
    #[test]
    fn parse_usmap_brotli_standard_windows_decode() {
        let payload = schema_payload();
        let mut first_bytes = std::collections::HashSet::new();
        for lgwin in 10..=24 {
            let stream = brotli_compress(&payload, false, lgwin);
            let _ = first_bytes.insert(stream[0]);
            let bytes = usmap_with(UsmapCompression::Brotli, &stream, payload.len());
            let usmap = Usmap::from_bytes(&bytes).unwrap_or_else(|e| panic!("lgwin={lgwin}: {e}"));
            assert_matches_uncompressed(&usmap);
        }
        assert_eq!(first_bytes.len(), 15, "each window has its own header code");
    }

    #[test]
    fn parse_usmap_brotli_large_window_rejected() {
        let payload = schema_payload();
        let stream = brotli_compress(&payload, true, 24);
        assert_eq!(
            parse_fault(&usmap_with(
                UsmapCompression::Brotli,
                &stream,
                payload.len()
            )),
            crate::error::MappingsParseFault::BrotliLargeWindowUnsupported
        );
    }

    #[test]
    fn parse_usmap_zstd_decodes_with_and_without_content_size() {
        let payload = schema_payload();
        for content_size in [false, true] {
            let stream = zstd_compress(&payload, content_size);
            let bytes = usmap_with(UsmapCompression::ZStandard, &stream, payload.len());
            let usmap = Usmap::from_bytes(&bytes)
                .unwrap_or_else(|e| panic!("content_size={content_size}: {e}"));
            assert_matches_uncompressed(&usmap);
        }
    }

    /// One byte off the declared size either way is a mismatch in every arm.
    /// Two bytes over, brotli still stops one past the declared size, while a
    /// one-shot zstd decode has no room left and fails.
    #[test]
    fn parse_usmap_decompressed_size_mismatch_rejected() {
        use crate::error::MappingsParseFault as F;
        use UsmapCompression::{Brotli, None as Stored, ZStandard};
        let payload = schema_payload();
        let n = payload.len();
        let mismatch = |declared: usize, found: usize| F::DecompressedSizeMismatch {
            expected: u32::try_from(declared).unwrap(),
            found,
        };
        let brotli = brotli_compress(&payload, false, 22);
        let mut cases = vec![
            ("none", Stored, payload.clone(), n + 1, mismatch(n + 1, n)),
            ("none", Stored, payload.clone(), n - 1, mismatch(n - 1, n)),
            ("brotli", Brotli, brotli.clone(), n + 1, mismatch(n + 1, n)),
            ("brotli", Brotli, brotli.clone(), n - 1, mismatch(n - 1, n)),
            ("brotli", Brotli, brotli, n - 2, mismatch(n - 2, n - 1)),
        ];
        for (label, stream) in [
            ("zstd", zstd_compress(&payload, false)),
            ("zstd+size", zstd_compress(&payload, true)),
        ] {
            let no_room = F::Truncated {
                offset: HEADER_LEN + stream.len(),
            };
            cases.push((label, ZStandard, stream.clone(), n + 1, mismatch(n + 1, n)));
            cases.push((label, ZStandard, stream.clone(), n - 1, mismatch(n - 1, n)));
            cases.push((label, ZStandard, stream, n - 2, no_room));
        }
        for (label, method, stream, declared, expected) in cases {
            let fault = parse_fault(&usmap_with(method, &stream, declared));
            assert_eq!(fault, expected, "{label} declared={declared}");
        }
    }

    /// Only zstd v1 and skippable frames reach the decoder: a pre-v1 frame is
    /// refused alone or after a valid one, and so is an empty payload. Each
    /// legacy frame is first shown to decode, so the refusal is the guard's.
    #[test]
    fn parse_usmap_zstd_rejects_legacy_frames_and_empty_payloads() {
        let payload = schema_payload();
        let n = payload.len();
        let v02 = zstd_legacy_frame(0xFD2F_B522, &[], &payload);
        let v04 = zstd_legacy_frame(0xFD2F_B524, &[0], &payload);
        for frame in [&v02, &v04] {
            assert_eq!(zstd::bulk::decompress(frame, n).unwrap(), payload);
        }
        let mut v1_then_legacy = zstd_compress(&payload, true);
        v1_then_legacy.extend_from_slice(&v02);
        for (label, stored, declared) in [
            ("v0.2", v02.clone(), n),
            ("v0.4", v04, n),
            ("v1 then v0.2", v1_then_legacy, 2 * n),
            ("empty", Vec::new(), n),
            ("empty, declared empty", Vec::new(), 0),
        ] {
            assert_eq!(
                parse_fault(&usmap_with(UsmapCompression::ZStandard, &stored, declared)),
                crate::error::MappingsParseFault::Truncated {
                    offset: HEADER_LEN + stored.len()
                },
                "{label}"
            );
        }
    }

    /// Bytes that are no stream at all are refused by both codecs.
    #[test]
    fn parse_usmap_garbage_payloads_rejected() {
        let n = schema_payload().len();
        let garbage = b"not a compressed stream".to_vec();
        for (label, method) in [
            ("brotli", UsmapCompression::Brotli),
            ("zstd", UsmapCompression::ZStandard),
        ] {
            assert_eq!(
                parse_fault(&usmap_with(method, &garbage, n)),
                crate::error::MappingsParseFault::Truncated {
                    offset: HEADER_LEN + garbage.len()
                },
                "{label}"
            );
        }
    }

    /// A header cut anywhere is truncated at the start of the field that
    /// ran out; a cut anywhere in the custom-version array, at the array's
    /// start. Each layout lists where its header fields start, then the
    /// payload's.
    #[test]
    fn every_cut_of_the_header_is_truncated_at_its_field() {
        // has_versioning = 1, two object versions, two custom versions, net_cl
        let versioning = [
            &1i32.to_le_bytes()[..],
            &[0; 8],
            &2u32.to_le_bytes(),
            &[0; 40],
            &[0; 4],
        ]
        .concat();
        for (label, bytes, fields) in [
            // magic, version, compression, two sizes
            ("v0", minimal_usmap_none(), &[0, 2, 3, 4, 8, 12][..]),
            // magic, version, has_versioning = 0, compression, two sizes
            (
                "unversioned v1",
                v1_usmap(&0i32.to_le_bytes()),
                &[0, 2, 3, 7, 8, 12, 16][..],
            ),
            // magic, version, the versioning block's six fields, compression,
            // two sizes
            (
                "versioned",
                v1_usmap(&versioning),
                &[0, 2, 3, 7, 11, 15, 19, 59, 63, 64, 68, 72][..],
            ),
        ] {
            assert_matches_uncompressed(&Usmap::from_bytes(&bytes).unwrap());
            let header_len = fields[fields.len() - 1];
            for cut in 0..header_len {
                let field = fields.iter().rev().find(|&&start| start <= cut).unwrap();
                assert_eq!(
                    parse_fault(&bytes[..cut]),
                    crate::error::MappingsParseFault::Truncated { offset: *field },
                    "{label} cut {cut}"
                );
            }
        }
    }

    /// Every cut of schema data that parses whole is a truncation, reported
    /// no later than the cut. The three blocks reach every read in the
    /// schema parser: v0 and v4 name lengths, enum value counts and values,
    /// and an enum-typed property.
    #[test]
    fn every_cut_of_the_schema_data_is_truncated() {
        let enum_speed = crate::testing::usmap::build_hero_usmap_with_enum_speed(
            "Difficulty",
            &["Easy", "Normal"],
        );
        for (label, version, data) in [
            ("minimal v0", 0, schema_payload()),
            ("enum speed v0", 0, enum_speed[HEADER_LEN..].to_vec()),
            ("minimal v4", 4, v4_schema_data()),
        ] {
            assert!(
                Usmap::parse_schema_data(&data, version, SchemaBudgets::DEFAULT).is_ok(),
                "{label}"
            );
            for cut in 0..data.len() {
                match schema_fault(&data[..cut], version, SchemaBudgets::DEFAULT) {
                    crate::error::MappingsParseFault::Truncated { offset } => {
                        assert!(offset <= cut, "{label} cut {cut}: offset {offset}");
                    }
                    other => panic!("{label} cut {cut}: {other:?}"),
                }
            }
        }
    }

    /// A short schema read is reported where the read began: the name
    /// count, the first name's bytes, and the last property's type byte.
    /// Through `from_bytes`, the offset is into the schema data, not the
    /// file.
    #[test]
    fn a_short_schema_read_reports_where_it_began() {
        let data = schema_payload();
        let last = data.len() - 1;
        for (cut, offset) in [(2, 0), (7, 5), (last, last)] {
            assert_eq!(
                schema_fault(&data[..cut], 0, SchemaBudgets::DEFAULT),
                crate::error::MappingsParseFault::Truncated { offset },
                "cut {cut}"
            );
        }
        assert_eq!(
            parse_fault(&usmap_with(UsmapCompression::None, &data[..7], 7)),
            crate::error::MappingsParseFault::Truncated { offset: 5 }
        );
    }

    /// A header claiming more stored bytes than the file holds is refused at
    /// the payload's start.
    #[test]
    fn parse_usmap_compressed_size_past_the_end_rejected() {
        let payload = schema_payload();
        let cap = usize::try_from(MAX_USMAP_COMPRESSED_SIZE).unwrap();
        for claimed in [payload.len() + 1, cap] {
            let mut bytes = usmap_with(UsmapCompression::None, &payload, payload.len());
            bytes[4..8].copy_from_slice(&u32::try_from(claimed).unwrap().to_le_bytes());
            assert_eq!(
                parse_fault(&bytes),
                crate::error::MappingsParseFault::Truncated { offset: HEADER_LEN },
                "claimed={claimed}"
            );
        }
    }

    #[test]
    fn parse_usmap_zstd_skips_skippable_frames() {
        let payload = schema_payload();
        let mut stored = Vec::new();
        for magic in [0x184D_2A50u32, 0x184D_2A5F] {
            stored.extend_from_slice(&magic.to_le_bytes());
            stored.extend_from_slice(&4u32.to_le_bytes());
            stored.extend_from_slice(b"skip");
        }
        stored.extend_from_slice(&zstd_compress(&payload, true));
        let bytes = usmap_with(UsmapCompression::ZStandard, &stored, payload.len());
        assert_matches_uncompressed(&Usmap::from_bytes(&bytes).unwrap());
    }

    /// Every reference to one name-table entry shares that entry's single
    /// allocation: enum names and values, property names, and struct and
    /// enum type names.
    #[test]
    fn name_references_share_one_allocation() {
        let mut data: Vec<u8> = Vec::new();
        // Names: "E"(0), "V"(1), "Hero"(2), "None"(3), "p"(4).
        data.extend_from_slice(&5u32.to_le_bytes());
        for name in ["E", "V", "Hero", "None", "p"] {
            data.push(u8::try_from(name.len()).unwrap());
            data.extend_from_slice(name.as_bytes());
        }
        // One enum, "E", whose two positional values are both "V".
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.push(2);
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        // One schema, "Hero", with two rows both named "p": a struct typed
        // "V" and an enum typed "E".
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2i32.to_le_bytes());
        data.extend_from_slice(&3i32.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        for (schema_index, type_bytes, type_name_idx) in
            [(0u16, &[9u8][..], 1i32), (1, &[26, 0][..], 0)]
        {
            data.extend_from_slice(&schema_index.to_le_bytes());
            data.push(1);
            data.extend_from_slice(&4i32.to_le_bytes());
            data.extend_from_slice(type_bytes);
            data.extend_from_slice(&type_name_idx.to_le_bytes());
        }

        let usmap =
            Usmap::from_bytes(&usmap_with(UsmapCompression::None, &data, data.len())).unwrap();
        let (enum_key, values) = usmap.enums.get_key_value("E").unwrap();
        let props = &usmap.schemas["Hero"].properties;
        let MappedPropertyType::Struct { struct_name } = &props[0].prop_type else {
            panic!("{:?}", props[0].prop_type);
        };
        let MappedPropertyType::Enum { enum_name } = &props[1].prop_type else {
            panic!("{:?}", props[1].prop_type);
        };
        assert!(Arc::ptr_eq(&values[&0], &values[&1]), "enum values");
        assert!(Arc::ptr_eq(&values[&0], struct_name), "struct type name");
        assert!(Arc::ptr_eq(enum_key, enum_name), "enum type name");
        assert!(
            Arc::ptr_eq(&props[0].name, &props[1].name),
            "property names"
        );
    }

    fn push_names(data: &mut Vec<u8>, names: &[&str]) {
        data.extend_from_slice(&u32::try_from(names.len()).unwrap().to_le_bytes());
        for name in names {
            data.push(u8::try_from(name.len()).unwrap());
            data.extend_from_slice(name.as_bytes());
        }
    }

    /// One schema, name 0 over super 1, whose rows are all property 2 of
    /// `row_type`, one row per entry of `array_sizes`.
    fn push_repeated_schema(data: &mut Vec<u8>, array_sizes: &[u8], row_type: &[u8]) {
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1i32.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes()); // prop_count
        data.extend_from_slice(&u16::try_from(array_sizes.len()).unwrap().to_le_bytes());
        for &array_size in array_sizes {
            data.extend_from_slice(&0u16.to_le_bytes());
            data.push(array_size);
            data.extend_from_slice(&2i32.to_le_bytes());
            data.extend_from_slice(row_type);
        }
    }

    /// One schema whose single row, `prop`, expands into `slots` slots of
    /// Map<Array<Int>, Set<Float>>: five type nodes.
    fn push_map_row_schema(data: &mut Vec<u8>, class: i32, super_class: i32, prop: i32, slots: u8) {
        data.extend_from_slice(&class.to_le_bytes());
        data.extend_from_slice(&super_class.to_le_bytes());
        data.extend_from_slice(&u16::from(slots).to_le_bytes()); // prop_count
        data.extend_from_slice(&1u16.to_le_bytes()); // serial_count
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(slots);
        data.extend_from_slice(&prop.to_le_bytes());
        data.extend_from_slice(&[24, 8, 2, 25, 3]);
    }

    /// The slots a row expands into, and the flattened cache's copies of
    /// them, share one type tree.
    #[test]
    fn expanded_slots_and_the_cache_share_one_type_tree() {
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["Hero", "None", "m"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&1u32.to_le_bytes()); // one schema
        push_map_row_schema(&mut data, 0, 1, 2, 3);

        let usmap =
            Usmap::from_bytes(&usmap_with(UsmapCompression::None, &data, data.len())).unwrap();
        let halves_of = |prop_type: &MappedPropertyType| match prop_type {
            MappedPropertyType::Map { key, value } => (Arc::clone(key), Arc::clone(value)),
            other => panic!("{other:?}"),
        };
        let slots = &usmap.schemas["Hero"].properties;
        let cached = usmap.get_all_properties("Hero");
        assert_eq!((slots.len(), cached.len()), (3, 3));
        let (key, value) = halves_of(&slots[0].prop_type);
        for prop_type in slots
            .iter()
            .map(|p| &p.prop_type)
            .chain(cached.iter().map(|r| &r.property.prop_type))
        {
            let (k, v) = halves_of(prop_type);
            assert!(Arc::ptr_eq(&key, &k) && Arc::ptr_eq(&value, &v));
        }
    }

    /// Expanded properties are counted across every schema, and a file past
    /// the budget is refused while the walk is still reading it: the third
    /// schema would take a later check to six.
    #[test]
    fn schema_walk_refuses_expanded_properties_past_the_file_budget() {
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["A", "B", "C", "None", "x"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&3u32.to_le_bytes()); // three schemas
        for class_name in [0i32, 1, 2] {
            data.extend_from_slice(&class_name.to_le_bytes());
            data.extend_from_slice(&3i32.to_le_bytes());
            data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
            data.extend_from_slice(&1u16.to_le_bytes()); // serial_count
            // One row, `x`: two Int slots.
            data.extend_from_slice(&0u16.to_le_bytes());
            data.push(2);
            data.extend_from_slice(&4i32.to_le_bytes());
            data.push(2);
        }
        let budgets = |expanded_properties| SchemaBudgets {
            expanded_properties,
            type_nodes: u64::MAX,
        };

        assert!(Usmap::parse_schema_data(&data, 0, budgets(6)).is_ok());
        assert_eq!(
            schema_fault(&data, 0, budgets(3)),
            crate::error::MappingsParseFault::ExpandedPropertiesTotalExceeded {
                requested: 4,
                limit: 3
            }
        );
    }

    /// A row's slots are charged as soon as its `array_size` is read, so a
    /// row past the budget is refused before its name or type is.
    #[test]
    fn a_rows_slots_are_charged_before_its_type_is_read() {
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["A", "B", "None", "x"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&2u32.to_le_bytes()); // two schemas
        for (class, prop) in [(0i32, 3i32), (1, 99)] {
            data.extend_from_slice(&class.to_le_bytes());
            data.extend_from_slice(&2i32.to_le_bytes());
            data.extend_from_slice(&2u16.to_le_bytes()); // prop_count
            data.extend_from_slice(&1u16.to_le_bytes()); // serial_count
            data.extend_from_slice(&0u16.to_le_bytes());
            data.push(2);
            data.extend_from_slice(&prop.to_le_bytes());
            data.push(2);
        }
        let budgets = SchemaBudgets {
            expanded_properties: 3,
            type_nodes: u64::MAX,
        };

        assert_eq!(
            schema_fault(&data, 0, budgets),
            crate::error::MappingsParseFault::ExpandedPropertiesTotalExceeded {
                requested: 4,
                limit: 3
            }
        );
    }

    /// Type-tree nodes are summed across the file and refused as soon as the
    /// total passes the budget: two five-node schemas, where a per-schema
    /// count never reaches eight and a check after the walk would say ten.
    #[test]
    fn schema_walk_refuses_type_nodes_past_the_file_budget() {
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["A", "B", "None", "m"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&2u32.to_le_bytes()); // two schemas
        for class in [0, 1] {
            push_map_row_schema(&mut data, class, 2, 3, 1);
        }
        let budgets = |type_nodes| SchemaBudgets {
            expanded_properties: u64::MAX,
            type_nodes,
        };

        assert!(Usmap::parse_schema_data(&data, 0, budgets(10)).is_ok());
        assert_eq!(
            schema_fault(&data, 0, budgets(7)),
            crate::error::MappingsParseFault::TypeNodesExceeded {
                requested: 8,
                limit: 7
            }
        );
    }

    /// `from_bytes` applies the flattened-cache cap to the whole file. The
    /// schemas share one name, so each overwrites the last and the walk
    /// holds at most two of them at once.
    #[test]
    fn from_bytes_caps_expanded_properties_across_repeated_schemas() {
        let per_schema = usize::try_from(max_usmap_expanded_properties_per_schema()).unwrap();
        let full_schemas = MAX_USMAP_FLATTENED_TOTAL_ENTRIES / u64::try_from(per_schema).unwrap();
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["S", "None", "x"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(&u32::try_from(full_schemas + 1).unwrap().to_le_bytes());
        let mut full = vec![255u8; per_schema / 255];
        full.push(u8::try_from(per_schema % 255).unwrap());
        for _ in 0..full_schemas {
            push_repeated_schema(&mut data, &full, &[2]);
        }
        push_repeated_schema(&mut data, &[1], &[2]);

        assert_eq!(
            parse_fault(&usmap_with(UsmapCompression::None, &data, data.len())),
            crate::error::MappingsParseFault::ExpandedPropertiesTotalExceeded {
                requested: MAX_USMAP_FLATTENED_TOTAL_ENTRIES + 1,
                limit: MAX_USMAP_FLATTENED_TOTAL_ENTRIES
            }
        );
    }

    /// `from_bytes` applies the type-node cap to the whole file. Every row
    /// has no slots, so its tree is dropped as soon as it is read and the
    /// walk holds at most one.
    #[test]
    fn from_bytes_caps_type_nodes_across_the_file() {
        // An Array nested to the depth limit around an Int.
        let mut row_type = vec![8u8; MAX_USMAP_ARRAY_NESTING_DEPTH];
        row_type.push(2);
        let rows = MAX_USMAP_TYPE_NODES / u64::try_from(row_type.len()).unwrap() + 1;
        let per_schema = u64::from(u16::MAX);
        let mut data: Vec<u8> = Vec::new();
        push_names(&mut data, &["S", "None", "x"]);
        data.extend_from_slice(&0u32.to_le_bytes()); // no enums
        data.extend_from_slice(
            &u32::try_from(rows.div_ceil(per_schema))
                .unwrap()
                .to_le_bytes(),
        );
        let mut left = rows;
        while left > 0 {
            let serial_count = left.min(per_schema);
            let no_slots = vec![0u8; usize::try_from(serial_count).unwrap()];
            push_repeated_schema(&mut data, &no_slots, &row_type);
            left -= serial_count;
        }

        assert_eq!(
            parse_fault(&usmap_with(UsmapCompression::None, &data, data.len())),
            crate::error::MappingsParseFault::TypeNodesExceeded {
                requested: MAX_USMAP_TYPE_NODES + 1,
                limit: MAX_USMAP_TYPE_NODES
            }
        );
    }

    #[test]
    fn max_usmap_type_nodes_accessor_returns_expected_value() {
        assert_eq!(max_usmap_type_nodes(), 4_194_304);
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
        // A directory path fails the ADVISORY pre-open `is_file()`
        // check and surfaces as Io with `InvalidInput` kind, on every
        // platform (Windows can't even open a directory — the pre-check
        // keeps the error shape uniform). The same pre-open rejection
        // covers FIFOs / sockets / devices where they exist — critical
        // for FIFOs, whose `open` would block before any post-open
        // check could fire.
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
