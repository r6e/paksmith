//! Core library for parsing and extracting Unreal Engine game assets.
//!
//! **Containers**: a reader for the `.pak` archive format (see
//! [`container::pak`]). IoStore (`.utoc`/`.ucas`) is reserved but not
//! yet implemented (Phase 8).
//!
//! **UAsset parsing**: the structural header
//! ([`asset::PackageSummary`] (`FPackageFileSummary`),
//! [`asset::NameTable`], [`asset::ImportTable`], [`asset::ExportTable`])
//! plus a full property system — `FPropertyTag` streams decode into
//! [`asset::PropertyBag::Tree`] with typed primitives (Bool, Int
//! variants, Float, Double, Str, Name, Enum, Text), containers
//! (Array/Map/Set/Struct), object references, and unversioned /
//! `.usmap` schema-driven properties. `.uexp` companion bodies are
//! stitched at parse time. Parse errors mid-iteration fall back to
//! [`asset::PropertyBag::Opaque`] with a `tracing::warn!` event.
//!
//! **Typed engine structs** (Phase 3c): a `StructProperty` whose wire
//! name is one of the registered decoders (`Vector`, `Vector2D`,
//! `Vector4`, `Rotator`, `Quat`, `Color`, `LinearColor`, `Box`,
//! `Box2D`) decodes to [`PropertyValue::TypedStruct`] carrying a typed
//! [`asset::structs::TypedStructValue`], instead of the empty tagged
//! `PropertyValue::Struct`. **This changes the inspect-JSON shape for
//! such properties** (`{"Struct": …}` → `{"TypedStruct": {"type":
//! "Vector", …}}`). `FTransform` and `FBoxSphereBounds` are tagged-
//! serialized under their bare wire names, so they are NOT registered;
//! their binary layouts ship as direct building blocks
//! ([`asset::structs::transform::FTransform::read_from`] /
//! [`asset::structs::bounds::FBoxSphereBounds::read_from`]) for the
//! native-serialized-array contexts (mesh bone poses / bounds).
//!
//! **Export pipeline** (Phase 3): typed export readers plus the
//! [`export`] module's `FormatHandler` impls turn parsed assets into
//! PNG (texture), glTF (static + skeletal mesh), WAV/OGG (audio), and
//! CSV/JSON (data table), fed by `FByteBulkData` resolution. Game
//! profile management remains planned (Phase 5) per
//! `docs/plans/ROADMAP.md`.

pub mod asset;
pub mod container;
pub mod digest;
pub mod error;
pub mod export;
pub mod profile;

mod seams;

/// Test-utility surface shared between in-source tests and the
/// integration suite under `tests/`. Gated behind the
/// `__test_utils` feature so production builds never compile or
/// expose it. Issue #68 promoted the v10+ fixture builder out of
/// the in-source test module so the integration proptest doesn't
/// need to duplicate ~30 lines of wire-format assembly.
#[cfg(feature = "__test_utils")]
pub mod testing;

// `AesKey` is a cross-cutting credential type (used by `PakReader::open_with_key`
// today; Phase 5 will extend it to IoStore). Promoted to the crate root so callers
// write `paksmith_core::AesKey`. `PakReader` is intentionally NOT promoted — it is a
// format-specific type and lives at `container::pak::PakReader`.
pub use container::pak::{AesKey, AesKeyHexError};
pub use digest::Sha1Digest;
pub use error::PaksmithError;

/// Convenience alias for `Result<T, PaksmithError>`.
pub type Result<T> = std::result::Result<T, PaksmithError>;

// Top-level public-API re-exports so consumers can write
// `use paksmith_core::{Package, Asset, PropertyBag, PropertyValue, Usmap};`
// instead of reaching into `asset::*` and `asset::property::*`. Mirrors
// the convention established for [`Sha1Digest`] and [`PaksmithError`].
//
// **One-way serialization note:** [`Package`] and [`Asset`] implement
// `Serialize` only — their JSON output is intentionally lossy
// (view-based FName resolution + byte-count `Opaque`). Most other
// serializable types re-exported below also implement `Deserialize`
// with caveats documented on the type itself (e.g.,
// [`EngineVersion`] drops the licensee bit; [`PropertyBag::Opaque`]
// reconstructs zero-filled bytes from the count). [`AssetContext`]
// and [`PackageIndexError`] are runtime-only (no serde at all).
// See each type's docs for the round-trip contract.
//
// **`#[non_exhaustive]` + `Deserialize` caveat:** `#[non_exhaustive]`
// types ([`PropertyBag`], [`PropertyValue`], `FTextHistory`) DO permit
// future variants without a source-breaking match, but adding a new
// variant IS a JSON wire-compatibility break for `Deserialize`
// consumers — serde rejects unknown tag discriminants by default.
// Pin against specific paksmith versions if you rely on bidirectional
// JSON round-trips of stored content.
pub use asset::property::text::{FText, FTextHistory};
pub use asset::property::{MapEntry, Property, PropertyValue};
pub use asset::structs::TypedStructValue;
pub use asset::{
    Asset, AssetContext, AssetVersion, CustomVersion, CustomVersionContainer, EngineVersion,
    ExportTable, FGuid, FName, ImportTable, NameTable, ObjectExport, ObjectImport, Package,
    PackageIndex, PackageIndexError, PackageSummary, PropertyBag, Usmap,
};

// Phase 3 export-pipeline public API. Consumers building format
// handlers, registering custom handlers, or iterating typed Asset
// variants reach these symbols from the crate root rather than
// reaching into `paksmith_core::export::*`. `BulkData` was held back
// from the 3a re-export set while its shape (unit-struct stub →
// fields-bearing) was in flux; 3b Task 4 finalized the shape and
// this PR promotes it to the crate root.
pub use export::{BulkData, FormatHandler, GenericHandler, HandlerRegistry};

// Phase 5b: game-profile public API. `GameProfile`, `KeyGuid`, and
// `ProfileStore` are the load-bearing types that consumers need to manage
// encryption keys and resolve pak-GUID → AesKey lookups. `resolve_key` is
// the pure resolution function; disk I/O (Task 3) and key-testing (Task 4)
// land in the `profile::store` and `profile::key_test` sub-modules.
pub use profile::{GameProfile, KeyGuid, KeyGuidHexError, ProfileStore, resolve_key};

/// Compile-time `Send + Sync` assertions on the public-API type
/// surface.
///
/// `assert_send_sync::<T>()` has an empty body; the bounds check
/// happens at compile time when each call is monomorphized. Any
/// future PR that introduces an `Rc`, `RefCell`, or other `!Send` /
/// `!Sync` field deep inside any listed type fails this test at
/// `cargo build --tests`, surfacing the regression before it lands
/// in a downstream consumer's build.
///
/// Issue #387 motivated the guard — a thread-safety audit verified
/// every public type was `Send + Sync` by structural inspection but
/// found no automated check protecting that invariant as the type
/// hierarchy grew. Adding `Usmap::flattened_cache` (issue #370) or
/// future Phase 3+ types would otherwise risk a silent regression.
#[cfg(test)]
mod send_sync_assertions {
    use super::*;
    use crate::asset::bulk_data::{BulkDataResolver, FByteBulkData};
    use crate::asset::mappings::{
        ClassSchema, MappedProperty, MappedPropertyType, ResolvedProperty,
    };
    use crate::container::pak::footer::PakFooter;
    use crate::container::pak::index::{PakIndex, PakIndexEntry};
    use crate::container::pak::version::PakVersion;
    use crate::container::pak::{AesKey, PakReader, RegionVerifyState, VerifyOutcome, VerifyStats};
    use crate::container::{ContainerFormat, EntryFlags, EntryMetadata};
    use crate::error::{
        AssetParseFault, CompanionFileKind, DecompressionFault, IndexParseFault,
        InvalidFooterFault, MappingsAllocationContext, MappingsParseFault,
    };
    use crate::export::{
        BulkData, DataTableCsvHandler, DataTableJsonHandler, GenericHandler, HandlerRegistry,
        OggHandler, PngHandler, RawSoundHandler, VorbisHandler, WavHandler,
    };

    // Empty-body bounds check; the assertion happens at
    // monomorphization. Plain `fn` (not `const fn`) — there is no
    // `const`-context caller and the `const` keyword would only
    // suggest some compile-time evaluation that doesn't exist.
    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn public_types_are_send_sync() {
        // Container surface
        assert_send_sync::<PakReader>();
        // Direct fields of `PakReader` (`PakFooter`, `PakVersion`,
        // `PakIndex` + its `PakIndexEntry` rows, `AesKey`) are
        // transitively covered today, but explicit assertions lockpin
        // them against a future refactor that converts a field to a
        // `OnceCell`-style lazy wrapper — which would silently
        // remove the inner type from the transitive `Send + Sync`
        // graph.
        assert_send_sync::<AesKey>();
        assert_send_sync::<PakFooter>();
        assert_send_sync::<PakVersion>();
        assert_send_sync::<PakIndex>();
        assert_send_sync::<PakIndexEntry>();
        // Container-trait return types — NOT stored on `PakReader`,
        // so transitive coverage doesn't apply. Explicit assertions
        // close the gap. `EntryFlags` is consumed by
        // `EntryMetadata::new` (not stored on `EntryMetadata`), so
        // it gets its own pin rather than relying on transitivity.
        assert_send_sync::<ContainerFormat>();
        assert_send_sync::<EntryMetadata>();
        assert_send_sync::<EntryFlags>();
        // `PakReader::verify_*` return types — also NOT stored on
        // `PakReader`. Lockpinned explicitly.
        assert_send_sync::<VerifyOutcome>();
        assert_send_sync::<VerifyStats>();
        assert_send_sync::<RegionVerifyState>();

        // Asset top-level
        assert_send_sync::<Asset>();
        assert_send_sync::<crate::asset::DataTableData>();
        assert_send_sync::<crate::asset::DataTableRow>();
        assert_send_sync::<crate::asset::Texture2DData>();
        assert_send_sync::<crate::asset::Texture2DMipMap>();
        assert_send_sync::<crate::asset::SoundWaveData>();
        assert_send_sync::<crate::asset::StreamedAudioData>();
        assert_send_sync::<crate::asset::StreamedAudioChunk>();
        assert_send_sync::<crate::asset::StaticMeshData>();
        assert_send_sync::<AssetContext>();
        assert_send_sync::<Package>();
        assert_send_sync::<PackageSummary>();
        assert_send_sync::<AssetVersion>();
        assert_send_sync::<EngineVersion>();

        // Name / index / GUID
        assert_send_sync::<FName>();
        assert_send_sync::<FGuid>();
        assert_send_sync::<NameTable>();
        assert_send_sync::<PackageIndex>();
        assert_send_sync::<PackageIndexError>();

        // Tables
        assert_send_sync::<ImportTable>();
        assert_send_sync::<ObjectImport>();
        assert_send_sync::<ExportTable>();
        assert_send_sync::<ObjectExport>();
        assert_send_sync::<CustomVersion>();
        assert_send_sync::<CustomVersionContainer>();

        // Properties
        assert_send_sync::<PropertyBag>();
        assert_send_sync::<Property>();
        assert_send_sync::<PropertyValue>();
        assert_send_sync::<MapEntry>();
        assert_send_sync::<FText>();
        assert_send_sync::<FTextHistory>();

        // Mappings (.usmap)
        assert_send_sync::<Usmap>();
        assert_send_sync::<ClassSchema>();
        assert_send_sync::<MappedProperty>();
        assert_send_sync::<MappedPropertyType>();
        assert_send_sync::<ResolvedProperty>();

        // Digest / errors
        assert_send_sync::<Sha1Digest>();
        assert_send_sync::<PaksmithError>();
        assert_send_sync::<InvalidFooterFault>();
        assert_send_sync::<DecompressionFault>();
        assert_send_sync::<IndexParseFault>();
        assert_send_sync::<AssetParseFault>();
        assert_send_sync::<MappingsParseFault>();
        assert_send_sync::<MappingsAllocationContext>();
        assert_send_sync::<CompanionFileKind>();

        // Phase 3 export pipeline. These types must all be Send + Sync —
        // HandlerRegistry holds Box<dyn FormatHandler + Send + Sync>;
        // GenericHandler / DataTableJsonHandler / PngHandler / OggHandler /
        // VorbisHandler / WavHandler are concrete handlers (3f-3h add more
        // typed siblings); BulkData + FByteBulkData
        // (fields-bearing as of 3b Tasks 3 + 4) are consumed by
        // FormatHandler::export and the typed-reader dispatch path,
        // which are callable across thread boundaries in Phase 5 async
        // + Phase 7 GUI. VorbisHandler holds no state but its export path
        // constructs a symphonia decoder per call — assert the type stays
        // thread-shareable.
        assert_send_sync::<HandlerRegistry>();
        assert_send_sync::<GenericHandler>();
        assert_send_sync::<DataTableJsonHandler>();
        assert_send_sync::<DataTableCsvHandler>();
        assert_send_sync::<PngHandler>();
        assert_send_sync::<OggHandler>();
        assert_send_sync::<VorbisHandler>();
        assert_send_sync::<WavHandler>();
        assert_send_sync::<RawSoundHandler>();
        assert_send_sync::<BulkData>();
        assert_send_sync::<FByteBulkData>();
        // BulkDataResolver carries Arc<[u8]>, AtomicU64, OnceLock<Vec<u8>>,
        // and Box<dyn Fn() -> Result + Send + Sync + 'static>. Send + Sync
        // required for Phase 5 (async runtime) and Phase 7 (GUI Iced
        // commands moving `Package` across thread boundaries).
        assert_send_sync::<BulkDataResolver>();

        // Phase 5b profile types. All three carry only owned heap data
        // (BTreeMap, String, [u8; N]) — no Rc/RefCell — so Send + Sync is
        // expected; pin them explicitly so a future field change surfaces here.
        assert_send_sync::<GameProfile>();
        assert_send_sync::<KeyGuid>();
        assert_send_sync::<ProfileStore>();
    }
}
