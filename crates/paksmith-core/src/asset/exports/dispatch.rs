//! Class-name → typed-reader-fn dispatch.
//!
//! Phase 3a Task 4 ships an empty table — every export's class name
//! falls through to the existing Phase 2 generic property-bag
//! iteration. Phase 3d-3h add the known typed classes by extending
//! [`class_dispatch_init`].
//!
//! Why a function-pointer table (not an enum)? Direct
//! `&'static str → fn(...)` dispatch means each sub-phase adds one
//! entry that constructs its typed `Asset::*` variant directly —
//! no intermediate discriminator enum, no per-sub-phase match-arm
//! widening in `read_payloads`. See master plan §"Naming convention"
//! for the broader `asset/exports/` vs `export/` distinction.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::asset::bulk_data::FByteBulkData;
use crate::asset::{Asset, AssetContext};

/// Signature for a typed-export reader. Each sub-phase's reader-fn
/// takes the export's serialized payload bytes (the slice carved
/// from `bytes` by `Package::read_from`'s `carve_export_slice`
/// helper), the parsing context, and the asset path (for error
/// reporting).
///
/// Returns a tuple of the typed [`Asset`] variant for the class
/// PLUS the [`FByteBulkData`] records the reader collected during
/// parse. Most readers collect zero records (DataTable, generic
/// property bag) and return `Vec::new()`; texture / mesh / audio
/// readers populate the vec during parse so the dispatcher can
/// drive `Package::insert_bulk_records` at the boundary (Phase 3b).
///
/// **Why the tuple return?** Typed readers parse `FByteBulkData`
/// metadata records mid-parse (e.g. per-mip records in
/// `Texture2D`). Those records need to land in `Package::bulk_data`
/// so 3b's lazy resolver can materialize bytes on demand. The
/// dispatch site (`Package::read_from::read_payloads`) is the
/// natural owner of `&mut Package` and drives the
/// `insert_bulk_records` insertion. Routing records through the
/// reader's return value keeps the reader a pure function (bytes
/// in, structured data out) — it doesn't need `&mut Package` access
/// at all.
pub(crate) type TypedReaderFn = fn(
    payload: &[u8],
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Asset, Vec<FByteBulkData>)>;

/// Returns the lazily-initialized class-name dispatch table.
///
/// Keys are interned engine class names (e.g. `"Texture2D"`,
/// `"StaticMesh"`, `"DataTable"`). A class name absent from the map
/// = no typed reader registered = `read_payloads` falls through to
/// the existing Phase 2 generic property-bag path.
pub(crate) fn class_dispatch() -> &'static HashMap<&'static str, TypedReaderFn> {
    static TABLE: OnceLock<HashMap<&'static str, TypedReaderFn>> = OnceLock::new();
    TABLE.get_or_init(class_dispatch_init)
}

fn class_dispatch_init() -> HashMap<&'static str, TypedReaderFn> {
    let mut table: HashMap<&'static str, TypedReaderFn> = HashMap::new();

    // Phase 3d: UDataTable. `CompositeDataTable` shares the identical
    // on-disk wire shape for standard (non-game-specific) builds — its
    // `Deserialize` calls `base.Deserialize` with no extra pre-reads
    // (see docs/formats/data/data-table.md §UCompositeDataTable) — so
    // both class names route through the same row-parser.
    let _ = table.insert("DataTable", crate::asset::exports::data_table::read_typed);
    let _ = table.insert(
        "CompositeDataTable",
        crate::asset::exports::data_table::read_typed,
    );

    // Phase 3e: UTexture2D. 3e-1 routes the class through dispatch and
    // decodes segment 1 (tagged properties); segment 2
    // (FTexturePlatformData) lands in 3e-2+. The typed reader collects
    // no bulk-data records yet (per-mip records arrive in 3e-3).
    let _ = table.insert(
        "Texture2D",
        crate::asset::exports::texture::texture2d::read_typed,
    );

    // Phase 3f: USoundWave. 3f-1 routes the class through dispatch and
    // captures segment 1 (the USoundBase tagged-property settings); the
    // binary header (Flags + per-codec audio buffers) lands in 3f-2+. The
    // typed reader collects no bulk-data records yet.
    let _ = table.insert(
        "SoundWave",
        crate::asset::exports::audio::sound_wave::read_typed,
    );

    // Phase 3g: UStaticMesh. Parses segment 1 (tagged properties + the
    // object-GUID tail), the full `UStaticMesh.Deserialize` chain (strip flags,
    // `bCooked`, `BodySetup`, `NavCollision`, `LightingGuid`, `Sockets`), and the
    // `bCooked`-gated `FStaticMeshRenderData` geometry (per-LOD vertex / index
    // buffers) into `StaticMeshData`. The inlined geometry carries its buffers
    // in-stream, so the typed reader collects no separate bulk-data records.
    let _ = table.insert(
        "StaticMesh",
        crate::asset::exports::mesh::static_mesh::read_typed,
    );

    // Phase 3h-PR2: USkeletalMesh. Parses segment 1 (tagged properties + the
    // object-GUID tail) and the `USkeletalMesh.Deserialize` prefix (strip flags,
    // `ImportedBounds`, `SkeletalMaterials`, `FReferenceSkeleton`, `bCooked`)
    // into `SkeletalMeshData`. The per-LOD skin geometry lands in later PRs; the
    // typed reader collects no separate bulk-data records.
    let _ = table.insert(
        "SkeletalMesh",
        crate::asset::exports::mesh::skeletal_mesh::read_typed,
    );

    // Each `read_typed` constructs the typed Asset variant
    // (`Ok((Asset::DataTable(data), records))`) directly.

    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_registers_data_table_texture2d_sound_wave_and_mesh_classes() {
        // Phase 3d registered the two DataTable class names; 3e-1 added
        // Texture2D; 3f-1 added SoundWave; 3g1 added StaticMesh; 3h-PR2 adds
        // SkeletalMesh. This count grows with each table-population PR.
        assert_eq!(class_dispatch().len(), 6);
        assert!(class_dispatch().contains_key("DataTable"));
        assert!(class_dispatch().contains_key("CompositeDataTable"));
        assert!(class_dispatch().contains_key("Texture2D"));
        assert!(class_dispatch().contains_key("SoundWave"));
        assert!(class_dispatch().contains_key("StaticMesh"));
        assert!(class_dispatch().contains_key("SkeletalMesh"));
    }

    #[test]
    fn dispatch_table_lookup_routes_registered_classes_and_misses_others() {
        // The registered DataTable + Texture2D + SoundWave + StaticMesh +
        // SkeletalMesh classes route to a typed reader; an unknown class
        // misses (falling through to the generic property-bag path). Pinned so
        // 3h-PR2's commit visibly flips SkeletalMesh from miss to hit.
        assert!(class_dispatch().get("DataTable").is_some());
        assert!(class_dispatch().get("CompositeDataTable").is_some());
        assert!(class_dispatch().get("Texture2D").is_some());
        assert!(class_dispatch().get("SoundWave").is_some());
        assert!(class_dispatch().get("StaticMesh").is_some());
        assert!(class_dispatch().get("SkeletalMesh").is_some());
        assert!(class_dispatch().get("AnyUnknownClass").is_none());
    }

    #[test]
    fn class_dispatch_returns_cached_singleton() {
        // OnceLock guarantees the same &'static across calls. Pins
        // against refactors that allocate a fresh table per call
        // (e.g. `Box::leak(Box::new(HashMap::new()))`).
        let p1: *const _ = class_dispatch();
        let p2: *const _ = class_dispatch();
        assert_eq!(p1, p2);
    }

    /// Synthetic destructure-pin: the
    /// `TypedReaderFn` signature in
    /// `read_payloads`'s dispatch arm (and the parallel arm in the
    /// unversioned-properties branch) destructures the reader's
    /// return as `(Asset, Vec<FByteBulkData>)`. Phase 3a's empty
    /// dispatch table never exercises that branch, leaving the
    /// destructure logic dead until 3d lands. This test pins the
    /// signature contract independently — a regression that
    /// breaks the tuple shape (e.g. someone "simplifies"
    /// `TypedReaderFn` to return `Result<Asset>`) fails here, not
    /// only when 3d's PR lands.
    #[test]
    fn typed_reader_fn_signature_destructures_as_tuple() {
        use crate::asset::property::bag::PropertyBag;

        // Dummy reader matching the TypedReaderFn signature exactly.
        // The Result wrap is intentional — pinning the signature
        // contract is the whole point of this test, so we suppress
        // `clippy::unnecessary_wraps` (which would otherwise demand
        // we strip Result and silently break the contract being
        // asserted).
        #[allow(clippy::unnecessary_wraps)]
        fn dummy(
            payload: &[u8],
            _ctx: &AssetContext,
            _asset_path: &str,
        ) -> crate::Result<(Asset, Vec<FByteBulkData>)> {
            Ok((
                Asset::Generic(PropertyBag::opaque(payload.to_vec())),
                Vec::new(),
            ))
        }
        // Assignment to TypedReaderFn pins the fn-pointer coercion.
        let f: TypedReaderFn = dummy;

        // Construct a minimal AssetContext for the call. The
        // dummy reader ignores all fields, so empty Arc-wrapped
        // tables suffice.
        let ctx = AssetContext::new(
            std::sync::Arc::new(crate::asset::NameTable::default()),
            std::sync::Arc::new(crate::asset::ImportTable::default()),
            std::sync::Arc::new(crate::asset::ExportTable::default()),
            crate::asset::AssetVersion::default(),
            std::sync::Arc::new(crate::asset::CustomVersionContainer::default()),
            None,
        );

        let (asset, records) = f(&[1, 2, 3], &ctx, "test.uasset").unwrap();
        assert!(records.is_empty(), "dummy reader returns no bulk records");
        match asset {
            Asset::Generic(PropertyBag::Opaque { bytes }) => {
                assert_eq!(bytes, vec![1, 2, 3], "dummy reader passes payload through");
            }
            other => panic!("expected Asset::Generic(Opaque), got {other:?}"),
        }
    }
}
