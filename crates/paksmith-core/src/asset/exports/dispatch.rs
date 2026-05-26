//! Class-name → typed-reader-fn dispatch.
//!
//! Phase 3a Task 4 ships an empty table — every export's class name
//! falls through to the existing Phase 2 generic property-bag
//! iteration. Phase 3d-3h add the five known classes by extending
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

// cargo-mutants: see `.cargo/mutants.toml` (`class_dispatch_init`
// entry) — remove that entry once Phase 3d populates the table.
fn class_dispatch_init() -> HashMap<&'static str, TypedReaderFn> {
    let table: HashMap<&'static str, TypedReaderFn> = HashMap::new();

    // Phase 3a Task 4 ships empty. Each later sub-phase inserts
    // one entry:
    //
    //   3d: table.insert("DataTable", crate::asset::exports::data_table::read_typed);
    //   3d: table.insert("CompositeDataTable", crate::asset::exports::data_table::read_typed);
    //   3e: table.insert("Texture2D", crate::asset::exports::texture::texture2d::read_typed);
    //   3f: table.insert("SoundWave", crate::asset::exports::audio::sound_wave::read_typed);
    //   3g: table.insert("StaticMesh", crate::asset::exports::mesh::static_mesh::read_typed);
    //   3h: table.insert("SkeletalMesh", crate::asset::exports::mesh::skeletal_mesh::read_typed);
    //
    // Each `read_typed` function constructs the typed Asset variant
    // (e.g. `Ok((Asset::DataTable(data), records))`) and returns it
    // directly.

    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_dispatch_returns_empty_table() {
        // Phase 3a ships with no typed readers registered. 3d-3h
        // add entries; the test count should match.
        assert!(class_dispatch().is_empty());
    }

    #[test]
    fn dispatch_table_lookup_misses_for_unknown_class() {
        // Every class name should miss the empty table. Pinned so
        // that 3d/3e/3f/3g/3h's table-population PRs visibly change
        // this assertion's expected entries.
        assert!(class_dispatch().get("DataTable").is_none());
        assert!(class_dispatch().get("Texture2D").is_none());
        assert!(class_dispatch().get("SoundWave").is_none());
        assert!(class_dispatch().get("StaticMesh").is_none());
        assert!(class_dispatch().get("SkeletalMesh").is_none());
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
