//! Top-level UAsset aggregate.
//!
//! [`Package::read_from`] orchestrates the per-component parsers:
//! 1. [`PackageSummary::read_from`] from byte 0.
//! 2. [`NameTable::read_from`] seeked to `summary.name_offset`.
//! 3. [`ImportTable::read_from`] seeked to `summary.import_offset`.
//! 4. [`ExportTable::read_from`] seeked to `summary.export_offset`.
//! 5. Per-export payload bytes carved out of the buffer.
//!
//! Each export's bytes are decoded by a typed reader (Phase 3d+) when a
//! reader is registered for the export's class AND the package uses
//! versioned (tagged) properties; otherwise by the generic parser.
//! Typed dispatch is **versioned-only** — the typed readers parse the
//! tagged-property stream, so unversioned (schema-serialized) bodies
//! always take the generic path.
//!
//! Failure handling differs by path:
//! - **Versioned typed**: a malformed-body error falls through to the
//!   generic tagged-property parse (a typed reader must never leave an
//!   export worse off than the generic parse it replaces), with a
//!   `tracing::warn!`. An `AllocationFailed` instead **propagates** —
//!   that is an out-of-memory condition the caller must see, not a
//!   corrupt export (libraries fail fast).
//! - **Versioned generic**: tagged-property iteration falls back to
//!   [`PropertyBag::Opaque`](crate::asset::property::PropertyBag) on any
//!   parse error (warn-logged), so one corrupt versioned export does not
//!   abort the package.
//! - **Unversioned** (`PKG_UnversionedProperties` + `.usmap`): deserialize
//!   against the schema and **propagate** on error — an unversioned parse
//!   failure usually signals a wrong/mismatched `.usmap`, which should
//!   fail loudly rather than silently produce `Opaque` exports that hide
//!   the bad mapping.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, OnceLock};

use serde::Serialize;
use serde::ser::SerializeStruct;

use crate::asset::AssetContext;
use crate::asset::bulk_data::{
    BulkData, BulkDataResolver, FByteBulkData, MAX_BULK_DATA_RECORDS_PER_EXPORT,
    missing_companion_loader,
};
use crate::asset::export_table::{ExportTable, ObjectExport};
use crate::asset::import_table::{ImportTable, ObjectImport};
use crate::asset::mappings::Usmap;
use crate::asset::name_table::NameTable;
use crate::asset::property::PropertyBag;
use crate::asset::property::unversioned::read_unversioned_properties;
use crate::asset::summary::{PKG_UNVERSIONED_PROPERTIES, PackageSummary};
use crate::error::{
    AssetAllocationContext, AssetOverflowSite, AssetParseFault, AssetWireField, BoundsUnit,
    CompanionFileKind, PaksmithError, try_reserve_asset,
};
// `SeamSite` goes unused in the no-`__test_utils` lib-test compile
// (the seam machinery no-ops there); that build mode is exercised by
// CI's package-scoped compile guard under `-D warnings`.
#[cfg_attr(not(feature = "__test_utils"), allow(unused_imports))]
use crate::seams::{AssetSeam, SeamSite, seam_check};

/// Maximum permitted per-export payload size. Defense-in-depth against
/// crafted assets that declare overlapping or oversized export ranges:
/// a single export can encode an arbitrary `i64` `serial_size` on the
/// wire, and the per-export `try_reserve_exact` below would otherwise
/// be the only allocator gate between malicious bytes and a process-
/// wide OOM. 256 MiB is far above any cooked-game export observed in
/// practice (typical asset payloads are kilobytes; the largest cooked
/// textures are tens of megabytes) and well below the `usize::MAX`
/// allocator-domain ceiling on 32-bit targets.
pub(crate) const MAX_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Hard cap on the `.uexp` companion file size. `total_header_size`
/// already caps the `.uasset` at 256 MiB; the export-body section in
/// `.uexp` is typically smaller. 1 GiB is generous headroom; bigger
/// would already be suspicious for an UE-cooked asset.
///
/// Enforced at the stitch boundary inside [`Package::read_from`] before
/// any allocation runs, so a malicious pak entry cannot force a
/// multi-GiB combined-buffer reservation by claiming a huge `.uexp`.
pub const MAX_UEXP_SIZE: usize = 1024 * 1024 * 1024;

/// One parsed `.uasset` package: structural header + per-export
/// typed [`Asset`](super::Asset) payloads.
///
/// **Thread safety:** `Package: Send + Sync`. The result of
/// [`Self::read_from`] is an immutable parsed representation; safe
/// to share across threads (clone the `Package` or wrap in `Arc`).
/// Pinned by the `send_sync_assertions` test in `lib.rs`.
///
/// `Serialize` is hand-rolled to emit the Phase 3 deliverable JSON
/// shape — each export carries an `"asset"` field rendering the
/// typed [`Asset`](super::Asset) under its externally-tagged form
/// (`{"Generic": {"kind": "...", ...}}` for Phase 2 closure;
/// `{"DataTable": {...}}` / `{"Texture2D": {...}}` / etc. for the
/// typed variants Phase 3 sub-phases 3d-3h add). See
/// `ObjectExportView::serialize` below for the per-export rendering.
///
/// **Round-trip note:** `Deserialize` is intentionally NOT implemented.
/// The view-based `Serialize` resolves FName indices to display
/// strings (via `ObjectImportView` / `ObjectExportView`) and
/// `PropertyBag::Opaque` (inside `Asset::Generic`) emits a byte count
/// rather than payload bytes — both are one-way mappings. Consumers
/// needing wire-faithful round-trip should serialize the constituent
/// types ([`PackageSummary`], [`NameTable`], [`ImportTable`],
/// [`ExportTable`]) and each [`PropertyBag`] directly, all of which
/// DO implement `Deserialize`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Package {
    /// Virtual path of the asset within its archive (e.g.
    /// `Game/Maps/Demo.uasset`).
    pub asset_path: String,
    /// Parsed package summary.
    pub summary: PackageSummary,
    /// Parsed FName pool.
    ///
    /// `Arc`-wrapped so [`Self::context`] is a refcount bump rather
    /// than a deep clone of the (potentially 1M-entry) name pool
    /// (issue #369). Consumers reading the table via `&pkg.names`
    /// continue to work — `Arc<NameTable>` derefs to `&NameTable`.
    pub names: Arc<NameTable>,
    /// Parsed import table. `Arc`-wrapped for the same reason as
    /// [`Self::names`] (issue #369).
    pub imports: Arc<ImportTable>,
    /// Parsed export table. `Arc`-wrapped for the same reason as
    /// [`Self::names`] (issue #369).
    pub exports: Arc<ExportTable>,
    /// Per-export typed payloads — same order as `self.exports.exports`.
    /// Each entry is an [`super::Asset`] variant. Phase 2 produced
    /// `Asset::Generic(PropertyBag::Tree { .. })` or
    /// `Asset::Generic(PropertyBag::Opaque { .. })` for every export;
    /// Phase 3 sub-phases (3d-3h) add typed variants (DataTable,
    /// Texture2D, SoundWave, StaticMesh, SkeletalMesh) on this same
    /// `#[non_exhaustive]` enum. Serialized per-export via
    /// `ObjectExportView` — see the Phase 3 deliverable JSON shape
    /// (externally-tagged `Asset`).
    pub payloads: Vec<super::Asset>,
    /// Mappings supplied to [`Package::read_from`], retained so
    /// [`Package::context()`] can resurface them to Phase 3+ format
    /// handlers that drive secondary decode passes. Private because
    /// the storage shape (`Arc<Usmap>`) is an implementation detail;
    /// callers access mappings via [`Package::context()`].
    mappings: Option<Arc<Usmap>>,
    /// `FByteBulkData` records + lazy-resolved bytes per export
    /// (Phase 3b). Sparse: keys are export indices that carry bulk
    /// records. **Single map with tuple values** (NOT two parallel
    /// maps) so the records and the cache slot are always in
    /// lockstep — no "records present but cache slot missing" failure
    /// mode. Populated by typed readers (3e `Texture2D` now; 3g/3h
    /// later): `read_payloads` surfaces each export's records and
    /// `read_from_inner` drives `Package::insert_bulk_records`
    /// (pub(crate)) after construction (3e-3b).
    ///
    /// **Clone behavior** (Phase 7 GUI hand-off): cloning a `Package`
    /// after `resolve_bulk_for_export` has populated a slot
    /// deep-copies the cached `Vec<BulkData>` payload — total memory
    /// can approach `2× resolved_bytes` for heavily-cloned packages.
    /// Bounded by the per-package budget (already charged on first
    /// resolve; clone does NOT re-charge). Phase 7 may want
    /// `OnceLock<Arc<Vec<BulkData>>>` to share resolved bytes across
    /// clones — not a Phase 3b change because Phase 3 has no
    /// concurrent-clone callers yet.
    pub(crate) bulk_data: HashMap<usize, (Vec<FByteBulkData>, OnceLock<Vec<BulkData>>)>,
    /// The bulk-data resolver. `Arc` (not owned) is load-bearing:
    /// `BulkDataResolver` does not implement `Clone` (the `Fn`-trait
    /// loader fields are not `Clone`), so an owned field would break
    /// `Package::Clone` outright. Equally important — sharing via
    /// `Arc` preserves the [`MAX_TOTAL_BULK_DATA_BYTES_PER_PACKAGE`]
    /// cap under clone: every clone observes the same
    /// `AtomicU64::bytes_resolved` counter, so a Phase 7 GUI cloning
    /// a `Package` across event-loop ticks cannot multiply the
    /// 16 GiB budget by the clone count.
    pub(crate) resolver: Arc<BulkDataResolver>,
    /// The parsed UE 5.2+ `FObjectDataResource` table; empty for
    /// pre-5.2 / absent / empty tables. Shared into every
    /// [`AssetContext`] this package hands out (`context()`), switching
    /// bulk reads to the indexed form when non-empty (#642).
    pub(crate) data_resources: Arc<[crate::asset::data_resource::FObjectDataResource]>,
}

impl Serialize for Package {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Phase 3 deliverable JSON shape: each export carries an
        // `"asset"` field rendering the typed `Asset` under its
        // externally-tagged form. ObjectExportView carries `&Asset`
        // (not `&PropertyBag` — that was the Phase 2b shape) and
        // delegates to Asset's derived `Serialize` impl.
        //
        // Imports/exports are wrapped in `ObjectImportView` /
        // `ObjectExportView` so FName references are resolved to
        // their UE display strings (e.g. `"class_package":
        // "/Script/CoreUObject"` instead of the raw u32 index pair).
        // The raw wire indices are still recoverable from the
        // top-level `names` array, which preserves wire order and
        // remains the source of truth for index-based lookups.

        // Build per-entry views. The intermediate `Vec` allocation is
        // fine here — `inspect` is a one-shot diagnostic, not a hot
        // path, and the view borrows are zero-copy aside from the
        // resolved string fields which `serde_json` would have to
        // materialize regardless. The export view zip relies on the
        // invariant `exports.exports.len() == payloads.len()`
        // established by `read_payloads`.
        let import_views: Vec<ObjectImportView<'_>> = self
            .imports
            .imports
            .iter()
            .map(|inner| ObjectImportView {
                inner,
                names: &self.names,
            })
            .collect();
        let export_views: Vec<ObjectExportView<'_>> = self
            .exports
            .exports
            .iter()
            .zip(self.payloads.iter())
            .map(|(inner, asset)| ObjectExportView {
                inner,
                names: &self.names,
                asset,
            })
            .collect();

        let mut s = serializer.serialize_struct("Package", 5)?;
        s.serialize_field("asset_path", &self.asset_path)?;
        s.serialize_field("summary", &self.summary)?;
        // Deref the Arc to avoid serde's `rc`-gated `Arc<T>: Serialize`
        // impl — serializing through the inner `&NameTable` is the
        // wire-identical path and doesn't pull in the extra feature.
        s.serialize_field("names", &*self.names)?;
        s.serialize_field("imports", &import_views)?;
        s.serialize_field("exports", &export_views)?;
        s.end()
    }
}

/// Serialization-only borrowed view of an [`ObjectImport`] that
/// resolves FName references to their canonical UE display strings.
///
/// The owning type [`ObjectImport`] keeps its derived `Serialize`
/// impl emitting raw `u32` indices (pinned by
/// `object_import_serializes_with_raw_indices` in `import_table.rs`)
/// — this view layers resolution on top for the
/// [`Package`]-level JSON output. The two shapes are deliberately
/// distinct: type-level Serialize is wire-format-faithful for
/// debugging an isolated record; the package-level Serialize
/// produces the human-readable Deliverable JSON.
struct ObjectImportView<'a> {
    inner: &'a ObjectImport,
    names: &'a NameTable,
}

impl Serialize for ObjectImportView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let class_package = self.names.resolve(
            self.inner.class_package_name,
            self.inner.class_package_number,
        );
        let class_name = self
            .names
            .resolve(self.inner.class_name, self.inner.class_name_number);
        let object_name = self
            .names
            .resolve(self.inner.object_name, self.inner.object_name_number);

        let mut s = serializer.serialize_struct("ObjectImportView", 5)?;
        s.serialize_field("class_package", &class_package)?;
        s.serialize_field("class_name", &class_name)?;
        s.serialize_field("outer_index", &self.inner.outer_index)?;
        s.serialize_field("object_name", &object_name)?;
        // `import_optional` stays as the parsed `Option<bool>` —
        // `null` for UE4 (gate inactive) and `false`/`true` for UE5
        // ≥ 1003. Kept in the view so consumers don't need to track
        // version gating just to count fields.
        s.serialize_field("import_optional", &self.inner.import_optional)?;
        s.end()
    }
}

/// Serialization-only borrowed view of an [`ObjectExport`] mirroring
/// [`ObjectImportView`]'s contract — FName references resolved
/// against the package's [`NameTable`], all other fields passed
/// through. The disambiguator-suffix folding means `object_name`
/// emits the canonical UE display string with no separate
/// `object_name_number` field.
struct ObjectExportView<'a> {
    inner: &'a ObjectExport,
    names: &'a NameTable,
    asset: &'a super::Asset,
}

impl Serialize for ObjectExportView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let object_name = self
            .names
            .resolve(self.inner.object_name, self.inner.object_name_number);

        // 25 fields — 24 wire fields from `ObjectExport` (minus
        // `object_name_number`, which folds into `object_name`) plus
        // a single `"asset"` field at the tail rendering the typed
        // `Asset` under its externally-tagged JSON shape (Phase 3
        // delegation to `Asset`'s derived `Serialize` impl — the
        // Phase 2b mutually-exclusive `properties`/`payload_bytes`
        // tail is gone). serde's `serialize_struct` length is
        // advisory for serde_json and the per-export shape is pinned
        // by tests.
        let mut s = serializer.serialize_struct("ObjectExportView", 25)?;
        s.serialize_field("class_index", &self.inner.class_index)?;
        s.serialize_field("super_index", &self.inner.super_index)?;
        s.serialize_field("template_index", &self.inner.template_index)?;
        s.serialize_field("outer_index", &self.inner.outer_index)?;
        s.serialize_field("object_name", &object_name)?;
        s.serialize_field("object_flags", &self.inner.object_flags)?;
        s.serialize_field("serial_size", &self.inner.serial_size)?;
        s.serialize_field("serial_offset", &self.inner.serial_offset)?;
        s.serialize_field("forced_export", &self.inner.forced_export)?;
        s.serialize_field("not_for_client", &self.inner.not_for_client)?;
        s.serialize_field("not_for_server", &self.inner.not_for_server)?;
        s.serialize_field("package_guid", &self.inner.package_guid)?;
        s.serialize_field("is_inherited_instance", &self.inner.is_inherited_instance)?;
        s.serialize_field("package_flags", &self.inner.package_flags)?;
        s.serialize_field(
            "not_always_loaded_for_editor_game",
            &self.inner.not_always_loaded_for_editor_game,
        )?;
        s.serialize_field("is_asset", &self.inner.is_asset)?;
        s.serialize_field("generate_public_hash", &self.inner.generate_public_hash)?;
        s.serialize_field(
            "script_serialization_start_offset",
            &self.inner.script_serialization_start_offset,
        )?;
        s.serialize_field(
            "script_serialization_end_offset",
            &self.inner.script_serialization_end_offset,
        )?;
        s.serialize_field(
            "first_export_dependency",
            &self.inner.first_export_dependency,
        )?;
        s.serialize_field(
            "serialization_before_serialization_count",
            &self.inner.serialization_before_serialization_count,
        )?;
        s.serialize_field(
            "create_before_serialization_count",
            &self.inner.create_before_serialization_count,
        )?;
        s.serialize_field(
            "serialization_before_create_count",
            &self.inner.serialization_before_create_count,
        )?;
        s.serialize_field(
            "create_before_create_count",
            &self.inner.create_before_create_count,
        )?;
        // Phase 3 per-export JSON shape: the typed `Asset` is rendered
        // under an `"asset"` field using Asset's own derived
        // (externally-tagged) `Serialize` impl. Phase 2 closure
        // exports surface as `"asset": {"Generic": <PropertyBag JSON>}`;
        // Phase 3 sub-phases (3d-3h) add sibling tags ("DataTable",
        // "Texture2D", etc.) on the same externally-tagged enum.
        s.serialize_field("asset", self.asset)?;
        s.end()
    }
}

/// Derive a companion file path from an asset path by swapping the extension.
///
/// `"Game/Weapon/Sword.uasset"` + `".uexp"` → `"Game/Weapon/Sword.uexp"`.
/// Suffix match is case-insensitive (CLI users may type `.UASSET`)
/// but the stem's casing is preserved — pak entry lookup is
/// exact-match, so lowercasing the whole path would break entries
/// that aren't all-lowercase. If `base` does not end in `.uasset`
/// (any casing), appends `new_ext` directly.
pub(super) fn derive_companion_path(base: &str, new_ext: &str) -> String {
    const UASSET_EXT: &str = ".uasset";
    // `str::get(split_at..)` returns `None` if `split_at` falls
    // inside a multibyte UTF-8 sequence (a real possibility for
    // attacker-crafted pak entry paths); the byte-index slice
    // `base[split_at..]` would panic on the same input and violate
    // CLAUDE.md's "No panics in core" invariant.
    if let Some(split_at) = base.len().checked_sub(UASSET_EXT.len())
        && let Some(tail) = base.get(split_at..)
        && tail.eq_ignore_ascii_case(UASSET_EXT)
    {
        return format!("{}{}", &base[..split_at], new_ext);
    }
    format!("{base}{new_ext}")
}

/// Validate that `uexp_len` does not exceed [`MAX_UEXP_SIZE`].
/// Extracted from [`Package::read_from_inner`]'s boundary check so
/// the `> cap` predicate can be unit-tested directly at the
/// boundary value (which would otherwise require allocating
/// `MAX_UEXP_SIZE = 1 GiB` bytes — impractical for a unit test).
/// Kills the `> with ==` and `> with >=` mutants the cargo-mutants
/// CI flagged on the inline boundary check.
fn check_uexp_size(uexp_len: usize, asset_path: &str) -> crate::Result<()> {
    if uexp_len > MAX_UEXP_SIZE {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::UexpSize,
                value: uexp_len as u64,
                limit: MAX_UEXP_SIZE as u64,
                unit: BoundsUnit::Bytes,
            },
        });
    }
    Ok(())
}

/// Build a `BulkDataResolver` companion-loader closure that reads
/// `companion_path` out of a `.pak` archive via the shared
/// `Arc<PakReader>` handle. `EntryNotFound` from the pak layer maps
/// to a typed `MissingCompanionFile { kind }` fault so callers see
/// the bulk-data tier context (Ubulk / Uptnl) rather than an opaque
/// "entry missing".
///
/// The returned closure satisfies the resolver's `Fn + Send + Sync +
/// 'static` bounds: it closes only over its by-value arguments
/// (`Arc<PakReader>`, two owned `String`s, `CompanionFileKind`).
fn pak_companion_loader(
    reader: Arc<crate::container::pak::PakReader>,
    companion_path: String,
    asset_path: String,
    kind: CompanionFileKind,
) -> impl Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static {
    use crate::container::ContainerReader;
    move || match reader.read_entry(&companion_path) {
        Ok(bytes) => Ok(bytes),
        Err(PaksmithError::EntryNotFound { .. }) => Err(PaksmithError::AssetParse {
            asset_path: asset_path.clone(),
            fault: AssetParseFault::MissingCompanionFile { kind },
        }),
        Err(e) => Err(e),
    }
}

impl Package {
    /// Parse a `.uasset` from `uasset`, optionally stitched with a
    /// companion `.uexp` slice.
    ///
    /// For monolithic assets (all export payloads inside `uasset`), pass
    /// `uexp = None` and the call is zero-copy on the input slice. For
    /// split assets (UE writes `.uasset` truncated at
    /// `total_header_size` with payloads in a separate `.uexp`), pass
    /// `Some(&uexp_bytes)`; the implementation concatenates the two
    /// into one contiguous buffer (capped by [`MAX_UEXP_SIZE`]) and
    /// parses the combined byte stream so the wire-encoded
    /// `serial_offset` values resolve naturally.
    ///
    /// The companion need-detection runs after the export table parse:
    /// if any export's payload extends past `uasset.len()` and `uexp`
    /// is `None`, returns
    /// [`AssetParseFault::MissingCompanionFile`]; if `uexp` is provided
    /// but no payload needs it, logs `tracing::warn!` and proceeds.
    ///
    /// # Errors
    /// Propagates any [`AssetParseFault`] from the component readers:
    /// - [`AssetParseFault::InvalidMagic`],
    ///   [`AssetParseFault::UnsupportedLegacyFileVersion`],
    ///   etc. from [`PackageSummary::read_from`]
    /// - [`AssetParseFault::NegativeValue`], [`AssetParseFault::BoundsExceeded`],
    ///   [`AssetParseFault::AllocationFailed`] from the table readers
    /// - [`AssetParseFault::InvalidOffset`] if any export's
    ///   `serial_offset + serial_size` extends past the stitched buffer
    /// - [`AssetParseFault::U64ArithmeticOverflow`] if `serial_offset + serial_size`
    ///   overflows, or if `uasset.len() + uexp.len()` overflows `usize`
    /// - [`AssetParseFault::U64ExceedsPlatformUsize`] on 32-bit targets if any
    ///   `serial_size` exceeds `usize::MAX`
    /// - [`AssetParseFault::BoundsExceeded`] with
    ///   `field = AssetWireField::UexpSize` if `uexp.len() > MAX_UEXP_SIZE`
    /// - [`AssetParseFault::MissingCompanionFile`] when a payload
    ///   extends past `uasset.len()` and no `.uexp` was provided
    /// - [`AssetParseFault::SplitAssetSizeMismatch`] when a `.uexp` is
    ///   needed but `uasset.len() != total_header_size`
    pub fn read_from(
        uasset: &[u8],
        uexp: Option<&[u8]>,
        mappings: Option<&Usmap>,
        asset_path: &str,
    ) -> crate::Result<Self> {
        // Non-pak callers (unit tests, raw-byte ingest) have no
        // companion source for streaming / optional-streaming tiers.
        // If any 3e/3g/3h typed reader pushes a streaming-tier
        // record into `Package::bulk_data` and a downstream consumer
        // calls `resolve_bulk_for_export`, the stub loaders fire
        // `MissingCompanionFile`. The pak entry point
        // (`read_from_pak`) overrides both with real `Arc<PakReader>`-
        // backed loaders.
        let ubulk_loader =
            missing_companion_loader(CompanionFileKind::Ubulk, asset_path.to_string());
        let uptnl_loader =
            missing_companion_loader(CompanionFileKind::Uptnl, asset_path.to_string());
        Self::read_from_inner(
            uasset,
            uexp,
            mappings,
            asset_path,
            ubulk_loader,
            uptnl_loader,
        )
    }

    /// Internal entry point shared by [`Self::read_from`] (stub
    /// loaders) and [`Self::read_from_pak`] (real
    /// `Arc<PakReader>`-backed loaders). The loaders are baked into
    /// the [`BulkDataResolver`] this constructs.
    #[allow(
        clippy::too_many_lines,
        reason = "Phase 2e stitching + 4-state companion detection + the existing summary/name/import/export/payload pipeline naturally cross the 100-line cap; splitting would obscure the linear top-to-bottom byte-stream flow that's the function's whole point"
    )]
    fn read_from_inner<U, T>(
        uasset: &[u8],
        uexp: Option<&[u8]>,
        mappings: Option<&Usmap>,
        asset_path: &str,
        ubulk_loader: U,
        uptnl_loader: T,
    ) -> crate::Result<Self>
    where
        U: Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static,
        T: Fn() -> crate::Result<Vec<u8>> + Send + Sync + 'static,
    {
        // Cap the .uexp size before allocating a combined buffer
        // sized to `uasset.len() + uexp.len()`. Without this guard
        // a malicious pak entry could force a multi-GiB allocation
        // by claiming a huge .uexp payload. Extracted to
        // `check_uexp_size` so boundary tests can hit the cap
        // without allocating MAX_UEXP_SIZE (1 GiB) bytes.
        if let Some(uexp_data) = uexp {
            check_uexp_size(uexp_data.len(), asset_path)?;
        }

        // Phase 3b: ALWAYS materialize the stitched buffer into an
        // owned `Arc<[u8]>`. The resolver field holds the same
        // `Arc<[u8]>` for inline / uexp-resident tier resolution,
        // and the parser uses the same backing allocation through
        // `&[u8]` deref — one allocation, two roles. For monolithic
        // assets this costs one `uasset.to_vec()`-equivalent copy
        // (no more zero-copy on the parse path); typical UE
        // monolithic assets are KB-scale, so the per-asset overhead
        // is negligible.
        //
        // `try_reserve_exact` + `extend_from_slice` produces a Vec
        // with `capacity == len`, so `into_boxed_slice()` is
        // alloc-free (no shrink-to-fit reallocation).
        let total = uasset
            .len()
            .checked_add(uexp.map_or(0, <[u8]>::len))
            .ok_or_else(|| PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::U64ArithmeticOverflow {
                    operation: AssetOverflowSite::SplitAssetConcatExtent,
                },
            })?;
        let mut buf: Vec<u8> = Vec::new();
        let reserve = buf.try_reserve_exact(total);
        seam_check!(reserve, SeamSite::Asset(AssetSeam::SplitAssetCombined));
        reserve.map_err(|source| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::AllocationFailed {
                context: AssetAllocationContext::SplitAssetCombined,
                requested: total,
                source,
            },
        })?;
        buf.extend_from_slice(uasset);
        if let Some(uexp_data) = uexp {
            buf.extend_from_slice(uexp_data);
        }
        let stitched: Arc<[u8]> = Arc::from(buf.into_boxed_slice());
        let bytes: &[u8] = &stitched;
        let mut cursor = Cursor::new(bytes);
        let summary = PackageSummary::read_from(&mut cursor, asset_path)?;

        // UE 5.2+ object data-resource table (#642). When populated, it
        // governs bulk resolution package-wide: every `FByteBulkData`
        // field in export data serializes as a single `i32` index into
        // this table instead of the classic inline header (see
        // `FByteBulkData::read_from_ctx`). Parse it up front and thread
        // it through `AssetContext` so the typed readers switch modes.
        // Empty/absent/unknown-version tables yield an empty vec —
        // classic parsing, matching CUE4Parse. Reads `bytes` directly so
        // `cursor`'s position (re-seeked per table below) is untouched.
        let data_resources: Arc<[crate::asset::data_resource::FObjectDataResource]> =
            Arc::from(match summary.data_resource_offset {
                Some(offset) => crate::asset::data_resource::parse_data_resource_table(
                    bytes, offset, asset_path,
                )?,
                None => Vec::new(),
            });

        // `Arc`-wrap the tables immediately at parse time (#369).
        // The same Arc is then shared between `Package` and the
        // `AssetContext` below (and any future `context()` callers)
        // — refcount bumps replace the previous per-clone deep
        // copies of the (potentially 1M-entry) tables.
        let names = Arc::new(NameTable::read_from(
            &mut cursor,
            i64::from(summary.name_offset),
            summary.name_count,
            asset_path,
        )?);
        let imports = Arc::new(ImportTable::read_from(
            &mut cursor,
            i64::from(summary.import_offset),
            summary.import_count,
            summary.version,
            asset_path,
        )?);
        let exports = Arc::new(ExportTable::read_from(
            &mut cursor,
            i64::from(summary.export_offset),
            summary.export_count,
            summary.version,
            summary.package_flags,
            asset_path,
        )?);

        // Four-state companion detection.
        //
        // `needs_uexp` is determined by whether any export's payload
        // region extends past the `.uasset` slice's length — that's the
        // structural discriminator between monolithic and split. A
        // naive `serial_offset >= total_header_size` check would
        // misfire on every asset (in both layouts, payloads sit at
        // offsets ≥ total_header_size; the difference is whether those
        // bytes physically live in the `.uasset` file or in `.uexp`).
        // Asking the file-length question directly avoids that trap.
        //
        // `serial_offset` and `serial_size` are validated `>= 0` by
        // `ObjectExport::read_from` (export_table.rs); the i64 -> u64
        // casts here are sign-safe (mirrors the pattern in
        // `read_payloads` below).
        let uasset_len_u64 = uasset.len() as u64;
        let needs_uexp = exports.exports.iter().any(|e| {
            #[allow(
                clippy::cast_sign_loss,
                reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
            )]
            let end = (e.serial_offset as u64).saturating_add(e.serial_size as u64);
            end > uasset_len_u64
        });

        if needs_uexp && uexp.is_none() {
            return Err(PaksmithError::AssetParse {
                asset_path: asset_path.to_string(),
                fault: AssetParseFault::MissingCompanionFile {
                    kind: crate::error::CompanionFileKind::Uexp,
                },
            });
        }

        if !needs_uexp && uexp.is_some() {
            tracing::warn!(
                asset = asset_path,
                total_header_size = summary.total_header_size,
                "'.uexp' companion bytes provided but no export payload extends \
                 past .uasset.len(); ignoring companion"
            );
        }

        // Verify the load-bearing invariant: when split, the `.uasset`
        // file contains exactly the header bytes (everything before the
        // export payload region). UE writes split assets with this
        // layout by convention, but a pathological writer could break
        // it (e.g. by appending AssetRegistryData past
        // `total_header_size` in `.uasset`). If
        // `uasset.len() != total_header_size`, then `serial_offset` —
        // which points into the logical full-asset byte stream — does
        // NOT index naturally into `[uasset || uexp]`. Fire a clear
        // error instead of silently misparsing.
        if needs_uexp {
            #[allow(
                clippy::cast_possible_wrap,
                reason = "usize fits in i64 on all paksmith targets (64-bit usize ≤ i64::MAX = 2^63 - 1; 32-bit usize ≤ u32::MAX); the wrap arm is structurally unreachable"
            )]
            let uasset_signed = uasset.len() as i64;
            if uasset_signed != i64::from(summary.total_header_size) {
                return Err(PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::SplitAssetSizeMismatch {
                        uasset_len: uasset.len(),
                        total_header_size: summary.total_header_size,
                    },
                });
            }
        }

        // Phase 3b: construct the bulk-data resolver from the stitched
        // buffer + the caller-provided companion loaders. Built before the
        // `AssetContext` so the context can carry it — typed readers resolve
        // a non-inlined (streamed) `FByteBulkData` payload through
        // `ctx.bulk_resolver` (e.g. a static mesh's out-of-line LOD geometry).
        // `Arc::clone` is a refcount bump — the parser-side `&stitched` and
        // the resolver's owned `Arc<[u8]>` share one allocation.
        #[allow(
            clippy::cast_sign_loss,
            reason = "total_header_size validated >= 0 by PackageSummary::read_from"
        )]
        let total_header_size = summary.total_header_size as u64;
        let resolver = Arc::new(BulkDataResolver::new(
            Arc::clone(&stitched),
            total_header_size,
            summary.bulk_data_start_offset,
            ubulk_loader,
            uptnl_loader,
        ));

        // Build the AssetContext now so read_payloads can drive the
        // tagged-property iterator per export. Tables share the
        // Arcs owned by `Package` (#369) — refcount bumps replace
        // the previous deep-clone-twice pattern. The optional
        // `Usmap` is `Arc`-wrapped once here so downstream clones
        // of the context are refcount-cheap.
        let ctx = AssetContext {
            names: Arc::clone(&names),
            imports: Arc::clone(&imports),
            exports: Arc::clone(&exports),
            version: summary.version,
            custom_versions: Arc::new(summary.custom_versions.clone()),
            mappings: mappings.map(|m| Arc::new(m.clone())),
            bulk_resolver: Some(Arc::clone(&resolver)),
            soft_object_paths_indexed: summary.soft_object_paths_indexed(),
            data_resources: Arc::clone(&data_resources),
        };

        // Phase 2f: dispatch the unversioned (schema-driven) property
        // path when `PKG_UnversionedProperties` is set.
        //
        // Without mappings: fire `UnversionedWithoutMappings`.
        // With mappings: walk each export's payload slice through
        // `read_unversioned_properties` and skip `read_payloads`
        // entirely — running the tagged-property decoder on
        // unversioned bytes would fall back to `PropertyBag::Opaque`
        // and emit a spurious warn-level log per export.
        //
        // The flag lives on `summary.package_flags`, so the gate is
        // summary-scoped: a single flagged package cannot mix
        // versioned and unversioned exports.
        let (payloads, bulk_records) = if summary.package_flags & PKG_UNVERSIONED_PROPERTIES != 0 {
            let usmap = ctx
                .mappings
                .as_deref()
                .ok_or_else(|| PaksmithError::AssetParse {
                    asset_path: asset_path.to_string(),
                    fault: AssetParseFault::UnversionedWithoutMappings,
                })?;
            let mut payloads: Vec<super::Asset> = Vec::new();
            try_reserve_asset(
                &mut payloads,
                exports.exports.len(),
                asset_path,
                AssetSeam::ExportPayloads,
            )?;
            for export in &exports.exports {
                // Propagate OOB errors here rather than swallowing them
                // with `unwrap_or_default()`. `PackageIndex::Null`
                // already returns `Ok(String::new())` from
                // `resolve_package_index`, so null class refs flow
                // through cleanly and `get_all_properties("")` returns
                // an empty schema (handled inside the decoder).
                let class_name = crate::asset::property::primitives::resolve_package_index(
                    export.class_index,
                    &ctx,
                    asset_path,
                )?;
                let export_slice = carve_export_slice(bytes, export, asset_path)?;

                // Typed dispatch is VERSIONED-ONLY. The registered typed
                // readers (DataTable, Texture2D, …) parse the *tagged*
                // property stream; unversioned bodies are schema-
                // serialized (no tags), so feeding them to `read_typed`
                // would at best fail and at worst MISPARSE — a schema
                // header whose first 8 bytes are `(0, 0)` reads as an
                // empty tagged stream, and the reader would then consume
                // schema bytes as its own fields and return a garbage
                // typed `Asset`. So the unversioned branch goes straight
                // to `read_unversioned_properties`, the correct parser
                // for these bytes. (A package-kind-aware typed dispatch
                // that consumes unversioned bodies via the usmap schema
                // is a later phase; until then unversioned typed-class
                // exports parse as `Generic`.)
                let mut export_cur = Cursor::new(export_slice);
                // NOTE: a schema-parse failure here propagates (no Opaque
                // fallback) — an unversioned parse error usually signals a
                // wrong/mismatched `.usmap`, which should fail loudly
                // rather than silently degrade.
                let props = read_unversioned_properties(
                    &mut export_cur,
                    &class_name,
                    usmap,
                    &ctx,
                    asset_path,
                    0,
                )?;
                payloads.push(super::Asset::Generic(PropertyBag::tree(props)));
            }
            // Unversioned bodies never reach typed dispatch (they're
            // schema-serialized, not tagged), so they surface no bulk
            // records.
            (payloads, Vec::new())
        } else {
            read_payloads(bytes, &exports, &ctx, asset_path)?
        };

        let mut package = Self {
            asset_path: asset_path.to_string(),
            summary,
            names,
            imports,
            exports,
            payloads,
            mappings: ctx.mappings.clone(),
            bulk_data: HashMap::new(),
            resolver,
            data_resources,
        };

        // 3e-3b: store the per-export bulk records surfaced by the typed
        // readers so `resolve_bulk_for_export(idx)` can lazily resolve the
        // mip / payload bytes. The key is the export index (= `payloads`
        // index), set in lockstep in `read_payloads`.
        for (export_idx, records) in bulk_records {
            if let Err(err) = package.insert_bulk_records(export_idx, records) {
                // Unreachable from the current typed readers: Texture2D caps
                // mips at `MAX_MIP_COUNT = 32`; the virtual-texture chunk reader
                // bounds its chunk records by the REMAINING per-export budget
                // (`MAX_BULK_DATA_RECORDS_PER_EXPORT - mip records`, failing loud
                // first); and the USoundWave streaming reader caps its chunk
                // count at `MAX_BULK_DATA_RECORDS_PER_EXPORT` itself (its bulk
                // vec starts empty, so the full budget applies) — so no current
                // reader's record count reaches this insert's
                // `> MAX_BULK_DATA_RECORDS_PER_EXPORT` rejection.
                // This is a defensive backstop for a future reader; degrade
                // like the typed-reader fallback (warn + drop this export's
                // records, keeping its already-parsed `Asset`) rather than
                // aborting the whole package.
                tracing::warn!(
                    asset = asset_path,
                    export.index = export_idx,
                    error = %err,
                    "bulk-record cap exceeded; dropping this export's bulk records"
                );
            }
        }

        Ok(package)
    }

    /// Open a `.pak` archive at `pak_path`, find the entry at
    /// `virtual_path`, decompress its bytes, and parse as a UAsset.
    ///
    /// Companion files are looked up automatically: a sibling `.uexp`
    /// entry (if present) is stitched in for split assets. Sibling
    /// `.ubulk` / `.uptnl` entries are wired into the bulk-data
    /// resolver via lazy loaders — first matching-tier
    /// [`Self::resolve_bulk_for_export`] call materializes them.
    ///
    /// `mappings` is a parsed `.usmap` schema registry — supply
    /// `Some(&usmap)` to decode assets whose `PKG_UnversionedProperties`
    /// flag is set, and `None` for versioned (tagged-property) assets.
    /// A flagged asset paired with `None` fires
    /// [`AssetParseFault::UnversionedWithoutMappings`].
    ///
    /// # Errors
    /// Any [`PaksmithError`] from the pak layer (open, find entry,
    /// decompress) or the asset layer (parse). A missing `.uexp`
    /// companion is silently treated as a monolithic asset; any other
    /// error from the companion lookup propagates. Missing
    /// `.ubulk` / `.uptnl` at pak-open time is fine — the lazy
    /// loaders only fire when bulk-data resolution actually needs
    /// them.
    pub fn read_from_pak<P: AsRef<std::path::Path>>(
        pak_path: P,
        virtual_path: &str,
        mappings: Option<&Usmap>,
    ) -> crate::Result<Self> {
        // Phase 3b: wrap `PakReader` in `Arc` so the companion-loader
        // closures can capture cloned refcounted handles. `PakReader`
        // is `Send + Sync` (Phase 1 design); `Arc<PakReader>` auto-
        // derefs to `&PakReader` for the synchronous reads below.
        let reader = Arc::new(crate::container::pak::PakReader::open(pak_path)?);
        Self::read_from_reader(&reader, virtual_path, mappings)
    }

    /// Parse the UAsset at `virtual_path` from an already-open pak reader.
    ///
    /// Identical to [`Self::read_from_pak`] but reuses a caller-provided
    /// `Arc<PakReader>` instead of opening (and re-parsing the index of)
    /// the pak on every call. The real `Arc<PakReader>`-backed
    /// `.ubulk` / `.uptnl` bulk loaders are wired exactly as in
    /// `read_from_pak`, so streaming-tier bulk resolution works.
    ///
    /// Batch callers (the CLI `extract` command, the future GUI) open the
    /// pak once and share the `Arc` across worker threads (`PakReader` is
    /// `Send + Sync`).
    ///
    /// Phase 8 (IoStore) will need its own parallel entry point — bulk-data
    /// wiring is pak-specific, so the IoStore reader is not a refactor of
    /// this function.
    ///
    /// # Errors
    /// Same as [`Self::read_from_pak`], minus the open step.
    pub fn read_from_reader(
        reader: &Arc<crate::container::pak::PakReader>,
        virtual_path: &str,
        mappings: Option<&Usmap>,
    ) -> crate::Result<Self> {
        use crate::container::ContainerReader;

        let uasset_bytes = reader.read_entry(virtual_path)?;

        // Look up the `.uexp` companion. Absence is normal for
        // monolithic assets; any other error from the pak layer
        // propagates.
        let uexp_path = derive_companion_path(virtual_path, ".uexp");
        let uexp_bytes = match reader.read_entry(&uexp_path) {
            Ok(bytes) => Some(bytes),
            Err(PaksmithError::EntryNotFound { .. }) => None,
            Err(e) => return Err(e),
        };

        // Phase 3b: build the `.ubulk` / `.uptnl` loader closures via
        // the shared `pak_companion_loader` helper. Each opens the
        // respective companion on first matching-tier resolution
        // (via `BulkDataResolver`'s `OnceLock` cache). `EntryNotFound`
        // from the pak layer maps to the typed `MissingCompanionFile`
        // fault so consumers get the bulk-data tier context (Ubulk /
        // Uptnl), not an opaque "entry missing". Closures capture
        // `Arc<PakReader>` clones (NOT `&reader`) to satisfy the
        // `'static + Send + Sync` bounds the resolver imposes for
        // Phase 5 async / Phase 7 GUI thread crossings.
        let ubulk_loader = pak_companion_loader(
            Arc::clone(reader),
            derive_companion_path(virtual_path, ".ubulk"),
            virtual_path.to_string(),
            CompanionFileKind::Ubulk,
        );
        let uptnl_loader = pak_companion_loader(
            Arc::clone(reader),
            derive_companion_path(virtual_path, ".uptnl"),
            virtual_path.to_string(),
            CompanionFileKind::Uptnl,
        );

        Self::read_from_inner(
            &uasset_bytes,
            uexp_bytes.as_deref(),
            mappings,
            virtual_path,
            ubulk_loader,
            uptnl_loader,
        )
    }

    /// Phase 3b: typed-reader hook used by 3e/3g/3h to register the
    /// `FByteBulkData` records collected during an export's parse.
    /// The companion `OnceLock<Vec<BulkData>>` cache slot is inserted
    /// alongside in the same call so subsequent
    /// [`Self::resolve_bulk_for_export`] lookups can never miss the
    /// cache half of the pair.
    ///
    /// Driven from production by `read_from_inner` (3e-3b), which feeds the
    /// per-export records `read_payloads` collected from the typed readers.
    ///
    /// **Defensive cap enforcement:** `records.len()` is checked
    /// against [`MAX_BULK_DATA_RECORDS_PER_EXPORT`] here so the cap
    /// fires even for export classes outside 3e/3g/3h's planned
    /// coverage (e.g. a future class added without security review,
    /// or a generic-class path that constructs records).
    ///
    /// **Empty insert** removes any prior records under
    /// `export_idx`. The contract is "no records present == no
    /// entry"; preserving stale records on an empty re-insert would
    /// break the equivalence and silently re-surface payload bytes
    /// from a prior parse.
    ///
    /// # Errors
    /// [`AssetParseFault::BulkDataRecordsExceeded`] when
    /// `records.len()` exceeds [`MAX_BULK_DATA_RECORDS_PER_EXPORT`].
    pub(crate) fn insert_bulk_records(
        &mut self,
        export_idx: usize,
        records: Vec<FByteBulkData>,
    ) -> crate::Result<()> {
        if records.is_empty() {
            // Drop any prior records under this index to maintain
            // the "no records present == no entry" invariant.
            let _removed = self.bulk_data.remove(&export_idx);
            return Ok(());
        }
        if records.len() > MAX_BULK_DATA_RECORDS_PER_EXPORT {
            return Err(PaksmithError::AssetParse {
                asset_path: self.asset_path.clone(),
                fault: AssetParseFault::BulkDataRecordsExceeded {
                    count: records.len(),
                    cap: MAX_BULK_DATA_RECORDS_PER_EXPORT,
                },
            });
        }
        let _replaced = self
            .bulk_data
            .insert(export_idx, (records, OnceLock::new()));
        Ok(())
    }

    /// `__test_utils`-gated public accessor for the crate-private
    /// `Package::insert_bulk_records` method (delegates verbatim).
    /// Lives at the public surface (gated by the feature flag) so
    /// out-of-crate integration tests in `paksmith-core-tests` can
    /// drive the bulk-data storage shape directly without waiting
    /// for the 3e/3g/3h typed readers to populate records via the
    /// production `pub(crate)` path.
    ///
    /// **Semantics:** empty input removes any prior entry under
    /// `export_idx`; the per-export records cap (256) is enforced;
    /// non-empty input replaces both records and cache slot atomically.
    ///
    /// # Errors
    /// [`AssetParseFault::BulkDataRecordsExceeded`] when
    /// `records.len()` exceeds the per-export cap (256).
    #[cfg(feature = "__test_utils")]
    pub fn insert_bulk_records_for_test(
        &mut self,
        export_idx: usize,
        records: Vec<FByteBulkData>,
    ) -> crate::Result<()> {
        self.insert_bulk_records(export_idx, records)
    }

    /// Whether `export_idx` has any serialized bulk-data records.
    ///
    /// Cheap O(1) map lookup that performs **no resolution and no I/O** —
    /// it only reports whether records were registered, not whether they
    /// resolve. Used by `classify_texture` to reject textures whose mip
    /// dimensions are populated but whose mip bytes were never serialized
    /// (`bSerializeMipData = false`); such textures would otherwise
    /// classify as decodable yet have no bytes to decode.
    ///
    /// Relies on the `insert_bulk_records` invariant that an empty record
    /// list removes the entry ("no records present == no entry"), so a
    /// present key always carries at least one record.
    pub(crate) fn has_bulk_records(&self, export_idx: usize) -> bool {
        self.bulk_data.contains_key(&export_idx)
    }

    /// Phase 3b: resolve all bulk-data records for `export_idx`. On
    /// first call, walks the export's records through the resolver
    /// and caches the result in a `OnceLock`. Subsequent calls return
    /// the cached slice in O(1).
    ///
    /// Returns an empty slice for exports with no bulk records (the
    /// common case — only 3e/3g/3h typed readers populate records via
    /// `Package::insert_bulk_records` — `pub(crate)`, intentionally
    /// not part of the public rustdoc surface).
    ///
    /// # Errors
    /// Any [`PaksmithError`] from the resolver (offset overflow, cap
    /// exceeded, companion missing, decompression failure, etc.).
    /// Errors are NOT cached — a failing resolve attempts again on
    /// the next call. (Intentional: a transient I/O failure shouldn't
    /// poison the export forever.)
    pub fn resolve_bulk_for_export(&self, export_idx: usize) -> crate::Result<&[BulkData]> {
        let Some((records, cache)) = self.bulk_data.get(&export_idx) else {
            return Ok(&[]);
        };
        if let Some(cached) = cache.get() {
            return Ok(cached.as_slice());
        }
        // Resolve all records up-front (fallible). On any per-record
        // error, the cache slot stays empty so the next call re-runs
        // — intentional: transient I/O failures shouldn't poison the
        // export forever.
        let mut resolved: Vec<BulkData> = Vec::with_capacity(records.len());
        for record in records {
            resolved.push(self.resolver.resolve(record, &self.asset_path)?);
        }
        // Race-safely place the freshly-resolved value into the
        // OnceLock. `get_or_init`'s closure is infallible
        // (`get_or_try_init` is gated on the unstable `once_cell_try`
        // feature, so this mirrors the `BulkDataResolver::ubulk` /
        // `uptnl` pattern). If another thread populated `cache`
        // between the `cache.get()` check above and this point, our
        // `resolved` is dropped here and the racing thread's value
        // is returned. **Payload bytes are equivalent** (both threads
        // ran the same `BulkDataResolver::resolve` chain over the
        // same `records`), but **the per-package budget counter
        // double-charges**: each thread's `resolve()` calls already
        // incremented `bytes_resolved` for every record before the
        // racing dropped our `resolved`. Fails closed (less apparent
        // headroom than reality), not open. Phase 5 async should
        // consider a CAS loop in `BulkDataResolver::resolve` to
        // close the budget over-count.
        Ok(cache.get_or_init(|| resolved).as_slice())
    }

    /// Build an [`AssetContext`] from this package. Used by Phase 2b+
    /// property parsers; Phase 2a only constructs it for the API
    /// shape sanity check in tests.
    ///
    /// Two independent calls produce semantically-equal contexts.
    /// `names` / `imports` / `exports` / `mappings` are all
    /// refcount-shared via `Arc` (#369) — context() is essentially
    /// allocator-free (only the `custom_versions` field still pays a
    /// `clone` because `PackageSummary` stores it by value).
    /// Pointer-equal via [`Arc::ptr_eq`] across calls; use that as a
    /// cache key on the individual fields, not the full context
    /// struct.
    #[must_use]
    pub fn context(&self) -> AssetContext {
        AssetContext {
            names: Arc::clone(&self.names),
            imports: Arc::clone(&self.imports),
            exports: Arc::clone(&self.exports),
            version: self.summary.version,
            custom_versions: Arc::new(self.summary.custom_versions.clone()),
            mappings: self.mappings.clone(),
            bulk_resolver: Some(Arc::clone(&self.resolver)),
            soft_object_paths_indexed: self.summary.soft_object_paths_indexed(),
            data_resources: Arc::clone(&self.data_resources),
        }
    }
}

/// Validate and carve out an `&[u8]` view of `export`'s payload from
/// the stitched asset buffer.
///
/// `bytes` is the full stitched `.uasset` + `.uexp` buffer (must not
/// be a sub-view — the bounds reporting uses `bytes.len()` as the
/// asset-size in error payloads). Checks `serial_size`, computes
/// `offset + size`, validates against `bytes.len()`, and returns the
/// borrowed slice. Both Phase 2f's unversioned branch in
/// `Package::read_from` and `read_payloads` route through this helper
/// so the bounds-check ordering stays identical at both sites.
///
/// # Errors
/// - [`AssetParseFault::BoundsExceeded`] for `serial_size >
///   MAX_PAYLOAD_BYTES`.
/// - [`AssetParseFault::U64ArithmeticOverflow`] for the addition.
/// - [`AssetParseFault::InvalidOffset`] when the computed end exceeds
///   the stitched buffer.
fn carve_export_slice<'a>(
    bytes: &'a [u8],
    export: &ObjectExport,
    asset_path: &str,
) -> crate::Result<&'a [u8]> {
    // `serial_offset` / `serial_size` are validated `>= 0` by
    // `ObjectExport::read_from`, so the i64→u64 casts are sign-safe.
    #[allow(
        clippy::cast_sign_loss,
        reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
    )]
    let offset = export.serial_offset as u64;
    #[allow(
        clippy::cast_sign_loss,
        reason = "serial_offset/serial_size validated >= 0 by ObjectExport::read_from"
    )]
    let size = export.serial_size as u64;
    if size > MAX_PAYLOAD_BYTES {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::BoundsExceeded {
                field: AssetWireField::ExportSerialSize,
                value: size,
                limit: MAX_PAYLOAD_BYTES,
                unit: BoundsUnit::Bytes,
            },
        });
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::U64ArithmeticOverflow {
                operation: AssetOverflowSite::ExportPayloadExtent,
            },
        })?;
    let asset_size = bytes.len() as u64;
    if end > asset_size {
        return Err(PaksmithError::AssetParse {
            asset_path: asset_path.to_string(),
            fault: AssetParseFault::InvalidOffset {
                field: AssetWireField::ExportSerialOffset,
                offset: export.serial_offset,
                asset_size,
            },
        });
    }
    // Post bounds-check: both `offset` and `end` are `<= asset_size`
    // = `bytes.len() as u64`. `bytes.len()` is bounded by `isize::MAX`
    // on every platform Rust supports, so both casts to `usize` are
    // infallible.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by asset_size = bytes.len() above"
    )]
    let start = offset as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by asset_size = bytes.len() above"
    )]
    let end_usize = end as usize;
    Ok(&bytes[start..end_usize])
}

/// Per-export `FByteBulkData` records surfaced by typed readers, paired
/// with the export index they belong to (`payloads[idx]`). Fed to
/// `Package::insert_bulk_records` so `resolve_bulk_for_export` lines up.
type ExportBulkRecords = Vec<(usize, Vec<FByteBulkData>)>;

fn read_payloads(
    bytes: &[u8],
    exports: &ExportTable,
    ctx: &AssetContext,
    asset_path: &str,
) -> crate::Result<(Vec<super::Asset>, ExportBulkRecords)> {
    let mut payloads: Vec<super::Asset> = Vec::new();
    try_reserve_asset(
        &mut payloads,
        exports.exports.len(),
        asset_path,
        AssetSeam::ExportPayloads,
    )?;
    // Per-export `FByteBulkData` records surfaced by typed readers (3e-3a),
    // keyed by export index so `Package::resolve_bulk_for_export(idx)` lines
    // up with `payloads[idx]`. Only non-empty record sets are kept (empty ⇒
    // no entry, matching `insert_bulk_records`'s empty-means-remove
    // contract; e.g. a UE5.3+ texture with `bSerializeMipData == false`).
    let mut bulk_records: ExportBulkRecords = Vec::new();

    for (export_idx, e) in exports.exports.iter().enumerate() {
        let export_slice = carve_export_slice(bytes, e, asset_path)?;

        // Phase 3a Task 4: resolve the export's class name and
        // consult the typed-reader dispatch table. A HashMap hit
        // means a typed reader exists for this class — call it
        // and use its returned Asset directly. A miss means no
        // typed reader is registered (the default case for Phase
        // 3a: dispatch table is empty), so we fall through to the
        // existing Phase 2 generic property-bag path below.
        //
        // The typed reader also returns `Vec<FByteBulkData>` (the
        // records it collected mid-parse). These are surfaced keyed by
        // `export_idx` (below) and returned to `read_from_inner`, which
        // drives `Package::insert_bulk_records` after construction (3e-3b)
        // so the mip / payload bytes resolve lazily.
        let class_name = crate::asset::property::primitives::resolve_package_index(
            e.class_index,
            ctx,
            asset_path,
        )?;
        if let Some(read_typed) =
            crate::asset::exports::dispatch::class_dispatch().get(class_name.as_str())
        {
            // Typed reader registered for this class (3d+ populate the
            // dispatch table). On success, push the typed Asset and
            // move on. On FAILURE, do NOT abort the whole package —
            // fall through to the generic tagged-property path below,
            // exactly as if no typed reader were registered. A typed
            // reader must never leave an export worse off than the
            // generic parse would: one corrupt typed export degrades
            // to `Generic` rather than failing every sibling export's
            // parse. (Before this, `read_typed(...)?` propagated and a
            // single malformed DataTable/Texture2D aborted the package.)
            //
            // The typed reader's `bulk_records` are surfaced here keyed by
            // `export_idx` and handed back to `read_from_inner`, which holds
            // `&mut Package` and drives `insert_bulk_records` after the
            // `Package` is constructed (`read_payloads` itself only has the
            // read-only `&ExportTable` / `&AssetContext`). 3e-3a collected
            // them; 3e-3b wires them through.
            match read_typed(export_slice, ctx, asset_path) {
                Ok((asset, records)) => {
                    payloads.push(asset);
                    if !records.is_empty() {
                        bulk_records.push((export_idx, records));
                    }
                    continue;
                }
                // Environmental failure: `AllocationFailed` means the
                // process is out of memory, NOT that this export is
                // corrupt — the caller must know, so propagate (libraries
                // fail fast). The caps (e.g. `DataTableRowCountExceeded`)
                // are deliberately NOT environmental: they fire before
                // allocating, so a malicious oversized-count export still
                // degrades like any other malformed body below.
                Err(err)
                    if matches!(
                        &err,
                        PaksmithError::AssetParse {
                            fault: AssetParseFault::AllocationFailed { .. },
                            ..
                        }
                    ) =>
                {
                    return Err(err);
                }
                // Malformed data: one corrupt export must not lose its
                // siblings (the package-resilience contract) — warn and
                // fall through to the generic parse below, exactly as if
                // no typed reader were registered.
                Err(err) => {
                    tracing::warn!(
                        asset = asset_path,
                        export.class = class_name.as_str(),
                        error = %err,
                        "typed reader failed; falling back to generic property-bag parse"
                    );
                    // fall through to the generic path below
                }
            }
        } else {
            // No typed reader registered. Trace-level so production
            // runs don't spam — UE shipping content carries thousands
            // of distinct classes, Phase 3 covers only a handful.
            tracing::trace!(
                asset = asset_path,
                export.class = class_name.as_str(),
                "no typed reader registered; using Generic property-bag iteration"
            );
        }

        // Phase 2b: attempt tagged-property iteration over the
        // export's bytes. On success, store as `PropertyBag::Tree`;
        // on parse error, fall back to `PropertyBag::Opaque` with
        // the original bytes (one corrupt export shouldn't lose every
        // other export's data). The fallback is logged at warn level
        // so operators see the version-skew signal.
        //
        // `Opaque` needs `Vec<u8>` ownership for storage in the
        // `Package` struct. The cold error path uses
        // `try_reserve_asset` + `extend_from_slice` (NOT
        // `to_vec()`, which routes through the infallible global
        // allocator path and would abort on OOM — violating
        // CLAUDE.md's "no panics in core" invariant). The hot
        // success path stays allocation-free.
        // UE5 >= 1011: per-object serialization-control byte precedes
        // the export root's tagged stream (#643). Read inside the
        // fallible block so its errors degrade to Opaque exactly like
        // a tag-level parse error would.
        let bag = match (|| {
            let mut cur = Cursor::new(export_slice);
            crate::asset::property::read_class_serialization_control(&mut cur, ctx, asset_path)?;
            crate::asset::property::read_properties(
                &mut cur,
                ctx,
                0,
                export_slice.len() as u64,
                asset_path,
            )
        })() {
            Ok(props) => {
                tracing::debug!(
                    asset = asset_path,
                    export = %e.object_name,
                    count = props.len(),
                    "decoded property tree"
                );
                PropertyBag::tree(props)
            }
            Err(err) => {
                tracing::warn!(
                    asset = asset_path,
                    export = %e.object_name,
                    error = %err,
                    "property iteration failed, falling back to Opaque"
                );
                let mut buf: Vec<u8> = Vec::new();
                try_reserve_asset(
                    &mut buf,
                    export_slice.len(),
                    asset_path,
                    AssetSeam::ExportPayloadBytes,
                )?;
                buf.extend_from_slice(export_slice);
                PropertyBag::opaque(buf)
            }
        };
        payloads.push(super::Asset::Generic(bag));
    }
    Ok((payloads, bulk_records))
}

#[cfg(all(test, feature = "__test_utils"))]
mod tests {
    use super::*;
    use crate::error::CompanionFileKind;
    use crate::testing::uasset::{
        MinimalPackage, build_minimal_ue4_27, build_minimal_ue4_27_split,
        build_minimal_ue4_27_with_data_table,
        build_minimal_ue4_27_with_valid_and_corrupt_data_tables, build_minimal_ue5_1010,
        build_minimal_ue5_1010_with_data_resources, build_minimal_ue5_1012, build_minimal_ue5_1013,
        build_minimal_with_texture2d,
    };

    /// End-to-end acceptance (#643): UE 5.4 (1012) and 5.5 (1013)
    /// packages with a REAL complete-type-name tagged payload parse
    /// into a `PropertyBag::Tree` — the serialization-control byte,
    /// the tree-shaped tag, and the flag-gated tail all decode through
    /// the generic bag path (previously rejected at the summary
    /// version gate).
    #[test]
    fn read_from_parses_ue5_1012_and_1013_tagged_payloads() {
        for (label, pkg) in [
            ("1012", build_minimal_ue5_1012()),
            ("1013", build_minimal_ue5_1013()),
        ] {
            let parsed = Package::read_from(&pkg.bytes, None, None, "t.uasset")
                .unwrap_or_else(|e| panic!("ue5 {label} must parse: {e}"));
            let crate::asset::Asset::Generic(bag) = &parsed.payloads[0] else {
                panic!("{label}: expected Generic payload");
            };
            match bag {
                PropertyBag::Tree { properties } => {
                    assert_eq!(properties.len(), 1, "{label}");
                    assert_eq!(properties[0].name(), "Score", "{label}");
                    assert!(
                        matches!(
                            properties[0].value,
                            crate::asset::property::PropertyValue::Int(7)
                        ),
                        "{label}: expected Int(7), got {:?}",
                        properties[0].value
                    );
                }
                other => panic!("{label}: expected Tree, got {other:?}"),
            }
        }
    }

    /// End-to-end (#642): `Package::read_from` on a UE5.2+ package whose
    /// `DataResourceOffset` points at a POPULATED table now PARSES the
    /// table (previously fail-loud `DataResourceMapUnsupported`) and
    /// threads it into the context. This is the acceptance fixture: a
    /// non-empty data-resource map on a real package parse.
    #[test]
    fn read_from_parses_populated_data_resource_map() {
        let pkg = build_minimal_ue5_1010_with_data_resources();
        let parsed = Package::read_from(&pkg.bytes, None, None, "dr.uasset")
            .expect("populated data-resource map must parse (#642)");
        // Full-struct equality pins every field the fixture builder
        // emits (helper-field pin-test discipline) — a drifted builder
        // constant fails here even if the parser ignores the field.
        let expected_entry =
            |serial_offset: i64, legacy: u32| crate::asset::data_resource::FObjectDataResource {
                flags: 0,
                cooked_index: 0,
                serial_offset,
                duplicate_serial_offset: -1,
                serial_size: 64,
                raw_size: 64,
                outer_index: 1,
                legacy_bulk_data_flags: legacy,
            };
        assert_eq!(
            parsed.data_resources.as_ref(),
            &[expected_entry(0x100, 0x0100), expected_entry(0x200, 0x0001)]
        );
        // The context hands the same table to typed readers.
        assert_eq!(parsed.context().data_resources.len(), 2);
    }

    /// End-to-end: a UE5.2+ package with an EMPTY data-resource map
    /// (`DataResourceOffset = 0`, the default cook) parses with an
    /// empty table — classic inline bulk headers.
    #[test]
    fn read_from_accepts_empty_data_resource_map() {
        let pkg = build_minimal_ue5_1010();
        let parsed = Package::read_from(&pkg.bytes, None, None, "dr.uasset")
            .expect("empty data-resource map parses");
        assert!(parsed.data_resources.is_empty());
    }

    /// Pins the typed-dispatch fall-through: a typed reader that errors
    /// on one export must NOT abort the package — it falls through to
    /// the generic property-bag parse (degrading that export to
    /// `Generic`, not propagating), so sibling exports survive.
    ///
    /// The fixture has two `DataTable` exports: a valid empty one and a
    /// corrupt one (segment-2 `RowName` index out of bounds). Asserting
    /// `payloads.len() == 2` also pins the `Ok` arm's `continue` — drop
    /// it and the valid export would push BOTH a typed `DataTable` and a
    /// generic fall-through, yielding 3 payloads.
    #[tracing_test::traced_test]
    #[test]
    fn typed_reader_failure_falls_back_to_generic_without_aborting_package() {
        let pkg = build_minimal_ue4_27_with_valid_and_corrupt_data_tables();
        let parsed = Package::read_from(&pkg.bytes, None, None, "x.uasset")
            .expect("package must parse despite one corrupt typed export");

        assert_eq!(
            parsed.payloads.len(),
            2,
            "both exports present; the valid sibling is not lost and the \
             valid export is not double-pushed"
        );
        // Export 0: valid empty DataTable decodes typed.
        assert!(
            matches!(parsed.payloads[0], crate::asset::Asset::DataTable(_)),
            "export 0 should be a typed DataTable, got {:?}",
            parsed.payloads[0]
        );
        // Export 1: corrupt DataTable -> typed reader errored -> fell
        // back to the generic tagged parse of segment 1 (a Tree carrying
        // the `Foo` class property), NOT an abort and NOT bare Opaque.
        match &parsed.payloads[1] {
            crate::asset::Asset::Generic(PropertyBag::Tree { properties }) => {
                assert_eq!(properties.len(), 1, "segment-1 Foo recovered");
                assert_eq!(properties[0].name(), "Foo");
                assert_eq!(
                    properties[0].value,
                    crate::asset::property::primitives::PropertyValue::Int(1)
                );
            }
            other => panic!("expected Generic(Tree) fall-through, got {other:?}"),
        }
        assert!(
            logs_contain("typed reader failed; falling back to generic property-bag parse"),
            "the fall-through must emit a warn so operators see the typed-parse failure"
        );
    }

    /// 3e-3b: parsing a package whose typed export surfaces `FByteBulkData`
    /// records populates `Package::bulk_data` **keyed by the export index**,
    /// so `resolve_bulk_for_export(idx)` lines up with `payloads[idx]`. The
    /// texture sits at export index **1** (non-zero) on purpose: a wiring
    /// bug that hardcoded `0` or used a stale counter would key the records
    /// under the wrong index and this test would fail.
    #[test]
    fn texture_export_bulk_records_keyed_at_their_export_index() {
        let pkg = build_minimal_with_texture2d();
        // Fixture integrity: `fixture_export` emits `first_export_dependency
        // = -1` (the "no preload deps" cooked value). Pin it so a `delete -`
        // mutant on the helper (→ `1`) can't survive — no other assertion
        // reads this field.
        assert_eq!(pkg.exports.exports[1].first_export_dependency, -1);
        let parsed = Package::read_from(&pkg.bytes, None, None, "tex.uasset")
            .expect("a package with a Texture2D export must parse");

        // Meta-assertion: export[1]'s body parsed AS a typed Texture2D
        // (it did not degrade to Generic). Without this, a stale fixture
        // body would yield empty records and the keying checks below would
        // pass vacuously.
        assert!(
            matches!(parsed.payloads[1], crate::asset::Asset::Texture2D(_)),
            "export 1 must be a typed Texture2D, got {:?}",
            parsed.payloads[1]
        );
        assert!(
            matches!(parsed.payloads[0], crate::asset::Asset::Generic(_)),
            "export 0 is the generic sibling"
        );

        // The records are stored under export index 1, NOT 0.
        assert!(
            parsed.bulk_data.contains_key(&1),
            "the texture's mip records must be keyed at export index 1"
        );
        assert!(
            !parsed.bulk_data.contains_key(&0),
            "the generic export 0 has no bulk records"
        );

        // End-to-end: the inline-tier mip record resolves to its 8 bytes.
        let resolved = parsed
            .resolve_bulk_for_export(1)
            .expect("the texture export's mip FByteBulkData resolves");
        assert_eq!(resolved.len(), 1, "exactly one mip's bulk record");
        assert_eq!(
            resolved[0].bytes.len(),
            8,
            "inline tier resolves `size_on_disk` (8) bytes from the package buffer"
        );

        // The generic export resolves to no records (the empty-slice path).
        assert!(
            parsed.resolve_bulk_for_export(0).expect("ok").is_empty(),
            "export 0 surfaced no records"
        );
    }

    /// Pins the OTHER half of the typed-dispatch error split: an
    /// environmental `AllocationFailed` from a typed reader must
    /// PROPAGATE through `Package::read_from` (libraries fail fast), NOT
    /// fall through to the generic parse like a malformed body does.
    ///
    /// In-source (mirrors `oom_asset.rs`'s integration test) because
    /// `cargo-mutants` runs over default-members and EXCLUDES
    /// `paksmith-core-tests` — without this, flipping the dispatch's
    /// `matches!(.. AllocationFailed ..)` guard to `false` (which would
    /// wrongly degrade OOM to a generic parse) survives mutation.
    #[test]
    fn typed_reader_allocation_failure_propagates_not_falls_back() {
        let pkg = build_minimal_ue4_27_with_data_table();
        let _guard = crate::testing::oom::arm_at(
            crate::seams::SeamSite::Asset(crate::seams::AssetSeam::DataTableRows),
            0,
        );
        let err = Package::read_from(&pkg.bytes, None, None, "x.uasset").unwrap_err();
        assert!(
            matches!(
                &err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::AllocationFailed {
                        context: AssetAllocationContext::DataTableRows,
                        ..
                    },
                    ..
                }
            ),
            "typed-reader AllocationFailed must propagate (fail fast), not \
             fall through to a generic parse; got {err:?}"
        );
    }

    #[test]
    fn derive_companion_path_strips_uasset() {
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.uasset", ".uexp"),
            "Game/Weapon/Sword.uexp"
        );
    }

    #[test]
    fn derive_companion_path_non_uasset_appends() {
        assert_eq!(derive_companion_path("Game/raw", ".uexp"), "Game/raw.uexp");
    }

    #[test]
    fn derive_companion_path_strips_uasset_case_insensitive() {
        // See `derive_companion_path` docs for the case-insensitive
        // + stem-case-preserving rationale (issue #374).
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.UASSET", ".uexp"),
            "Game/Weapon/Sword.uexp"
        );
        assert_eq!(
            derive_companion_path("Game/Weapon/Sword.UAsset", ".ubulk"),
            "Game/Weapon/Sword.ubulk"
        );
    }

    #[test]
    fn derive_companion_path_handles_multibyte_at_suffix_boundary() {
        // An attacker-crafted pak entry path can be any valid UTF-8
        // (`FString` decode does not enforce ASCII). The byte index
        // `base.len() - ".uasset".len()` may land inside a multibyte
        // character; the slice `&base[split_at..]` would panic.
        // Verifies the fix uses `str::get(split_at..)` which returns
        // `None` instead, falling through to the no-suffix branch.
        //
        // `"ab😀abcd"` is 10 bytes (`a`, `b`, 4-byte emoji, `a`, `b`,
        // `c`, `d`); `split_at = 3` lands inside the emoji.
        let result = derive_companion_path("ab😀abcd", ".uexp");
        // Either treats as no-match (append) or strip; the function
        // contract is "append" because no `.uasset` suffix is present
        // at the byte level.
        assert_eq!(result, "ab😀abcd.uexp");
    }

    #[test]
    fn read_from_monolithic_no_uexp_succeeds() {
        // Standard monolithic fixture: payloads live within `bytes`.
        let pkg = build_minimal_ue4_27();
        let result = Package::read_from(&pkg.bytes, None, None, "test.uasset");
        assert!(result.is_ok(), "monolithic parse failed: {result:?}");
    }

    #[test]
    fn read_from_split_with_uexp_succeeds() {
        // Split fixture: header bytes + uexp bytes. Stitch and parse.
        let (uasset, uexp) = build_minimal_ue4_27_split();
        let result = Package::read_from(&uasset, Some(&uexp), None, "test.uasset");
        assert!(result.is_ok(), "split parse failed: {result:?}");
    }

    #[test]
    fn read_from_split_missing_uexp_errors() {
        // Split fixture header with no uexp provided → MissingCompanionFile.
        let (uasset, _uexp) = build_minimal_ue4_27_split();
        let err = Package::read_from(&uasset, None, None, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::MissingCompanionFile {
                        kind: CompanionFileKind::Uexp,
                    },
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn read_from_monolithic_with_extra_uexp_warns_and_succeeds() {
        // Monolithic fixture (no export needs .uexp) but we pass Some(uexp)
        // anyway. Should warn and succeed (no error).
        let pkg = build_minimal_ue4_27();
        let dummy_uexp: Vec<u8> = vec![0xDE, 0xAD];
        let result = Package::read_from(&pkg.bytes, Some(&dummy_uexp), None, "test.uasset");
        assert!(result.is_ok(), "extra-uexp warn path failed: {result:?}");
    }

    #[test]
    fn round_trip_minimal_ue4_27() {
        let MinimalPackage {
            bytes,
            summary,
            names,
            imports,
            exports,
            payload,
            ..
        } = build_minimal_ue4_27();
        let parsed = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        assert_eq!(parsed.summary, summary);
        assert_eq!(*parsed.names, names);
        assert_eq!(*parsed.imports, imports);
        assert_eq!(*parsed.exports, exports);
        assert_eq!(parsed.payloads.len(), 1);
        assert_eq!(
            parsed.payloads[0],
            crate::asset::Asset::Generic(PropertyBag::opaque(payload))
        );
    }

    /// Build a minimal `ObjectExport` for the `carve_export_slice`
    /// helper tests below. All fields except `serial_offset` and
    /// `serial_size` are stubbed to neutral / `Null` values — the
    /// helper only inspects offset/size.
    fn make_carve_export(serial_offset: i64, serial_size: i64) -> ObjectExport {
        use crate::asset::package_index::PackageIndex;
        ObjectExport {
            class_index: PackageIndex::Null,
            super_index: PackageIndex::Null,
            template_index: PackageIndex::Null,
            outer_index: PackageIndex::Null,
            object_name: 0,
            object_name_number: 0,
            object_flags: 0,
            serial_offset,
            serial_size,
            forced_export: false,
            not_for_client: false,
            not_for_server: false,
            package_guid: None,
            is_inherited_instance: None,
            package_flags: 0,
            not_always_loaded_for_editor_game: false,
            is_asset: false,
            generate_public_hash: None,
            script_serialization_start_offset: None,
            script_serialization_end_offset: None,
            first_export_dependency: -1,
            serialization_before_serialization_count: 0,
            create_before_serialization_count: 0,
            serialization_before_create_count: 0,
            create_before_create_count: 0,
        }
    }

    /// Direct unit test on `carve_export_slice` — exercises the
    /// `end > asset_size` branch the helper shares between
    /// `read_payloads` and the Phase 2f unversioned branch. Without a
    /// test that targets the helper directly, the two call sites
    /// share coverage only through whichever integration test happens
    /// to drive each path (the unversioned branch's bounds-check has
    /// no integration-test coverage today). Architect retro on PR
    /// `chore/retro-review-batch`.
    #[test]
    fn carve_export_slice_rejects_offset_plus_size_past_buffer() {
        let bytes = vec![0u8; 100];
        let export = make_carve_export(80, 40); // 80 + 40 = 120 > 100
        let err = carve_export_slice(&bytes, &export, "x.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidOffset {
                        field: AssetWireField::ExportSerialOffset,
                        offset: 80,
                        asset_size: 100,
                    },
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    /// Companion to the bounds-past-buffer test: confirms the
    /// `serial_size > MAX_PAYLOAD_BYTES` cap fires on the helper
    /// (same cap both call sites share).
    #[test]
    fn carve_export_slice_rejects_serial_size_over_cap() {
        let bytes = vec![0u8; 16];
        #[allow(clippy::cast_possible_wrap)]
        let oversized = (MAX_PAYLOAD_BYTES as i64) + 1;
        let export = make_carve_export(0, oversized);
        let err = carve_export_slice(&bytes, &export, "x.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::ExportSerialSize,
                        unit: BoundsUnit::Bytes,
                        ..
                    },
                    ..
                }
            ),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn rejects_export_payload_past_eof() {
        // Phase 2e: with the companion-file detection in place, a
        // monolithic-shape truncated asset trips `MissingCompanionFile`
        // first (any payload extending past `uasset.len()` is now
        // treated as a split-asset hint). To exercise the original
        // `InvalidOffset` path inside `read_payloads`, split the fixture
        // into header + truncated-uexp so companion detection sees the
        // uexp and the `end > asset_size` check in `read_payloads`
        // fires on the post-stitch buffer length.
        let pkg = build_minimal_ue4_27();
        #[allow(
            clippy::cast_sign_loss,
            reason = "total_header_size is non-negative by construction"
        )]
        let split_at = pkg.summary.total_header_size as usize;
        let uasset = pkg.bytes[..split_at].to_vec();
        let mut uexp = pkg.bytes[split_at..].to_vec();
        // Truncate 8 bytes off the end of the payload region so the
        // stitched buffer is short of what the export table claims.
        uexp.truncate(uexp.len() - 8);
        let err = Package::read_from(&uasset, Some(&uexp), None, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::InvalidOffset {
                        field: AssetWireField::ExportSerialOffset,
                        ..
                    },
                    ..
                }
            ),
            "expected InvalidOffset(ExportSerialOffset); got {err:?}"
        );
    }

    #[test]
    // MAX_PAYLOAD_BYTES (256 MiB) + 1 fits comfortably in i64.
    #[allow(clippy::cast_possible_wrap)]
    fn rejects_export_payload_exceeding_max_payload_bytes() {
        // Defense-in-depth: a single export claiming a payload larger
        // than MAX_PAYLOAD_BYTES is rejected at the cap check before
        // any byte read or allocation. The synthesized bytes are tiny
        // (no 256 MiB allocation needed) because the check fires on
        // the wire-claimed `serial_size`, not on the asset's actual
        // length.
        //
        // Phase 2e: with companion detection, a 256-MiB `serial_size`
        // also pushes `end > uasset.len()` and trips
        // `MissingCompanionFile` first when fed as a monolithic blob.
        // Split into header + tiny-uexp so detection is satisfied and
        // execution reaches `read_payloads` — where the actual
        // `MAX_PAYLOAD_BYTES` cap check lives and the test's intent
        // applies.
        use crate::asset::export_table::EXPORT_RECORD_SIZE_UE4_27;

        let MinimalPackage {
            mut bytes,
            mut exports,
            summary,
            ..
        } = build_minimal_ue4_27();
        // Push the wire-claimed size one byte past the cap. The
        // serial_offset stays valid (still points at end-of-header);
        // the cap check fires before the offset+size bounds check.
        exports.exports[0].serial_size = MAX_PAYLOAD_BYTES as i64 + 1;
        let mut export_buf = Vec::new();
        exports
            .write_to(&mut export_buf, summary.version, summary.package_flags)
            .unwrap();
        assert_eq!(export_buf.len(), EXPORT_RECORD_SIZE_UE4_27);
        // summary.export_offset is set by the fixture builder to the
        // header's end position — always positive in this test.
        #[allow(clippy::cast_sign_loss)]
        let export_offset = summary.export_offset as usize;
        bytes[export_offset..export_offset + EXPORT_RECORD_SIZE_UE4_27]
            .copy_from_slice(&export_buf);

        #[allow(
            clippy::cast_sign_loss,
            reason = "total_header_size is non-negative by construction"
        )]
        let split_at = summary.total_header_size as usize;
        let uasset = bytes[..split_at].to_vec();
        let uexp = bytes[split_at..].to_vec();

        let err = Package::read_from(&uasset, Some(&uexp), None, "test.uasset").unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::BoundsExceeded {
                        field: AssetWireField::ExportSerialSize,
                        unit: BoundsUnit::Bytes,
                        ..
                    },
                    ..
                }
            ),
            "expected BoundsExceeded(ExportSerialSize); got {err:?}"
        );
    }

    #[test]
    fn context_clones_cheaply() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = ctx_a.clone();
        assert!(Arc::ptr_eq(&ctx_a.names, &ctx_b.names));
    }

    /// Pins issue #369's `context()` contract: two separate
    /// `pkg.context()` calls (not `.clone()` of a single context)
    /// return `Arc::ptr_eq`-equal tables — refcount-shared with the
    /// `Arc<NameTable>`/`Arc<ImportTable>`/`Arc<ExportTable>` stored
    /// on `Package`, NOT deep-cloned per call. A regression that
    /// re-introduces `Arc::new((*self.names).clone())` would type-
    /// check and pass `context_clones_cheaply` (which only exercises
    /// the `Arc::clone` of a single ctx); this test fails on it.
    #[test]
    fn two_context_calls_share_arc_tables() {
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let ctx_a = pkg.context();
        let ctx_b = pkg.context();
        assert!(
            Arc::ptr_eq(&ctx_a.names, &ctx_b.names),
            "names: two context() calls must share the Arc, not deep-clone"
        );
        assert!(
            Arc::ptr_eq(&ctx_a.imports, &ctx_b.imports),
            "imports: two context() calls must share the Arc, not deep-clone"
        );
        assert!(
            Arc::ptr_eq(&ctx_a.exports, &ctx_b.exports),
            "exports: two context() calls must share the Arc, not deep-clone"
        );
    }

    #[test]
    fn context_preserves_mappings_passed_to_read_from() {
        // Phase 3+ format handlers reconstruct an `AssetContext` from
        // a parsed `Package` to drive secondary decode passes. The
        // mappings supplied to `Package::read_from` must persist —
        // dropping them would silently misparse unversioned assets
        // downstream.
        use crate::testing::usmap::build_minimal_usmap_bytes;
        let usmap = Usmap::from_bytes(&build_minimal_usmap_bytes()).expect("Usmap parse");
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, Some(&usmap), "test.uasset").unwrap();
        let ctx = pkg.context();
        assert!(
            ctx.mappings.is_some(),
            "mappings supplied to read_from must survive into context()"
        );
        // Pointer-equality on the second clone: the stored Arc<Usmap>
        // is reused, not deep-cloned per context() call.
        let ctx_b = pkg.context();
        let (a, b) = (
            ctx.mappings.as_ref().unwrap(),
            ctx_b.mappings.as_ref().unwrap(),
        );
        assert!(
            Arc::ptr_eq(a, b),
            "two context() calls must share the same Arc<Usmap>"
        );
    }

    #[test]
    fn serialize_emits_per_export_asset_wrapper_with_externally_tagged_generic() {
        // Phase 3 deliverable JSON shape: each export carries its own
        // `asset` field rendering the typed Asset variant under an
        // externally-tagged shape. For the minimal fixture's 0xAA
        // bytes (which trigger negative-FName rejection in
        // read_properties → Opaque fallback), the per-export field
        // is `"asset": {"Generic": {"kind": "opaque", "bytes": 16}}`.
        // Pinned so a future Serialize refactor can't silently
        // regress the Phase-3 contract.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let json = serde_json::to_string(&pkg).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Top-level scalar removed (Phase 2b guarantee, still holds).
        assert!(
            parsed.get("payload_bytes").is_none(),
            "top-level payload_bytes must not be emitted; got: {json}"
        );
        // Top-level payloads array still absent (Phase 2a guarantee).
        assert!(
            parsed.get("payloads").is_none(),
            "top-level payloads array must not be emitted; got: {json}"
        );
        // Per-export `asset` field present (Phase 3 shape).
        assert!(
            parsed["exports"][0].get("asset").is_some(),
            "per-export asset must be present; got: {json}"
        );
        // Externally-tagged Generic with inner PropertyBag::Opaque.
        assert_eq!(
            parsed["exports"][0]["asset"]["Generic"]["kind"], "opaque",
            "expected per-export asset.Generic.kind = 'opaque'; got: {json}"
        );
        assert_eq!(
            parsed["exports"][0]["asset"]["Generic"]["bytes"], 16,
            "expected per-export asset.Generic.bytes = 16; got: {json}"
        );
    }

    #[test]
    fn serialize_resolves_fname_references_in_imports_and_exports() {
        // Phase 2a follow-up: the package-level Serialize emits
        // resolved FName strings for imports/exports (matching the
        // plan's Deliverable example), distinct from the type-level
        // Serialize impls which emit raw u32 indices for debugging
        // an isolated record.
        //
        // The minimal UE4.27 fixture has names = ["/Script/CoreUObject",
        // "Package", "Default__Object"]; its single import points
        // class_package=0, class_name=1, object_name=2 → resolved
        // strings below.
        let MinimalPackage { bytes, .. } = build_minimal_ue4_27();
        let pkg = Package::read_from(&bytes, None, None, "test.uasset").unwrap();
        let json = serde_json::to_string(&pkg).unwrap();

        // Resolved import — bare strings, no raw `class_package_name:0`
        // / `class_package_number:0` field pair.
        assert!(
            json.contains(r#""class_package":"/Script/CoreUObject""#),
            "got: {json}"
        );
        assert!(json.contains(r#""class_name":"Package""#), "got: {json}");
        assert!(
            json.contains(r#""object_name":"Default__Object""#),
            "got: {json}"
        );
        assert!(
            !json.contains(r#""class_package_name":"#),
            "raw index field must not leak into package-level JSON; got: {json}"
        );
        assert!(
            !json.contains(r#""class_package_number":"#),
            "raw number field must not leak into package-level JSON; got: {json}"
        );
        assert!(
            !json.contains(r#""object_name_number":"#),
            "raw number field must not leak into package-level JSON; got: {json}"
        );
    }

    // Phase 3b Task 6: storage-shape + accessor coverage for the
    // `bulk_data` map and `resolver` field on `Package`. The 3e/3g/3h
    // typed-reader sites that actually populate the map land later;
    // these tests pin the shape so the resolver + cap-enforcement +
    // OnceLock caching all behave as the plan describes BEFORE the
    // downstream sub-phases consume the surface.

    #[test]
    fn read_from_initializes_empty_bulk_data_and_resolver() {
        // Phase 3b ships the storage shape empty; 3e/3g/3h drive the
        // typed-reader dispatch sites to populate per-export records.
        let pkg = build_minimal_ue4_27();
        let parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        assert!(
            parsed.bulk_data.is_empty(),
            "bulk_data must be empty on read_from"
        );
        // Resolver is constructed — `Arc::strong_count >= 1` and the
        // stitched-buffer accessor (via Debug) confirms it holds the
        // input bytes.
        let dbg = format!("{:?}", parsed.resolver);
        assert!(
            dbg.contains("BulkDataResolver"),
            "resolver Debug rendering missing; got: {dbg}"
        );
    }

    #[test]
    fn resolve_bulk_for_export_returns_empty_for_unregistered_index() {
        // Missing key → empty slice, not an error. 3e/3g/3h's
        // typed readers only call `insert_bulk_records` for the
        // export indices that actually carry FByteBulkData records;
        // any other export must resolve to the empty slice.
        let pkg = build_minimal_ue4_27();
        let parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let bulk = parsed.resolve_bulk_for_export(0).unwrap();
        assert!(bulk.is_empty());
        // Out-of-range indices are also empty (not an error — the
        // accessor is forgiving since `HashMap::get(&k)` returns
        // `None` for any unregistered key).
        let bulk_oob = parsed.resolve_bulk_for_export(9_999).unwrap();
        assert!(bulk_oob.is_empty());
    }

    #[test]
    fn insert_bulk_records_empty_is_noop() {
        // Empty Vec into a fresh slot: no HashMap entry. Matches the
        // contract that "no records" and "no entry" are observably
        // equivalent.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        parsed.insert_bulk_records(0, Vec::new()).unwrap();
        assert!(
            parsed.bulk_data.is_empty(),
            "empty insert must not create a HashMap entry"
        );
        assert!(parsed.resolve_bulk_for_export(0).unwrap().is_empty());
    }

    #[test]
    fn insert_bulk_records_empty_removes_prior_records() {
        // Contract: "no records present == no entry". An empty
        // re-insert after a non-empty one must REMOVE the prior
        // records, not silently preserve them — otherwise the
        // documented invariant breaks and `resolve_bulk_for_export`
        // would re-surface stale payload bytes from the prior parse.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let records = vec![FByteBulkData {
            flags: crate::asset::bulk_data::BulkDataFlags::from(0u32),
            element_count: 0,
            size_on_disk: 0,
            offset_in_file: 0,
        }];
        parsed.insert_bulk_records(3, records).unwrap();
        assert!(parsed.bulk_data.contains_key(&3));
        parsed.insert_bulk_records(3, Vec::new()).unwrap();
        assert!(
            !parsed.bulk_data.contains_key(&3),
            "empty re-insert must remove the prior entry to preserve the no-records==no-entry invariant"
        );
        assert!(parsed.resolve_bulk_for_export(3).unwrap().is_empty());
    }

    #[test]
    fn insert_bulk_records_over_cap_rejected() {
        // Defensive cap at the insertion boundary — the plan's
        // Design Decision #15. Even though the per-record cap also
        // exists in the typed-reader sites, any future class that
        // routes through `insert_bulk_records` is gated here too.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();

        // Construct (MAX + 1) trivially-zero records. The cap-check
        // fires on `len()` — record content is irrelevant.
        let oversized = vec![
            FByteBulkData {
                flags: crate::asset::bulk_data::BulkDataFlags::from(0u32),
                element_count: 0,
                size_on_disk: 0,
                offset_in_file: 0,
            };
            MAX_BULK_DATA_RECORDS_PER_EXPORT + 1
        ];
        let err = parsed.insert_bulk_records(7, oversized).unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault: AssetParseFault::BulkDataRecordsExceeded { count, cap },
                ..
            } => {
                assert_eq!(count, MAX_BULK_DATA_RECORDS_PER_EXPORT + 1);
                assert_eq!(cap, MAX_BULK_DATA_RECORDS_PER_EXPORT);
            }
            other => panic!("expected BulkDataRecordsExceeded, got {other:?}"),
        }
        // Rejected insert must not partially populate the map.
        assert!(!parsed.bulk_data.contains_key(&7));
    }

    #[test]
    fn insert_bulk_records_at_cap_accepted() {
        // Boundary test: exactly MAX records is OK; only MAX + 1
        // is rejected. Pinpoints the `<=` vs `<` boundary against
        // off-by-one mutations.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let at_cap = vec![
            FByteBulkData {
                flags: crate::asset::bulk_data::BulkDataFlags::from(0u32),
                element_count: 0,
                size_on_disk: 0,
                offset_in_file: 0,
            };
            MAX_BULK_DATA_RECORDS_PER_EXPORT
        ];
        parsed.insert_bulk_records(2, at_cap).unwrap();
        assert!(parsed.bulk_data.contains_key(&2));
        assert_eq!(
            parsed.bulk_data.get(&2).unwrap().0.len(),
            MAX_BULK_DATA_RECORDS_PER_EXPORT
        );
    }

    #[test]
    fn insert_bulk_records_for_test_mirrors_pub_crate_path() {
        // Phase 3b Task 7: pin the `__test_utils`-gated public
        // accessor against a `Ok(())` whole-function mutant. The
        // wrapper delegates verbatim to `insert_bulk_records`, so
        // any mutation that no-ops the delegate would lose the
        // HashMap mutation that this assertion observes. The
        // out-of-crate integration tests in `paksmith-core-tests`
        // also call this accessor but cargo-mutants only runs the
        // own-crate test binary, so this inline pin is required.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let records = vec![FByteBulkData {
            flags: crate::asset::bulk_data::BulkDataFlags::from(0u32),
            element_count: 0,
            size_on_disk: 0,
            offset_in_file: 0,
        }];
        parsed.insert_bulk_records_for_test(5, records).unwrap();
        assert!(
            parsed.bulk_data.contains_key(&5),
            "insert_bulk_records_for_test must populate bulk_data identically to the pub(crate) path"
        );
        assert_eq!(parsed.bulk_data.get(&5).unwrap().0.len(), 1);
        // Mirror the empty-removes-prior invariant too.
        parsed.insert_bulk_records_for_test(5, Vec::new()).unwrap();
        assert!(
            !parsed.bulk_data.contains_key(&5),
            "empty insert via test accessor must remove the prior entry (delegated semantics)"
        );
    }

    #[test]
    fn check_uexp_size_at_cap_accepted() {
        // Boundary: exactly MAX_UEXP_SIZE is OK. Pins the `<=`
        // semantics — kills the `> with ==` cargo-mutants mutant
        // (which would make EQUAL trigger the rejection).
        check_uexp_size(MAX_UEXP_SIZE, "test.uasset").unwrap();
    }

    #[test]
    fn check_uexp_size_at_zero_accepted() {
        // Trivial accept boundary — pins that the bare 0 case
        // doesn't trip any sign-related mutation.
        check_uexp_size(0, "test.uasset").unwrap();
    }

    #[test]
    fn check_uexp_size_above_cap_rejected() {
        // Boundary: MAX_UEXP_SIZE + 1 is rejected. Kills the
        // `> with >=` mutant — the mutated check would still fire
        // for `>=`, but combined with `at_cap_accepted` it pins the
        // exact `>` semantics.
        let err = check_uexp_size(MAX_UEXP_SIZE + 1, "test.uasset").unwrap_err();
        match err {
            PaksmithError::AssetParse {
                fault:
                    AssetParseFault::BoundsExceeded {
                        field: AssetWireField::UexpSize,
                        value,
                        limit,
                        unit: BoundsUnit::Bytes,
                    },
                ..
            } => {
                assert_eq!(value, MAX_UEXP_SIZE as u64 + 1);
                assert_eq!(limit, MAX_UEXP_SIZE as u64);
            }
            other => panic!("expected BoundsExceeded(UexpSize), got {other:?}"),
        }
    }

    #[test]
    fn resolve_bulk_for_export_propagates_per_record_error() {
        // Pins that `resolve_bulk_for_export` actually walks records
        // and propagates per-record resolver errors — closes the
        // cargo-mutants gap where the whole function body could be
        // replaced with `Ok(&[])` and tests still passed.
        //
        // Streaming-tier record (FLAG_PAYLOAD_IN_SEPARATE_FILE =
        // 0x100; private constant in `bulk_data.rs` — reproduced as
        // a literal here). `read_from`'s stub loaders fire
        // MissingCompanionFile, so the resolver's per-record
        // resolve() routes through `ubulk()` and surfaces the
        // typed fault.
        let pkg = build_minimal_ue4_27();
        let mut parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let streaming_record = FByteBulkData {
            flags: crate::asset::bulk_data::BulkDataFlags::from(0x0000_0100u32),
            element_count: 8,
            size_on_disk: 8,
            offset_in_file: 0,
        };
        parsed
            .insert_bulk_records(0, vec![streaming_record])
            .unwrap();
        let err = parsed.resolve_bulk_for_export(0).unwrap_err();
        assert!(
            matches!(
                err,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::MissingCompanionFile {
                        kind: CompanionFileKind::Ubulk,
                    },
                    ..
                }
            ),
            "expected MissingCompanionFile(Ubulk), got {err:?}"
        );
        // Failure must NOT be cached — a transient I/O failure
        // shouldn't poison the export forever. Verify by calling
        // again and expecting the same error class to fire.
        let err2 = parsed.resolve_bulk_for_export(0).unwrap_err();
        assert!(
            matches!(
                err2,
                PaksmithError::AssetParse {
                    fault: AssetParseFault::MissingCompanionFile { .. },
                    ..
                }
            ),
            "second call must also error (errors are not cached); got {err2:?}"
        );
    }

    #[test]
    fn package_is_clone_and_resolver_shared_via_arc() {
        // `Package: Clone` is load-bearing for the GUI (Phase 7
        // event-loop ticks clone Packages across thread boundaries).
        // The resolver must be `Arc`-shared, NOT deep-copied, or
        // each clone's fresh `bytes_resolved` counter would
        // effectively multiply the 16 GiB cap.
        let pkg = build_minimal_ue4_27();
        let parsed = Package::read_from(&pkg.bytes, None, None, "test.uasset").unwrap();
        let cloned = parsed.clone();
        assert!(
            Arc::ptr_eq(&parsed.resolver, &cloned.resolver),
            "Package::clone must share the resolver via Arc, not deep-copy"
        );
    }
}
