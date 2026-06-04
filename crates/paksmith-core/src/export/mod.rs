//! Phase 3 export pipeline. Converts parsed UE assets into target
//! interchange formats (PNG, glTF, WAV, CSV, JSON).
//!
//! The pipeline has two layers:
//!
//! 1. **Parse-time specialization** (in `asset/exports/`, lands in
//!    Phase 3a Task 4) — each export's class name dispatches to a
//!    typed reader. Phase 3a's dispatch table starts empty; 3d-3h
//!    populate it.
//! 2. **Export-time format handlers** (this module) — typed
//!    [`crate::asset::Asset`] values feed [`FormatHandler`] impls
//!    that produce target-format bytes. Registry is discriminant-keyed
//!    (`Discriminant<Asset>`); handlers register against the variant
//!    they serve.
//!
//! Phase 3a Task 2 ships the trait + registry skeleton only. Task 3
//! adds the `Generic` handler that wraps Phase 2's `PropertyBag`
//! shape as JSON. Tasks 4 + 5 wire the class-name dispatch + public
//! re-exports.
//!
//! See `docs/plans/phase-3-export-pipeline.md` and
//! `docs/plans/phase-3a-format-handler-trait.md` for the full plan.
//!
//! # Quick start
//!
//! ```rust
//! use paksmith_core::{Asset, HandlerRegistry, PropertyBag};
//!
//! // The default registry pre-registers every Phase-3-defined handler.
//! // Phase 3a Task 3 ships GenericHandler; 3d-3h extend additively.
//! let reg = HandlerRegistry::all_default_handlers();
//!
//! // Phase 2 closure yields Asset::Generic; Phase 3 sub-phases add
//! // typed variants (DataTable, Texture2D, etc.) under the same
//! // #[non_exhaustive] enum.
//! let asset = Asset::Generic(PropertyBag::opaque(vec![0u8; 4]));
//!
//! // Find the matching handler by Asset variant discriminant.
//! // Load-bearing: `.expect(...)` panics if a regression drops
//! // `GenericHandler` from `all_default_handlers()`.
//! let handler = reg
//!     .find_handler(&asset)
//!     .expect("default registry registers GenericHandler for Asset::Generic");
//! let bytes = handler.export(&asset, &[]).expect("export");
//! let ext = handler.output_extension(); // "json" for GenericHandler
//! // Caller writes `bytes` to `<path>.<ext>`.
//! assert_eq!(ext, "json");
//! assert!(!bytes.is_empty());
//! ```

use std::collections::HashMap;
use std::mem::Discriminant;

use crate::asset::Asset;
pub use crate::asset::bulk_data::BulkData;

// Private — handlers are re-exported below. Phase 3d-3h handler
// submodules follow the same `mod <name>;` + `pub use
// <name>::<Handler>;` pattern.
mod data_table;
mod generic;
mod texture;

pub use data_table::{DataTableCsvHandler, DataTableJsonHandler};
pub use generic::GenericHandler;
pub use texture::PngHandler;

/// Converts a typed [`Asset`] plus optional bulk data into
/// target-format bytes. Handlers are **stateless and side-effect-free**.
///
/// The registry stores `Box<dyn FormatHandler>` — the trait is
/// object-safe by construction (no generic methods, no associated
/// types with `Self` bounds, `&self` everywhere).
///
/// # Sub-variant dispatch
///
/// The registry filters by [`Asset`] variant via
/// [`std::mem::Discriminant`] before consulting [`Self::supports`];
/// the `supports` check is only consulted within the per-variant
/// bucket to disambiguate among handlers serving the same variant
/// (e.g. OGG vs OPUS vs PCM handlers for `Asset::SoundWave` in 3f,
/// CSV vs JSON for `Asset::DataTable` in 3d). Handlers that don't
/// care about sub-variants return `true` unconditionally — the
/// discriminant filter already ensures the variant is correct.
///
/// # Example
///
/// ```rust,no_run
/// use paksmith_core::export::{FormatHandler, HandlerRegistry};
/// use paksmith_core::asset::Asset;
///
/// fn pick_extension(reg: &HandlerRegistry, asset: &Asset) -> &'static str {
///     reg.find_handler(asset)
///         .map(|h| h.output_extension())
///         .unwrap_or("bin")
/// }
/// ```
pub trait FormatHandler: Send + Sync {
    /// File extension for the produced output (e.g. `"png"`, `"gltf"`,
    /// `"csv"`). No leading dot.
    fn output_extension(&self) -> &'static str;

    /// Sub-variant support check. See trait-level docs.
    fn supports(&self, asset: &Asset) -> bool;

    /// Convert `asset` (+ its resolved bulk records) into output bytes.
    ///
    /// `bulk` is the export's full resolved bulk-record slice (from
    /// `Package::resolve_bulk_for_export`); the handler selects what it needs —
    /// a texture picks its mip, a virtual texture indexes its chunk payloads.
    /// Pass `&[]` for assets with no bulk data (e.g. data tables).
    ///
    /// # Errors
    /// Any [`crate::PaksmithError`] from the format's encode path.
    /// A handler that returned `true` from [`Self::supports`] for
    /// this asset MUST NOT return a `MismatchedAsset`-style error
    /// from `export` — that's a registry contract violation.
    /// Phase 3a Task 3 introduces a `PaksmithError::Internal`
    /// variant specifically for surfacing such violations from
    /// the `Generic` handler.
    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>>;
}

/// Registry of format handlers keyed by [`Asset`] variant
/// discriminant. Within each variant's bucket, handlers are walked
/// in registration order; the first whose [`FormatHandler::supports`]
/// returns `true` wins.
///
/// Use [`HandlerRegistry::new`] for an empty registry; Phase 3a
/// Task 3 adds an `all_default_handlers()` constructor that
/// pre-registers the `Generic` handler. Each Phase 3 sub-phase
/// (3d-3h) extends that constructor additively.
pub struct HandlerRegistry {
    by_variant: HashMap<Discriminant<Asset>, Vec<Box<dyn FormatHandler>>>,
}

impl HandlerRegistry {
    /// Empty registry — register handlers explicitly.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_variant: HashMap::new(),
        }
    }

    /// Registry pre-populated with every Phase-3-defined handler
    /// across 3a-3h. Sub-phases extend this function additively;
    /// callers wanting a subset use [`Self::new`] + explicit
    /// [`Self::register`] calls.
    ///
    /// Phase 3a Task 3: registers [`GenericHandler`] only. Phase
    /// 3d-3h each add their handler(s) here. Sentinel-Asset
    /// construction is inline at each registration site — no
    /// per-variant `register_for_<variant>` helper cascade.
    #[must_use]
    pub fn all_default_handlers() -> Self {
        use crate::asset::property::bag::PropertyBag;
        let mut reg = Self::new();

        // Asset::Generic — sentinel uses the cheapest PropertyBag
        // (empty Opaque, zero-allocation). Discriminant comparison
        // ignores the payload.
        let generic_sentinel = Asset::Generic(PropertyBag::opaque(Vec::new()));
        reg.register(
            std::mem::discriminant(&generic_sentinel),
            Box::new(GenericHandler),
        );

        // Phase 3d — UDataTable. CSV is registered FIRST so it's the
        // `find_handler` default for an `Asset::DataTable` (rows are
        // the high-priority extraction target per the format doc);
        // JSON is reached via `find_handler_by_extension("json", …)`.
        // The sentinel uses `DataTableData::empty()` (zero-allocation;
        // `discriminant` ignores the payload). See 3a Design Decision
        // #14: each typed inner type exposes a cheap `empty()`.
        let dt_sentinel = Asset::DataTable(crate::asset::DataTableData::empty());
        let dt_disc = std::mem::discriminant(&dt_sentinel);
        reg.register(dt_disc, Box::new(DataTableCsvHandler));
        reg.register(dt_disc, Box::new(DataTableJsonHandler));

        // Phase 3e-8 — UTexture2D PNG export. Sentinel uses
        // `Texture2DData::empty()` (zero-allocation; `discriminant` ignores the
        // payload). Single PngHandler for the variant, so `supports` is
        // unconditional within the bucket.
        let tex_sentinel = Asset::Texture2D(crate::asset::Texture2DData::empty());
        reg.register(std::mem::discriminant(&tex_sentinel), Box::new(PngHandler));

        // 3f-3h add their handlers here the same way.
        reg
    }

    /// Register a handler under a specific [`Asset`] variant
    /// discriminant. Callers obtain the discriminant via
    /// `std::mem::discriminant(&Asset::SomeVariant(sentinel))`. The
    /// sentinel's payload is never read — discriminant comparison
    /// ignores it.
    ///
    /// No removal API. Handlers register once at startup; Phase 3
    /// has no use case for dynamic registration / unregistration.
    pub fn register(&mut self, variant: Discriminant<Asset>, handler: Box<dyn FormatHandler>) {
        self.by_variant.entry(variant).or_default().push(handler);
    }

    /// Find the first registered handler for `asset`'s variant whose
    /// [`FormatHandler::supports`] returns `true`. O(1) variant
    /// lookup + linear scan within bucket (typical: 1-3 handlers per
    /// variant). Returns `None` if no handler is registered for the
    /// asset's variant, OR if every registered handler's `supports`
    /// returned `false` (sub-variant mismatch).
    #[must_use]
    pub fn find_handler(&self, asset: &Asset) -> Option<&dyn FormatHandler> {
        let disc = std::mem::discriminant(asset);
        self.by_variant.get(&disc).and_then(|bucket| {
            bucket
                .iter()
                .find(|h| h.supports(asset))
                .map(std::convert::AsRef::as_ref)
        })
    }

    /// Find a handler whose [`FormatHandler::supports`] returns `true`
    /// for `asset` AND whose [`FormatHandler::output_extension`] equals
    /// `extension`. Use when the caller wants a specific output
    /// format (e.g. CSV vs JSON for a DataTable in 3d).
    #[must_use]
    pub fn find_handler_by_extension(
        &self,
        extension: &str,
        asset: &Asset,
    ) -> Option<&dyn FormatHandler> {
        let disc = std::mem::discriminant(asset);
        self.by_variant.get(&disc).and_then(|bucket| {
            bucket
                .iter()
                .find(|h| h.supports(asset) && h.output_extension() == extension)
                .map(std::convert::AsRef::as_ref)
        })
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::property::bag::PropertyBag;

    /// Mock handler for registry contract tests. Returns
    /// configurable `supports` + `output_extension` so the registry's
    /// per-bucket linear-scan + extension-filter paths can be
    /// pinned independently of any production handler.
    struct MockHandler {
        ext: &'static str,
        supports_value: bool,
    }
    impl FormatHandler for MockHandler {
        fn output_extension(&self) -> &'static str {
            self.ext
        }
        fn supports(&self, _asset: &Asset) -> bool {
            self.supports_value
        }
        fn export(&self, _asset: &Asset, _bulk: &[BulkData]) -> crate::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn generic_sentinel() -> Asset {
        Asset::Generic(PropertyBag::opaque(Vec::new()))
    }

    #[test]
    fn registry_new_finds_nothing() {
        // Empty registry returns None for any asset variant.
        let reg = HandlerRegistry::new();
        assert!(reg.find_handler(&generic_sentinel()).is_none());
    }

    #[test]
    fn registry_register_then_find_returns_handler() {
        // After register, find_handler returns the handler when
        // supports() is true for the asset's variant.
        let mut reg = HandlerRegistry::new();
        let asset = generic_sentinel();
        let disc = std::mem::discriminant(&asset);
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "json",
                supports_value: true,
            }),
        );
        let handler = reg.find_handler(&asset).expect("registered handler");
        assert_eq!(handler.output_extension(), "json");
    }

    #[test]
    fn registry_skips_supports_false_in_favor_of_later_handler() {
        // Within a per-variant bucket, the registry walks in
        // registration order; a handler whose supports returns false
        // is skipped in favor of the next handler that returns true.
        let mut reg = HandlerRegistry::new();
        let asset = generic_sentinel();
        let disc = std::mem::discriminant(&asset);
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "first",
                supports_value: false,
            }),
        );
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "second",
                supports_value: true,
            }),
        );
        let handler = reg.find_handler(&asset).expect("second handler");
        assert_eq!(
            handler.output_extension(),
            "second",
            "registry should skip the supports=false handler and return the next"
        );
    }

    #[test]
    fn registry_find_by_extension_filters_correctly() {
        // find_handler_by_extension returns the handler matching
        // both the variant AND the requested extension.
        let mut reg = HandlerRegistry::new();
        let asset = generic_sentinel();
        let disc = std::mem::discriminant(&asset);
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "csv",
                supports_value: true,
            }),
        );
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "json",
                supports_value: true,
            }),
        );
        assert_eq!(
            reg.find_handler_by_extension("csv", &asset)
                .expect("csv handler")
                .output_extension(),
            "csv"
        );
        assert_eq!(
            reg.find_handler_by_extension("json", &asset)
                .expect("json handler")
                .output_extension(),
            "json"
        );
        assert!(
            reg.find_handler_by_extension("yaml", &asset).is_none(),
            "non-registered extension must return None"
        );
    }

    #[test]
    fn registry_all_default_handlers_matches_generic() {
        // The default registry pre-registers GenericHandler. An
        // Asset::Generic should resolve to GenericHandler (output
        // extension "json").
        let reg = HandlerRegistry::all_default_handlers();
        let asset = generic_sentinel();
        let handler = reg
            .find_handler(&asset)
            .expect("default registry must have a GenericHandler for Asset::Generic");
        assert_eq!(handler.output_extension(), "json");
    }

    #[test]
    fn registry_find_by_extension_skips_supports_false() {
        // find_handler_by_extension still respects supports() —
        // a handler with matching extension but supports=false
        // is skipped.
        let mut reg = HandlerRegistry::new();
        let asset = generic_sentinel();
        let disc = std::mem::discriminant(&asset);
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "csv",
                supports_value: false,
            }),
        );
        assert!(
            reg.find_handler_by_extension("csv", &asset).is_none(),
            "supports=false handler must be skipped even when extension matches"
        );
    }
}
