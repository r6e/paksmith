//! Phase 3 export pipeline. Converts parsed UE assets into target
//! interchange formats (PNG, glTF, WAV, OGG, CSV, JSON).
//!
//! The pipeline has two layers:
//!
//! 1. **Parse-time specialization** (in `asset/exports/`) — each
//!    export's class name dispatches to a typed reader that produces a
//!    typed [`crate::asset::Asset`] variant (DataTable, Texture2D,
//!    SoundWave, StaticMesh, SkeletalMesh).
//! 2. **Export-time format handlers** (this module) — typed
//!    [`crate::asset::Asset`] values feed [`FormatHandler`] impls
//!    that produce target-format bytes. The registry is
//!    discriminant-keyed (`Discriminant<Asset>`); handlers register
//!    against the variant they serve.
//!
//! [`HandlerRegistry::all_default_handlers`] pre-registers every shipped
//! handler: `GenericHandler` (property-bag JSON), `PngHandler`,
//! `GltfStaticMeshHandler`, `GltfSkeletalMeshHandler`, the WAV/OGG audio
//! handlers, and the DataTable CSV/JSON handlers.
//!
//! See `docs/plans/phase-3-export-pipeline.md` for the full design.
//!
//! # Quick start
//!
//! ```rust
//! use paksmith_core::{Asset, HandlerRegistry, PropertyBag};
//!
//! // The default registry pre-registers every shipped handler.
//! let reg = HandlerRegistry::all_default_handlers();
//!
//! // A property-bag export yields Asset::Generic; typed export readers
//! // produce the other variants (DataTable, Texture2D, etc.) under the
//! // same #[non_exhaustive] enum.
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
use crate::asset::Package;
pub use crate::asset::bulk_data::BulkData;

// Private — handlers are re-exported below. Phase 3d-3h handler
// submodules follow the same `mod <name>;` + `pub use
// <name>::<Handler>;` pattern.
mod adpcm;
mod audio;
mod data_table;
mod generic;
mod gltf_common;
mod pcm;
mod skeletal_mesh;
mod static_mesh;
mod texture;
mod vorbis;

pub use audio::{OggHandler, RawSoundHandler, VorbisHandler, WavHandler};
pub use data_table::{DataTableCsvHandler, DataTableJsonHandler};
pub use generic::GenericHandler;
#[cfg(feature = "__test_utils")]
pub use pcm::max_audio_decoded_bytes;
pub use skeletal_mesh::GltfSkeletalMeshHandler;
pub use static_mesh::GltfStaticMeshHandler;
pub use texture::{PngCompression, PngHandler};

// Audio transcoders, surfaced to the `__test_utils` bench/fuzz seams in
// `testing::bench` (the `adpcm` / `vorbis` modules are private, so the
// `pub(crate)` fns aren't otherwise nameable from outside `export`).
// Production code reaches them via the in-module path.
#[cfg(feature = "__test_utils")]
pub(crate) use adpcm::transcode_adpcm_to_pcm;
#[cfg(feature = "__test_utils")]
pub(crate) use vorbis::transcode_vorbis_to_pcm;

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
    /// `PaksmithError::Internal` exists specifically for surfacing
    /// such violations (e.g. from the `Generic` handler).
    fn export(&self, asset: &Asset, bulk: &[BulkData]) -> crate::Result<Vec<u8>>;
}

/// Registry of format handlers keyed by [`Asset`] variant
/// discriminant. Within each variant's bucket, handlers are walked
/// in registration order; the first whose [`FormatHandler::supports`]
/// returns `true` wins.
///
/// Use [`HandlerRegistry::new`] for an empty registry, or
/// [`HandlerRegistry::all_default_handlers`] for one pre-registered with
/// every shipped handler (the `Generic` property-bag handler plus the
/// Phase 3 texture / mesh / audio / data-table handlers).
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
        // `PngHandler::default()` = `Balanced` compression, preserving the prior
        // fixed behavior. The registry always registers the default level; a
        // caller wanting a different level constructs
        // `PngHandler::with_compression(level)` and calls `.export()` directly
        // (the handler is the unit of work — the registry is just dispatch). Wiring
        // a chosen level *through* the registry for the bulk-extract pipeline is
        // deferred to Phase 4, which owns the extract-options model (a `--compression`
        // flag flowing into a per-export options struct, not a PNG-special-cased
        // registry constructor here).
        reg.register(
            std::mem::discriminant(&tex_sentinel),
            Box::new(PngHandler::default()),
        );

        // Phase 3f — USoundWave audio export. Sentinel uses
        // `SoundWaveData::empty()` (zero-allocation; `discriminant` ignores the
        // payload). Handlers claim codec sets via `supports`: `OggHandler` and
        // `VorbisHandler` both serve `"OGG"` (verbatim `.ogg` passthrough vs
        // decoded `.wav`); `WavHandler` → `"PCM"` / `"ADPCM"` (.wav). `OggHandler`
        // is registered FIRST so it's the `find_handler` default for `"OGG"` (the
        // `.ogg` is already universally playable; decoding only adds size). The
        // decoded `.wav` is reached via `find_handler_by_extension("wav", …)`,
        // which skips `OggHandler` (`.ogg` extension) and `WavHandler` (its
        // `supports` rejects `"OGG"`), landing on `VorbisHandler`.
        //
        // The codecs paksmith does NOT decode — proprietary `"BINKA"` / `"XMA2"` /
        // `"AT9"` and the custom-framed UE Opus `"OPUS"` / `"OPUSNX"` — are claimed
        // by `RawSoundHandler` instances that pass the raw cooked buffer through
        // with a codec-appropriate extension (so the asset surfaces + is
        // extractable for an external tool, rather than `find_handler` returning
        // `None`). Their codec sets are disjoint from the OGG/WAV handlers', so
        // registration order among them is irrelevant.
        let sw_sentinel = Asset::SoundWave(crate::asset::SoundWaveData::empty());
        let sw_disc = std::mem::discriminant(&sw_sentinel);
        reg.register(sw_disc, Box::new(OggHandler));
        reg.register(sw_disc, Box::new(WavHandler));
        reg.register(sw_disc, Box::new(VorbisHandler));
        reg.register(sw_disc, Box::new(RawSoundHandler::new(&["BINKA"], "binka")));
        reg.register(sw_disc, Box::new(RawSoundHandler::new(&["XMA2"], "xma")));
        reg.register(sw_disc, Box::new(RawSoundHandler::new(&["AT9"], "at9")));
        // The UE Opus keys get distinct extensions, NOT `.opus`: each buffer is a
        // custom UE framing, not a standard Ogg-Opus file, and the two are
        // *different* framings — desktop `"OPUS"` is "UE4OPUS"; Switch `"OPUSNX"`
        // is the distinct "NXOpus" layout. Honest extensions also leave `.opus`
        // free for a future real Opus decoder.
        reg.register(
            sw_disc,
            Box::new(RawSoundHandler::new(&["OPUS"], "ue4opus")),
        );
        reg.register(
            sw_disc,
            Box::new(RawSoundHandler::new(&["OPUSNX"], "nxopus")),
        );

        // A future Opus *decoder* (over the verified UE4OPUS framing) would
        // register under `sw_disc` the same way, reached by output-extension
        // alongside the `RawSoundHandler` passthrough — as `VorbisHandler`'s
        // `.wav` decode sits beside `OggHandler`'s `.ogg` passthrough today.

        // Phase 3g2: UStaticMesh -> glTF (.glb). Sole static-mesh handler.
        let static_mesh_sentinel = Asset::StaticMesh(crate::asset::StaticMeshData::empty());
        reg.register(
            std::mem::discriminant(&static_mesh_sentinel),
            Box::new(static_mesh::GltfStaticMeshHandler),
        );

        // Phase 3h — USkeletalMesh -> skinned glTF (.glb). Sole skeletal-mesh
        // handler. Sentinel uses `SkeletalMeshData::empty()` (zero-allocation;
        // `discriminant` ignores the payload).
        let skel_sentinel = Asset::SkeletalMesh(crate::asset::SkeletalMeshData::empty());
        reg.register(
            std::mem::discriminant(&skel_sentinel),
            Box::new(skeletal_mesh::GltfSkeletalMeshHandler),
        );
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

/// One exportable `(payload, format)` pair: the payload at `payload_idx` in a
/// [`Package`] can be written as a file with extension `extension` by a
/// registered [`FormatHandler`]. `Copy` so it rides a GUI `Message` freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportFormat {
    /// Index into [`Package::payloads`].
    pub payload_idx: usize,
    /// Output extension (no leading dot), e.g. `"png"`, `"csv"`, `"json"`.
    pub extension: &'static str,
}

/// Every `(payload index, output extension)` pair that `registry` can export
/// from `payloads`, in payload order then handler-registration order.
///
/// Within one payload an extension appears at most once (first registered
/// handler wins), so a caller building a format menu never shows a duplicate
/// entry — matching [`HandlerRegistry::find_handler_by_extension`]'s
/// first-match dispatch. Empty when no payload has a supporting handler.
fn formats_for_payloads(registry: &HandlerRegistry, payloads: &[Asset]) -> Vec<ExportFormat> {
    let mut out = Vec::new();
    for (payload_idx, asset) in payloads.iter().enumerate() {
        let disc = std::mem::discriminant(asset);
        let Some(bucket) = registry.by_variant.get(&disc) else {
            continue;
        };
        let mut seen: Vec<&'static str> = Vec::new();
        for handler in bucket {
            if !handler.supports(asset) {
                continue;
            }
            let ext = handler.output_extension();
            if !seen.contains(&ext) {
                seen.push(ext);
                out.push(ExportFormat {
                    payload_idx,
                    extension: ext,
                });
            }
        }
    }
    out
}

/// Every exportable `(payload, format)` pair for `package` under `registry`.
///
/// The GUI's Export As… picker is built from this; the CLI's `extract` selects
/// one payload via its own preference logic and does not call this.
#[must_use]
pub fn available_formats(registry: &HandlerRegistry, package: &Package) -> Vec<ExportFormat> {
    formats_for_payloads(registry, &package.payloads)
}

/// Resolve the bulk for `payload_idx` and run the handler that produces
/// `extension`, returning the exported file bytes.
///
/// Errors (all [`crate::PaksmithError`], never panics):
/// - `InvalidArgument { arg: "payload_idx", .. }` — index past the end of
///   `package.payloads`.
/// - `InvalidArgument { arg: "extension", .. }` — no registered handler both
///   `supports` the payload and emits `extension`.
/// - bulk-resolution / handler errors propagate unchanged.
///
/// The caller must build `registry` with [`HandlerRegistry::all_default_handlers`]
/// (the same registry used to enumerate via [`available_formats`]) so a
/// successfully-enumerated `(payload_idx, extension)` always dispatches here.
pub fn export_payload(
    package: &Package,
    payload_idx: usize,
    extension: &str,
    registry: &HandlerRegistry,
) -> crate::Result<Vec<u8>> {
    let asset =
        package
            .payloads
            .get(payload_idx)
            .ok_or_else(|| crate::PaksmithError::InvalidArgument {
                arg: "payload_idx",
                reason: format!(
                    "no payload at index {payload_idx} (package has {} payload(s))",
                    package.payloads.len()
                ),
            })?;
    let handler = registry
        .find_handler_by_extension(extension, asset)
        .ok_or_else(|| crate::PaksmithError::InvalidArgument {
            arg: "extension",
            reason: format!("no handler exports `{extension}` for this payload"),
        })?;
    let bulk = package.resolve_bulk_for_export(payload_idx)?;
    handler.export(asset, bulk)
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "__test_utils"))]
mod facade_tests {
    use super::*;
    use crate::asset::Package;

    /// A real package with a single `Asset::Generic` payload (json handler).
    fn generic_pkg() -> Package {
        let mp = crate::testing::uasset::build_minimal_ue4_27();
        Package::read_from(&mp.bytes, None, None, "Game/Foo.uasset")
            .expect("build_minimal_ue4_27 must parse")
    }

    #[test]
    fn export_payload_generic_to_json_ok() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let bytes = export_payload(&pkg, 0, "json", &reg).expect("generic→json");
        assert!(!bytes.is_empty(), "json export must produce bytes");
    }

    #[test]
    fn export_payload_out_of_range_idx_is_invalid_argument() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let err = export_payload(&pkg, 99, "json", &reg).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::InvalidArgument {
                    arg: "payload_idx",
                    ..
                }
            ),
            "out-of-range index must be InvalidArgument(payload_idx), got {err:?}"
        );
    }

    #[test]
    fn export_payload_unhandled_extension_is_invalid_argument() {
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        // A Generic payload only exports json; png has no handler for it.
        let err = export_payload(&pkg, 0, "png", &reg).unwrap_err();
        assert!(
            matches!(
                err,
                crate::PaksmithError::InvalidArgument {
                    arg: "extension",
                    ..
                }
            ),
            "unhandled extension must be InvalidArgument(extension), got {err:?}"
        );
    }

    #[test]
    fn available_formats_generic_pkg_offers_json() {
        // Package-level smoke for the Task-1 enumerator. Tolerant of extra
        // payloads (exact ordering/dedup are pinned in formats_for_payloads
        // unit tests); asserts the json entry for payload 0 is present.
        let pkg = generic_pkg();
        let reg = HandlerRegistry::all_default_handlers();
        let formats = available_formats(&reg, &pkg);
        assert!(
            formats
                .iter()
                .any(|f| f.payload_idx == 0 && f.extension == "json"),
            "generic package must offer json for payload 0, got {formats:?}"
        );
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
    fn registry_ogg_soundwave_defaults_to_ogg_passthrough_wav_is_opt_in() {
        // An "OGG" SoundWave resolves to OggHandler (.ogg passthrough) by default;
        // the decoded .wav is opt-in via `find_handler_by_extension("wav", …)`,
        // served by VorbisHandler (NOT WavHandler, whose supports() rejects "OGG").
        let reg = HandlerRegistry::all_default_handlers();
        let mut sw = crate::asset::SoundWaveData::empty();
        sw.cooked = true;
        sw.compressed_format_keys = vec![std::sync::Arc::from("OGG")];
        let asset = Asset::SoundWave(sw);

        assert_eq!(
            reg.find_handler(&asset)
                .expect("default OGG handler")
                .output_extension(),
            "ogg",
            "default for an OGG SoundWave is the .ogg passthrough"
        );
        assert_eq!(
            reg.find_handler_by_extension("wav", &asset)
                .expect("wav decode handler")
                .output_extension(),
            "wav",
            "the .wav decode is reachable via extension"
        );
        assert_eq!(
            reg.find_handler_by_extension("ogg", &asset)
                .expect("ogg handler")
                .output_extension(),
            "ogg"
        );
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

    #[test]
    fn formats_for_payloads_empty_when_no_handler() {
        // Empty registry → no payload has a handler → empty list.
        let reg = HandlerRegistry::new();
        assert!(formats_for_payloads(&reg, &[generic_sentinel()]).is_empty());
    }

    #[test]
    fn formats_for_payloads_single_handler() {
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "json",
                supports_value: true,
            }),
        );
        assert_eq!(
            formats_for_payloads(&reg, &[generic_sentinel()]),
            vec![ExportFormat {
                payload_idx: 0,
                extension: "json"
            }]
        );
    }

    #[test]
    fn formats_for_payloads_orders_by_payload_then_registration() {
        // Two handlers for the variant, two payloads → payload-major, then
        // registration order within each payload.
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
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
        let payloads = [generic_sentinel(), generic_sentinel()];
        assert_eq!(
            formats_for_payloads(&reg, &payloads),
            vec![
                ExportFormat {
                    payload_idx: 0,
                    extension: "csv"
                },
                ExportFormat {
                    payload_idx: 0,
                    extension: "json"
                },
                ExportFormat {
                    payload_idx: 1,
                    extension: "csv"
                },
                ExportFormat {
                    payload_idx: 1,
                    extension: "json"
                },
            ]
        );
    }

    #[test]
    fn formats_for_payloads_dedups_same_extension_within_payload() {
        // Two handlers emitting the same extension for one payload → one entry
        // (first wins) so a format menu never shows a duplicate button.
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "json",
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
            formats_for_payloads(&reg, &[generic_sentinel()]),
            vec![ExportFormat {
                payload_idx: 0,
                extension: "json"
            }]
        );
    }

    #[test]
    fn formats_for_payloads_skips_supports_false() {
        let mut reg = HandlerRegistry::new();
        let disc = std::mem::discriminant(&generic_sentinel());
        reg.register(
            disc,
            Box::new(MockHandler {
                ext: "json",
                supports_value: false,
            }),
        );
        assert!(formats_for_payloads(&reg, &[generic_sentinel()]).is_empty());
    }
}
