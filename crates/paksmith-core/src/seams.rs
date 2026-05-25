//! Always-compiled OOM-seam type + macro.
//!
//! Lives outside `__test_utils`-gated `crate::testing` so [`SeamSite`]
//! is reachable in helper signatures (`crate::error::try_reserve_index`)
//! and so [`seam_check!`] is callable at every production site
//! regardless of feature configuration. Runtime dispatch
//! (`maybe_fail_at`) remains `__test_utils`-gated. See #266 and #270.

/// Identifier for an OOM-injection seam. Each variant maps 1:1 to a
/// `try_reserve*` site in production code that's gated behind
/// `#[cfg(feature = "__test_utils")]` to allow integration tests to
/// force the failure path.
///
/// Adding a new seam: append a variant here, bump [`Self::COUNT`],
/// and slot the variant into the exhaustive `match` in
/// `tests::seam_site_discriminants_match_slot_indices`. The `const _`
/// compile-time assertion below [`impl SeamSite`] refuses to build
/// when `COUNT` and the largest declared discriminant disagree.
///
/// `#[repr(usize)]` so the variant's index maps directly to its slot
/// in the `ARM_STATE` array in [`crate::testing::oom`].
// Decompression/parser variants are constructed only via the
// `__test_utils`-gated `seam_check!` macro expansion, invisible to
// the dead-code analyzer in non-test builds.
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum SeamSite {
    /// `stream_zlib_to`'s pre-decode per-block `try_reserve_exact`.
    /// Surfaces as
    /// [`crate::error::DecompressionFault::CompressedBlockReserveFailed`].
    CompressedReserve,
    /// `stream_zlib_to`'s mid-decode `try_reserve(n)` loop. Surfaces
    /// as [`crate::error::DecompressionFault::ZlibScratchReserveFailed`].
    ///
    /// To pin `already_committed > 0` (the field that structurally
    /// distinguishes mid-decode failure from the
    /// [`Self::CompressedReserve`] case), pass `skip_count >= 1` so
    /// the first chunk's reservation succeeds and the failure fires
    /// on a later iteration.
    ScratchReserve,
    /// `read_fstring` UTF-16 branch (negative-length-prefixed
    /// FStrings). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FStringUtf16CodeUnits`.
    FstringUtf16,
    /// `read_fstring` UTF-8 branch (positive-length-prefixed
    /// FStrings). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FStringUtf8Bytes`.
    FstringUtf8,
    /// FDI walk's `dir + file` full-path `String::try_reserve_exact`.
    /// Surfaces as [`crate::error::IndexParseFault::AllocationFailed`]
    /// with `context: AllocationContext::FdiFullPathBytes`.
    ///
    /// `skip_count >= 1` is the typical knob — the first FDI entry's
    /// path reservation succeeds and the failure fires on a later
    /// entry, pinning that the seam fires per-entry rather than once.
    FdiFullPath,
    // Helper-routed variants: each is dispatched through
    // `crate::error::try_reserve_index` and surfaces as
    // `IndexParseFault::AllocationFailed` with the named
    // `AllocationContext`. The variant name is the
    // `AllocationContext` it pairs with (1:1 by convention).
    /// `FlatIndex::read_from`'s entries vec.
    FlatIndexEntries,
    /// `PakEntryHeader::read_from` (v3-v9) inline compression-block table.
    InlineCompressionBlocks,
    /// `PakEntryHeader::read_encoded` (v10+) compression-block table.
    EncodedCompressionBlocks,
    /// v10+ main-index bytes buffer.
    V10MainIndexBytes,
    /// v10+ encoded-entries blob (bit-packed pak entries).
    V10EncodedEntriesBytes,
    /// v10+ non-encoded entries vec (`PakEntryHeader` records).
    V10NonEncodedEntries,
    /// v10+ Full Directory Index (FDI) bytes buffer.
    V10FdiBytes,
    /// v10+ Path Hash Index (PHI) bytes buffer.
    V10PhiBytes,
    /// v10+ entries vec — parallel to [`Self::FlatIndexEntries`] but
    /// reached via the v10+ index parser.
    V10IndexEntries,
    // Asset-side seams (#276). Each pairs 1:1 with an
    // `AssetAllocationContext` variant used at a `try_reserve_asset`
    // call site. The issue filed these as a watch-item ("revisit when
    // Phase 2b adds asset-side seams"); Phase 2 surfaces had
    // `try_reserve_asset` HELPER coverage but no seam-injection
    // integration test surface. This PR closes that gap. PR 2 will
    // refactor `SeamSite` to a grouped enum (Pak/Asset) — kept flat
    // here so reviewers can focus on wiring vs structure separately.
    /// `NameTable::read_from`'s entries vec.
    /// Surfaces as [`crate::error::AssetParseFault::AllocationFailed`]
    /// with `context: AssetAllocationContext::NameTable`.
    AssetNameTable,
    /// `ImportTable::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::ImportTable`.
    AssetImportTable,
    /// `ExportTable::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::ExportTable`.
    AssetExportTable,
    /// `CustomVersionContainer::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::CustomVersionContainer`.
    AssetCustomVersionContainer,
    /// `Package::read_from`'s per-export `PropertyBag` vec.
    /// Surfaces as `AssetAllocationContext::ExportPayloads`.
    AssetExportPayloads,
    /// `Package::read_payloads`'s Opaque-fallback export bytes vec.
    /// Surfaces as `AssetAllocationContext::ExportPayloadBytes`.
    AssetExportPayloadBytes,
    /// `read_array_value` / `read_map_value` / `read_set_value` /
    /// `read_unversioned_value` (the `Array<T>` arm) element list
    /// reservation. Surfaces as
    /// `AssetAllocationContext::CollectionElements`. Shared across
    /// all collection decoders — five `try_reserve_asset` call sites
    /// route through this variant.
    AssetCollectionElements,
    /// `Package::read_from`'s split-asset concat buffer
    /// (uasset + uexp). Direct `try_reserve_exact` call site, NOT
    /// helper-routed; wired via the `seam_check!` macro inline.
    /// Surfaces as `AssetAllocationContext::SplitAssetCombined`.
    AssetSplitAssetCombined,
}

impl SeamSite {
    /// Total number of seam sites. Used to size the `ARM_STATE` array
    /// in [`crate::testing::oom`]. The `const _` guard below pins
    /// `COUNT` to [`Self::AssetSplitAssetCombined`]'s position, AND
    /// the exhaustive `match` in
    /// `tests::seam_site_discriminants_match_slot_indices` fails to
    /// compile when a new variant is added without slotting it in.
    /// Together they keep array indexing panic-free.
    pub const COUNT: usize = 22;
}

// Compile-time guard: `SeamSite::COUNT` must equal the last variant's
// discriminant + 1. This narrowly pins COUNT to the *current* last
// variant's position. A new variant added AFTER the last one would
// NOT trip this guard alone — the exhaustive `match` in the test
// module's `seam_site_discriminants_match_slot_indices` is the
// load-bearing catch for that case (it forces a compile error at the
// test site whenever a variant is added). Both layers together
// guarantee `ARM_STATE`'s array bounds.
const _: [(); SeamSite::COUNT] = [(); SeamSite::AssetSplitAssetCombined as usize + 1];

/// Fold an OOM-injection seam check into an existing
/// `Result<(), TryReserveError>` binding by name.
///
/// `$binding` names an existing `let` binding the macro shadows;
/// `$site` is a [`SeamSite`] variant path (the `:path` matcher
/// rejects arbitrary expressions, preventing production-build
/// expression-evaluation drift).
///
/// `and_then` short-circuits when `$binding` is already `Err`, so a
/// real allocation failure takes precedence over the test-armed
/// synthetic one — armed seams only force failure at sites where the
/// real allocation would have succeeded.
macro_rules! seam_check {
    ($binding:ident, $site:path) => {
        #[cfg(feature = "__test_utils")]
        let $binding = $binding.and_then(|()| $crate::testing::oom::maybe_fail_at($site));
    };
}

pub(crate) use seam_check;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`SeamSite`] variant names its end-to-end coverage test
    /// in `paksmith-core-tests/tests/oom_pak.rs`. The exhaustive
    /// `match` is the load-bearing guard: adding a variant without a
    /// match arm fails to compile, so a new seam can't slip in
    /// production-wired-but-test-uncovered (#275).
    #[test]
    fn every_seamsite_variant_has_named_integration_coverage() {
        const fn integration_test_name(site: SeamSite) -> &'static str {
            match site {
                SeamSite::CompressedReserve => {
                    "read_entry_surfaces_compressed_block_reserve_failed_under_oom"
                }
                SeamSite::ScratchReserve => {
                    "read_entry_surfaces_zlib_scratch_reserve_failed_with_committed_bytes_under_oom"
                }
                SeamSite::FstringUtf16 => "read_fstring_utf16_surfaces_allocation_failed_under_oom",
                SeamSite::FstringUtf8 => "read_fstring_utf8_surfaces_allocation_failed_under_oom",
                SeamSite::FdiFullPath => "read_fdi_full_path_surfaces_allocation_failed_under_oom",
                SeamSite::FlatIndexEntries => {
                    "read_flat_index_entries_surfaces_allocation_failed_under_oom"
                }
                SeamSite::InlineCompressionBlocks => {
                    "read_inline_compression_blocks_surfaces_allocation_failed_under_oom"
                }
                SeamSite::EncodedCompressionBlocks => {
                    "read_encoded_compression_blocks_surfaces_allocation_failed_under_oom"
                }
                SeamSite::V10MainIndexBytes => {
                    "read_v10_main_index_bytes_surfaces_allocation_failed_under_oom"
                }
                SeamSite::V10EncodedEntriesBytes => {
                    "read_v10_encoded_entries_bytes_surfaces_allocation_failed_under_oom"
                }
                SeamSite::V10NonEncodedEntries => {
                    "read_v10_non_encoded_entries_surfaces_allocation_failed_under_oom"
                }
                SeamSite::V10FdiBytes => "read_v10_fdi_bytes_surfaces_allocation_failed_under_oom",
                SeamSite::V10PhiBytes => "read_v10_phi_bytes_surfaces_allocation_failed_under_oom",
                SeamSite::V10IndexEntries => {
                    "read_v10_index_entries_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetNameTable => {
                    "read_asset_name_table_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetImportTable => {
                    "read_asset_import_table_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetExportTable => {
                    "read_asset_export_table_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetCustomVersionContainer => {
                    "read_asset_custom_version_container_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetExportPayloads => {
                    "read_asset_export_payloads_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetExportPayloadBytes => {
                    "read_asset_export_payload_bytes_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetCollectionElements => {
                    "read_asset_collection_elements_surfaces_allocation_failed_under_oom"
                }
                SeamSite::AssetSplitAssetCombined => {
                    "read_asset_split_asset_combined_surfaces_allocation_failed_under_oom"
                }
            }
        }
        // Touch the const fn so the match's compile-time exhaustiveness
        // is anchored to a live call (otherwise dead-code analysis
        // could elide the function and the match below it).
        let _ = integration_test_name(SeamSite::CompressedReserve);
    }

    /// Every [`SeamSite`] discriminant lines up with its slot index.
    /// The exhaustive `match` in `expected_index` is the load-bearing
    /// guard — adding a variant without updating it fails to compile
    /// here, forcing the contributor to slot the new site in. Paired
    /// with the `const _` compile-time `COUNT` guard above, this pins
    /// both the count AND the contiguous `0..COUNT` ordering that
    /// `ARM_STATE`'s array indexing assumes.
    #[test]
    fn seam_site_discriminants_match_slot_indices() {
        const fn expected_index(site: SeamSite) -> usize {
            match site {
                SeamSite::CompressedReserve => 0,
                SeamSite::ScratchReserve => 1,
                SeamSite::FstringUtf16 => 2,
                SeamSite::FstringUtf8 => 3,
                SeamSite::FdiFullPath => 4,
                SeamSite::FlatIndexEntries => 5,
                SeamSite::InlineCompressionBlocks => 6,
                SeamSite::EncodedCompressionBlocks => 7,
                SeamSite::V10MainIndexBytes => 8,
                SeamSite::V10EncodedEntriesBytes => 9,
                SeamSite::V10NonEncodedEntries => 10,
                SeamSite::V10FdiBytes => 11,
                SeamSite::V10PhiBytes => 12,
                SeamSite::V10IndexEntries => 13,
                SeamSite::AssetNameTable => 14,
                SeamSite::AssetImportTable => 15,
                SeamSite::AssetExportTable => 16,
                SeamSite::AssetCustomVersionContainer => 17,
                SeamSite::AssetExportPayloads => 18,
                SeamSite::AssetExportPayloadBytes => 19,
                SeamSite::AssetCollectionElements => 20,
                SeamSite::AssetSplitAssetCombined => 21,
            }
        }
        let all = [
            SeamSite::CompressedReserve,
            SeamSite::ScratchReserve,
            SeamSite::FstringUtf16,
            SeamSite::FstringUtf8,
            SeamSite::FdiFullPath,
            SeamSite::FlatIndexEntries,
            SeamSite::InlineCompressionBlocks,
            SeamSite::EncodedCompressionBlocks,
            SeamSite::V10MainIndexBytes,
            SeamSite::V10EncodedEntriesBytes,
            SeamSite::V10NonEncodedEntries,
            SeamSite::V10FdiBytes,
            SeamSite::V10PhiBytes,
            SeamSite::V10IndexEntries,
            SeamSite::AssetNameTable,
            SeamSite::AssetImportTable,
            SeamSite::AssetExportTable,
            SeamSite::AssetCustomVersionContainer,
            SeamSite::AssetExportPayloads,
            SeamSite::AssetExportPayloadBytes,
            SeamSite::AssetCollectionElements,
            SeamSite::AssetSplitAssetCombined,
        ];
        assert_eq!(all.len(), SeamSite::COUNT);
        for site in all {
            assert_eq!(site as usize, expected_index(site));
        }
    }
}

#[cfg(all(test, feature = "__test_utils"))]
mod macro_tests {
    use std::collections::TryReserveError;

    use super::SeamSite;
    use crate::testing::oom::arm_at;

    /// Armed seam turns `Ok(())` into `Err(_)`. Pins the basic
    /// macro-expansion contract.
    #[test]
    fn seam_check_fires_when_armed() {
        let _guard = arm_at(SeamSite::CompressedReserve, 0);
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::CompressedReserve);
        assert!(result.is_err(), "armed seam must turn Ok into Err");
    }

    /// Unarmed seam passes `Ok(())` through unchanged.
    #[test]
    fn seam_check_passes_when_unarmed() {
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::FdiFullPath);
        assert!(result.is_ok(), "unarmed seam must passthrough Ok");
    }

    /// When the binding is already `Err`, `and_then` short-circuits
    /// — the seam is NOT consumed and the original error is
    /// preserved. This is the load-bearing invariant: a real
    /// allocation failure always wins over an armed synthetic one,
    /// so tests can't accidentally mask real OOMs.
    #[test]
    fn seam_check_preserves_prior_error_without_consuming_arm() {
        let _guard = arm_at(SeamSite::ScratchReserve, 0);
        let original = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("synthetic capacity-overflow must fail");
        let result: Result<(), TryReserveError> = Err(original);
        seam_check!(result, SeamSite::ScratchReserve);
        assert!(result.is_err(), "original error must propagate");
        // Arm state must NOT have been consumed by the short-circuit.
        let probe = crate::testing::oom::maybe_fail_at(SeamSite::ScratchReserve);
        assert!(
            probe.is_err(),
            "seam was incorrectly consumed despite Err short-circuit"
        );
    }
}
