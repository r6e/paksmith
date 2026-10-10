//! Always-compiled OOM-seam type + macro.
//!
//! Lives outside `__test_utils`-gated `crate::testing` so [`SeamSite`]
//! is reachable in helper signatures (`crate::error::try_reserve_index`,
//! `crate::error::check_asset_reserve`,
//! `crate::error::check_mappings_reserve`) and so [`seam_check!`] is
//! callable at every production site regardless of feature
//! configuration. Runtime dispatch (`maybe_fail_at`) remains
//! `__test_utils`-gated. See #266, #270, and #276.

/// Identifier for an OOM-injection seam. Each variant maps 1:1 to a
/// `try_reserve*` site in production code, gated behind
/// `#[cfg(feature = "__test_utils")]` so tests can force the failure
/// path.
///
/// **Grouped structure** (#276): inner enums — [`PakSeam`] for
/// container/index/decompression seams, [`AssetSeam`] for asset
/// parser seams, [`MappingsSeam`] for `.usmap` parser seams — wrapped
/// in this outer discriminator. The grouping makes the cross-domain
/// distinction structural rather than naming-convention; the flat
/// 22-variant form that preceded it
/// (PR #452) mixed pak and asset variants in one namespace and
/// became increasingly incoherent as the asset side grew.
///
/// Adding a new seam: append a variant to the relevant inner enum
/// ([`PakSeam`], [`AssetSeam`] or [`MappingsSeam`]), bump that inner
/// enum's `COUNT`, and slot the variant into the exhaustive matches in
/// [`Self::slot`] and `tests::*`. The `const _` compile-time guards
/// after each inner enum refuse to build when `COUNT` and the
/// largest declared discriminant disagree.
///
/// Slot indexing: see [`Self::slot`] for the layout contract.
///
/// **Deliberately NOT `#[non_exhaustive]`** for the same reasons the
/// flat form wasn't: exhaustive matching is the load-bearing guard
/// for both the slot-index test and the named-coverage test.
/// `#[non_exhaustive]` would force `_ =>` arms and silently undo
/// both guarantees. Visibility cost is acceptable because the type
/// lives under `__test_utils`-gated re-exports.
// Variants are constructed only via the `__test_utils`-gated
// `seam_check!` macro expansion, invisible to the dead-code analyzer
// in non-test builds.
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeamSite {
    /// Container / index / decompression seams. See [`PakSeam`].
    Pak(PakSeam),
    /// Asset parser seams (#276). See [`AssetSeam`].
    Asset(AssetSeam),
    /// `.usmap` parser seams. See [`MappingsSeam`].
    Mappings(MappingsSeam),
}

/// Container / index / decompression OOM seams. The inner enum of
/// [`SeamSite::Pak`].
///
/// `#[repr(usize)]` so the variant's discriminant maps directly to
/// its slot in the lower portion of the `ARM_STATE` array (see
/// [`SeamSite::slot`]).
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PakSeam {
    /// `read_compressed_block`'s pre-decode per-block
    /// `try_reserve_exact` — the compressed-input read shared by the
    /// zlib and LZ4 paths. Surfaces as
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
    /// The pak index's `read_fstring`, UTF-16 branch
    /// (negative-length-prefixed FStrings). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FStringUtf16CodeUnits`.
    FstringUtf16,
    /// The pak index's `read_fstring`, UTF-8 branch
    /// (positive-length-prefixed FStrings). Surfaces as
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
    /// `stream_lz4_to`'s pre-decode per-block output-buffer
    /// `try_reserve_exact` (#636). Surfaces as
    /// [`crate::error::DecompressionFault::Lz4OutputReserveFailed`].
    /// The LZ4 path's compressed-INPUT reservation shares
    /// [`Self::CompressedReserve`] with the zlib path (identical
    /// site semantics + fault variant). Appended at the enum tail so
    /// existing discriminants (and their slot indices) are unchanged.
    Lz4OutputReserve,
}

impl PakSeam {
    /// Total number of pak-side seam sites. Pinned by the `const _`
    /// guard below and by the exhaustive `match` in
    /// [`SeamSite::slot`].
    pub const COUNT: usize = 15;
}

// Compile-time guard: refuses to build when `COUNT` and the largest
// declared discriminant disagree. Implicit precondition (shared with
// the `AssetSeam` guard below): variants are declared in source order
// with no explicit `= N` assignments and no gaps, so that
// `last as usize + 1` equals the variant count.
const _: [(); PakSeam::COUNT] = [(); PakSeam::Lz4OutputReserve as usize + 1];

/// Asset parser OOM seams (#276). The inner enum of [`SeamSite::Asset`].
///
/// Each variant pairs 1:1 with an
/// [`crate::error::AssetAllocationContext`] variant, which
/// `check_asset_reserve` derives from it at every asset-side reservation
/// (`try_reserve_asset` for a `Vec`).
///
/// `#[repr(usize)]` so the variant's discriminant maps directly to
/// its slot after the pak slots of the `ARM_STATE` array (see
/// [`SeamSite::slot`]).
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum AssetSeam {
    /// `NameTable::read_from`'s entries vec.
    /// Surfaces as [`crate::error::AssetParseFault::AllocationFailed`]
    /// with `context: AssetAllocationContext::NameTable`.
    NameTable,
    /// `ImportTable::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::ImportTable`.
    ImportTable,
    /// `ExportTable::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::ExportTable`.
    ExportTable,
    /// `CustomVersionContainer::read_from`'s entries vec.
    /// Surfaces as `AssetAllocationContext::CustomVersionContainer`.
    CustomVersionContainer,
    /// `Package::read_from`'s per-export `PropertyBag` vec.
    /// Surfaces as `AssetAllocationContext::ExportPayloads`.
    ExportPayloads,
    /// `Package::read_payloads`'s Opaque-fallback export bytes vec.
    /// Surfaces as `AssetAllocationContext::ExportPayloadBytes`.
    ExportPayloadBytes,
    /// `read_array_value` / `read_map_value` / `read_set_value` /
    /// `read_unversioned_value` (the `Array<T>` arm) element list
    /// reservation. Surfaces as
    /// `AssetAllocationContext::CollectionElements`. Shared across
    /// all collection decoders.
    CollectionElements,
    /// `Package::read_from`'s split-asset concat buffer
    /// (uasset + uexp).
    /// Surfaces as `AssetAllocationContext::SplitAssetCombined`.
    SplitAssetCombined,
    /// `data_table::read_from`'s row-list reservation (Phase 3d).
    /// Surfaces as `AssetAllocationContext::DataTableRows`.
    DataTableRows,
    /// `parse_data_resource_table`'s entries-vec reservation (#642).
    /// Surfaces as `AssetAllocationContext::DataResourceTable`.
    DataResourceTable,
    /// `BulkDataResolver`'s copy of an uncompressed record's bytes.
    /// Surfaces as `AssetAllocationContext::BulkDataBytes`.
    BulkDataBytes,
    /// `decompress_zlib`'s output pre-size.
    /// Surfaces as `AssetAllocationContext::DecompressedBulkDataBytes`.
    DecompressedBulkDataBytes,
    /// `UsmapView`'s enum value-table memo, a `HashMap` grown by one
    /// per enum name a package read resolves, through
    /// `check_asset_reserve`.
    /// Surfaces as `AssetAllocationContext::EnumTableMemo`.
    EnumTableMemo,
    /// `read_asset_fstring`'s UTF-8 buffer.
    /// Surfaces as `AssetAllocationContext::FStringUtf8Bytes`.
    FStringUtf8Bytes,
    /// `read_asset_fstring`'s UTF-16 buffer.
    /// Surfaces as `AssetAllocationContext::FStringUtf16CodeUnits`.
    FStringUtf16CodeUnits,
    /// `UsmapView`'s struct-layout memo, a `HashMap` grown by one per
    /// struct name a package read resolves, through `check_asset_reserve`.
    /// Surfaces as `AssetAllocationContext::StructLayoutMemo`.
    StructLayoutMemo,
    /// `UsmapView`'s class-schema memo, a `HashMap` grown by one per
    /// class name a package read resolves, through `check_asset_reserve`.
    /// Surfaces as `AssetAllocationContext::ClassSchemaMemo`.
    ClassSchemaMemo,
}

impl AssetSeam {
    /// Total number of asset-side seam sites. Pinned by the `const _`
    /// guard below and by the exhaustive `match` in
    /// [`SeamSite::slot`].
    pub const COUNT: usize = 17;

    /// Map an asset seam to its paired
    /// [`crate::error::AssetAllocationContext`].
    ///
    /// The 1:1 pairing is enforced structurally by this exhaustive
    /// match — adding a variant to [`AssetSeam`] without a context
    /// counterpart fails to compile, so the binding
    /// can't silently drift out of sync. `crate::error::check_asset_reserve`,
    /// which every asset-side reservation goes through, derives the
    /// context tag from the seam via this method, so no call site names
    /// an `AssetAllocationContext` itself.
    #[must_use]
    pub const fn context(self) -> crate::error::AssetAllocationContext {
        use crate::error::AssetAllocationContext as C;
        match self {
            Self::NameTable => C::NameTable,
            Self::ImportTable => C::ImportTable,
            Self::ExportTable => C::ExportTable,
            Self::CustomVersionContainer => C::CustomVersionContainer,
            Self::ExportPayloads => C::ExportPayloads,
            Self::ExportPayloadBytes => C::ExportPayloadBytes,
            Self::CollectionElements => C::CollectionElements,
            Self::SplitAssetCombined => C::SplitAssetCombined,
            Self::DataTableRows => C::DataTableRows,
            Self::DataResourceTable => C::DataResourceTable,
            Self::BulkDataBytes => C::BulkDataBytes,
            Self::DecompressedBulkDataBytes => C::DecompressedBulkDataBytes,
            Self::EnumTableMemo => C::EnumTableMemo,
            Self::FStringUtf8Bytes => C::FStringUtf8Bytes,
            Self::FStringUtf16CodeUnits => C::FStringUtf16CodeUnits,
            Self::StructLayoutMemo => C::StructLayoutMemo,
            Self::ClassSchemaMemo => C::ClassSchemaMemo,
        }
    }
}

// Same compile-time guard pattern as PakSeam above (see precondition).
const _: [(); AssetSeam::COUNT] = [(); AssetSeam::ClassSchemaMemo as usize + 1];

/// `.usmap` parser OOM seams. The inner enum of [`SeamSite::Mappings`].
///
/// Each variant pairs 1:1 with a
/// [`crate::error::MappingsAllocationContext`] variant, which
/// `check_mappings_reserve` derives from it. The family is partial: every
/// other reservation in the parser maps a refusal with
/// `mappings_alloc_failed` directly and has no seam.
///
/// `#[repr(usize)]` so the variant's discriminant maps directly to its
/// slot after the pak and asset slots of the `ARM_STATE` array (see
/// [`SeamSite::slot`]).
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum MappingsSeam {
    /// `copy_name`'s reservation. Surfaces as
    /// [`crate::error::MappingsParseFault::AllocationFailed`] with
    /// `context: MappingsAllocationContext::SchemaNameBytes`.
    SchemaNameBytes,
    /// `DecoderAlloc::alloc_cell`'s reservation, for each block of the
    /// Brotli decoder's working memory. Surfaces as
    /// [`crate::error::MappingsParseFault::AllocationFailed`] with
    /// `context: MappingsAllocationContext::BrotliDecoderBytes`.
    BrotliDecoderBytes,
    /// `check_flattened_reserve`'s reservations, the flattened-cache build's.
    /// Surfaces as [`crate::error::MappingsParseFault::AllocationFailed`] with
    /// `context: MappingsAllocationContext::FlattenedCache`.
    FlattenedCache,
}

impl MappingsSeam {
    /// Total number of `.usmap` seam sites. Pinned by the `const _` guard
    /// below and by `tests::seam_site_discriminants_match_slot_indices`.
    pub const COUNT: usize = 3;

    /// Map a `.usmap` seam to its paired
    /// [`crate::error::MappingsAllocationContext`], as
    /// [`AssetSeam::context`] does for the asset family.
    #[must_use]
    pub const fn context(self) -> crate::error::MappingsAllocationContext {
        use crate::error::MappingsAllocationContext as C;
        match self {
            Self::SchemaNameBytes => C::SchemaNameBytes,
            Self::BrotliDecoderBytes => C::BrotliDecoderBytes,
            Self::FlattenedCache => C::FlattenedCache,
        }
    }
}

// Same compile-time guard pattern as PakSeam above (see precondition).
const _: [(); MappingsSeam::COUNT] = [(); MappingsSeam::FlattenedCache as usize + 1];

// In the feature-off LIB target `COUNT`/`slot` are dead: their only
// production consumers live in the `__test_utils`-gated
// `testing::oom` module. (The ungated seam test below keeps them
// used in the lib-TEST compile.) CI's package-scoped compile guard
// builds that lib target under `-D warnings`; same pattern as the
// enum's attr above.
#[cfg_attr(not(feature = "__test_utils"), allow(dead_code))]
impl SeamSite {
    /// Total number of seam sites across all domains. Used to size
    /// the `ARM_STATE` array in [`crate::testing::oom`].
    pub const COUNT: usize = PakSeam::COUNT + AssetSeam::COUNT + MappingsSeam::COUNT;

    /// Flatten the grouped enum to a global slot index in
    /// `0..SeamSite::COUNT`. Pak variants occupy `0..PakSeam::COUNT`,
    /// asset variants the next `AssetSeam::COUNT` slots, and `.usmap`
    /// variants the rest.
    /// Used by [`crate::testing::oom::arm_at`] and the production-side
    /// `maybe_fail_at` dispatch for array indexing.
    ///
    /// `const fn` so callers in test infrastructure can constant-
    /// evaluate slot indices for documentation / static assertions.
    #[must_use]
    pub const fn slot(self) -> usize {
        match self {
            Self::Pak(s) => s as usize,
            Self::Asset(s) => PakSeam::COUNT + s as usize,
            Self::Mappings(s) => s as usize + PakSeam::COUNT + AssetSeam::COUNT,
        }
    }
}

/// Fold an OOM-injection seam check into an existing
/// `Result<(), TryReserveError>` binding by name.
///
/// `$binding` names an existing `let` binding the macro shadows;
/// `$site` is any expression evaluating to [`SeamSite`]. Callers
/// pass either a constructor like
/// `SeamSite::Pak(PakSeam::CompressedReserve)` or a variable, and
/// the type system pins the value to [`SeamSite`] at the
/// `maybe_fail_at` call boundary.
///
/// `and_then` short-circuits when `$binding` is already `Err`, so a
/// real allocation failure takes precedence over the test-armed
/// synthetic one — armed seams only force failure at sites where the
/// real allocation would have succeeded.
macro_rules! seam_check {
    ($binding:ident, $site:expr) => {
        #[cfg(feature = "__test_utils")]
        let $binding = $binding.and_then(|()| $crate::testing::oom::maybe_fail_at($site));
    };
}

pub(crate) use seam_check;

#[cfg(test)]
mod tests {
    use super::*;

    /// Every [`SeamSite`] variant names its end-to-end coverage test.
    /// Pak/index/decompression variants are tested in
    /// `paksmith-core-tests/tests/oom_pak.rs`; asset-side variants
    /// are tested in `paksmith-core-tests/tests/oom_asset.rs`; `.usmap`
    /// variants are tested in `asset/mappings.rs`, since cargo-mutants
    /// credits only a crate's own tests. The exhaustive `match` is the
    /// load-bearing guard: adding a variant without a match arm fails to
    /// compile, so a new seam can't slip in
    /// production-wired-but-test-uncovered (#275, #276). The named string is documentary — the contributor's
    /// commitment to name the integration test exactly that, not a
    /// runtime check the function exists.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one match arm per seam variant, across every family"
    )]
    fn every_seamsite_variant_has_named_integration_coverage() {
        const fn pak_integration_test_name(site: PakSeam) -> &'static str {
            match site {
                PakSeam::CompressedReserve => {
                    "read_entry_surfaces_compressed_block_reserve_failed_under_oom"
                }
                PakSeam::ScratchReserve => {
                    "read_entry_surfaces_zlib_scratch_reserve_failed_with_committed_bytes_under_oom"
                }
                PakSeam::FstringUtf16 => "read_fstring_utf16_surfaces_allocation_failed_under_oom",
                PakSeam::FstringUtf8 => "read_fstring_utf8_surfaces_allocation_failed_under_oom",
                PakSeam::FdiFullPath => "read_fdi_full_path_surfaces_allocation_failed_under_oom",
                PakSeam::FlatIndexEntries => {
                    "read_flat_index_entries_surfaces_allocation_failed_under_oom"
                }
                PakSeam::InlineCompressionBlocks => {
                    "read_inline_compression_blocks_surfaces_allocation_failed_under_oom"
                }
                PakSeam::EncodedCompressionBlocks => {
                    "read_encoded_compression_blocks_surfaces_allocation_failed_under_oom"
                }
                PakSeam::V10MainIndexBytes => {
                    "read_v10_main_index_bytes_surfaces_allocation_failed_under_oom"
                }
                PakSeam::V10EncodedEntriesBytes => {
                    "read_v10_encoded_entries_bytes_surfaces_allocation_failed_under_oom"
                }
                PakSeam::V10NonEncodedEntries => {
                    "read_v10_non_encoded_entries_surfaces_allocation_failed_under_oom"
                }
                PakSeam::V10FdiBytes => "read_v10_fdi_bytes_surfaces_allocation_failed_under_oom",
                PakSeam::V10PhiBytes => "read_v10_phi_bytes_surfaces_allocation_failed_under_oom",
                PakSeam::V10IndexEntries => {
                    "read_v10_index_entries_surfaces_allocation_failed_under_oom"
                }
                PakSeam::Lz4OutputReserve => {
                    "read_entry_surfaces_lz4_output_reserve_failed_under_oom"
                }
            }
        }
        const fn asset_integration_test_name(site: AssetSeam) -> &'static str {
            match site {
                AssetSeam::NameTable => {
                    "read_asset_name_table_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::ImportTable => {
                    "read_asset_import_table_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::ExportTable => {
                    "read_asset_export_table_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::CustomVersionContainer => {
                    "read_asset_custom_version_container_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::ExportPayloads => {
                    "read_asset_export_payloads_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::ExportPayloadBytes => {
                    "read_asset_export_payload_bytes_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::CollectionElements => {
                    "read_asset_collection_elements_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::SplitAssetCombined => {
                    "read_asset_split_asset_combined_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::DataTableRows => {
                    "read_asset_data_table_rows_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::DataResourceTable => {
                    "read_asset_data_resource_table_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::BulkDataBytes => {
                    "resolve_bulk_data_bytes_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::DecompressedBulkDataBytes => {
                    "resolve_decompressed_bulk_data_bytes_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::EnumTableMemo => {
                    "read_asset_enum_table_memo_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::FStringUtf8Bytes => {
                    "read_asset_fstring_utf8_bytes_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::FStringUtf16CodeUnits => {
                    "read_asset_fstring_utf16_code_units_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::StructLayoutMemo => {
                    "read_asset_struct_layout_memo_surfaces_allocation_failed_under_oom"
                }
                AssetSeam::ClassSchemaMemo => {
                    "read_asset_class_schema_memo_surfaces_allocation_failed_under_oom"
                }
            }
        }
        const fn mappings_test_name(site: MappingsSeam) -> &'static str {
            match site {
                MappingsSeam::SchemaNameBytes => {
                    "every_schema_name_copy_the_allocator_refuses_is_an_allocation_fault"
                }
                MappingsSeam::BrotliDecoderBytes => {
                    "every_brotli_decoder_allocation_the_allocator_refuses_is_an_allocation_fault"
                }
                MappingsSeam::FlattenedCache => {
                    "every_flattened_cache_reservation_the_allocator_refuses_is_an_allocation_fault"
                }
            }
        }
        // Touch the const fns so the matches' compile-time
        // exhaustiveness is anchored to live calls.
        let _ = pak_integration_test_name(PakSeam::CompressedReserve);
        let _ = asset_integration_test_name(AssetSeam::NameTable);
        let _ = mappings_test_name(MappingsSeam::SchemaNameBytes);
    }

    /// Every [`PakSeam`] / [`AssetSeam`] / [`MappingsSeam`] discriminant
    /// lines up with its slot index. The exhaustive `match`es are the
    /// load-bearing guards — adding a variant without updating them fails
    /// to compile here, forcing the contributor to slot the new site in. Paired with the `const _` `COUNT` guards on each inner
    /// enum, this pins both the counts AND the contiguous
    /// `0..COUNT` ordering that `ARM_STATE`'s array indexing assumes.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one match arm per seam variant, across every family"
    )]
    fn seam_site_discriminants_match_slot_indices() {
        const fn expected_pak_slot(site: PakSeam) -> usize {
            match site {
                PakSeam::CompressedReserve => 0,
                PakSeam::ScratchReserve => 1,
                PakSeam::FstringUtf16 => 2,
                PakSeam::FstringUtf8 => 3,
                PakSeam::FdiFullPath => 4,
                PakSeam::FlatIndexEntries => 5,
                PakSeam::InlineCompressionBlocks => 6,
                PakSeam::EncodedCompressionBlocks => 7,
                PakSeam::V10MainIndexBytes => 8,
                PakSeam::V10EncodedEntriesBytes => 9,
                PakSeam::V10NonEncodedEntries => 10,
                PakSeam::V10FdiBytes => 11,
                PakSeam::V10PhiBytes => 12,
                PakSeam::V10IndexEntries => 13,
                PakSeam::Lz4OutputReserve => 14,
            }
        }
        const fn expected_asset_slot(site: AssetSeam) -> usize {
            match site {
                AssetSeam::NameTable => PakSeam::COUNT,
                AssetSeam::ImportTable => PakSeam::COUNT + 1,
                AssetSeam::ExportTable => PakSeam::COUNT + 2,
                AssetSeam::CustomVersionContainer => PakSeam::COUNT + 3,
                AssetSeam::ExportPayloads => PakSeam::COUNT + 4,
                AssetSeam::ExportPayloadBytes => PakSeam::COUNT + 5,
                AssetSeam::CollectionElements => PakSeam::COUNT + 6,
                AssetSeam::SplitAssetCombined => PakSeam::COUNT + 7,
                AssetSeam::DataTableRows => PakSeam::COUNT + 8,
                AssetSeam::DataResourceTable => PakSeam::COUNT + 9,
                AssetSeam::BulkDataBytes => PakSeam::COUNT + 10,
                AssetSeam::DecompressedBulkDataBytes => PakSeam::COUNT + 11,
                AssetSeam::EnumTableMemo => PakSeam::COUNT + 12,
                AssetSeam::FStringUtf8Bytes => PakSeam::COUNT + 13,
                AssetSeam::FStringUtf16CodeUnits => PakSeam::COUNT + 14,
                AssetSeam::StructLayoutMemo => PakSeam::COUNT + 15,
                AssetSeam::ClassSchemaMemo => PakSeam::COUNT + 16,
            }
        }
        const fn expected_mappings_slot(site: MappingsSeam) -> usize {
            match site {
                MappingsSeam::SchemaNameBytes => PakSeam::COUNT + AssetSeam::COUNT,
                MappingsSeam::BrotliDecoderBytes => PakSeam::COUNT + AssetSeam::COUNT + 1,
                MappingsSeam::FlattenedCache => PakSeam::COUNT + AssetSeam::COUNT + 2,
            }
        }
        let pak_all = [
            PakSeam::CompressedReserve,
            PakSeam::ScratchReserve,
            PakSeam::FstringUtf16,
            PakSeam::FstringUtf8,
            PakSeam::FdiFullPath,
            PakSeam::FlatIndexEntries,
            PakSeam::InlineCompressionBlocks,
            PakSeam::EncodedCompressionBlocks,
            PakSeam::V10MainIndexBytes,
            PakSeam::V10EncodedEntriesBytes,
            PakSeam::V10NonEncodedEntries,
            PakSeam::V10FdiBytes,
            PakSeam::V10PhiBytes,
            PakSeam::V10IndexEntries,
            PakSeam::Lz4OutputReserve,
        ];
        assert_eq!(pak_all.len(), PakSeam::COUNT);
        for site in pak_all {
            assert_eq!(site as usize, expected_pak_slot(site));
            assert_eq!(SeamSite::Pak(site).slot(), expected_pak_slot(site));
        }
        let asset_all = [
            AssetSeam::NameTable,
            AssetSeam::ImportTable,
            AssetSeam::ExportTable,
            AssetSeam::CustomVersionContainer,
            AssetSeam::ExportPayloads,
            AssetSeam::ExportPayloadBytes,
            AssetSeam::CollectionElements,
            AssetSeam::SplitAssetCombined,
            AssetSeam::DataTableRows,
            AssetSeam::DataResourceTable,
            AssetSeam::BulkDataBytes,
            AssetSeam::DecompressedBulkDataBytes,
            AssetSeam::EnumTableMemo,
            AssetSeam::FStringUtf8Bytes,
            AssetSeam::FStringUtf16CodeUnits,
            AssetSeam::StructLayoutMemo,
            AssetSeam::ClassSchemaMemo,
        ];
        assert_eq!(asset_all.len(), AssetSeam::COUNT);
        for site in asset_all {
            assert_eq!(
                SeamSite::Asset(site).slot(),
                expected_asset_slot(site),
                "asset slot index mismatch for {site:?}"
            );
        }
        let mappings_all = [
            MappingsSeam::SchemaNameBytes,
            MappingsSeam::BrotliDecoderBytes,
            MappingsSeam::FlattenedCache,
        ];
        assert_eq!(mappings_all.len(), MappingsSeam::COUNT);
        for site in mappings_all {
            assert_eq!(
                SeamSite::Mappings(site).slot(),
                expected_mappings_slot(site),
                "mappings slot index mismatch for {site:?}"
            );
        }
        assert_eq!(
            SeamSite::COUNT,
            PakSeam::COUNT + AssetSeam::COUNT + MappingsSeam::COUNT
        );
    }
}

#[cfg(all(test, feature = "__test_utils"))]
mod macro_tests {
    use std::collections::TryReserveError;

    use super::{AssetSeam, PakSeam, SeamSite};
    use crate::testing::oom::arm_at;

    /// Armed seam turns `Ok(())` into `Err(_)`. Pins the basic
    /// macro-expansion contract.
    #[test]
    fn seam_check_fires_when_armed() {
        let _guard = arm_at(SeamSite::Pak(PakSeam::CompressedReserve), 0);
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::Pak(PakSeam::CompressedReserve));
        assert!(result.is_err(), "armed seam must turn Ok into Err");
    }

    /// Unarmed seam passes `Ok(())` through unchanged.
    #[test]
    fn seam_check_passes_when_unarmed() {
        let result: Result<(), TryReserveError> = Ok(());
        seam_check!(result, SeamSite::Pak(PakSeam::FdiFullPath));
        assert!(result.is_ok(), "unarmed seam must passthrough Ok");
    }

    /// When the binding is already `Err`, `and_then` short-circuits
    /// — the seam is NOT consumed and the original error is
    /// preserved. This is the load-bearing invariant: a real
    /// allocation failure always wins over an armed synthetic one,
    /// so tests can't accidentally mask real OOMs.
    #[test]
    fn seam_check_preserves_prior_error_without_consuming_arm() {
        let _guard = arm_at(SeamSite::Pak(PakSeam::ScratchReserve), 0);
        let original = Vec::<u8>::new()
            .try_reserve_exact(usize::MAX)
            .expect_err("synthetic capacity-overflow must fail");
        let result: Result<(), TryReserveError> = Err(original);
        seam_check!(result, SeamSite::Pak(PakSeam::ScratchReserve));
        assert!(result.is_err(), "original error must propagate");
        // Arm state must NOT have been consumed by the short-circuit.
        let probe = crate::testing::oom::maybe_fail_at(SeamSite::Pak(PakSeam::ScratchReserve));
        assert!(
            probe.is_err(),
            "seam was incorrectly consumed despite Err short-circuit"
        );
    }

    /// Grouped enum doesn't introduce cross-domain leakage: arming a
    /// pak seam doesn't fire on the corresponding-slot asset seam,
    /// and vice versa.
    #[test]
    fn pak_and_asset_seams_are_isolated() {
        // Pak slot 0 (CompressedReserve) vs Asset slot 0 (NameTable
        // → global slot PakSeam::COUNT). Different slot indices.
        let _guard = arm_at(SeamSite::Pak(PakSeam::CompressedReserve), 0);
        assert!(
            crate::testing::oom::maybe_fail_at(SeamSite::Asset(AssetSeam::NameTable)).is_ok(),
            "armed Pak seam must not fire on Asset seam"
        );
    }

    /// Asset-side seam firing exercises slot indices >= PakSeam::COUNT,
    /// pinning that slot() routes asset variants past the pak block.
    #[test]
    fn asset_seam_fires_at_upper_slot() {
        let _guard = arm_at(SeamSite::Asset(AssetSeam::SplitAssetCombined), 0);
        let probe =
            crate::testing::oom::maybe_fail_at(SeamSite::Asset(AssetSeam::SplitAssetCombined));
        assert!(probe.is_err(), "armed Asset seam must fire");
    }
}
