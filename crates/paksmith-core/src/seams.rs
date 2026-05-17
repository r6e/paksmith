//! Always-compiled OOM-seam type + macro.
//!
//! Lives outside `crate::testing` (which is `__test_utils`-gated) for
//! two reasons:
//!
//! 1. The [`seam_check!`] macro is callable at every production site
//!    regardless of feature configuration; the cfg gate sits inside
//!    the macro body and expands to nothing when `__test_utils` is
//!    off.
//! 2. [`SeamSite`] itself is always available, so helpers like
//!    `crate::error::try_reserve_index` can accept an
//!    `Option<SeamSite>` parameter in their signature — the runtime
//!    [`crate::testing::oom::maybe_fail_at`] dispatch is still
//!    `__test_utils`-gated, but the type plumbing doesn't fragment by
//!    feature flag. See #266 and #270.

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
// All variants are reachable: the [`Self::CompressedReserve`] family
// is constructed in [`crate::seams::seam_check!`] macro expansions
// which the dead-code analyzer skips in non-`__test_utils` builds,
// and the [`Self::FlatIndexEntries`] family is constructed by the
// always-compiled `crate::error::try_reserve_index` callers. The
// suppression covers the cfg-gated-usage blindspot, not real dead
// code.
#[allow(dead_code)]
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
    /// `FlatIndex::read_from`'s entries vec. Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::FlatIndexEntries`. Routed via
    /// `crate::error::try_reserve_index`.
    FlatIndexEntries,
    /// `FPakEntry` v3-v9 inline compression-block table. Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::InlineCompressionBlocks`. Routed
    /// via `crate::error::try_reserve_index`.
    InlineCompressionBlocks,
    /// `FPakEntry` v10+ encoded compression-block table (bit-packed
    /// from the 31-bit length-prefix word). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::EncodedCompressionBlocks`. Routed
    /// via `crate::error::try_reserve_index`.
    EncodedCompressionBlocks,
    /// v10+ main-index bytes buffer. Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10MainIndexBytes`. Routed via
    /// `crate::error::try_reserve_index`.
    V10MainIndexBytes,
    /// v10+ encoded-entries blob (bit-packed pak entries). Surfaces
    /// as [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10EncodedEntriesBytes`. Routed
    /// via `crate::error::try_reserve_index`.
    V10EncodedEntriesBytes,
    /// v10+ non-encoded entries vec (`PakEntryHeader` records for
    /// entries that didn't fit the bit-packed encoding). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10NonEncodedEntries`. Routed via
    /// `crate::error::try_reserve_index`.
    V10NonEncodedEntries,
    /// v10+ Full Directory Index (FDI) bytes buffer. Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10FdiBytes`. Routed via
    /// `crate::error::try_reserve_index`.
    V10FdiBytes,
    /// v10+ Path Hash Index (PHI) bytes buffer. Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10PhiBytes`. Routed via
    /// `crate::error::try_reserve_index`.
    V10PhiBytes,
    /// v10+ flat-index entries vec (parallel to
    /// [`Self::FlatIndexEntries`] but reached via the v10+ code
    /// path). Surfaces as
    /// [`crate::error::IndexParseFault::AllocationFailed`] with
    /// `context: AllocationContext::V10IndexEntries`. Routed via
    /// `crate::error::try_reserve_index`.
    V10IndexEntries,
}

impl SeamSite {
    /// Total number of seam sites. Used to size the `ARM_STATE` array
    /// in [`crate::testing::oom`]. The `const _` guard below pins
    /// `COUNT` to [`Self::V10IndexEntries`]'s position, AND the
    /// exhaustive `match` in
    /// `tests::seam_site_discriminants_match_slot_indices` fails to
    /// compile when a new variant is added without slotting it in.
    /// Together they keep array indexing panic-free.
    pub const COUNT: usize = 14;
}

// Compile-time guard: `SeamSite::COUNT` must equal the last variant's
// discriminant + 1. This narrowly pins COUNT to the *current* last
// variant's position. A new variant added AFTER the last one would
// NOT trip this guard alone — the exhaustive `match` in the test
// module's `seam_site_discriminants_match_slot_indices` is the
// load-bearing catch for that case (it forces a compile error at the
// test site whenever a variant is added). Both layers together
// guarantee `ARM_STATE`'s array bounds.
const _: [(); SeamSite::COUNT] = [(); SeamSite::V10IndexEntries as usize + 1];

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
