//! `FReferenceSkeleton` reader — bone hierarchy + bind pose for `USkeletalMesh`
//! (Phase 3h). Wire reference: `docs/formats/mesh/skeleton.md`. Wired into
//! `USkeletalMesh::read_typed` by PR2.

/// Maximum bones per skeleton. Matches the 16-bit bone-index ceiling
/// (`2^16`) used by `FStaticLODModel` / `FSkinWeightVertexBuffer`.
///
/// NOTE: no `#[cfg(feature = "__test_utils")]` accessor — per the sibling
/// mesh-cap convention (`vertex_buffers.rs` / `texture2d.rs`), the cap is pinned
/// via the in-source over-cap error-path test (added with the reader in Task 4);
/// an integration-test consumer would add the accessor when one exists.
///
/// `#[allow(dead_code)]`: the only referent until Task 4 is the value-pin test;
/// the lib target (compiled without `cfg(test)` by `clippy --all-targets`) would
/// otherwise flag it dead. `read_reference_skeleton` (Task 4) is the real user.
#[allow(dead_code)]
pub(crate) const MAX_BONES_PER_SKELETON: usize = 1 << 16; // 65_536

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_bones_cap_value() {
        assert_eq!(MAX_BONES_PER_SKELETON, 65_536);
    }
}
