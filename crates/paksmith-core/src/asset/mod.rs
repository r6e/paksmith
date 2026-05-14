//! UAsset deserialization.
//!
//! # Scope (Phase 2a)
//!
//! Parses the structural header of UE 4.21–UE 5.x `.uasset` files.
//! Property bodies (`FPropertyTag`-iterated payloads inside export
//! serialized regions) are carried as opaque bytes via the
//! `PropertyBag::Opaque` variant landing in a later task; tagged-
//! property iteration arrives in Phase 2b.
//!
//! # Module layout (Phase 2a, growing per-task)
//!
//! Phase 2a builds incrementally: each task in `docs/plans/phase-2a-
//! uasset-header.md` adds one submodule. This `mod.rs` re-exports the
//! types that have landed so far. The aggregate `Package::read_from`
//! plus `Asset` and `AssetContext` types land alongside the orchestrating
//! parser in a later task.
//!
//! See `docs/plans/phase-2a-uasset-header.md` for the implementation
//! plan and `docs/design/SPEC.md` § "Asset Data Model" for the
//! architectural intent.

pub mod version;

pub use version::AssetVersion;

#[cfg(test)]
mod tests {
    // Smoke test: read_fstring is reachable from this module via the
    // crate-public re-export at container::pak::index. Compile-only —
    // the test passes iff this links.
    //
    // Phase 2a Task 2 motivation: the existing read_fstring was
    // pub(super) inside container::pak::index. Promoting to pub(crate)
    // lets asset/ parsers share the one FString reader instead of
    // forking it. See the use statement above.
    #[test]
    fn read_fstring_is_crate_visible() {
        // Bind through an explicit `fn` pointer with a HRTB-shaped
        // input-lifetime: the path must resolve AND the generic must
        // accept any `&mut Cursor<Vec<u8>>`. The owned-`Vec` reader
        // sidesteps the second lifetime parameter that
        // `Cursor<&[u8]>` would introduce (which would defeat the
        // function-item → fn-pointer coercion).
        let _: for<'a> fn(&'a mut std::io::Cursor<Vec<u8>>) -> crate::Result<String> =
            crate::container::pak::index::read_fstring;
    }
}
