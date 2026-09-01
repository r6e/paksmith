//! Test-utility surface for the integration test suite under
//! `tests/` and for in-source `#[cfg(test)] mod tests` blocks that
//! want to avoid duplicating wire-format synthesis helpers.
//!
//! **Stability**: gated behind the `__test_utils` Cargo feature (note
//! the leading `__` prefix — the convention signals "internal to
//! paksmith's test infra; do not depend on this from downstream
//! crates"). An in-source test in THIS crate must enable the feature
//! to reach it. An ordinary build compiles none of it, and anything
//! `pub` here is a `cargo test`-only surface that may change in any
//! release.
//!
//! That is the gate's INTENT, not a guarantee cargo enforces. Features
//! resolve globally per package, so a non-dev dependency on
//! `paksmith-core` from a workspace member, plus anything in the graph
//! activating `__test_utils`, compiles this module into that member's
//! release build. The crate's `Cargo.toml` records the same caveat and
//! asks reviewers to check it when adding a consumer.
//!

pub mod bench;
pub mod bulk_data;
pub mod gltf_fixtures;
pub mod oom;
pub mod uasset;
pub mod usmap;
pub mod v10;
pub mod wire;
