//! Test-utility surface for the integration test suite under
//! `tests/` and for in-source `#[cfg(test)] mod tests` blocks that
//! want to avoid duplicating wire-format synthesis helpers.
//!
//! **Stability**: gated behind the `__test_utils` Cargo feature
//! (note the leading `__` prefix — the convention signals "internal
//! to paksmith's test infra; do not depend on this from downstream
//! crates"). Anything `pub` here is a `cargo test`-only surface and
//! may change in any release.

pub mod oom;
pub mod v10;
