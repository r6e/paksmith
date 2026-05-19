//! Shared test scaffolding for the `property` sub-modules.
//!
//! `make_ctx` and `write_fname` show up in every property test file
//! (tag.rs, primitives.rs, text.rs, mod.rs tests, plus the
//! integration tests under `tests/`). Centralizing them here:
//! 1. Removes ~30 lines of identical scaffolding per module.
//! 2. Makes Phase 2c's container reader tests (which also use
//!    `make_ctx` in 30+ sites per the plan) reach the same helper
//!    without copying again.
//!
//! Gated on `#[cfg(any(test, feature = "__test_utils"))]` matching
//! the rest of `paksmith-core::testing` — the helpers are never
//! reachable from release builds.

use std::sync::Arc;

use crate::asset::{
    AssetContext,
    export_table::ExportTable,
    import_table::ImportTable,
    name_table::{FName, NameTable},
    version::AssetVersion,
};

/// Build an `AssetContext` whose name table is the given list of
/// strings (in wire order), with empty import/export tables and the
/// default `AssetVersion`. Sufficient for almost every property
/// reader unit test — they only consume `ctx.names` for FName
/// resolution.
#[must_use]
pub fn make_ctx(names: &[&str]) -> AssetContext {
    let table = NameTable {
        names: names.iter().map(|n| FName::new(n)).collect(),
    };
    AssetContext {
        names: Arc::new(table),
        imports: Arc::new(ImportTable::default()),
        exports: Arc::new(ExportTable::default()),
        version: AssetVersion::default(),
        mappings: None,
    }
}

/// Append a wire-format FName `(index, number)` pair to `buf` — the
/// two-i32-LE little-endian payload `read_fname_pair` expects on the
/// other side of the byte stream.
pub fn write_fname(buf: &mut Vec<u8>, index: i32, number: i32) {
    buf.extend_from_slice(&index.to_le_bytes());
    buf.extend_from_slice(&number.to_le_bytes());
}
