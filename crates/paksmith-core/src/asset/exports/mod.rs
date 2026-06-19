//! Phase 3 typed export readers. The module hosts the class-name
//! dispatch table plus the typed reader functions in the
//! `data_table.rs`, `texture/`, `audio/`, and `mesh/` submodules.
//!
//! The dispatch from class-name → typed-reader-fn lives in
//! [`dispatch::class_dispatch`]. Each entry maps a `&'static str`
//! class name to a `fn(...)` reader; the reader-fn returns the typed
//! `Asset::*` variant for its class PLUS any `FByteBulkData` records
//! the reader collected during parse.

pub(crate) mod audio;
pub(crate) mod data_table;
pub(crate) mod dispatch;
pub(crate) mod mesh;
pub(crate) mod texture;
