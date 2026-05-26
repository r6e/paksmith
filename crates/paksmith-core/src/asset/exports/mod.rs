//! Phase 3 typed export readers. Today (3a) the module hosts only
//! the class-name dispatch table; 3d-3h populate the table with
//! `data_table.rs`, `texture/`, `audio/`, `mesh/` submodules and
//! their typed reader functions.
//!
//! The dispatch from class-name → typed-reader-fn lives in
//! [`dispatch::class_dispatch`]. Each sub-phase (3d/3e/3f/3g/3h)
//! inserts one `&'static str → fn(...)` entry; the reader-fn
//! returns the typed `Asset::*` variant for its class PLUS any
//! `FByteBulkData` records the reader collected during parse.

pub(crate) mod dispatch;
