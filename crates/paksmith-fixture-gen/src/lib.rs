//! Library surface for `paksmith-fixture-gen` — exposes the
//! cross-parser oracle and synthetic UAsset helpers to integration
//! test targets (`tests/*.rs`) inside this crate.
//!
//! The `main.rs` binary is the primary consumer; the library is a
//! thin wrapper that re-exports the same `uasset` module so the
//! `differential_proptest` integration test (issue #244) can reach
//! [`uasset::cross_validate_with_unreal_asset`] without duplicating
//! it. Not intended for downstream consumers — this crate is
//! excluded from the workspace's `default-members` and not
//! published.

#![allow(missing_docs)]

pub mod uasset;

/// UE's conventional pak mount point — three `..` segments instructing
/// the runtime to traverse three directories up from the pak's load
/// location before resolving in-pak entry paths. Lives here (not on
/// `main.rs`) so the bin/lib split has a single source of truth, and
/// so `uasset.rs`'s `super::MOUNT_POINT` resolves under the lib build.
pub const MOUNT_POINT: &str = "../../../";
