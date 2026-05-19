//! Library surface for `paksmith-doc-lint` — hosts the CI lint
//! routines that validate the `docs/formats/` per-format documentation
//! template introduced in the UE format documentation framework.
//!
//! Two subcommands ship with this crate:
//!   - `required-headings` — verifies every per-format README under a
//!     given directory contains the canonical section headings.
//!   - `status-enum` — verifies the inventory README's status column
//!     only uses values from a fixed enum.
//!
//! Module bodies land in subsequent commits; this file is the
//! scaffolding entry point. Not intended for downstream consumers —
//! this crate is excluded from the workspace's `default-members` and
//! not published.

#![allow(missing_docs)]

pub mod required_headings;
pub mod status_enum;
