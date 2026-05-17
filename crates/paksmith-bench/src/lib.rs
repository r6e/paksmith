//! Shared bench helpers for `paksmith-bench`.
//!
//! Provides a lazy-cache layer for bench fixtures that would
//! otherwise be regenerated on every `cargo bench` invocation. The
//! cache lives under `target/bench-fixtures/` (gitignored via the
//! workspace's `/target` exclusion) and is keyed by the fixture's
//! identifier; the consumer supplies a closure that materializes
//! the bytes when the cache misses.
//!
//! **Stability:** internal to `paksmith-bench`. Not published; not
//! intended for downstream consumers.

#![allow(missing_docs)]

use std::path::PathBuf;

/// Resolve `target/bench-fixtures/<name>` and return it. Walks up
/// from `CARGO_MANIFEST_DIR` (this crate's directory) to find the
/// workspace root by looking for the workspace `Cargo.toml`. Falls
/// back to a sibling `target/` if the workspace marker isn't found
/// (shouldn't happen in normal invocation but keeps the resolver
/// defensive against unusual `cargo` invocation contexts).
#[must_use]
pub fn bench_fixture_path(name: &str) -> PathBuf {
    // `CARGO_MANIFEST_DIR` is set by cargo to the directory of the
    // crate currently being built — `crates/paksmith-bench`. Walk up
    // two levels to land at the workspace root, then into `target/
    // bench-fixtures/`.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or(&manifest_dir);
    workspace_root.join("target/bench-fixtures").join(name)
}

/// Lazy-generate a bench fixture file. If `target/bench-fixtures/
/// <name>` already exists, returns its path immediately. Otherwise
/// runs `generate` to materialize the bytes, atomically writes them
/// via `.tmp` + rename, and returns the path.
///
/// `generate` should be deterministic — see
/// `paksmith_fixture_gen::uasset::synthesize_uasset` for the
/// canonical deterministic generator. Determinism makes the cache
/// reusable across runs (and across baselines, when comparing
/// against `phase-2a-done`). Not linked because
/// `paksmith-fixture-gen` lives in `[dev-dependencies]` and isn't
/// reachable from rustdoc's resolution scope on this crate.
///
/// # Panics
/// On any filesystem failure (mkdir, atomic-rename, write) — these
/// are infrastructure errors, not bench-domain errors, and surfacing
/// them as panics inside `cargo bench` is the simplest signal.
#[must_use]
pub fn lazy_fixture(name: &str, generate: impl FnOnce() -> Vec<u8>) -> PathBuf {
    let path = bench_fixture_path(name);
    if path.exists() {
        return path;
    }

    let parent = path.parent().expect("bench_fixture_path has parent");
    std::fs::create_dir_all(parent).expect("create target/bench-fixtures/");

    let bytes = generate();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes).expect("write bench fixture tmp");
    std::fs::rename(&tmp, &path).expect("rename bench fixture into place");
    path
}
