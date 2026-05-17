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

use std::io::Write;
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

/// Path to the canonical 818-byte v8b pak committed under
/// `tests/fixtures/`. Walks up two levels from `CARGO_MANIFEST_DIR`
/// (the bench crate's directory) to the workspace root, then into
/// `tests/fixtures/`. Used by the asset + pak benches that exercise
/// the canonical end-to-end pipeline.
///
/// # Panics
/// If `CARGO_MANIFEST_DIR` doesn't have two ancestor directories —
/// would only happen if cargo's directory layout invariant changes
/// upstream, in which case every bench in this crate would fail
/// for the same reason.
#[must_use]
pub fn tiny_pak_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above paksmith-bench manifest");
    workspace_root.join("tests/fixtures/real_v8b_uasset.pak")
}

/// `/dev/null`-equivalent sink — counts nothing, drops everything.
/// Avoids letting `Vec` reallocation noise into decompression /
/// serialization benches whose subject is throughput-per-byte rather
/// than allocator behavior. Lives here so `pak.rs` and `inspect.rs`
/// share one implementation rather than each carrying its own copy.
pub struct NullWriter;

impl Write for NullWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
