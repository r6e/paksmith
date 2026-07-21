# Allocation-cap rationale and empirical justification

Paksmith's index parsers enforce hard upper bounds on the size of
buffers and entry counts they will reserve from the allocator. This
document records the empirical data backing those caps and the
corrected rationale.

**Status:** macOS-arm64 local baseline. Linux x86_64 and Windows
x86_64 measurements are tracked separately; see `Out of scope` below.

## Caps under audit

| Constant | Value | Defined at | Receiver | Rationale |
|---|---|---|---|---|
| `MAX_FDI_BYTES` | 256 MiB | `path_hash.rs:128` | `Vec<u8>` | RAM commit during `resize+read_exact`; sized so a `paksmith list` consumer never commits more than 256 MiB for an FDI region. |
| `MAX_INDEX_BYTES` | 1 GiB | `path_hash.rs:148` | `Vec<u8>` | RAM commit during `resize+read_exact`; sized for a >30M-entry v10+ archive at ~30 B/entry while staying under "shouldn't surprise a metadata-only consumer." |
| `MAX_FLAT_INDEX_ENTRIES` | 10 M | `flat.rs:38` | `Vec<PakIndexEntry>` | Per-entry heap allocation + Vec slot commit during the `push`-fill loop; sized so the loop's worst-case cost (10M iterations × `read_from` + filename `String` alloc) stays bounded. |
| `MAX_IOSTORE_DIRECTORY_INDEX_BYTES` | 256 MiB *(provisional)* | *(Phase 8 deliverable — no constant exists yet)* | `Vec<u8>` | RAM commit for the `.utoc` directory-index buffer read (see `docs/formats/container/iostore-directory-index.md` §*Caps & limits*). Provisional value borrowed by analogy from `MAX_FDI_BYTES` — both are "metadata sub-region read in full before parsing inside a larger container." The Phase 8 IoStore-reader implementation PR MUST land this constant and replace the provisional value with an empirically-justified one if real-world cooked containers exceed 256 MiB. |

## The "thrashing" claim was wrong

Source-code comments and PR-message language framed the caps as
protection against `try_reserve_exact(N)` "thrashing the allocator on
constrained runners" for very large `N`. Per PR #181:

> "the byte-budget check below still allowed ~946M entries against a
> 50 GB archive — `try_reserve_exact` would fail soft, but the attempt
> thrashes the allocator on constrained runners."

That framing is **wrong on macOS-arm64** (and likely on Linux under
default overcommit). The bench data below shows the `try_reserve_exact`
call itself completes in microseconds at every tested size — including
1 GiB. `vm_allocate` / `mmap(MAP_ANONYMOUS)` reserve address space
lazily, without committing physical pages.

## Empirical measurement (issue #228)

Bench source: `crates/paksmith-bench/benches/try_reserve_exact_cost.rs`.
Methodology: criterion default sample_size (50 for `try_reserve_exact_cost`,
10 for `resize_fill_cost`) + `measurement_time(5s)` per group. Numbers
below are criterion's median point estimate ± typical absolute deviation.

### `try_reserve_exact_cost` (just the reserve call)

Each iteration constructs `Vec::<u8>::new()` and calls
`try_reserve_exact(N)`. Drop runs inside the measured closure. For
unwritten reservations on lazy-mmap platforms, time is dominated by
address-space bookkeeping, NOT physical commit.

| `N` | Median |
|---|---|
| 1 KiB | 29.4 ns |
| 1 MiB | 611 ns |
| 256 MiB (`MAX_FDI_BYTES`) | 528 ns |
| 1 GiB (`MAX_INDEX_BYTES`) | 910 ns |
| `isize::MAX` | 8.5 ns (synchronous `RawVec` capacity-overflow refusal) |
| `usize::MAX` | 2.0 ns (synchronous `RawVec` capacity-overflow refusal) |

Reserve cost is **microseconds even at 1 GiB**. The "allocator
thrash at reservation time" claim is empirically false on this
platform.

### `resize_fill_cost` (reserve + `resize(N, 0)`)

Each iteration constructs `Vec::<u8>::new()`, calls
`try_reserve_exact(N)`, then `Vec::resize(N, 0)` to zero-fill — which
faults every page in the new capacity, the work that **actually**
commits physical RAM. Capped at 256 MiB to bound `sample_size(10) × N`
total touched memory.

| `N` | Median |
|---|---|
| 1 KiB | 38.3 ns |
| 1 MiB | 9.19 µs |
| 64 MiB | 544 µs |
| 256 MiB (`MAX_FDI_BYTES`) | 2.21 ms |

Fill cost scales **linearly** with N at ~8.6 ms/GiB. Extrapolated to
the production caps:
- 256 MiB FDI region: ~2.2 ms (measured)
- 1 GiB main index: ~9 ms (extrapolated from the 256 MiB → 1 GiB scaling)
- 50 GiB unbounded index (the rejected case): ~430 ms

The caps prevent the unbounded case from spending arbitrary time
committing RAM. On a 2 GiB GHA hosted runner, the 50 GiB case would
also exhaust physical memory — not just stall the parser.

## Corrected rationale — two distinct mechanisms

The two cap families protect different post-reserve phases:

### `path_hash.rs` v10+ regions: `resize+read_exact`

```rust
let mut buf: Vec<u8> = Vec::new();
try_reserve_index(&mut buf, n, ctx, PakSeam::*)?;          // lazy, microseconds
buf.resize(n, 0);                                          // zero-fills n bytes → commits n bytes of RAM
reader.read_exact(&mut buf)?;                              // overwrites zeros with wire bytes
```

The cap bounds the `resize` step. A 50 GiB `index_size` would commit
50 GiB of physical RAM on a machine with sufficient swap, or
`oom-kill` an under-provisioned runner before `read_exact` reads the
first byte. The `resize_fill_cost` numbers above show the per-MB
zero-fill rate.

### `flat.rs` v3-v9 entries: `push`-fill loop

```rust
let mut entries: Vec<PakIndexEntry> = Vec::new();
try_reserve_index(&mut entries, n, ctx, PakSeam::FlatIndexEntries)?;        // lazy address-space reserve
for _ in 0..n {
    entries.push(PakIndexEntry::read_from(&mut bounded, ...)?);             // per-iter: heap alloc + slot commit
}
```

The cap bounds the loop iteration count. Each `push` initializes one
Vec slot (small commit) AND `PakIndexEntry::read_from` heap-allocates
a filename `String`. Without the cap, an attacker-recorded
`entry_count = 946M` would drive 946M loop iterations doing the
per-entry allocation + slot commit, even though the `try_reserve_exact`
call itself is microseconds.

(The upstream `index_size / ENTRY_MIN_RECORD_BYTES` byte-budget check
truncates `entry_count` against the actual index byte size — but at a
50 GB archive that's still ~946M permitted entries without the
`MAX_FLAT_INDEX_ENTRIES` cap fired on top.)

## Decision: caps stay as-is (macOS-confirmed)

The current values are justified by the corrected rationale and the
empirical reserve+fill numbers. The v3-v9 vs v10+ unit asymmetry
(entries vs bytes) is intentional — each cap is expressed in the
dimension that matches the bounded allocation's receiver type, and
the per-cap RAM-commitment ceiling is in the same order of magnitude
(1-2 GiB).

The decision is **provisional pending cross-platform confirmation**
(#281). Windows `HeapAlloc` via Low Fragmentation Heap may commit
eagerly above certain size classes — if so, the original "allocator
overhead at reservation time" framing could be correct on Windows
even though it's wrong on macOS-arm64, and the per-cap headroom may
need revisiting.

## Out of scope

- **Cross-platform measurements** (Linux x86_64, Windows x86_64) —
  filed #281. macOS findings likely generalize to Linux (lazy mmap
  under default overcommit); Windows is the question mark.
- **CI baseline gating** — extending `.github/workflows/bench.yml`
  (already `workflow_dispatch`-only) to capture and compare baselines
  is a separate task; this PR is a one-time audit.
- **Cap retuning derived from a runner-pressure model** — current
  values are "comfortably larger than legitimate, smaller than
  surprise"; a more rigorous derivation (e.g., GHA hosted runner has
  7 GiB RAM, reserve X for parser + OS, cap at Y) is a separate
  exercise.
