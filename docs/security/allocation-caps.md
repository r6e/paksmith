# Allocation-cap rationale and empirical justification

Paksmith's index parsers enforce hard upper bounds on the size of
buffers and entry counts they will reserve from the allocator. This
document records the empirical data backing those caps and the
correct rationale (which differs from the original commit messages).

**Status:** Per-platform local baseline (macOS-arm64). Cross-platform
(Linux x86_64, Windows x86_64) measurements deferred — see follow-up
issue.

## Caps under audit

| Constant | Value | Defined at | Applied to |
|---|---|---|---|
| `MAX_FDI_BYTES` | 256 MiB | `path_hash.rs:57` | v10+ FDI region byte size + per-PHI region byte size |
| `MAX_INDEX_BYTES` | 1 GiB | `path_hash.rs:71` | v10+ main-index region byte size |
| `MAX_FLAT_INDEX_ENTRIES` | 10 M | `flat.rs:38` | v3-v9 `Vec<PakIndexEntry>` entry count (≈ 1-2 GiB at `sizeof(PakIndexEntry) ≈ 144 B`) |

## What the original justification claimed

Source-code comments and PR-message language framed the caps as
protection against "thrashing the allocator on constrained runners"
during a `try_reserve_exact(N)` call for very large `N`. Per PR #181
(closing #128, sibling of PR #226):

> "the byte-budget check below still allowed ~946M entries against a
> 50 GB archive — `try_reserve_exact` would fail soft, but the attempt
> thrashes the allocator on constrained runners."

That framing is **wrong on macOS-arm64**, and likely wrong on Linux
x86_64 with default overcommit. The empirical measurement below
shows the `try_reserve_exact` call itself is microseconds at every
tested size — there is no thrashing because `vm_allocate` / `mmap`
return immediately without committing physical pages.

## Empirical measurement (issue #228)

Bench source: `crates/paksmith-bench/benches/try_reserve_exact_cost.rs`.
Methodology: each iteration constructs `Vec::<u8>::new()` and calls
`try_reserve_exact(N)`. Drop runs inside the measured closure;
criterion adapts its iteration count to per-iteration cost.

### Results — macOS-arm64

Hardware: Apple Silicon (`Darwin 25.1.0`, arm64). Criterion `--quick`
mode (point estimates, ~5 s total).

| `N` | Median wall-clock | Notes |
|---|---|---|
| 1 KiB | 62.7 ns | Small alloc, ordinary heap path |
| 1 MiB | 620 ns | Lazy mmap |
| 256 MiB (`MAX_FDI_BYTES`) | 538 ns | Lazy mmap — no page commit |
| 1 GiB (`MAX_INDEX_BYTES`) | 898 ns | Lazy mmap — no page commit |
| 10 GiB | 15.2 µs | Larger mapping, more page-table entries |
| 100 GiB | 136.6 µs | Same scaling pattern |
| `isize::MAX` | 7.8 ns | Synchronous `RawVec` capacity-overflow refusal |
| `usize::MAX` | 2.1 ns | Synchronous `RawVec` capacity-overflow refusal |

**All reservations complete in < 1 ms across the entire tested
range, including 100 GiB.** The "thrashing" model does not match the
allocator's actual behavior on this platform — macOS's `vm_allocate`
is lazy.

## Corrected rationale

The caps ARE load-bearing — but for a different reason than
"allocator overhead at `try_reserve_exact` time."

Every reservation site in `path_hash.rs` follows the pattern:

```rust
let mut buf: Vec<u8> = Vec::new();
try_reserve_index(&mut buf, n, ctx, Some(SeamSite::*))?;   // (1) lazy reserve
buf.resize(n, 0);                                          // (2) eager fill — commits N bytes of RAM
reader.read_exact(&mut buf)?;                              // (3) overwrites with wire bytes
```

Step **(1)** is microseconds (per the empirical data above) — the
mapping is lazily-backed.

Step **(2)** `Vec::resize` touches every byte of the new capacity to
zero-initialize it. **This is the step that commits physical RAM.**
A 50 GB unbounded `index_size` would commit 50 GB of RAM on a
machine with sufficient swap, or `oom-kill` an under-provisioned
runner before step (3) even reads the first byte.

Step **(3)** then overwrites the just-committed memory with parsed
bytes.

So the caps prevent **eager RAM commit during `Vec::resize`**, not
allocator thrash. The protective intent is identical, but the cost
model is different.

This matters for two reasons:

1. **Future cap tuning**: numbers should be sized against
   acceptable RAM commitment for a `paksmith list`-style consumer
   that opens an archive but doesn't extract entries. 1 GiB is a
   generous but defensible upper bound for "shouldn't surprise a
   metadata-only consumer."
2. **Documentation accuracy**: the misleading "allocator thrash"
   comments have been corrected in this PR. Future contributors
   reading the cap rationale will see the actual mechanism.

## Decision: caps stay as-is

The current values are justified by the corrected rationale:

- **`MAX_FDI_BYTES = 256 MiB`**: 256 MiB RAM commitment for an FDI
  region. A real-world FDI for a 100k-file pak is typically a few MB;
  256 MiB is comfortably larger than anything legitimate while still
  bounding memory commitment for a `list`-style consumer.
- **`MAX_INDEX_BYTES = 1 GiB`**: 1 GiB RAM commitment for the v10+
  main-index byte buffer. A 1 GiB main index supports a >30M-entry
  archive at ~30 bytes/entry.
- **`MAX_FLAT_INDEX_ENTRIES = 10 M`**: ≈ 1-2 GiB RAM at
  `sizeof(PakIndexEntry) ≈ 144 B`. Comparable upper bound to
  `MAX_INDEX_BYTES` in commitment terms, expressed in the entry-count
  unit that matches the receiver type (`Vec<PakIndexEntry>`, not
  `Vec<u8>`).

The v3-v9 vs v10+ unit asymmetry (entries vs bytes) is intentional —
each cap is expressed in the dimension that matches the bounded
allocation's receiver type, and the per-cap RAM-commitment ceiling
is in the same order of magnitude (1-2 GiB).

## Out of scope (follow-up)

- **Linux x86_64 measurements**: `mmap(MAP_ANONYMOUS)` is also lazy
  by default (`vm.overcommit_memory = 0`), so the macOS findings
  likely generalize, but should be measured. Of particular interest:
  GitHub Actions hosted runners (2-core, 7 GiB RAM) where the
  overcommit ceiling is lower than a 64-GiB workstation.
- **Windows x86_64 measurements**: `HeapAlloc` via Low Fragmentation
  Heap may commit eagerly for size classes above a threshold;
  behavior may differ from the lazy-mmap platforms.
- **Cross-runner CI benchmark**: extend `.github/workflows/bench.yml`
  (already gated `workflow_dispatch`-only) to run this bench on the
  three-platform matrix and capture baseline numbers.
