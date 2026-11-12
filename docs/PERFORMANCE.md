# Paksmith performance baseline

Snapshots of paksmith-core's hot paths. The `phase-2a-done` baseline
was measured immediately before the Phase 2b property-iteration
rewrite, per issue #245, so a regression introduced by the
typed-property work is detectable against a real-numbers reference
rather than against operator intuition. Later sections time targeted
inputs.

## How to read this

Each table row is one criterion benchmark target. The numbers
reported are the **median** point estimate across the sample
collection — not the mean, not the worst case. Median is robust to
the single-sample outliers that show up under macOS scheduler
pressure on a workstation.

Read with the input scale in mind: a 16-byte parse and a 1 MiB parse
both report their median ns/iter, but comparing them directly is
meaningless. The throughput column is the input-scaled metric and
should be the first thing to consult for "is this bench getting
faster or slower."

For comparison across runs:

```bash
# Run the baseline-aware compare
# IMPORTANT: the numbers in this file are macOS/ARM64. Comparing
# another platform's run against them (e.g. Linux/x86) shows 200-400%
# variance from hardware alone — that's noise, not regression signal.
cargo bench -p paksmith-bench -- --baseline phase-2a-done

# Save a new named baseline (e.g. after Phase 2b lands)
cargo bench -p paksmith-bench -- --save-baseline phase-2b-done
```

The `estimates.json` from each bench's `phase-2a-done` baseline is
committed under `crates/paksmith-bench/baselines/phase-2a-done-arm64/`,
and later baselines sit beside it, so the numbers are reproducible
from a fresh checkout without re-running the suite. They hold
criterion's summary estimates, not the raw samples (`sample.json`) a
`--baseline` compare loads, so a compare needs a run saved locally
with `--save-baseline`.

**Cache invalidation**: bench fixtures are cached to
`target/bench-fixtures/` (gitignored). The cache keys solely on the
fixture filename, so changes to `synthesize_uasset` are not detected
automatically — to force regeneration, delete the cache directory:

```bash
rm -rf target/bench-fixtures/
```

## phase-2a-done (macOS / ARM64)

### Machine

| Field    | Value                              |
| -------- | ---------------------------------- |
| CPU      | Apple M2 Pro                       |
| OS       | macOS 26.1 (Darwin 25.1)           |
| Rust     | 1.95.0 (stable, 2026-04-14)        |
| Profile  | `bench` (cargo default)            |
| Captured | 2026-05-17                         |

A second baseline on Linux/x86 (the audit's recommended companion
target) is **not** included here — the implementer's only host is
the M2 Pro. Capturing Linux/x86 numbers cleanly requires a quiet
box of the same caliber and is filed as a follow-up rather than
faked from the macOS run.

### Pak container

| Bench                                | Input       | Median ns/iter | Throughput     |
| ------------------------------------ | ----------- | -------------- | -------------- |
| `pak_open_tiny`                      | 818 B       |         15,676 |  49.7 MiB/s    |
| `pak_open_large`                     | ~100 MiB    |        224,973 | 463 GiB/s †    |
| `pak_read_entry_uncompressed_small`  | 10 KiB      |            612 |  15.50 GiB/s   |
| `pak_read_entry_zlib_small`          | 10 KiB out  |          8,701 |   1.02 GiB/s   |
| `pak_read_entry_zlib_large`          | 100 MiB out |     34,448,411 |   2.77 GiB/s   |
| `pak_verify_full`                    | ~10 MiB     |      5,993,009 |   1.50 GiB/s   |

† Open-path throughput keyed on input file size is misleading by
construction — `PakReader::open` reads the footer (~200 B) + the
index region (~30 KB at 1000 entries × 30 B/entry), not the full
file. The reported "GiB/s" is "input-bytes-divided-by-time" but
the actual byte-count touched is a small fraction of input size.
Treat the absolute throughput as a regression-detector ratio
against future runs, not as a real I/O throughput estimate.

The open benches use `PakReader::open(&path)` (the filesystem
entry point) — earlier drafts used `from_bytes(bytes.clone())`
which pulled the input clone into the timed region, drowning the
real wire-format work in memcpy bandwidth. The current numbers
reflect footer + index parse + per-entry bounds-check work only.

`pak_open_large` is currently sized at 1000 entries / 100 MiB
(scaled down from issue #245's "1GB / 10k entries" wish-list value —
a 1GB fixture would have made the first-run cache generation cost
prohibitive). Bump entry count or payload size as future
investigations require — the bench's lazy-cache pattern under
`target/bench-fixtures/` handles regeneration.

### Asset parser

| Bench                          | Input        | Median ns/iter | Throughput   |
| ------------------------------ | ------------ | -------------- | ------------ |
| `package_read_from_tiny`       | ~447 B       |            513 |  830 MiB/s   |
| `package_read_from_small`      | ~10 KiB      |          3,807 |  2.50 GiB/s  |
| `package_read_from_medium`     | ~1 MiB       |         60,017 | 16.7 GiB/s   |
| `package_read_from_pak_tiny`   | full pipeline|         17,905 |     —        |

`package_read_from_pak_tiny` has no throughput line because the
input is the pak fixture *path*, not a byte buffer: the bench
measures `open + locate entry + decompress + parse` as a single
op. Useful for "what's the end-to-end inspect command cost" but
not directly comparable to a byte-rate.

The medium-tier throughput looks high (16.7 GiB/s) because the
input is small enough to live in L1/L2 cache across iterations
and the parser is largely a header walk + zero-copy reads — not a
byte-by-byte transform. Treat it as a regression signal, not a
real-disk throughput estimate.

### Name resolution + JSON emission

| Bench                            | Input          | Median ns/iter | Throughput     |
| -------------------------------- | -------------- | -------------- | -------------- |
| `name_table_resolve_hot`         | 1000 ops       |         46,771 | 19.7 Melem/s   |
| `inspect_json_compact`           | medium pkg     |         41,317 |  1.47 GiB/s    |
| `inspect_json_pretty`            | medium pkg     |         40,546 |  1.50 GiB/s    |

The pretty-vs-compact difference is **within sample noise** at this
input size — the medium fixture's structure (small JSON nesting,
limited string content) doesn't exercise the indentation cost
heavily. A larger fixture would likely separate the two. This is the
kind of "surprising result up front, investigate later" datapoint
the baseline exists to surface.

`name_table_resolve_hot` is the load-bearing bench for Phase 2b:
each typed property iteration will call `resolve` to materialize
the property's name string for display. The current cost — ~47 ns
per lookup — sets the budget for what Phase 2b can spend on this
path before parsing perceptibly slows.

## Empty zlib blocks (macOS / ARM64)

Issue #846's empty-block benches, saved as the `empty-zlib-blocks`
baseline (`crates/paksmith-bench/baselines/empty-zlib-blocks-arm64/`).
To compare a later run against a local `empty-zlib-blocks` run (the
filter skips the other benches' timing, not their fixture setup):

```bash
cargo bench -p paksmith-bench --bench bulk --bench pak -- zlib_empty_ --baseline empty-zlib-blocks
```

### Machine

| Field    | Value                              |
| -------- | ---------------------------------- |
| CPU      | Apple M2 Pro                       |
| OS       | macOS 26.1 (Darwin 25.1)           |
| Rust     | 1.100.0 (stable, 2026-11-09)       |
| Profile  | `bench` (cargo default)            |
| Captured | 2026-11-12                         |

### Empty-block padding

| Bench                                       | Input          | Median ns/iter | Throughput   |
| ------------------------------------------- | -------------- | -------------- | ------------ |
| `bulk_decompress_zlib_empty_fixed_blocks`   | 104,000 blocks |    180,926,906 | 575 Kelem/s  |
| `bulk_decompress_zlib_empty_dynamic_blocks` | 104,000 blocks |    154,980,229 | 671 Kelem/s  |
| `pak_read_entry_zlib_empty_blocks/fixed`    | 104,000 blocks |    177,357,812 | 586 Kelem/s  |
| `pak_read_entry_zlib_empty_blocks/dynamic`  | 104,000 blocks |    154,553,344 | 673 Kelem/s  |

Each iteration decodes one zlib stream of 104,000 empty non-final
blocks (`PADDED_BLOCKS`) and a final stored block holding one byte,
as a bulk-data chunk or as a pak compression block. The fixed-block
stream is 130,012 bytes and the dynamic one 1,170,012. On both paths
an empty fixed-Huffman block (10 bits) costs about 1.7 µs and an
empty dynamic-Huffman block (90 bits) about 1.5 µs: `miniz_oxide`
0.9.1, flate2's default backend, builds the fixed tables again for
every fixed block and builds each dynamic block's tables from its
header. That is about 1.4 µs per input byte for fixed blocks and
0.13 µs for dynamic ones, so a 512 MiB bulk record of padding
(`MAX_BULK_DATA_COMPRESSED_SIZE`) takes about 12 min (fixed) or 71 s
(dynamic), extrapolated, not measured. A bulk record's bytes are
themselves a pak entry's decoded output, and padding compresses well
under the pak's zlib (about 675:1 for empty fixed blocks), so far
fewer archive bytes can stand behind a 512 MiB record. A pak block's
stream costs the same per input byte, and only the archive's size
bounds the block of an unencrypted entry stored in the inline form
(v5-v9, and v10+ non-encoded; see
[`pak-block-framing.md`](formats/compression/pak-block-framing.md)).

The dynamic benches use `FOUR_EMPTY_DYNAMIC_BLOCKS`'s one-code form
(see its doc comment); the form in
[`zlib.md`](formats/compression/zlib.md#deflate-blocks) whose
literal/length code is complete was not timed.

## CI policy

`paksmith-bench` is **not** run per-PR. Criterion needs quiet
boxes; GHA shared runners introduce ±15-30 % variance that would
make the gate noisy and the false-positive rate intolerable.

A `workflow_dispatch`-only workflow lives at
`.github/workflows/bench.yml` so a maintainer can trigger a manual
run from the Actions tab — useful for sanity-checking a PR that
explicitly targets the hot path. CI output is the raw criterion
log; baselines are not auto-committed from CI.

## Future work

- **Linux/x86 baseline**: capture on a quiet Linux x86 box, commit
  alongside the ARM64 baselines. The audit's recommended companion.
- **Empty zlib blocks**: issue #846 keeps flate2's default
  `miniz_oxide` backend instead of the `zlib-rs` swap planned in
  issue #245 Commit F: on the M2 Pro on 2026-11-11 a scratch harness
  measured `zlib-rs` 0.6.7 6-10% slower than `miniz_oxide` 0.9.1 on a
  normal 8 MiB decode of the same input, and it adds `unsafe` code to
  an untrusted-input decoder. A
  fixed-table change is proposed in
  [a comment on Frommi/miniz_oxide#198](https://github.com/Frommi/miniz_oxide/issues/198#issuecomment-6832564883);
  a local prototype of it cut empty fixed blocks to about 10-20 ns
  each and left dynamic blocks unchanged. This repo's Dependabot
  config doesn't update indirect dependencies, so adopt a 0.9 release
  by hand with `cargo update -p miniz_oxide@0.9 --precise <version>`,
  again with `--manifest-path fuzz/Cargo.toml`, then rerun the
  empty-block benches above.
- **`pak_open_large` re-scaling**: bump back to 10k entries / 1GB
  if the 1000-entry shape doesn't reveal interesting open-time
  scaling. The bench harness handles it via the existing
  `lazy_fixture` pattern.
- **Bench HTML report archival**: criterion emits HTML graphs under
  `target/criterion/<bench>/report/index.html`. Not currently
  committed — exposing them via GitHub Pages or a per-release
  artifact upload is a future ergonomics improvement.
