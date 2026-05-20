# Conventions

Format-doc-wide conventions. Per-format quirks belong inside individual
docs, not here.

## Hex-anchor blocks

Inside `### Worked example` subsections, embed a reproducible shell command
and the expected output verbatim. A hex-anchor CI check (planned; see the
design spec) will run every command and fail the build on drift — until
that lands, authors must manually re-verify worked examples when fixtures
change.

Format:

````markdown
### Worked example: pak v8 footer

```bash
xxd -s -44 -l 44 tests/fixtures/real_v8b_split.pak
```

```
00012345: 0123 4567 89ab cdef 0123 4567 89ab cdef  ........ ........
00012355: ...
```
````

**Allowed commands** (must be deterministic, read-only, and available on
the CI runners or installed by the workflow):

- `xxd`
- `hexdump`
- `od`
- `wc`
- `sha1sum` (macOS contributors: `shasum -a 1` produces equivalent output;
  CI uses Ubuntu runners with `sha1sum` so doc anchors should pin
  `sha1sum` for byte-equal CI matches)

Adding a new inspection tool to this list is a PR in its own right — update
this section AND ensure the CI workflow has the tool available.

## Citation format

Inline footnote markers in `## Wire layout`, `## Versions`, and `## Variants`.
Resolve to entries in `## References` of the form:

```markdown
1. `<project>/<path>@<sha>` — one-line description.
```

SHAs (not branch names) so links don't rot. Required oracle priority when
multiple sources cover a claim:

1. CUE4Parse — broadest coverage; default for asset internals.
2. repak — pak-specific; default for container claims.
3. FModel — UI/struct insights.
4. UE4SS — runtime RE; cite for behavior not visible in cooked output.
5. unreal_asset — Rust API; cite when triangulating a Rust-perspective view.

## Version-marker syntax

When citing a UE version constant, use the exact name from the engine
(`FileVersionUE4 ≥ 507`, `EUnrealEngineObjectUE5Version::INITIAL_VERSION`,
etc.) and link the constant to its definition in
`crates/paksmith-core/src/asset/version.rs` if paksmith pins it.

## Attribution boundary

Per `CONTRIBUTING.md`, format docs cite community implementations
(CUE4Parse, repak, FModel, UE4SS, unreal_asset). Plain-prose engine facts
are fine; URLs to engine-source repositories are not.
