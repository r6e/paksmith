# <Format name> (`.ext` / `FStructName`)

> One-line summary: what this is and where it appears in a UE pak.

## Overview

What this format encodes, where it sits in the bigger picture, what other docs
to read first.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ NNN` | … | `<community-project>@<sha>` |

Anchor for every conditional in later sections. Each row cites the community
implementation + commit SHA where the change was first documented.

## Wire layout

Byte-by-byte reference. One subsection per top-level record. Each field
listed as:

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|

Optionally include `### Worked example` subsections with annotated hex blocks
from a named fixture. Hex blocks follow `CONVENTIONS.md`.

## Variants

Per-version, per-platform, per-game variants. Each variant gets a named
subsection that references back to the Versions table.

## Caps & limits

What paksmith refuses to parse and why. Cross-link to
`docs/security/allocation-caps.md`. **Required even if the answer is "none"** —
the section header must be present so readers can rely on the absence of caps
being intentional.

## Verification

How a reader can verify the spec is correct against a real file:

- Fixture path in `tests/fixtures/` (or `(none yet)` with a tracking issue
  link)
- Hex anchor commands (e.g. `xxd -s 0x40 -l 32 tests/fixtures/<file>`)
- Cross-validation oracle (community impl name + version)
- Known divergences between oracle and engine-cooked output

## Paksmith implementation

Audience-switch sidebar. Names the parser module, the error variants, the
cap constants, the test files. Status: `not implemented` / `partial` /
`complete`. Links to the phase plan that owns the work.

## References

1. `<community-project>/<path>@<sha>` — one-line description of what's cited.
