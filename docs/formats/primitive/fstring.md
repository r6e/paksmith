# FString (`FString`)

> UE's variable-length string primitive: signed-i32 length prefix, sign-tagged
> encoding (UTF-8 vs UTF-16 LE), NUL-terminated.

## Overview

`FString` is UE's wire-format string type. It appears everywhere — pak index
filenames, asset name-table entries, custom-version data, soft-object paths,
property tag values. The wire shape is uniform; what varies is which caller
is reading it and how strict that caller is about edge cases.

A positive length prefix selects UTF-8 bytes; a negative prefix selects
UTF-16 LE code units; both counts include the trailing NUL.

Two paksmith readers exist for this primitive:

- `container::pak::index::read_fstring` — strict reader used inside the pak
  index. Rejects `len == 0` because the pak FDI record-size invariant
  depends on the 5-byte minimum FString size.
- `asset::read_asset_fstring` — wrapper around the pak reader that accepts
  `len == 0` as the empty string, matching CUE4Parse's
  `FArchive.ReadFString` semantics for inside-asset reads. All other error
  cases are remapped from `IndexParseFault` to `AssetParseFault` for
  consistent operator categorization.

The strict-vs-lenient split is intentional — see Variants below.

**Document status: complete.** Wire format documented in full for
the `i32` length prefix (positive = UTF-8 bytes, negative = UTF-16 LE
code units; both counts include the trailing NUL), the 7-step decode
procedure (sign / `i32::MIN` / `FSTRING_MAX_LEN` / NUL-terminator /
embedded-NUL defense-in-depth / `String::from_utf8` /
`String::from_utf16`), and the two paksmith reader variants
(`pak-side strict — len == 0 rejected` vs
`asset-side lenient — len == 0 accepted as ""`).

**Paksmith parser status: `complete`.** Phase 1 + Phase 2a deliverable;
the strict pak-side reader ships at
`paksmith-core/src/container/pak/index/fstring.rs` and the asset-side
wrapper ships at `paksmith-core/src/asset/fstring.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Wire shape stable since UE3. | `CUE4Parse/UE4/Readers/FArchive.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `length` | `i32` | Sign-tagged length prefix. See Decode procedure below. |
| 4 | variable | LE | `body` | UTF-8 bytes or UTF-16 code units | Encoding selected by sign of `length`; size selected by absolute value. Includes trailing NUL. |

### Decode procedure

1. Read 4-byte signed `length` (LE).
2. If `length == 0`: handle per-context (see Variants below).
3. If `length == i32::MIN`: reject as malformed (no positive counterpart for
   absolute value).
4. Compute `abs_len = length.abs()`.
5. If `abs_len > FSTRING_MAX_LEN` (65,536): reject as malformed.
6. If `length > 0`:
   - Read `abs_len` bytes as UTF-8.
   - The last byte must be `0x00`. If not, reject as malformed.
   - Strip the trailing NUL.
   - Defense in depth: reject if any non-trailing byte is `0x00`
     (embedded NUL).
   - Convert to `String` via `String::from_utf8`. UTF-8 validation failures
     surface as malformed.
7. If `length < 0`:
   - Read `abs_len` LE `u16` code units.
   - The last code unit must be `0x0000`. If not, reject as malformed.
   - Strip the trailing NUL code unit.
   - Defense in depth: reject if any non-trailing code unit is `0x0000`
     (embedded NUL).
   - Convert to `String` via `String::from_utf16`. UTF-16 validation failures
     surface as malformed.

## Variants

### Pak-index reader (strict)

`container::pak::index::read_fstring`. Used for all pak-index FString fields
(entry filenames, mount points, FDI directory/file names).

- `len == 0` → reject as `IndexParseFault::FStringMalformed { kind: LengthIsZero }`.
- All other rules as above.

Rationale: paksmith's FDI bounds-check arithmetic
(`MIN_FDI_*_RECORD_BYTES = 9`) assumes the 5-byte minimum FString
(`length(4) + NUL(1)`). Allowing `len == 0` would shrink the per-record
minimum to 4 bytes and let an attacker pack ~12.5% more records into a
given FDI region than the cap predicts. See issue #104 and
`container/pak/index/fstring.rs:54-70`.

### Asset-side wrapper (lenient on `len == 0`)

`asset::read_asset_fstring`. Used for all asset-side FString fields (name
table entries, custom-version branch names, soft-object paths, property tag
values).

- `len == 0` → accept as `""` (empty string).
- All other malformations remapped from `IndexParseFault::FStringMalformed`
  to `AssetParseFault::FStringMalformed` for consistent operator-facing
  error categorization.

Rationale: CUE4Parse's `FArchive.ReadFString` returns `""` on `len == 0`
without throwing[^1]. Paksmith matches that semantics inside assets (no
FDI invariant to protect) but keeps the strict pak-side reader for archive
structural integrity.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`length`**: `i32` LE; sign-tagged (positive = UTF-8 byte count incl. NUL; negative = UTF-16 LE code-unit count incl. NUL). `i32::MIN` has no positive counterpart and is malformed.
- **`body`**: variable size; total bytes = `abs(length)` (UTF-8) or `abs(length) × 2` (UTF-16 LE).
- **NUL terminator**: trailing element MUST be `0x00` (UTF-8) or `0x0000` (UTF-16); included in the length count.

### Implementation hardening (recommended for any parser)

- **Length cap.** `FSTRING_MAX_LEN = 65_536` bytes (UTF-8) or code units
  (UTF-16) — `container/pak/index/fstring.rs:26`. Sized to comfortably
  exceed any realistic UE virtual path while rejecting attacker-controlled
  multi-GB allocations. Surfaces as
  `FStringFault::LengthExceedsMaximum { length, maximum }`.
- **`len == 0`** — see Variants for the per-reader handling.
- **`len == i32::MIN`** — reject (no positive counterpart). Surfaces as
  `FStringFault::LengthIsI32Min`.
- **Embedded NUL bytes/code units** — reject with position index. Surfaces
  as `FStringFault::EmbeddedNul { encoding, at }`. Defensive measure: UE
  writers never emit embedded NULs, and allowing them through would let an
  attacker craft a path like `"asset.uasset\0../../etc/passwd"` that gets
  truncated at the NUL by POSIX `open(2)` but preserved on NTFS — a
  cross-platform path-truncation vector. Currently inert in paksmith
  (FName-as-HashMap-key carries the NUL through transparently), but the
  parser is the right chokepoint to gate at before Phase 4+ extraction
  lands.
- **Missing trailing NUL** — reject. Surfaces as
  `FStringFault::MissingNullTerminator { encoding }`.
- **Allocation cap.** Allocations use `try_reserve_exact` and surface as
  `IndexParseFault::AllocationFailed { context: FStringUtf8Bytes |
  FStringUtf16CodeUnits, requested, source, path }` if reservation fails.
  At the `FSTRING_MAX_LEN` cap, the maximum allocation is 128 KiB for
  UTF-16 — well within infallible territory on a healthy machine.

See `docs/security/allocation-caps.md` for the broader allocation-cap
policy.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5.uasset` carries multiple
  asset-side FStrings. The `folder_name` field of the package summary at
  offset `0x1C` is the cleanest single-FString anchor — a 5-byte UTF-8
  payload with the length-prefix `05 00 00 00`, bytes `4E 6F 6E 65 00`
  (string `"None"` + trailing NUL). Verify with:
  ```bash
  xxd -s 0x1C -l 9 tests/fixtures/minimal_uasset_v5.uasset
  ```
  Expected output:
  ```
  0000001c: 0500 0000 4e6f 6e65 00                   ....None.
  ```
  The command above will be promoted to a formal `### Worked example`
  block in Wire layout once the hex-anchor CI check lands per the
  framework spec.
- **Cross-validation oracle:** CUE4Parse's `FArchive.ReadFString`[^1] and
  `unreal_helpers`'s `UnrealReadExt::read_fstring`[^2]. Both confirm the
  sign-tagged length, the UTF-8/UTF-16 selection, and the trailing-NUL
  discipline.
- **Known divergences:**
  - **`len == 0` handling.** CUE4Parse accepts `len == 0` as `""`
    universally. Paksmith splits: pak-side strict rejection (for FDI
    invariants), asset-side lenient acceptance (matches CUE4Parse). Both
    behaviors are intentional. See
    `crates/paksmith-core/src/asset/fstring.rs:1-13`.
  - **Embedded NUL rejection.** Paksmith rejects embedded NULs as a
    defense-in-depth path-traversal guard. CUE4Parse does not. The
    practical impact is nil because UE writers never emit embedded NULs.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/container/pak/index/fstring.rs` — strict pak-index
  reader (`read_fstring`).
- `crates/paksmith-core/src/asset/fstring.rs` — asset-side wrapper
  (`read_asset_fstring`, `write_asset_fstring`).

**Status:** `complete`.

**Public surface:**
- `pub(crate) fn read_fstring<R: Read>(reader: &mut R) -> Result<String>`
  (re-exported as `crate::container::pak::index::read_fstring`).
- `pub(crate) fn read_asset_fstring<R: Read>(reader: &mut R, asset_path: &str) -> Result<String>`.
- `pub(crate) fn write_asset_fstring<W: Write>(writer: &mut W, s: &str) -> io::Result<()>` (gated behind `__test_utils`).

Both readers are `pub(crate)` — no external API surface for FString reading.
Consumers go through the structured `NameTable`, `CustomVersion`,
`PackageSummary`, etc. types that own the per-record context.

**Error variants:**
- `IndexParseFault::FStringMalformed { kind: FStringFault::* }` (pak-side).
- `AssetParseFault::FStringMalformed { kind: FStringFault::* }` (asset-side, remapped).
- `FStringFault::{LengthIsZero, LengthIsI32Min, LengthExceedsMaximum, MissingNullTerminator, EmbeddedNul, InvalidEncoding}`.
- `IndexParseFault::AllocationFailed { context: FStringUtf8Bytes |
  FStringUtf16CodeUnits, … }`.

**Cap constants:**
- `FSTRING_MAX_LEN: i32 = 65_536` (`container/pak/index/fstring.rs:26`).

**Test files:**
- `crates/paksmith-core/src/container/pak/index/fstring.rs` `mod tests` (if
  present) plus the FString-focused tests in
  `crates/paksmith-core/src/container/pak/index/mod.rs:990-1238`.
- `crates/paksmith-core/src/asset/fstring.rs` `mod tests` (`len_zero_decodes_as_empty_string`, `non_zero_malformation_still_errors`, `embedded_nul_forwards_through_wrapper`).

**Phase plan:**
- Pak-side strict reader: covered by Phase 1 hardening (issue #104).
- Asset-side wrapper: `docs/plans/phase-2a-uasset-header.md` (Task 1).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Readers/FArchive.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FArchive.ReadFString` including the `len == 0` carve-out and the sign-tagged encoding selection.
[^2]: `AstroTechies/unrealmodding/unreal_helpers/src/read_ext.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `UnrealReadExt::read_fstring` trait method paksmith cross-validates against.
