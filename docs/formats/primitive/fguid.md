# FGuid (`FGuid`)

> UE's 128-bit identifier — 16 fixed bytes interpreted as four little-endian u32s.

## Overview

`FGuid` is UE's standard globally-unique-identifier type, used throughout the
engine wherever a stable 128-bit ID is needed: package identifiers in the
package summary, plugin identifiers in custom-version records[^1], asset GUIDs
in cooked metadata, and editor-only object identifiers.

The wire shape is the simplest of all UE primitives — sixteen raw bytes, no
length prefix, no version conditional, no encoding selection. The
interpretation is the interesting part: those bytes are four
little-endian `u32` fields conventionally named `A`, `B`, `C`, `D`, and the
canonical display form reshapes them into the standard 8-4-4-4-12 hex layout.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | No change since UE3. | `CUE4Parse/Objects/Core/Misc/FGuid.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

`FGuid` has had a stable on-disk shape since UE3. Newer engine versions added
ergonomic constructors (`NewGuid()`, `Parse()`) and a `EGuidFormats` enum for
the display side, but the serialized 16 bytes have never changed.

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `A` | `u32` | First u32 field. |
| 4 | 4 | LE | `B` | `u32` | Second u32 field. |
| 8 | 4 | LE | `C` | `u32` | Third u32 field. |
| 12 | 4 | LE | `D` | `u32` | Fourth u32 field. |

Total: 16 bytes, fixed.

### Display form

UE's `FGuid::ToString(EGuidFormats::DigitsWithHyphens)` reshapes the four
u32s into the canonical 8-4-4-4-12 hex layout[^1]:

```
{A:08x}-{B>>16:04x}-{B&0xFFFF:04x}-{C>>16:04x}-{C&0xFFFF:04x}{D:08x}
```

Note the asymmetry: `A` and `D` render as single 8-hex-digit groups, while `B`
and `C` each split into two 4-hex-digit halves. This matches the RFC-4122
visual convention but is **not** an endianness conversion — the bytes are still
read little-endian. The display form is a rearrangement of nibbles, not a
swap.

### Worked example

Input bytes (hex): `DE AD BE EF 00 01 02 03 04 05 06 07 08 09 0A 0B`

Decoded:
- `A = 0xEFBEADDE` (LE of `DE AD BE EF`)
- `B = 0x03020100`
- `C = 0x07060504`
- `D = 0x0B0A0908`

Display: `efbeadde-0302-0100-0706-05040b0a0908`

This is exercised by the `display_renders_canonical_ue_form` test in
`crates/paksmith-core/src/asset/guid.rs`.

## Variants

None on the wire. UE has multiple `EGuidFormats` for display (with-hyphens,
without-hyphens, parentheses, braces, base64, etc.) but all read the same 16
bytes.

The zero GUID (`00000000-0000-0000-0000-000000000000`) is meaningful as a
sentinel in some contexts — for example, an `FCustomVersion` row keyed on the
zero GUID is invalid. Each consumer documents its own zero-GUID semantics;
the primitive itself treats zero as a valid value.

## Caps & limits

None beyond IO. The size is fixed; there is no length field to validate. The
parser's only failure mode is short read (`PaksmithError::Io`) when the
underlying source has fewer than 16 bytes remaining.

## Verification

- **Fixture:** `(none yet)` — `tests/fixtures/minimal_uasset_v5.uasset` contains
  several FGuid instances (package GUID at the start of the summary, custom-
  version GUIDs in the custom-version container), but no fixture is currently
  named or positioned to make FGuid the focal anchor.
- **Cross-validation oracle:** CUE4Parse's `FGuid.Read`[^1] and
  `unreal_asset`'s `read_guid`[^2]. Both impls confirm the 16-byte fixed
  shape and the four-u32 interpretation for display purposes.
- **Known divergences:** none. Every oracle paksmith has consulted agrees on
  FGuid's wire shape and display form.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/guid.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct FGuid` — 16-byte storage; `Copy`.
- `FGuid::read_from<R: Read>(&mut R) -> Result<FGuid>` — 16 raw bytes.
- `FGuid::from_bytes([u8; 16]) -> FGuid` — type-checked constructor.
- `FGuid::as_bytes() -> &[u8; 16]` — borrow for round-trip writes.
- `impl Display` — canonical 8-4-4-4-12 form.
- `impl Serialize` — JSON string matching `Display`.

**Error variants:** none specific to FGuid. Short reads bubble up as
`PaksmithError::Io`.

**Cap constants:** none.

**Test files:** `crates/paksmith-core/src/asset/guid.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 4).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Misc/FGuid.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FGuid` implementation including the 16-byte serializer and the `EGuidFormats::DigitsWithHyphens` renderer.
[^2]: `AstroTechies/unrealmodding/unreal_helpers/src/read_ext.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `read_guid` implementation reading 16 raw bytes into a `Guid([u8; 16])`; paksmith's fixture-gen cross-checks against this crate.
