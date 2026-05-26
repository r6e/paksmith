# FGuid (`FGuid`)

> UE's 128-bit identifier — 16 fixed bytes interpreted as four little-endian u32s.

## Overview

`FGuid` is UE's standard globally-unique-identifier type, used throughout the
engine wherever a stable 128-bit ID is needed: package identifiers in the
package summary, plugin identifiers in custom-version records[^1], asset GUIDs
in cooked metadata, editor-only object identifiers, and as the magic bytes
of the `.locres` localization-resource format (see
[`../data/locres.md`](../data/locres.md)).

The wire shape is the simplest of all UE primitives — sixteen raw bytes, no
length prefix, no version conditional, no encoding selection. The
interpretation is the interesting part: those bytes are four
little-endian `u32` fields conventionally named `A`, `B`, `C`, `D`, and the
canonical display form reshapes them into the standard 8-4-4-4-12 hex layout.

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with a worked example below; a committed binary fixture
exists at [`tests/fixtures/data/sample_v2.locres`](../../../tests/fixtures/data/sample_v2.locres)
(first 16 bytes are the canonical `.locres` magic FGuid).

**Paksmith parser status: `complete`.** Module
`crates/paksmith-core/src/asset/guid.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | No change since UE3. | `CUE4Parse/UE4/Objects/Core/Misc/FGuid.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

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

Note the asymmetry between the four fields. `A` renders as a standalone
8-hex-digit group; `B` and `C` each split into two 4-hex-digit halves; `D`
contributes its 8 hex digits directly onto the trailing group with no hyphen,
fusing with `C`'s low half to form the final 12-char segment of the
`8-4-4-4-12` layout. This matches the RFC-4122 visual convention but is
**not** an endianness conversion — the bytes are still read little-endian.
The display form is a rearrangement of nibbles, not a swap.

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

### Format-defined limits (wire-imposed)

None. The size is fixed at exactly 16 bytes; there is no length field,
no count, no offset. Every possible 16-byte sequence is a valid `FGuid`.

### Implementation hardening (recommended for any parser)

- **Short-read rejection.** A reader MUST verify 16 bytes are available
  before consuming the FGuid; truncation surfaces as a short-read error
  (paksmith: `PaksmithError::Io`). This is the only failure mode.
- **Zero-GUID semantics are consumer-specific.** The zero GUID
  (`00000000-0000-0000-0000-000000000000`) is structurally valid but
  some consumers treat it as a sentinel (e.g., an `FCustomVersion` row
  keyed on the zero GUID is meaningless). The primitive itself does
  NOT enforce zero-GUID rejection; each consumer documents its own
  semantics.

## Verification

- **Fixture:** [`tests/fixtures/data/sample_v2.locres`](../../../tests/fixtures/data/sample_v2.locres)
  — first 16 bytes are the canonical `.locres` magic
  `FGuid{0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3}`. This is the
  most accessible committed FGuid in the repository.
- **Hex anchor commands:**
  ```
  # Extract the magic FGuid from the locres fixture:
  xxd -l 16 tests/fixtures/data/sample_v2.locres
  # Expected output (offset 0, 16 bytes):
  #   00000000: 0e14 7475 674a 03fc 4a15 909d c337 7f1b  ..tugJ..J....7..
  ```
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
