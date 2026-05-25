# FCustomVersion (`FCustomVersion`)

> Per-plugin version stamp serialized into the package summary as a counted
> array of `(FGuid, i32 version)` rows.

## Overview

UE's core engine version is one number; individual plugins each have their own
version counter so a plugin can detect "this archive was saved before I added
field X" without re-versioning the entire engine. The package summary carries
an `FCustomVersion` container that maps plugin GUID to plugin-local version.

The container is a length-prefixed array. Each row is the plugin's
`FGuid`[^3] (16 bytes) followed by an `i32` version number (4 bytes). Total
record size: 20 bytes.

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with a worked example below covering a 2-row container.

**Paksmith parser status: complete.** Module
`crates/paksmith-core/src/asset/custom_version.rs`.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ∈ {-9, -8, -7}` (UE4.21+ through UE5.4+) | "Optimized" layout: `FGuid + i32` rows only. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Serialization/FCustomVersion.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |
| Older `LegacyFileVersion` (less negative than -7, i.e., -6, -5, … or positive) | "Guids" or "Enum" layout: each row carries an additional `FString`[^4] name. | Same source[^1] |

UE's convention: the legacy-file-version constant becomes more negative with
each engine major release. Paksmith accepts only the post-UE4.13
("Optimized") layout, gated by the `LegacyFileVersion ∈ {-9, -8, -7}` window
in the package summary parser. Older archives are rejected upstream and
never reach the custom-version reader.

## Wire layout

### Container

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 4 | LE | `count` | `i32` | Number of `FCustomVersion` rows that follow. |
| 4 | `count × 20` | — | `rows` | `FCustomVersion[count]` | Per-row layout below. |

### Single row (`FCustomVersion`)

| offset (within row) | size | endian | name | type | semantics |
|---------------------|------|--------|------|------|-----------|
| 0 | 16 | LE u32×4 | `guid` | `FGuid`[^3] | Plugin identifier. |
| 16 | 4 | LE | `version` | `i32` | Plugin-local version counter. |

Row size: 20 bytes. Container size: `4 + (count × 20)` bytes.

### Worked example

A synthetic 2-row container with placeholder plugin GUIDs (real cookers
emit Epic's well-known engine GUIDs like
`B3B7E3F0-C6F4-4B41-8F4D-D5A0F94B86C9`):

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -------------------------------
+0      02 00 00 00                                         count = 2 (i32)

# Row 0: plugin GUID + version
+4      A1 A2 A3 A4 B1 B2 B3 B4 C1 C2 C3 C4 D1 D2 D3 D4    guid = FGuid{0xA4A3A2A1, 0xB4B3B2B1, 0xC4C3C2C1, 0xD4D3D2D1}
+20     0F 00 00 00                                         version = 15 (i32)

# Row 1: plugin GUID + version
+24     E1 E2 E3 E4 F1 F2 F3 F4 11 12 13 14 21 22 23 24    guid = FGuid{0xE4E3E2E1, 0xF4F3F2F1, 0x14131211, 0x24232221}
+40     2A 00 00 00                                         version = 42 (i32)
+44                                                          (end of container — 44 bytes)
```

Container size: `4 + 2 × 20 = 44` bytes.

## Variants

Not supported by paksmith — see the Versions table.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`count` field range:** `i32`, signed. Wire-imposed maximum
  `i32::MAX = 2_147_483_647` rows. Signedness is the relevant wire fact
  (the writer never emits negative values, but the wire format permits
  them as bytes — that's an implementation-hardening concern below).
- **Per-row size:** fixed 20 bytes (`FGuid` 16 + `version: i32` 4).
- **Container size formula:** `4 + (count × 20)` bytes.

### Implementation hardening (recommended for any parser)

- **`count < 0` MUST be rejected.** Negative i32 cast to usize for
  allocation produces near-`usize::MAX` values; immediate OOM. Paksmith
  surfaces this as
  `AssetParseFault::NegativeValue { field: AssetWireField::CustomVersionCount, value }`.
- **Upper bound on `count` SHOULD be enforced.** A conservative cap
  prevents attacker-controlled multi-GB allocations. Paksmith uses
  `MAX_CUSTOM_VERSIONS = 1024` (see
  `crates/paksmith-core/src/asset/custom_version.rs:29`). Real archives
  carry at most a few dozen plugin versions. Surfaces as
  `AssetParseFault::BoundsExceeded { field: CustomVersionCount, value, limit, unit: Items }`.
- **Allocation failure handling.** Use a fallible reservation
  (`try_reserve` equivalent); failures surface as
  `AssetParseFault::AllocationFailed { context: CustomVersionContainer, … }`
  rather than aborting the process.
- **Zero-GUID rows are wire-valid but semantically meaningless.** A row
  keyed on the all-zero `FGuid` doesn't identify any real plugin; the
  primitive itself accepts the value, but consumers SHOULD treat
  zero-GUID rows as informational (likely cooker error) rather than
  rejecting the file or applying a version conditional based on the
  zero key.

See `docs/security/allocation-caps.md` for the broader allocation-cap policy.

## Verification

- **Fixture:** the Worked example above is synthetic with placeholder
  GUIDs. The `tests/fixtures/minimal_uasset_v5.uasset` and sibling
  fixtures contain real custom-version containers at offsets specified
  by their package summary headers; isolating one requires walking the
  summary to find the offset.
- **Hex anchor commands:**
  ```
  # Synthesize the 44-byte Worked example container:
  printf '\x02\x00\x00\x00\xA1\xA2\xA3\xA4\xB1\xB2\xB3\xB4\xC1\xC2\xC3\xC4\xD1\xD2\xD3\xD4\x0F\x00\x00\x00\xE1\xE2\xE3\xE4\xF1\xF2\xF3\xF4\x11\x12\x13\x14\x21\x22\x23\x24\x2A\x00\x00\x00' | xxd
  ```
  Any conformant parser fed these 44 bytes MUST produce a 2-row
  container with the GUIDs and versions shown in the Worked example.
- **Cross-validation oracle:** CUE4Parse's `FCustomVersion` row serializer
  and the surrounding container dispatch[^1], and `unreal_asset`'s
  `CustomVersion::read`[^2]. Both impls confirm the 4-byte count prefix and
  the 20-byte row layout for the "Optimized" variant.
- **Known divergences:** none on the implemented ("Optimized") wire shape.
  The pre-Optimized layouts CUE4Parse supports are a coverage gap (see
  Variants and Versions table), not a wire divergence.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/custom_version.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct CustomVersion { pub guid: FGuid, pub version: i32 }`.
- `CustomVersion::read_from<R: Read>(&mut R) -> Result<CustomVersion>` — 20-byte row.
- `pub struct CustomVersionContainer { pub versions: Vec<CustomVersion> }` with `#[serde(transparent)]`.
- `CustomVersionContainer::read_from<R: Read>(&mut R, asset_path) -> Result<CustomVersionContainer>` — container with cap enforcement.

**Error variants:**
- `AssetParseFault::NegativeValue { field: CustomVersionCount, value }`.
- `AssetParseFault::BoundsExceeded { field: CustomVersionCount, value, limit, unit }`.
- `AssetParseFault::AllocationFailed { context: CustomVersionContainer, … }`.

**Cap constants:**
- `MAX_CUSTOM_VERSIONS: u32 = 1024` (`custom_version.rs:29`).

**Test files:** `crates/paksmith-core/src/asset/custom_version.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 7).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Serialization/FCustomVersion.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FCustomVersion` row class (the container-level dispatch across the four historical serialization formats lives in adjacent CUE4Parse files in the same tree).
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/custom_version.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust `CustomVersion::read` paksmith cross-validates against.
[^3]: See [`fguid.md`](fguid.md) for FGuid wire details.
[^4]: See [`fstring.md`](fstring.md) for FString wire details.
