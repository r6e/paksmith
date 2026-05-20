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

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `LegacyFileVersion ∈ {-9, -8, -7}` (UE4.21+ through UE5.4+) | "Optimized" layout: `FGuid + i32` rows only. | `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Serialization/FCustomVersion.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |
| Older `LegacyFileVersion` (more negative than -9, or positive) | "Guids" or "Enum" layout: each row carries an additional FString name. | Same source[^1] |

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

## Variants

Not supported by paksmith — see the Versions table.

## Caps & limits

- **`count < 0` rejected.** Surfaces as
  `AssetParseFault::NegativeValue { field: AssetWireField::CustomVersionCount, value }`.
- **`count > MAX_CUSTOM_VERSIONS` rejected.**
  `MAX_CUSTOM_VERSIONS = 1024` (see
  `crates/paksmith-core/src/asset/custom_version.rs:29`). Surfaces as
  `AssetParseFault::BoundsExceeded { field: CustomVersionCount, value, limit, unit: Items }`.
  Sized to cover any realistic plugin count while preventing
  attacker-controlled multi-GB allocations.
- **Allocation failure handled.** `try_reserve_asset` is used for the row
  `Vec`; failures surface as
  `AssetParseFault::AllocationFailed { context: CustomVersionContainer, … }`
  rather than aborting the process.

See `docs/security/allocation-caps.md` for the broader allocation-cap policy.

## Verification

- **Fixture:** `(none yet — see issue #339)` — `tests/fixtures/minimal_uasset_v5.uasset`
  contains a custom-version container at the offset specified by the
  summary header, but a precise pinned offset and embedded hex anchor are
  deferred to the primitive-focused fixture work tracked there.
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
