# FEngineVersion (`FEngineVersion`)

> UE's engine-version stamp: major.minor.patch + changelist + branch name.

## Overview

`FEngineVersion` captures the engine build that produced an archive: a
three-part semantic version (`major.minor.patch`), a Perforce-style integer
changelist with a top-bit flag for licensee builds, and an FString[^3] branch
name (e.g. `"++UE4+Release-4.27"`, `"++UE5+Release-5.1"`).

It appears in the package summary's compatibility section and in pak entry
metadata for newer pak versions. The wire shape has been stable since UE4 but
the licensee-bit packing in the changelist field is easy to overlook.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| All UE4 + UE5 | Wire shape stable. | `CUE4Parse/UE4/Objects/Core/Misc/FEngineVersion.cs@380d005380d166a3fc19a8bb6940a61af8261e8a`[^1] |

## Wire layout

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 2 | LE | `major` | `u16` | Major version (e.g. `5`). |
| 2 | 2 | LE | `minor` | `u16` | Minor version (e.g. `1`). |
| 4 | 2 | LE | `patch` | `u16` | Patch version (e.g. `1`). |
| 6 | 4 | LE | `changelist` | `u32` | Packed: bit 31 = licensee flag, bits 0-30 = changelist number. See below. |
| 10 | variable | — | `branch` | `FString`[^3] | Branch name (e.g. `"++UE5+Release-5.1"`). |

Fixed-prefix size: 10 bytes. Total size: `10 + sizeof(branch)`.

### Changelist licensee-bit packing

UE packs two values into the single `u32` `changelist` field:

| Bit range | Mask | Meaning |
|-----------|------|---------|
| 0-30 | `0x7FFF_FFFF` | Perforce-style changelist number, capped at ~2.1 billion. |
| 31 | `0x8000_0000` | Licensee flag: set by studios maintaining private UE forks to indicate that the changelist number is from their internal Perforce stream, not Epic's. |

Paksmith preserves the raw u32 verbatim in `EngineVersion::changelist` for
identity round-trip; user-facing surfaces (`Display`, JSON) mask the high bit
off via `EngineVersion::masked_changelist()`. The licensee flag is exposed
separately via `EngineVersion::is_licensee_version()`.

A pinned-offset `### Worked example` block belongs in a follow-up — see
issue #339.

## Variants

- **Empty branch.** Theoretical only — UE writers never emit one. See
  Known divergences in Verification.

(Licensee vs Epic builds share one wire shape; the bit-31 flag is the only
runtime distinction, documented above in *Changelist licensee-bit packing*.)

## Caps & limits

- **No primitive-level caps** beyond those imposed by the embedded `FString`
  branch — see [`fstring.md`](fstring.md) for the `FSTRING_MAX_LEN = 65_536`
  cap that applies to the branch field.
- **Changelist overflow** is impossible at the wire level (the field is u32);
  the licensee-bit packing means the practical "real" changelist range is
  `0..=0x7FFF_FFFF`.

## Verification

- **Fixture:** `(none yet — see issue #339)` — `tests/fixtures/minimal_uasset_v5.uasset`
  carries an `FEngineVersion` ending in the branch FString `"++UE4+Release-4.27"`,
  but the exact byte offset is deferred to the primitive-focused fixture
  work tracked there.
- **Cross-validation oracle:** CUE4Parse's `FEngineVersion` constructor
  (reads via successive `Ar.Read<>` calls)[^1] and the `unreal_asset`
  version-constants enum[^2]. CUE4Parse confirms the
  `u16+u16+u16+u32+FString` wire layout and the licensee-bit packing in
  `FEngineVersionBase`; `unreal_asset`'s engine_version.rs is the catalog of
  UE version constants paksmith aligns its `LegacyFileVersion` floor
  against (no standalone wire reader in that crate).
- **Known divergences:**
  - **Empty-branch display.** UE's `FEngineVersion::ToString` suppresses
    `+branch` when `branch.IsEmpty()`. Paksmith always emits `+branch` so
    `Display` stays in lockstep with `Serialize` (which routes through
    `collect_str`). UE writers don't emit empty branches in practice, so
    this divergence is theoretical. See
    `crates/paksmith-core/src/asset/engine_version.rs:43-50`.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/engine_version.rs`

**Status:** `complete`.

**Public surface:**
- `pub struct EngineVersion { pub major: u16, pub minor: u16, pub patch: u16, pub changelist: u32, pub branch: String }`.
- `EngineVersion::read_from<R: Read>(&mut R, asset_path) -> Result<EngineVersion>`.
- `EngineVersion::masked_changelist() -> u32` — bits 0-30.
- `EngineVersion::is_licensee_version() -> bool` — bit 31.
- `impl Display` — `"M.m.p-CL+branch"` form (masked changelist).
- `impl Serialize` — JSON string matching `Display`.

**Error variants:**
- `PaksmithError::Io` on truncation.
- `AssetParseFault::FStringMalformed { kind }` on a malformed branch FString
  (forwarded from `read_asset_fstring`).

**Cap constants:** none specific to `EngineVersion`; the branch FString
inherits `FSTRING_MAX_LEN = 65_536` from `container/pak/index/fstring.rs:26`.

**Test files:** `crates/paksmith-core/src/asset/engine_version.rs` `mod tests`.

**Phase plan:** `docs/plans/phase-2a-uasset-header.md` (Task 5).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/Misc/FEngineVersion.cs@380d005380d166a3fc19a8bb6940a61af8261e8a` — reference C# `FEngineVersion` class (and its base `FEngineVersionBase` in the same directory) including the wire constructor and `IsLicenseeVersion`.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/engine_version.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust catalog of UE version constants. The crate does not expose a standalone `FEngineVersion::read`; the wire payload is read inline by the package summary parser.
[^3]: See [`fstring.md`](fstring.md) for FString wire details.
