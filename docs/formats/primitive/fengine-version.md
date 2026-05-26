# FEngineVersion (`FEngineVersion`)

> UE's engine-version stamp: major.minor.patch + changelist + branch name.

## Overview

`FEngineVersion` captures the engine build that produced an archive: a
three-part semantic version (`major.minor.patch`), a Perforce-style integer
changelist with a top-bit flag for licensee builds, and an FString[^3] branch
name (e.g. `"++UE4+Release-4.27"`, `"++UE5+Release-5.1"`).

It appears in the package summary's compatibility section and in pak entry
metadata for newer pak versions. The changelist field packs a licensee-build
flag into bit 31 (see *Changelist licensee-bit packing* below).

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with worked examples below covering both the standard
and licensee-flag-set cases.

**Paksmith parser status: `complete`.** Module
`crates/paksmith-core/src/asset/engine_version.rs`.

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

### Worked example

A synthetic UE 5.1.1 release-branch stamp (changelist 12345, licensee
flag clear):

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -------------------------------
+0      05 00                                               major = 5 (u16)
+2      01 00                                               minor = 1 (u16)
+4      01 00                                               patch = 1 (u16)
+6      39 30 00 00                                         changelist = 12345 (u32; bit 31 = 0, non-licensee)
+10     12 00 00 00                                         FString length = 18 (chars + null; positive → ASCII)
+14     2B 2B 55 45 35 2B 52 65 6C 65 61 73 65 2D 35 2E 31 00    "++UE5+Release-5.1\0"
+32                                                          (end — 32 bytes total)
```

Decoded: `EngineVersion { major: 5, minor: 1, patch: 1, changelist: 12345 (masked), is_licensee: false, branch: "++UE5+Release-5.1" }`.
Display: `5.1.1-12345+++UE5+Release-5.1`.

### Worked example — licensee variant

Same version with the licensee bit set (changelist 12345 → wire value
`0x80003039`):

```
Offset  Bytes (LE)                                          Field
------  --------------------------------------------------  -------------------------------
+6      39 30 00 80                                         changelist raw = 0x80003039 (bit 31 = 1, licensee)
```

(Other fields identical.) Decoded:
`masked_changelist() = 12345`, `is_licensee_version() = true`. The raw
`changelist` field still stores `0x80003039` for round-trip identity.

## Variants

- **Empty branch.** Theoretical only — UE writers never emit one. See
  Known divergences in Verification.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`major` / `minor` / `patch`:** `u16` each. Wire-imposed range
  `0..=65_535` per field. UE's actual release range is far narrower
  (UE4: 0-27, UE5: 0-5 at time of writing).
- **`changelist`:** `u32`. Wire-imposed range `0..=u32::MAX`. The
  licensee-bit packing (bit 31) means the "real" changelist range is
  `0..=0x7FFF_FFFF`; the high bit is metadata, not part of the
  changelist value.
- **`branch`:** `FString`. Length is `i32` per [`fstring.md`](fstring.md);
  negative length signals UTF-16 encoding. No primitive-level upper
  bound on branch length — `i32::MAX` chars is the wire ceiling.

### Implementation hardening (recommended for any parser)

- **`branch` length cap SHOULD be enforced.** The embedded `FString`
  inherits the parser's FString length cap; lengths beyond the cap
  MUST be rejected at the FString reader level. Paksmith caps at
  `FSTRING_MAX_LEN = 65_536`
  (`container/pak/index/fstring.rs:26`). Real branches are typically
  20-40 characters (`"++UE5+Release-5.1"`, `"++Fortnite+Release-29.40"`).
- **Licensee-flag preservation.** A reader MUST preserve the raw
  `changelist` u32 verbatim if round-trip fidelity is required (writing
  the same bytes back). Masking off bit 31 at parse time loses the
  licensee marker for any consumer that needs to identify the source
  fork. Paksmith stores the raw value in `EngineVersion::changelist`
  and exposes the masked value via `masked_changelist()`.

(The "Empty-branch display" divergence is a paksmith-vs-UE display
behavior, not a parser hardening item — see Verification → Known
divergences for the full description.)

## Verification

- **Fixture:** the Worked examples above are synthetic and byte-exact.
  `tests/fixtures/minimal_uasset_v5.uasset` carries an `FEngineVersion`
  ending in the branch FString `"++UE4+Release-4.27"` but extracting
  it requires walking the package summary to find its offset.
- **Hex anchor commands:**
  ```
  # The standard Worked example (32 bytes total):
  printf '\x05\x00\x01\x00\x01\x00\x39\x30\x00\x00\x12\x00\x00\x00++UE5+Release-5.1\x00' | xxd
  # The licensee variant differs only at offset +6 (changelist):
  printf '\x05\x00\x01\x00\x01\x00\x39\x30\x00\x80\x12\x00\x00\x00++UE5+Release-5.1\x00' | xxd
  ```
  Any conformant parser fed these byte sequences MUST produce the
  decoded values shown in the Worked examples above.
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
