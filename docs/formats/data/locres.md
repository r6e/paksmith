# Locres (`.locres`)

> Standalone localization-table format produced by the UE cooker.
> Maps `(namespace, key) → source string` for each culture; runtime
> uses the matching `.locres` file based on the player's language
> setting. **Not a UE package** — has its own header, version field,
> and table layout.

## Overview

`.locres` ("localization resource") is the binary format UE's
cooker emits for runtime localization. A cooked game ships one
`.locres` file per supported culture (e.g. `en/Game.locres`,
`fr/Game.locres`, `ja/Game.locres`) plus per-mod / per-plugin
variants. At runtime, the engine looks up text by
`(namespace, key)` and returns the source string from the active
culture's `.locres`.

The format is **not a UE package** — it has no `FPackageFileSummary`,
no name table, no import / export tables. It's a flat binary file
with:

1. A header (16-byte `FGuid` magic + version byte).
2. A strings array (deduplicated source strings with reference
   counts; versions `Compact` and later).
3. A namespace table mapping `namespace → entries`.
4. Per-namespace entry tables mapping `key → (source-string-hash, string-array-index)`.

Public, stable format. paksmith's Phase 3 work should extract
`.locres` files into per-culture JSON or CSV for translation
workflows — high-value extraction target since game scripts and
dialog ship via this format.

**Status: not yet implemented in paksmith.** Phase 3+ deliverable.

## Versions

`.locres` carries its own version field (distinct from any UE
asset or pak version). Four versions exist:

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `ELocResVersion::Legacy` (v0, pre-UE 4.13) | No file header / magic; starts directly with the namespace count. Inline `FString` per key entry for the localized string (no strings array, no `StringIndex`). | `FabianFG/CUE4Parse/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| `ELocResVersion::Compact` (v1, UE 4.13+) | Added 16-byte magic + version byte; added the deduplicated strings array with offset pointer. Key entries store an `i32 StringIndex` instead of an inline `FString`. No pre-hashed namespace/key strings. | Same[^1] |
| `ELocResVersion::Optimized_CRC32` (v2, UE 4.14+) | Added total entries count field (4 bytes, skipped). Namespace and key strings now pre-hashed with CRC32 (hash read before each `FString`). `RefCount` (`i32`) added to each strings-array entry. | Same[^1] |
| `ELocResVersion::Optimized_CityHash64_UTF16` (v3, UE 4.20+) | Switched pre-hash function from CRC32 to CityHash64 of UTF-16-encoded strings, low 32 bits. | Same[^1] |

Cooked content paksmith targets uses version 3 almost exclusively
(UE 4.21+).

## Wire layout

### File header

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 16 | LE | `magic` | `FGuid` | `{0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3}` (four `u32` LE). Absence indicates a Legacy (version 0) file — on mismatch, seek back to offset 0 and assume Legacy. |
| 16 | 1 | — | `version` | `ELocResVersion` (u8) | `0` = Legacy (but Legacy files have no magic — this byte is only present when magic matched), `1` = Compact, `2` = Optimized_CRC32, `3` = Optimized_CityHash64_UTF16. |

The on-disk byte sequence of the magic FGuid (four u32 in
little-endian): `0E 14 74 75 67 4A 03 FC 4A 15 90 9D C3 37 7F 1B`.

### Strings array (versions `Compact` and later)

Immediately after the version byte, a seek-and-return pattern:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `StringsArrayOffset` | 8 | LE | `i64` | Byte offset to the strings array within the file. If `-1` (INDEX_NONE), the strings array is absent for this file. |
| (seek to `StringsArrayOffset`) | | | | |
| `NumStrings` | 4 | LE | `i32` | Number of deduplicated strings in the array. |
| `Strings` | variable | — | `FTextLocalizationResourceString[]` | Each entry: `FString text` + (versions `Optimized_CRC32` and later only) `i32 RefCount`. Version `Compact` strings have no RefCount field (`RefCount` is treated as `-1`). |
| (seek back to position 25, byte immediately after the 8-byte `StringsArrayOffset` field) | | | | |

The deduplication is a cooker optimization — strings shared across
many `(namespace, key)` pairs (e.g. `"Continue"`, `"Cancel"`,
empty strings) are stored once. `RefCount` tracks how many entries
reference each string; runtime doesn't need it.

### Total entries count (versions `Optimized_CRC32` and later)

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `EntriesCount` | 4 | LE | `u32` | Total `(namespace, key)` entries across all namespaces. Skipped by the reader (sanity-check data only). |

### Namespace table

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumNamespaces` | 4 | LE | `u32` | Number of namespaces. |
| `Namespaces` | variable | — | `FNamespaceEntry[]` | Per-namespace records. |

Each `FNamespaceEntry`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NamespaceHash` | 4 | LE | `u32` | Hash of the namespace string. **Present only for versions `Optimized_CRC32` and later.** CRC32 for version 2; CityHash64-of-UTF16 (low 32 bits) for version 3. |
| `Namespace` | variable | — | `FString` | Namespace name (e.g. `"Game"`, `"UI"`, `"DialogueLines"`). |
| `NumKeys` | 4 | LE | `u32` | Number of `(key, entry)` pairs in this namespace. |
| `Entries` | variable | — | `FKeyEntry[]` | Per-key records. |

Each `FKeyEntry`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `KeyHash` | 4 | LE | `u32` | Hash of the key string. **Present only for versions `Optimized_CRC32` and later** — same algorithm as `NamespaceHash`. |
| `Key` | variable | — | `FString` | Key name (e.g. `"5DD42A4E4B5C7F8A_Continue"`). |
| `SourceStringHash` | 4 | LE | `u32` | Cooker-side hash of the source string for change-detection only. Reader MUST NOT use this value for lookup, dispatch, deduplication, or cache-key logic — treat as informational only. Mismatches with actual string content are silently ignored per oracle. |
| `StringIndex` | 4 | LE | `i32` | Index into the strings array. **Present for versions `Compact` (v1) and later only.** Legacy (v0) reads an inline `FString` for the localized string instead — no `StringIndex` field exists in Legacy key entries. A parser that attempts a fallback `FString` read on OOB would corrupt its read position. See Caps & limits for bounds enforcement. |

> **Cursor-misalignment trap:** A reader that gates hash-field reads on `>= Compact` instead of `>= Optimized_CRC32` will misalign its read cursor on every key/namespace entry in version 1 (Compact) files. The gating must match the wire-table row condition exactly.

### Legacy (version 0) layout

Legacy files start at offset 0 with no magic or version byte:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumNamespaces` | 4 | LE | `u32` | Number of namespaces. |
| `Namespaces` | variable | — | Legacy namespace entries — no `NamespaceHash`, no `KeyHash`, inline `FString` per entry instead of `StringIndex`. | |

Detection: read 16 bytes at offset 0; if not equal to the magic
FGuid, seek back to 0 and parse as Legacy.

### Worked example

`(none yet — Phase 3 deliverable)`. A minimal version-3 `.locres`
fixture would be cheap to synthesize: one namespace, two keys, two
strings — approximately 150 bytes. Adding one is a natural follow-up
when Phase 3 implements the reader.

## Variants

UE cooks one `.locres` per culture per target. A game's localization
tree typically looks like:

```
Content/Localization/Game/
├── en/Game.locres
├── fr/Game.locres
├── ja/Game.locres
└── …
```

paksmith's CLI integration (Phase 4) should expose per-culture
extraction so users can dump a single language without parsing
every locale's file.

## Caps & limits

Phase 3+ deferred work. Cap values for `MAX_NAMESPACES_PER_LOCRES`,
`MAX_ENTRIES_PER_NAMESPACE`, and `MAX_STRINGS_PER_LOCRES` will be
determined when the Phase 3 reader lands. The `i32 StringIndex`
type sets an implicit ceiling on the strings-array size.

The following are **required wire invariants** — not deferred Phase 3
work. They MUST be enforced the moment any reader exists:

- **Unknown version rejection (required wire invariant):** When the first 16 bytes match the magic FGuid, `versionByte` MUST be in `{1, 2, 3}` (`ELocResVersion::{Compact, Optimized_CRC32, Optimized_CityHash64_UTF16}`). Any value > 3 MUST cause the reader to reject the file — silent fallthrough to version-3 parsing on an unknown discriminant misaligns field boundaries and is a DoS vector. Version byte `0` AFTER magic match is a contradictory state (Legacy files by definition have no magic prefix; `0` belongs only to the no-magic dispatch path) and MUST also be rejected on the magic-match path to prevent silent layout confusion. Files that fail magic-match are dispatched to the Legacy (v0) read path, which does NOT read a version byte at all and seeks back to offset 0 to read `NumNamespaces` directly.
- **`StringsArrayOffset` (`i64`) bounds-check (required wire invariant):** When `StringsArrayOffset != -1`, MUST satisfy `25 <= StringsArrayOffset < file_size` (offset 25 = first byte after the 8-byte `StringsArrayOffset` field itself; offsets `[17, 24]` ARE the field bytes — a parser CAN'T seek INTO them; -1 is the sentinel for absent strings array). Values outside this range (other than -1) MUST be rejected — a crafted offset is an arbitrary-seek DoS vector: a very large positive offset causes hang on sparse read or silent truncation reading garbage; a negative non-(-1) offset is a sign-extension hazard on seek; an offset in `[17, 24]` would re-read bytes of the offset field itself as `NumStrings`. The seek-and-return-to-position-25 protocol relies on this bounds-check holding before the seek.
- **`NumStrings` (`i32`) sign-check + allocation cap (required wire invariant, not deferred):** MUST be validated `>= 0` before allocating the strings array. A negative `NumStrings` cast to `usize` produces `usize::MAX`-adjacent values; immediate OOM or panic on allocation. Additionally: same direct-allocation-driver hazard as `NumNamespaces`/`NumKeys` — a conservative cap of `2^20 = 1,048,576` is sufficient to prevent OOM on adversarial input while remaining well above any production locres file. Phase 3 SHOULD tighten via `MAX_STRINGS_PER_LOCRES` once usage patterns are established. This is NOT a deferred cap — it is a wire invariant required the moment any reader exists.
- **`NumNamespaces` and `NumKeys` (`u32`) allocation caps (required wire invariant, not deferred):** Both fields are direct allocation drivers. A `u32::MAX` value causes OOM on any implementation that allocates a `Vec` upfront with that capacity before reading entries. Phase 3 SHOULD set tightened caps via per-format limits (`MAX_NAMESPACES_PER_LOCRES`, `MAX_KEYS_PER_NAMESPACE`); until then, a conservative cap of `2^20 = 1,048,576` per field is sufficient to prevent OOM on synthetic adversarial input while remaining well above any production locres file. The file-size backstop alone is insufficient since allocation precedes read.
- **`StringIndex` (`i32`) bounds-check (required wire invariant):** MUST be validated `0 <= StringIndex < NumStrings` before use. Negative values must be rejected — in Rust, casting `-1i32` to `usize` either panics on indexing or wraps to `usize::MAX` depending on implementation. Out-of-range positive values must be treated per oracle: log a warning, leave the entry untranslated, do NOT attempt any fallback read.
- **`StringsArrayOffset == -1` interaction with non-(-1) `StringIndex` (required behavior):** When `StringsArrayOffset == -1`, the strings array is empty per oracle. In this case, all `StringIndex` values in key entries MUST be treated as invalid (effective `NumStrings == 0`); any non-(-1) `StringIndex` produces empty/error strings, NOT an attempted dereference into an absent array.

## Verification

- **Fixture:** `(none yet — Phase 3 deliverable)`.
- **Hex anchor commands:** `(none yet — Phase 3 deliverable)`.
- **Cross-validation oracle:** CUE4Parse[^1]. The format is fully
  public; no proprietary-codec concerns.
- **Known divergences:** none yet.

## Paksmith implementation

**Parser module:** not yet implemented.

**Status:** `not impl`.

**Phase plan:** See `docs/plans/ROADMAP.md` for the Phase 3 and
Phase 4 work that will add the `.locres` reader and CLI integration.
The module belongs outside `crates/paksmith-core/src/asset/` because
`.locres` is not a UObject package.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers all four versions, the magic FGuid, the seek-and-return strings-array pattern, and the hash-algorithm dispatch. Supporting types: `ELocResVersion` in `UE4/Objects/Core/i18N/ELocResVersion.cs`, `FTextKey` in `UE4/Objects/Core/i18N/FTextKey.cs`, `FEntry` in `UE4/Objects/Core/i18N/FEntry.cs`, `FTextLocalizationResourceString` in `UE4/Objects/Core/i18N/FTextLocalizationResourceString.cs`.
