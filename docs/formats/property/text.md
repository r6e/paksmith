# TextProperty (`FText`)

> UE's localization-aware text property — a discriminated union over
> `ETextHistoryType` carrying a namespace / key / source string for
> localized content, an invariant string for non-localized content, or
> a more complex history record (formatted text, ordered-argument
> substitution, etc.) for derived text.

## Overview

`FText` is UE's text-with-localization-context type. Unlike `FString`
(see [`../primitive/fstring.md`](../primitive/fstring.md)), FText
carries the metadata needed to look up the displayed string in the
runtime localization tables: namespace, key, and the raw source
string that serves as a fallback if localization data is missing.

The wire shape is a `u32 flags` field followed by an `i8 history_type`
discriminant, followed by a history-specific body. Paksmith decodes
five variants — `None` (culture-invariant string), `Base` (the
canonical namespace/key/source triple), and, as of
[#641](https://github.com/r6e/paksmith/issues/641), `NamedFormat`,
`OrderedFormat`, and `StringTableEntry`. The remaining variants (see
§*ETextHistoryType reference*) are stored as
`FTextHistory::Unknown { history_type, skipped_bytes }` — the wire is
consumed so downstream fields stay aligned, but the value isn't
decoded.

**Document status: complete.** Wire format documented in full
against CUE4Parse[^1] with worked examples below for the two most
common history variants (`None` empty and `Base` namespace+key+source)
and field tables for the #641 trio. The remaining deferred history
variants are catalogued by discriminant value; their body layouts are
documented in CUE4Parse for implementers who need them.

**Paksmith parser status: `partial`.** `None`, `Base`,
`NamedFormat`, `OrderedFormat`, and `StringTableEntry` cover the vast
majority of cooked content, including string-table-referenced UI text
and runtime-formatted patterns; the still-unhandled variants are
mostly locale rendering (dates, numbers, currency) and the
editor-side `ArgumentFormat`/`TextGenerator` forms.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `FileVersionUE4 ≥ 504` | `(u32 flags, i8 history_type, body)` shape stable. | `CUE4Parse/UE4/Objects/Core/i18N/FText.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

Some history-variant bodies have version-conditional fields (e.g.
`AsNumber` formatting options); paksmith doesn't decode those
bodies, so the version conditionals don't bite within the supported
range.

## Wire layout

### Outer record

| field | size | type | semantics |
|-------|------|------|-----------|
| `flags` | 4 | `u32` LE | `ETextFlag` mask — Transient, CultureInvariant, ConvertedProperty, Immutable, InitializedFromString. Stored but mostly informational. |
| `history_type` | 1 | `i8` | `ETextHistoryType` discriminant. `-1` → `None`, `0` → `Base`, other values → variants paksmith doesn't decode. |
| `body` | variable | — | History-specific body; layout depends on `history_type`. |

### `history_type == -1` (`None`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `has_culture_invariant` | 4 | `u32` LE | Non-zero → read `culture_invariant`. `FArchive::ReadBoolean` emits a 4-byte value on the wire; the field is read as `u32`. |
| `culture_invariant` | variable | `FString` | Present iff `has_culture_invariant != 0`. |

`PropertyValue::Text(FText { flags, history: FTextHistory::None { culture_invariant: Option<String> } })`.

### `history_type == 0` (`Base`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `namespace` | variable | `FString` | Localization namespace (often empty for non-localized strings). |
| `key` | variable | `FString` | Localization key. |
| `source_string` | variable | `FString` | The raw source string (the English original by convention). |

`PropertyValue::Text(FText { flags, history: FTextHistory::Base { namespace, key, source_string } })`.

### `history_type == 1` (`NamedFormat`) / `== 2` (`OrderedFormat`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `source_fmt` | variable | `FText` | The format pattern — a **full recursive FText** (flags + history type + body). |
| `count` | 4 | `i32` LE | Argument count. Paksmith rejects negative or > 65,536 (`CollectionElementCountExceeded`); CUE4Parse has no cap. |
| per argument (`NamedFormat` only) | variable | `FString` | The placeholder name. |
| per argument | 1 | `i8` | `EFormatArgumentType`: `Int (0)` → i64, `UInt (1)` → u64, `Float (2)` → f32, `Double (3)` → f64, `Text (4)` → recursive `FText`. `Gender (5)` and unknown bytes are fail-closed (`TextFormatArgUnsupported`) — no community reference implements a Gender payload. |
| per argument | variable | typed | The payload per the type byte. |

In this (non-`ArgumentFormat`) context the type byte is always present
and `Int` is always i64 — the `isArgumentData` version gates in
CUE4Parse apply only to the undecoded `ArgumentFormat (3)` history.
Recursion (the pattern and `Text`-typed arguments) is bounded by
`MAX_PROPERTY_DEPTH = 128`; a nested FText with an undecoded history
type is fail-closed (`TextHistoryUnsupportedInElement`) because nested
contexts carry no size to skip with.

### `history_type == 11` (`StringTableEntry`)

| field | size | type | semantics |
|-------|------|------|-----------|
| `table_id` | 8 | `FName` | `i32` name-table index + `i32` number; resolved against the asset's name table. |
| `key` | variable | `FString` | The entry key within the string table. |

No version gates.

### Other `history_type` values

After reading `flags` and `history_type`, the parser computes `remaining
= tag_size - bytes_already_consumed` using `saturating_sub`, then reads
exactly that many opaque bytes. The body surfaces as
`FTextHistory::Unknown { history_type, skipped_bytes }`. Unknown variants
don't declare their own body size — the enclosing tag's `size` field
bounds the skip, and `saturating_sub` prevents a malformed `tag_size`
from driving an oversized allocation. (CUE4Parse instead aliases unknown
history types to `None` — a mis-decode paksmith deliberately does not
copy.)

For the full discriminant-to-name mapping, see §*ETextHistoryType reference* below.

### ETextHistoryType reference

| Value | Name | Paksmith |
|-------|------|----------|
| -1 | `None` | decoded |
| 0 | `Base` | decoded |
| 1 | `NamedFormat` | decoded (#641) |
| 2 | `OrderedFormat` | decoded (#641) |
| 3 | `ArgumentFormat` | `Unknown` skip |
| 4 | `AsNumber` | `Unknown` skip |
| 5 | `AsPercent` | `Unknown` skip |
| 6 | `AsCurrency` | `Unknown` skip |
| 7 | `AsDate` | `Unknown` skip |
| 8 | `AsTime` | `Unknown` skip |
| 9 | `AsDateTime` | `Unknown` skip |
| 10 | `Transform` | `Unknown` skip |
| 11 | `StringTableEntry` | decoded (#641) |
| 12 | `TextGenerator` | `Unknown` skip |

### Worked example — `None` history with empty culture-invariant (9 bytes)

The most compact FText: flags = 0, history_type = -1 (None), no
culture-invariant string. This is the default-constructed editor-side
FText.

```
Offset  Bytes (LE)              Field
------  ----------------------  ---------------------
+0      00 00 00 00             flags = 0 (u32)
+4      FF                      history_type = -1 (i8, two's-complement = 0xFF)
+5      00 00 00 00             has_culture_invariant = 0 (u32; ReadBoolean as 4-byte)
+9                               (end — 9 bytes)
```

Decoded: `FText { flags: 0, history: FTextHistory::None { culture_invariant: None } }`.

### Worked example — `Base` history with namespace+key+source

A typical localized FText: `flags = 0`, `history_type = 0` (Base),
namespace `"Game"`, key `"k1"`, source string `"Hello"`.

```
Offset  Bytes (LE)                                  Field
------  ------------------------------------------  ---------------------
+0      00 00 00 00                                 flags = 0 (u32)
+4      00                                          history_type = 0 (i8, Base)
+5      05 00 00 00 47 61 6D 65 00                  namespace FString len=5, "Game\0"
+14     03 00 00 00 6B 31 00                        key FString len=3, "k1\0"
+21     06 00 00 00 48 65 6C 6C 6F 00               source_string FString len=6, "Hello\0"
+31                                                  (end — 31 bytes)
```

Decoded: `FText { flags: 0, history: FTextHistory::Base { namespace: "Game", key: "k1", source_string: "Hello" } }`.

The runtime localization lookup uses `(namespace, key)` to find the
displayed translation in the active culture's `.locres` (see
[`../data/locres.md`](../data/locres.md)); if no entry matches,
the runtime falls back to `source_string`.

## Variants

Variation is whole-history-typed: the discriminant byte selects which of the 14 history shapes to decode. Paksmith decodes `None`, `Base`, `NamedFormat`, `OrderedFormat`, and `StringTableEntry` in full; the other 9 are deferred to `FTextHistory::Unknown` with the byte count preserved (see Wire layout §*Other history_type values* for the `saturating_sub` mechanism). A decodable `NamedFormat`/`OrderedFormat` whose NESTED content is undecodable (an `Unknown`-typed pattern/argument FText, or a `Gender` argument) also degrades to `Unknown` in the direct tag-sized context, and fails closed in size-less contexts.

### Empty culture-invariant string

`history_type == -1` with `has_culture_invariant == 0` is the most
compact FText — 9 bytes total (`u32 flags` + `i8 history_type` +
`u32 has_culture_invariant`). Common for editor-side default values
that don't carry localization context.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`tag.size`** — the enclosing tag publishes the FText body's
  total byte size (`MAX_PROPERTY_TAG_SIZE = 16 MiB` per
  [`tagged.md`](tagged.md)). Every FText fits within this bound by
  construction.
- **`history_type: i8`** range: `-128..=127` per the type. UE
  currently uses `-1..=12` (14 variants); values outside this range
  are wire-format-valid but have no defined body shape.
- **FString fields** inherit the FString length cap from
  [`../primitive/fstring.md`](../primitive/fstring.md).

### Implementation hardening (recommended for any parser)

- **`history_type` discriminant validation.** A reader MUST treat
  values outside `{-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}` as
  unknown rather than mis-dispatching. Silent fallthrough to a
  default body decode would corrupt the cursor and silently
  mis-decode every subsequent property tag — this is a correctness
  invariant, not a recommendation.
- **`saturating_sub` for unknown-variant skip.** When computing how
  many bytes to skip for an unknown history type, use
  `saturating_sub(tag_size, bytes_consumed)` rather than `tag_size -
  bytes_consumed`. A malformed tag with a smaller `Size` than
  expected (e.g., `tag.size = 5`, `bytes_consumed = 9` because the
  parser already read the 9-byte `None`-history prefix) would
  underflow without `saturating_sub`. The saturation produces 0,
  meaning no skip (which is correct — the body is already over).
- **Skip without allocation for unknown-variant bodies.** The body
  bytes for unknown variants carry no useful information for a
  parser that doesn't decode them; the only requirement is to
  advance the cursor by exactly the right count so the next property
  tag aligns. Stream the bytes directly into a discard sink (e.g.
  `io::copy(&mut reader.by_ref().take(remaining), &mut io::sink())`
  — `by_ref()` reborrows the reader so subsequent properties can
  still use it) instead of allocating a buffer. A 16 MiB `tag.size`
  then costs zero heap bytes. Paksmith's `skip_asset_bytes` helper
  implements exactly this; only the `usize` byte count is retained
  for `FTextHistory::Unknown::skipped_bytes`.
- **`FSTRING_MAX_LEN = 65,536`** — applies to each FString field
  inside the FText body (namespace, key, source_string, culture
  invariant) via the FString reader's own caps.

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset`
  carries `Base`-history TextProperty entries (Phase 2d coverage).
  The worked examples above are byte-exact and self-contained for
  the most common 9-byte and 31-byte cases.
- **Hex anchor commands:**
  ```
  # Synthesize the empty-None FText (9 bytes):
  printf '\x00\x00\x00\x00\xFF\x00\x00\x00\x00' | xxd
  # Synthesize the Base-history FText with Game/k1/Hello (31 bytes):
  printf '\x00\x00\x00\x00\x00\x05\x00\x00\x00Game\x00\x03\x00\x00\x00k1\x00\x06\x00\x00\x00Hello\x00' | xxd
  ```
  Any conformant parser fed these byte sequences MUST decode them
  as the FText values shown in the Worked examples above.
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both handle more of the history-type catalog. Paksmith's decoded
  variants round-trip against both; the Unknown-history fallback for
  the remaining types is a paksmith-specific limitation.
- **Known divergences:**
  - **History-variant coverage.** Paksmith decodes `None`, `Base`,
    `NamedFormat`, `OrderedFormat`, and `StringTableEntry` typed
    ([#641](https://github.com/r6e/paksmith/issues/641)); the other 9
    variants surface as `Unknown { history_type, skipped_bytes }`.
    CUE4Parse and unreal_asset specialize more of the format variants.
    Practical impact: gameplay text, string-table references, and
    runtime-formatted patterns decode; locale rendering (dates,
    numbers, currency) doesn't.
  - **Unknown-history handling.** CUE4Parse aliases unrecognized
    history types to `None` (and still conditionally reads a bool) —
    a mis-decode paksmith deliberately does not copy (skip-to-tag-end
    `Unknown` instead).

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/text.rs`.

**Status:** `partial`. `FTextHistory::None`, `Base`, `NamedFormat`,
`OrderedFormat`, and `StringTableEntry` decode typed; other variants →
`FTextHistory::Unknown`.

**Public surface:**
- `pub struct FText { pub flags: u32, pub history: FTextHistory }`.
- `pub enum FTextHistory` (`#[non_exhaustive]`) — `None`, `Base`,
  `NamedFormat`, `OrderedFormat`, `StringTableEntry`, `Unknown`.
- `pub struct FTextNamedArg { pub name: String, pub value: FTextFormatArg }`.
- `pub enum FTextFormatArg` (`#[non_exhaustive]`) — `Int` / `UInt` /
  `Float` / `Double` / `Text`.
- `pub fn read_ftext<R: Read + Seek>(reader, ctx, asset_path, tag_size, depth) -> Result<FText>`.

**Error variants:**
- `AssetParseFault::UnexpectedEof { field }` — short read on any binary field.
- `AssetParseFault::FStringMalformed { kind }` — malformed FString inside any text-body field.
- `AssetParseFault::PropertyDepthExceeded { depth, limit }` — recursive FText nesting past `MAX_PROPERTY_DEPTH` (128).
- `AssetParseFault::CollectionElementCountExceeded { collection: TextFormatArguments, .. }` — negative or over-cap format-argument count.
- `AssetParseFault::TextFormatArgUnsupported { arg_type }` — `Gender (5)` or unknown argument type (recovered to `Unknown` in the direct context; fail-closed in size-less contexts).
- `AssetParseFault::TextHistoryUnsupportedInElement { history_type }` — undecoded history in a size-less context (element / unversioned / nested FText).
- `AssetParseFault::U64ExceedsPlatformUsize { field: FTextField, value }` — `tag_size` residual doesn't fit `usize` (only reachable on 32-bit targets with a pathological tag).
- `PaksmithError::Io` — `stream_position()` or skip-sink I/O failure.

**Phase plan:**
- None + Base: `docs/plans/phase-2b-tagged-properties.md` (Task 5).
- NamedFormat / OrderedFormat / StringTableEntry:
  [#641](https://github.com/r6e/paksmith/issues/641).
- Remaining history variants (locale rendering, `ArgumentFormat`,
  `Transform`, `TextGenerator`): deferred, no phase plan yet.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/i18N/FText.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. Documents every `ETextHistoryType` variant's body layout.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/str_property.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle (FText decoder lives alongside FString in the `str_property` module).
