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
discriminant, followed by a history-specific body. Paksmith handles
the two most common variants — `None` (culture-invariant string) and
`Base` (the canonical namespace/key/source triple). Other variants
(`NamedFormat`, `OrderedFormat`, `ArgumentFormat`, `AsNumber`,
`AsPercent`, `AsCurrency`, `AsDate`, `AsTime`, `AsDateTime`,
`Transform`, `StringTableEntry`, `TextGenerator`) are stored as
`FTextHistory::Unknown { history_type, skipped_bytes }` — the wire is
consumed so downstream fields stay aligned, but the value isn't
decoded.

**Paksmith status: `partial`.** `None` and `Base` cover the vast
majority of cooked content; the unhandled variants appear mostly for
UI text with runtime formatting (player names interpolated into
dialog, dates rendered for the user's locale, etc.). Phase 3+ work
may specialize the format variants as part of UI / dialog asset
support.

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

### Other `history_type` values

After reading `flags` and `history_type`, the parser computes `remaining
= tag_size - bytes_already_consumed` using `saturating_sub`, then reads
exactly that many opaque bytes. The body surfaces as
`FTextHistory::Unknown { history_type, skipped_bytes }`. Unknown variants
don't declare their own body size — the enclosing tag's `size` field
bounds the skip, and `saturating_sub` prevents a malformed `tag_size`
from driving an oversized allocation.

The discriminants and their UE names (for reference; paksmith doesn't
decode them):

| Value | Name |
|-------|------|
| 1 | `NamedFormat` |
| 2 | `OrderedFormat` |
| 3 | `ArgumentFormat` |
| 4 | `AsNumber` |
| 5 | `AsPercent` |
| 6 | `AsCurrency` |
| 7 | `AsDate` |
| 8 | `AsTime` |
| 9 | `AsDateTime` |
| 10 | `Transform` |
| 11 | `StringTableEntry` |
| 12 | `TextGenerator` |

### Worked example: first FText body

```bash
xxd tests/fixtures/minimal_uasset_v5_with_extended_types.uasset | head -30
```

The first TextProperty body begins with `u32 flags` followed by
`i8 history_type`. The history-specific body follows; the easiest
anchor is a `Base`-history text (most cooked content) starting with
an FString namespace.

## Variants

Paksmith decodes two variants typed — `None` (`history_type == -1`, culture-invariant string) and `Base` (`history_type == 0`, namespace/key/source triple) — and stores the remaining 12 `ETextHistoryType` values as `FTextHistory::Unknown { history_type, skipped_bytes }`, consuming exactly `tag_size - bytes_already_consumed` opaque bytes via `saturating_sub` to keep downstream fields aligned.

### Empty culture-invariant string

`history_type == -1` with `has_culture_invariant == 0` is the most
compact FText — 9 bytes total (`u32 flags` + `i8 history_type` +
`u32 has_culture_invariant`). Common for editor-side default values
that don't carry localization context.

## Caps & limits

- **`tag.size`** — the enclosing tag publishes the FText body's byte
  size. For unknown history types, the parser skips
  `tag_size - bytes_already_consumed` opaque bytes (computed via
  `saturating_sub`). `try_reserve_exact` routes any OOM through
  `AllocationFailed { context: UnknownFTextBytes }` rather than
  aborting; the allocation is bounded per-call by `tag_size ≤
  MAX_PROPERTY_TAG_SIZE`.
- **`FSTRING_MAX_LEN = 65,536`** — applies to each FString field
  inside the FText body (namespace, key, source_string, culture
  invariant).

## Verification

- **Fixture:** `tests/fixtures/minimal_uasset_v5_with_extended_types.uasset`
  carries `Base`-history TextProperty entries (Phase 2d coverage).
- **Hex anchor commands:** see the *Worked example* block in Wire layout (the embedded `xxd` command produces the expected bytes against the named fixture).
- **Cross-validation oracle:** CUE4Parse[^1] and `unreal_asset`[^2].
  Both handle the full history-type catalog. Paksmith's
  None+Base coverage round-trips against both; the
  Unknown-history fallback is a paksmith-specific limitation.
- **Known divergences:**
  - **History-variant coverage.** Paksmith decodes `None` and `Base`
    typed; the other 12 variants surface as `Unknown { history_type, skipped_bytes }`.
    CUE4Parse and unreal_asset specialize the format variants.
    Practical impact: gameplay text (`Base`) and editor defaults
    (`None`) decode; runtime-formatted UI text doesn't.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/asset/property/text.rs`.

**Status:** `partial`. `FTextHistory::None` and `Base` decode typed;
other variants → `FTextHistory::Unknown`.

**Public surface:**
- `pub struct FText { pub flags: u32, pub history: FTextHistory }`.
- `pub enum FTextHistory` (`#[non_exhaustive]`) — `None`, `Base`,
  `Unknown`.
- `pub fn read_ftext<R: Read + Seek>(reader, ctx, asset_path, tag_size) -> Result<FText>`.

**Error variants:**
- `AssetParseFault::UnexpectedEof { field }` — short read on any binary field.
- `AssetParseFault::FStringMalformed { kind }` — malformed FString inside any text-body field.
- `AssetParseFault::AllocationFailed { context: UnknownFTextBytes, ... }` — OOM allocating the Unknown-history skip buffer.
- `AssetParseFault::U64ExceedsPlatformUsize { field: FTextField, value }` — `tag_size` residual doesn't fit `usize` (only reachable on 32-bit targets with a pathological tag).
- `PaksmithError::Io` — `stream_position()` failure on any seek.

**Phase plan:**
- None + Base: `docs/plans/phase-2b-tagged-properties.md` (Task 5).
- Other history variants: deferred, no phase plan yet. Likely
  Phase 3+ alongside UI / dialog asset handlers.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Objects/Core/i18N/FText.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle. Documents every `ETextHistoryType` variant's body layout.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_properties/src/str_property.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle (FText decoder lives alongside FString in the `str_property` module).
