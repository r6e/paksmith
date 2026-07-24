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

All multi-byte integers are little-endian. All strings use UE's
`FString` serialization (see [`../primitive/fstring.md`](../primitive/fstring.md)).

Public, stable format with a working pure-Rust reference fixture in
this repository (see Verification below). Any decoder can be built
directly from this document plus an `FString` reader and a hash
function for the version's hash algorithm.

**Document status: complete.** Wire format documented in full
against CUE4Parse[^1] with a working `v2` fixture, hex anchors, and
a byte-by-byte worked example.

**Paksmith parser status: `complete`.** `.locres` is parsed by
`crates/paksmith-core/src/localization/locres.rs` and exported to
CSV/JSON; the CLI `extract` command converts `.locres` entries via
`--locres-format` (#646).

## Versions

`.locres` carries its own version field (distinct from any UE
asset or pak version). Four versions exist:

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `ELocResVersion::Legacy` (v0, pre-UE 4.13) | No file header / magic; starts directly with the namespace count. Inline `FString` per key entry for the localized string (no strings array, no `StringIndex`). | `FabianFG/CUE4Parse/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d`[^1] |
| `ELocResVersion::Compact` (v1, UE 4.13+) | Added 16-byte magic + version byte; added the deduplicated strings array with offset pointer. Key entries store an `i32 StringIndex` instead of an inline `FString`. No pre-hashed namespace/key strings. | Same[^1] |
| `ELocResVersion::Optimized_CRC32` (v2, UE 4.14+) | Added total entries count field (4 bytes, skipped by reference parsers). Namespace and key strings now pre-hashed with CRC32 (hash read before each `FString`). `RefCount` (`i32`) added to each strings-array entry. | Same[^1] |
| `ELocResVersion::Optimized_CityHash64_UTF16` (v3, UE 4.20+) | Switched pre-hash function from CRC32 to CityHash64 of UTF-16-LE-encoded strings, low 32 bits. | Same[^1] |

Cooked content paksmith targets uses version 3 almost exclusively
(UE 4.21+); version 2 remains in some long-tail cooked content
from the UE 4.14–4.19 era.

### Hash algorithms

- **v2** (`Optimized_CRC32`): `crc32(string.encode_utf16_le())` —
  ISO/IEC standard CRC-32/IEEE polynomial (`0xEDB88320` reversed,
  matches `zlib.crc32` in Python and the `crc32fast` crate in Rust).
  Input is the string's UTF-16 little-endian byte representation
  WITHOUT BOM and WITHOUT null terminator.[^3]
- **v3** (`Optimized_CityHash64_UTF16`):
  `cityhash64(string.encode_utf16_le()) & 0xFFFFFFFF` — Google
  CityHash64 reference algorithm (the original 2011 publication;
  not CityHash64WithSeed). Low 32 bits only. Same UTF-16-LE input
  format as v2. Pure-Rust implementation available via the
  `cityhasher` crate or any CityHash64 binding matching the
  reference C++.[^2]

In both versions, the hash is informational metadata — the source
of truth is the string itself. Hash mismatches are silently
ignored per the oracle's runtime behavior. See "Implementation
hardening" below for why parsers should still compute the expected
hash as a corruption-detection check.

## Wire layout

### File header

| offset | size | endian | name | type | semantics |
|--------|------|--------|------|------|-----------|
| 0 | 16 | LE | `magic` | `FGuid` | `{0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3}` (four `u32` LE — see [`../primitive/fguid.md`](../primitive/fguid.md) for the standard `FGuid` four-word LE layout). Absence indicates a Legacy (v0) file: on mismatch, seek back to offset 0 and use the Legacy parse path. |
| 16 | 1 | — | `version` | `ELocResVersion` (u8) | `1` = Compact, `2` = Optimized_CRC32, `3` = Optimized_CityHash64_UTF16. Value `0` after a magic match is a contradictory state (Legacy has no magic prefix); paksmith rejects it, see "Implementation hardening". |

The on-disk byte sequence of the magic `FGuid` (four `u32` written
in little-endian order):

```
00000000: 0E 14 74 75  67 4A 03 FC  4A 15 90 9D  C3 37 7F 1B
```

The version byte sits immediately at offset 16.

### Strings array (versions `Compact` and later)

Immediately after the version byte, the reader uses a
seek-and-return pattern to load the deduplicated strings array
from a separately-pointed-at region of the file:

| field | offset (from header) | size | endian | type | semantics |
|-------|---------------------|------|--------|------|-----------|
| `StringsArrayOffset` | 17 | 8 | LE | `i64` | Byte offset to the strings array within the file. If `-1` (INDEX_NONE), the strings array is absent for this file (all `StringIndex` references must then resolve to "empty"). |
| *(seek to `StringsArrayOffset`)* | | | | | |
| `NumStrings` | (at offset) | 4 | LE | `i32` | Number of deduplicated strings in the array. |
| `Strings` | | variable | — | `FTextLocalizationResourceString[]` | Each entry: `FString text` + (v2+ only) `i32 RefCount`. v1 strings have no `RefCount` field and the reader treats it as `-1`. |
| *(seek back to position 25 — byte immediately after the 8-byte `StringsArrayOffset` field)* | | | | | |

The deduplication is a cooker optimization: source strings shared
across many `(namespace, key)` pairs (e.g. `"Continue"`,
`"Cancel"`, empty strings) are stored once and referenced
multiple times. `RefCount` records how many entries reference each
string; runtime doesn't use it.

The seek-and-return-to-position-25 contract means: after the
strings-array round-trip, the next read at offset 25 is
`EntriesCount` (v2+) or `NumNamespaces` (v1).

### Total entries count (versions `Optimized_CRC32` and later)

| field | offset | size | endian | type | semantics |
|-------|--------|------|--------|------|-----------|
| `EntriesCount` | 25 | 4 | LE | `u32` | Total `(namespace, key)` entries across all namespaces. Reference parsers skip this field; it is a sanity-check value the cooker emits but the runtime doesn't validate. Parsers MAY validate `EntriesCount == sum(NumKeys[i] for i in namespaces)` as a structural-integrity check after parsing the full namespace table. |

### Namespace table

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumNamespaces` | 4 | LE | `u32` | Number of namespaces. |
| `Namespaces` | variable | — | `FNamespaceEntry[]` | Per-namespace records, concatenated. |

Each `FNamespaceEntry`:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NamespaceHash` | 4 | LE | `u32` | Hash of the namespace string. **Present only for v2 and v3.** Algorithm per version (CRC32 for v2; CityHash64-of-UTF16 low 32 bits for v3). |
| `Namespace` | variable | — | `FString` | Namespace name (e.g. `"Game"`, `"UI"`, `"DialogueLines"`). Cookers may emit the empty string (`""`) as a namespace name; this is valid. |
| `NumKeys` | 4 | LE | `u32` | Number of `(key, entry)` pairs in this namespace. |
| `Entries` | variable | — | `FKeyEntry[]` | Per-key records, concatenated. |

Each `FKeyEntry` (table below applies to Compact (v1) and later;
see "Legacy (v0) layout" further down for v0's distinct shape):

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `KeyHash` | 4 | LE | `u32` | Hash of the key string. **Present only for v2 and v3** — same algorithm as `NamespaceHash`. |
| `Key` | variable | — | `FString` | Key name (e.g. `"5DD42A4E4B5C7F8A_Continue"`). |
| `SourceStringHash` | 4 | LE | `u32` | Cooker-side hash of the source string for change-detection. Present in **all** versions (v0/v1/v2/v3) — the oracle reads it unconditionally. Algorithm is **not** verifiable against CUE4Parse — the oracle never computes or validates any `.locres` hash, in any version, so the wire byte is read and carried opaquely. (UE itself computes `SourceStringHash` via `FCrc::StrCrc32` in all versions; the v2→v3 CityHash64 switch documented for `NamespaceHash`/`KeyHash` applies to the `FTextKey` pre-hashes only, not `SourceStringHash`. Paksmith stores all three hashes uninterpreted and validates none of them.) |
| `StringIndex` | 4 | LE | `i32` | Index into the strings array. **Present only for `Compact` (v1) and later.** Legacy (v0) reads an inline `FString` here instead. On v1+, the source string is `strings_array[StringIndex]`. |

> **Cursor-misalignment trap:** A reader that gates hash-field reads on `>= Compact` instead of `>= Optimized_CRC32` will misalign its read cursor on every key/namespace entry in v1 (Compact) files. The gating must match the wire-table row condition exactly: hashes are v2+, not v1+.

### Legacy (v0) layout

Legacy files start at offset 0 with no magic or version byte:

| field | size | endian | type | semantics |
|-------|------|--------|------|-----------|
| `NumNamespaces` | 4 | LE | `u32` | Number of namespaces. |
| `Namespaces` | variable | — | Legacy `FNamespaceEntry[]` | No `NamespaceHash`, no `KeyHash`. Each `FKeyEntry` reads an inline `FString` for the localized string instead of a `StringIndex` — i.e., layout is `Key: FString`, `SourceStringHash: u32`, `LocalizedString: FString`. |

Detection: read 16 bytes at offset 0; if they don't match the magic
`FGuid`, seek back to 0 and parse as Legacy.

### Worked example

The file `tests/fixtures/data/sample_v2.locres` (124 bytes) holds a
hand-crafted v2 `.locres` with one namespace (`"Game"`) and two
key/string pairs (`key1 → "Hello"`, `key2 → "World"`). Generator:
`tools/gen-locres-fixture.py` (pure-Python, `zlib.crc32` for hashes).

Full hex dump:

```
$ xxd tests/fixtures/data/sample_v2.locres
00000000: 0e14 7475 674a 03fc 4a15 909d c337 7f1b  ..tugJ..J....7..
00000010: 025c 0000 0000 0000 0002 0000 0001 0000  .\..............
00000020: 005e 7814 5405 0000 0047 616d 6500 0200  .^x.T....Game...
00000030: 0000 c915 f060 0500 0000 6b65 7931 000f  .....`....key1..
00000040: 714f 1a00 0000 000a 46dd 4b05 0000 006b  qO......F.K....k
00000050: 6579 3200 820d 0287 0100 0000 0200 0000  ey2.............
00000060: 0600 0000 4865 6c6c 6f00 0100 0000 0600  ....Hello.......
00000070: 0000 576f 726c 6400 0100 0000            ..World.....
```

Byte-by-byte walk:

| offset | bytes | field | value |
|--------|-------|-------|-------|
| 0–15 | `0E 14 74 75 67 4A 03 FC 4A 15 90 9D C3 37 7F 1B` | `magic` | `FGuid{0x7574140E, 0xFC034A67, 0x9D90154A, 0x1B7F37C3}` ✓ |
| 16 | `02` | `version` | `Optimized_CRC32` (v2) |
| 17–24 | `5C 00 00 00 00 00 00 00` | `StringsArrayOffset` | `0x5C = 92` (the strings array starts at byte 92) |
| 25–28 | `02 00 00 00` | `EntriesCount` | `2` — matches `sum(NumKeys) = 2` |
| 29–32 | `01 00 00 00` | `NumNamespaces` | `1` |
| 33–36 | `5E 78 14 54` | `NamespaceHash` | `0x5414785E` = `crc32(b"G\0a\0m\0e\0")` |
| 37–40 | `05 00 00 00` | `Namespace` len | `5` (`FString` length = char count + 1 for null) |
| 41–45 | `47 61 6D 65 00` | `Namespace` bytes | `"Game\0"` |
| 46–49 | `02 00 00 00` | `NumKeys` | `2` |
| 50–53 | `C9 15 F0 60` | `KeyHash` #0 | `0x60F015C9` = `crc32(b"k\0e\0y\0\x31\0")` for `"key1"` |
| 54–57 | `05 00 00 00` | `Key` #0 len | `5` |
| 58–62 | `6B 65 79 31 00` | `Key` #0 bytes | `"key1\0"` |
| 63–66 | `0F 71 4F 1A` | `SourceStringHash` #0 | `0x1A4F710F` = `crc32(b"H\0e\0l\0l\0o\0")` for `"Hello"` |
| 67–70 | `00 00 00 00` | `StringIndex` #0 | `0` → `strings_array[0] = "Hello"` |
| 71–74 | `0A 46 DD 4B` | `KeyHash` #1 | `0x4BDD460A` = `crc32(b"k\0e\0y\0\x32\0")` for `"key2"` |
| 75–78 | `05 00 00 00` | `Key` #1 len | `5` |
| 79–83 | `6B 65 79 32 00` | `Key` #1 bytes | `"key2\0"` |
| 84–87 | `82 0D 02 87` | `SourceStringHash` #1 | `0x87020D82` = `crc32(b"W\0o\0r\0l\0d\0")` for `"World"` |
| 88–91 | `01 00 00 00` | `StringIndex` #1 | `1` → `strings_array[1] = "World"` |
| 92–95 | `02 00 00 00` | `NumStrings` | `2` |
| 96–99 | `06 00 00 00` | `Strings[0]` len | `6` (5 chars + null) |
| 100–105 | `48 65 6C 6C 6F 00` | `Strings[0]` bytes | `"Hello\0"` |
| 106–109 | `01 00 00 00` | `Strings[0]` `RefCount` | `1` |
| 110–113 | `06 00 00 00` | `Strings[1]` len | `6` |
| 114–119 | `57 6F 72 6C 64 00` | `Strings[1]` bytes | `"World\0"` |
| 120–123 | `01 00 00 00` | `Strings[1]` `RefCount` | `1` |

Final decoded content:

```
Namespace "Game"
├─ key1 → "Hello"  (refcount 1)
└─ key2 → "World"  (refcount 1)
```

The hash values in the file are byte-for-byte reproducible with
`zlib.crc32(s.encode("utf-16-le"))` for any modern Python 3 — see
`tools/gen-locres-fixture.py` for the generator.

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

The wire format is identical across cultures; only the source-string
content differs. Extractor tools should expose per-culture
extraction so users can dump a single language without parsing
every locale's file.

## Caps & limits

### Format-defined limits (wire-imposed)

These are bounds the wire format itself imposes, independent of any
specific parser's hardening strategy:

- `NumNamespaces`, `NumKeys`, `NumStrings`, `EntriesCount`,
  `NamespaceHash`, `KeyHash`, `SourceStringHash` are all 4-byte
  fields, so each is bounded by `u32::MAX = 4_294_967_295` (or
  `i32::MAX = 2_147_483_647` for the signed `NumStrings` /
  `StringIndex`).
- `StringIndex` is `i32`, so the strings array can hold at most
  `2_147_483_647` entries.
- `StringsArrayOffset` is `i64`, so files larger than `i64::MAX`
  bytes cannot encode a strings-array offset. (No realistic
  `.locres` approaches this; included for completeness.)
- `FString` length is `i32`, bounded by `i32::MAX` characters
  (signed because UE uses negative length to signal UTF-16
  encoding — see [`../primitive/fstring.md`](../primitive/fstring.md)).
- Strings stored in `Strings[]` are deduplicated by exact byte
  equality — cookers do not perform Unicode normalization or
  case-folding when deduplicating.

### Implementation hardening (recommended for any parser)

These are not part of the wire format spec — they are reader-side
defensive measures that a robust parser SHOULD enforce regardless
of which language or runtime it's built in. Failures here are
parser bugs / DoS vectors, not format-spec violations.

- **Unknown version rejection.** When the first 16 bytes match the
  magic `FGuid`, `versionByte` MUST be in `{1, 2, 3}`. Values
  outside this range MUST be rejected — continuing past an unknown
  version causes cursor misalignment because per-version field
  layouts differ (e.g., hash fields absent in v1 but present in
  v2+). The reference oracle throws `ParserException` on
  `versionByte > 3`. Value `0` after a magic match is contradictory
  (Legacy has no magic prefix); the oracle does NOT reject it (it
  parses a legacy body from offset 17, almost certainly garbage) but
  paksmith fails closed on it — a deliberate divergence. This is
  parser correctness, not a style preference.
- **`StringsArrayOffset` bounds-check (two-stage).** When
  `StringsArrayOffset != -1`, the value MUST satisfy `25 <=
  StringsArrayOffset < file_size`. Offsets `[17, 24]` ARE the
  field's own bytes — a seek there would re-read the offset field
  as `NumStrings`. A negative non-(-1) offset is a sign-extension
  hazard on seek. A very large positive offset causes hang on
  sparse read or silent truncation reading garbage. **Important:
  the `>= 25` lower bound is necessary but NOT sufficient.**
  Offsets in `[25, end-of-namespace-table)` overlap the namespace
  table, which the parser hasn't read yet. The seek-and-return
  mechanic prevents cursor desync (the parser comes back to
  position 25 for the namespace table regardless), but the
  *strings array contents* will be read from namespace-table bytes
  interpreted as a sequence of `(FString, RefCount)` — producing
  arbitrary attacker-controlled "strings" that the parser will
  faithfully return to its caller. The parser MUST perform a
  two-stage check: stage 1 is the cheap `>= 25` lower bound, which
  is sufficient to permit the seek-and-return mechanic; stage 2,
  AFTER the namespace table is fully parsed, MUST verify
  `StringsArrayOffset >= end_of_namespace_table_position` and
  reject the file otherwise. Stage 2 is not optional — without it,
  the strings payload is attacker-controlled.
- **Signed count fields cast safely.** `NumStrings` (`i32`),
  `StringIndex` (`i32`), and all `FString` length fields are
  signed. A reader that casts a negative value directly to an
  unsigned integer (Rust `as usize`, C `(size_t)`) produces values
  near `usize::MAX` and causes immediate OOM on allocation. Always
  validate `>= 0` before any allocation arithmetic.
- **`NumNamespaces` / `NumKeys` / `NumStrings` upper bounds.** All
  three are direct allocation drivers; a `u32::MAX` or
  `i32::MAX` value will OOM any naïve `Vec::with_capacity(count)`
  call before reading entries. A conservative parser-side cap of
  `2^20 = 1_048_576` per field comfortably exceeds any production
  `.locres` while bounding the worst-case allocation request.
- **Per-`FString` length cap.** Each `FString`'s length prefix is an
  independent allocation driver (the `Vec<u16>` / `String` for one
  namespace/key/localized string). Paksmith caps it at
  `65_536` code units/bytes (matching the pak index reader's
  `FSTRING_MAX_LEN`) BEFORE allocating — bounding the per-string
  allocation independently of the surrounding file size.
- **`StringIndex` bounds-check.** Each `StringIndex` MUST be
  validated as `0 <= idx < NumStrings` before indexing. The oracle's
  own check is **upper-bound only** (`NumStrings > idx`): a NEGATIVE
  index passes it and then throws an uncaught `IndexOutOfRangeException`
  (a crash), while an over-range index is warned and left untranslated.
  Paksmith fails closed on **both** sides
  (`LocresParseFault::StringIndexOutOfRange`) — it does not port the
  oracle's negative-index crash, and it does not attempt any fallback
  `FString` read (a fallback would corrupt the read position).
- **`StringsArrayOffset == -1` + non-(-1) `StringIndex`.** When
  the strings array is absent, all `StringIndex` references MUST be
  treated as invalid (effectively empty array). Do not attempt to
  dereference a `StringIndex` against an empty array.
- **`RefCount` is informational — parsers MUST NOT iterate based
  on its value.** `RefCount` is an `i32` recorded per strings-array
  entry to track how many `(namespace, key)` entries reference each
  unique source string. A reader's role is to surface the source
  string, not enforce reference accounting. A hostile or corrupt
  file can set `RefCount` to a negative value or to `i32::MAX`; a
  parser that loops `RefCount` times for any reason hangs or OOMs.
  Read the field for round-trip fidelity if needed; do not use it
  as a loop bound.
- **Hash validation.** Per oracle, the runtime does NOT validate
  `NamespaceHash`, `KeyHash`, or `SourceStringHash` against the
  corresponding string content. A robust parser SHOULD compute the
  expected hash and log mismatches as corruption-detection
  signals — but MUST NOT fail-close on mismatch (cooker bugs and
  legitimate platform-encoding variations have produced mismatches
  in shipped content). Do not use the stored hash for lookup,
  dispatch, deduplication, or cache-key logic — always rehash the
  string content directly.

## Verification

- **Fixture:** `tests/fixtures/data/sample_v2.locres` — 124-byte
  hand-crafted v2 file (one namespace, two keys, two unique
  source strings). Generator: `tools/gen-locres-fixture.py`. The
  fixture exercises every v2 wire field except the
  `StringsArrayOffset == -1` and Legacy-fallback paths.
- **Hex anchor commands:**
  ```
  # Whole file (124 bytes):
  xxd tests/fixtures/data/sample_v2.locres

  # Magic FGuid (first 16 bytes):
  xxd -l 16 tests/fixtures/data/sample_v2.locres

  # Version byte + StringsArrayOffset (offset 16, 9 bytes):
  xxd -s 16 -l 9 tests/fixtures/data/sample_v2.locres

  # Strings array (offset 92, 32 bytes):
  xxd -s 92 -l 32 tests/fixtures/data/sample_v2.locres
  ```
- **Cross-validation oracle:** CUE4Parse[^1]. The format is fully
  public; no proprietary-codec concerns.
- **Known divergences:** the `StellarBlade` and `HonorofKingsWorld`
  game-specific carve-outs in `FTextLocalizationResource.cs` add
  game-version-specific bytes after `StringIndex` and a different
  table shape for super-recent (`> Latest`) versions, respectively.
  These are game-profile concerns out of scope for general-purpose
  `.locres` parsing.

## Paksmith implementation

**Parser module:** `crates/paksmith-core/src/localization/locres.rs`
(#646). Lives outside `crates/paksmith-core/src/asset/` because
`.locres` is not a UObject package. Exported to CSV/JSON by
`crates/paksmith-core/src/export/locres.rs`; the CLI `extract`
command converts `.locres` entries (`--locres-format csv|json`).

**Parser status:** `complete`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/Localization/FTextLocalizationResource.cs@cf74fc32fe1b40e9fd3440032508c5e1d50cf58d` — primary oracle. Covers all four versions, the magic FGuid, the seek-and-return strings-array pattern, the version dispatch, and the per-version hash-algorithm choice. Supporting types: `ELocResVersion` in `UE4/Objects/Core/i18N/ELocResVersion.cs`, `FTextKey` in `UE4/Objects/Core/i18N/FTextKey.cs`, `FEntry` in `UE4/Objects/Core/i18N/FEntry.cs`, `FTextLocalizationResourceString` in `UE4/Objects/Core/i18N/FTextLocalizationResourceString.cs`.

[^2]: Google CityHash reference — the 2011 publication
(`https://github.com/google/cityhash`). v3 uses `CityHash64`
(NOT `CityHash64WithSeed`) of the UTF-16-LE-encoded string,
low 32 bits. Pure-Rust implementations include the `cityhasher`
crate. Implementations matching the reference C++ produce
byte-identical hashes.

[^3]: CRC-32/IEEE polynomial reference — the standard zlib /
PNG / Ethernet polynomial (`0xEDB88320` reversed). v2 uses
this CRC over the UTF-16-LE byte representation. Python's
`zlib.crc32` and Rust's `crc32fast` crate match.
