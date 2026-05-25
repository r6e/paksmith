# Unversioned property serialization

> UE5 schema-driven property serialization — properties encoded as a
> compact bitstream of "which fields are present" + raw bodies, with
> the field schema living in a sibling `.usmap` mapping file.

## Overview

UE5 cooked shipping builds may opt into **unversioned** property
serialization (via the `PKG_UnversionedProperties = 0x2000` package
flag) instead of the tagged scheme (see [`tagged.md`](tagged.md)).
In unversioned mode, each export body is a sequence of `u16`
fragments forming an `FUnversionedHeader` — each fragment encoding
`(skip_count, value_count, has_zeros, is_last)` — optionally followed
by a zero-mask byte run, then raw per-property bodies in
schema-declared order. The reader needs the class schema to know each
body's wire shape; the schema is not embedded in the asset itself but
in a sibling `.usmap` file produced by an engine commandlet.

The `PKG_UnversionedProperties` flag is package-scoped: either all
exports in a package use unversioned serialization, or none do. There
is no per-export opt-in.

**Document status: complete.** Wire format documented in full against
CUE4Parse[^1] with a worked example below covering a minimal 1-fragment
header + 2-property body. The full `.usmap` file format is also
documented exhaustively.

**Paksmith parser status: `partial`.** The `.usmap` loader
(`crates/paksmith-core/src/asset/mappings.rs`) and the unversioned
bitstream decoder
(`crates/paksmith-core/src/asset/property/unversioned.rs`) are both
implemented and exercised by integration tests. Known gaps: Map,
Set, Delegate, Interface, and FieldPath property types trigger
`UnversionedTypeNotSupported` and stop the property walk; Oodle
`.usmap` compression is unsupported.

When a caller supplies no `.usmap` and the asset has
`PKG_UnversionedProperties` set, the parser returns
`AssetParseFault::UnversionedWithoutMappings` rather than
silently mis-decoding the property stream as tagged bytes.

## Versions

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| `EUsmapVersion::Initial` (byte 0) | Baseline: `u8` name lengths, `u8` enum value counts, positional enum ordinals. | `FabianFG/CUE4Parse/CUE4Parse/MappingsProvider/Usmap/UsmapParser.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |
| `EUsmapVersion::PackageVersioning` (byte 1) | Adds an optional versioning block (object version, custom version array, netCL) before the compression header. | Same[^1] |
| `EUsmapVersion::LongFName` (byte 2) | Widens name-table entry length field from `u8` to `u16` (needed for names > 255 bytes). | Same[^1] |
| `EUsmapVersion::LargeEnums` (byte 3) | Widens per-enum value count from `u8` to `u16`. | Same[^1] |
| `EUsmapVersion::ExplicitEnumValues` (byte 4, latest) | Enum entries carry explicit `u64` ordinals instead of positional indices. Supports sparse enums (`A = 0, C = 2`). | Same[^1] |

## Wire layout

### Fragment header (`FUnversionedHeader`)

Each export's property stream opens with a run of `u16` fragments
(little-endian). All bit fields are extracted from each `u16`:

| bits | mask | field | semantics |
|------|------|-------|-----------|
| 6:0 | `0x007f` | `skip_num` | Number of schema slots to skip before this fragment's values. |
| 7 | `0x0080` | `has_zeros` | If set, some slots in this fragment may be zero/default and are recorded in the zero-mask. |
| 8 | `0x0100` | `is_last` | If set, this is the final fragment; the header ends here. |
| 15:9 | `0xfe00` (shift 9) | `value_num` | Number of schema slots that have serialised (non-skip) values in this fragment. |

The reader accumulates a running `cumulative_first: u16` cursor to
compute each fragment's `first_num` (the absolute schema-slot index
of the fragment's first value):

```
first_num = cumulative_first + skip_num
cumulative_first += skip_num + value_num
```

Reading continues until `is_last = 1`. The wire format does not
bound the fragment count itself; an implementation cap belongs in
§*Implementation hardening* (see `MAX_FRAGMENTS_PER_HEADER` and the
accumulator-saturation rows in the table).

### Zero-mask byte run

Immediately after the last fragment, if any fragment had `has_zeros`
set, a byte run encodes which slots within those fragments hold
zero/default values (emitting no body). The run length depends on the
total count of value slots across all `has_zeros` fragments
(`total_zero_count`):

| `total_zero_count` | run length |
|--------------------|------------|
| 1–8 | 1 byte |
| 9–16 | 2 bytes |
| 17+ | `div_ceil(total_zero_count, 32) × 4` bytes (rounded to 4-byte words) |

Bit ordering is Lsb0 across the run: bit 0 of byte 0 corresponds to
the first value slot in the first `has_zeros` fragment. A `0` bit
means the value IS serialised (body present); a `1` bit means the
value is zero/default (no body). This inversion is a UE engine
convention.

`total_zero_count` accumulates the per-fragment value counts across
`has_zeros` fragments and bounds the byte run length per the table
above. The wire format does not bound this accumulator; saturation
semantics for the reader are documented in §*Implementation
hardening*.

### Per-property bodies

After the header + zero-mask, raw property values follow in
schema-declared order. The reader iterates the class's schema (from
the `.usmap`) sorted by `schema_index`, skips slots not marked
serialised by the header, and reads each present slot as a type-sized
payload — no name, no type tag, no body-size field.

The `schema_index` in the `.usmap` is the wire-declared absolute slot
index (not the property's position in the file). The header's
fragments address these same indices. Using the wire-declared value
preserves correctness when a schema has gaps (transient, editor-only,
or deprecated properties that occupy schema slots but are absent from
`serializablePropertyCount`).

#### Type wire widths

| `EPropertyType` byte | Rust variant | Wire size |
|----------------------|--------------|-----------|
| 0 (`ByteProperty`) | `UInt8` | 1 byte |
| 1 (`BoolProperty`) | `Bool` | 1 byte (non-zero = true) |
| 2 (`IntProperty`) | `Int32` | 4 bytes LE |
| 3 (`FloatProperty`) | `Float` | 4 bytes LE |
| 4 (`ObjectProperty`) | `Object` | 4 bytes LE (`i32` package index) |
| 5 (`NameProperty`) | `Name` | 8 bytes ([`FName`](../primitive/fname.md): `i32` index + `i32` number) |
| 7 (`DoubleProperty`) | `Double` | 8 bytes LE |
| 8 (`ArrayProperty`) | `Array` | `i32` element count LE + `count` element bodies |
| 9 (`StructProperty`) | `Struct` | nested `FUnversionedHeader` + bodies for the struct's schema |
| 10 (`StrProperty`) | `Str` | [`FString`](../primitive/fstring.md) (4-byte length prefix + UTF-8/UTF-16 bytes) |
| 11 (`TextProperty`) | `Text` | `FText` (see [`text.md`](text.md)) |
| 17 (`SoftObjectProperty`) | `SoftObjectPath` | [`FName`](../primitive/fname.md) (8 bytes) + [`FString`](../primitive/fstring.md) |
| 18 (`UInt64Property`) | `UInt64` | 8 bytes LE |
| 19 (`UInt32Property`) | `UInt32` | 4 bytes LE |
| 20 (`UInt16Property`) | `UInt16` | 2 bytes LE |
| 21 (`Int64Property`) | `Int64` | 8 bytes LE |
| 22 (`Int16Property`) | `Int16` | 2 bytes LE |
| 23 (`Int8Property`) | `Int8` | 1 byte |
| 26 (`EnumProperty`) | `Enum` | 1 byte (`u8` ordinal; resolved via `.usmap` enum table) |
| 6, 12–16, 24–25, 27 | `Unknown(byte)` | not decoded — triggers `UnversionedTypeNotSupported` |

### Worked example — minimal export body (1-fragment, no zeros, 2 properties)

Suppose a class schema with 2 properties:
- Slot 0: `Value: IntProperty`
- Slot 1: `Enabled: BoolProperty`

The export body serializes both slots, neither is zero/default,
both have values:
- `Value = 42`
- `Enabled = true`

**Fragment header (1 `u16`, LE):**

```
Bits      Field         Value
--------  ------------  -----
6:0       skip_num      0       (skip no slots before first value)
7         has_zeros     0       (no zero-mask bytes follow)
8         is_last       1       (only fragment)
15:9      value_num     2       (2 slot values follow)
```

Packed: `(2 << 9) | (1 << 8) | (0 << 7) | 0 = 0x0500`. Wire LE bytes:
`00 05`.

**Per-property bodies (no zero-mask since `has_zeros == 0`):**

```
Offset  Bytes (LE)              Field
------  ----------------------  ---------------------
+0      00 05                   Fragment header (u16): skip=0, is_last=1, value_num=2
+2      2A 00 00 00             Slot 0 (Value: IntProperty) = 42 (i32 LE)
+6      01                      Slot 1 (Enabled: BoolProperty) = true (u8 non-zero)
+7                               (end of body — 7 bytes total)
```

The reader logic for this 7-byte stream:

1. Read `u16 = 0x0500`. Extract: `skip_num=0`, `has_zeros=0`,
   `is_last=1`, `value_num=2`.
2. `cumulative_first = 0`; `first_num = 0 + 0 = 0`. Fragment covers
   slots `[0, 2)` (i.e., slots 0 and 1, both serialized).
3. `is_last=1` → header done.
4. No zero-mask bytes (no fragment had `has_zeros=1`).
5. Iterate schema: slot 0 (`Value`, IntProperty) → read 4 bytes (`2A 00 00 00`) → 42.
6. Slot 1 (`Enabled`, BoolProperty) → read 1 byte (`01`) → true.

**Worked example variant — with zero-mask:**

If `Enabled` were `false` (zero-default), the fragment would set
`has_zeros=1` (`u16 = 0x0580`), then a single zero-mask byte would
follow: bit 0 = 0 (Value is serialized), bit 1 = 1 (Enabled is
zero-default → no body). Body becomes 2 bytes for the fragment
header (`00 05` → `80 05`) + 1 zero-mask byte (`02`) + 4 bytes for
`Value` + 0 bytes for the zero-defaulted `Enabled` = 7 bytes total.
The reader fills `Enabled` with the type's default (false for
`BoolProperty`).

### `.usmap` file format

A `.usmap` file is a compressed binary blob. The outer header is
always uncompressed:

| field | size | type | semantics |
|-------|------|------|-----------|
| magic | 2 | `u16` LE | Must equal `0x30C4` (on-disk bytes `C4 30`). |
| version | 1 | `u8` | `EUsmapVersion` discriminant (0–4; see Versions table). |
| [versioning block] | variable | — | Present iff `version ≥ 1` AND next byte is non-zero. Reads: `has_versioning u8`, then if set: `object_version i32`, `object_version_ue5 i32`, `custom_version_count u32`, `custom_version_count × 20` bytes (GUID + i32), `net_cl u32`. |
| compression | 1 | `u8` | `0` = None, `1` = Oodle (unsupported), `2` = Brotli, `3` = ZStandard. |
| compressed_size | 4 | `u32` LE | Byte count of the compressed payload. Capped at `MAX_USMAP_COMPRESSED_SIZE = 64 MiB`. |
| decompressed_size | 4 | `u32` LE | Expected decompressed byte count. Capped at `MAX_USMAP_DECOMPRESSED_SIZE = 256 MiB`. |
| [payload] | `compressed_size` | bytes | Compressed schema data. |

After decompression, the schema data is parsed as:

1. **Name table** — `u32` name count, then per entry: name length (`u8` for version < 2, `u16` for version ≥ 2) + that many UTF-8 bytes (no null terminator).
2. **Enum table** — `u32` enum count (capped at `MAX_USMAP_ENUM_COUNT = 4096`), then per enum: name-table index (`i32`) + value count (`u8` for version < 3, `u16` for version ≥ 3; capped at `MAX_USMAP_VALUES_PER_ENUM = 1024`) + per value: for version ≥ 4 an explicit `u64` ordinal then a name-table index, otherwise just a name-table index (ordinal = positional index).
3. **Schema table** — `u32` schema count, then per schema: name index, super-type name index (the sentinel `"None"` means no superclass), `prop_count u16` (total slots including gaps), `serial_count u16` (serializable slot count), then `serial_count` property entries. Each entry: `schema_index u16`, `array_size u8`, name index (`i32`), type byte (recursively decoded).

## Variants

Variance has two axes, both documented above. (1) `.usmap`-version
gates — the EUsmapVersion byte controls name-length widths (u8→u16 at
v2), enum-count widths (u8→u16 at v3), and enum-ordinal encoding
(positional vs explicit u64 at v4) per the Versions table and Wire
layout §*.usmap file format*. (2) Per-file compression — None /
Brotli / ZStandard, with Oodle rejected, selected by the compression
byte in the `.usmap` header. The unversioned property bitstream
format itself has no version discriminant.

## Caps & limits

### Format-defined limits (wire-imposed)

- **Fragment field widths**: `skip_num` is 7 bits (max 127),
  `value_num` is 7 bits (max 127). Per-fragment a maximum of
  127 + 127 = 254 schema slots are touched.
- **`.usmap` discriminant** (`EUsmapVersion`): wire-imposed range
  `0..=4` (5 variants documented). Future versions extend this; a
  reader gates compatibility on the value.
- **`.usmap` compression byte**: `0..=3` (None / Oodle / Brotli /
  ZStandard). Other values are wire-imposed-invalid.

The wire format does NOT embed an explicit cap on fragment count,
`cumulative_first`, or `total_zero_count` — the only implicit
arithmetic bound comes from the 7-bit per-fragment field widths
(254 slots/fragment maximum) listed above. Reader-side ceilings on
the accumulators are parser-side concerns; see §*Implementation
hardening*.

### Implementation hardening (recommended for any parser)

| Constant | Value | Guards |
|----------|-------|--------|
| `MAX_FRAGMENTS_PER_HEADER` | 65535 (`u16::MAX`) | Prevents unbounded `Vec` growth from an adversarial `is_last=0` fragment stream. Implementations SHOULD enforce a tighter cap if profiling reveals real assets never exceed a few hundred fragments. |
| `MAX_USMAP_COMPRESSED_SIZE` | 64 MiB | Bounds pre-decompression allocation from a malicious size claim. |
| `MAX_USMAP_DECOMPRESSED_SIZE` | 256 MiB | Prevents decompression bombs from exhausting memory. |
| `MAX_USMAP_ENUM_COUNT` | 4096 | Bounds the enum-table `HashMap` heap cost per `.usmap`. |
| `MAX_USMAP_VALUES_PER_ENUM` | 1024 | Bounds per-enum `HashMap` heap cost. |
| `MAX_INHERITANCE_DEPTH` | 64 | Breaks cyclic `super_type` chains in `.usmap`; a malicious cycle would otherwise loop forever in `get_all_properties`. |
| `MAX_PROPERTY_DEPTH` | 128 | Shared with the tagged path; prevents stack overflow from adversarial `Struct<Struct<...>>` or `Array<Array<...>>` nesting. |
| `cumulative_first` saturation | `u16::MAX` | Reader MUST accumulate via `saturating_add(skip_num + value_num)`. Adversarial input could otherwise overflow `u16` after roughly `65_535 / 254 ≈ 258` fragments — plain wrapping arithmetic would re-address slot 0 and silently corrupt the property tree. After saturation, a reader SHOULD treat any further schema-slot lookups as not-serialised (default-skip), since the saturated cursor sits beyond every legitimate schema slot index. |
| `total_zero_count` saturation | `u16::MAX` | Reader MUST also use saturating accumulation. After saturation, out-of-range zero-mask lookups (bits past the parsed buffer) SHOULD default to "zero/default" (i.e. body absent — cursor stays parked), NOT "serialised". Defaulting to "serialised" would attempt a body read from a truncated zero-mask region; defaulting to "default-skip" leaves the cursor undisturbed and lets the next legitimate property tag align. |

Additional implementation hardening notes:

- **`.usmap` magic MUST be validated** as `0x30C4` (bytes `C4 30`).
  A reader that proceeds without magic validation can interpret an
  unrelated file's bytes as a usmap header.
- **Decompressed size MUST match the header's stated value.** A
  decompressor that returns more or fewer bytes than declared
  indicates corruption or a decompression-bomb attempt; reject.
- **Cyclic `super_type` chains MUST be detected.** A schema whose
  super-type chain `A → B → C → A` would loop indefinitely in
  `get_all_properties` without depth bounding. Paksmith uses
  `MAX_INHERITANCE_DEPTH = 64` as the safety net.
- **Unknown property type bytes MUST stop the property walk.** A
  reader that silently skips an unknown type byte loses cursor
  position because unversioned bodies have no per-property size
  field. Paksmith surfaces this as
  `AssetParseFault::UnversionedTypeNotSupported { type_byte,
  property_name }` and stops the walk; the partial property tree
  collected up to that point is returned.

The `MAX_FRAGMENTS_PER_HEADER` cap has a test-only accessor
`max_fragments_per_header()` (behind `__test_utils`) so integration
tests can read the live value without duplicating the literal.

## Verification

- **Fixture:** `tests/fixtures/` — integration tests in
  `paksmith-core-tests` exercise the `.usmap` loader and the
  unversioned decoder against synthetic byte fixtures
  (`crates/paksmith-core/src/testing/usmap.rs`). The Worked example
  above is byte-exact and self-contained for the simple 2-property
  case; larger schemas extend the same pattern with additional
  fragments and (optionally) zero-mask bytes.
- **Hex anchor commands:**
  ```
  # Synthesize the 7-byte Worked example body (1 fragment, 2 slots,
  # Value=42, Enabled=true):
  printf '\x00\x05\x2A\x00\x00\x00\x01' | xxd
  # Synthesize the zero-mask variant (1 fragment, has_zeros=1,
  # zero-mask byte, Value=42, Enabled=default-false):
  printf '\x80\x05\x02\x2A\x00\x00\x00' | xxd
  ```
  Any conformant parser fed these byte sequences MUST decode them
  as the property maps described in the Worked example.
- **Cross-validation oracle:** CUE4Parse[^1] (primary) and `unreal_asset`[^2].
- **Known divergences:**
  - Map (`24`), Set (`25`), Delegate (`6`), Interface (`12`/`13`), MulticastDelegate (same), WeakObject (`14`), LazyObject (`15`), AssetObject (`16`), and FieldPath (`27`) are decoded as `Unknown(byte)`, triggering `UnversionedTypeNotSupported`. The decoder stops the property walk at the first unsupported slot and returns the partial tree collected up to that point.

## Paksmith implementation

**Parser modules:**
- `crates/paksmith-core/src/asset/property/unversioned.rs` — `UnversionedHeader::read`, `read_unversioned_properties`, `read_unversioned_value`. Bit masks cross-referenced against `unreal_asset_base::unversioned::header::UnversionedHeaderFragment`.
- `crates/paksmith-core/src/asset/mappings.rs` — `Usmap::from_bytes`, `Usmap::parse_schema_data`, `Usmap::get_all_properties`. Wire format cross-referenced against CUE4Parse's `UsmapParser.cs`.

**Dispatch point:** `Package::read_from` (in `crates/paksmith-core/src/asset/package.rs`) checks `summary.package_flags & PKG_UNVERSIONED_PROPERTIES`. If set and a `Usmap` was supplied, it routes each export through `read_unversioned_properties`; if set and no `Usmap` was supplied, it returns `AssetParseFault::UnversionedWithoutMappings`.

**Status:** `partial`. Properties whose types are not yet supported return `AssetParseFault::UnversionedTypeNotSupported { type_byte, property_name }`; the decoder stops the walk and returns the partial `Vec<Property>` at the outermost export frame.

**Phase plan:** `docs/plans/phase-2f-unversioned-properties.md`.

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/MappingsProvider/Usmap/UsmapParser.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the `.usmap` wire format and `EUsmapVersion` discriminants. `FabianFG/CUE4Parse/CUE4Parse/UE4/Assets/Objects/Unversioned/FUnversionedHeader.cs@ecc4878950336126f125af0747190edf474b2a21` — primary oracle for the fragment-header bitstream.
[^2]: `AstroTechies/unrealmodding/unreal_asset/unreal_asset_base/src/unversioned/header.rs@f4df5d8e75b1e184832384d1865f0b696b90a614` — Rust oracle; bit-mask constants cross-referenced against `UnversionedHeaderFragment`. The `EPropertyType` discriminant table is pinned at the same SHA.
