# Zstd decompression

> Per-block codec for Zstd-compressed pak entries: each compression
> block holds one or more whole **Zstandard frames** (RFC 8878), v1
> frames or skippable frames, with nothing after the last. The method
> name `Zstd` is resolvable only in v8+ archives, through the footer's
> FName compression-slot table.

## Overview

The block *framing* (how an entry's payload is split into
`FPakCompressedBlock` regions) is method-agnostic and documented in
[`pak-block-framing.md`](pak-block-framing.md); this doc covers what
lives inside each block when the entry's compression method resolves
to `Zstd`.

Zstandard data is made up of one or more frames, each of which can be
decompressed independently of the others (RFC 8878 §3.1).[^1] A pak
Zstd block is such a sequence: its frames decode, in order, to the
block's output. A frame need not record its decoded size; the reader
takes each block's expected output from the entry header, as for
[LZ4](lz4.md): every block but the last decodes to exactly
`compression_block_size` bytes, and the last to the rest of
`uncompressed_size`.

repak, the writer behind paksmith's Zstd fixtures, cuts an entry into
blocks of `0x3e << 11` (126976) bytes and compresses each with
`zstd::stream::encode_all(chunk, 0)`, level 0 being libzstd's default
level,[^4] so each block is one v1 frame.[^2] The frames in those fixtures record
no `Frame_Content_Size` and no `Content_Checksum` (see the worked
example). No UE-written Zstd pak is in paksmith's corpus, and this doc
does not describe UE's writer.

On the read side, CUE4Parse decodes a Zstd block with ZstdSharp's
`ZSTD_decompress` into a destination the size of the block's expected
output, and fails the block unless the output fills it.[^3]

## Versions

| UE version range | Wire-format change | Source |
|------------------|--------------------|--------|
| Wire version 8+ | Zstd resolvable. From v8 the compression method is a 1-based index into the footer's FName compression-slot table (32-byte name slots); repak writes the name `Zstd`, which paksmith matches case-insensitively (`CompressionMethod::from_name`). The v3-v7 numeric method IDs paksmith recognizes are `Zlib=1`, `Gzip=2`, `Oodle=4` (`CompressionMethod::from_u32`) — none is Zstd — so paksmith resolves Zstd only through the v8+ slot table. | `trumank/repak/repak/src/footer.rs@e215472c51db69328b1ce77be2db24d24c1d646b`[^2] |

The frame format itself is version-independent: only the *method
resolution* is version-gated. Frames are zstd's v1 format, magic
`0xFD2FB528`, which libzstd marks valid since zstd v0.8.0.[^4]

## Wire layout

Per RFC 8878 §3.1.[^1] Every multi-byte field below is little-endian.

### Frame

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `Magic_Number` | `0xFD2FB528`: the bytes `28 B5 2F FD`. |
| 4 | 2-14 | `Frame_Header` | See below. |
| after the header | 3 + content, each | `Data_Block`s | One or more blocks; the last sets `Last_Block`. |
| end − 4 | 0 or 4 | `Content_Checksum` | Present only when `Content_Checksum_Flag` is set: the low 4 bytes of XXH64, seed 0, over the frame's decoded data. |

### Frame header

| field | size | semantics |
|-------|------|-----------|
| `Frame_Header_Descriptor` | 1 | Bit fields below. |
| `Window_Descriptor` | 0 or 1 | Absent when `Single_Segment_Flag` is set, and `Window_Size` is then `Frame_Content_Size`. Otherwise bits 7-3 are `Exponent` and bits 2-0 `Mantissa`: `windowLog = 10 + Exponent`, `windowBase = 1 << windowLog`, `Window_Size = windowBase + (windowBase / 8) × Mantissa`. The minimum `Window_Size` is 1 KiB. |
| `Dictionary_ID` | 0, 1, 2 or 4 | Size from `Dictionary_ID_Flag` = 0, 1, 2, 3. |
| `Frame_Content_Size` | 0, 1, 2, 4 or 8 | Size from `Frame_Content_Size_Flag` (below). The 2-byte form stores the size minus 256. Absent, the frame does not declare its decoded size. |

`Frame_Header_Descriptor`:

| bits | name | semantics |
|------|------|-----------|
| 7-6 | `Frame_Content_Size_Flag` | 0: no `Frame_Content_Size`, or a 1-byte one when `Single_Segment_Flag` is set; 1: 2 bytes; 2: 4 bytes; 3: 8 bytes. |
| 5 | `Single_Segment_Flag` | Data must be regenerated within a single continuous memory segment; no `Window_Descriptor`. |
| 4 | `Unused_Bit` | Not interpreted by a decoder. |
| 3 | `Reserved_Bit` | Must be 0; a decoder rejects a frame that sets it (§3.1.1.1.1.4). |
| 2 | `Content_Checksum_Flag` | `Content_Checksum` present. |
| 1-0 | `Dictionary_ID_Flag` | `Dictionary_ID` size, as above. |

The smallest v1 frame is 9 bytes: the magic, a 2-byte header and one
3-byte block header with no content.

### Blocks

A `Block_Header` is 3 bytes, a little-endian 24-bit value: bit 0
`Last_Block`, bits 1-2 `Block_Type`, bits 3-23 `Block_Size`.

| `Block_Type` | name | content |
|--------------|------|---------|
| 0 | `Raw_Block` | `Block_Size` bytes, copied to the output. |
| 1 | `RLE_Block` | 1 byte, repeated `Block_Size` times. |
| 2 | `Compressed_Block` | `Block_Size` bytes: a `Literals_Section` and a `Sequences_Section` (RFC 8878 §3.1.1.3). |
| 3 | reserved | Corrupt data; a decoder must reject it. |

`Block_Maximum_Size` is the smaller of `Window_Size` and 128 KiB. It
bounds both a block's content and its decoded size.

### Skippable frame

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `Magic_Number` | Any of `0x184D2A50`-`0x184D2A5F`. |
| 4 | 4 | `Frame_Size` | Length of `User_Data`, u32. |
| 8 | `Frame_Size` | `User_Data` | Skipped by a decoder; adds no output. |

The smallest skippable frame is 8 bytes.

### Worked example: repak's first block

```bash
xxd -s 0x30 -l 66 tests/fixtures/real_v8b_zstd.pak
```

```
00000030: 0300 0000 6900 0000 0000 0000 0706 0000  ....i...........
00000040: 0000 0000 0706 0000 0000 0000 230c 0000  ............#...
00000050: 0000 0000 230c 0000 0000 0000 5b0f 0000  ....#.......[...
00000060: 0000 0000 0000 f001 0028 b52f fd00 58ad  .........(./..X.
00000070: 2c00                                     ,.
```

`real_v8b_zstd.pak`'s one entry record starts at offset 0, so its
relative block offsets read as file offsets here. At `0x30` the record
lists 3 blocks: `[0x69, 0x607)`, `[0x607, 0xc23)` and
`[0xc23, 0xf5b)`, 1438, 1564 and 824 bytes. After the flags byte
(`00`), `compression_block_size` is `0x0001f000` (126976). The first
block follows at `0x69`:

- `28 b5 2f fd` — `Magic_Number`.
- `00` — `Frame_Header_Descriptor`: no `Frame_Content_Size`, not
  single-segment, no checksum, no dictionary.
- `58` — `Window_Descriptor`: `Exponent` 11, `Mantissa` 0, so
  `Window_Size` is 2 MiB and `Block_Maximum_Size` 128 KiB.
- `ad 2c 00` — `Block_Header` `0x002cad`: `Last_Block` 1,
  `Block_Type` 2 (`Compressed_Block`), `Block_Size` `0x595` (1429).

4 + 2 + 3 + 1429 = 1438 bytes: the frame fills the pak block exactly.
Blocks 1 and 2 (`xxd -s 0x607 -l 9` and `xxd -s 0xc23 -l 9` on the
same file) open with the same magic, `00` and `58`, and each holds one
last `Compressed_Block`, of 1555 and 815 bytes, that fills its pak
block.

## Variants

### Frames per block

RFC 8878 allows one or more frames. libzstd's one-shot decoder decodes
each frame in turn, skips skippable frames, and fails when bytes are
left that do not form a frame.[^4] repak writes one v1 frame per
block.[^2]

### Frame-header options

- **`Frame_Content_Size`**: optional, and absent from repak's frames.
  When a frame carries it, libzstd fails the frame unless its decoded
  size matches.[^4]
- **`Content_Checksum`**: optional, and absent from repak's frames.
  When a frame carries it, libzstd verifies it by default.[^4]
- **`Dictionary_ID`**: the pak format has no field that supplies a
  dictionary. libzstd fails a frame that names a dictionary it was not
  given (`dictionary_wrong`).[^4]
- **`Window_Size`**: repak's frames declare 2 MiB, so their
  `Block_Maximum_Size` is 128 KiB, above the 126976-byte pak block; in
  the fixtures each frame holds one zstd block.

### Legacy frames

Before the v1 format, zstd frames carried other magics, none defined
by RFC 8878. Frames of zstd v0.2-v0.7 open with the u32
`0xFD2FB522`-`0xFD2FB527` (the bytes `22 B5 2F FD` to `27 B5 2F FD`);
frames of v0.1 open with the bytes `FD 2F B5 1E`.[^4] libzstd decodes
them only when built with its legacy decoders.

## Caps & limits

### Format-defined limits (wire-imposed)

- A zstd block's content and its decoded size are both at most
  `Block_Maximum_Size`, and so at most 128 KiB.
- Maximum expansion: N compressed bytes decode to fewer than
  N × 32768 bytes. `Block_Maximum_Size` is at most 128 KiB, and the
  densest block is a 4-byte `RLE_Block` (a 3-byte `Block_Header` and
  one byte), so no block yields more than 131072 / 4 output bytes per
  input byte; frame headers and skippable frames add input with no
  output. Paksmith holds this as `MAX_ZSTD_BLOCK_EXPANSION_RATIO`
  in `crates/paksmith-core/src/codec/mod.rs`; see also
  [`../../security/allocation-caps.md`](../../security/allocation-caps.md).
- `Frame_Content_Size` is optional, so a frame need not bound its own
  output; the pak layer bounds it via `compression_block_size` and
  `uncompressed_size`.
- A Zstd pak block is at least 8 bytes: the smallest frame is a 9-byte
  v1 frame or an 8-byte skippable frame (see
  [`pak-block-framing.md`](pak-block-framing.md) for the empty block).

### Implementation hardening (recommended for any parser)

- Check each frame's magic before decoding and accept only
  `0xFD2FB528` and `0x184D2A50`-`0x184D2A5F`; refuse an empty block
  and bytes after the last frame. A build can include libzstd's legacy
  decoders without the parser asking for them (Cargo feature
  unification can turn the zstd crate's `legacy` feature on), and a
  one-shot decode hands each legacy frame to them (paksmith:
  `zstd_v1_frames`).
- Bound each block's output before decoding: reserve the smaller of
  the block's expected output and `compressed_len` × the expansion
  ratio, decode one-shot into it, and fail a block that needs more,
  rather than growing a buffer.
- Enforce the non-final-block == `compression_block_size` and
  cumulative == `uncompressed_size` invariants, as for every block
  codec (see [`pak-block-framing.md`](pak-block-framing.md)).
- Don't size anything from `Frame_Content_Size` or `Window_Size`: both
  come from the untrusted frame.
- repak's frames carry no `Content_Checksum`, so for them the entry
  SHA1 over the on-disk compressed bytes is the only content-integrity
  check (`verify_entry`).
- `uncompressed_size` is capped at open time
  (`MAX_UNCOMPRESSED_ENTRY_BYTES`, 8 GiB) like every entry.

## Verification

- **Fixtures:** `tests/fixtures/real_v8b_zstd.pak` and
  `real_v11_zstd.pak`, generated by `paksmith-fixture-gen`, which
  drives repak's writer. Each holds one entry,
  `Content/Compressed.uasset`: 261871 bytes of numbered text pages
  (`zstd_payload` in `crates/paksmith-fixture-gen/src/main.rs`) in
  blocks of 126976, 126976 and 7919 bytes, stored as 3826 compressed
  bytes, one v1 frame per block.
- **Hex anchor commands:** see *Worked example: repak's first block*
  under Wire layout.
- **Cross-validation oracle:** repak.[^2]
  `cross_parser_agreement_v8b_zstd` and
  `cross_parser_agreement_v11_zstd` in
  `crates/paksmith-fixture-gen/tests/cross_validation.rs` check that
  paksmith and repak read the same bytes and sizes from each fixture,
  and, for v8b, that the suite's wire oracle reads the same index
  metadata. Both readers link the same libzstd (one `zstd-sys`,
  `2.1.3+zstd.1.5.7`, in `Cargo.lock`), so the agreement checks
  paksmith's block walk, budgets and frame check around the codec,
  not one zstd decoder against another. CUE4Parse's decode call[^3]
  is the reference for the per-block contract: the block's frames
  decode to exactly its expected output.
- **Integrity path:** `paksmith verify` reports the v8b entry
  verified, its SHA1 matching repak's over the compressed blocks. The
  v11 entry's index record is encoded and has no hash field, so it is
  skipped (`SkippedNoHash`), as for `real_v11_lz4.pak`.
- **Known divergences:**
  - repak's reader differs from paksmith's.[^2] It decodes
    each block's range with the zstd crate's streaming decoder and
    appends the output, comparing neither a block's output with
    `compression_block_size` nor the total with `uncompressed_size`,
    and its zstd dependency turns on the crate's default `legacy`
    feature. Those two make repak more lenient, and show only on
    malformed or legacy blocks. repak decodes through libzstd's
    streaming API and paksmith through its one-shot API; the streaming
    path enforces limits the one-shot path does not,[^4] so a frame can
    decode in paksmith and fail in repak.
  - Against CUE4Parse, paksmith departs on the same three shapes
    [`lz4.md`](lz4.md#per-block-decompressed-size-derivation) lists.

## Paksmith implementation

**Status:** `complete`.

`stream_block_codec_to` in `crates/paksmith-core/src/container/pak/mod.rs`
walks the blocks, sharing `validate_block_bounds`, the hoisted
two-buffer scheme and the per-block budget (`block_codec_budget`)
with LZ4 (see [`lz4.md`](lz4.md)). Each block goes through
`decode_block` in `crates/paksmith-core/src/codec/mod.rs`
(`decode_zstd`):

- `zstd_v1_frames` refuses an empty block, any frame that is not a v1
  or skippable frame, and bytes after the last frame, before anything
  is reserved. It accepts any number of v1 and skippable frames, empty
  frames (no output) included. The `.usmap` parser applies the same
  check through `is_zstd_v1_stream`.
- The output reservation is `block_output_cap`: the block's budget,
  capped at `compressed_len × MAX_ZSTD_BLOCK_EXPANSION_RATIO`, made
  through the caller (OOM seam `PakSeam::BlockOutputReserve`), with no
  zero-fill.
- libzstd's one-shot decoder (`DCtx::decompress`) writes into the
  buffer's spare capacity, with no window buffer sized by the frame;
  output past the reservation fails.

**Error variants:**
- `DecompressionFault::BlockDecodeFailed { codec, block_index, message }`
  — a block the frame check refuses, that libzstd fails, or that
  decodes past its bound; `codec` is `"zstd"`.
- `DecompressionFault::BlockOutputReserveFailed { codec, block_index, requested, source }`.
- `DecompressionFault::BlockContextUnavailable { codec, block_index }`
  — libzstd could not allocate its decoder context.
- `DecompressionFault::NonFinalBlockSizeMismatch`,
  `DecompressionFault::SizeUnderrun` and
  `DecompressionFault::CompressedBlockReserveFailed`, shared with the
  other block codecs.

`verify_entry` hashes a Zstd entry's blocks like zlib and LZ4 ones,
decompressing nothing. Encrypted Zstd entries are decrypted, then
decoded through the same path; see `crypto/aes-pak.md`.

**Tests:** `codec::tests::zstd_arm` (the frame check, the reservation,
skippable and empty frames, an RLE frame near the ratio),
`container::pak::tests::zstd_entries` (synthetic v8b paks built with
`testing::wire::build_v8b_zstd_pak`), and the fixture-gen agreement
tests above.

## References

[^1]: RFC 8878, *Zstandard Compression and the 'application/zstd' Media Type* (February 2021): §3.1 (frames), §3.1.1 (frame layout, `Magic_Number`, `Content_Checksum`), §3.1.1.1 (`Frame_Header`, `Frame_Header_Descriptor`, `Window_Descriptor`, `Dictionary_ID`, `Frame_Content_Size`), §3.1.1.2 (`Block_Header`, block types, `Block_Maximum_Size`), §3.1.1.3 (compressed blocks), §3.1.2 (skippable frames).
[^2]: `trumank/repak/repak/src/data.rs@e215472c51db69328b1ce77be2db24d24c1d646b` — `build_partial_entry` sets `compression_block_size = 0x3e << 11` and compresses each chunk with `compress`, whose Zstd arm is `zstd::stream::encode_all(data, 0)`. `trumank/repak/repak/src/entry.rs@e215472c51db69328b1ce77be2db24d24c1d646b` — `Entry::read_file` decodes each block range with `zstd::stream::read::Decoder` and `io::copy`. `trumank/repak/repak/src/footer.rs@e215472c51db69328b1ce77be2db24d24c1d646b` — the v8+ compression-slot table of 32-byte names parsed with `Compression::from_str`. `trumank/repak/repak/Cargo.toml@e215472c51db69328b1ce77be2db24d24c1d646b` — `zstd = { version = "0.13", optional = true }`, with the crate's default features. paksmith's `Cargo.lock` resolves that to zstd 0.13.3, whose `stream::raw::Decoder::with_dictionary` creates its `DCtx` without setting `ZSTD_d_windowLogMax`.
[^3]: `FabianFG/CUE4Parse/CUE4Parse/Compression/Compression.cs@c7e78422ec4858036c9bba5d9d3c55eb197f93c9` — the `CompressionAlgorithm.Zstd` decompressor calls ZstdSharp's `ZSTD_decompress` with the destination's length as its capacity, and `Decompress` throws when `bytesWritten != uncompressed.Length`. `CUE4Parse/UE4/Pak/PakFileReader.cs` at the same revision — `Extract` sizes each block's destination at `Math.Min(compressionBlockSize, pakEntry.UncompressedSize - blockIndex * compressionBlockSize)`.
[^4]: `facebook/zstd@f8745da6ff1ad1e7bab384bd1f9d742439278e99` (v1.5.7, the libzstd that `zstd-sys 2.1.3+zstd.1.5.7` bundles; line numbers at that revision). `lib/zstd.h`: `ZSTD_MAGICNUMBER` (L142, "valid since v0.8.0"), `ZSTD_MAGIC_SKIPPABLE_START` (L144), `ZSTD_c_compressionLevel` (L359, "value 0 means default"). `lib/legacy/zstd_legacy.h`: `ZSTD_isLegacy` (L56) and `ZSTD_decompressLegacy` (L121), legacy dispatch. `lib/legacy/zstd_v01.h` (`ZSTDv01_magicNumberLE`, `0x1EB52FFD`) and `lib/legacy/zstd_v02.h` to `zstd_v07.h` (`ZSTDv02_magicNumber` to `ZSTDv07_MAGICNUMBER`, `0xFD2FB522` to `0xFD2FB527`). `lib/decompress/zstd_decompress.c`: `ZSTD_decompressMultiFrame` (L1070), the frame loop, with legacy frames at L1090-L1097 and "input not entirely consumed" at L1166; `ZSTD_decompressFrame` (L953), the `Frame_Content_Size` and checksum checks; `ZSTD_decodeFrameHeader` (L702), `dictionary_wrong` (L718); `ZSTD_decompressStream` (L2086), the single-pass shortcut (L2185-L2202) and window check (L2231); `ZSTD_decompressContinue` (L1275), block-size check (L1367). The one-shot path, `ZSTD_decompressDCtx` through `ZSTD_decompressMultiFrame`, does not run these streaming checks.
