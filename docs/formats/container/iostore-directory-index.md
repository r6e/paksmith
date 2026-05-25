# IoStore directory-index buffer (`FIoDirectoryIndexResource`)

> Virtual-path → chunk-ID lookup tree carried in the optional
> directory-index region of an IoStore `.utoc`. Lets a reader resolve
> a string path (e.g. `Game/Content/Foo.uasset`) to a chunk slot in
> the parent `.utoc`'s chunk-ID array.

## Overview

An IoStore container is keyed by `FIoChunkId` — the cooker doesn't
ship file paths in the chunk identifiers themselves. The directory
index is a separate buffer inside the `.utoc` that reconstructs the
human-readable virtual path tree so a reader can `lookup("/Game/...")`
and recover the `UserData` index into the parent `.utoc`'s
`ChunkIds[]` array.

The buffer is **optional**: it ships only when the `EIoContainerFlags::Indexed`
flag is set in the `.utoc` header AND `DirectoryIndexSize > 0`. A
reader that doesn't need path lookup MAY skip the entire buffer via
`cursor += DirectoryIndexSize` (see
[`iostore-utoc.md`](iostore-utoc.md) §*Directory-index buffer*).

When the parent container is AES-encrypted (`EIoContainerFlags::Encrypted`
in the `.utoc` header), the entire directory-index buffer is encrypted
with the container's AES-256-ECB key and MUST be decrypted before
parsing. The buffer length is always a multiple of 16 bytes (AES block
size) in encrypted containers.

The buffer is a flat layout of four sequential sections:

- **`MountPoint`** — `FString` virtual root for the contained entries.
- **`DirectoryEntries`** — counted array of 16-byte fixed-layout records.
- **`FileEntries`** — counted array of 12-byte fixed-layout records.
- **`StringTable`** — counted array of `FString` entries that the
  per-entry `Name` u32 indices into the first two arrays resolve through.

Tree traversal starts at `DirectoryEntries[0]` (the root). Each
directory carries first-child and next-sibling pointers (u32 indices,
`0xFFFFFFFF` = invalid sentinel) into `DirectoryEntries`, plus a
first-file pointer into `FileEntries`. Each file entry carries a
next-file pointer (linked list within a directory) plus a `UserData`
u32 — the index into the parent `.utoc`'s `ChunkIds[]` slot the file
resolves to.

**Document status: complete.** Wire format documented in full for
all four sections (mount-point `FString`, directory-entry counted
array, file-entry counted array, string-table counted-FString array),
the traversal model (sibling-and-child linked lists with the
`0xFFFFFFFF` invalid sentinel), the `UserData → utoc.ChunkIds[]`
index resolution, the AES-decryption wrapper, and the mount-point
normalisation contract (`../../..` prefix strip + leading-`/` check
+ fallback to `/`). Phase 8 paksmith reader will parse this surface
directly from the `.utoc` body's directory-index region; no further
sub-format remains undocumented inside this buffer.

**Paksmith parser status: `not impl`.** Phase 8 deliverable. Implements
together with the `.utoc` reader since the buffer is a sub-region of
the TOC body and shares its decryption key.

## Versions

The directory-index buffer's internal layout is wire-stable across all
TOC versions that emit it: `EIoStoreTocVersion::DirectoryIndex (v2)`
introduced the buffer; no subsequent TOC version (`PartitionSize`,
`PerfectHashWithOverflow`, `OnDemandMetaData`, `ReplaceIoChunkHashWithIoHash`,
`RemovedOnDemandMetaData`) has changed the internal directory-index shape.

| UE version range | Wire-format change | Source |
|------------------|---------------------|--------|
| UE 4.25+ (`EIoStoreTocVersion::DirectoryIndex (v2)`) | Buffer introduced; layout (mount-point + 3 counted arrays) wire-stable from this point onward. | `CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21`[^1] |

## Wire layout

The buffer is `DirectoryIndexSize` bytes (the header field of the same
name in [`iostore-utoc.md`](iostore-utoc.md) §*Directory-index size*).
Read sequentially from offset 0 of the (possibly decrypted) buffer:

| section | order | content |
|---------|-------|---------|
| `MountPoint` | 1 | `FString` — UE virtual root for the contained entries (e.g. `../../../ProjectName/Content/`). |
| `DirectoryEntries` | 2 | Counted array — `i32` count + `FIoDirectoryIndexEntry[count]` (16 bytes each). |
| `FileEntries` | 3 | Counted array — `i32` count + `FIoFileIndexEntry[count]` (12 bytes each). |
| `StringTable` | 4 | Counted-`FString` array — `i32` count + `FString[count]`. |

### `MountPoint` (FString)

Standard UE `FString` encoding (see
[`../primitive/fstring.md`](../primitive/fstring.md)):
4-byte `i32` length prefix + character bytes + null terminator. A
positive length is ANSI/UTF-8 (1 byte per char); a negative length is
UCS-2 (`|length| * 2` bytes per char). The cooked mount point is
typically ANSI, starts with `../../../`, and resolves a virtual UE
content root (`../../../GameName/Content/...`).

Mount-point normalisation (per `ValidateMountPoint` in
`AbstractVfsReader.cs` at the pinned SHA):

1. Read the raw `FString`.
2. Set `badMountPoint = !mountPoint.StartsWith("../../..")`; strip the
   `../../..` prefix when present.
3. If the post-strip value is empty, or doesn't start with `/`, or
   the second character is `.` — `badMountPoint = true`.
4. If `badMountPoint`, replace with `/` and log a warning ("strange
   mount point").
5. Strip the leading `/` from the final stored value (so an in-memory
   mount point reads as e.g. `ProjectName/Content/`).

### `DirectoryEntries` (counted array of `FIoDirectoryIndexEntry`)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `count` | 4 | LE | `i32` | Entry count. Read via `FArchive.ReadArray<T>()` — implicit `i32` length prefix. |
| 2 | `entries` | `16 × count` | LE | `FIoDirectoryIndexEntry[]` | Fixed-layout records (see below). |

`FIoDirectoryIndexEntry` (16 bytes, 4 × `u32` LE):

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `Name` | Index into `StringTable`. `0xFFFFFFFF` (`uint.MaxValue`) = no name (the root directory typically has `Name == 0xFFFFFFFF`). |
| 4 | 4 | `FirstChildEntry` | Index into `DirectoryEntries` for the first child directory. `0xFFFFFFFF` = no children. |
| 8 | 4 | `NextSiblingEntry` | Index into `DirectoryEntries` for the next sibling directory at the same depth. `0xFFFFFFFF` = end of sibling list. |
| 12 | 4 | `FirstFileEntry` | Index into `FileEntries` for the first file in this directory. `0xFFFFFFFF` = no files. |

The root directory is always `DirectoryEntries[0]`. Tree traversal
walks both linked lists in parallel: `FirstChildEntry → recurse`,
`NextSiblingEntry → loop`, `FirstFileEntry → walk file list`. The
sentinel value `uint.MaxValue` (`0xFFFFFFFF`) terminates each chain.

### `FileEntries` (counted array of `FIoFileIndexEntry`)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `count` | 4 | LE | `i32` | Entry count. Read via `FArchive.ReadArray<T>()`. |
| 2 | `entries` | `12 × count` | LE | `FIoFileIndexEntry[]` | Fixed-layout records (see below). |

`FIoFileIndexEntry` (12 bytes, 3 × `u32` LE):

| offset | size | name | semantics |
|--------|------|------|-----------|
| 0 | 4 | `Name` | Index into `StringTable`. The file's leaf name (no directory component). |
| 4 | 4 | `NextFileEntry` | Index into `FileEntries` for the next file in the SAME directory. `0xFFFFFFFF` = end of file list. |
| 8 | 4 | `UserData` | Index into the parent `.utoc`'s `ChunkIds[]` array (NOT a raw `FIoChunkId`). Resolves to the chunk slot the file occupies. |

The full resolved path of a file at `FileEntries[i]` reachable from
directory `DirectoryEntries[d]` is the concatenation:

```
MountPoint + (path-segment per ancestor directory's StringTable[Name])
           + StringTable[FileEntries[i].Name]
```

Ancestor directory names are joined with `/` separators; an empty name
(`Name == 0xFFFFFFFF`) contributes nothing. The `FileEntries[i].UserData`
index then selects which slot of the parent `.utoc`'s
`ChunkIds: FIoChunkId[TocEntryCount]` array (per
[`iostore-utoc.md`](iostore-utoc.md) §*ChunkIds table*) the file maps to.

### `StringTable` (counted array of `FString`)

| order | field | size | endian | type | semantics |
|-------|-------|------|--------|------|-----------|
| 1 | `count` | 4 | LE | `i32` | String count. Read via `GenericBufferReader.ReadFStringMemoryArray()` — implicit `i32` length prefix, then per-entry `FString`. |
| 2 | `strings` | variable | LE | `FString[]` | Per-entry: 4-byte `i32` length + char bytes + null terminator (standard FString encoding). Each entry is referenced by the `Name` u32 indices in `DirectoryEntries` and `FileEntries`. |

Each string is the leaf name (directory name or file name with
extension) — the table is a deduplicated pool. The path `Game/Foo.uasset`
under mount point `../../../Game/Content/` would have at minimum two
entries (`"Game"` for the directory, `"Foo.uasset"` for the file), but
typical real-world tables share substantial dedup (the `.uasset`
suffix isn't shared — strings are full leaf names).

### Worked example — minimal directory-index buffer (107 bytes, one file)

A directory-index for a single file `Foo.uasset` inside a single
directory `Game`, mount-point `../../../Demo/Content/`, no encryption:

```
Offset  Bytes (LE; multi-byte annotated)                  Field
------  ------------------------------------------------  -------------------------
+0      17 00 00 00                                        MountPoint FString length = 23 (ANSI, includes null)
+4      2E 2E 2F 2E 2E 2F 2E 2E 2F 44 65 6D 6F 2F 43 6F   "../../../Demo/Co"
+20     6E 74 65 6E 74 2F 00                              "ntent/" + NUL
+27     02 00 00 00                                        DirectoryEntries count = 2
+31     FF FF FF FF                                        DirectoryEntries[0].Name = 0xFFFFFFFF (root, no name)
+35     01 00 00 00                                        DirectoryEntries[0].FirstChildEntry = 1 (the "Game" dir)
+39     FF FF FF FF                                        DirectoryEntries[0].NextSiblingEntry = invalid (root has no sibling)
+43     FF FF FF FF                                        DirectoryEntries[0].FirstFileEntry = invalid (no files in root)
+47     00 00 00 00                                        DirectoryEntries[1].Name = 0 → StringTable[0] = "Game"
+51     FF FF FF FF                                        DirectoryEntries[1].FirstChildEntry = invalid
+55     FF FF FF FF                                        DirectoryEntries[1].NextSiblingEntry = invalid
+59     00 00 00 00                                        DirectoryEntries[1].FirstFileEntry = 0 (FileEntries[0])
+63     01 00 00 00                                        FileEntries count = 1
+67     01 00 00 00                                        FileEntries[0].Name = 1 → StringTable[1] = "Foo.uasset"
+71     FF FF FF FF                                        FileEntries[0].NextFileEntry = invalid (last file)
+75     00 00 00 00                                        FileEntries[0].UserData = 0 → utoc.ChunkIds[0]
+79     02 00 00 00                                        StringTable count = 2
+83     05 00 00 00                                        StringTable[0] FString length = 5 ("Game" + NUL)
+87     47 61 6D 65 00                                     "Game" + NUL
+92     0B 00 00 00                                        StringTable[1] FString length = 11 ("Foo.uasset" + NUL)
+96     46 6F 6F 2E 75 61 73 73 65 74 00                  "Foo.uasset" + NUL
+107                                                       (end of buffer)
```

Total bytes: 4 (mount-point len) + 23 (mount-point data) + 4
(DirEntries count) + 32 (2 × 16-byte DirEntries) + 4 (FileEntries count)
+ 12 (1 × 12-byte FileEntry) + 4 (StringTable count) + 4 (str[0] len)
+ 5 (str[0] data) + 4 (str[1] len) + 11 (str[1] data) = **107 bytes**.

Resolved path: traverse from `DirectoryEntries[0]` → its
`FirstChildEntry = 1` → `DirectoryEntries[1]` with name `"Game"` → its
`FirstFileEntry = 0` → `FileEntries[0]` with name `"Foo.uasset"`,
producing the in-memory path `Demo/Content/Game/Foo.uasset` (post
mount-point-normalisation, the `../../../` prefix is stripped and the
leading `/` is removed). The file resolves to
`utoc.ChunkIds[FileEntries[0].UserData] = utoc.ChunkIds[0]`.

## Variants

### Encrypted containers

When `.utoc` `ContainerFlags & EIoContainerFlags::Encrypted` is set,
the entire directory-index buffer is AES-256-ECB encrypted using the
container's encryption key (matched via `EncryptionKeyGuid` from the
`.utoc` header — see [`iostore-utoc.md`](iostore-utoc.md) §*Encryption
key GUID*). The buffer length on disk is always a multiple of 16
bytes (AES block alignment); decryption produces a buffer whose first
`FString` mount-point length field is the de-facto integrity check —
an incorrect key yields a corrupted/oversized mount-point length and
the parse aborts.

### Empty index buffer

When `DirectoryIndexSize == 0`, the entire buffer is absent. The
`EIoContainerFlags::Indexed` flag MAY still be set (a no-op), but
typically both go together (flag set ↔ size > 0). Readers MUST NOT
attempt to parse a zero-length buffer.

### Game-specific quirks

CUE4Parse handles one game-specific path remapping:
`EGame.GAME_NeedForSpeedMobile` strips a `"../../../"` prefix from the
post-traversal full path before storing. This is a path-level fixup,
not a wire-format variant — the buffer content is unchanged.

## Caps & limits

### Format-defined limits (wire-imposed)

- **`MountPoint`**: `FString`, length-prefix is `i32` (negative = UCS-2). No format-defined upper bound; CUE4Parse uses `MAX_MOUNTPOINT_TEST_LENGTH = 128` for HEURISTIC validity-testing of pre-decryption buffers but does NOT cap the parsed value at 128 bytes.
- **`DirectoryEntries.count`**: `i32`. Total bytes = `4 + 16 × count`.
- **`FileEntries.count`**: `i32`. Total bytes = `4 + 12 × count`.
- **`StringTable.count`**: `i32`. Per-entry FString length is also `i32`; total bytes are variable.
- **`FIoDirectoryIndexEntry`**: fixed 16 bytes (4 × `u32` LE).
- **`FIoFileIndexEntry`**: fixed 12 bytes (3 × `u32` LE).
- **Invalid sentinel**: `uint.MaxValue` (`0xFFFFFFFF`) for `Name`, `FirstChildEntry`, `NextSiblingEntry`, `FirstFileEntry`, `NextFileEntry`. The `UserData` field has NO defined invalid sentinel — all 2³² values are valid chunk-table indices (subject to upper-bound validation against `utoc.TocEntryCount`).
- **AES alignment**: when the parent container is encrypted, `DirectoryIndexSize` MUST be a multiple of 16 bytes (AES-256 block size).

### Implementation hardening (recommended for any parser)

A directory-index reader (paksmith does not yet have one) MUST:

- **Cap `DirectoryIndexSize`** against a project-defined ceiling before allocating the read buffer. Inherit `MAX_DIRECTORY_INDEX_BYTES` from the same allocation-cap policy as `iostore-utoc.md` (a `u32::MAX` `DirectoryIndexSize` would drive a 4 GiB read). The cap should bound BOTH the on-disk buffer length AND the post-decryption interpretation.
- **Verify the `i32` count prefixes** (`DirectoryEntries.count`, `FileEntries.count`, `StringTable.count`) are non-negative AND that the implied size (`4 + 16 × count` for directories, `4 + 12 × count` for files, variable for string table) fits within the remaining buffer bytes. A negative count cast to `usize` produces `usize::MAX`-adjacent values; an oversized count drives over-large allocations even before per-entry bounds-checking would catch downstream errors.
- **Bounds-check every `Name` index** in `DirectoryEntries` and `FileEntries` against `StringTable.count` before any string lookup. Allow the explicit `0xFFFFFFFF` sentinel for `DirectoryEntries[i].Name` (root + nameless directories); reject `0xFFFFFFFF` for `FileEntries[i].Name` (files must always have a name); reject any other value `>= StringTable.count` as an OOB index.
- **Bounds-check every `FirstChildEntry`, `NextSiblingEntry`** against `DirectoryEntries.count` (allowing the `0xFFFFFFFF` sentinel). An OOB index reads attacker-controlled adjacent memory in a tight-packed struct array.
- **Bounds-check every `FirstFileEntry`, `NextFileEntry`** against `FileEntries.count` (allowing the `0xFFFFFFFF` sentinel).
- **Bounds-check every `UserData`** against the parent `.utoc`'s `TocEntryCount` (i.e. `ChunkIds.Length`) before using it as a chunk-table index. An OOB value reads the wrong chunk slot or panics on slice access. There is NO sentinel value — every `UserData` MUST resolve to a valid chunk slot.
- **Detect cycles in the directory and file linked lists.** The `FirstChildEntry → NextSiblingEntry → NextFileEntry` traversal is unbounded recursion otherwise. A directory whose `NextSiblingEntry` points to itself, or a file whose `NextFileEntry` points to an earlier file, would cause infinite recursion / infinite loop on traversal. Cap traversal depth at `DirectoryEntries.count + FileEntries.count` total visits, or use a visited-set of already-seen entry indices.
- **Detect path-traversal in the StringTable.** The `MountPoint` normalisation strips one fixed `../../..` prefix, but does NOT sanitise the per-entry directory/file names. A `StringTable[i]` value of `"../sibling"` or `"/etc/passwd"` would, after path-concatenation, produce a path that escapes the container's intended mount root. Reader MUST reject any string containing `/`, `\`, `..`, or NUL bytes as illegal in a leaf-name slot. (UE's cooker doesn't emit these, but a hostile container can.)
- **Enforce AES alignment** when the parent container is encrypted: `DirectoryIndexSize % 16 == 0`. A non-aligned size indicates corruption (or a parser that's reading a non-encrypted buffer with the encrypted-path code path) and decryption will throw.
- **Validate `MountPoint` post-normalisation** stays within a project-defined maximum length (typically the same as `MAX_MOUNTPOINT_TEST_LENGTH = 128` per CUE4Parse's pre-decryption heuristic). A parser that doesn't cap the mount-point length here will cap it implicitly via the file-path concatenation budget downstream, but rejecting early surfaces the error closer to the wire.

See `docs/security/allocation-caps.md` for the broader policy.

## Verification

- **Fixture:** The 107-byte Worked example above is byte-exact and self-contained. Real cooked fixtures from any UE 4.25+ `.utoc` with `EIoContainerFlags::Indexed` set exercise the same wire shape; a synthetic single-file fixture is a Phase 8 deliverable.
- **Hex anchor command:**
  ```
  # Synthesize the 107-byte minimal directory-index buffer from the Worked example
  # (mount-point "../../../Demo/Content/" + root + "Game" dir + "Foo.uasset" file + 2-entry string table):
  printf '\x17\x00\x00\x00\x2E\x2E\x2F\x2E\x2E\x2F\x2E\x2E\x2F\x44\x65\x6D\x6F\x2F\x43\x6F\x6E\x74\x65\x6E\x74\x2F\x00\x02\x00\x00\x00\xFF\xFF\xFF\xFF\x01\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x02\x00\x00\x00\x05\x00\x00\x00\x47\x61\x6D\x65\x00\x0B\x00\x00\x00\x46\x6F\x6F\x2E\x75\x61\x73\x73\x65\x74\x00' | xxd
  ```
  A conformant directory-index parser fed these 107 bytes MUST resolve a single file at path `Demo/Content/Game/Foo.uasset` with `UserData = 0` (chunk-table index 0).
- **Cross-validation oracle:** CUE4Parse[^1] (sole oracle; repak does not parse IoStore containers).
- **Known divergences:** none — no paksmith implementation to diverge.

## Paksmith implementation

**Parser module:** *(not yet implemented — planned under
`crates/paksmith-core/src/container/iostore/directory_index.rs`,
called from `container/iostore/toc.rs` when the directory-index buffer
is requested)*

**Status:** `not impl`.

**Phase plan:** `docs/plans/ROADMAP.md` Phase 8 (IoStore container reader).

## References

[^1]: `FabianFG/CUE4Parse/CUE4Parse/UE4/IO/IoStoreReader.cs@ecc4878950336126f125af0747190edf474b2a21` (`ProcessIndex` method covers the open-flow that reads this buffer end-to-end). `Objects/FIoDirectoryIndexEntry.cs` + `Objects/FIoFileIndexEntry.cs` define the 16-byte and 12-byte fixed-layout records (`[StructLayout(LayoutKind.Sequential)]`). `UE4/VirtualFileSystem/AbstractVfsReader.cs` provides the `ValidateMountPoint` normalisation contract. The `ReadFStringMemoryArray` extension method used for the string table is defined in the upstream `NotOfficer/GenericReader` package that CUE4Parse depends on (counted array of `FString` entries; same wire shape as a hand-rolled `i32 count + FString[count]`).
