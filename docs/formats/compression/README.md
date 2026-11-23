# Compression backends

How paksmith decompresses entry payloads after the container reader has
located them.

- **`pak-block-framing.md`** — how `.pak` slices an entry into compressed
  blocks before applying the backend.
- **`zlib.md`** — zlib block layout and the deflate dictionary defaults UE
  uses.
- **`lz4.md`** — raw LZ4 Block Format per compression block (v8+
  FName-slot resolution); the second backend paksmith fully decompresses.
- **`zstd.md`** — one or more zstd v1 or skippable frames per
  compression block, per RFC 8878 (v8+ FName-slot resolution); the third
  backend paksmith fully decompresses, refusing legacy frames and bytes
  after the last frame.
- **Gzip** (v3-v7 method ID 2, v8+ FName slot `Gzip`) — one gzip member
  per compression block, per RFC 1952; paksmith decompresses it from v5,
  checks the member's CRC-32 and length, and ignores bytes after the
  member. Its format doc is not written yet (#1082).
- **`oodle.md`** — Oodle Data (Kraken, Mermaid, Selkie, Leviathan).
  Notes on licensing: the Oodle decompressor is not redistributable;
  if paksmith adds Oodle support in the future, it would link against
  a system-provided shared library at runtime; until then, Oodle-compressed
  entries are detected but rejected — see `oodle.md`.
