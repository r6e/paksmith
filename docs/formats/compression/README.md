# Compression backends

How paksmith decompresses entry payloads after the container reader has
located them.

- **`pak-block-framing.md`** — how `.pak` slices an entry into compressed
  blocks before applying the backend.
- **`zlib.md`** — zlib block layout and the deflate dictionary defaults UE
  uses.
- **`oodle.md`** — Oodle Data (Kraken, Mermaid, Selkie, Leviathan).
  Notes on licensing: the Oodle decompressor is not redistributable;
  if paksmith adds Oodle support in the future, it would link against
  a system-provided shared library at runtime; until then, Oodle-compressed
  entries are detected but rejected — see `oodle.md`.
