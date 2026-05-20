# Texture formats

Cooked texture payloads — mostly platform-specific compressed pixel data
wrapped in a thin UE record. Lives under `Texture2D` plus a handful of
specialized variants (cube, volume, render-target).

- **`texture2d.md`** — the `Texture2D` record itself.
- **`pixel-formats.md`** — the `EPixelFormat` enum and the on-disk layout
  for each format paksmith intends to decode (DXT/BC family, ASTC, ETC2,
  PVRTC, uncompressed RGBA8/BGRA8).
- **`mips-and-streaming.md`** — how mip chains are split between the
  `.uasset` body and the `.ubulk` companion, and how streaming priorities
  are encoded.
