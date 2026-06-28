# Phase 7b: TextureViewer — Design

**Status:** Approved (2026-06-25)
**Phase:** 7b — second slice of Phase 7 (GUI Asset Viewers)
**Depends on:** Phase 7a (tabbed content host + view-mode seam — PR #594), Phase 3e (texture decode: BCn / ASTC / ETC / HDR → RGBA8), Phase 6 (GUI shell)
**Builds toward:** 7c (AudioPlayer + chrome: toasts, context menu, debug console)

## Goal

Add a fourth in-tab view mode, **Texture**, that renders a decoded `UTexture2D` (or virtual texture) as an image the user can inspect: zoom/pan, isolate the R/G/B/A channels, and step through mip levels. Reuse Phase 3's existing texture decoder (which already produces RGBA8 for PNG export) as the pixel source; render with iced's built-in `image` widget — **no GPU/wgpu pipeline**.

## Why CPU/image, not GPU/wgpu

The ROADMAP sketched a custom `iced::widget::shader` wgpu widget (own a GPU texture, channel-mask + zoom in a WGSL shader). The `shader` widget does exist in iced 0.14, so that path is feasible — but it would be the project's first wgpu code (render pipeline, bind groups, sampler, uniform buffer, WGSL), is GPU-driver-dependent and hard to unit-test, and adds the iced `wgpu`/`advanced` feature. The CPU path decodes to RGBA8 and displays via `iced::widget::image` with `FilterMethod::Nearest` (crisp texels); zoom, channel isolation, and mip selection are all achievable on the decoded buffer with pure, unit-testable state logic (panning is delegated to iced's built-in `scrollable`, so it needs no custom state at all). It delivers the same user-facing features with far less complexity and zero GPU risk, and it fits the project's pure-state / thin-`#[mutants::skip]`-view / mutation-tested discipline. GPU remains a possible later optimization if a real performance need appears (it is not expected for textures bounded by `MAX_DECODED_TEXTURE_BYTES`).

## Scope

### In scope

- **`ViewMode::Texture`** — a fourth view mode alongside Properties / Hex / Info, offered only for decodable-texture tabs.
- **Display** — render the decoded mip as an image, nearest-neighbour filtered, on a neutral/checkered backdrop so alpha and edges read clearly.
- **Zoom/pan** — discrete zoom steps + a fit-to-window default; in manual-zoom mode the image sits in a native `scrollable(Direction::Both)` that provides panning (scrollbars + trackpad/wheel, clamped to content bounds), so there is no explicit pan offset or clamp math to maintain.
- **Channel isolation** — independent R/G/B/A toggles; isolating channels rewrites the displayed RGBA buffer on the CPU (no re-decode).
- **Mip selector** — a dropdown of the texture's serialized mips (with dimensions); selecting one re-decodes that mip asynchronously.
- **Public core decode API** — promote the currently `pub(crate)` texture decode to a small public surface (a decodability classifier + a mip decoder returning `{ width, height, rgba }`), reused from the existing `decode_mip` / `flatten_virtual_texture` internals.
- **Async decode** — mip decode runs off the UI thread (like the existing asset load), delivered via a message.

### Out of scope (YAGNI / deferred)

- Any GPU/wgpu rendering, shaders, or the iced `wgpu`/`advanced` feature.
- Export-from-viewer (PNG export already exists via the CLI / Phase 3 handler).
- Cube-map / texture-array face navigation, volume-texture slices (mips only this pass).
- Histograms, colour pickers, pixel-value readout, exposure/tonemap controls for HDR.
- Persisting per-tab viewer state across sessions.

## Architecture

Mirrors the Phase 7a split (pure `state/` · thin `widgets/` · async `task/`), adding one view mode end-to-end.

```
paksmith-core/src/asset/exports/texture/
  pixel_format.rs        # promote decode_mip + DecodedTexture to a public wrapper
  (new public fns)       # classify_texture(...) + decode_texture_mip(...)

paksmith-gui/src/
  state/texture_view.rs  # PURE math (zoom/fit, channel set, selected mip) +
                         #       mask_rgba(), fully unit-tested. Caches one iced
                         #       image Handle on TextureState (its only iced dep)
  widgets/texture_viewer.rs  # THIN #[mutants::skip]: image(Handle) + zoom +
                             #       scrollable pan + R/G/B/A toggles + mip dropdown
  task/texture.rs        # async: resolve bulk + decode mip -> DecodedTexture
  state/tabs.rs          # +ViewMode::Texture; pick_view_after_load promotion
  panels/content.rs      # +ViewMode::Texture match arm; conditional switcher entry
  app.rs                 # +messages: TextureDecoded,
                         #            channel toggles, zoom, fit-to-window, mip select
```

### Core API (the one core change)

The decoder (`decode_mip`, `DecodedTexture`, `PixelFormat`, `flatten_virtual_texture`) is `pub(crate)` today. Phase 7b exposes a minimal public surface, reusing those internals unchanged:

1. **Classifier** — `classify_texture(package: &Package) -> Option<TextureInfo>`. Returns `Some` when the package's primary export is a `UTexture2D` (standard or virtual) whose pixel format is decodable **and** that carries serialized mip / chunk data within the size cap; `None` otherwise (non-texture, unsupported format, `bSerializeMipData=false`, OOM-capped). `TextureInfo` carries what the GUI needs to drive the UI without decoding: the per-mip `(width, height)` list (for a virtual texture, the single flattened min_level bitmap size the decode emits), a format label, and a normal-map flag. This is a cheap, pure inspection of the parsed `Package` — it drives the "offer a Texture tab?" decision.

2. **Mip decoder** — `decode_texture_mip(package, export_idx, mip_index) -> Result<DecodedTextureRgba>`, where `DecodedTextureRgba { width: u32, height: u32, rgba: Vec<u8> }` is the public form of the existing `DecodedTexture`. Dispatches to the standard mip path (`decode_mip` over `bulk[mip_index]` + `mips[mip_index]` dims) or the virtual-texture flatten path, matching the PNG handler's existing logic. Bulk resolution (`Package::resolve_bulk_for_export(export_idx)`, which needs the reader for `.ubulk` mips) happens **inside** the function — the GUI's async task supplies the already-loaded `Package` (whose loaders close over the reader), so the public API takes an `export_idx` rather than a pre-resolved bulk slice.

The exact factoring (free functions vs. methods, where `TextureInfo` lives) is a plan-level detail; the contract above is fixed.

### Data flow

1. Tab opens → existing Phase 7a async load → parsed `Package` in `TabContent::Ready` (unchanged).
2. On load, the GUI runs `classify_texture`. If `Some`, `pick_view_after_load` promotes the tab to `ViewMode::Texture` and the GUI dispatches an async decode of mip 0.
3. The async task (`task/texture.rs`) holds the tab's `Arc<Package>` (whose loaders close over the reader) and calls `decode_texture_mip(&package, export_idx, mip)` (which resolves the export's bulk records internally), then returns a `DecodedTextureRgba` (or a stringified error) via a `TextureDecoded { generation, mip, result }` message — guarded by the same `archive_generation` fence Phase 7a uses for stale async results.
4. The tab's texture state stores the decoded RGBA for the current mip plus a cached `iced::widget::image::Handle` built from the channel-masked buffer (`Handle::from_rgba(w, h, mask_rgba(rgba, channels))`). It is recomputed only when the decoded mip or channel set changes, never per-frame; the widget clones that cached handle each `view()`, so the mask, the buffer allocation, and the GPU upload happen once per state change. (Caching the `Handle` itself — not just the masked `Vec` — is the one iced type `TextureState` holds; the pure math/`mask_rgba` helpers stay iced-free.)
5. **Channel toggle** → recompute `mask_rgba` on the held buffer → new `Handle`. No re-decode.
6. **Mip select** → dispatch a fresh async decode for that mip index; on `TextureDecoded`, replace the held RGBA.

### The four features

- **Display.** `iced::widget::image` with `FilterMethod::Nearest`. A checkered/neutral backdrop behind the image makes alpha and texture edges legible.
- **Zoom/pan.** A small set of discrete zoom factors plus a fit-to-window default computed from the image and viewport dimensions (pure math in `state/texture_view.rs`). Panning is **not** custom state: in manual-zoom mode the fixed-size image is wrapped in a native `scrollable(Direction::Both)`, which provides scrollbar/trackpad/wheel panning clamped to content bounds — so there is no `(x, y)` pan offset or clamp algorithm to maintain or test. Fit-to-window mode centers the image without a scrollable.
- **Channel isolation.** Four independent toggles (R, G, B, A). `mask_rgba(src: &[u8], channels: ChannelSet) -> Vec<u8>` produces the display buffer: deselected colour channels are zeroed; isolating a single channel renders it as grayscale; an alpha toggle shows alpha as opaque grayscale. Pure and golden-tested.
- **Mip selector.** A dropdown listing each serialized mip as `index — WxH`. Selecting a mip re-decodes asynchronously; while decoding, the previous mip stays visible.

### Error handling & fallback

- A non-texture export never offers a Texture tab (`classify_texture` → `None`).
- Non-decodable textures (unsupported pixel format, no serialized mip / `bSerializeMipData=false`, OOM-capped) → `None` → no Texture tab; the tab uses Properties/Hex/Info as in 7a.
- A decode that fails *after* classification (rare; e.g. a format edge the classifier accepted but the decoder rejects) surfaces a readable reason **inside** the Texture view — it does not panic and does not remove the tab.
- All core fallible paths return `Result<_, PaksmithError>`; the GUI stringifies decode errors for display, consistent with Phase 7a's `parsed: Result<_, String>` pattern.

## Testing

- **Pure state** (`state/texture_view.rs`): fit-to-window and zoom-step math; `mask_rgba` per-channel golden buffers (R-only, A-only, RGB, none); selected-mip-index transitions; channel-set toggling. (No pan math to test — panning is delegated to iced's `scrollable`.)
- **Classifier** (core): `UTexture2D` standard / virtual → `Some` with correct mip dimensions; non-texture / unsupported-format / no-serialized-mip / over-cap → `None`.
- **Mip decoder** (core): one decode per pixel-format family already covered by Phase 3e fixtures, asserting `{width, height, rgba.len()}`; mip-index bounds; virtual-texture flatten path.
- **Thin widget** (`widgets/texture_viewer.rs`): `#[mutants::skip]`; logic extracted to `state/` so nothing testable lives in the view.
- **Standing UI/UX reviewer** on the widget per the Phase 6+ mandate (contrast of the backdrop/toggles, zoom affordance clarity, keyboard access).
- `cargo mutants --in-diff` to 0-missed before push, per the standing gate.

## Constraints (carried from prior phases)

- GUI-only **plus** the single public-API addition in `paksmith-core` described above — no other core changes.
- No new direct third-party dependencies (the iced `image` widget + `Handle::from_rgba` come from enabling iced's existing `image-without-codecs` feature — not the full `image` feature, which cargo-deny rejects; the decoder already exists).
- No panics in core; `thiserror`/`Result` throughout.
- MSRV 1.88 (no let-chains, no `if let` match guards).
- Conventional commits; the standing adversarial review panel + UI/UX reviewer; convergence before push.
