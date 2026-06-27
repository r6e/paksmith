# Phase 7b: TextureViewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth in-tab view mode, `Texture`, that decodes a `UTexture2D` (standard or virtual) to RGBA8 and displays it with zoom/pan, R/G/B/A channel isolation, and a mip-level selector — using iced's CPU `image` widget, no wgpu.

**Architecture:** One public core decode API (a cheap `classify_texture` + a `decode_texture_mip` returning `{width, height, rgba}`, reusing the existing `pub(crate)` `decode_mip` / `flatten_virtual_texture` / `DecodedTexture` internals). GUI side mirrors the Phase 7a split: pure `state/texture_view.rs` (zoom/fit/pan math, channel masking, selected mip) + thin `#[mutants::skip]` `widgets/texture_viewer.rs` (iced `image` + controls) + async `task/texture.rs` (off-thread decode, `archive_generation`-fenced). A new `ViewMode::Texture` slots into the existing tab seam.

**Tech Stack:** Rust, iced 0.14 (enable the `image` feature), paksmith-core texture decoder (Phase 3e), `#[mutants::skip]` + `mutants` crate, `thiserror`, `tracing`.

## Global Constraints

- **GUI-only PLUS exactly one public-API addition in `paksmith-core`** (`classify_texture`, `decode_texture_mip`, public `DecodedTextureRgba`, public `TextureInfo`). No other core behavior changes — the decode logic is *reused* from existing internals, not rewritten.
- **CPU render path only.** No wgpu, no `iced::widget::shader`, no WGSL, no iced `wgpu`/`advanced` feature.
- **Enable iced's codec-free `image-without-codecs` feature** in `crates/paksmith-gui/Cargo.toml` (`features = ["tokio", "image-without-codecs"]`). This is a feature of the existing `iced` dependency, not a new direct dependency. The full `image` feature force-enables all `image`-crate codecs (AVIF/rav1e → cargo-deny licenses+bans FAIL); the viewer only needs `Handle::from_rgba` raw pixels, so the codec-free variant suffices. It still pulls BSD-2-Clause `kamadak-exif` + `mutate_once` transitively → scoped `deny.toml` `[[licenses.exceptions]]` — note for the cargo-deny / cargo-audit gates.
- **No other new third-party dependencies.**
- **No panics in core** — all fallible paths return `Result<T, PaksmithError>`.
- **MSRV 1.88** — no let-chains, no `if let` match guards (plain `if EXPR` guards OK); use let-else / nested `if` + `#[allow(clippy::collapsible_if)]`.
- **Pure-logic `state/` (helpers iced-free; `TextureState` caches one iced `Handle`) · thin `#[mutants::skip]` `widgets/` · async `task/`** — the Phase 7a discipline.
- **`archive_generation` fence** on every async result (drop if `generation != app.archive_generation`).
- **Decoded RGBA is displayed as-is** (no gamma/sRGB re-encoding, no HDR tonemap controls — the decoder already tonemaps HDR to RGBA8).
- Conventional commits; the standing adversarial review panel + **standing UI/UX reviewer** on the widget; `cargo mutants --in-diff <merge-base..HEAD> -p <pkg> --all-features` to **0 missed** before push; `cargo fmt`/`clippy --all-targets --all-features -D warnings`/`test`/`RUSTDOCFLAGS=-D warnings cargo doc`/`typos` all green before push.

## File Structure

**Core (one change):**
- `crates/paksmith-core/src/asset/exports/texture/pixel_format.rs` — make `DecodedTexture` reachable; add the public `decode_texture_mip` low-level wrapper.
- `crates/paksmith-core/src/asset/exports/texture/mod.rs` — add `classify_texture` + `decode_texture_mip` + `TextureInfo` + `DecodedTextureRgba` as the public module surface; re-export from a stable path.
- `crates/paksmith-core/src/asset/mod.rs` or `lib.rs` — `pub use` the new types/functions at a discoverable path (`paksmith_core::asset::texture::*` or alongside `Texture2DData`).

**GUI:**
- `crates/paksmith-gui/src/state/texture_view.rs` — **new**: pure helpers (`ChannelSet`, `mask_rgba`, zoom/fit math, `DecodedMip`) + `TextureState`, which caches one iced `Handle` (its only iced dependency).
- `crates/paksmith-gui/src/state/tabs.rs` — `ViewMode::Texture`; `Tab.texture: TextureState`; `pick_view_after_load` promotion; `texture_available`; `TabContent::Ready.parsed` `Box`→`Arc`.
- `crates/paksmith-gui/src/state/mod.rs` — register `texture_view`.
- `crates/paksmith-gui/src/task/texture.rs` — **new**, async decode → `DecodedMip`.
- `crates/paksmith-gui/src/task/mod.rs` — register `texture`.
- `crates/paksmith-gui/src/widgets/texture_viewer.rs` — **new**, thin `#[mutants::skip]`: `image` + zoom/pan + R/G/B/A toggles + mip dropdown.
- `crates/paksmith-gui/src/widgets/mod.rs` — register `texture_viewer`.
- `crates/paksmith-gui/src/panels/content.rs` — `ViewMode::Texture` arm + conditional switcher entry.
- `crates/paksmith-gui/src/app.rs` — `Message` variants + `update` wiring (decode dispatch, `TextureDecoded` handler, channel/zoom/pan/mip messages).
- `crates/paksmith-gui/Cargo.toml` — enable iced `image` feature.

---

## Task 1: Public core texture-decode API

**Files:**
- Modify: `crates/paksmith-core/src/asset/exports/texture/pixel_format.rs`
- Modify: `crates/paksmith-core/src/asset/exports/texture/mod.rs`
- Modify: `crates/paksmith-core/src/asset/mod.rs` (re-export)
- Test: in `mod.rs` `#[cfg(test)]` (reuse existing 3e fixtures / constructed `Texture2DData`)

**Interfaces:**
- Consumes (existing `pub(crate)`): `DecodedTexture { width, height, rgba }`, `PixelFormat::from_name`, `codec_for(&PixelFormat) -> Option<Codec>`, `decode_mip(&PixelFormat, &[u8], u32, u32, bool, &str) -> Result<DecodedTexture>`, `flatten_virtual_texture(vt, bulk, is_normal_map) -> Result<DecodedTexture>`, `Package::resolve_bulk_for_export(usize) -> Result<&[BulkData]>`, `Asset::Texture2D(Texture2DData)`, `Texture2DData { properties, pixel_format, mips, virtual_texture, .. }`, `Package.payloads: Vec<Asset>`.
- Produces (NEW public):
  - `pub struct DecodedTextureRgba { pub width: u32, pub height: u32, pub rgba: Vec<u8> }` (`#[derive(Debug, Clone, PartialEq, Eq)]`).
  - `pub struct TextureInfo { pub export_idx: usize, pub mips: Vec<(u32, u32)>, pub format_label: String, pub is_normal_map: bool }` (`#[derive(Debug, Clone, PartialEq, Eq)]`).
  - `pub fn classify_texture(package: &Package) -> Option<TextureInfo>`.
  - `pub fn decode_texture_mip(package: &Package, export_idx: usize, mip_index: usize) -> crate::Result<DecodedTextureRgba>`.

**Design notes (read before implementing):**
- `classify_texture` is a **pure, cheap** scan: find the first `package.payloads` index that is `Asset::Texture2D(data)` where the texture is decodable. Decodable = (`data.virtual_texture.is_some()` with a decodable layer-0 format) OR (`!data.mips.is_empty()` AND `codec_for(&PixelFormat::from_name(&data.pixel_format)).is_some()`). Build `mips` from the per-mip dimensions: for the standard path use the serialized-mip dimensions (mirror the existing `selected_mip_dimensions` logic — `data.mips[i]`'s SizeX/SizeY); for virtual textures use the single full-resolution `(width, height)`. `is_normal_map` mirrors the existing `has_enum(data, "CompressionSettings", "TC_Normalmap")` check on `data.properties`. Do **not** resolve bulk here (no reader/borrow needed; keep it pure over `&Package`).
- `decode_texture_mip` resolves bulk **internally** via `package.resolve_bulk_for_export(export_idx)`, extracts `Asset::Texture2D(data)`, then dispatches exactly like `PngHandler::export`: virtual → `flatten_virtual_texture(vt, bulk, is_normal_map)`; standard → `decode_mip(&format, &bulk[mip_index].bytes, w, h, is_normal_map, "<texture mip>")` with `(w, h)` from the serialized mip dimensions. Convert the resulting `DecodedTexture` into `DecodedTextureRgba`. Return `PaksmithError` on: export not a texture, `mip_index` out of range, empty bulk (no serialized mip), or any decode fault — never panic.
- DRY: factor the `is_normal_map` / `selected_mip_dimensions` logic so Task 1 and the existing `export/texture.rs` share it rather than duplicating (extract to the texture module if not already shared).

- [ ] **Step 1: Write the failing test for `classify_texture`**

Add to `crates/paksmith-core/src/asset/exports/texture/mod.rs` tests. Use the existing real texture fixture the export tests use (grep `real_*` texture fixtures / the `decode`-path tests already in `export/texture.rs` or `texture2d.rs` for the exact fixture + parse helper). Example shape:

```rust
#[test]
fn classify_texture_returns_info_for_a_decodable_texture2d() {
    let pkg = parse_texture_fixture(); // reuse the existing test helper / fixture loader
    let info = classify_texture(&pkg).expect("a UTexture2D fixture must classify as decodable");
    assert!(!info.mips.is_empty(), "must report at least one mip");
    assert_eq!(info.mips[0], (expected_w, expected_h)); // pin to the fixture's top serialized mip
    assert!(!info.format_label.is_empty());
}

#[test]
fn classify_texture_none_for_non_texture() {
    let pkg = parse_non_texture_fixture(); // e.g. the Demo.uasset used by the GUI asset tests
    assert!(classify_texture(&pkg).is_none());
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p paksmith-core --all-features classify_texture`
Expected: FAIL — `classify_texture` not found.

- [ ] **Step 3: Implement `DecodedTextureRgba`, `TextureInfo`, `classify_texture`**

In `mod.rs`, add the two public structs and `classify_texture`, reusing `PixelFormat::from_name` + `codec_for` + the shared `is_normal_map`/mip-dimension helpers. Re-export from `asset/mod.rs` so the GUI reaches them at a stable path (e.g. `pub use exports::texture::{classify_texture, decode_texture_mip, DecodedTextureRgba, TextureInfo};`).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p paksmith-core --all-features classify_texture`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `decode_texture_mip`**

```rust
#[test]
fn decode_texture_mip_yields_rgba_of_expected_size() {
    let pkg = parse_texture_fixture();
    let info = classify_texture(&pkg).unwrap();
    let out = decode_texture_mip(&pkg, info.export_idx, 0).expect("mip 0 must decode");
    assert_eq!(out.rgba.len() as u64, u64::from(out.width) * u64::from(out.height) * 4);
    assert_eq!((out.width, out.height), info.mips[0]);
}

#[test]
fn decode_texture_mip_out_of_range_is_err_not_panic() {
    let pkg = parse_texture_fixture();
    let info = classify_texture(&pkg).unwrap();
    assert!(decode_texture_mip(&pkg, info.export_idx, info.mips.len() + 99).is_err());
}
```

- [ ] **Step 6: Run to verify failure, implement, verify pass**

Run: `cargo test -p paksmith-core --all-features decode_texture_mip` → FAIL, then implement `decode_texture_mip` (dispatch standard/virtual exactly like `PngHandler::export`), then re-run → PASS.

- [ ] **Step 7: Gate + commit**

Run: `cargo fmt --all && cargo clippy -p paksmith-core --all-targets --all-features -- -D warnings && cargo test -p paksmith-core --all-features texture`
Expected: all green.

```bash
git add crates/paksmith-core/src/asset/
git commit -m "feat(core): public texture decode API (classify_texture + decode_texture_mip)"
```

---

## Task 2: Pure GUI texture-view state

**Files:**
- Create: `crates/paksmith-gui/src/state/texture_view.rs`
- Modify: `crates/paksmith-gui/src/state/mod.rs` (add `pub mod texture_view;`)
- Test: in `texture_view.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `paksmith_core::asset::DecodedTextureRgba` for the `DecodedMip` newtype dimensions (store `width`/`height`/`rgba` directly). The pure helpers (`mask_rgba`, zoom/fit math) import no iced and stay fully unit-testable; the **one** iced dependency is a cached `iced::widget::image::Handle` field on `TextureState` — a per-frame GPU-upload-skip optimization added during implementation, built by a small `render_handle`/`recompute_render` pair.
- Produces:
  - `pub struct ChannelSet { pub r: bool, pub g: bool, pub b: bool, pub a: bool }` with `Default` = all true, and `pub fn toggle(&mut self, ch: Channel)`, `pub enum Channel { R, G, B, A }`.
  - `pub fn mask_rgba(src: &[u8], channels: ChannelSet) -> Vec<u8>` — see semantics below.
  - `pub struct DecodedMip { pub width: u32, pub height: u32, pub rgba: Vec<u8> }`.
  - `pub struct TextureState { pub selected_mip: usize, pub channels: ChannelSet, pub zoom: f32, pub pan: (f32, f32), pub decoded: Option<DecodedMip>, pub error: Option<String> }` with `Default`.
  - `pub fn fit_zoom(img: (u32, u32), viewport: (f32, f32)) -> f32`.
  - `pub fn clamp_pan(pan: (f32, f32), scaled: (f32, f32), viewport: (f32, f32)) -> (f32, f32)`.
  - `pub const ZOOM_STEPS: &[f32]` + `pub fn zoom_in(z: f32) -> f32` / `zoom_out(z: f32) -> f32` (snap to neighbouring step).

**`mask_rgba` semantics (pin exactly with tests):**
- All four channels on → identity copy.
- A colour channel off → that channel's bytes set to 0 in the output (R off ⇒ every pixel's byte 0 = 0).
- Alpha off → alpha forced to 255 (opaque), so masking colours doesn't make the image vanish.
- Exactly one colour channel on (and others off) → render it as **grayscale** (replicate that channel into R=G=B), alpha 255 — so isolating G shows a readable grayscale of the green channel.
- Alpha-only (a on, rgb off) → show alpha as opaque grayscale (R=G=B=alpha, A=255).
- Output length always equals input length.

- [ ] **Step 1: Write failing tests for `mask_rgba`**

```rust
#[test]
fn mask_identity_when_all_channels_on() {
    let src = vec![10, 20, 30, 40, 50, 60, 70, 80];
    assert_eq!(mask_rgba(&src, ChannelSet::default()), src);
}

#[test]
fn mask_single_channel_is_grayscale() {
    // one RGBA pixel (R=10,G=20,B=30,A=40); isolate G → 20,20,20,255
    let out = mask_rgba(&[10, 20, 30, 40], ChannelSet { r: false, g: true, b: false, a: false });
    assert_eq!(out, vec![20, 20, 20, 255]);
}

#[test]
fn mask_alpha_off_forces_opaque() {
    let out = mask_rgba(&[10, 20, 30, 40], ChannelSet { r: true, g: true, b: true, a: false });
    assert_eq!(out, vec![10, 20, 30, 255]);
}

#[test]
fn mask_alpha_only_shows_alpha_as_gray() {
    let out = mask_rgba(&[10, 20, 30, 40], ChannelSet { r: false, g: false, b: false, a: true });
    assert_eq!(out, vec![40, 40, 40, 255]);
}

#[test]
fn mask_preserves_length() {
    let src = vec![1u8; 4 * 7];
    assert_eq!(mask_rgba(&src, ChannelSet { r: true, g: false, b: true, a: true }).len(), src.len());
}
```

- [ ] **Step 2: Run → FAIL** (`cargo test -p paksmith-gui mask_`), then implement `mask_rgba` + `ChannelSet`/`Channel`, then **Step 3: Run → PASS**.

- [ ] **Step 4: Write failing tests for zoom/fit/pan math**

```rust
#[test]
fn fit_zoom_scales_to_fit_smaller_axis() {
    // 200x100 image into 100x100 viewport → fit = 0.5
    assert!((fit_zoom((200, 100), (100.0, 100.0)) - 0.5).abs() < f32::EPSILON);
}

#[test]
fn zoom_in_then_out_returns_to_neighbourhood() {
    let z = 1.0;
    assert!(zoom_in(z) > z);
    assert!(zoom_out(zoom_in(z)) <= zoom_in(z));
}

#[test]
fn clamp_pan_keeps_image_in_view() {
    // image larger than viewport: pan clamped so an edge cannot pass the far side
    let p = clamp_pan((10_000.0, 0.0), (400.0, 400.0), (100.0, 100.0));
    assert!(p.0 <= (400.0 - 100.0)); // cannot scroll past the right edge
}
```

- [ ] **Step 5: Run → FAIL, implement, Run → PASS.** Keep the logic helpers pure (no iced); the lone iced touch is the cached-`Handle` builder added later (`render_handle`/`recompute_render`).

- [ ] **Step 6: Gate + commit**

```bash
cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings && cargo test -p paksmith-gui texture_view
git add crates/paksmith-gui/src/state/
git commit -m "feat(gui): pure texture-view state (channel mask, zoom/fit/pan math)"
```

---

## Task 3: Tab seam — `ViewMode::Texture`, promotion, availability, `Arc<Package>`

**Files:**
- Modify: `crates/paksmith-gui/src/state/tabs.rs`
- Test: in `tabs.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `paksmith_core::asset::classify_texture`, `crate::state::texture_view::TextureState`, existing `ViewMode`/`Tab`/`TabContent`/`Tabs`.
- Produces:
  - `ViewMode::Texture` variant.
  - `Tab.texture: TextureState` field (added to the struct + the `open_or_activate` constructor with `TextureState::default()`).
  - `TabContent::Ready.parsed` changed from `Result<Box<Package>, String>` to `Result<std::sync::Arc<Package>, String>`.
  - `pub fn texture_available(tab: &Tab) -> bool` (free fn or method) — `true` iff the tab is `Ready { parsed: Ok(pkg), .. }` and `classify_texture(pkg).is_some()`.
  - `pick_view_after_load` extended: when `texture_available` and the tab is still on the default `Properties` view, promote to `ViewMode::Texture` (texture promotion takes precedence over the Err→Info demotion; an `Ok` decodable texture is the common landing case).

**Critical (dedup-drift guard):** the existing `pick_view_after_load` Err→Info demotion logic must be preserved exactly. Add the texture promotion as a *new* branch; pin BOTH behaviors with tests before and after.

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn pick_view_promotes_decodable_texture_to_texture_view() {
    let mut t = Tabs::default();
    t.open_or_activate("Game/T_Rock.uasset");
    t.set_content("Game/T_Rock.uasset", ready_with_texture_pkg()); // helper: Ready{Ok(Arc<Package>)} of a texture
    t.pick_view_after_load("Game/T_Rock.uasset");
    assert_eq!(t.open[0].view, ViewMode::Texture);
}

#[test]
fn pick_view_non_texture_ok_stays_properties() {
    // existing 7a behavior preserved
    let mut t = Tabs::default();
    t.open_or_activate("a.uasset");
    t.set_content("a.uasset", ready_ok_non_texture());
    t.pick_view_after_load("a.uasset");
    assert_eq!(t.open[0].view, ViewMode::Properties);
}

#[test]
fn pick_view_parse_err_still_demotes_to_info() {
    // existing 7a behavior preserved (regression guard)
    let mut t = Tabs::default();
    t.open_or_activate("a.uasset");
    t.set_content("a.uasset", ready_err());
    t.pick_view_after_load("a.uasset");
    assert_eq!(t.open[0].view, ViewMode::Info);
}

#[test]
fn texture_available_false_for_non_texture_and_err() { /* assert both false */ }
```

- [ ] **Step 2: Run → FAIL.**

- [ ] **Step 3: Implement.** Add `ViewMode::Texture`; add `Tab.texture`; change `parsed` to `Arc<Package>` (update the struct + every constructor/match site in tabs.rs); add `texture_available`; extend `pick_view_after_load`:

```rust
pub fn pick_view_after_load(&mut self, path: &str) {
    let Some(tab) = self.open.iter_mut().find(|t| t.path == path) else { return };
    if tab.view != ViewMode::Properties {
        return; // user already switched; respect their choice
    }
    if texture_available(tab) {
        tab.view = ViewMode::Texture;
    } else if matches!(&tab.content, TabContent::Ready { parsed: Err(_), .. }) {
        tab.view = ViewMode::Info;
    }
}
```

- [ ] **Step 4: Run → PASS** (`cargo test -p paksmith-gui tabs`). Fix any `Box`→`Arc` fallout in this file only (downstream files are later tasks).

- [ ] **Step 5: Commit**

```bash
git add crates/paksmith-gui/src/state/tabs.rs
git commit -m "feat(gui): ViewMode::Texture seam + promotion + Arc<Package> tab content"
```

---

## Task 4: Async decode + app message wiring

**Files:**
- Create: `crates/paksmith-gui/src/task/texture.rs`
- Modify: `crates/paksmith-gui/src/task/mod.rs`
- Modify: `crates/paksmith-gui/src/app.rs`
- Modify: `crates/paksmith-gui/Cargo.toml` (enable iced `image` feature)
- Test: `app.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `paksmith_core::asset::{classify_texture, decode_texture_mip}`, `crate::state::tabs::{TabContent, ViewMode, texture_available}`, `crate::state::texture_view::DecodedMip`, `app.archive_generation`, existing `Message::AssetLoaded` flow.
- Produces:
  - `task/texture.rs`: `pub async fn decode(pkg: std::sync::Arc<Package>, export_idx: usize, mip: usize) -> Result<DecodedMip, String>` — calls `decode_texture_mip(&pkg, export_idx, mip)`, maps to `DecodedMip`/stringified error. `#[allow(clippy::unused_async, reason = "async required by iced Task::perform")]` if it ends up sync-bodied; otherwise leave the CPU decode in the async body so `Task::perform` runs it off the UI thread.
  - `Message::DecodeTextureMip { path: String, mip: usize, generation: u64 }` (internal trigger) and `Message::TextureDecoded { path: String, mip: usize, result: Result<DecodedMip, String>, generation: u64 }`.
  - `Message::TextureChannelToggled { channel: Channel }`, `Message::TextureZoomIn`, `Message::TextureZoomOut`, `Message::TextureMipSelected(usize)`, `Message::TexturePan { dx: f32, dy: f32 }` (active-tab-scoped; mutate the active tab's `TextureState`).
  - In `Message::AssetLoaded` handling: after `set_content` + `pick_view_after_load`, if `texture_available(active tab)`, read `classify_texture(pkg).export_idx`, store it on the tab's `TextureState` (add `export_idx: usize` to `TextureState`), and dispatch `Task::perform(task::texture::decode(pkg.clone(), export_idx, 0), move |result| Message::TextureDecoded { path, mip: 0, result, generation })`.
  - `Message::TextureDecoded`: drop if `generation != app.archive_generation`; else write `decoded`/`error` into the matching tab's `TextureState` (only if `mip` still equals the tab's `selected_mip`, else stale mip — drop).
  - `Message::TextureMipSelected(m)`: set `selected_mip = m` on the active tab, dispatch a fresh `decode` for `m`.
  - Channel/zoom/pan messages: mutate the active tab's `TextureState` via a `Tabs::active_tab_mut()` helper (add it if absent); these need no async.

**`Arc<Package>` note:** `pkg.clone()` is a cheap `Arc` clone (Task 3 made `parsed` an `Arc`). Extract `Arc<Package>` from `TabContent::Ready { parsed: Ok(arc), .. }` to move into the task.

- [ ] **Step 1: Enable the iced image feature**

In `crates/paksmith-gui/Cargo.toml`: `iced = { version = "0.14", features = ["tokio", "image"] }`. Run `cargo build -p paksmith-gui` to confirm it resolves.

- [ ] **Step 2: Write a failing test for the decode dispatch + generation fence**

Mirror the existing `app.rs` AssetLoaded tests. Example:

```rust
#[tokio::test]
async fn texture_decoded_stale_generation_is_dropped() {
    let mut app = app_with_texture_archive();
    let _ = update(&mut app, Message::OpenAsset("Game/T_Rock.uasset".into()));
    // ... drive AssetLoaded so the tab is Ready with a texture ...
    let stale = app.archive_generation.wrapping_sub(1);
    let _ = update(&mut app, Message::TextureDecoded {
        path: "Game/T_Rock.uasset".into(), mip: 0,
        result: Ok(DecodedMip { width: 2, height: 2, rgba: vec![0; 16] }),
        generation: stale,
    });
    assert!(app.tabs.active_tab().unwrap().texture.decoded.is_none(),
        "a stale-generation decode must be ignored");
}

#[test]
fn texture_channel_toggle_updates_active_tab_state() {
    let mut app = app_with_open_texture_tab();
    let before = app.tabs.active_tab().unwrap().texture.channels.r;
    let _ = update(&mut app, Message::TextureChannelToggled { channel: Channel::R });
    assert_ne!(app.tabs.active_tab().unwrap().texture.channels.r, before);
}
```

- [ ] **Step 3: Run → FAIL, implement `task/texture.rs` + the `Message` variants + `update` arms, Run → PASS.**

- [ ] **Step 4: Gate + commit**

```bash
cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings && cargo test -p paksmith-gui
git add crates/paksmith-gui/src/task/ crates/paksmith-gui/src/app.rs crates/paksmith-gui/Cargo.toml
git commit -m "feat(gui): async texture decode + message wiring (generation-fenced)"
```

---

## Task 5: TextureViewer widget + content integration

**Files:**
- Create: `crates/paksmith-gui/src/widgets/texture_viewer.rs`
- Modify: `crates/paksmith-gui/src/widgets/mod.rs`
- Modify: `crates/paksmith-gui/src/panels/content.rs`
- Test: thin widget is `#[mutants::skip]`; rely on Task 2/4 state tests. Add a content `view` smoke build only.

**Interfaces:**
- Consumes: `crate::state::texture_view::{TextureState, ChannelSet, Channel, mask_rgba}`, `crate::state::tabs::{Tab, ViewMode, texture_available}`, `Message::{TextureChannelToggled, TextureZoomIn, TextureZoomOut, TextureMipSelected}`, the active accent `iced::Color`.
- Produces: `pub fn view<'a>(state: &TextureState, accent: iced::Color) -> iced::Element<'a, Message>` (the `#[mutants::skip]` widget) following the existing `widgets/hex_view.rs` / `widgets/property_tree.rs` idioms for layout, theming, and message emission.

**Implementation guidance (match the existing widgets — do not invent a new style):**
- Build the image: `iced::widget::image(iced::widget::image::Handle::from_rgba(w, h, mask_rgba(&decoded.rgba, state.channels))).filter_method(iced::widget::image::FilterMethod::Nearest)`. (Constructor is `from_rgba`, NOT `from_rgba8`.)
- Wrap in a fixed pixel size derived from `(w, h) * state.zoom`, inside a `scrollable` (the pan affordance) over a neutral/checkered `container` background.
- Controls row: R/G/B/A toggle buttons (highlight active per `state.channels`, using the accent like the existing view-mode switcher), zoom +/- buttons, and a `pick_list` mip dropdown listing `format!("{i} — {w}×{h}")` from `state.decoded`/the tab's mip list, emitting `Message::TextureMipSelected(i)`.
- Empty/decoding state: when `state.decoded.is_none() && state.error.is_none()`, show a muted "Decoding…" placeholder; when `state.error.is_some()`, show the reason (the post-classification failure path).
- Reuse `widgets/hex_view.rs`'s mouse/scroll handling patterns where applicable; keep ALL arithmetic in `state/texture_view.rs` (the widget only reads state + emits messages).

**`content.rs` integration:**
- Add the arm: `ViewMode::Texture => texture_viewer::view(&tab.texture, accent),`.
- In `view_mode_switcher`, append the **Texture** entry only when `texture_available(tab)` (pass the tab in or a bool); Properties/Hex/Info always present.

- [ ] **Step 1: Implement the widget** (`#[mutants::skip]` on `view`), register in `widgets/mod.rs`.
- [ ] **Step 2: Wire `content.rs`** (arm + conditional switcher entry).
- [ ] **Step 3: Build + smoke**

Run: `cargo build -p paksmith-gui && cargo test -p paksmith-gui`
Expected: compiles; existing + new state tests pass.

- [ ] **Step 4: Manual click-test note** (for the controller, not a blocker): `cargo run -p paksmith-gui`, open a texture asset, verify display + zoom + channel toggles + mip dropdown.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all && cargo clippy -p paksmith-gui --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc -p paksmith-gui --no-deps --all-features && typos .
git add crates/paksmith-gui/src/widgets/ crates/paksmith-gui/src/panels/content.rs
git commit -m "feat(gui): TextureViewer widget + content integration"
```

---

## Final verification (before the whole-branch review)

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
- [ ] `typos .`
- [ ] `cargo mutants --in-diff <git merge-base main HEAD..HEAD> -p paksmith-core --all-features` → 0 missed (Task 1 surface)
- [ ] `cargo mutants --in-diff <…> -p paksmith-gui --all-features` → 0 missed (Tasks 2–5 surface)
- [ ] Adversarial review panel (code-reviewer + architect + simplifier) **+ standing UI/UX reviewer** on `widgets/texture_viewer.rs` + a wire/format-aware reviewer on the core decode API (bounds, OOM cap, virtual-texture path). Converge before push.
- [ ] cargo-deny / cargo-audit note: the iced `image` feature pulls the `image` crate transitively — confirm no NEW advisory fires (or, if an unmaintained-transitive does, handle per the `audit.yml` ignore precedent).

## Self-Review (author's check against the spec)

1. **Spec coverage:** display (T5 image), zoom/pan (T2 math + T5 container), channel isolation (T2 `mask_rgba` + T5 toggles), mip selector (T1 mip list + T4 re-decode + T5 dropdown), public core API (T1), async + generation fence (T4), `ViewMode::Texture`/promotion/fallback (T3), pure-state/thin-view/async split (T2/T5/T4) — all mapped.
2. **Placeholders:** none — every type/fn is named with a concrete signature; test bodies are concrete (fixture helpers reference the existing texture test fixtures the implementer must locate in Step 1 of Task 1).
3. **Type consistency:** `DecodedTextureRgba`/`DecodedMip`/`TextureInfo`/`ChannelSet`/`Channel`/`TextureState` names are used identically across tasks; `parsed: Arc<Package>` introduced in T3 and consumed in T4; `classify_texture`/`decode_texture_mip` signatures fixed in T1 and consumed in T3/T4.
4. **Scope:** one view mode + one core API; no GPU; single plan, no decomposition needed.
