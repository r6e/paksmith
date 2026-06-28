//! Texture-view state: channel masking, zoom steps, and fit-to-viewport
//! scaling. The logic functions ([`mask_rgba`], [`fit_zoom`], the zoom steps)
//! are pure and iced-free so they unit-test without a renderer. The one iced
//! type here is the cached render [`Handle`](iced::widget::image::Handle) on
//! [`TextureState`] (see [`TextureState::render`] for why it is cached), built
//! by [`TextureState::recompute_render`].

/// A single decoded mip level: raw RGBA bytes + dimensions.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedMip {
    pub width: u32,
    pub height: u32,
    /// Raw RGBA bytes, length == width * height * 4.
    pub rgba: Vec<u8>,
}

/// Which RGBA channels are currently visible.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSet {
    pub r: bool,
    pub g: bool,
    pub b: bool,
    pub a: bool,
}

impl Default for ChannelSet {
    fn default() -> Self {
        Self {
            r: true,
            g: true,
            b: true,
            a: true,
        }
    }
}

/// An individual channel selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    R,
    G,
    B,
    A,
}

impl ChannelSet {
    /// Toggle a single channel on/off.
    pub fn toggle(&mut self, ch: Channel) {
        match ch {
            Channel::R => self.r = !self.r,
            Channel::G => self.g = !self.g,
            Channel::B => self.b = !self.b,
            Channel::A => self.a = !self.a,
        }
    }

    fn active_count(self) -> u8 {
        u8::from(self.r) + u8::from(self.g) + u8::from(self.b) + u8::from(self.a)
    }
}

/// Zoom step table. Contains 1.0; has entries both below and above it.
pub const ZOOM_STEPS: &[f32] = &[
    0.0625, 0.125, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0, 8.0,
];

/// Apply channel masking to raw RGBA bytes.
///
/// # Semantics
/// - All four channels on → identity copy.
/// - Exactly one channel on → render as grayscale: R=G=B=that channel's value,
///   A=255.  Applies to single-colour isolations *and* alpha-only.
/// - Otherwise: keep each RGB channel if its flag is set, else 0; keep alpha if
///   its flag is set, else 255 (opaque).
/// - Output length always equals input length. Pixels whose byte-slice is
///   shorter than 4 (trailing partial pixel) are left unchanged.
#[must_use]
pub fn mask_rgba(src: &[u8], channels: ChannelSet) -> Vec<u8> {
    let count = channels.active_count();

    // All four channels on is the identity copy — skip the per-pixel loop.
    if count == 4 {
        return src.to_vec();
    }

    let mut out = src.to_vec();
    for px in out.chunks_mut(4) {
        if px.len() < 4 {
            continue;
        }
        if count == 1 {
            // Single-channel grayscale.
            let val = if channels.r {
                px[0]
            } else if channels.g {
                px[1]
            } else if channels.b {
                px[2]
            } else {
                px[3] // alpha-only
            };
            px[0] = val;
            px[1] = val;
            px[2] = val;
            px[3] = 255;
        } else {
            // Multi-channel: per-channel keep-or-zero, alpha keep-or-opaque.
            if !channels.r {
                px[0] = 0;
            }
            if !channels.g {
                px[1] = 0;
            }
            if !channels.b {
                px[2] = 0;
            }
            if !channels.a {
                px[3] = 255;
            }
        }
    }

    out
}

/// Compute zoom level that fits `img` entirely within `viewport`, preserving
/// aspect ratio. Returns the minimum of the two axis scales.
///
/// `viewport` dimensions must be positive; returns 1.0 as a safe fallback
/// for degenerate inputs.
#[must_use]
#[allow(clippy::cast_precision_loss)] // texture dims ≤ 16384 are exact in f32
pub fn fit_zoom(img: (u32, u32), viewport: (f32, f32)) -> f32 {
    let (iw, ih) = img;
    let (vw, vh) = viewport;
    if iw == 0 || ih == 0 || vw <= 0.0 || vh <= 0.0 {
        return 1.0;
    }
    let sx = vw / iw as f32;
    let sy = vh / ih as f32;
    sx.min(sy)
}

/// Snap `z` to the next higher step in `ZOOM_STEPS`. If already at or above
/// the maximum step, returns the maximum.
#[must_use]
pub fn zoom_in(z: f32) -> f32 {
    ZOOM_STEPS
        .iter()
        .copied()
        .find(|&s| s > z)
        .unwrap_or_else(|| *ZOOM_STEPS.last().expect("ZOOM_STEPS is non-empty"))
}

/// Snap `z` to the next lower step in `ZOOM_STEPS`. If already at or below
/// the minimum step, returns the minimum.
#[must_use]
pub fn zoom_out(z: f32) -> f32 {
    ZOOM_STEPS
        .iter()
        .copied()
        .rev()
        .find(|&s| s < z)
        .unwrap_or_else(|| *ZOOM_STEPS.first().expect("ZOOM_STEPS is non-empty"))
}

/// All view state for the texture inspector panel.
#[derive(Debug, Clone)]
pub struct TextureState {
    /// Export index within the `Package` that holds the texture.
    ///
    /// Set by the `AssetLoaded` handler via `classify_texture`; used when
    /// dispatching a decode task. Defaults to `0` (harmless sentinel when no
    /// texture is loaded — decode tasks are only dispatched when a real export
    /// index is known).
    pub export_idx: usize,
    /// Available mip dimensions `(width, height)` for the loaded texture, in
    /// highest-to-lowest resolution order.  Empty until a texture is loaded.
    ///
    /// Also serves as the per-frame "decodable texture loaded" signal for
    /// [`texture_available`](crate::state::tabs::texture_available): non-empty
    /// iff the tab's current content is a decodable texture. `Tabs::set_content`
    /// resets this state on any content swap, keeping that equivalence coherent.
    pub mips: Vec<(u32, u32)>,
    /// Index into the decoded mip chain.
    pub selected_mip: usize,
    /// Active channel visibility flags.
    pub channels: ChannelSet,
    /// Current zoom factor (1.0 = 100 %).
    pub zoom: f32,
    /// When `true`, the image area uses `fit_zoom` to scale the texture to fill
    /// the available space.  Automatically reverts to `false` when the user
    /// manually zooms in or out via the `+`/`−` buttons.
    ///
    /// In manual-zoom mode the image is wrapped in a `scrollable`, which owns
    /// panning natively (scrollbars + trackpad/wheel, clamped to content bounds)
    /// — the widget keeps no separate pan offset.
    pub fit_to_window: bool,
    /// Decoded pixel data for the currently displayed mip, if available. A
    /// successful decode sets this; a *failed* decode leaves the previous value
    /// in place (C18) so the last-good image stays on screen, so `decoded` and
    /// [`Self::error`] can both be `Some` at once — see [`Self::has_retained_error`].
    pub decoded: Option<DecodedMip>,
    /// Error message from the most recent decode attempt, if any. Set when a
    /// decode fails; cleared by a *successful* decode (the `TextureDecoded` Ok
    /// arm) or by selecting another mip (`TextureMipSelected`, which clears it
    /// before redispatching), and — like every field here — implicitly reset
    /// when `Tabs::set_content` replaces the tab's content on a content swap.
    /// It is otherwise independent of [`Self::decoded`]: toggling channels on a
    /// retained image re-masks the image but leaves the error (and its banner)
    /// standing, because the failed mip is still failed.
    pub error: Option<String>,
    /// Cached iced render handle for `decoded` under `channels`.
    ///
    /// Kept in sync with `(decoded, channels)` by [`Self::recompute_render`],
    /// which the message handlers call whenever either changes. The widget
    /// clones this handle each `view()` (which fires on every redraw — resize
    /// drags, hover, etc.) instead of rebuilding it: the channel mask, the
    /// buffer allocation, and the GPU upload all happen once per state change
    /// rather than per frame. A cloned [`Handle`](iced::widget::image::Handle)
    /// keeps the same `Id` (and its pixel `Bytes` are reference-counted, so the
    /// clone is O(1)), which lets iced's raster cache reuse the existing upload.
    /// `None` whenever `decoded` is.
    ///
    /// This handle owns the channel-masked pixel buffer — a second full-size
    /// allocation that coexists with [`Self::decoded`]. See the `render_handle`
    /// builder's `# Memory` note for the resulting per-mip memory tradeoff.
    pub render: Option<iced::widget::image::Handle>,
}

impl Default for TextureState {
    fn default() -> Self {
        Self {
            export_idx: 0,
            mips: Vec::new(),
            selected_mip: 0,
            channels: ChannelSet::default(),
            zoom: 1.0,
            fit_to_window: true,
            decoded: None,
            error: None,
            render: None,
        }
    }
}

/// Build the iced render handle for a decoded mip under a channel set:
/// [`mask_rgba`] produces the display buffer, which is then moved into an RGBA
/// image handle. Shared by [`TextureState::recompute_render`] (the cached path)
/// and the widget's cache-miss fallback so the two builds can never drift.
///
/// # Memory
/// [`mask_rgba`] always returns a fresh buffer the same length as its input
/// (even the all-channels-on identity branch copies), and that buffer is
/// *moved* — not copied — into the handle. It coexists with the source pixels
/// still held in [`TextureState::decoded`], so at rest one open texture tab
/// holds ≈ 2× a single decoded mip (retained source + masked handle). During a
/// rebuild ([`TextureState::recompute_render`] or a landing decode) the peak is
/// ≈ 3× for one mip: Rust evaluates the new masked buffer before dropping the
/// old handle, so source, old handle, and new buffer are briefly all live. Each
/// decoded mip is bounded by the core `MAX_DECODED_TEXTURE_BYTES` cap (1 GiB at
/// the 16384² worst case), making the transient ceiling ≈ 3 GiB; only one mip is
/// ever retained — selecting another replaces `decoded`, it does not accumulate.
///
/// This is a deliberate space-for-time tradeoff: retaining `decoded` lets a
/// channel toggle re-mask instantly with no re-decode, and caching the handle
/// (see [`TextureState::render`]) lets every redraw skip the mask and GPU
/// upload. For any actual channel isolation the masked bytes differ from the
/// source, so the second allocation is inherent regardless of API or
/// dependencies; only the all-channels-on identity copy could be shared, and
/// that alone would need `bytes::Bytes` as a direct dependency (`iced` exposes
/// no public path to its `Bytes` type), which the crate's no-new-dependencies
/// constraint rules out. The behavioural alternatives — re-decoding per toggle
/// or a GPU shader mask — are the slower / explicitly-rejected `wgpu` paths.
pub(crate) fn render_handle(d: &DecodedMip, channels: ChannelSet) -> iced::widget::image::Handle {
    iced::widget::image::Handle::from_rgba(d.width, d.height, mask_rgba(&d.rgba, channels))
}

impl TextureState {
    /// Rebuild the cached [`Self::render`] handle from the current `decoded`
    /// mip and `channels`. Call after every mutation of `decoded` or `channels`
    /// to preserve the invariant `render == decoded.map(|d| render_handle(d, ch))`.
    ///
    /// A fresh handle gets a fresh `Id`, so every call here invalidates iced's
    /// raster cache exactly once, and intervening redraws (which clone the
    /// handle) reuse the upload.
    ///
    /// Deliberately NOT called on mip *selection* (which leaves `decoded`
    /// untouched until the new mip's async decode lands): the old handle still
    /// matches the still-displayed old mip, so the viewer keeps showing it
    /// until `TextureDecoded` arrives and rebuilds.
    pub fn recompute_render(&mut self) {
        self.render = self
            .decoded
            .as_ref()
            .map(|d| render_handle(d, self.channels));
    }

    /// Whether a decoded image is retained *and* a new decode error is pending
    /// (both [`Self::decoded`] and [`Self::error`] are `Some`). This is the
    /// "failed re-select" case: the viewer keeps the last-good image (C18) and
    /// the widget surfaces the error as a compact banner above it. When no image
    /// is retained (`decoded` is `None`) the error fills the content area
    /// instead, so no banner is shown.
    ///
    /// Lives here, not inline in the `#[mutants::skip]` widget, so the
    /// banner-vs-placeholder decision is unit-testable and mutation-covered.
    #[must_use]
    pub fn has_retained_error(&self) -> bool {
        self.decoded.is_some() && self.error.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── mask_rgba ──────────────────────────────────────────────────────────────

    #[test]
    fn mask_identity_when_all_channels_on() {
        let src = vec![10, 20, 30, 40, 50, 60, 70, 80];
        assert_eq!(mask_rgba(&src, ChannelSet::default()), src);
    }

    #[test]
    fn mask_single_channel_is_grayscale() {
        // one RGBA pixel (R=10,G=20,B=30,A=40); isolate G → 20,20,20,255
        let out = mask_rgba(
            &[10, 20, 30, 40],
            ChannelSet {
                r: false,
                g: true,
                b: false,
                a: false,
            },
        );
        assert_eq!(out, vec![20, 20, 20, 255]);
    }

    #[test]
    fn mask_alpha_off_forces_opaque() {
        let out = mask_rgba(
            &[10, 20, 30, 40],
            ChannelSet {
                r: true,
                g: true,
                b: true,
                a: false,
            },
        );
        assert_eq!(out, vec![10, 20, 30, 255]);
    }

    #[test]
    fn mask_alpha_only_shows_alpha_as_gray() {
        let out = mask_rgba(
            &[10, 20, 30, 40],
            ChannelSet {
                r: false,
                g: false,
                b: false,
                a: true,
            },
        );
        assert_eq!(out, vec![40, 40, 40, 255]);
    }

    #[test]
    fn mask_preserves_length() {
        let src = vec![1u8; 4 * 7];
        assert_eq!(
            mask_rgba(
                &src,
                ChannelSet {
                    r: true,
                    g: false,
                    b: true,
                    a: true
                }
            )
            .len(),
            src.len()
        );
    }

    // Extra: pin a two-channel-on case so the multi-channel branch is explicit.
    #[test]
    fn mask_two_channels_on_keeps_those_zero_others() {
        // R + B on, G + A off → G=0, A=255
        let out = mask_rgba(
            &[10, 20, 30, 40],
            ChannelSet {
                r: true,
                g: false,
                b: true,
                a: false,
            },
        );
        assert_eq!(out, vec![10, 0, 30, 255]);
    }

    // Extra: all channels off (active_count == 0) → the multi-channel branch
    // zeroes every colour channel and forces alpha opaque, yielding opaque
    // black. Pins the "none" golden buffer (design doc) so the count==0 path
    // can't regress (e.g. a stray `count == 0` special-case).
    #[test]
    fn mask_all_channels_off_is_opaque_black() {
        let out = mask_rgba(
            &[10, 20, 30, 40, 200, 150, 100, 50],
            ChannelSet {
                r: false,
                g: false,
                b: false,
                a: false,
            },
        );
        assert_eq!(out, vec![0, 0, 0, 255, 0, 0, 0, 255]);
    }

    // Extra: single R channel grayscale.
    #[test]
    fn mask_single_r_channel_is_grayscale() {
        let out = mask_rgba(
            &[100, 50, 10, 200],
            ChannelSet {
                r: true,
                g: false,
                b: false,
                a: false,
            },
        );
        assert_eq!(out, vec![100, 100, 100, 255]);
    }

    // Extra: single B channel grayscale.
    #[test]
    fn mask_single_b_channel_is_grayscale() {
        let out = mask_rgba(
            &[100, 50, 77, 200],
            ChannelSet {
                r: false,
                g: false,
                b: true,
                a: false,
            },
        );
        assert_eq!(out, vec![77, 77, 77, 255]);
    }

    // Extra: empty input survives.
    #[test]
    fn mask_empty_input() {
        assert_eq!(mask_rgba(&[], ChannelSet::default()), Vec::<u8>::new());
    }

    // Extra: a trailing partial pixel (< 4 bytes) is passed through untouched.
    // Pins the `px.len() < 4` guard: the `< -> >` mutant would fail to skip the
    // 1-byte chunk and index past it (panic on px[0..]).
    #[test]
    fn mask_partial_trailing_pixel_left_unchanged() {
        // one full RGBA pixel + a 1-byte partial.
        let src = vec![10, 20, 30, 40, 99];
        let out = mask_rgba(
            &src,
            ChannelSet {
                r: true,
                g: false,
                b: false,
                a: false,
            },
        );
        assert_eq!(out.len(), 5, "length must be preserved");
        assert_eq!(out[4], 99, "trailing partial byte must be left unchanged");
    }

    // ── zoom / fit ───────────────────────────────────────────────────────────

    #[test]
    fn fit_zoom_scales_to_fit_smaller_axis() {
        // 200x100 image into 100x100 viewport → fit = 0.5
        assert!((fit_zoom((200, 100), (100.0, 100.0)) - 0.5).abs() < f32::EPSILON);
    }

    // Extra: a taller-than-wide image is limited by its height axis. Pins the
    // `sy = vh / ih` division: the `/ -> *` mutant would make sy huge so the
    // width axis (1.0) would win, returning 1.0 instead of 0.5.
    #[test]
    fn fit_zoom_scales_to_fit_taller_axis() {
        // 100x200 image into 100x100 viewport → height-limited → fit = 0.5
        assert!((fit_zoom((100, 200), (100.0, 100.0)) - 0.5).abs() < f32::EPSILON);
    }

    // Extra: each degenerate condition independently returns 1.0. Pins the three
    // `||` operators in the guard — a `|| -> &&` flip on any one would let a
    // single-zero case fall through to a divide-by-zero scale.
    #[test]
    #[allow(clippy::float_cmp)]
    fn fit_zoom_single_zero_dimension_returns_one() {
        assert_eq!(fit_zoom((0, 5), (100.0, 100.0)), 1.0, "zero width only");
        assert_eq!(fit_zoom((5, 0), (100.0, 100.0)), 1.0, "zero height only");
        assert_eq!(
            fit_zoom((100, 100), (0.0, 100.0)),
            1.0,
            "zero viewport width only"
        );
        assert_eq!(
            fit_zoom((100, 100), (100.0, 0.0)),
            1.0,
            "zero viewport height only"
        );
    }

    #[test]
    fn zoom_in_then_out_returns_to_neighbourhood() {
        let z = 1.0;
        assert!(zoom_in(z) > z);
        assert!(zoom_out(zoom_in(z)) <= zoom_in(z));
    }

    // Extra: zoom_out saturates at minimum.
    #[test]
    #[allow(clippy::float_cmp)]
    fn zoom_out_saturates_at_minimum() {
        assert_eq!(zoom_out(ZOOM_STEPS[0]), ZOOM_STEPS[0]);
    }

    // Extra: zoom_in saturates at maximum.
    #[test]
    #[allow(clippy::float_cmp)]
    fn zoom_in_saturates_at_maximum() {
        let max = *ZOOM_STEPS.last().unwrap();
        assert_eq!(zoom_in(max), max);
    }

    // Extra: fit_zoom degenerate cases return 1.0.
    #[test]
    #[allow(clippy::float_cmp)]
    fn fit_zoom_degenerate_returns_one() {
        assert_eq!(fit_zoom((0, 0), (100.0, 100.0)), 1.0);
        assert_eq!(fit_zoom((100, 100), (0.0, 0.0)), 1.0);
    }

    // Extra: ChannelSet default is all-on.
    #[test]
    fn channel_set_default_is_all_on() {
        let cs = ChannelSet::default();
        assert!(cs.r && cs.g && cs.b && cs.a);
    }

    // Extra: TextureState default has zoom 1.0.
    #[test]
    #[allow(clippy::float_cmp)]
    fn texture_state_default_zoom_is_one() {
        assert_eq!(TextureState::default().zoom, 1.0);
    }

    // Extra: TextureState default has fit_to_window = true.
    #[test]
    fn texture_state_default_fit_to_window_is_true() {
        assert!(TextureState::default().fit_to_window);
    }

    // Extra: toggle flips each channel independently (covers all four match
    // arms so the `delete !` mutant survives on none of them).
    #[test]
    fn channel_set_toggle_flips_each_channel() {
        let get = |cs: &ChannelSet, ch: Channel| match ch {
            Channel::R => cs.r,
            Channel::G => cs.g,
            Channel::B => cs.b,
            Channel::A => cs.a,
        };
        for ch in [Channel::R, Channel::G, Channel::B, Channel::A] {
            let mut cs = ChannelSet::default(); // all on
            cs.toggle(ch);
            assert!(!get(&cs, ch), "toggling {ch:?} once must set it false");
            cs.toggle(ch);
            assert!(get(&cs, ch), "toggling {ch:?} twice must restore true");
        }
    }

    // ── recompute_render ───────────────────────────────────────────────────────

    fn one_pixel(rgba: [u8; 4]) -> DecodedMip {
        DecodedMip {
            width: 1,
            height: 1,
            rgba: rgba.to_vec(),
        }
    }

    #[test]
    fn one_pixel_helper_pins_emitted_fields() {
        // `one_pixel`'s hardcoded dims aren't read by the mask tests, so this
        // reads every emitted field to kill the struct-field-deletion mutants.
        let p = one_pixel([9, 8, 7, 6]);
        assert_eq!((p.width, p.height), (1, 1));
        assert_eq!(p.rgba, vec![9, 8, 7, 6]);
    }

    /// Destructure a render handle into `(width, height, pixels)` so tests can
    /// assert the cached upload's dimensions and masked bytes directly.
    fn handle_parts(h: &iced::widget::image::Handle) -> (u32, u32, &[u8]) {
        match h {
            iced::widget::image::Handle::Rgba {
                width,
                height,
                pixels,
                ..
            } => (*width, *height, pixels.as_ref()),
            other => panic!("expected an Rgba handle, got {other:?}"),
        }
    }

    #[test]
    fn recompute_render_is_none_without_decoded() {
        let mut st = TextureState::default();
        st.recompute_render();
        assert!(st.render.is_none(), "no decoded mip → render stays None");
    }

    #[test]
    fn recompute_render_builds_handle_from_masked_decoded() {
        // Isolate green so the result differs from the identity buffer — this
        // proves the mask is actually applied, not just copied, and that the
        // handle carries the decoded mip's dimensions.
        let mut st = TextureState {
            decoded: Some(one_pixel([10, 20, 30, 40])),
            channels: ChannelSet {
                r: false,
                g: true,
                b: false,
                a: false,
            },
            ..TextureState::default()
        };
        st.recompute_render();
        let handle = st.render.as_ref().expect("decoded mip → render is Some");
        let (w, h, pixels) = handle_parts(handle);
        assert_eq!((w, h), (1, 1), "handle must carry the decoded mip's dims");
        assert_eq!(
            pixels,
            mask_rgba(&[10, 20, 30, 40], st.channels).as_slice(),
            "handle pixels must equal mask_rgba(decoded.rgba, channels)"
        );
        assert_ne!(
            pixels,
            [10u8, 20, 30, 40].as_slice(),
            "single-channel mask must not equal the unmasked source"
        );
    }

    #[test]
    fn recompute_render_rebuilds_with_fresh_id_on_channel_change() {
        // The cache is keyed on handle identity: a rebuild must mint a fresh
        // `Id` so iced re-uploads the newly masked pixels. A handle left in
        // place (no rebuild) would keep its old `Id` and show stale pixels.
        let mut st = TextureState {
            decoded: Some(one_pixel([10, 20, 30, 40])),
            ..TextureState::default()
        };
        st.recompute_render();
        let id_before = st.render.as_ref().expect("render Some").id();

        st.channels = ChannelSet {
            r: false,
            g: true,
            b: false,
            a: false,
        };
        st.recompute_render();
        let id_after = st.render.as_ref().expect("render Some").id();

        assert_ne!(
            id_before, id_after,
            "rebuilding the render handle must mint a fresh Id (cache invalidation)"
        );
    }

    #[test]
    fn recompute_render_clears_when_decoded_removed() {
        let mut st = TextureState {
            decoded: Some(one_pixel([1, 2, 3, 4])),
            ..TextureState::default()
        };
        st.recompute_render();
        assert!(
            st.render.is_some(),
            "render populated while decoded is Some"
        );
        st.decoded = None;
        st.recompute_render();
        assert!(
            st.render.is_none(),
            "render must clear once decoded is removed"
        );
    }

    // `has_retained_error` is the banner-vs-placeholder decision (C18). All four
    // (decoded, error) combinations are pinned so the `&&` and both `is_some()`
    // operands are mutation-covered: only the retained-image-plus-error case is
    // true, every other case is false.
    #[test]
    fn has_retained_error_true_only_with_image_and_error() {
        let st = TextureState {
            decoded: Some(one_pixel([1, 2, 3, 4])),
            error: Some("boom".to_string()),
            ..TextureState::default()
        };
        assert!(
            st.has_retained_error(),
            "a retained image plus a decode error must report a retained error"
        );
    }

    #[test]
    fn has_retained_error_false_with_image_and_no_error() {
        let st = TextureState {
            decoded: Some(one_pixel([1, 2, 3, 4])),
            error: None,
            ..TextureState::default()
        };
        assert!(
            !st.has_retained_error(),
            "an image with no error is the normal state, not a retained error"
        );
    }

    #[test]
    fn has_retained_error_false_with_error_and_no_image() {
        let st = TextureState {
            decoded: None,
            error: Some("boom".to_string()),
            ..TextureState::default()
        };
        assert!(
            !st.has_retained_error(),
            "an error with no retained image fills the content area, not a banner"
        );
    }

    #[test]
    fn has_retained_error_false_when_empty() {
        let st = TextureState::default();
        assert!(
            !st.has_retained_error(),
            "neither image nor error must not report a retained error"
        );
    }
}
