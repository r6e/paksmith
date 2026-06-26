//! Pure texture-view state: channel masking, zoom steps, and fit-to-viewport
//! scaling. No `iced` imports — widget logic consumes this at a higher layer.

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
    let mut out = src.to_vec();
    let count = channels.active_count();

    for px in out.chunks_mut(4) {
        if px.len() < 4 {
            continue;
        }
        if count == 4 {
            // All on — identity, nothing to do.
        } else if count == 1 {
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
    /// Decoded pixel data for the currently displayed mip, if available.
    pub decoded: Option<DecodedMip>,
    /// Error message from the most recent decode attempt, if any.
    pub error: Option<String>,
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
        }
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

    // ── zoom / fit ───────────────────────────────────────────────────────────

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

    // Extra: toggle flips individual channels.
    #[test]
    fn channel_set_toggle_flips_channel() {
        let mut cs = ChannelSet::default();
        cs.toggle(Channel::G);
        assert!(!cs.g);
        assert!(cs.r && cs.b && cs.a);
        cs.toggle(Channel::G);
        assert!(cs.g);
    }
}
