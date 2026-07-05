//! Waveform canvas widget for the audio player.
//!
//! Draws a column-per-peak waveform with a playhead line and emits
//! [`crate::app::Message::AudioSeek`] on left-press inside the canvas.  The full
//! widget is rendering/hit-test glue; all pure logic lives in
//! [`crate::state::audio_view`].

use iced::widget::{button, canvas, column, container, row, slider, text};
use iced::{Color, Element, Length, Point, Rectangle, Renderer, Theme};

use crate::app::Message;
use crate::state::audio_view::{AudioState, Transport, format_time};
use crate::theme::tokens::{
    SPACE_LG, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_MD, TEXT_MUTED_ALPHA, TEXT_SM,
};

// ── canvas height (pixels) ────────────────────────────────────────────────────

/// Pixel height of the rendered waveform canvas.
const WAVEFORM_HEIGHT: f32 = 80.0;

// ── Waveform struct ───────────────────────────────────────────────────────────

/// A `canvas::Program` that renders a waveform + playhead and emits
/// [`Message::AudioSeek`] on click.
///
/// The `draw`/`update` methods are `#[mutants::skip]` rendering/hit-test glue;
/// the only pure logic (the click → seek fraction) is extracted to the tested
/// [`seek_fraction_from_x`].
struct Waveform<'a> {
    /// Pre-computed per-column (min, max) amplitude pairs in `[-1.0, 1.0]`.
    peaks: &'a [(f32, f32)],
    /// Current playhead position as a fraction of the total duration (`0.0`–`1.0`).
    playhead_frac: f32,
    /// Accent colour used for the playhead line.
    accent: Color,
}

impl canvas::Program<Message> for Waveform<'_> {
    type State = ();

    // Event plumbing glue (iced `Cursor`/`Event` aren't unit-constructible); the
    // seek-fraction math it delegates to is pinned by `seek_fraction_from_x`.
    #[mutants::skip]
    fn update(
        &self,
        _state: &mut Self::State,
        event: &canvas::Event,
        bounds: Rectangle,
        cursor: iced::mouse::Cursor,
    ) -> Option<canvas::Action<Message>> {
        // Emit a seek message on left-button press inside the canvas.
        let iced::Event::Mouse(iced::mouse::Event::ButtonPressed(iced::mouse::Button::Left)) =
            event
        else {
            return None;
        };
        // `pos.x` is already relative to `bounds.x` (origin = top-left of canvas).
        let pos = cursor.position_in(bounds)?;
        let frac = seek_fraction_from_x(pos.x, bounds.width);
        Some(canvas::Action::publish(Message::AudioSeek(frac)).and_capture())
    }

    // Pure rendering glue (coordinate math → iced geometry); visual correctness
    // is verified by manual smoke, not unit tests.
    #[mutants::skip]
    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        theme: &Theme,
        bounds: Rectangle,
        _cursor: iced::mouse::Cursor,
    ) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let half_h = bounds.height / 2.0;

        // ── waveform bars ─────────────────────────────────────────────────────
        let num_cols = self.peaks.len();
        if num_cols > 0 {
            let bar_color = theme.palette().text.scale_alpha(0.4);
            #[allow(clippy::cast_precision_loss)]
            // `num_cols` is WAVEFORM_COLUMNS (512), which fits exactly in f32
            // (2^9 < 2^24 mantissa bits); no precision loss.
            let col_width = bounds.width / num_cols as f32;

            for (i, &(min_amp, max_amp)) in self.peaks.iter().enumerate() {
                // Centre x of this column.
                #[allow(clippy::cast_precision_loss)]
                // Column index ≤ 512; fits exactly in f32.
                let x = (i as f32 + 0.5) * col_width;

                // Map amplitude [-1, 1] to y coords (y = 0 at top, half_h at
                // centre/silence, height at bottom).
                let y_top = half_h - max_amp.clamp(-1.0, 1.0) * half_h;
                let y_bot = half_h - min_amp.clamp(-1.0, 1.0) * half_h;
                // Guarantee at least 1 px height even for silence.
                let y_bot = y_bot.max(y_top + 1.0);

                let path = canvas::Path::line(Point::new(x, y_top), Point::new(x, y_bot));
                frame.stroke(
                    &path,
                    canvas::Stroke::default()
                        .with_color(bar_color)
                        .with_width(col_width.max(1.0)),
                );
            }
        }

        // ── playhead line ─────────────────────────────────────────────────────
        let ph_x = (self.playhead_frac * bounds.width).clamp(0.0, bounds.width);
        let ph_path = canvas::Path::line(Point::new(ph_x, 0.0), Point::new(ph_x, bounds.height));
        frame.stroke(
            &ph_path,
            canvas::Stroke::default()
                .with_color(self.accent)
                .with_width(2.0),
        );

        vec![frame.into_geometry()]
    }
}

// ── public factory ────────────────────────────────────────────────────────────

/// Build a waveform canvas element from the current [`AudioState`].
///
/// `accent` is the theme colour used for the playhead line (typically the
/// theme's primary accent). The canvas fills its parent's width and is fixed
/// at [`WAVEFORM_HEIGHT`] pixels tall.
///
/// Task 10 places this element inside the full audio-player view.
// Rendering glue: not tested directly — visual correctness is verified via
// manual smoke (Task 9 Step 3).
#[mutants::skip]
pub fn waveform_canvas(state: &AudioState, accent: Color) -> Element<'_, Message> {
    let playhead_frac = if state.duration_secs() > 0.0 {
        (state.position_secs / state.duration_secs()).clamp(0.0, 1.0)
    } else {
        0.0
    };
    iced::widget::canvas(Waveform {
        peaks: &state.waveform,
        playhead_frac,
        accent,
    })
    .width(Length::Fill)
    .height(Length::Fixed(WAVEFORM_HEIGHT))
    .into()
}

// ── audio-player view ─────────────────────────────────────────────────────────

/// Render the audio-player panel for the given [`AudioState`].
///
/// Layout, top to bottom:
/// - a one-line metadata header (codec, channels, duration, and — once the clip
///   is decoded — the sample rate), always shown;
/// - the decode/playback error, if any, on a danger-coloured line beneath the
///   header (non-fatal: the rest of the view still renders);
/// - for a **playable** codec, the waveform overview (or a muted "Decoding…"
///   line while the first decode is in flight) followed by a transport row
///   (play/pause, stop, a volume slider, and a `position / duration` readout);
/// - for a **non-playable** codec, a hint pointing the user at Export As… to save
///   the raw stream, with no transport controls.
///
/// `accent` is the theme accent colour, used for the waveform playhead.
///
/// This function is `#[mutants::skip]` rendering glue; the two pieces of pure
/// logic it delegates to ([`play_pause_label`] and [`metadata_summary`]) are
/// unit-tested below.
#[mutants::skip]
pub fn view<'a>(state: &'a AudioState, accent: Color) -> Element<'a, Message> {
    let Some(info) = state.info.as_ref() else {
        // Defensive: the content host only routes audio tabs here (their `info`
        // is `Some`), so this placeholder should never actually surface.
        return centered_muted("No audio");
    };

    // ── metadata header (always) ──────────────────────────────────────────────
    let sample_rate = state.decoded.as_ref().map(|d| d.sample_rate);
    let header = text(metadata_summary(
        &info.codec_label,
        info.channels,
        state.duration_secs(),
        sample_rate,
    ))
    .size(f32::from(TEXT_MD));

    let mut children: Vec<Element<'a, Message>> = vec![header.into()];

    // Decode/playback error, non-fatal: shown beneath the header while the rest
    // of the view still renders.
    if let Some(err) = state.error.as_ref() {
        children.push(error_line(err.clone()));
    }

    if info.playable {
        // Waveform once decoded; otherwise a muted "Decoding…" line — but not
        // when an error is already shown (that line stands in for it).
        if state.decoded.is_some() {
            children.push(waveform_canvas(state, accent));
        } else if state.error.is_none() {
            children.push(muted_line("Decoding\u{2026}".to_owned()));
        }
        children.push(transport_row(state));
    } else {
        children.push(muted_line(format!(
            "Codec {} can't be decoded in-app \u{2014} use Export As\u{2026} to save the raw stream.",
            info.codec_label
        )));
    }

    container(column(children).spacing(SPACE_MD).width(Length::Fill))
        .padding(SPACE_LG)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Transport controls row: play/pause, stop, a volume slider, and the
/// `position / duration` readout. Nothing here borrows `state` (all values are
/// copied or owned), so the element is `'static`.
#[mutants::skip]
fn transport_row(state: &AudioState) -> Element<'static, Message> {
    let play_pause = button(text(play_pause_label(state.transport)).size(f32::from(TEXT_SM)))
        .on_press(Message::AudioPlayPause)
        .padding([SPACE_XS, SPACE_SM])
        .style(iced::widget::button::secondary);

    let stop = button(text("Stop").size(f32::from(TEXT_SM)))
        .on_press(Message::AudioStop)
        .padding([SPACE_XS, SPACE_SM])
        .style(iced::widget::button::secondary);

    // Explicit 0.01 step: a slider's default step is `1`, which on a `0.0..=1.0`
    // range would snap the volume to only 0 % or 100 %.
    let volume = slider(0.0..=1.0, state.volume, Message::AudioVolume)
        .step(0.01_f32)
        .width(Length::Fixed(140.0));

    let readout = text(format!(
        "{} / {}",
        format_time(state.position_secs),
        format_time(state.duration_secs()),
    ))
    .size(f32::from(TEXT_SM));

    row![play_pause, stop, volume, readout]
        .spacing(SPACE_SM)
        .align_y(iced::Alignment::Center)
        .into()
}

/// Label for the play/pause button: `"Pause"` while playing, `"Play"` in either
/// idle state.
fn play_pause_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Playing => "Pause",
        Transport::Stopped | Transport::Paused => "Play",
    }
}

/// Build the one-line metadata summary shown above the waveform.
///
/// Joins the codec label, channel count (`"{n} ch"`, or an em-dash when
/// unknown), the formatted duration, and — once `sample_rate` is `Some` (i.e. the
/// clip has been decoded) — the sample rate, with a middle-dot separator.
fn metadata_summary(
    codec_label: &str,
    channels: Option<u16>,
    duration_secs: f32,
    sample_rate: Option<u32>,
) -> String {
    let channels = match channels {
        Some(n) => format!("{n} ch"),
        None => "\u{2014}".to_owned(),
    };
    // Precompute the (optional) sample-rate suffix so the summary is built with a
    // single `format!` — avoids `push_str(&format!(..))` (clippy::format_push_string).
    let rate_suffix = match sample_rate {
        Some(rate) => format!(" \u{b7} {rate} Hz"),
        None => String::new(),
    };
    format!(
        "{codec_label} \u{b7} {channels} \u{b7} {}{rate_suffix}",
        format_time(duration_secs)
    )
}

/// Muted text style (foreground scaled by [`TEXT_MUTED_ALPHA`]). Shared by
/// [`muted_line`] and [`centered_muted`] so the alpha lives in one place.
///
/// `#[mutants::skip]`: render glue (theme → `Style`), the same untested-by-design
/// category as the `#[mutants::skip]` view functions it feeds; visual correctness
/// is verified by manual smoke, and a `Default::default()` mutant only changes the
/// muted colour, not behavior.
#[mutants::skip]
fn muted_text_style(theme: &iced::Theme) -> iced::widget::text::Style {
    iced::widget::text::Style {
        color: Some(theme.palette().text.scale_alpha(TEXT_MUTED_ALPHA)),
    }
}

/// A muted single-line text element (in-flight "Decoding…" and the non-playable
/// export hint).
#[mutants::skip]
fn muted_line(msg: String) -> Element<'static, Message> {
    text(msg)
        .size(f32::from(TEXT_SM))
        .style(muted_text_style)
        .into()
}

/// A danger-coloured single-line error element, shown beneath the header when a
/// decode or playback attempt failed.
#[mutants::skip]
fn error_line(msg: String) -> Element<'static, Message> {
    text(msg)
        .size(f32::from(TEXT_SM))
        .style(|theme: &iced::Theme| iced::widget::text::Style {
            color: Some(theme.palette().danger),
        })
        .into()
}

/// A muted placeholder centred in the full viewport (the `info.is_none()` guard).
#[mutants::skip]
fn centered_muted(msg: &'static str) -> Element<'static, Message> {
    container(text(msg).size(f32::from(TEXT_MD)).style(muted_text_style))
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

/// Map a click x-coordinate (relative to the canvas left edge) and the canvas
/// width to a seek fraction in `[0.0, 1.0]`. A zero/negative width returns
/// `0.0`, guarding the caller against a NaN/inf fraction from division by zero.
fn seek_fraction_from_x(x: f32, width: f32) -> f32 {
    if width <= 0.0 {
        return 0.0;
    }
    (x / width).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::{metadata_summary, play_pause_label, seek_fraction_from_x};
    use crate::state::audio_view::Transport;

    #[test]
    fn play_pause_label_reflects_transport() {
        // Playing → "Pause"; both idle states → "Play". Divergent labels kill a
        // match-arm swap (Playing → "Play" would fail here).
        assert_eq!(play_pause_label(Transport::Playing), "Pause");
        assert_eq!(play_pause_label(Transport::Paused), "Play");
        assert_eq!(play_pause_label(Transport::Stopped), "Play");
    }

    #[test]
    fn metadata_summary_joins_all_fields_when_decoded() {
        // Fully populated: codec · channels · duration · sample rate. Distinct,
        // asymmetric values pin the field order and every separator.
        let s = metadata_summary("Vorbis (Ogg)", Some(2), 3.0, Some(44_100));
        assert_eq!(s, "Vorbis (Ogg) \u{b7} 2 ch \u{b7} 0:03 \u{b7} 44100 Hz");
    }

    #[test]
    fn metadata_summary_omits_sample_rate_until_decoded() {
        // sample_rate None (pre-decode) → no " · NNNN Hz" tail. Pins the branch
        // that appends the rate against a mutant that always/never appends it.
        let s = metadata_summary("PCM", Some(1), 1.0, None);
        assert_eq!(s, "PCM \u{b7} 1 ch \u{b7} 0:01");
    }

    #[test]
    fn metadata_summary_shows_dash_for_unknown_channels() {
        // channels None → em-dash placeholder, not "0 ch".
        let s = metadata_summary("ADPCM", None, 0.0, None);
        assert_eq!(s, "ADPCM \u{b7} \u{2014} \u{b7} 0:00");
    }

    #[test]
    #[allow(clippy::float_cmp)] // clamp returns the exact bounds 0.0 / 1.0
    fn seek_fraction_from_x_maps_and_clamps() {
        // x=40 of an 80-wide canvas → 0.5. Divergent values kill `/ -> *`
        // (3200 → clamps to 1.0) and `/ -> %` (40.0).
        assert!((seek_fraction_from_x(40.0, 80.0) - 0.5).abs() < 1e-6);
        assert!((seek_fraction_from_x(20.0, 80.0) - 0.25).abs() < 1e-6);
        assert_eq!(seek_fraction_from_x(-10.0, 80.0), 0.0, "clamp low");
        assert_eq!(seek_fraction_from_x(200.0, 80.0), 1.0, "clamp high");
        assert_eq!(seek_fraction_from_x(40.0, 0.0), 0.0, "zero-width guard");
    }
}
