//! Waveform canvas widget for the audio player.
//!
//! Draws a column-per-peak waveform with a playhead line and emits
//! [`Message::AudioSeek`] on left-press inside the canvas.  The full
//! widget is rendering/hit-test glue; all pure logic lives in
//! [`crate::state::audio_view`].

use iced::widget::canvas;
use iced::{Color, Element, Length, Point, Rectangle, Renderer, Theme};

use crate::app::Message;
use crate::state::audio_view::AudioState;

// ── canvas height (pixels) ────────────────────────────────────────────────────

/// Pixel height of the rendered waveform canvas.
const WAVEFORM_HEIGHT: f32 = 80.0;

// ── Waveform struct ───────────────────────────────────────────────────────────

/// A `canvas::Program` that renders a waveform + playhead and emits
/// [`Message::AudioSeek`] on click.
///
/// Marked `#[mutants::skip]` because the draw and update methods are
/// rendering / hit-test glue with no observable pure-logic state to assert
/// against in unit tests.
#[mutants::skip]
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
        let pos = cursor.position_in(bounds)?;
        // `pos.x` is already relative to `bounds.x` (origin = top-left of canvas).
        // `bounds.width` is always > 0 while the canvas is laid out.
        let frac = (pos.x / bounds.width).clamp(0.0, 1.0);
        Some(canvas::Action::publish(Message::AudioSeek(frac)).and_capture())
    }

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
#[allow(dead_code)] // wired into the audio view in Task 10
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
