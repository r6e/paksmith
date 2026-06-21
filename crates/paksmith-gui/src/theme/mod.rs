//! Theme: maps the OS light/dark preference (and, in Task 5, the system accent)
//! onto an Iced theme + the design tokens.

pub mod tokens;

/// Light or dark appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
}

/// Read the OS appearance preference, defaulting to `Dark` when unknown.
///
/// `dark-light v2.0.0` returns `Result<dark_light::Mode, Error>` with a
/// `Dark`, `Light`, or `Unspecified` variant. The contract here is:
/// OS-Light → `Mode::Light`; OS-Dark, Unspecified, or any error → `Mode::Dark`.
pub fn detect_mode() -> Mode {
    match dark_light::detect() {
        Ok(dark_light::Mode::Light) => Mode::Light,
        Ok(dark_light::Mode::Dark | dark_light::Mode::Unspecified) | Err(_) => Mode::Dark,
    }
}

/// The Iced base theme for a given appearance mode.
pub fn iced_theme(mode: Mode) -> iced::Theme {
    match mode {
        Mode::Light => iced::Theme::Light,
        Mode::Dark => iced::Theme::Dark,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_mode_maps_to_iced_dark() {
        assert!(matches!(iced_theme(Mode::Dark), iced::Theme::Dark));
        assert!(matches!(iced_theme(Mode::Light), iced::Theme::Light));
    }

    #[test]
    fn tokens_are_a_consistent_scale() {
        use crate::theme::tokens::*;
        const { assert!(SPACE_XS < SPACE_SM && SPACE_SM < SPACE_MD && SPACE_MD < SPACE_LG) }
    }
}
