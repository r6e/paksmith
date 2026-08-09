//! Theme: maps the OS light/dark preference (and, in Task 5, the system accent)
//! onto an Iced theme + the design tokens.

pub mod accent;
pub mod tokens;

/// Light or dark appearance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Light,
    Dark,
}

/// One OS appearance reading, preserving the tri-state the OS reports.
///
/// Kept tri-state on purpose (#662 R1): collapsing to binary [`Mode`] before
/// the theme-follow edge detector destroyed real edges — GNOME's default
/// Light style reports the portal's `NoPreference`, so a Dark→Light switch
/// there never produced a transition once both ends folded to `Dark`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsReading {
    Light,
    Dark,
    /// The OS reported no explicit preference (`dark-light`'s `Unspecified`).
    NoPreference,
}

/// Map a raw `dark-light` result to a poll reading — the tested seam behind
/// [`read_os`]. `None` means the read FAILED, which is no reading at all,
/// never a value: `dark-light`'s Linux backend times out a portal D-Bus
/// roundtrip at 25 ms, and treating that transient `Err` as a value
/// fabricated theme flips on loaded systems (#662 R1).
#[must_use]
fn reading_from(result: &Result<dark_light::Mode, dark_light::Error>) -> Option<OsReading> {
    match result {
        Ok(dark_light::Mode::Light) => Some(OsReading::Light),
        Ok(dark_light::Mode::Dark) => Some(OsReading::Dark),
        Ok(dark_light::Mode::Unspecified) => Some(OsReading::NoPreference),
        Err(_) => None,
    }
}

/// Read the OS appearance; see [`reading_from`] for the `None` contract.
// `#[mutants::skip]`: one-expression IO glue over the external `dark-light`
// read. The mapping is the tested `reading_from`; a live positive control
// here would assert environment facts (a registry value, a preference
// domain) that the backends do NOT guarantee and that vary by CI runner
// image — flake by design (R2 catch).
#[mutants::skip]
pub fn read_os() -> Option<OsReading> {
    reading_from(&dark_light::detect())
}

/// The appearance the app STARTS in for a given startup reading.
///
/// The pre-#662 contract verbatim: OS-Light → `Light`; Dark, NoPreference,
/// or a failed read → `Dark`. With no transition evidence yet, unknown
/// leans on the app's dark default.
#[must_use]
pub fn startup_mode(reading: Option<OsReading>) -> Mode {
    match reading {
        Some(OsReading::Light) => Mode::Light,
        Some(OsReading::Dark | OsReading::NoPreference) | None => Mode::Dark,
    }
}

/// The appearance a LIVE transition into `reading` adopts.
///
/// Differs from [`startup_mode`] on `NoPreference`, deliberately: on GNOME
/// — the common emitter — `NoPreference` is what the default Light style
/// reports, so a transition INTO it is the user switching to Light. This is
/// a trade-off, not a universal: other desktops can emit `NoPreference` for
/// schemes that are actually dark (reported for KDE Plasma 5's third-party
/// color schemes), where Light is a mis-adoption — accepted because the
/// alternative left every GNOME light-switch unanswered (the R1 major). At
/// startup the same value carries no transition evidence and keeps the
/// conservative dark default.
#[must_use]
pub fn adopted_mode(reading: OsReading) -> Mode {
    match reading {
        OsReading::Light | OsReading::NoPreference => Mode::Light,
        OsReading::Dark => Mode::Dark,
    }
}

/// The Iced base theme for a given appearance mode.
pub fn iced_theme(mode: Mode) -> iced::Theme {
    match mode {
        Mode::Light => iced::Theme::Light,
        Mode::Dark => iced::Theme::Dark,
    }
}

/// How often the app re-reads the OS appearance to follow live theme changes
/// (#662 — detection used to be startup-only).
///
/// Coarse: an OS theme flip is a rare, human-driven event, and each poll is a
/// preference read (`dark-light`), not a render. Five seconds keeps the app
/// feeling responsive to a system-wide switch without joining the fast tick
/// tiers (console 250 ms–1 s, audio 100 ms, memory 2 s).
///
/// A poll rather than iced's native `SystemThemeChanged` event, on purpose:
/// winit's `ThemeChanged` is unsupported on X11, and its binary theme
/// cannot express the `NoPreference` tri-state the edge logic depends on.
pub const THEME_FOLLOW_TICK: std::time::Duration = std::time::Duration::from_secs(5);

/// What a successful appearance poll does to the displayed mode, if
/// anything. Three regimes:
///
/// - **Watermark present, reading changed**: a real OS edge — adopt
///   [`adopted_mode`]. An OS change wins over a standing manual override
///   (flipping the system theme is the fresher intent). The comparison runs
///   on the raw tri-state [`OsReading`], never the collapsed [`Mode`], so
///   GNOME's Dark↔NoPreference flips are real edges.
/// - **Watermark present, reading unchanged**: nothing — edge-triggering is
///   what lets a manual Toggle Theme survive every quiet tick (a
///   level-triggered "always match the OS" would revert the user's choice
///   within one poll interval).
/// - **Watermark `None`** (every read so far failed): read RECOVERY, which
///   is not an OS change — adopting [`adopted_mode`] here handed a startup
///   D-Bus race the power to revert overrides and to decide a steady GNOME
///   NoPreference system's theme by timing (R2). But adopting NOTHING left
///   the app Dark forever on a Light desktop whose startup read timed out
///   once (R3). So: adopt the deterministic STARTUP mapping — the same
///   theme a successful startup read would have produced — unless the user
///   already toggled manually. `user_chose` is an explicit flag, NOT a
///   mode comparison: an even toggle count lands back on the default mode
///   yet is still a standing choice (R5).
#[must_use]
pub fn poll_decision(last: Option<OsReading>, now: OsReading, user_chose: bool) -> Option<Mode> {
    match last {
        Some(prev) if prev != now => Some(adopted_mode(now)),
        Some(_) => None,
        None => (!user_chose).then(|| startup_mode(Some(now))),
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

    #[test]
    fn theme_follow_tick_is_coarse() {
        // Pins the tick's coarseness like MEMORY_TICK's twin test: a typo'd
        // unit (from_millis(5)) would hammer the Linux portal with ~200
        // D-Bus reads per second and nothing else in the suite would
        // notice. (Constants aren't mutation targets; this guards human
        // edits.)
        assert_eq!(THEME_FOLLOW_TICK, std::time::Duration::from_secs(5));
    }

    #[test]
    fn startup_mode_is_light_only_for_a_definite_light_reading() {
        // The pre-#662 contract verbatim: everything but OS-Light starts Dark.
        assert_eq!(startup_mode(Some(OsReading::Light)), Mode::Light);
        assert_eq!(startup_mode(Some(OsReading::Dark)), Mode::Dark);
        assert_eq!(startup_mode(Some(OsReading::NoPreference)), Mode::Dark);
        assert_eq!(startup_mode(None), Mode::Dark);
    }

    #[test]
    fn adopted_mode_treats_no_preference_as_light() {
        // The GNOME mapping: a LIVE transition into NoPreference is the user
        // switching to the default Light style.
        assert_eq!(adopted_mode(OsReading::Light), Mode::Light);
        assert_eq!(adopted_mode(OsReading::NoPreference), Mode::Light);
        assert_eq!(adopted_mode(OsReading::Dark), Mode::Dark);
    }

    #[test]
    fn os_change_is_adopted_in_both_directions() {
        // The edge branch ignores `current` — an OS change wins over any
        // standing mode, override included.
        assert_eq!(
            poll_decision(Some(OsReading::Dark), OsReading::Light, false),
            Some(Mode::Light)
        );
        assert_eq!(
            poll_decision(Some(OsReading::Light), OsReading::Dark, true),
            Some(Mode::Dark)
        );
        // The GNOME edge that a binary-Mode comparison destroyed (#662 R1):
        // PreferDark → NoPreference is a real transition and lands Light.
        assert_eq!(
            poll_decision(Some(OsReading::Dark), OsReading::NoPreference, false),
            Some(Mode::Light)
        );
    }

    #[test]
    fn quiet_polls_with_a_watermark_adopt_nothing() {
        for reading in [OsReading::Light, OsReading::Dark, OsReading::NoPreference] {
            assert_eq!(poll_decision(Some(reading), reading, false), None);
            assert_eq!(poll_decision(Some(reading), reading, true), None);
        }
    }

    #[test]
    fn read_recovery_adopts_the_startup_mapping_unless_the_user_chose() {
        // A None watermark means the reads so far FAILED. Recovery is not an
        // OS edge (R2) — but while the user has not chosen, adopt what a
        // SUCCESSFUL startup read would have produced, or a Light desktop
        // whose startup read timed out once would stay Dark forever (R3).
        // Deterministic: NoPreference recovers to Dark, exactly like the
        // startup-success path — never decided by timing.
        assert_eq!(
            poll_decision(None, OsReading::Light, false),
            Some(Mode::Light)
        );
        assert_eq!(
            poll_decision(None, OsReading::Dark, false),
            Some(Mode::Dark)
        );
        assert_eq!(
            poll_decision(None, OsReading::NoPreference, false),
            Some(Mode::Dark)
        );
        // ANY manual toggle before recovery — even a count that lands back
        // on the default mode (R5) — means the user already chose: recovery
        // must not revert it, whatever the reading says.
        assert_eq!(poll_decision(None, OsReading::Light, true), None);
        assert_eq!(poll_decision(None, OsReading::Dark, true), None);
        assert_eq!(poll_decision(None, OsReading::NoPreference, true), None);
    }

    #[test]
    fn reading_from_maps_the_tristate_and_drops_errors() {
        assert_eq!(
            reading_from(&Ok(dark_light::Mode::Light)),
            Some(OsReading::Light)
        );
        assert_eq!(
            reading_from(&Ok(dark_light::Mode::Dark)),
            Some(OsReading::Dark)
        );
        assert_eq!(
            reading_from(&Ok(dark_light::Mode::Unspecified)),
            Some(OsReading::NoPreference)
        );
        assert_eq!(reading_from(&Err(dark_light::Error::Timeout)), None);
    }
}
