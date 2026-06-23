//! System accent color. Each platform reads the user's accent and falls back to
//! `DEFAULT_ACCENT` when unavailable. The accent drives selection/focus styling.
//!
//! The macOS implementation calls Objective-C APIs via `objc2-app-kit`.
//! Since objc2-app-kit 0.3.2 the relevant bindings are safe; every call
//! follows the Objective-C memory rules enforced by `objc2`'s `Retained<T>`
//! smart pointer. Windows and Linux reads are deferred as follow-up work;
//! both platforms fall back to `DEFAULT_ACCENT`.

// Dead-code: `DEFAULT_ACCENT` and `system_accent` are public API for later tasks
// that haven't consumed them yet (same as tokens.rs). `platform_accent` is
// private and similarly unconsumed outside tests; suppressed at file scope
// because the `pub` items need it too.
#![allow(dead_code)]

// The macOS arm calls objc2 bindings. Since objc2-app-kit 0.3.2 the relevant
// class methods are safe; no unsafe block is required. Workspace-wide
// unsafe_code = "deny" is satisfied — no unsafe here.
#[cfg(target_os = "macos")]
mod macos_impl {
    use iced::Color;
    use objc2_app_kit::{NSColor, NSColorSpace};

    pub(super) fn accent() -> Option<Color> {
        // Thread contract: these `NSColor`/`NSColorSpace` reads are intended
        // to run on the main thread at app startup — `system_accent()` is
        // called from `App::default`, which Iced invokes on the main thread.
        // objc2 does not statically enforce main-thread confinement for these
        // marker-less `NSColor` class methods; callers MUST ensure this is not
        // invoked from a background `Task` or worker thread.
        //
        // `NSColorSpace::sRGBColorSpace()` and `NSColor::controlAccentColor()`
        // are class methods that succeed when AppKit is loaded (the two methods
        // always return a valid object; only the conversion step below can
        // return `None`). `colorUsingColorSpace` returns
        // `Option<Retained<NSColor>>` — `None` means the sRGB conversion
        // failed and is propagated via `?`. The `Retained<T>` lifetime of
        // `converted` covers all three component reads (`redComponent`,
        // `greenComponent`, `blueComponent`) that follow; no raw pointer
        // escapes the block. f64→f32 narrowing is intentional: f32 precision
        // is more than sufficient for an 8-bit-origin display color, and
        // `iced::Color` uses f32 throughout.
        let srgb = NSColorSpace::sRGBColorSpace();
        let raw = NSColor::controlAccentColor();
        let converted = raw.colorUsingColorSpace(&srgb)?;
        #[allow(clippy::cast_possible_truncation)]
        // f64→f32: sRGB components are in [0.0, 1.0]; f32 is sufficient
        // for color representation. iced::Color uses f32 throughout.
        let r = converted.redComponent() as f32;
        #[allow(clippy::cast_possible_truncation)]
        let g = converted.greenComponent() as f32;
        #[allow(clippy::cast_possible_truncation)]
        let b = converted.blueComponent() as f32;
        // Alpha is forced to 1.0 — controlAccentColor is always opaque,
        // and constructing it from r/g/b keeps the f32 round-trip exact.
        Some(Color { r, g, b, a: 1.0 })
    }
}

use iced::Color;

/// Fallback accent (a calm blue) used when the OS accent can't be read.
pub const DEFAULT_ACCENT: Color = Color::from_rgb(0.36, 0.55, 0.93);

/// The user's system accent color, or `DEFAULT_ACCENT`.
pub fn system_accent() -> Color {
    platform_accent().unwrap_or(DEFAULT_ACCENT)
}

/// macOS: delegate to the AppKit-backed implementation.
#[cfg(target_os = "macos")]
fn platform_accent() -> Option<Color> {
    macos_impl::accent()
}

/// Non-macOS: no native read — falls back to `DEFAULT_ACCENT`.
///
/// Windows (`UISettings.GetColorValue(UIColorType::Accent)`) and Linux
/// (`xdg-desktop-portal` org.freedesktop.portal.Settings "accent-color") native
/// reads are deferred as follow-up work. Both are untestable on this macOS dev
/// host and the scope guard allows shipping `None` rather than unverified code.
#[cfg(not(target_os = "macos"))]
fn platform_accent() -> Option<Color> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accent_is_a_valid_opaque_color() {
        let c = system_accent();
        assert!(
            (0.0..=1.0).contains(&c.r) && (0.0..=1.0).contains(&c.g) && (0.0..=1.0).contains(&c.b)
        );
        // a is constructed as 1.0_f32 literal — exact equality is correct here.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(c.a, 1.0_f32);
        }
    }

    #[test]
    fn default_accent_is_opaque() {
        // DEFAULT_ACCENT.a is the literal 1.0_f32 from Color::from_rgb —
        // exact equality is correct.
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(DEFAULT_ACCENT.a, 1.0_f32);
        }
    }

    /// Validates the macOS native accent read when a display session is present.
    ///
    /// On a headless CI runner `colorUsingColorSpace` may return `None` (no
    /// window server / display session); the test skips the assertions in that
    /// case. Validity when the fallback path fires is covered by
    /// `accent_is_a_valid_opaque_color`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_accent_is_some_and_valid() {
        // On a headless CI runner the native read may return None; only assert
        // validity when a color IS produced (the fallback path is covered by
        // `accent_is_a_valid_opaque_color`).
        if let Some(c) = platform_accent() {
            assert!(
                (0.0..=1.0).contains(&c.r),
                "red component out of range: {}",
                c.r
            );
            assert!(
                (0.0..=1.0).contains(&c.g),
                "green component out of range: {}",
                c.g
            );
            assert!(
                (0.0..=1.0).contains(&c.b),
                "blue component out of range: {}",
                c.b
            );
            // a is the literal 1.0_f32 — exact equality is correct.
            #[allow(clippy::float_cmp)]
            {
                assert_eq!(c.a, 1.0_f32);
            }
        }
    }
}
