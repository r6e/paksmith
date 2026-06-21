//! System accent color. Each platform reads the user's accent and falls back to
//! `DEFAULT_ACCENT` when unavailable. The accent drives selection/focus styling.
//!
//! The macOS implementation calls Objective-C APIs via `objc2-app-kit`. All
//! `objc2` bindings are declared `unsafe fn` by the crate — the unsafety is
//! bounded to this module and every call follows the Objective-C memory rules
//! enforced by `objc2`'s `Retained<T>` smart pointer. Windows and Linux reads
//! are deferred as follow-up work; both platforms fall back to `DEFAULT_ACCENT`.

// Dead-code: `DEFAULT_ACCENT` and `system_accent` are public API for later tasks
// that haven't consumed them yet (same as tokens.rs).
#![allow(dead_code)]

// The macOS arm calls objc2 bindings, which are unconditionally `unsafe fn`.
// The unsafety is bounded to this module; every site uses `Retained<T>` RAII
// so there are no raw pointer leaks. Workspace-wide unsafe_code = "deny" is
// overridden here because Objective-C interop has no safe alternative in the
// objc2 0.5 API.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos_impl {
    use iced::Color;
    use objc2_app_kit::{NSColor, NSColorSpace};

    pub(super) fn accent() -> Option<Color> {
        // SAFETY: `NSColorSpace::sRGBColorSpace()` and
        // `NSColor::controlAccentColor()` are class methods that always
        // succeed when AppKit is loaded. `colorUsingColorSpace` returns
        // `Option<Retained<NSColor>>` — `None` means the conversion failed
        // (propagated via `?`). All `Retained<T>` values are RAII; no manual
        // memory management. The f64 components from `redComponent` etc. are
        // in [0.0, 1.0] for any valid sRGB color; f32 is the iced::Color
        // representation so the narrowing cast is intentional and lossless for
        // this value range.
        unsafe {
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

    /// Asserts the macOS native read actually succeeds on this host (not just
    /// the fallback). If this fails, the native read path is broken.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_accent_is_some_and_valid() {
        let c = platform_accent().expect("macOS controlAccentColor should be readable");
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
