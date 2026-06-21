//! Profile list for the toolbar game-selector dropdown.
//!
//! `ProfileChoice` is the GUI's view of a profile entry: an id + display name,
//! with no dependency on core cache internals.  The list is loaded once at
//! startup; refreshing after a registry fetch is not yet implemented.

use std::fmt;

/// A single selectable profile in the toolbar game picker.
///
/// Implements [`fmt::Display`] (shows `name`) so `iced::widget::pick_list`
/// can render it via the `ToString` bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileChoice {
    /// Canonical profile id (used when threading into key resolution).
    pub id: String,
    /// Human-readable display name shown in the picker.
    pub name: String,
}

impl fmt::Display for ProfileChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// Return all known profiles (local first, then unshadowed registry entries)
/// suitable for populating the toolbar dropdown.
///
/// On error the list degrades to empty (with a `tracing::warn`) so the GUI
/// keeps running without a profile selector.
pub fn available() -> Vec<ProfileChoice> {
    match paksmith_core::profile::resolve::available_profiles() {
        Ok(matches) => matches
            .into_iter()
            .map(|m| ProfileChoice {
                id: m.id,
                name: m.name,
            })
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to load profile list for toolbar selector");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_choice_display_shows_name() {
        let choice = ProfileChoice {
            id: "my-game".into(),
            name: "My Game".into(),
        };
        assert_eq!(choice.to_string(), "My Game");
    }

    #[test]
    fn available_does_not_panic() {
        // `available_profiles()` may return Ok([]) or an error depending on
        // whether the config dir exists in the test environment.  Either way
        // `available()` must return a Vec without panicking.
        let _ = available();
    }
}
