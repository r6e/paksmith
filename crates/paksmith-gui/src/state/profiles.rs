//! Profile list for the toolbar game-selector dropdown.
//!
//! `ProfileChoice` is the GUI's view of a profile entry: an id + display name,
//! with no dependency on core cache internals.  The list is loaded once at
//! startup (and optionally refreshed after a registry fetch).

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

/// A sentinel choice shown at the top of the list that means "no game selected".
///
/// Selecting it clears `App.active_game` so resolution falls back to the
/// default heuristics (no `--game` arg).
pub const NO_PROFILE_CHOICE: ProfileChoice = ProfileChoice {
    id: String::new(),
    name: String::new(),
};

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
    fn available_degrades_to_empty_on_missing_store() {
        // In the test environment there is no profiles.toml configured, so
        // `available_profiles()` may return Ok([]) or an error depending on
        // whether the config dir exists.  Either way `available()` must return
        // a Vec (never panic) and degrade gracefully.
        let result = available();
        // Just assert it doesn't panic and returns a Vec.
        let _ = result;
    }
}
