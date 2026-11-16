//! The version text a frontend shows for itself. It lives here because
//! the CLI and the GUI share code only through this crate.

/// Set at compile time by the packaging action for a nightly build, so
/// a nightly binary can be told from a release.
const BUILD_LABEL: Option<&str> = option_env!("PAKSMITH_BUILD_LABEL");

/// `version`, followed by this build's label when it has one, as in
/// `0.1.0 (nightly-20261115-abc1234)`.
///
/// A frontend passes its own `CARGO_PKG_VERSION`.
#[must_use]
pub fn version_text(version: &str) -> String {
    describe(version, BUILD_LABEL)
}

fn describe(version: &str, label: Option<&str>) -> String {
    match label.filter(|label| !label.is_empty()) {
        Some(label) => format!("{version} ({label})"),
        None => version.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_without_a_label_is_the_version() {
        assert_eq!(describe("1.2.3", None), "1.2.3");
    }

    /// A workflow input left empty reaches the compiler as an empty
    /// variable, not an absent one.
    #[test]
    fn describe_with_an_empty_label_is_the_version() {
        assert_eq!(describe("1.2.3", Some("")), "1.2.3");
    }

    #[test]
    fn describe_with_a_label_appends_it() {
        assert_eq!(
            describe("1.2.3", Some("nightly-20261115-abc1234")),
            "1.2.3 (nightly-20261115-abc1234)"
        );
    }

    #[test]
    fn version_text_describes_this_build() {
        assert_eq!(version_text("1.2.3"), describe("1.2.3", BUILD_LABEL));
    }
}
