//! The string `paksmith --version` prints after the program name.

use std::sync::LazyLock;

/// Set at compile time by the packaging action for a nightly build, so
/// an extracted nightly can be told from a release.
const BUILD_LABEL: Option<&str> = option_env!("PAKSMITH_BUILD_LABEL");

/// The crate version, followed by the build label when there is one.
pub(crate) static VERSION: LazyLock<String> =
    LazyLock::new(|| describe(env!("CARGO_PKG_VERSION"), BUILD_LABEL));

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
}
