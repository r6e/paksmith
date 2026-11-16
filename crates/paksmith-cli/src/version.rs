//! The string `paksmith --version` prints after the program name.

use std::sync::LazyLock;

use paksmith_core::build::version_text;

/// The crate version, followed by the build label when there is one.
pub(crate) static VERSION: LazyLock<String> =
    LazyLock::new(|| version_text(env!("CARGO_PKG_VERSION")));
