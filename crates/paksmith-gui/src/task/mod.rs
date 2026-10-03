//! Async pipeline tasks for the GUI.
pub mod asset;
pub mod audio;
pub mod export;
pub mod open;
pub mod texture;

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::PathBuf;
    use std::sync::Arc;

    use paksmith_core::asset::{ParseInputs, Usmap};
    use paksmith_core::container::ContainerReader;

    pub(crate) fn fixture(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    /// A versioned uasset that parses without inputs.
    pub(crate) const DEMO_ENTRY: &str = "Game/Maps/Demo.uasset";

    pub(crate) fn demo_reader() -> Arc<dyn ContainerReader> {
        paksmith_core::container::open(&fixture("real_v8b_uasset.pak"), None).unwrap()
    }

    /// The unversioned fixture pak and its one entry, whose `Hero` class
    /// only decodes with [`hero_inputs`].
    pub(crate) const UNVERSIONED_PAK: &str = "real_v8b_unversioned.pak";
    pub(crate) const HERO_ENTRY: &str = "Game/Heroes/Hero.uasset";

    pub(crate) fn hero_reader() -> Arc<dyn ContainerReader> {
        paksmith_core::container::open(&fixture(UNVERSIONED_PAK), None).unwrap()
    }

    /// The `.usmap` carrying the `Hero { Health, Speed }` schema.
    pub(crate) fn hero_usmap() -> PathBuf {
        fixture("external_minimal_v0.usmap")
    }

    /// Inputs carrying [`hero_usmap`].
    pub(crate) fn hero_inputs() -> ParseInputs {
        let mut inputs = ParseInputs::default();
        inputs.mappings = Some(Arc::new(Usmap::from_path(hero_usmap()).unwrap()));
        inputs
    }
}
