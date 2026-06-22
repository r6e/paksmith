//! Async asset-load pipeline: read an entry's raw bytes (for Hex/Info) and
//! parse it as a UAsset `Package` (for Properties), both off the UI thread.

use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

/// Result of loading one asset entry: the raw bytes (always present on a
/// successful entry read) plus the parse outcome (`Ok` for parseable UAssets,
/// `Err(reason)` otherwise — the Hex/Info views still work from `bytes`).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AssetLoad {
    pub bytes: Vec<u8>,
    pub parsed: Result<Box<Package>, String>,
}

/// Whether `path` looks like a parseable UAsset header (so we attempt a parse).
/// Non-UAsset entries (`.uexp`, `.ubulk`, textures, raw files) skip the parse —
/// they have no standalone property bag — and render Hex + Info only.
#[allow(dead_code)]
pub fn should_attempt_parse(path: &str) -> bool {
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    {
        let lower = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        lower.ends_with(".uasset") || lower.ends_with(".umap")
    }
}

/// Read `path`'s raw bytes and, when it looks like a UAsset, parse it.
///
/// `bytes` is whatever `read_entry` returns (empty on a read error). `parsed`
/// is `Ok` only when the entry both looks parseable and parses cleanly; every
/// failure path is stringified so the result stays `Clone` for `Message`.
#[allow(dead_code, clippy::unused_async)]
pub async fn load(reader: Arc<PakReader>, path: String) -> AssetLoad {
    let bytes = reader.read_entry(&path).unwrap_or_default();

    let parsed = if should_attempt_parse(&path) {
        // `mappings = None`: 7a does not load `.usmap`. Unversioned assets that
        // require a mapping return `UnversionedWithoutMappings`, surfaced here
        // as a stringified parse error → Properties view shows the reason.
        Package::read_from_reader(&reader, &path, None)
            .map(Box::new)
            .map_err(|e| e.to_string())
    } else {
        Err(format!("{path} is not a UAsset — showing raw bytes"))
    };

    AssetLoad { bytes, parsed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn should_attempt_parse_only_for_uasset_umap() {
        assert!(should_attempt_parse("Game/Maps/Demo.uasset"));
        assert!(should_attempt_parse("Game/Maps/Level.umap"));
        assert!(should_attempt_parse("A/B/UPPER.UASSET")); // case-insensitive
        assert!(!should_attempt_parse("Game/Maps/Demo.uexp"));
        assert!(!should_attempt_parse("Game/T_Rock.ubulk"));
        assert!(!should_attempt_parse("readme.txt"));
    }

    #[tokio::test]
    async fn load_parses_uasset_fixture() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Maps/Demo.uasset".to_string()).await;
        assert!(!out.bytes.is_empty(), "raw bytes must be present");
        assert!(
            out.parsed.is_ok(),
            "Demo.uasset must parse: {:?}",
            out.parsed.err()
        );
    }

    #[tokio::test]
    async fn load_missing_entry_is_err_with_empty_bytes() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Does/Not/Exist.uasset".to_string()).await;
        assert!(out.bytes.is_empty(), "missing entry yields no bytes");
        assert!(out.parsed.is_err(), "missing entry must be a parse error");
    }
}
