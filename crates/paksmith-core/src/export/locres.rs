//! `.locres` → CSV / JSON exporters (#646).
//!
//! NOT [`FormatHandler`](super::FormatHandler) implementations: the
//! handler registry is keyed on [`Asset`](crate::asset::Asset)
//! variants, and a `.locres` file is a standalone localization
//! resource, not a package export. These are plain byte-producing
//! functions; the CLI's extract path calls them directly after
//! [`LocresResource::parse`]. They mirror the DataTable handlers'
//! output conventions (RFC-4180 CSV with LF terminators;
//! pretty-printed JSON).

use crate::localization::LocresResource;

/// Render a parsed `.locres` as RFC-4180 CSV with a fixed
/// `namespace,key,localized` header. Quoting/escaping is delegated to
/// the `csv` writer (fields containing commas, quotes, or newlines
/// are quoted; embedded quotes doubled). Hashes are omitted — they
/// are opaque wire metadata (never validated by the oracle or by
/// paksmith); the JSON exporter carries them for consumers that want
/// fidelity.
///
/// # Errors
/// [`PaksmithError::Internal`](crate::PaksmithError::Internal) on a
/// CSV-writer failure (writing to `Vec<u8>` cannot fail on I/O; the
/// arm exists for the writer's structural errors).
pub fn locres_to_csv(resource: &LocresResource) -> crate::Result<Vec<u8>> {
    let mut writer = csv::WriterBuilder::new()
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(Vec::new());

    let internal = |context: String| crate::PaksmithError::Internal { context };

    writer
        .write_record(["namespace", "key", "localized"])
        .map_err(|e| internal(format!("locres_to_csv header: {e}")))?;

    for ns in &resource.namespaces {
        for entry in &ns.entries {
            writer
                .write_record([ns.namespace.as_str(), &entry.key, &entry.localized])
                .map_err(|e| internal(format!("locres_to_csv row: {e}")))?;
        }
    }

    writer
        .into_inner()
        .map_err(|e| internal(format!("locres_to_csv finish: {e}")))
}

/// Render a parsed `.locres` as pretty-printed JSON — the full
/// structure including version and the opaque namespace/key/source
/// hashes (the CSV exporter drops them).
///
/// # Errors
/// [`PaksmithError::Internal`](crate::PaksmithError::Internal) if
/// serde serialization fails (structurally impossible for this type;
/// the arm satisfies the fallible signature).
pub fn locres_to_json(resource: &LocresResource) -> crate::Result<Vec<u8>> {
    serde_json::to_vec_pretty(resource).map_err(|e| crate::PaksmithError::Internal {
        context: format!("locres_to_json: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::localization::{LocresEntry, LocresNamespace, LocresVersion};

    fn sample() -> LocresResource {
        LocresResource {
            version: LocresVersion::OptimizedCrc32,
            namespaces: vec![
                LocresNamespace {
                    namespace: "Game".to_string(),
                    namespace_hash: 1,
                    entries: vec![
                        LocresEntry {
                            key: "key1".to_string(),
                            key_hash: 2,
                            source_string_hash: 3,
                            localized: "Hello".to_string(),
                        },
                        LocresEntry {
                            key: "key2".to_string(),
                            key_hash: 4,
                            source_string_hash: 5,
                            localized: "World".to_string(),
                        },
                    ],
                },
                LocresNamespace {
                    namespace: String::new(),
                    namespace_hash: 0,
                    entries: vec![LocresEntry {
                        key: "quoted".to_string(),
                        key_hash: 0,
                        source_string_hash: 0,
                        localized: "say \"hi\",\nfriend".to_string(),
                    }],
                },
            ],
        }
    }

    /// Exact-bytes shape: fixed header, wire order preserved across
    /// namespaces, RFC-4180 quoting for embedded quotes/commas/
    /// newlines.
    #[test]
    fn csv_shape_is_exact() {
        let csv = String::from_utf8(locres_to_csv(&sample()).unwrap()).unwrap();
        assert_eq!(
            csv,
            "namespace,key,localized\n\
             Game,key1,Hello\n\
             Game,key2,World\n\
             ,quoted,\"say \"\"hi\"\",\nfriend\"\n"
        );
    }

    /// An empty resource still emits the header (a valid, empty CSV).
    #[test]
    fn csv_empty_resource_is_header_only() {
        let empty = LocresResource {
            version: LocresVersion::Legacy,
            namespaces: Vec::new(),
        };
        let csv = String::from_utf8(locres_to_csv(&empty).unwrap()).unwrap();
        assert_eq!(csv, "namespace,key,localized\n");
    }

    /// JSON carries the full structure — version tag and the opaque
    /// hashes the CSV drops.
    #[test]
    fn json_carries_version_and_hashes() {
        let json: serde_json::Value =
            serde_json::from_slice(&locres_to_json(&sample()).unwrap()).unwrap();
        assert_eq!(json["version"], "optimized_crc32");
        assert_eq!(json["namespaces"][0]["namespace"], "Game");
        assert_eq!(json["namespaces"][0]["namespace_hash"], 1);
        assert_eq!(json["namespaces"][0]["entries"][0]["key"], "key1");
        assert_eq!(json["namespaces"][0]["entries"][0]["source_string_hash"], 3);
        assert_eq!(
            json["namespaces"][1]["entries"][0]["localized"],
            "say \"hi\",\nfriend"
        );
    }

    /// End-to-end: the committed fixture parses and exports.
    #[test]
    fn fixture_round_trips_through_both_exporters() {
        let bytes = include_bytes!("../../../../tests/fixtures/data/sample_v2.locres");
        let parsed = LocresResource::parse(bytes).unwrap();
        let csv = String::from_utf8(locres_to_csv(&parsed).unwrap()).unwrap();
        assert_eq!(
            csv,
            "namespace,key,localized\nGame,key1,Hello\nGame,key2,World\n"
        );
        let json: serde_json::Value =
            serde_json::from_slice(&locres_to_json(&parsed).unwrap()).unwrap();
        assert_eq!(json["namespaces"][0]["entries"][1]["localized"], "World");
    }
}
