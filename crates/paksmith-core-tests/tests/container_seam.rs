//! Issue #654 — container-agnostic open/read seam, exercised end-to-end
//! through `dyn ContainerReader` (the pre-Phase-8 acceptance test).
//!
//! Two seams under test:
//! 1. `container::open` — the factory every frontend uses instead of
//!    naming `PakReader`; returns `Arc<dyn ContainerReader>` and passes
//!    `PaksmithError` through unchanged (the GUI's Decryption→Locked
//!    policy depends on the error identity surviving).
//! 2. `Package::read_from_reader` generalized over
//!    `R: ContainerReader + ?Sized` — driven here with a SECOND
//!    `ContainerReader` impl (`MapReader`, defined in this out-of-crate
//!    test on purpose: it also exercises the external-implementor
//!    ergonomics the trait docs promise, incl. `EntryMetadata::new` +
//!    `EntryFlags::NONE` as the non_exhaustive escape hatches).
//!
//! The `.ubulk` leg matters most: the companion loader captures the
//! reader in a `Fn + Send + Sync + 'static` closure — the only
//! genuinely new bound the generalization imposes — so the test drives
//! `resolve_bulk_for_export` through the trait object, not just the
//! uasset/uexp reads.
//!
//! Required feature: `__test_utils` (byte builders + bulk test hooks).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use paksmith_core::asset::bulk_data::{BulkDataFlags, BulkDataTier, FByteBulkData};
use paksmith_core::container::{ContainerFormat, ContainerReader, EntryFlags, EntryMetadata};
use paksmith_core::testing::bulk_data::BULK_COMPANION_SENTINEL;
use paksmith_core::testing::uasset::build_minimal_ue4_27_split;
use paksmith_core::{BulkData, Package, PaksmithError};

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

/// Streaming-tier flag bits (mirrors `bulk_data.rs`'s private
/// constants; values anchored by the wire format, not the code).
const PAYLOAD_IN_SEPARATE_FILE: u32 = 1 << 8;
const NO_OFFSET_FIXUP: u32 = 1 << 16;

/// Minimal second `ContainerReader`: an in-memory path→bytes map.
/// Deliberately NOT a pak — proves the seam carries any container.
struct MapReader(BTreeMap<String, Vec<u8>>);

impl ContainerReader for MapReader {
    fn entries(&self) -> Box<dyn Iterator<Item = EntryMetadata> + Send + '_> {
        Box::new(self.0.iter().map(|(p, b)| {
            EntryMetadata::new(p.clone(), b.len() as u64, b.len() as u64, EntryFlags::NONE)
        }))
    }

    // Inverted vs. the trait's streaming contract (`read_entry_to` is
    // the primitive there): the bytes are already resident in the map,
    // so there is nothing to stream. Don't copy this into a real reader.
    fn read_entry_to(&self, path: &str, writer: &mut dyn Write) -> paksmith_core::Result<u64> {
        let bytes = self.read_entry(path)?;
        writer.write_all(&bytes)?;
        Ok(bytes.len() as u64)
    }

    fn read_entry(&self, path: &str) -> paksmith_core::Result<Vec<u8>> {
        self.0
            .get(path)
            .cloned()
            .ok_or_else(|| PaksmithError::EntryNotFound { path: path.into() })
    }

    // `ContainerFormat` has no synthetic variant and the seam under
    // test never reads this, so the required method returns the only
    // sensible value.
    fn format(&self) -> ContainerFormat {
        ContainerFormat::Pak
    }

    // The `&'static str` clippy wants is not writable here: the return
    // type is pinned by the `ContainerReader` signature (`&self`-tied).
    #[allow(clippy::unnecessary_literal_bound)]
    fn mount_point(&self) -> &str {
        "../../../"
    }
}

/// A `MapReader` serving the split minimal asset + a `.ubulk` sentinel,
/// erased to `Arc<dyn ContainerReader>`.
fn dyn_map_reader() -> Arc<dyn ContainerReader> {
    let (uasset, uexp) = build_minimal_ue4_27_split();
    let mut map = BTreeMap::new();
    let _ = map.insert("Game/Maps/Demo.uasset".to_string(), uasset);
    let _ = map.insert("Game/Maps/Demo.uexp".to_string(), uexp);
    let _ = map.insert(
        "Game/Maps/Demo.ubulk".to_string(),
        BULK_COMPANION_SENTINEL.to_vec(),
    );
    Arc::new(MapReader(map))
}

/// Acceptance (b)+(c): `read_from_reader` parses a package through a
/// NON-pak reader held as `Arc<dyn ContainerReader>`, including the
/// `.uexp` companion stitch.
#[test]
fn read_from_reader_parses_through_dyn_container_reader() {
    let reader = dyn_map_reader();
    let pkg = Package::read_from_reader(&reader, "Game/Maps/Demo.uasset", None)
        .expect("dyn ContainerReader must drive a full package parse");
    assert!(
        !pkg.exports.exports.is_empty(),
        "exports parsed through the trait object"
    );
}

/// The companion loaders capture the TRAIT OBJECT in the
/// `Fn + Send + Sync + 'static` closures: a streaming-tier bulk record
/// must resolve the `.ubulk` sentinel through `Arc<dyn ContainerReader>`.
#[test]
fn bulk_resolution_fires_companion_loader_through_dyn_reader() {
    let reader = dyn_map_reader();
    let mut pkg = Package::read_from_reader(&reader, "Game/Maps/Demo.uasset", None)
        .expect("dyn ContainerReader parse");
    let streaming = FByteBulkData::for_test(
        BulkDataFlags::from(PAYLOAD_IN_SEPARATE_FILE | NO_OFFSET_FIXUP),
        32,   // element_count
        32,   // size_on_disk = sentinel length
        0i64, // offset_in_file
    );
    pkg.insert_bulk_records_for_test(0, vec![streaming])
        .expect("insert streaming record");
    let bulk = pkg.resolve_bulk_for_export(0).expect("streaming resolve");
    assert_eq!(bulk.len(), 1);
    let BulkData { bytes, tier, .. } = &bulk[0];
    assert_eq!(*tier, BulkDataTier::Streaming);
    assert_eq!(
        bytes.as_slice(),
        BULK_COMPANION_SENTINEL,
        ".ubulk sentinel must round-trip through the dyn companion loader"
    );
}

/// The trait's `# Error identity contract`: an absent path surfaces as
/// `EntryNotFound` — never a generic `Io` error — through the dyn
/// handle, for both `read_entry` and `read_entry_to`. This is the
/// identity `read_from_reader`'s companion detection relies on.
#[test]
fn absent_path_surfaces_entry_not_found_through_dyn_reader() {
    let reader = dyn_map_reader();

    let err = reader.read_entry("Game/Maps/Absent.uasset").unwrap_err();
    assert!(
        matches!(err, PaksmithError::EntryNotFound { .. }),
        "read_entry on an absent path must surface EntryNotFound, got {err:?}"
    );

    let mut sink = Vec::new();
    let err = reader
        .read_entry_to("Game/Maps/Absent.uasset", &mut sink)
        .unwrap_err();
    assert!(
        matches!(err, PaksmithError::EntryNotFound { .. }),
        "read_entry_to on an absent path must surface EntryNotFound, got {err:?}"
    );
    assert!(sink.is_empty(), "nothing may be written for an absent path");
}

/// Acceptance (a): the `container::open` factory opens a real pak as
/// `Arc<dyn ContainerReader>` with output identical to the direct
/// constructor path.
#[test]
fn container_open_factory_matches_direct_pak_open() {
    let path = fixture_path("real_v8b_uasset.pak");
    let via_factory =
        paksmith_core::container::open(&path, None).expect("factory open of a plain pak");
    let direct = paksmith_core::container::pak::PakReader::open(&path).expect("direct open");

    let mut factory_paths: Vec<String> = via_factory
        .entries()
        .map(|e| e.path().to_string())
        .collect();
    let mut direct_paths: Vec<String> = direct.entries().map(|e| e.path().to_string()).collect();
    factory_paths.sort();
    direct_paths.sort();
    assert_eq!(factory_paths, direct_paths, "identical entry sets");

    let entry = &factory_paths[0];
    assert_eq!(
        via_factory.read_entry(entry).expect("factory read"),
        direct.read_entry(entry).expect("direct read"),
        "identical bytes through the seam"
    );
}

/// The factory passes `PaksmithError` through unchanged: an encrypted
/// index without a key surfaces as `Decryption` (the GUI's
/// Decryption→Locked prompt policy depends on this identity), and a
/// missing file surfaces as `Io`.
#[test]
fn container_open_factory_preserves_error_identity() {
    // `expect_err` needs `Ok: Debug`, which `Arc<dyn ContainerReader>`
    // deliberately isn't — destructure instead.
    let Err(err) =
        paksmith_core::container::open(&fixture_path("real_v8b_encrypted_index.pak"), None)
    else {
        panic!("keyless open of an encrypted index must fail");
    };
    assert!(
        matches!(err, PaksmithError::Decryption { .. }),
        "Decryption identity must survive the factory: {err:?}"
    );

    let Err(err) =
        paksmith_core::container::open(std::path::Path::new("/nonexistent/nope.pak"), None)
    else {
        panic!("missing pak must fail");
    };
    assert!(matches!(err, PaksmithError::Io(_)), "got {err:?}");
}
