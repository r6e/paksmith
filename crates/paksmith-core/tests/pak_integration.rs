#![allow(missing_docs)]

use paksmith_core::container::pak::PakReader;
use paksmith_core::container::pak::version::PakVersion;
use paksmith_core::container::{ContainerFormat, ContainerReader};

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

#[test]
fn open_minimal_v11_pak() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    assert_eq!(reader.version(), PakVersion::Fnv64BugFix);
    assert_eq!(reader.format(), ContainerFormat::Pak);
    assert_eq!(reader.mount_point(), "../../../");
}

#[test]
fn list_entries_minimal_v11() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let entries = reader.list_entries();

    assert_eq!(entries.len(), 3);

    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"Content/Textures/hero.uasset"));
    assert!(paths.contains(&"Content/Maps/level01.umap"));
    assert!(paths.contains(&"Content/Sounds/bgm.uasset"));
}

#[test]
fn entry_metadata_correct() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let entries = reader.list_entries();

    let hero = entries.iter().find(|e| e.path.contains("hero")).unwrap();
    assert_eq!(hero.uncompressed_size, 22); // b"HERO_TEXTURE_DATA_HERE".len()
    assert!(!hero.is_compressed);
    assert!(!hero.is_encrypted);
}

#[test]
fn read_entry_data() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let data = reader.read_entry("Content/Textures/hero.uasset").unwrap();
    assert_eq!(data, b"HERO_TEXTURE_DATA_HERE");
}

#[test]
fn read_entry_not_found() {
    let reader = PakReader::open(fixture_path("minimal_v11.pak")).unwrap();
    let err = reader
        .read_entry("Content/DoesNotExist.uasset")
        .unwrap_err();
    assert!(matches!(
        err,
        paksmith_core::PaksmithError::EntryNotFound { .. }
    ));
}

#[test]
fn open_nonexistent_file() {
    let err = PakReader::open("/tmp/this_does_not_exist.pak").unwrap_err();
    assert!(matches!(err, paksmith_core::PaksmithError::Io(_)));
}
