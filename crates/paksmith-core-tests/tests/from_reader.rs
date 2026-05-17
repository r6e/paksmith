//! Issue #161: `PakReader::from_reader<R: PakReadSeek>` and
//! `PakReader::from_bytes(Vec<u8>)` entry-point coverage. Pins
//! the in-memory API at parity with the existing
//! `PakReader::open(path)` filesystem entry point.

use std::io::Cursor;

use paksmith_core::container::ContainerReader;
use paksmith_core::container::pak::PakReader;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest_dir.join("../../tests/fixtures").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../tests/fixtures").join(name)
}

/// `from_bytes` produces a `PakReader` byte-identical (in observable
/// behavior) to one built via `open`. The convenience wrapper is the
/// thinnest of veneers — it's enough to verify entry-count + path-set
/// agreement; deeper coverage lives in the existing fixture suite.
#[test]
fn from_bytes_parses_same_as_open() {
    let fixture = "minimal_v6.pak";
    let from_disk = PakReader::open(fixture_path(fixture)).expect("open fixture via path");
    let from_mem =
        PakReader::from_bytes(fixture_bytes(fixture)).expect("open fixture via from_bytes");

    let disk_paths: Vec<String> = from_disk.entries().map(|e| e.path().to_string()).collect();
    let mem_paths: Vec<String> = from_mem.entries().map(|e| e.path().to_string()).collect();
    assert_eq!(disk_paths, mem_paths);
    assert_eq!(from_disk.entries().count(), from_mem.entries().count());
}

/// `from_reader<R: Read + Seek>` with the most common reader type
/// (`Cursor<Vec<u8>>`) produces the same result. Distinct test from
/// `from_bytes` so a future bug that breaks only the convenience
/// wrapper surfaces in its own failure rather than masking the
/// generic path.
#[test]
fn from_reader_with_cursor_parses_same_as_open() {
    let fixture = "minimal_v6.pak";
    let from_disk = PakReader::open(fixture_path(fixture)).expect("open fixture via path");
    let cursor = Cursor::new(fixture_bytes(fixture));
    let from_cursor = PakReader::from_reader(cursor).expect("open fixture via from_reader(Cursor)");

    let disk_paths: Vec<String> = from_disk.entries().map(|e| e.path().to_string()).collect();
    let cursor_paths: Vec<String> = from_cursor
        .entries()
        .map(|e| e.path().to_string())
        .collect();
    assert_eq!(disk_paths, cursor_paths);
}

/// `from_reader` accepts arbitrary `R: Read + Seek + Send + 'static`.
/// Demonstrates the genericity by wrapping a fixture's bytes in a
/// trivially-custom `Cursor` newtype — if `from_reader`'s bound is
/// ever tightened (e.g., to only accept concrete `Cursor`), this
/// test fails to compile.
#[test]
fn from_reader_accepts_custom_read_seek_type() {
    struct OwnedCursor(Cursor<Vec<u8>>);
    impl std::io::Read for OwnedCursor {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl std::io::Seek for OwnedCursor {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    let custom = OwnedCursor(Cursor::new(fixture_bytes("minimal_v6.pak")));
    let reader = PakReader::from_reader(custom).expect("open via custom reader");
    assert!(reader.entries().count() > 0);
}
