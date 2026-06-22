//! Async asset-load pipeline: read an entry's raw bytes (for Hex/Info) and
//! parse it as a UAsset `Package` (for Properties), both off the UI thread.

use std::sync::Arc;

use paksmith_core::asset::Package;
use paksmith_core::container::ContainerReader as _;
use paksmith_core::container::pak::PakReader;

/// Maximum bytes retained from a streamed entry read for the Hex and Info views.
///
/// The Hex view renders at most this many bytes per frame; retaining more would
/// waste memory for every large texture or bulk-data entry that the user opens
/// in a tab. The cap is enforced at read time (via [`CappedWriter`]) so the
/// tab never holds more than this many raw bytes in memory.
pub const HEX_BYTES_CAP: usize = 16 * 1024;

/// A [`std::io::Write`] sink that collects at most `cap` bytes and tracks
/// whether the underlying stream produced more data than that.
///
/// After `read_entry_to` completes, [`into_buf`][CappedWriter::into_buf] yields
/// the prefix and [`overflowed`][CappedWriter::overflowed] indicates whether the
/// entry was larger than the cap.
///
/// Once the buffer is full and more data arrives, [`write`][std::io::Write::write]
/// returns `Ok(0)`, which makes core's `write_all` / `io::copy` streaming loop
/// stop with [`ErrorKind::WriteZero`][std::io::ErrorKind::WriteZero] instead of
/// reading and decompressing the rest of the entry for bytes the UI will never
/// render. [`load`] recognizes that induced stop (via [`overflowed`]
/// [CappedWriter::overflowed]) as an intentional truncation rather than a read
/// failure — see [`read_outcome_error`].
struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
    /// Total bytes offered to `write` so far (capped at `usize::MAX`).
    total_seen: usize,
}

impl CappedWriter {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap.min(1024 * 64)),
            cap,
            total_seen: 0,
        }
    }

    /// Whether the entry had more than `cap` bytes.
    fn overflowed(&self) -> bool {
        self.total_seen > self.cap
    }

    /// Consume the writer and return the buffered prefix.
    fn into_buf(self) -> Vec<u8> {
        self.buf
    }
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.total_seen = self.total_seen.saturating_add(data.len());
        // Take only the remaining capacity (0 once full) via saturating_sub — no
        // `<` guard, so there is no boundary-equivalent `< vs <=` mutant; when the
        // buffer is already at the cap, `take == 0` and `&data[..0]` is a no-op.
        let take = self.cap.saturating_sub(self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        if take < data.len() {
            // Buffer is now full but the stream has more bytes. Returning `Ok(0)`
            // makes core's `write_all` loop stop with `ErrorKind::WriteZero`, so
            // it does not read/decompress the remainder of the entry. `total_seen`
            // was already incremented above, so `overflowed()` is true and `load`
            // treats the resulting error as an intentional truncation.
            return Ok(0);
        }
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Classify a `read_entry_to` outcome: `None` when the read succeeded or was
/// halted by [`CappedWriter`] hitting the cap (`overflowed`), `Some(msg)` for a
/// genuine I/O / decryption / decompression failure.
///
/// `CappedWriter` only returns `Ok(0)` (→ `WriteZero`) after `total_seen` has
/// passed the cap, and core stops at that write, so once `overflowed` is true the
/// error is always our induced stop — never a real fault we would want to hide.
fn read_outcome_error<E: std::fmt::Display>(
    result: Result<u64, E>,
    overflowed: bool,
) -> Option<String> {
    match result {
        Ok(_) => None,
        Err(_) if overflowed => None,
        Err(e) => Some(e.to_string()),
    }
}

/// Result of loading one asset entry: a capped byte prefix (for Hex/Info) and
/// the parse outcome (`Ok` for parseable UAssets, `Err(reason)` otherwise).
///
/// `bytes` holds at most [`HEX_BYTES_CAP`] bytes regardless of the entry's
/// actual size; `truncated` is `true` when the entry has more data than the cap.
/// On a read error, `bytes` contains whatever was captured before the failure and
/// the error is surfaced in `parsed`.
#[derive(Debug, Clone)]
pub struct AssetLoad {
    /// Capped raw prefix, ≤ [`HEX_BYTES_CAP`] bytes.
    pub bytes: Vec<u8>,
    /// Whether the entry is larger than [`HEX_BYTES_CAP`].
    pub truncated: bool,
    /// Parse outcome: `Ok` only when the entry both looks parseable and parses cleanly.
    /// Every failure path is stringified so the result stays `Clone` for `Message`.
    pub parsed: Result<Box<Package>, String>,
}

/// Whether `path` looks like a parseable UAsset header (so we attempt a parse).
/// Non-UAsset entries (`.uexp`, `.ubulk`, textures, raw files) skip the parse —
/// they have no standalone property bag — and render Hex + Info only.
pub fn should_attempt_parse(path: &str) -> bool {
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    {
        let lower = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        lower.ends_with(".uasset") || lower.ends_with(".umap")
    }
}

/// Read `path`'s raw bytes (up to [`HEX_BYTES_CAP`]) and, when it looks like a
/// UAsset, parse it.
///
/// Uses `ContainerReader::read_entry_to` with a [`CappedWriter`] to stream the
/// entry without pre-reserving the full `uncompressed_size` (F1). I/O and
/// decryption errors are surfaced in `parsed` rather than silently producing an
/// empty byte slice (F2).
#[allow(
    clippy::unused_async,
    reason = "async required by iced Task::perform interface"
)]
pub async fn load(reader: Arc<PakReader>, path: String) -> AssetLoad {
    let mut w = CappedWriter::new(HEX_BYTES_CAP);
    let read_result = reader.read_entry_to(&path, &mut w);
    let truncated = w.overflowed();
    let read_err = read_outcome_error(read_result, truncated);
    let bytes = w.into_buf();

    let parsed = if let Some(e) = read_err {
        Err(e) // F2: surface the real read error
    } else if should_attempt_parse(&path) {
        // `mappings = None`: 7a does not load `.usmap`. Unversioned assets that
        // require a mapping return `UnversionedWithoutMappings`, surfaced here
        // as a stringified parse error → Properties view shows the reason.
        Package::read_from_reader(&reader, &path, None)
            .map(Box::new)
            .map_err(|e| e.to_string())
    } else {
        Err("Not a UAsset \u{2014} showing raw bytes".to_string())
    };

    AssetLoad {
        bytes,
        truncated,
        parsed,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;

    use super::*;

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
        assert!(!should_attempt_parse("x.uasset/file.bin")); // dir named *.uasset, file is .bin
    }

    // ── CappedWriter tests ────────────────────────────────────────────────────

    #[test]
    fn capped_writer_below_cap_not_truncated() {
        let mut w = CappedWriter::new(100);
        w.write_all(&[0u8; 50]).unwrap();
        assert_eq!(w.buf.len(), 50);
        assert!(!w.overflowed());
    }

    #[test]
    fn capped_writer_exactly_at_cap_not_truncated() {
        let mut w = CappedWriter::new(100);
        w.write_all(&[0u8; 100]).unwrap();
        assert_eq!(w.buf.len(), 100);
        assert!(!w.overflowed(), "exactly == cap must not overflow");
    }

    #[test]
    fn capped_writer_above_cap_stops_stream_with_write_zero() {
        // Past the cap, `write` returns Ok(0) so `write_all` reports WriteZero —
        // the signal that halts core's streaming loop early. The prefix is still
        // captured up to the cap and `overflowed()` flips true.
        let mut w = CappedWriter::new(100);
        let err = w
            .write_all(&[0u8; 110])
            .expect_err("over-cap write_all must stop the stream");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::WriteZero,
            "the induced stop must surface as WriteZero"
        );
        assert_eq!(w.buf.len(), 100, "prefix is captured up to the cap");
        assert!(w.overflowed(), "cap + 10 must overflow");
    }

    #[test]
    fn capped_writer_at_exactly_cap_does_not_stop() {
        // A single write of exactly `cap` bytes is fully consumed (take == len),
        // so `write` returns Ok(len) and the stream is NOT halted.
        let mut w = CappedWriter::new(100);
        let n = w.write(&[0u8; 100]).expect("exact-cap write must succeed");
        assert_eq!(n, 100, "exact-cap write consumes all bytes (no Ok(0))");
        assert!(!w.overflowed(), "exactly == cap must not overflow");
    }

    #[test]
    fn capped_writer_accumulates_and_stops_on_the_overflowing_write() {
        // Two 10-KiB writes at cap=16 KiB: first fills 10 KiB (fully consumed, no
        // overflow), second fills the remaining 6 KiB then stops the stream.
        let cap = HEX_BYTES_CAP; // 16 KiB
        let mut w = CappedWriter::new(cap);
        w.write_all(&vec![0u8; 10 * 1024])
            .expect("first 10 KiB fits below the cap");
        assert_eq!(w.buf.len(), 10 * 1024);
        assert!(!w.overflowed(), "first 10 KiB must not overflow");
        let err = w
            .write_all(&vec![0u8; 10 * 1024])
            .expect_err("the write that crosses the cap must stop the stream");
        assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
        assert_eq!(w.buf.len(), cap, "buf must be capped at HEX_BYTES_CAP");
        assert!(w.overflowed(), "total 20 KiB > 16 KiB must overflow");
    }

    // ── read_outcome_error ─────────────────────────────────────────────────────

    #[test]
    fn read_outcome_error_ok_is_none() {
        assert!(read_outcome_error::<&str>(Ok(42), false).is_none());
        assert!(
            read_outcome_error::<&str>(Ok(42), true).is_none(),
            "a successful read is never an error, overflow or not"
        );
    }

    #[test]
    fn read_outcome_error_genuine_failure_surfaces_when_not_overflowed() {
        let msg = read_outcome_error(Err("disk exploded"), false)
            .expect("a real error with no overflow must surface");
        assert_eq!(msg, "disk exploded");
    }

    #[test]
    fn read_outcome_error_induced_stop_is_suppressed_when_overflowed() {
        // The WriteZero we induce at the cap arrives as Err while overflowed is
        // true — that is an intentional truncation, not a failure to report.
        assert!(
            read_outcome_error(Err("WriteZero"), true).is_none(),
            "an error after overflow is our induced cap-stop and must be swallowed"
        );
    }

    // ── load tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn load_parses_uasset_fixture() {
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Maps/Demo.uasset".to_string()).await;
        assert!(!out.bytes.is_empty(), "raw bytes must be present");
        assert!(!out.truncated, "small fixture must not be truncated");
        assert!(
            out.parsed.is_ok(),
            "Demo.uasset must parse: {:?}",
            out.parsed.err()
        );
    }

    #[tokio::test]
    async fn load_missing_entry_surfaces_read_error() {
        // F2: a missing entry must surface the real I/O error in `parsed`, NOT the
        // "not a UAsset" string.  A non-.uasset extension is used deliberately:
        // for a missing .uasset the old code also attempted a parse and returned a
        // core error, so that path wouldn't distinguish old from new behaviour.
        let reader = Arc::new(PakReader::open(fixture("real_v8b_uasset.pak")).unwrap());
        let out = load(reader, "Game/Does/Not/Exist.bin".to_string()).await;
        assert!(out.bytes.is_empty(), "missing entry yields no bytes");
        assert!(out.parsed.is_err(), "missing entry must be a parse error");
        let err_msg = out.parsed.unwrap_err();
        assert!(
            !err_msg.contains("Not a UAsset"),
            "read error must not be the 'not a UAsset' message (was: {err_msg:?})"
        );
    }
}
