//! `read_to_end` whose every growth is a fallible reservation, for
//! buffers sized by untrusted input.
//!
//! std's default `Read::read_to_end`, which `Take` and flate2's decoders
//! keep, makes a call's first growth past the capacity it started with
//! through an infallible `extend_from_slice`, which aborts the process
//! when the allocation fails, and doubles the buffer with no cap.

use std::collections::TryReserveError;
use std::io::{self, Read};

/// Bytes offered to the reader per read: std's `DEFAULT_BUF_SIZE`.
const SCRATCH_BYTES: usize = 8 * 1024;

/// Read `reader` to its end onto `out` and return the bytes read.
///
/// Each growth of `out` is one `try_reserve_exact`, handed to `reserved`
/// with the bytes it reserves past `out.len()`; `reserved` must fail when
/// the reservation did. Growth doubles `out`'s capacity but stops at
/// `ceiling` unless the bytes read need more, so pass a ceiling no lower
/// than `out.len()` plus the reader's limit. Every read is offered room,
/// even when `out` is full: a decoder reports a stream cut short only to
/// a read with room. An error other than `Interrupted` ends the read
/// through `read_failed`.
pub(crate) fn read_to_end_within<R: Read + ?Sized>(
    reader: &mut R,
    out: &mut Vec<u8>,
    ceiling: usize,
    mut reserved: impl FnMut(Result<(), TryReserveError>, usize) -> crate::Result<()>,
    read_failed: impl FnOnce(io::Error) -> crate::PaksmithError,
) -> crate::Result<usize> {
    let start = out.len();
    let mut scratch = [0u8; SCRATCH_BYTES];
    loop {
        let n = match reader.read(&mut scratch) {
            Ok(0) => return Ok(out.len() - start),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(read_failed(e)),
        };
        let needed = out.len().saturating_add(n);
        if needed > out.capacity() {
            let target = needed.max(out.capacity().saturating_mul(2).min(ceiling));
            let additional = target - out.len();
            reserved(out.try_reserve_exact(additional), additional)?;
        }
        out.extend_from_slice(&scratch[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message `read_recording`'s `read_failed` gives the errors it maps.
    const READ_FAILED: &str = "read_failed";

    /// `reader` read to its end onto `start`, with each reservation's size
    /// and the kind of a read error mapped through `read_failed`.
    fn read_recording(
        mut reader: impl Read,
        start: &[u8],
        ceiling: usize,
    ) -> (Result<usize, io::ErrorKind>, Vec<u8>, Vec<usize>) {
        let mut out = start.to_vec();
        let mut sizes = Vec::new();
        let read = read_to_end_within(
            &mut reader,
            &mut out,
            ceiling,
            |reserve, n| {
                sizes.push(n);
                reserve.map_err(|e| crate::PaksmithError::Io(e.into()))
            },
            |e| crate::PaksmithError::Io(io::Error::new(e.kind(), READ_FAILED)),
        )
        .map_err(|e| match e {
            crate::PaksmithError::Io(e) if e.to_string() == READ_FAILED => e.kind(),
            other => panic!("expected an error from read_failed, got {other:?}"),
        });
        (read, out, sizes)
    }

    /// Yields `script` read by read, then ends the way flate2 ends a
    /// stream cut short: `Ok(0)` for an empty buffer, `UnexpectedEof` for
    /// one with room.
    struct Scripted(std::vec::IntoIter<io::Result<&'static [u8]>>);

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.next() {
                Some(Ok(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                Some(Err(e)) => Err(e),
                None if buf.is_empty() => Ok(0),
                None => Err(io::ErrorKind::UnexpectedEof.into()),
            }
        }
    }

    fn scripted(
        start: &[u8],
        script: Vec<io::Result<&'static [u8]>>,
        limit: u64,
    ) -> (Result<usize, io::ErrorKind>, Vec<u8>) {
        let (read, out, _sizes) =
            read_recording(Scripted(script.into_iter()).take(limit), start, usize::MAX);
        (read, out)
    }

    #[test]
    fn growth_doubles_through_exact_reservations_up_to_the_ceiling() {
        // (bytes already in `out`, bytes read, ceiling, reservations, capacity)
        // With 100 bytes to start, the third growth begins below capacity.
        let cases: [(usize, usize, usize, &[usize], usize); 4] = [
            (
                0,
                100_000,
                100_000,
                &[8192, 8192, 16_384, 32_768, 34_464],
                100_000,
            ),
            (100, 24_576, usize::MAX, &[8192, 8292, 16_684], 33_168),
            // The ceiling bounds the whole buffer, its first 100 bytes included.
            (100, 24_576, 24_676, &[8192, 8292, 8192], 24_676),
            // A read the ceiling has no room for still grows, by what it needs.
            (0, 12_288, 8192, &[8192, 4096], 12_288),
        ];
        for (start, limit, ceiling, reservations, capacity) in cases {
            let reader = io::repeat(0xA5).take(u64::try_from(limit).unwrap());
            let (read, out, sizes) = read_recording(reader, &vec![0xA5; start], ceiling);
            assert_eq!(read, Ok(limit), "start {start}, ceiling {ceiling}");
            assert_eq!(out, vec![0xA5; start + limit]);
            assert_eq!(sizes, reservations, "start {start}, ceiling {ceiling}");
            assert_eq!(out.capacity(), capacity, "start {start}, ceiling {ceiling}");
        }
    }

    #[test]
    fn a_refused_growth_ends_the_read_before_its_bytes_are_appended() {
        let mut out = Vec::new();
        let read = read_to_end_within(
            &mut io::repeat(0xA5).take(16_384),
            &mut out,
            usize::MAX,
            |_, _| Err(crate::PaksmithError::Io(io::ErrorKind::OutOfMemory.into())),
            crate::PaksmithError::Io,
        );
        assert!(
            matches!(&read, Err(crate::PaksmithError::Io(e)) if e.kind() == io::ErrorKind::OutOfMemory),
            "got {read:?}"
        );
        assert_eq!(out, b"");
    }

    #[test]
    fn reads_append_retry_interruptions_and_end_with_room_to_spare() {
        use io::ErrorKind::{Interrupted, Other, UnexpectedEof};
        assert_eq!(
            scripted(b"", vec![Err(Interrupted.into()), Ok(b"abc")], 3),
            (Ok(3), b"abc".to_vec())
        );
        assert_eq!(
            scripted(b"", vec![Err(Other.into()), Ok(b"abc")], 3),
            (Err(Other), Vec::new())
        );
        assert_eq!(
            scripted(b"xy", vec![Ok(b"abc")], 3),
            (Ok(3), b"xyabc".to_vec())
        );
        // The buffer is full when the stream runs out, and the read that
        // finds the end still gets a byte of room.
        assert_eq!(
            scripted(b"", vec![Ok(b"abc")], 4),
            (Err(UnexpectedEof), b"abc".to_vec())
        );
    }
}
