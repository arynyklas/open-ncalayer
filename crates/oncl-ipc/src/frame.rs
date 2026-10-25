//! Length-prefixed frames.
//!
//! - IPC between the daemon and the relay: `u32` little-endian length, then the payload.
//! - Native messaging stdio of the browser: `u32` length in the platform byte order, then
//!   UTF-8 JSON. The browser accepts at most [`NM_OUT_LIMIT`] bytes per host message.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest payload of a frame read or written by this crate.
pub const MAX_FRAME: usize = 64 << 20;

/// Largest payload of a native messaging frame from the host to the browser (1 MiB).
pub const NM_OUT_LIMIT: usize = 1024 * 1024;

/// Reads one IPC frame.
///
/// Returns `None` if the stream ends exactly on a frame boundary.
///
/// # Errors
///
/// - [`io::ErrorKind::UnexpectedEof`] if the stream ends inside a frame;
/// - [`io::ErrorKind::InvalidData`] if the frame is longer than [`MAX_FRAME`];
/// - any error of `r`.
///
/// # Cancel safety
///
/// Not cancel safe. If the future is dropped before it completes (e.g. as a losing
/// `tokio::select!` branch), the part of the frame read so far is lost and the stream is out
/// of sync: drop the stream. Keep one `read_frame` future alive across `select!` iterations
/// instead, or read in a dedicated task.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    read_prefixed(r, u32::from_le_bytes).await
}

/// Writes `payload` as one IPC frame and flushes `w`.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] if `payload` is longer than [`MAX_FRAME`]; any error of `w`.
///
/// # Cancel safety
///
/// Not cancel safe: dropping the future may leave a partial frame on the stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    write_prefixed(w, payload, MAX_FRAME, u32::to_le_bytes).await
}

/// Reads one native messaging frame (length in the platform byte order).
///
/// Returns `None` if the stream ends exactly on a frame boundary.
///
/// # Errors
///
/// As [`read_frame`].
///
/// # Cancel safety
///
/// Not cancel safe, as [`read_frame`].
pub async fn read_nm_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    read_prefixed(r, u32::from_ne_bytes).await
}

/// Writes `payload` as one native messaging frame (length in the platform byte order) and
/// flushes `w`.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`] if `payload` is longer than [`NM_OUT_LIMIT`]: the browser
/// would drop the relay; any error of `w`.
///
/// # Cancel safety
///
/// Not cancel safe, as [`write_frame`].
pub async fn write_nm_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> io::Result<()> {
    write_prefixed(w, payload, NM_OUT_LIMIT, u32::to_ne_bytes).await
}

async fn read_prefixed<R: AsyncRead + Unpin>(
    r: &mut R,
    decode: fn([u8; 4]) -> u32,
) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match r.read(&mut header[filled..]).await? {
            0 if filled == 0 => return Ok(None),
            0 => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            n => filled += n,
        }
    }
    let len = usize::try_from(decode(header)).unwrap_or(usize::MAX);
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the limit of {MAX_FRAME}"),
        ));
    }
    // Grows with the data actually received instead of trusting the header up front.
    let mut payload = Vec::with_capacity(len.min(1 << 20));
    let len64 = u64::try_from(len).unwrap_or(u64::MAX);
    r.take(len64).read_to_end(&mut payload).await?;
    if payload.len() != len {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }
    Ok(Some(payload))
}

async fn write_prefixed<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
    limit: usize,
    encode: fn(u32) -> [u8; 4],
) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= limit)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "frame of {} bytes exceeds the limit of {limit}",
                    payload.len()
                ),
            )
        })?;
    w.write_all(&encode(len)).await?;
    w.write_all(payload).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames_of(payloads: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in payloads {
            write_frame(&mut out, p).await.expect("write to Vec");
        }
        out
    }

    #[tokio::test]
    async fn frame_roundtrip_and_eof() {
        let big = vec![0xA5; 70_000];
        let wire = frames_of(&[b"", b"x", &big]).await;
        assert_eq!(&wire[..4], &[0, 0, 0, 0]);
        assert_eq!(&wire[4..9], &[1, 0, 0, 0, b'x']);
        assert_eq!(&wire[9..13], &70_000u32.to_le_bytes());

        let mut r = wire.as_slice();
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(vec![]));
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(b"x".to_vec()));
        assert_eq!(read_frame(&mut r).await.unwrap(), Some(big));
        assert_eq!(read_frame(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn frame_over_limit_is_invalid_data() {
        let over = u32::try_from(MAX_FRAME + 1).unwrap();
        let mut r = &over.to_le_bytes()[..];
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut r = &over.to_ne_bytes()[..];
        let err = read_nm_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut sink = Vec::new();
        let err = write_frame(&mut sink, &vec![0; MAX_FRAME + 1])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(sink.is_empty());
    }

    #[tokio::test]
    async fn frame_at_limit_is_accepted() {
        let wire = frames_of(&[&vec![7; MAX_FRAME]]).await;
        let frame = read_frame(&mut wire.as_slice()).await.unwrap().unwrap();
        assert_eq!(frame.len(), MAX_FRAME);
    }

    #[tokio::test]
    async fn eof_inside_frame_is_unexpected_eof() {
        // Inside the header.
        let mut r = &[5u8, 0][..];
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // Inside the payload.
        let mut r = &[5u8, 0, 0, 0, b'a', b'b'][..];
        let err = read_frame(&mut r).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn nm_frame_roundtrip_uses_native_order() {
        let mut wire = Vec::new();
        write_nm_frame(&mut wire, br#"{"t":"relay"}"#)
            .await
            .unwrap();
        assert_eq!(&wire[..4], &13u32.to_ne_bytes());
        let mut r = wire.as_slice();
        assert_eq!(
            read_nm_frame(&mut r).await.unwrap(),
            Some(br#"{"t":"relay"}"#.to_vec())
        );
        assert_eq!(read_nm_frame(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn nm_write_refuses_over_1_mib() {
        let mut sink = Vec::new();
        write_nm_frame(&mut sink, &vec![b'a'; NM_OUT_LIMIT])
            .await
            .expect("exactly 1 MiB is allowed");
        assert_eq!(sink.len(), 4 + NM_OUT_LIMIT);

        let mut sink = Vec::new();
        let err = write_nm_frame(&mut sink, &vec![b'a'; NM_OUT_LIMIT + 1])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(sink.is_empty());
    }
}
