//! The bridge to the browser extension: protocol v1 over a local IPC connection from the
//! native messaging relay.
//!
//! One IPC connection carries the extension's virtual sockets, each named by a `sid`. A
//! socket behaves like a WebSocket connection of the wss server: greeting, heartbeat echo,
//! requests answered one at a time in order, `addInfo.origin` from its `open` frame. Text
//! messages travel as `msg` frames whose `data` pieces are concatenated up to the frame
//! without `"more":true`.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use oncl_ipc::{IpcListener, IpcStream, read_frame, write_frame};
use oncl_protocol::{AddInfo, COMPAT_VERSION, HEARTBEAT, Registry, greeting};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::server::{IDLE_TIMEOUT, MAX_MESSAGE};
use crate::session::process;

/// Largest serialized frame the daemon sends. The relay forwards frames to the browser,
/// which accepts at most 1 MiB per native message.
pub const NM_FRAME_LIMIT: usize = 1_000_000;

/// Version of the bridge protocol.
const PROTOCOL_VERSION: u32 = 1;
/// Frames of a connection waiting for its writer.
const OUT_QUEUE: usize = 16;
/// Longest JSON-escaped form of one character inside a string (`\u0001`).
const MAX_ESCAPED_CHAR: usize = 6;

/// Serves bridge connections accepted on `listener`, each in its own task, until the
/// process exits. Failed accepts are logged and retried.
///
/// # Errors
///
/// None at present: the signature leaves room for fatal listener errors.
pub async fn serve_ipc(mut listener: IpcListener, registry: Arc<Registry>) -> io::Result<()> {
    loop {
        let stream = match listener.accept().await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(error = %e, "IPC accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            match connection(stream, registry).await {
                Ok(()) => debug!("bridge connection closed"),
                Err(e) => debug!(error = %e, "bridge connection ended"),
            }
        });
    }
}

/// Serialized `msg` frames carrying `text` for `sid`, each at most `limit` bytes. `text` is
/// cut at character boundaries so that its JSON-escaped pieces fit; all frames but the last
/// have `"more":true`. An empty `text` is one frame.
///
/// # Panics
///
/// If `limit` leaves no room for the escaped form of a character next to the other fields.
pub fn split_message(sid: u32, text: &str, limit: usize) -> Vec<String> {
    msg_frames(sid, text, limit).collect()
}

/// The frames of [`split_message`], made one at a time.
fn msg_frames(sid: u32, text: &str, limit: usize) -> impl Iterator<Item = String> + '_ {
    // The frame around the data is longest with `"more":true`.
    let overhead = Outbound::Msg {
        sid,
        data: "",
        more: true,
    }
    .to_json()
    .len();
    let room = limit
        .checked_sub(overhead)
        .filter(|room| *room >= MAX_ESCAPED_CHAR)
        .unwrap_or_else(|| panic!("a frame limit of {limit} bytes leaves no room for data"));
    let mut rest = Some(text);
    std::iter::from_fn(move || {
        let text = rest?;
        let (data, tail) = text.split_at(fitting_prefix(text, room));
        rest = (!tail.is_empty()).then_some(tail);
        Some(
            Outbound::Msg {
                sid,
                data,
                more: rest.is_some(),
            }
            .to_json(),
        )
    })
}

/// Length in bytes of the longest prefix of `text`, cut at a character boundary, whose
/// JSON-escaped form takes at most `room` bytes. Bytes of a multi-byte character are written
/// as they are, so each counts one.
fn fitting_prefix(text: &str, room: usize) -> usize {
    let mut used = 0;
    for (at, &byte) in text.as_bytes().iter().enumerate() {
        used += escaped_len(byte);
        if used > room {
            let mut cut = at;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            return cut;
        }
    }
    text.len()
}

/// Bytes that `byte` of a UTF-8 string takes inside a JSON string written by `serde_json`.
fn escaped_len(byte: u8) -> usize {
    match byte {
        b'"' | b'\\' | 0x08 | 0x0c | b'\n' | b'\r' | b'\t' => 2,
        0x00..=0x1f => MAX_ESCAPED_CHAR,
        _ => 1,
    }
}

/// A frame from the extension, checked.
#[derive(Debug, PartialEq)]
enum Request {
    Open {
        sid: u32,
        origin: Option<String>,
    },
    Msg {
        sid: u32,
        piece: Piece,
    },
    Close {
        sid: u32,
    },
    /// A frame type of a newer protocol: ignored.
    Unknown(String),
}

/// A piece of a text message.
#[derive(Debug, PartialEq)]
struct Piece {
    data: String,
    more: bool,
}

/// Parses a frame from the extension. Only the fields of known frame types are looked at.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] if `frame` is not a JSON object with a string `t`, or a
/// field of a known frame type is missing or of the wrong type (`sid`: an integer above 0;
/// `origin`: a string or `null`; `data`: a string; `more`: a boolean).
fn parse(frame: &[u8]) -> io::Result<Request> {
    let invalid = |what: String| io::Error::new(io::ErrorKind::InvalidData, what);
    let mut frame = match serde_json::from_slice(frame) {
        Ok(Value::Object(frame)) => frame,
        Ok(_) => return Err(invalid("bridge frame is not a JSON object".to_owned())),
        Err(e) => return Err(invalid(format!("malformed bridge frame: {e}"))),
    };
    let t = match frame.remove("t") {
        Some(Value::String(t)) => t,
        _ => return Err(invalid("bridge frame without a type".to_owned())),
    };
    let field = |name: &str| invalid(format!("`{t}` frame: bad or missing `{name}`"));
    let sid = frame
        .get("sid")
        .and_then(Value::as_u64)
        .and_then(|sid| u32::try_from(sid).ok())
        .filter(|&sid| sid > 0);
    Ok(match t.as_str() {
        "open" => Request::Open {
            sid: sid.ok_or_else(|| field("sid"))?,
            origin: match frame.remove("origin") {
                Some(Value::String(origin)) => Some(origin),
                None | Some(Value::Null) => None,
                Some(_) => return Err(field("origin")),
            },
        },
        "msg" => Request::Msg {
            sid: sid.ok_or_else(|| field("sid"))?,
            piece: Piece {
                data: match frame.remove("data") {
                    Some(Value::String(data)) => data,
                    _ => return Err(field("data")),
                },
                more: match frame.get("more") {
                    None => false,
                    Some(Value::Bool(more)) => *more,
                    Some(_) => return Err(field("more")),
                },
            },
        },
        "close" => Request::Close {
            sid: sid.ok_or_else(|| field("sid"))?,
        },
        _ => Request::Unknown(t),
    })
}

/// A frame to the extension. `more` is written only when `true`.
#[derive(Serialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum Outbound<'a> {
    Hello {
        v: u32,
        version: &'a str,
        compat: &'a str,
    },
    Open {
        sid: u32,
    },
    Msg {
        sid: u32,
        data: &'a str,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        more: bool,
    },
    Close {
        sid: u32,
    },
}

impl Outbound<'_> {
    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("bridge frames are plain JSON objects")
    }
}

/// Sends `text` to the extension as the `msg` frames of `sid`.
async fn send_message(
    out: &mpsc::Sender<String>,
    sid: u32,
    text: &str,
) -> Result<(), mpsc::error::SendError<String>> {
    for frame in msg_frames(sid, text, NM_FRAME_LIMIT) {
        out.send(frame).await?;
    }
    Ok(())
}

fn writer_gone<T>(_: mpsc::error::SendError<T>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the bridge writer stopped")
}

/// A socket of the extension: the queue of its message pieces and its task. Dropping it
/// stops the task; a module call already running finishes on the blocking pool, its reply
/// is dropped.
struct Socket {
    pieces: mpsc::UnboundedSender<Piece>,
    task: AbortHandle,
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One IPC connection: a reader task, a writer task fed through a queue, and a task per
/// socket. Ends when the relay closes the connection or reading or writing fails.
async fn connection(stream: IpcStream, registry: Arc<Registry>) -> io::Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    let (out, out_rx) = mpsc::channel(OUT_QUEUE);
    let mut writer = tokio::spawn(write_frames(writer, out_rx));
    // One frame read ahead at most: a busy connection waits in the pipe, not in memory.
    let (frames_tx, frames) = mpsc::channel(1);
    let reader = tokio::spawn(read_frames(reader, frames_tx));
    let result = relay_frames(frames, &out, &mut writer, &registry).await;
    // Both halves must go for the pipe to close.
    reader.abort();
    writer.abort();
    result
}

/// Handles the frames of a connection until it ends.
async fn relay_frames(
    mut frames: mpsc::Receiver<io::Result<Vec<u8>>>,
    out: &mpsc::Sender<String>,
    writer: &mut JoinHandle<io::Result<()>>,
    registry: &Arc<Registry>,
) -> io::Result<()> {
    let hello = Outbound::Hello {
        v: PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        compat: COMPAT_VERSION,
    };
    out.send(hello.to_json()).await.map_err(writer_gone)?;
    let mut sockets: HashMap<u32, Socket> = HashMap::new();
    loop {
        // Both branches are cancel safe: the frames are read in their own task.
        let frame = tokio::select! {
            frame = frames.recv() => frame,
            written = &mut *writer => {
                return written.map_err(io::Error::other).flatten();
            }
        };
        let request = match frame {
            None => return Ok(()),
            Some(frame) => parse(&frame?)?,
        };
        match request {
            Request::Open { sid, origin } => {
                // Sockets that the daemon closed may be opened again.
                sockets.retain(|_, socket| !socket.pieces.is_closed());
                if sockets.remove(&sid).is_some() {
                    info!(sid, "socket opened twice; closing it");
                    out.send(Outbound::Close { sid }.to_json())
                        .await
                        .map_err(writer_gone)?;
                    continue;
                }
                let shown = origin.as_deref().unwrap_or("-");
                info!(sid, origin = %shown, "bridge socket opened");
                out.send(Outbound::Open { sid }.to_json())
                    .await
                    .map_err(writer_gone)?;
                send_message(out, sid, &greeting())
                    .await
                    .map_err(writer_gone)?;
                let (pieces, pieces_rx) = mpsc::unbounded_channel();
                let task = tokio::spawn(socket(
                    sid,
                    pieces_rx,
                    out.clone(),
                    Arc::clone(registry),
                    AddInfo { origin },
                ));
                sockets.insert(
                    sid,
                    Socket {
                        pieces,
                        task: task.abort_handle(),
                    },
                );
            }
            Request::Msg { sid, piece } => match sockets.get(&sid) {
                Some(socket) if socket.pieces.send(piece).is_ok() => {}
                Some(_) => {
                    debug!(sid, "message for a closed socket ignored");
                    sockets.remove(&sid);
                }
                None => debug!(sid, "message for an unknown socket ignored"),
            },
            Request::Close { sid } => match sockets.remove(&sid) {
                Some(_) => debug!(sid, "socket closed by the extension"),
                None => debug!(sid, "close of an unknown socket ignored"),
            },
            Request::Unknown(t) => debug!(t, "frame of an unknown type ignored"),
        }
    }
}

/// Reads frames into `frames` until the stream ends (the channel closes) or fails (the error
/// is the last item).
async fn read_frames(mut reader: ReadHalf<IpcStream>, frames: mpsc::Sender<io::Result<Vec<u8>>>) {
    loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) => return,
            Err(e) => Err(e),
        };
        let failed = frame.is_err();
        if frames.send(frame).await.is_err() || failed {
            return;
        }
    }
}

/// Writes the frames of `out` until it closes.
async fn write_frames(
    mut writer: WriteHalf<IpcStream>,
    mut out: mpsc::Receiver<String>,
) -> io::Result<()> {
    while let Some(frame) = out.recv().await {
        write_frame(&mut writer, frame.as_bytes()).await?;
    }
    Ok(())
}

/// A socket: assembles messages from `pieces` and answers them in order. The daemon closes
/// the socket (a `close` frame) on a request that is not a JSON object, a message over
/// [`MAX_MESSAGE`], a failed module call or [`IDLE_TIMEOUT`] without a frame.
async fn socket(
    sid: u32,
    mut pieces: mpsc::UnboundedReceiver<Piece>,
    out: mpsc::Sender<String>,
    registry: Arc<Registry>,
    add_info: AddInfo,
) {
    let mut message = String::new();
    let reason = loop {
        let piece = match timeout(IDLE_TIMEOUT, pieces.recv()).await {
            Err(_) => break "idle timeout",
            Ok(None) => return,
            Ok(Some(piece)) => piece,
        };
        if message.len() + piece.data.len() > MAX_MESSAGE {
            break "message too large";
        }
        if message.is_empty() {
            message = piece.data;
        } else {
            message.push_str(&piece.data);
        }
        if piece.more {
            continue;
        }
        let text = std::mem::take(&mut message);
        // The heartbeat is answered right here: never queued behind a module or a dialog.
        let reply = if text == HEARTBEAT {
            text
        } else {
            let len = text.len();
            match process(&registry, text, &add_info).await {
                Ok(Some(reply)) => reply,
                Ok(None) => {
                    // As the original drops the TCP connection.
                    info!(
                        sid,
                        request_len = len,
                        "request is not a JSON object; closing the socket"
                    );
                    break "invalid request";
                }
                Err(e) => {
                    warn!(sid, error = %e, "request failed");
                    break "failed request";
                }
            }
        };
        if send_message(&out, sid, &reply).await.is_err() {
            return;
        }
    };
    debug!(sid, reason, "closing the socket");
    // The connection may be gone already: nothing to tell then.
    let _ = out.send(Outbound::Close { sid }.to_json()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_len_matches_serde_json() {
        for byte in 0u8..0x80 {
            let text = char::from(byte).to_string();
            let quoted = serde_json::to_string(&text).unwrap();
            assert_eq!(escaped_len(byte), quoted.len() - 2, "byte {byte:#04x}");
        }
    }

    #[test]
    fn prefix_stops_before_an_escape_or_a_split_character() {
        assert_eq!(fitting_prefix("abc", 3), 3);
        assert_eq!(fitting_prefix("abc", 2), 2);
        // `\u0001` takes 6 bytes: it fits whole or not at all.
        assert_eq!(fitting_prefix("a\u{1}b", 6), 1);
        assert_eq!(fitting_prefix("a\u{1}b", 7), 2);
        // 'ж' is two bytes: never cut in the middle.
        assert_eq!(fitting_prefix("aж", 2), 1);
        assert_eq!(fitting_prefix("aж", 3), 3);
        assert_eq!(fitting_prefix("", 6), 0);
    }

    #[test]
    fn frames_serialize_like_the_protocol_table() {
        assert_eq!(
            Outbound::Open { sid: 1 }.to_json(),
            r#"{"t":"open","sid":1}"#
        );
        assert_eq!(
            Outbound::Close { sid: 2 }.to_json(),
            r#"{"t":"close","sid":2}"#
        );
        assert_eq!(
            split_message(3, "--heartbeat--", NM_FRAME_LIMIT),
            [r#"{"t":"msg","sid":3,"data":"--heartbeat--"}"#]
        );
        assert_eq!(
            split_message(3, "", NM_FRAME_LIMIT),
            [r#"{"t":"msg","sid":3,"data":""}"#]
        );
        let hello = Outbound::Hello {
            v: 1,
            version: "0.1.0",
            compat: "1.4",
        };
        assert_eq!(
            hello.to_json(),
            r#"{"t":"hello","v":1,"version":"0.1.0","compat":"1.4"}"#
        );
    }

    #[test]
    #[should_panic(expected = "leaves no room")]
    fn split_refuses_a_limit_without_room() {
        split_message(1, "x", 30);
    }

    #[test]
    fn parse_checks_known_frames_only() {
        assert_eq!(
            parse(br#"{"t":"open","sid":1,"origin":"https://a.kz","url":"https://a.kz/x"}"#)
                .unwrap(),
            Request::Open {
                sid: 1,
                origin: Some("https://a.kz".to_owned())
            }
        );
        assert_eq!(
            parse(br#"{"t":"msg","sid":2,"data":"x","more":true}"#).unwrap(),
            Request::Msg {
                sid: 2,
                piece: Piece {
                    data: "x".to_owned(),
                    more: true
                }
            }
        );
        assert_eq!(
            parse(br#"{"t":"close","sid":3}"#).unwrap(),
            Request::Close { sid: 3 }
        );
        assert_eq!(
            parse(br#"{"t":"ping","sid":"x","data":[1],"more":0}"#).unwrap(),
            Request::Unknown("ping".to_owned())
        );
        assert_eq!(
            parse(br#"{"t":"open","sid":4,"origin":null}"#).unwrap(),
            Request::Open {
                sid: 4,
                origin: None
            }
        );
        for bad in [
            &br#"{"t":"open","sid":0}"#[..],
            br#"{"t":"open","sid":4294967296}"#,
            br#"{"t":"open","sid":1,"origin":5}"#,
            br#"{"t":"close"}"#,
            br#"{"t":"msg","sid":1}"#,
            br#"{"t":"msg","sid":1,"data":"x","more":1}"#,
            br#"{"t":7,"sid":1}"#,
            br#"{"sid":1}"#,
            b"[]",
            b"nope",
        ] {
            let err = parse(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        }
    }
}
