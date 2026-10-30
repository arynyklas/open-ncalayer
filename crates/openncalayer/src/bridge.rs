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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oncl_ipc::{IpcListener, read_frame, write_frame};
use oncl_protocol::{COMPAT_VERSION, HEARTBEAT, Registry, greeting};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::server::{IDLE_TIMEOUT, MAX_MESSAGE};
use crate::session::{DROP_CLOSE, Session, process};

/// Largest serialized frame the daemon sends. The relay forwards frames to the browser,
/// which accepts at most 1 MiB per native message.
pub const NM_FRAME_LIMIT: usize = 1_000_000;

/// Version of the bridge protocol.
const PROTOCOL_VERSION: u32 = 1;
/// Frames of a connection waiting for its writer.
const OUT_QUEUE: usize = 16;
/// Most live sockets of a connection: the browser's own WebSocket limits, for every tab of
/// a profile together, with room to spare.
const MAX_SOCKETS: usize = 4096;
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
            match connection(stream, registry, Limits::DAEMON).await {
                Ok(()) => debug!("bridge connection closed"),
                // A relay speaking another protocol: every socket of it is gone.
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    warn!(error = %e, "bridge connection dropped: protocol error");
                }
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

/// What a queued piece costs besides its data: empty pieces are not free.
const PIECE_OVERHEAD: usize = std::mem::size_of::<Queued>();

impl Piece {
    /// The bytes of the connection's budget the piece takes while queued: its data and
    /// [`PIECE_OVERHEAD`].
    fn cost(&self) -> usize {
        self.data.len() + PIECE_OVERHEAD
    }
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

/// Limits of a connection and its sockets.
#[derive(Clone, Copy, Debug)]
struct Limits {
    /// Largest assembled message.
    max_message: usize,
    /// Most bytes of inbound messages a connection holds at once: queued for its sockets,
    /// being assembled or being answered.
    budget: usize,
    /// A socket without a frame for this long is closed.
    idle: Duration,
    /// Most live sockets of a connection; an `open` over it is answered with `close`.
    max_sockets: usize,
}

impl Limits {
    /// [`MAX_MESSAGE`], a budget of two such messages, [`IDLE_TIMEOUT`] and [`MAX_SOCKETS`].
    const DAEMON: Limits = Limits {
        max_message: MAX_MESSAGE,
        budget: 2 * MAX_MESSAGE,
        idle: IDLE_TIMEOUT,
        max_sockets: MAX_SOCKETS,
    };
}

/// The inbound bytes a connection holds, against [`Limits::budget`].
#[derive(Clone)]
struct Budget {
    held: Arc<AtomicUsize>,
    limit: usize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Budget {
            held: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }

    /// Reserves `len` bytes, or `None` if they do not fit.
    fn take(&self, len: usize) -> Option<Held> {
        self.held
            .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                held.checked_add(len).filter(|&total| total <= self.limit)
            })
            .ok()?;
        Some(Held {
            held: Arc::clone(&self.held),
            len,
        })
    }
}

/// Bytes reserved from a [`Budget`], returned on drop.
struct Held {
    held: Arc<AtomicUsize>,
    len: usize,
}

impl Held {
    /// Takes over the bytes of `other`.
    fn absorb(&mut self, mut other: Held) {
        self.len += std::mem::take(&mut other.len);
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.held.fetch_sub(self.len, Ordering::AcqRel);
    }
}

/// A piece queued for a socket with its share of the connection's budget.
struct Queued {
    piece: Piece,
    held: Held,
}

/// A socket of the extension: the queue of its message pieces and its task. Dropping it
/// stops the task and frees its queue; a module call already running finishes on the
/// blocking pool, its reply is dropped.
struct Socket {
    pieces: mpsc::UnboundedSender<Queued>,
    task: AbortHandle,
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One IPC connection: a reader task, a writer task fed through a queue, and a task per
/// socket. Ends when the relay closes the connection or reading or writing fails.
async fn connection<S>(stream: S, registry: Arc<Registry>, limits: Limits) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let (out, out_rx) = mpsc::channel(OUT_QUEUE);
    let mut writer = tokio::spawn(write_frames(writer, out_rx));
    // At most one frame waits here; the pieces handed on to sockets count against the
    // connection's budget until their message is answered.
    let (frames_tx, frames) = mpsc::channel(1);
    let reader = tokio::spawn(read_frames(reader, frames_tx));
    let result = relay_frames(frames, &out, &mut writer, &registry, limits).await;
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
    limits: Limits,
) -> io::Result<()> {
    let hello = Outbound::Hello {
        v: PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION"),
        compat: COMPAT_VERSION,
    };
    out.send(hello.to_json()).await.map_err(writer_gone)?;
    let budget = Budget::new(limits.budget);
    let mut sockets: HashMap<u32, Socket> = HashMap::new();
    // Socket tasks report their sid here when they end, so their entries go at once.
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    loop {
        // Every branch is cancel safe: the frames are read in their own task. Ended sockets
        // go first, so they never count against `max_sockets`.
        let frame = tokio::select! {
            biased;
            Some(sid) = ended.recv() => {
                forget_ended(&mut sockets, sid);
                continue;
            }
            written = &mut *writer => {
                return written.map_err(io::Error::other).flatten();
            }
            frame = frames.recv() => frame,
        };
        let request = match frame {
            None => return Ok(()),
            Some(frame) => parse(&frame?)?,
        };
        match request {
            Request::Open { sid, origin } => {
                let shown = origin.as_deref().unwrap_or("-");
                // A socket that the daemon closed may be opened again.
                if let Some(old) = sockets.remove(&sid)
                    && !old.pieces.is_closed()
                {
                    info!(sid, origin = %shown, "socket opened twice; closing it");
                    send_close(out, sid).await?;
                    continue;
                }
                if sockets.len() >= limits.max_sockets {
                    warn!(sid, origin = %shown, "too many sockets on the connection; closing the new one");
                    send_close(out, sid).await?;
                    continue;
                }
                info!(sid, origin = %shown, "bridge socket opened");
                out.send(Outbound::Open { sid }.to_json())
                    .await
                    .map_err(writer_gone)?;
                send_message(out, sid, &greeting())
                    .await
                    .map_err(writer_gone)?;
                let (pieces, pieces_rx) = mpsc::unbounded_channel();
                let task = tokio::spawn({
                    let run = socket(
                        sid,
                        pieces_rx,
                        out.clone(),
                        Arc::clone(registry),
                        origin,
                        limits,
                    );
                    let ended = ended_tx.clone();
                    async move {
                        run.await;
                        // The connection may be gone already.
                        let _ = ended.send(sid);
                    }
                });
                sockets.insert(
                    sid,
                    Socket {
                        pieces,
                        task: task.abort_handle(),
                    },
                );
            }
            Request::Msg { sid, piece } => {
                let Some(socket) = sockets.get(&sid) else {
                    debug!(sid, "message for an unknown socket ignored");
                    continue;
                };
                if socket.pieces.is_closed() {
                    debug!(sid, "message for a closed socket ignored");
                    sockets.remove(&sid);
                    continue;
                }
                // A socket that sends more than the connection may hold is closed; the
                // others go on.
                let Some(held) = budget.take(piece.cost()) else {
                    warn!(
                        sid,
                        "too much data waiting on the connection; closing the socket"
                    );
                    sockets.remove(&sid);
                    send_close(out, sid).await?;
                    continue;
                };
                if socket.pieces.send(Queued { piece, held }).is_err() {
                    debug!(sid, "message for a closed socket ignored");
                    sockets.remove(&sid);
                }
            }
            Request::Close { sid } => match sockets.remove(&sid) {
                Some(_) => debug!(sid, "socket closed by the extension"),
                None => debug!(sid, "close of an unknown socket ignored"),
            },
            Request::Unknown(t) => debug!(t, "frame of an unknown type ignored"),
        }
    }
}

async fn send_close(out: &mpsc::Sender<String>, sid: u32) -> io::Result<()> {
    out.send(Outbound::Close { sid }.to_json())
        .await
        .map_err(writer_gone)
}

/// Drops the entry of `sid` once its task has ended: the task drops its queue first, so an
/// entry with an open queue belongs to a socket opened again under the same sid.
fn forget_ended(sockets: &mut HashMap<u32, Socket>, sid: u32) {
    if sockets
        .get(&sid)
        .is_some_and(|socket| socket.pieces.is_closed())
    {
        sockets.remove(&sid);
    }
}

/// Reads frames into `frames` until the stream ends (the channel closes) or fails (the error
/// is the last item).
async fn read_frames<R: AsyncRead>(
    mut reader: ReadHalf<R>,
    frames: mpsc::Sender<io::Result<Vec<u8>>>,
) {
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
async fn write_frames<W: AsyncWrite>(
    mut writer: WriteHalf<W>,
    mut out: mpsc::Receiver<String>,
) -> io::Result<()> {
    while let Some(frame) = out.recv().await {
        write_frame(&mut writer, frame.as_bytes()).await?;
    }
    Ok(())
}

/// A socket: assembles messages from `pieces` and answers them in order. The daemon closes
/// the socket (a `close` frame) on a request that is not a JSON object, a message over
/// [`Limits::max_message`], a failed module call or [`Limits::idle`] without a frame. The
/// socket is a session of its own, closed once the task has ended (or been aborted) and its
/// last module call returned.
async fn socket(
    sid: u32,
    mut pieces: mpsc::UnboundedReceiver<Queued>,
    out: mpsc::Sender<String>,
    registry: Arc<Registry>,
    origin: Option<String>,
    limits: Limits,
) {
    let session = Session::new(&registry, origin);
    let mut message = String::new();
    // The budget share of `message`, kept until it is answered.
    let mut message_held: Option<Held> = None;
    let reason = loop {
        let Queued { piece, held } = match timeout(limits.idle, pieces.recv()).await {
            Err(_) => break "idle timeout",
            Ok(None) => return,
            Ok(Some(queued)) => queued,
        };
        if message.len() + piece.data.len() > limits.max_message {
            break "message too large";
        }
        match &mut message_held {
            Some(all) => all.absorb(held),
            None => message_held = Some(held),
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
            match process(&session, text).await {
                Ok(Some(reply)) => reply,
                Ok(None) => {
                    // As the original drops the TCP connection: the extension closes the
                    // page's socket with DROP_CLOSE.
                    info!(
                        sid,
                        request_len = len,
                        close_code = DROP_CLOSE,
                        "request without a reply (not a JSON object, or the module dropped it); closing the socket"
                    );
                    break "invalid request";
                }
                Err(e) => {
                    warn!(sid, error = %e, "request failed");
                    break "failed request";
                }
            }
        };
        let sent = send_message(&out, sid, &reply).await;
        message_held = None;
        if sent.is_err() {
            return;
        }
    };
    debug!(sid, reason, "closing the socket");
    drop(message_held);
    // The `close` is queued while `pieces` is still open: until then the connection keeps
    // the socket (pieces for it are queued and dropped with `pieces`). Were `pieces` closed
    // first, a frame or an `open` for this sid could drop the socket and abort this task
    // while it waits for room in a full queue, and the `close` would be lost. The
    // connection may be gone already: nothing to tell then.
    let _ = out.send(Outbound::Close { sid }.to_json()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_protocol::{AddInfo, Reply};

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

    /// The relay's end of a connection served with `limits`.
    struct Relay(tokio::io::DuplexStream);

    impl Relay {
        async fn start(registry: Registry, limits: Limits) -> Relay {
            let (relay, daemon) = tokio::io::duplex(1 << 16);
            tokio::spawn(connection(daemon, Arc::new(registry), limits));
            let mut relay = Relay(relay);
            assert!(relay.next().await.starts_with(r#"{"t":"hello""#));
            relay
        }

        async fn send(&mut self, frame: Value) {
            write_frame(&mut self.0, frame.to_string().as_bytes())
                .await
                .unwrap();
        }

        async fn next(&mut self) -> String {
            let frame = timeout(Duration::from_secs(60), read_frame(&mut self.0))
                .await
                .expect("no frame in time")
                .unwrap()
                .expect("connection closed");
            String::from_utf8(frame).unwrap()
        }

        async fn open(&mut self, sid: u32) {
            self.send(serde_json::json!({"t": "open", "sid": sid, "origin": "https://t.test"}))
                .await;
            assert_eq!(self.next().await, format!(r#"{{"t":"open","sid":{sid}}}"#));
            assert!(self.next().await.contains("version"));
        }

        async fn piece(&mut self, sid: u32, data: &str, more: bool) {
            let mut frame = serde_json::json!({"t": "msg", "sid": sid, "data": data});
            if more {
                frame["more"] = Value::Bool(true);
            }
            self.send(frame).await;
        }

        async fn heartbeat(&mut self, sid: u32) {
            self.piece(sid, HEARTBEAT, false).await;
            assert_eq!(
                self.next().await,
                format!(r#"{{"t":"msg","sid":{sid},"data":"--heartbeat--"}}"#)
            );
        }
    }

    /// The budget holds 150 bytes of data in two pieces.
    const SMALL: Limits = Limits {
        max_message: 100,
        budget: 150 + 2 * PIECE_OVERHEAD,
        idle: Duration::from_secs(600),
        max_sockets: 3,
    };

    #[tokio::test]
    async fn open_over_the_socket_cap_is_closed_freed_slots_are_reused() {
        let mut relay = Relay::start(Registry::default(), SMALL).await;
        for sid in 1..=3 {
            relay.open(sid).await;
        }
        // Over the cap: refused, the open sockets go on.
        relay
            .send(serde_json::json!({"t": "open", "sid": 4, "origin": "https://t.test"}))
            .await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":4}"#);
        relay.heartbeat(1).await;
        // A socket closed by the extension frees its slot.
        relay
            .send(serde_json::json!({"t": "close", "sid": 1}))
            .await;
        relay.open(4).await;
        // So does one the daemon closed: its entry goes without a frame for it.
        relay.piece(2, "nope", false).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":2}"#);
        relay.open(5).await;
        relay
            .send(serde_json::json!({"t": "open", "sid": 6, "origin": "https://t.test"}))
            .await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":6}"#);
        relay.heartbeat(3).await;
        relay.heartbeat(4).await;
        relay.heartbeat(5).await;
    }

    /// Asks for the connection to be dropped.
    struct Dropping;

    impl oncl_protocol::Module for Dropping {
        fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
            Reply::Drop
        }
    }

    #[tokio::test]
    async fn bridge_drop_closes_virtual_socket_1006() {
        let mut registry = Registry::default();
        registry.register("drop", Arc::new(Dropping));
        let mut relay = Relay::start(registry, SMALL).await;
        relay.open(1).await;
        relay.open(2).await;
        relay.piece(1, r#"{"module":"drop"}"#, false).await;
        // The extension's shim turns a `close` from the daemon into close 1006 for the page.
        assert_eq!(relay.next().await, r#"{"t":"close","sid":1}"#);
        assert_eq!(crate::session::DROP_CLOSE, 1006);
        relay.heartbeat(2).await;
    }

    /// A request of exactly `len` bytes for a module that does not exist.
    fn unknown_module_request(len: usize) -> String {
        let head = r#"{"module":"none","pad":""#;
        let request = format!(r#"{head}{}"}}"#, "p".repeat(len - head.len() - 2));
        assert_eq!(request.len(), len);
        request
    }

    #[tokio::test]
    async fn message_over_the_limit_closes_only_its_socket() {
        let mut relay = Relay::start(Registry::default(), SMALL).await;
        relay.open(1).await;
        relay.open(2).await;
        // 101 bytes of a valid request: refused for its size alone.
        let over = unknown_module_request(101);
        relay.piece(1, &over[..60], true).await;
        relay.piece(1, &over[60..], false).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":1}"#);
        relay.heartbeat(2).await;
        // Exactly the limit is accepted and answered.
        let exact = unknown_module_request(100);
        relay.piece(2, &exact[..60], true).await;
        relay.piece(2, &exact[60..], false).await;
        assert_eq!(
            relay.next().await,
            r#"{"t":"msg","sid":2,"data":"{\"success\":false,\"errorCode\":\"MODULE_NOT_FOUND\"}"}"#
        );
    }

    /// Dynamic modules that serve `module` (under any name), if set, and record what they are
    /// told.
    #[derive(Default)]
    struct Recorder {
        module: Option<Arc<dyn oncl_protocol::Module>>,
        missing: std::sync::Mutex<Vec<(String, AddInfo)>>,
        closed: std::sync::Mutex<Vec<oncl_protocol::SessionId>>,
    }

    impl oncl_protocol::DynamicModules for Recorder {
        fn module(&self, _name: &str) -> Option<Arc<dyn oncl_protocol::Module>> {
            self.module.clone()
        }

        fn names(&self) -> Vec<String> {
            Vec::new()
        }

        fn session_closed(&self, session: oncl_protocol::SessionId) {
            self.closed.lock().unwrap().push(session);
        }

        fn missing(&self, name: &str, add_info: &AddInfo) {
            self.missing
                .lock()
                .unwrap()
                .push((name.to_owned(), add_info.clone()));
        }
    }

    /// Waits until `recorder` has seen `n` closed sessions; returns them sorted.
    async fn closed(recorder: &Recorder, n: usize) -> Vec<oncl_protocol::SessionId> {
        timeout(Duration::from_secs(60), async {
            loop {
                let mut closed = recorder.closed.lock().unwrap().clone();
                if closed.len() >= n {
                    closed.sort_unstable();
                    return closed;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sessions not closed in time")
    }

    #[tokio::test]
    async fn sockets_are_sessions_closed_once_and_report_missing_modules() {
        let recorder = Arc::new(Recorder::default());
        let mut registry = Registry::default();
        registry.set_dynamic(Arc::clone(&recorder) as Arc<dyn oncl_protocol::DynamicModules>);
        let mut relay = Relay::start(registry, SMALL).await;
        for sid in 1..=3 {
            relay.open(sid).await;
            relay.piece(sid, r#"{"module":"x.Y"}"#, false).await;
            assert_eq!(
                relay.next().await,
                format!(
                    r#"{{"t":"msg","sid":{sid},"data":"{{\"success\":false,\"errorCode\":\"MODULE_NOT_FOUND\"}}"}}"#
                )
            );
        }
        let missing = recorder.missing.lock().unwrap().clone();
        assert_eq!(missing.len(), 3);
        let mut sessions: Vec<_> = missing.iter().map(|(_, info)| info.session).collect();
        for (name, info) in &missing {
            assert_eq!(name, "x.Y");
            assert_eq!(info.origin.as_deref(), Some("https://t.test"));
            assert_ne!(info.session, 0);
        }
        sessions.sort_unstable();
        sessions.dedup();
        assert_eq!(sessions.len(), 3, "every socket is a session of its own");
        // Closed by the extension (the task is aborted), by the daemon on an invalid request,
        // and with the whole connection.
        relay
            .send(serde_json::json!({"t": "close", "sid": 1}))
            .await;
        relay.piece(2, "nope", false).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":2}"#);
        drop(relay);
        assert_eq!(closed(&recorder, 3).await, sessions);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(recorder.closed.lock().unwrap().len(), 3, "closed once each");
    }

    #[tokio::test]
    async fn idle_socket_closes_its_session() {
        let recorder = Arc::new(Recorder::default());
        let mut registry = Registry::default();
        registry.set_dynamic(Arc::clone(&recorder) as Arc<dyn oncl_protocol::DynamicModules>);
        let limits = Limits {
            idle: Duration::from_millis(50),
            ..SMALL
        };
        let mut relay = Relay::start(registry, limits).await;
        relay.open(1).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":1}"#);
        assert_eq!(closed(&recorder, 1).await.len(), 1);
        relay.open(1).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":1}"#);
        let both = closed(&recorder, 2).await;
        assert_ne!(both[0], both[1], "a reopened sid is a new session");
    }

    /// Tells the test that a call came in, then answers once the test lets it.
    struct Entered {
        entered: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl oncl_protocol::Module for Entered {
        fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
            let _ = self.entered.lock().unwrap().send(());
            let _ = self.release.lock().unwrap().recv();
            r#"{"gate":"open"}"#.into()
        }
    }

    #[tokio::test]
    async fn session_closes_after_its_last_call_returns() {
        let (entered_tx, entered) = std::sync::mpsc::channel();
        let (release, release_rx) = std::sync::mpsc::channel();
        let recorder = Arc::new(Recorder {
            module: Some(Arc::new(Entered {
                entered: std::sync::Mutex::new(entered_tx),
                release: std::sync::Mutex::new(release_rx),
            })),
            ..Recorder::default()
        });
        let mut registry = Registry::default();
        registry.set_dynamic(Arc::clone(&recorder) as Arc<dyn oncl_protocol::DynamicModules>);
        let mut relay = Relay::start(registry, SMALL).await;
        relay.open(1).await;
        relay.piece(1, r#"{"module":"x.Y"}"#, false).await;
        tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(60)))
            .await
            .unwrap()
            .expect("the call did not start");
        // The extension closes the socket while its call runs: the socket task is aborted.
        relay
            .send(serde_json::json!({"t": "close", "sid": 1}))
            .await;
        // Frames are handled in order: once sid 2 is open, the close has been handled.
        relay.open(2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            recorder.closed.lock().unwrap().is_empty(),
            "closed while its call runs"
        );
        release.send(()).unwrap();
        assert_eq!(closed(&recorder, 1).await.len(), 1);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(recorder.closed.lock().unwrap().len(), 1, "closed once");
    }

    /// Answers once the test lets it.
    struct Gate(std::sync::Mutex<std::sync::mpsc::Receiver<()>>);

    impl oncl_protocol::Module for Gate {
        fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
            let _ = self.0.lock().unwrap().recv();
            r#"{"gate":"open"}"#.into()
        }
    }

    #[tokio::test]
    async fn socket_over_the_budget_is_closed_others_go_on() {
        let (release, gate) = std::sync::mpsc::channel();
        let mut registry = Registry::default();
        registry.register("gate", Arc::new(Gate(std::sync::Mutex::new(gate))));
        let mut relay = Relay::start(registry, SMALL).await;
        for sid in 1..=3 {
            relay.open(sid).await;
        }
        // 86 bytes held while the module waits.
        let request = format!(r#"{{"module":"gate","pad":"{}"}}"#, "x".repeat(60));
        relay.piece(1, &request, false).await;
        // 86 + 70 > 150: sid 2 is closed.
        relay.piece(2, &"y".repeat(70), true).await;
        assert_eq!(relay.next().await, r#"{"t":"close","sid":2}"#);
        // 86 + 13 fits.
        relay.heartbeat(3).await;
        release.send(()).unwrap();
        assert_eq!(
            relay.next().await,
            r#"{"t":"msg","sid":1,"data":"{\"gate\":\"open\"}"}"#
        );
        // The answered request no longer counts: 90 bytes fit (86 + 90 would not). Had sid 3
        // been closed, its `close` would come before the heartbeat's reply.
        relay.piece(3, &"z".repeat(90), true).await;
        relay.heartbeat(1).await;
    }

    #[tokio::test]
    async fn empty_pieces_count_against_the_budget() {
        let (release, gate) = std::sync::mpsc::channel();
        let mut registry = Registry::default();
        registry.register("gate", Arc::new(Gate(std::sync::Mutex::new(gate))));
        let mut relay = Relay::start(registry, SMALL).await;
        for sid in 1..=3 {
            relay.open(sid).await;
        }
        let request = format!(r#"{{"module":"gate","pad":"{}"}}"#, "x".repeat(60));
        relay.piece(1, &request, false).await;
        // Empty pieces hold no data but still fill the budget: sid 2 is closed.
        for _ in 0..10 {
            relay.piece(2, "", true).await;
        }
        assert_eq!(relay.next().await, r#"{"t":"close","sid":2}"#);
        relay.heartbeat(3).await;
        release.send(()).unwrap();
        assert_eq!(
            relay.next().await,
            r#"{"t":"msg","sid":1,"data":"{\"gate\":\"open\"}"}"#
        );
    }

    #[test]
    fn budget_returns_bytes_on_drop() {
        let budget = Budget::new(10);
        let mut a = budget.take(6).unwrap();
        assert!(budget.take(5).is_none());
        let b = budget.take(4).unwrap();
        a.absorb(b);
        assert!(budget.take(1).is_none());
        drop(a);
        assert!(budget.take(10).is_some());
        assert_eq!(budget.held.load(Ordering::Acquire), 0);
    }

    /// Replies with `len` bytes.
    struct Big(usize);

    impl oncl_protocol::Module for Big {
        fn process(&self, _request: &str, _add_info: &AddInfo) -> Reply {
            "b".repeat(self.0).into()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn close_survives_a_full_out_queue() {
        let mut registry = Registry::default();
        // More frames than the out queue and the duplex buffer hold together.
        registry.register("big", Arc::new(Big((OUT_QUEUE + 8) * NM_FRAME_LIMIT)));
        let mut relay = Relay::start(registry, Limits::DAEMON).await;
        relay.open(1).await;
        relay.open(2).await;
        // The relay reads nothing: sid 1's reply fills the out queue.
        relay.piece(1, r#"{"module":"big"}"#, false).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        // sid 2 ends while its `close` cannot be queued yet...
        relay.piece(2, "nope", false).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        // ...and the connection meanwhile sees a frame for it and an `open`.
        relay.piece(2, HEARTBEAT, false).await;
        relay
            .send(serde_json::json!({"t": "open", "sid": 3, "origin": "https://t.test"}))
            .await;
        // Read everything up to sid 3's greeting.
        let mut closes = 0;
        loop {
            let frame: Value = serde_json::from_str(&relay.next().await).unwrap();
            if frame == serde_json::json!({"t": "close", "sid": 2}) {
                closes += 1;
            }
            if frame["sid"] == 3 && frame["t"] == "msg" {
                break;
            }
        }
        assert_eq!(closes, 1, "sid 2 must be closed exactly once");
        // sid 3 works; the rest of sid 1's reply may come in between.
        relay.piece(3, HEARTBEAT, false).await;
        loop {
            let frame: Value = serde_json::from_str(&relay.next().await).unwrap();
            assert_ne!(frame["sid"], 2, "{frame}");
            if frame["sid"] == 3 {
                assert_eq!(
                    frame,
                    serde_json::json!({"t": "msg", "sid": 3, "data": HEARTBEAT})
                );
                break;
            }
        }
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
