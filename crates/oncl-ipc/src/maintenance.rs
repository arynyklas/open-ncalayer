//! The management endpoint: how a maintainer (the installer that WinGet runs) asks the
//! running program to hold still while the program is replaced.
//!
//! It is an endpoint of its own ([`endpoint`]), not the relay's and not a route of the wss
//! server or native messaging: only a process of the same user and session reaches it, and
//! it does one thing. A maintainer connects and asks to [`Client::hold`] the program. The
//! program answers with the same decision its updater takes ([`Host::hold`]: new operations
//! are held back first, and only then is it looked at whether an operation runs or ran
//! within the quiet time, or a window is open), so the answer is either [`Reply::Granted`]
//! (nothing runs, nothing new starts) or [`Reply::Busy`] (nothing changed). The hold belongs
//! to the connection: it ends when the maintainer releases it, when the connection closes
//! (a maintainer that was killed), or when `max_lease` has passed (one that hangs).
//!
//! Frames are those of [`crate::write_frame`]; a request is `b"ONCLM"`, the version byte `1`
//! and one operation byte, a reply the same prefix and one status byte.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::timeout_at;

use crate::{Endpoint, IpcListener, IpcStream, connect, read_frame, write_frame};

/// The longest a maintainer holds the program by default: the installer's own limit is
/// shorter, so this is only what ends a lease nobody gives back.
pub const MAX_LEASE: Duration = Duration::from_secs(20 * 60);

const MAGIC: &[u8; 5] = b"ONCLM";
const VERSION: u8 = 1;
/// The largest request or reply this module reads.
const MAX_MESSAGE: usize = 64 * 1024;

const OP_HOLD: u8 = 1;
const OP_RELEASE: u8 = 2;

const STATUS_GRANTED: u8 = 1;
const STATUS_BUSY: u8 = 2;
const STATUS_RELEASED: u8 = 3;
const STATUS_REFUSED: u8 = 4;

/// The management endpoint of the current user, session and data directory.
///
/// # Errors
///
/// As [`crate::endpoint`].
pub fn endpoint(data_dir: &Path) -> io::Result<Endpoint> {
    crate::endpoint::management(data_dir)
}

/// The program a maintainer holds, as the server of the management endpoint sees it.
pub trait Host: Send + Sync + 'static {
    /// One attempt to hold the program: new operations are held back, and only then is it
    /// looked at whether the program is idle (no operation, none within the quiet time, no
    /// window open). `true` if it is and the hold is in place; `false` leaves nothing held.
    /// May block (a window is asked on the event loop).
    fn hold(&self) -> bool;

    /// Lets the operations held back through again; called only after a [`Host::hold`] that
    /// returned `true`.
    fn release(&self);

    /// The arguments (after the program's name) the program runs with, for the maintainer to
    /// start it again as it was.
    fn restart_args(&self) -> Vec<String>;
}

/// A hold made through [`Host::hold`], given back when dropped.
struct Held<H: Host>(Arc<H>);

impl<H: Host> Drop for Held<H> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// Serves the management endpoint: every connection may hold `host`, for `max_lease` at
/// most. Returns only with the error of the listener.
///
/// # Errors
///
/// The listener fails.
pub async fn serve<H: Host>(
    mut listener: IpcListener,
    host: Arc<H>,
    max_lease: Duration,
) -> io::Result<()> {
    loop {
        let stream = listener.accept().await?;
        tokio::spawn(connection(stream, Arc::clone(&host), max_lease));
    }
}

/// One connection: requests in turn, until it closes, fails or its lease runs out. What is
/// held is given back however this ends, even if the task is dropped.
async fn connection<H: Host>(mut stream: IpcStream, host: Arc<H>, max_lease: Duration) {
    let mut held: Option<(Held<H>, Instant)> = None;
    loop {
        let read = read_frame(&mut stream);
        let frame = match &held {
            Some((_, until)) => match timeout_at((*until).into(), read).await {
                Ok(frame) => frame,
                // The lease ran out: the hold is let go, the connection closed.
                Err(_) => return,
            },
            None => read.await,
        };
        let Ok(Some(frame)) = frame else {
            return;
        };
        let status = match request(&frame) {
            Some(OP_HOLD) if held.is_some() => granted(&*host),
            Some(OP_HOLD) => {
                let attempt = Arc::clone(&host);
                // Under `spawn_blocking`: a window is asked on the event loop. The guard is
                // made in the closure, so a hold that succeeds after this task is gone is
                // still given back.
                let hold =
                    tokio::task::spawn_blocking(move || attempt.hold().then(|| Held(attempt)))
                        .await;
                match hold {
                    Ok(Some(guard)) => {
                        held = Some((guard, Instant::now() + max_lease));
                        granted(&*host)
                    }
                    Ok(None) => vec![STATUS_BUSY],
                    Err(_) => return,
                }
            }
            Some(OP_RELEASE) => {
                drop(held.take());
                vec![STATUS_RELEASED]
            }
            _ => vec![STATUS_REFUSED],
        };
        if write_frame(&mut stream, &reply(&status)).await.is_err() {
            return;
        }
    }
}

/// The operation of a well-formed request.
fn request(frame: &[u8]) -> Option<u8> {
    let rest = frame.strip_prefix(MAGIC.as_slice())?;
    match rest {
        [VERSION, op] => Some(*op),
        _ => None,
    }
}

fn reply(status: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MAGIC.len() + 1 + status.len());
    frame.extend_from_slice(MAGIC);
    frame.push(VERSION);
    frame.extend_from_slice(status);
    frame
}

/// The status of a grant: the arguments to start the program with again, each at most
/// `u16::MAX` bytes (what does not fit is not told).
fn granted<H: Host>(host: &H) -> Vec<u8> {
    let args: Vec<String> = host
        .restart_args()
        .into_iter()
        .filter(|arg| arg.len() <= usize::from(u16::MAX))
        .take(usize::from(u16::MAX))
        .collect();
    let mut status = vec![STATUS_GRANTED];
    status.extend_from_slice(&u16::try_from(args.len()).unwrap_or(0).to_le_bytes());
    for arg in &args {
        status.extend_from_slice(&u16::try_from(arg.len()).unwrap_or(0).to_le_bytes());
        status.extend_from_slice(arg.as_bytes());
    }
    status
}

/// What the program answered to a request to hold it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Nothing runs and nothing new starts until the connection of the [`Client`] ends or it
    /// releases the hold. `restart` are the arguments the program runs with.
    Granted {
        /// The arguments (after the program's name) to start it again with.
        restart: Vec<String>,
    },
    /// An operation runs or ended within the quiet time, a window is open or another
    /// maintainer holds the program. Nothing is held.
    Busy,
}

/// The connection of a maintainer to the running program; a hold lasts as long as it.
#[derive(Debug)]
pub struct Client {
    stream: IpcStream,
}

impl Client {
    /// Connects to the management endpoint `ep`, whose server must run as this user.
    ///
    /// # Errors
    ///
    /// As [`crate::connect`]: [`io::ErrorKind::NotFound`] or
    /// [`io::ErrorKind::ConnectionRefused`] if no program serves `ep`.
    pub async fn connect(ep: &Endpoint) -> io::Result<Client> {
        Ok(Client {
            stream: connect(ep).await?,
        })
    }

    /// Asks the program to hold still once. Asking again while holding is granted again.
    ///
    /// # Errors
    ///
    /// The connection fails or closes (a hold of this connection is gone then), or the
    /// program does not understand the request.
    pub async fn hold(&mut self) -> io::Result<Reply> {
        let status = self.ask(OP_HOLD).await?;
        match status.split_first() {
            Some((&STATUS_GRANTED, rest)) => Ok(Reply::Granted {
                restart: parse_args(rest).ok_or_else(invalid)?,
            }),
            Some((&STATUS_BUSY, [])) => Ok(Reply::Busy),
            Some((&STATUS_REFUSED, _)) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the program does not understand this request",
            )),
            _ => Err(invalid()),
        }
    }

    /// [`Client::hold`] again every `poll` while the program is busy, until `within` has
    /// passed: the answer of the last attempt, which is [`Reply::Busy`] if the program never
    /// came idle. At least one attempt is made.
    ///
    /// # Errors
    ///
    /// As [`Client::hold`].
    pub async fn hold_within(&mut self, within: Duration, poll: Duration) -> io::Result<Reply> {
        let deadline = Instant::now() + within;
        loop {
            let reply = self.hold().await?;
            let left = deadline.saturating_duration_since(Instant::now());
            if matches!(reply, Reply::Granted { .. }) || left.is_zero() {
                return Ok(reply);
            }
            // The last attempt is made at the deadline itself.
            tokio::time::sleep(poll.min(left)).await;
        }
    }

    /// Gives the hold back (nothing is done if there is none).
    ///
    /// # Errors
    ///
    /// The connection fails or closes.
    pub async fn release(&mut self) -> io::Result<()> {
        match self.ask(OP_RELEASE).await?.as_slice() {
            [STATUS_RELEASED] => Ok(()),
            _ => Err(invalid()),
        }
    }

    async fn ask(&mut self, op: u8) -> io::Result<Vec<u8>> {
        let mut request = Vec::with_capacity(MAGIC.len() + 2);
        request.extend_from_slice(MAGIC);
        request.extend_from_slice(&[VERSION, op]);
        write_frame(&mut self.stream, &request).await?;
        let frame = read_frame(&mut self.stream)
            .await?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        if frame.len() > MAX_MESSAGE {
            return Err(invalid());
        }
        frame
            .strip_prefix(MAGIC.as_slice())
            .and_then(|rest| rest.strip_prefix(&[VERSION]))
            .map(<[u8]>::to_vec)
            .ok_or_else(invalid)
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the program's answer is not understood",
    )
}

/// The arguments of a grant: a `u16` count, then each as a `u16` length and UTF-8 bytes.
fn parse_args(mut rest: &[u8]) -> Option<Vec<String>> {
    let mut take = |n: usize| -> Option<&[u8]> {
        let (head, tail) = rest.split_at_checked(n)?;
        rest = tail;
        Some(head)
    };
    let count = usize::from(u16::from_le_bytes(take(2)?.try_into().ok()?));
    let mut args = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let len = usize::from(u16::from_le_bytes(take(2)?.try_into().ok()?));
        args.push(String::from_utf8(take(len)?.to_vec()).ok()?);
    }
    rest.is_empty().then_some(args)
}
