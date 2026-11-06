//! Holding the running program still for the whole replacement.
//!
//! The running program serves a management endpoint ([`oncl_ipc::maintenance`]); a hold
//! there is the decision of its own updater, taken with new operations already held back.
//! The hold belongs to the connection, so the lease here is the connection: it is kept for
//! as long as the installation is being replaced, and if this process dies the program lets
//! go by itself.
//!
//! A program that serves no endpoint is not the same as no program: [`acquire`] says
//! [`Acquired::Absent`] only when nothing listens, and the caller must then look for a
//! running program it cannot ask before it goes on.

use std::io;
use std::time::Duration;

use oncl_ipc::Endpoint;
use oncl_ipc::maintenance::{Client, Reply};
use tokio::runtime::{Builder, Runtime};

/// Why the program could not be held.
#[derive(Debug)]
pub enum Refusal {
    /// It stayed busy for the whole wait: an operation runs or ended within the quiet time,
    /// a window is open, or another maintainer holds it.
    Busy,
    /// It listens but could not be asked (another user's, an answer not understood, a broken
    /// connection).
    Unreachable(io::Error),
}

/// The outcome of asking for the hold.
#[derive(Debug)]
pub enum Acquired {
    /// The program is held until the lease ends.
    Held(Lease),
    /// Nothing listens on the endpoint.
    Absent,
}

/// The hold of the running program: kept for as long as this lives.
#[derive(Debug)]
pub struct Lease {
    // The client goes before the runtime its connection is registered with.
    client: Client,
    runtime: Runtime,
    restart: Vec<String>,
    pid: u32,
}

impl Lease {
    /// The process that holds still.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The arguments the program runs with, for starting it again.
    pub fn restart_args(&self) -> &[String] {
        &self.restart
    }

    /// Whether the program still holds still for this lease: asked again, right now.
    ///
    /// # Errors
    ///
    /// The connection is gone (the hold ended with it) or the program is not holding any
    /// more.
    pub fn confirm(&mut self) -> io::Result<()> {
        match self.runtime.block_on(self.client.hold())? {
            Reply::Granted { .. } => Ok(()),
            Reply::Busy => Err(io::Error::other("the program does not hold still any more")),
        }
    }
}

/// Asks the program on `endpoint` to hold still, again every `poll` while it is busy, for
/// `wait` at most (one attempt is always made).
///
/// # Errors
///
/// [`Refusal::Busy`] if it did not become idle in time, [`Refusal::Unreachable`] if it
/// could not be asked.
pub fn acquire(endpoint: &Endpoint, wait: Duration, poll: Duration) -> Result<Acquired, Refusal> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(Refusal::Unreachable)?;
    let mut client = match runtime.block_on(Client::connect(endpoint)) {
        Ok(client) => client,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(Acquired::Absent);
        }
        Err(e) => return Err(Refusal::Unreachable(e)),
    };
    match runtime.block_on(client.hold_within(wait, poll)) {
        Ok(Reply::Granted { restart, pid }) => Ok(Acquired::Held(Lease {
            pid,
            client,
            runtime,
            restart,
        })),
        Ok(Reply::Busy) => Err(Refusal::Busy),
        Err(e) => Err(Refusal::Unreachable(e)),
    }
}
