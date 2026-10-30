//! The host functions, by area:
//!
//! - [`keys`]: the user's key, chosen in the storage and key dialogs or opened from a store
//!   the plugin names, behind a handle of the instance; signatures made here, the private
//!   key never reaching the guest;
//! - [`crypto`]: digests, certificate details and the CAs the core trusts (every plugin);
//! - [`dialogs`]: a message, a yes/no question and a password that stays in the core;
//! - [`files`]: a file the user opens or saves in the system dialogs;
//! - [`net`]: HTTPS requests to URLs under the manifest's prefixes, redirects not followed.
//!
//! The first host function that shows a window takes the process-wide dialog-flow turn
//! ([`lock_dialog_flow`]) and holds it until `oncl_process` returns, trap or not
//! ([`DialogTurn`]), so a plugin's dialogs and those of other modules do not interleave.

mod crypto;
mod dialogs;
mod files;
mod keys;
mod net;

pub(crate) use crypto::{ca_issuer, ca_list, cert_details, hash};
pub use dialogs::MAX_SECRETS;
pub(crate) use dialogs::{Secrets, dialog_confirm, dialog_message, dialog_password};
pub(crate) use files::{file_open, file_save};
pub(crate) use keys::{
    KeyTable, keys_chain, keys_choose, keys_open, keys_release, keys_select, keys_sign_cms,
    keys_sign_raw, keys_sign_xml, keys_terminals,
};
pub(crate) use net::http_request;
pub use net::{HTTP_TIMEOUT, MAX_HTTP_BODY};

use crate::host::HostState;
use oncl_basics::lock_dialog_flow;
use oncl_pdk::abi::{ErrorCode, HostError, HostResult};
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::MutexGuard;

/// The most keys an instance holds at once.
pub const MAX_KEY_HANDLES: usize = 16;

/// The page files the user allowed pages to open in an instance's session: (origin,
/// canonical path).
pub(crate) type Consents = HashSet<(String, PathBuf)>;

/// Longest text of a message or a question, in bytes.
const MAX_DIALOG_TEXT: usize = 16 << 10;

/// Longest `detail` of `keys_choose` and suggested file name, in bytes.
const MAX_LINE: usize = 1024;

/// Origin shown when the connection sent none.
const UNIDENTIFIED: &str = "UNIDENTIFIED";

thread_local! {
    /// The dialog-flow turn this thread's request holds, once a dialog was shown.
    static TURN: RefCell<Option<MutexGuard<'static, ()>>> = const { RefCell::new(None) };
    /// How many [`DialogTurn`] scopes are open on this thread.
    static SCOPES: Cell<usize> = const { Cell::new(0) };
}

/// The span of one `oncl_process` call on this thread: the dialog-flow turn a host function
/// takes in it is let go when the outermost scope ends, whatever ended it.
pub(crate) struct DialogTurn(());

impl DialogTurn {
    /// Opens a scope.
    pub(crate) fn scope() -> DialogTurn {
        SCOPES.set(SCOPES.get() + 1);
        DialogTurn(())
    }

    /// Takes the turn for the rest of the scope, unless this thread has it already.
    fn hold() {
        TURN.with_borrow_mut(|turn| {
            if turn.is_none() {
                *turn = Some(lock_dialog_flow());
            }
        });
    }
}

impl Drop for DialogTurn {
    fn drop(&mut self) {
        let open = SCOPES.get().saturating_sub(1);
        SCOPES.set(open);
        if open == 0 {
            TURN.with_borrow_mut(|turn| drop(turn.take()));
        }
    }
}

fn invalid(message: impl Into<String>) -> HostError {
    HostError::new(ErrorCode::Invalid, message)
}

fn denied(message: impl Into<String>) -> HostError {
    HostError::new(ErrorCode::Denied, message)
}

fn failed(message: impl std::fmt::Display) -> HostError {
    HostError::new(ErrorCode::Failed, message.to_string())
}

fn limit(message: impl Into<String>) -> HostError {
    HostError::new(ErrorCode::Limit, message)
}

/// The page's origin, as the dialogs show it.
fn origin(state: &HostState) -> String {
    state
        .call
        .origin
        .clone()
        .unwrap_or_else(|| UNIDENTIFIED.to_owned())
}

/// The plugin's name in the request's language, as the dialogs show it.
fn source(state: &HostState) -> String {
    state.session.plugin_name.get(state.call.locale).to_owned()
}

fn check_line(what: &str, text: &str, max: usize) -> HostResult<()> {
    if text.len() > max {
        return Err(limit(format!("{what} is over {max} bytes")));
    }
    Ok(())
}
