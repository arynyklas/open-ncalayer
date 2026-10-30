//! `dialogs`: a message, a yes/no question and a password that stays in the core.

use super::{DialogTurn, MAX_DIALOG_TEXT, MAX_LINE, check_line, invalid, limit, origin, source};
use crate::host::HostState;
use oncl_basics::{ConfirmPrompt, MessagePrompt, PasswordPrompt, Prompt};
use oncl_pdk::abi::{ConfirmArgs, HostResult, MessageArgs, MessageKind, PasswordArgs, SecretRef};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The most passwords of `dialog_password` an instance keeps.
pub const MAX_SECRETS: usize = 8;

/// The passwords of `dialog_password` an instance keeps, by id. Ids count up and are never
/// reused.
#[derive(Default)]
pub(crate) struct Secrets {
    secrets: BTreeMap<u32, Zeroizing<String>>,
    last: u32,
}

impl Secrets {
    /// Whether another password fits.
    fn has_room(&self) -> HostResult<()> {
        if self.secrets.len() >= MAX_SECRETS || self.last == u32::MAX {
            return Err(limit(format!(
                "at most {MAX_SECRETS} passwords in an instance"
            )));
        }
        Ok(())
    }

    /// Keeps `secret` under a new id.
    fn insert(&mut self, secret: Zeroizing<String>) -> HostResult<u32> {
        self.has_room()?;
        self.last += 1;
        self.secrets.insert(self.last, secret);
        Ok(self.last)
    }

    /// The password of `id`.
    pub(crate) fn get(&self, id: u32) -> HostResult<&str> {
        self.secrets
            .get(&id)
            .map(|s| s.as_str())
            .ok_or_else(|| invalid(format!("no password has the id {id}")))
    }
}

/// `dialog_password`: the plugin's password dialog; the password stays in the instance,
/// the guest gets its id.
pub(crate) fn dialog_password(
    state: &mut HostState,
    args: PasswordArgs,
) -> HostResult<Option<SecretRef>> {
    check_line("the title", &args.title, MAX_LINE)?;
    check_line("the label", &args.label, MAX_DIALOG_TEXT)?;
    check_line("the OK text", &args.ok, MAX_LINE)?;
    check_line("the Cancel text", &args.cancel, MAX_LINE)?;
    state.secrets.has_room()?;
    let non_empty = |text: String| (!text.is_empty()).then_some(text);
    let prompt = PasswordPrompt {
        origin: origin(state),
        locale: state.call.locale,
        message: non_empty(args.label),
        source: Some(source(state)),
        title: non_empty(args.title),
        ok: non_empty(args.ok),
        cancel: non_empty(args.cancel),
        allow_empty: args.allow_empty,
    };
    DialogTurn::hold();
    match state.services.prompter.password(&prompt) {
        Prompt::Answer(password) if password.is_empty() && !args.allow_empty => Ok(None),
        Prompt::Answer(password) => Ok(Some(SecretRef {
            id: state.secrets.insert(password)?,
        })),
        Prompt::Cancelled => Ok(None),
    }
}

/// `dialog_message`.
pub(crate) fn dialog_message(state: &mut HostState, args: MessageArgs) -> HostResult<()> {
    check_line("the text", &args.text, MAX_DIALOG_TEXT)?;
    let prompt = MessagePrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        kind: match args.kind {
            MessageKind::Info => oncl_basics::MessageKind::Info,
            MessageKind::Warning => oncl_basics::MessageKind::Warning,
            MessageKind::Error => oncl_basics::MessageKind::Error,
        },
        text: args.text,
    };
    DialogTurn::hold();
    // Read or closed: the plugin goes on either way.
    let _ = state.services.prompter.message(&prompt);
    Ok(())
}

/// `dialog_confirm`: `true` only for yes.
pub(crate) fn dialog_confirm(state: &mut HostState, args: ConfirmArgs) -> HostResult<bool> {
    check_line("the text", &args.text, MAX_DIALOG_TEXT)?;
    let prompt = ConfirmPrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        text: args.text,
    };
    DialogTurn::hold();
    Ok(state.services.prompter.confirm(&prompt) == Prompt::Answer(true))
}
