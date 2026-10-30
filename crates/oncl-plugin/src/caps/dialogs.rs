//! `dialogs`: a message, a yes/no question, a choice of the plugin's buttons (and list) and
//! a password that stays in the core.

use super::{DialogTurn, MAX_DIALOG_TEXT, MAX_LINE, check_line, invalid, limit, origin, source};
use crate::host::HostState;
use oncl_basics::{
    ChoiceAnswer, ChoicePrompt, ConfirmPrompt, MessagePrompt, PasswordPrompt, Prompt,
};
use oncl_pdk::abi::{
    ChoiceArgs, ConfirmArgs, HostResult, MAX_CHOICE_OPTIONS, MessageArgs, MessageKind,
    PasswordArgs, SecretRef,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The most passwords of `dialog_password` an instance keeps; a further one replaces the
/// oldest.
pub const MAX_SECRETS: usize = 8;

/// The passwords of `dialog_password` an instance keeps, by id. Ids count up and are never
/// reused, so the id of a password that was let go stays invalid.
#[derive(Default)]
pub(crate) struct Secrets {
    secrets: BTreeMap<u32, Zeroizing<String>>,
    last: u32,
}

impl Secrets {
    /// Whether another id is left.
    fn has_room(&self) -> HostResult<()> {
        if self.last == u32::MAX {
            return Err(limit("no password ids left in this instance".to_owned()));
        }
        Ok(())
    }

    /// Keeps `secret` under a new id; at [`MAX_SECRETS`] the oldest password is wiped.
    fn insert(&mut self, secret: Zeroizing<String>) -> HostResult<u32> {
        self.has_room()?;
        while self.secrets.len() >= MAX_SECRETS {
            self.secrets.pop_first();
        }
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
        kind: message_kind(args.kind),
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

fn message_kind(kind: MessageKind) -> oncl_basics::MessageKind {
    match kind {
        MessageKind::Info => oncl_basics::MessageKind::Info,
        MessageKind::Warning => oncl_basics::MessageKind::Warning,
        MessageKind::Error => oncl_basics::MessageKind::Error,
    }
}

/// The most buttons of `dialog_choice`.
const MAX_CHOICE_BUTTONS: usize = 3;

/// `dialog_choice`: the index of the button pressed; with a list, the index of the option
/// selected when the first button is pressed (else `None`); `None` if the dialog is closed.
pub(crate) fn dialog_choice(state: &mut HostState, args: ChoiceArgs) -> HostResult<Option<u8>> {
    if args.buttons.is_empty() || args.buttons.len() > MAX_CHOICE_BUTTONS {
        return Err(invalid(format!(
            "a choice has 1 to {MAX_CHOICE_BUTTONS} buttons"
        )));
    }
    if usize::from(args.default) >= args.buttons.len() {
        return Err(invalid("the default button is not one of the buttons"));
    }
    if args.options.len() > MAX_CHOICE_OPTIONS {
        return Err(invalid(format!(
            "a choice has at most {MAX_CHOICE_OPTIONS} options"
        )));
    }
    let too_long = |text: &str, max: usize| text.len() > max;
    if too_long(&args.text, MAX_DIALOG_TEXT)
        || args.title.as_deref().is_some_and(|t| too_long(t, MAX_LINE))
        || args
            .buttons
            .iter()
            .chain(&args.options)
            .any(|t| too_long(t, MAX_LINE))
    {
        return Err(invalid(format!(
            "the text is over {MAX_DIALOG_TEXT} bytes, or a title, button or option over {MAX_LINE}"
        )));
    }
    let options = args.options.len();
    let prompt = ChoicePrompt {
        origin: origin(state),
        locale: state.call.locale,
        source: source(state),
        kind: message_kind(args.kind),
        title: args.title,
        text: args.text,
        buttons: args.buttons,
        default: usize::from(args.default),
        options: args.options,
    };
    DialogTurn::hold();
    let answer = match state.services.prompter.choice(&prompt) {
        Prompt::Answer(answer) => answer,
        Prompt::Cancelled => return Ok(None),
    };
    let picked = match answer {
        ChoiceAnswer { button, .. } if button >= prompt.buttons.len() => None,
        ChoiceAnswer { button, .. } if options == 0 => Some(button),
        ChoiceAnswer {
            button: 0,
            option: Some(option),
        } if option < options => Some(option),
        ChoiceAnswer { .. } => None,
    };
    // At most 32 options or 3 buttons: fits a u8.
    Ok(picked.map(|i| i as u8))
}
