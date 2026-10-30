//! `dialogs`: a message and a yes/no question.

use super::{DialogTurn, MAX_DIALOG_TEXT, check_line, origin, source};
use crate::host::HostState;
use oncl_basics::{ConfirmPrompt, MessagePrompt, Prompt};
use oncl_pdk::abi::{ConfirmArgs, HostResult, MessageArgs, MessageKind};

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
