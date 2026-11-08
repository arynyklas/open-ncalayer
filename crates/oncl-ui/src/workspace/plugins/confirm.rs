//! The confirm button's handler, and the only code that can make a [`PressToken`].
//!
//! [`consent::user_confirmed`](super::consent::user_confirmed) needs a `PressToken`. The token's
//! constructor is private to the nested module `press`, which only this module can see, so no
//! other part of the page (the worker in `run.rs`, the consent text, a test helper outside
//! `cfg(test)`) can make one: the user's confirmation cannot be made anywhere but here, from the
//! handler of the button, after the controller let the press through.

use std::rc::Rc;

use super::controller::{Effect, Event};
use super::run::Decision;
use super::{consent, facts_of, locale, render, report, state, texts};
use crate::workspace::Workspace;

mod press {
    /// The press of the confirm button, as a value. Not `Clone`, not `Copy`.
    pub struct PressToken(());

    /// Made by the handler of the button, with its callback context, and by nothing else.
    pub(super) fn of_the_button(_callback: &crate::workspace::Workspace) -> PressToken {
        PressToken(())
    }

    #[cfg(test)]
    pub(in crate::workspace::plugins) fn for_tests() -> PressToken {
        PressToken(())
    }
}

pub(super) use press::PressToken;

#[cfg(test)]
pub(super) use press::for_tests as press_for_tests;

/// The button that names the action: the only way to the key. The controller lets the press
/// through only for a prepared, shown and armed confirmation; the confirmation is then made for
/// exactly the summary the page shows and sent to the worker that waits for it.
pub(super) fn confirm(open: &Rc<Workspace>) {
    let t = texts(open);
    let mut st = state(open);
    if st.controller.dispatch(Event::Confirm) != Effect::Confirmed {
        return;
    }
    let confirmation = st
        .shown
        .as_ref()
        .map(|shown| consent::user_confirmed(&shown.summary, press::of_the_button(open)));
    let sent = match (confirmation, st.decision.take()) {
        (Some(confirmation), Some(tx)) => tx.send(Decision::Proceed(confirmation)).is_ok(),
        _ => false,
    };
    // Nothing of the confirmation stays on the page.
    st.shown = None;
    st.shown_at = None;
    st.tick.stop();
    if !sent {
        // The worker is gone: there is nobody to confirm to, and the key was never used.
        st.controller.dispatch(Event::Finished);
        let facts = facts_of(&st);
        st.result = Some(report::render_cancelled(&facts.as_facts(), locale(open)));
    }
    drop(st);
    open.ui.set_status_text(t.s_running.into());
    render(open);
}
