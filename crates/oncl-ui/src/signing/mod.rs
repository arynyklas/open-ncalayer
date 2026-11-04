//! One signing operation in one window, step by step: the state machine and its consent
//! contract ([`controller`]).

pub mod controller;
pub mod runner;

pub use controller::{
    ActionKind, Approved, Candidate, Controller, Effect, Event, Item, Refusal, Step, Unsuitable,
    UserConsent,
};

#[cfg(test)]
pub(crate) mod testing;
