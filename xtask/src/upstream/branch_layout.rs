//! The layout of the `upstream` branch: `state.json`, `latest/facts.json`, `index.json` and
//! `history/<id>/{facts,diff,changes}.json`.

/// The poll state.
pub const STATE: &str = "state.json";
/// The latest facts.
pub const LATEST: &str = "latest/facts.json";
/// The index of the history.
pub const INDEX: &str = "index.json";
