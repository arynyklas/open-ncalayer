//! Reports of the manual tools: what the SDK found, said without deciding it again.
//! [`controller`] holds the owned views of the SDK's structured reports and the transformations
//! in which a careless word would mislead (an indeterminate verdict called success, a partial
//! batch called finished, a key called unused); this module turns them into the rows the page
//! shows, in the window's language.

pub(crate) mod controller;
