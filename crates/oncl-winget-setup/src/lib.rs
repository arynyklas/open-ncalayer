//! The installer entry WinGet runs for OpenNCALayer.
//!
//! WinGet starts an installer, waits for its exit code and believes it. Velopack's own
//! `Setup.exe`, run over an installation, ends the installed program at once, whatever it is
//! doing (a signature in progress included), and with a prerequisite it cannot install it
//! exits with code 0 having installed nothing. So the release carries the unchanged `Setup.exe`
//! inside this small program ([`payload`]), and WinGet runs this program instead.
//!
//! [`run`] does, in this order, and stops at the first thing that fails with an exit code
//! of its own ([`Exit`]):
//!
//! 1. refuses to run elevated (the installation is the user's own);
//! 2. checks the payload it carries: its SHA-256, version and architecture ([`payload`]);
//! 3. if a program of the installation runs, asks it through its management endpoint to hold
//!    still until nothing is being signed, nothing ended within the quiet time and no window
//!    is open, and holds it for the whole replacement ([`maintenance`]); a program that runs
//!    but cannot be asked is an error, and a busy one is `Busy`: nothing is ever stopped by
//!    force;
//! 4. runs the payload with `--silent` and no other switch, from a private copy it checked;
//! 5. before it declares success, checks what is installed against what it carried
//!    ([`install::verify`]): the installation's own manifest, the installed program, and the
//!    user's Apps & Features entry. Setup's exit code proves nothing by itself;
//! 6. starts the program again if it ran before.
//!
//! Only [`Exit::Success`] is an exit code WinGet may take for success; every other code means
//! that the installation was not replaced (or not proven to be), and says why.
//!
//! The installer is Windows-only: elsewhere [`run`] reports [`Exit::Unsupported`].

pub mod install;
pub mod maintenance;
pub mod payload;
#[cfg(windows)]
pub mod processes;
mod run;

pub use run::{Config, Exit, Report, run};
#[cfg(windows)]
pub use run::{data_dir, production};
