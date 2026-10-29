//! Logging to stderr and to daily-rotated files in the log directory.
//!
//! Passwords and the data being signed are never logged: the server logs only lengths of
//! requests and replies.

use std::io;
use std::path::Path;

use tracing::level_filters::LevelFilter;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Log files kept: one per day.
const KEEP_FILES: usize = 7;

/// Sends `INFO` and above to stderr and to `<dir>/openncalayer.<date>.log`, rotated daily,
/// keeping [`KEEP_FILES`] files. Without a usable `dir` only stderr is used and the returned
/// error says why.
///
/// # Errors
///
/// The log directory cannot be created or opened; logging to stderr is set up anyway.
pub fn init(dir: &Path) -> io::Result<()> {
    init_with(dir, true)
}

/// As [`init`], but to the files only: for commands that print for the user themselves.
///
/// # Errors
///
/// The log directory cannot be created or opened; nothing is logged then.
pub fn init_files(dir: &Path) -> io::Result<()> {
    init_with(dir, false)
}

fn init_with(dir: &Path, stderr: bool) -> io::Result<()> {
    let file = std::fs::create_dir_all(dir).and_then(|()| {
        RollingFileAppender::builder()
            .rotation(Rotation::DAILY)
            .filename_prefix("openncalayer")
            .filename_suffix("log")
            .max_log_files(KEEP_FILES)
            .build(dir)
            .map_err(io::Error::other)
    });
    let (file_layer, result) = match file {
        Ok(appender) => (
            Some(fmt::layer().with_ansi(false).with_writer(appender)),
            Ok(()),
        ),
        Err(e) => (None, Err(e)),
    };
    tracing_subscriber::registry()
        .with(LevelFilter::INFO)
        .with(stderr.then(|| fmt::layer().with_writer(io::stderr)))
        .with(file_layer)
        .init();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The only test that installs the global subscriber in this test binary.
    #[test]
    fn log_records_reach_the_file() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path()).unwrap();
        log::error!(target: "rfd", "Failed to pick file with zenity: test record");
        log::debug!(target: "rfd", "below the level: not written");
        let files: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(files.len(), 1, "{files:?}");
        let text = std::fs::read_to_string(&files[0]).unwrap();
        assert!(
            text.contains("ERROR rfd: Failed to pick file with zenity: test record"),
            "{text}"
        );
        assert!(!text.contains("below the level"), "{text}");
    }
}
