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
        .with(fmt::layer().with_writer(io::stderr))
        .with(file_layer)
        .init();
    result
}
