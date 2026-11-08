//! Saving the reply of a plugin call, as received.
//!
//! The reply is the plugin's own text and the host cannot say which part of it is a signature
//! (that differs from plugin to plugin), so the host never extracts, cleans or cuts it: the
//! whole reply goes to one `.json` file, byte for byte. What the host decides is everything
//! around it: the file is offered only for a call Core reported as applied and finished without
//! error ([`super::report`]), its name is built from the operation's identifier and the plugin's
//! id (never from the reply), the user picks the place in a dialog the host owns, and the file is
//! published as an exclusive hard link of a synced temporary file in the same folder, so that an
//! existing file is never replaced and a failure leaves nothing behind.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroize;

use crate::workspace::JobError;
use crate::workspace::operations::preflight_destination;

/// The longest file name the host suggests, with its extension.
const MAX_NAME: usize = 96;
/// The only extension of a saved reply.
const EXTENSION: &str = ".json";

/// The whole reply as received. It is wiped when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct RawReply(String);

impl RawReply {
    pub(super) fn new(reply: &str) -> RawReply {
        RawReply(reply.to_owned())
    }

    pub(super) fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Drop for RawReply {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for RawReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RawReply({} bytes)", self.0.len())
    }
}

/// What the result page can save: the reply and the name the host suggests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SaveOffer {
    pub(super) reply: RawReply,
    pub(super) name: String,
}

impl SaveOffer {
    pub(super) fn new(reply: &str, operation: &str, plugin_id: &str) -> SaveOffer {
        SaveOffer {
            reply: RawReply::new(reply),
            name: suggested_name(operation, plugin_id),
        }
    }
}

/// The file name suggested for the reply of `operation` of the plugin `plugin_id`: both are
/// the host's own data (the identifier of the declared operation and the installed plugin's id),
/// lower-case letters, digits, `.`, `_` and `-` only, at most [`MAX_NAME`] characters, and
/// always `.json`.
pub(super) fn suggested_name(operation: &str, plugin_id: &str) -> String {
    let base: String = format!("{operation}-{plugin_id}")
        .chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches(|c| matches!(c, '.' | '-'));
    let base = if base.is_empty() {
        "plugin-reply"
    } else {
        base
    };
    let room = MAX_NAME - EXTENSION.len();
    let cut: String = base.chars().take(room).collect();
    format!("{}{EXTENSION}", cut.trim_end_matches(['.', '-']))
}

/// Why the reply was not saved.
#[derive(Debug)]
pub(super) enum SaveError {
    /// The reply is larger than the window saves.
    TooLarge { len: usize, cap: usize },
    /// The destination or the write failed; the words are the tools window's.
    Job(JobError),
}

impl From<std::io::Error> for SaveError {
    fn from(e: std::io::Error) -> Self {
        SaveError::Job(JobError::Io(e.kind()))
    }
}

/// Writes `reply` to `target`: refused above `cap` bytes, refused if the file exists or the
/// folder cannot publish one without replacing anything, otherwise published atomically.
pub(super) fn save_reply(target: &Path, reply: &[u8], cap: usize) -> Result<(), SaveError> {
    save_with(target, reply, cap, |from, to| std::fs::hard_link(from, to))
}

/// [`save_reply`] with the publishing step given (the tests break it).
fn save_with(
    target: &Path,
    reply: &[u8],
    cap: usize,
    link: impl Fn(&Path, &Path) -> std::io::Result<()>,
) -> Result<(), SaveError> {
    if reply.len() > cap {
        return Err(SaveError::TooLarge {
            len: reply.len(),
            cap,
        });
    }
    let parent = match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => PathBuf::from("."),
    };
    if !std::fs::metadata(&parent)?.is_dir() {
        return Err(SaveError::Job(JobError::Io(std::io::ErrorKind::NotFound)));
    }
    preflight_destination(target, &parent).map_err(SaveError::Job)?;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let temporary = parent.join(format!(
        ".oncl-reply-{}-{}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(reply)?;
        file.sync_all()
    })();
    let published = written.map_err(SaveError::from).and_then(|()| {
        link(&temporary, target).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                SaveError::Job(JobError::DestinationExists)
            } else {
                SaveError::Job(JobError::NoLinks)
            }
        })
    });
    let _ = std::fs::remove_file(&temporary);
    published
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn the_name_is_built_from_the_operation_and_the_plugin_and_is_always_json() {
        assert_eq!(
            suggested_name("sign-xml", "kz.rating1c.port"),
            "sign-xml-kz.rating1c.port.json"
        );
        // Whatever the id holds, only the safe set is left.
        let name = suggested_name("sign", "../EVIL/ x\u{202e}.exe");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c)),
            "{name}"
        );
        assert!(name.ends_with(".json") && !name.starts_with('.'));
        let long = suggested_name(&"a".repeat(200), &"b".repeat(200));
        assert!(long.len() <= MAX_NAME && long.ends_with(".json"), "{long}");
        assert_eq!(suggested_name("", ""), "plugin-reply.json");
    }

    #[test]
    fn the_whole_reply_is_written_byte_for_byte_and_no_temporary_file_stays() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.json");
        let reply = format!(
            "{{\"responseObject\":\"{}\"}}\r\n\u{202e}",
            "A".repeat(5000)
        );
        assert!(reply.len() > 2000);
        save_reply(&target, reply.as_bytes(), 1 << 20).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), reply.as_bytes());
        assert_eq!(leftovers(dir.path()), ["out.json"]);
    }

    #[test]
    fn an_existing_file_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.json");
        std::fs::write(&target, b"mine").unwrap();
        let e = save_reply(&target, b"theirs", 1 << 20).unwrap_err();
        assert!(
            matches!(e, SaveError::Job(JobError::DestinationExists)),
            "{e:?}"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"mine");
        assert_eq!(leftovers(dir.path()), ["out.json"]);
        // Also when it appears after the check, at the publishing step itself.
        let late = dir.path().join("late.json");
        let e = save_with(&late, b"theirs", 1 << 20, |from, to| {
            std::fs::write(to, b"mine")?;
            std::fs::hard_link(from, to)
        })
        .unwrap_err();
        assert!(
            matches!(e, SaveError::Job(JobError::DestinationExists)),
            "{e:?}"
        );
        assert_eq!(std::fs::read(&late).unwrap(), b"mine");
    }

    #[test]
    fn a_failed_write_leaves_no_temporary_file_and_a_folder_without_links_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.json");
        let e = save_with(&target, b"x", 1 << 20, |_, _| {
            Err(std::io::ErrorKind::Unsupported.into())
        })
        .unwrap_err();
        assert!(matches!(e, SaveError::Job(JobError::NoLinks)), "{e:?}");
        assert!(
            leftovers(dir.path()).is_empty(),
            "{:?}",
            leftovers(dir.path())
        );
        // A folder that is not there fails before anything is created.
        let missing = dir.path().join("none").join("out.json");
        assert!(save_reply(&missing, b"x", 1 << 20).is_err());
    }

    #[test]
    fn a_reply_over_the_cap_is_refused_with_its_size_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("out.json");
        let e = save_reply(&target, &[b'a'; 11], 10).unwrap_err();
        assert!(
            matches!(e, SaveError::TooLarge { len: 11, cap: 10 }),
            "{e:?}"
        );
        assert!(leftovers(dir.path()).is_empty());
        save_reply(&target, &[b'a'; 10], 10).unwrap();
    }
}
