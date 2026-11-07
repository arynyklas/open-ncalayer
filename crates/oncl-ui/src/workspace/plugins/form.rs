//! The form of one operation: the fields its declared parameters make, the values the user
//! typed read into typed values, and the document read once into memory within its declared
//! limit. Nothing here touches Slint or the engine.
//!
//! The declaration (`oncl_plugin::operations::Param`) is the only source of fields: a field has
//! the kind and the limit the manifest gave it, the window adds none and widens none. The engine
//! checks the same limits again when it builds the request ([`oncl_core::Engine::plugin_request`]);
//! this is the early, friendly refusal, not the authority.

use std::path::{Path, PathBuf};

use oncl_flows::Locale;
use oncl_pki::resource::{OperationControl, Progress};
use oncl_plugin::operations::{Param, ParamKind};

use crate::workspace::JobError;
use crate::workspace::open_regular;

/// One field of the form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FormField {
    /// The parameter's name: `^[a-z][a-z0-9_]{0,31}$`, checked at parse.
    pub(super) name: String,
    pub(super) kind: FieldKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FieldKind {
    /// A file the user picks; at most `max_bytes`.
    Document {
        max_bytes: u64,
    },
    /// Typed text; at most `max_chars` characters.
    Text {
        max_chars: u32,
    },
    /// One of the declared choices.
    Choice {
        choices: Vec<String>,
    },
    Flag,
    /// `ru`, `kk` or `en`.
    Locale,
}

/// The languages a `locale` parameter takes, in the order of its choices.
pub(super) const LOCALES: [&str; 3] = ["ru", "kk", "en"];

/// What the page holds for one field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FieldValue {
    /// The path of a document, or typed text.
    Text(String),
    /// The index of a choice or of a language.
    Index(Option<usize>),
    Flag(bool),
}

/// The fields of `params`, in the manifest's order.
pub(super) fn fields_of(params: &[Param]) -> Vec<FormField> {
    params
        .iter()
        .map(|p| FormField {
            name: p.name.clone(),
            kind: match &p.kind {
                ParamKind::Document { max_bytes } => FieldKind::Document {
                    max_bytes: *max_bytes,
                },
                ParamKind::Text { max_chars } => FieldKind::Text {
                    max_chars: *max_chars,
                },
                ParamKind::Choice { choices } => FieldKind::Choice {
                    choices: choices.clone(),
                },
                ParamKind::Flag => FieldKind::Flag,
                ParamKind::Locale => FieldKind::Locale,
            },
        })
        .collect()
}

/// The empty form: no path, no text, no choice (a choice is made by the user, never defaulted),
/// the flag off, the language the window speaks.
pub(super) fn initial(fields: &[FormField], window: Locale) -> Vec<FieldValue> {
    fields
        .iter()
        .map(|f| match &f.kind {
            FieldKind::Document { .. } | FieldKind::Text { .. } => FieldValue::Text(String::new()),
            FieldKind::Choice { .. } => FieldValue::Index(None),
            FieldKind::Flag => FieldValue::Flag(false),
            FieldKind::Locale => FieldValue::Index(Some(match window {
                Locale::Ru => 0,
                Locale::Kk => 1,
                Locale::En => 2,
            })),
        })
        .collect()
}

/// A value of the form, typed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Typed {
    Document(PathBuf),
    Text(String),
    Choice(String),
    Flag(bool),
    Locale(&'static str),
}

/// Why the form cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FormError {
    NoPath(String),
    TextTooLong {
        name: String,
        max: u32,
    },
    NoChoice(String),
    /// A text with a character that cannot be shown as it is typed (see [`bad_text_char`]).
    BadText(String),
}

/// Whether `c` may not be in a text parameter. A text is SIGNED BYTES: the confirmation shows
/// the exact text, so a character that is drawn as nothing or reorders the text around it
/// (controls other than line breaks and tab, bidirectional marks and isolates, zero-width and
/// other invisible format characters) is refused instead of being hidden on the page.
pub(super) fn bad_text_char(c: char) -> bool {
    !matches!(c, '\n' | '\r' | '\t') && crate::view::is_invisible(c)
}

/// A path as typed or pasted: Explorer's «Copy as path» wraps it in quotes.
fn typed_path(text: &str) -> &str {
    text.trim().trim_matches('"').trim()
}

/// The typed values of the form, each against its field. A text is counted in characters, like
/// its declared limit; it is not normalised or trimmed (what is signed over it is exactly what
/// was typed).
///
/// # Errors
///
/// The first field that is not acceptable.
pub(super) fn read(
    fields: &[FormField],
    values: &[FieldValue],
) -> Result<Vec<(String, Typed)>, FormError> {
    let mut out = Vec::with_capacity(fields.len());
    for (field, value) in fields.iter().zip(values) {
        let typed = match (&field.kind, value) {
            (FieldKind::Document { .. }, FieldValue::Text(path)) => {
                let path = typed_path(path);
                if path.is_empty() {
                    return Err(FormError::NoPath(field.name.clone()));
                }
                Typed::Document(PathBuf::from(path))
            }
            (FieldKind::Text { max_chars }, FieldValue::Text(text)) => {
                if text.chars().any(bad_text_char) {
                    return Err(FormError::BadText(field.name.clone()));
                }
                if text.chars().count() as u64 > u64::from(*max_chars) {
                    return Err(FormError::TextTooLong {
                        name: field.name.clone(),
                        max: *max_chars,
                    });
                }
                Typed::Text(text.clone())
            }
            (FieldKind::Choice { choices }, FieldValue::Index(Some(i))) if *i < choices.len() => {
                Typed::Choice(choices[*i].clone())
            }
            (FieldKind::Choice { .. }, _) => return Err(FormError::NoChoice(field.name.clone())),
            (FieldKind::Flag, FieldValue::Flag(on)) => Typed::Flag(*on),
            (FieldKind::Locale, FieldValue::Index(Some(i))) if *i < LOCALES.len() => {
                Typed::Locale(LOCALES[*i])
            }
            // A value of another kind than its field's: the page and the form disagree, and
            // nothing is guessed.
            _ => return Err(FormError::NoChoice(field.name.clone())),
        };
        out.push((field.name.clone(), typed));
    }
    Ok(out)
}

/// A value frozen for the call: the document's bytes as they were read once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Frozen {
    /// The file's name as the user's path gives it (never checked, shown as given), and its
    /// bytes.
    Document {
        file_name: String,
        bytes: Vec<u8>,
    },
    Text(String),
    Choice(String),
    Flag(bool),
    Locale(&'static str),
}

/// Why a document was not frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::workspace) enum FreezeError {
    Unreadable(String),
    TooBig { name: String, max: u64 },
    Empty(String),
    Cancelled,
}

/// How much of a file is read between two checks for a cancel.
const CHUNK: usize = 1 << 20;

/// `typed` frozen: a document is read once, whole, into memory, at most its declared limit
/// (a longer file, even one that grew after its size was looked at, is refused), and not empty.
/// `control` is checked between the pieces, so a cancel is heard.
///
/// # Errors
///
/// [`FreezeError`], with nothing kept.
pub(super) fn freeze(
    fields: &[FormField],
    typed: Vec<(String, Typed)>,
    control: &dyn OperationControl,
) -> Result<Vec<(String, Frozen)>, FreezeError> {
    typed
        .into_iter()
        .zip(fields)
        .map(|((name, value), field)| {
            let frozen = match (value, &field.kind) {
                (Typed::Document(path), FieldKind::Document { max_bytes }) => {
                    freeze_document(&name, &path, *max_bytes, control)?
                }
                (Typed::Text(t), _) => Frozen::Text(t),
                (Typed::Choice(c), _) => Frozen::Choice(c),
                (Typed::Flag(f), _) => Frozen::Flag(f),
                (Typed::Locale(l), _) => Frozen::Locale(l),
                (Typed::Document(_), _) => return Err(FreezeError::Unreadable(name)),
            };
            Ok((name, frozen))
        })
        .collect()
}

/// Reads `reader` to its end, at most `max_bytes`: the limit caps what is READ, on the opened
/// file, so a file that grew after its size was looked at (or one with no end) cannot exceed it.
/// `control` is checked between the pieces. Not empty.
fn read_capped(
    reader: impl std::io::Read,
    len_hint: u64,
    name: &str,
    max_bytes: u64,
    control: &dyn OperationControl,
) -> Result<Vec<u8>, FreezeError> {
    let too_big = || FreezeError::TooBig {
        name: name.to_owned(),
        max: max_bytes,
    };
    use std::io::Read as _;
    let mut reader = reader.take(max_bytes + 1);
    let mut bytes = Vec::with_capacity(usize::try_from(len_hint).unwrap_or(0).min(CHUNK * 16));
    let mut piece = vec![0u8; CHUNK];
    loop {
        control
            .checkpoint(Progress {
                bytes_in: bytes.len() as u64,
                bytes_out: 0,
            })
            .map_err(|_| FreezeError::Cancelled)?;
        let n = reader
            .read(&mut piece)
            .map_err(|_| FreezeError::Unreadable(name.to_owned()))?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&piece[..n]);
        if bytes.len() as u64 > max_bytes {
            return Err(too_big());
        }
    }
    if bytes.is_empty() {
        return Err(FreezeError::Empty(name.to_owned()));
    }
    Ok(bytes)
}

fn freeze_document(
    name: &str,
    path: &Path,
    max_bytes: u64,
    control: &dyn OperationControl,
) -> Result<Frozen, FreezeError> {
    let unreadable = || FreezeError::Unreadable(name.to_owned());
    let (file, len) = open_regular(path).map_err(|e| match e {
        JobError::Cancelled => FreezeError::Cancelled,
        _ => unreadable(),
    })?;
    if len > max_bytes {
        return Err(FreezeError::TooBig {
            name: name.to_owned(),
            max: max_bytes,
        });
    }
    let bytes = read_capped(file, len, name, max_bytes, control)?;
    Ok(Frozen::Document {
        file_name: path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_pki::resource::ProcessingError;

    struct Control(bool);
    impl OperationControl for Control {
        fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
            if self.0 {
                Err(ProcessingError::Cancelled)
            } else {
                Ok(())
            }
        }
    }

    fn params() -> Vec<Param> {
        let p = |name: &str, kind| Param {
            name: name.to_owned(),
            kind,
        };
        vec![
            p("file", ParamKind::Document { max_bytes: 16 }),
            p("path", ParamKind::Text { max_chars: 4 }),
            p(
                "mode",
                ParamKind::Choice {
                    choices: vec!["fast".to_owned(), "slow".to_owned()],
                },
            ),
            p("loud", ParamKind::Flag),
            p("lang", ParamKind::Locale),
        ]
    }

    fn filled(file: &str) -> (Vec<FormField>, Vec<FieldValue>) {
        let fields = fields_of(&params());
        let mut values = initial(&fields, Locale::Kk);
        values[0] = FieldValue::Text(file.to_owned());
        values[1] = FieldValue::Text("/a/b".to_owned());
        values[2] = FieldValue::Index(Some(1));
        (fields, values)
    }

    #[test]
    fn the_fields_are_the_declared_parameters_and_the_form_starts_empty() {
        let fields = fields_of(&params());
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].kind, FieldKind::Document { max_bytes: 16 });
        assert_eq!(fields[1].kind, FieldKind::Text { max_chars: 4 });
        let values = initial(&fields, Locale::Kk);
        assert_eq!(values[0], FieldValue::Text(String::new()));
        // A choice is never defaulted; the language is the window's.
        assert_eq!(values[2], FieldValue::Index(None));
        assert_eq!(values[3], FieldValue::Flag(false));
        assert_eq!(values[4], FieldValue::Index(Some(1)));
        assert_eq!(
            read(&fields, &values),
            Err(FormError::NoPath("file".to_owned()))
        );
    }

    #[test]
    fn typed_values_follow_their_kinds_and_limits() {
        let (fields, mut values) = filled("\"docs/a.txt\"");
        let typed = read(&fields, &values).unwrap();
        assert_eq!(
            typed[0],
            (
                "file".to_owned(),
                Typed::Document(PathBuf::from("docs/a.txt"))
            ),
            "the quotes of «Copy as path» are not part of the path"
        );
        assert_eq!(typed[1].1, Typed::Text("/a/b".to_owned()));
        assert_eq!(typed[2].1, Typed::Choice("slow".to_owned()));
        assert_eq!(typed[3].1, Typed::Flag(false));
        assert_eq!(typed[4].1, Typed::Locale("kk"));

        // A text is counted in characters, not bytes: four Cyrillic letters fit a limit of 4.
        values[1] = FieldValue::Text("абвг".to_owned());
        assert!(read(&fields, &values).is_ok());
        values[1] = FieldValue::Text("абвгд".to_owned());
        assert_eq!(
            read(&fields, &values),
            Err(FormError::TextTooLong {
                name: "path".to_owned(),
                max: 4
            })
        );
        values[1] = FieldValue::Text("ok".to_owned());
        // No choice made, or one that is not in the list: refused.
        values[2] = FieldValue::Index(None);
        assert_eq!(
            read(&fields, &values),
            Err(FormError::NoChoice("mode".to_owned()))
        );
        values[2] = FieldValue::Index(Some(2));
        assert_eq!(
            read(&fields, &values),
            Err(FormError::NoChoice("mode".to_owned()))
        );
    }

    #[test]
    fn what_is_read_is_capped_even_when_the_file_grew_or_has_no_end() {
        // A reader that never ends (a file that kept growing after its size was looked at):
        // the read stops at the limit and refuses, it does not fill the memory.
        let endless = std::io::repeat(9);
        assert_eq!(
            read_capped(endless, 0, "file", 16, &Control(false)),
            Err(FreezeError::TooBig {
                name: "file".to_owned(),
                max: 16
            })
        );
        // Exactly the limit is accepted; one byte more is not.
        let exact = std::io::Read::take(std::io::repeat(1), 16);
        assert_eq!(
            read_capped(exact, 16, "file", 16, &Control(false))
                .unwrap()
                .len(),
            16
        );
        let over = std::io::Read::take(std::io::repeat(1), 17);
        assert!(read_capped(over, 17, "file", 16, &Control(false)).is_err());
    }

    #[test]
    fn a_text_is_refused_if_it_cannot_be_shown_as_typed_and_is_kept_byte_for_byte_otherwise() {
        let (fields, mut values) = filled("docs/a.txt");
        for bad in [
            "a\u{202E}b",
            "a\u{200B}b",
            "a\u{200E}",
            "a\u{0007}",
            "\u{2066}x",
            "a\u{FEFF}",
        ] {
            values[1] = FieldValue::Text(bad.to_owned());
            assert_eq!(
                read(&fields, &values),
                Err(FormError::BadText("path".to_owned())),
                "{bad:?}"
            );
        }
        // Line breaks and tab are text: CRLF stays CRLF, LF stays LF, all the way to the
        // value the engine is given.
        for good in ["a\r\nb", "a\nb", "a\tb"] {
            values[1] = FieldValue::Text(good.to_owned());
            let typed = read(&fields, &values).unwrap();
            assert_eq!(typed[1].1, Typed::Text(good.to_owned()));
        }
    }

    #[test]
    fn a_document_is_frozen_within_its_declared_limit() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        let freeze_file = |path: &Path| {
            let (fields, values) = filled(&path.to_string_lossy());
            freeze(&fields, read(&fields, &values).unwrap(), &Control(false))
        };
        let ok = write("ok.txt", &[7; 16]);
        let frozen = freeze_file(&ok).unwrap();
        assert_eq!(
            frozen[0].1,
            Frozen::Document {
                file_name: "ok.txt".to_owned(),
                bytes: vec![7; 16]
            }
        );
        assert_eq!(frozen[2].1, Frozen::Choice("slow".to_owned()));
        // One byte over the declared limit: refused, nothing kept.
        let big = write("big.txt", &[7; 17]);
        assert_eq!(
            freeze_file(&big),
            Err(FreezeError::TooBig {
                name: "file".to_owned(),
                max: 16
            })
        );
        let empty = write("empty.txt", b"");
        assert_eq!(
            freeze_file(&empty),
            Err(FreezeError::Empty("file".to_owned()))
        );
        assert_eq!(
            freeze_file(&dir.path().join("missing.txt")),
            Err(FreezeError::Unreadable("file".to_owned()))
        );
        // A directory is not a file.
        assert_eq!(
            freeze_file(dir.path()),
            Err(FreezeError::Unreadable("file".to_owned()))
        );
        // A cancel is heard while reading.
        let (fields, values) = filled(&ok.to_string_lossy());
        assert_eq!(
            freeze(&fields, read(&fields, &values).unwrap(), &Control(true)),
            Err(FreezeError::Cancelled)
        );
    }
}
