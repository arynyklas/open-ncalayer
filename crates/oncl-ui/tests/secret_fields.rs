//! The secret fields (a key store password, a key file password, a PIN) are password fields.
//!
//! A `LineEdit` of `input-type: password` is what keeps a secret out of an accessibility
//! client's reach: the platform adapter (Slint 1.18.1's accesskit adapter) gives such a field
//! the password role and exposes the characters it displays, dots, as its value and text; the
//! typed characters are only in the field's raw `accessible-value` property, which the adapter
//! replaces (the comment in `i-slint-core`'s `textlayout/sharedparley/accessibility.rs` says
//! so). The native evidence (UIA on a real window) is `scripts/uia-secret-probe.ps1`. A field
//! that holds a secret but is not a password field would be read out in plain text, so these
//! tests read the `.slint` sources: every `LineEdit` or `TextField` that names a password or
//! a PIN is a password field, and the only way to its text is the user's own «Show password».

use std::fs;
use std::path::Path;

/// The windows' `.slint` files: name and text.
fn sources() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut files = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "slint"))
        .map(|p| {
            (
                p.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// The code of a line, without its `//` comment.
fn code(line: &str) -> &str {
    line.split("//").next().unwrap_or("").trim()
}

/// An element of the text-editing kind: where it starts (1-based line) and its text, the
/// opening line to the closing brace.
struct Block {
    file: String,
    line: usize,
    text: String,
}

fn blocks() -> Vec<Block> {
    let mut found = Vec::new();
    for (file, text) in sources() {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let head = code(line);
            if !(head.ends_with("LineEdit {") || head.ends_with("TextField {")) {
                continue;
            }
            let mut depth = 0_i32;
            let mut body = String::new();
            for next in &lines[i..] {
                let next = code(next);
                body.push_str(next);
                body.push('\n');
                depth += next.matches('{').count() as i32 - next.matches('}').count() as i32;
                if depth <= 0 {
                    break;
                }
            }
            found.push(Block {
                file: file.clone(),
                line: i + 1,
                text: body,
            });
        }
    }
    found
}

/// Names a secret: a password or a PIN.
fn names_a_secret(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("password") || lower.contains("pin code")
}

#[test]
fn every_field_of_a_password_or_pin_is_a_password_field() {
    let mut secrets = Vec::new();
    let mut plain = Vec::new();
    for block in blocks() {
        if names_a_secret(&block.text) {
            secrets.push(block);
        } else {
            plain.push(block);
        }
    }

    // The fields known today, so that a parse that finds none cannot pass.
    for file in [
        "common.slint",
        "csr.slint",
        "import.slint",
        "manual_plugins.slint",
        "password.slint",
        "signing.slint",
        "storage.slint",
        "workspace.slint",
    ] {
        assert!(
            secrets.iter().any(|b| b.file == file),
            "{file}: no secret field found"
        );
    }

    let refused: Vec<String> = secrets
        .iter()
        .filter(|b| {
            // A `LineEdit` is masked by its input type; a `TextField` by its `secret`.
            !(b.text.contains("InputType.password")
                || b.text.contains("input-type: password;")
                || b.text.contains("secret:"))
        })
        .map(|b| format!("{}:{}", b.file, b.line))
        .collect();
    assert!(
        refused.is_empty(),
        "a field of a password or a PIN that is not a password field: {refused:?}"
    );

    // Nothing else is masked by hand: a field that is not a secret has no `input-type`.
    let odd: Vec<String> = plain
        .iter()
        .filter(|b| b.text.contains("input-type:") && !b.text.contains("root.secret"))
        .map(|b| format!("{}:{}", b.file, b.line))
        .collect();
    assert!(
        odd.is_empty(),
        "an input type on a field that is no secret: {odd:?}"
    );
}

/// The input types in the sources are the password type, or the password type that the
/// user's «Show password» switches to text, or the `secret` of `TextField`.
#[test]
fn the_text_of_a_secret_is_shown_only_by_show_password() {
    let allowed = [
        "input-type: password;",
        "input-type: show-password.checked ? InputType.text : InputType.password;",
        "input-type: root.secret ? InputType.password : InputType.text;",
    ];
    let mut refused = Vec::new();
    for (file, text) in sources() {
        for (i, line) in text.lines().enumerate() {
            let line = code(line);
            if line.contains("input-type") && !allowed.contains(&line) {
                refused.push(format!("{file}:{}: {line}", i + 1));
            }
        }
    }
    assert!(refused.is_empty(), "{}", refused.join("\n"));

    // And every `secret` of a `TextField` is the opposite of a «Show password» check box.
    let mut unconditional = Vec::new();
    for (file, text) in sources() {
        for (i, line) in text.lines().enumerate() {
            let line = code(line);
            if line.starts_with("secret:") && line != "secret: !show-password.checked;" {
                unconditional.push(format!("{file}:{}: {line}", i + 1));
            }
        }
    }
    assert!(
        unconditional.is_empty(),
        "a secret not tied to «Show password»: {unconditional:?}"
    );
}
