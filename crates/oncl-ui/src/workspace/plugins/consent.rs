//! The confirmation page's text, and the one place where the user's confirmation is made.
//!
//! [`compose`] builds the page from the [`ConsentSummary`] Core prepared (trusted data only)
//! and from the declared operation (for the wording of the kind of key use and of the profile,
//! the same lines the installation window uses). Every line of the trusted block is the HOST's
//! words, or data of the file, the certificate and the plugin's identity that the host
//! computed; a plugin's own text (its name, its label of the operation, an XPath it fixed) is
//! only in [`FrameView`], under a caption that says whose words they are. What is not Core's
//! own (the file's name, the key's alias and subject, a value the user typed) is cleaned of
//! control and bidirectional characters before it is drawn.
//!
//! [`user_confirmed`] is the ONLY place in the workspace that makes a
//! [`UserConfirmation`](oncl_core::plugins::UserConfirmation): it is called by the handler of
//! the page's confirm button, after the controller let that press through, and nowhere else (a
//! test scans the source tree for it).

use std::time::Duration;

use oncl_core::plugins::{ConsentNetwork, ConsentSummary, PackageHash, UserConfirmation};
use oncl_flows::Locale;
use oncl_flows::capabilities::{CapabilityLine, KeyUseKind, capability_text, is_operation_name};
use oncl_pki::key::HashAlg;
use oncl_plugin::operations::{KeyKind, Operation, Profile, Source};

use super::form::Frozen;
use super::offer::OfferedOperation;
use super::texts::Texts;
use crate::install_plugin::{
    MAX_UNTRUSTED_XPATH, cut, frame_caption, frame_xpath, untrusted_label,
};
use crate::view::page_text;

/// Everything [`compose`] needs.
pub(super) struct ConsentInput<'a> {
    /// What Core prepared: the trusted description of the key use.
    pub(super) summary: &'a ConsentSummary,
    /// The operation as the registry declares it (from the engine, not from a plugin's reply).
    pub(super) declared: &'a Operation,
    /// The offer's entry (the plugin's own text for the frame, the parameter list).
    pub(super) offered: &'a OfferedOperation,
    /// The name of the file the user picked, as its path gives it.
    pub(super) file_name: &'a str,
    /// What the user entered for the other parameters.
    pub(super) entered: &'a [(String, Frozen)],
    /// How long an approval lives after the confirmation.
    pub(super) ttl: Duration,
    pub(super) locale: Locale,
}

/// The plugin's own words, in their own frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct FrameView {
    /// «The plugin calls it (the plugin's own words, not checked):».
    pub(super) caption: String,
    /// «The plugin's name (…):».
    pub(super) name_caption: String,
    pub(super) name: String,
    pub(super) label: String,
    /// The XPaths the declared profile fixes (the plugin's text), captioned.
    pub(super) lines: Vec<String>,
}

/// The confirmation page, as text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ConsentView {
    pub(super) title: String,
    pub(super) lead: String,
    /// The operation, the plugin, the kind of key use, the profile, the network: the host's
    /// words.
    pub(super) trusted: Vec<String>,
    pub(super) package_caption: String,
    /// The full SHA-256 of the package file, hex.
    pub(super) package_sha: String,
    /// The file chosen by the user: its name and its size.
    pub(super) file_lines: Vec<String>,
    pub(super) file_sha_caption: String,
    /// The full SHA-256 of the file, hex.
    pub(super) file_sha: String,
    /// What the key actually signs when it signs a digest: the caption and the hex.
    pub(super) prehash_caption: String,
    pub(super) prehash: String,
    pub(super) key_heading: String,
    pub(super) key_lines: Vec<String>,
    pub(super) fingerprint_caption: String,
    /// The full SHA-256 of the key's certificate, hex.
    pub(super) fingerprint: String,
    /// The other values the user entered (empty heading: none).
    pub(super) inputs_caption: String,
    pub(super) inputs: Vec<String>,
    pub(super) ttl_line: String,
    pub(super) trust_note: String,
    pub(super) frame: FrameView,
    /// The button that agrees: it names the action.
    pub(super) confirm_label: String,
    pub(super) cancel_label: String,
}

impl ConsentView {
    /// Every text of the page that is the host's own, for the tests: all but the frame.
    #[cfg(test)]
    pub(super) fn host_texts(&self) -> Vec<&str> {
        let mut all: Vec<&str> = vec![
            &self.title,
            &self.lead,
            &self.package_caption,
            &self.package_sha,
            &self.file_sha_caption,
            &self.file_sha,
            &self.prehash_caption,
            &self.prehash,
            &self.key_heading,
            &self.fingerprint_caption,
            &self.fingerprint,
            &self.inputs_caption,
            &self.ttl_line,
            &self.trust_note,
            &self.confirm_label,
            &self.cancel_label,
        ];
        all.extend(self.trusted.iter().map(String::as_str));
        all.extend(self.file_lines.iter().map(String::as_str));
        all.extend(self.key_lines.iter().map(String::as_str));
        all.extend(self.inputs.iter().map(String::as_str));
        all
    }
}

/// Why no page can be shown for a prepared key use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConsentError {
    /// What Core prepared and what the registry declares do not agree (another operation, a
    /// kind of key use the operation does not declare, an operation name that is not an
    /// identifier, a typed text the profile names that is not the one entered): nothing is
    /// shown to confirm.
    Mismatch,
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn kind_line(kind: KeyKind) -> KeyUseKind {
    match kind {
        KeyKind::Raw => KeyUseKind::Raw,
        KeyKind::Cms => KeyUseKind::Cms,
        KeyKind::CmsEx => KeyUseKind::CmsEx,
        KeyKind::Xml => KeyUseKind::Xml,
        KeyKind::XmlEx => KeyUseKind::XmlEx,
        KeyKind::Xades => KeyUseKind::Xades,
    }
}

fn algorithm(alg: HashAlg) -> &'static str {
    match alg {
        HashAlg::Sha1 => "SHA-1",
        HashAlg::Sha256 => "SHA-256",
        HashAlg::Sha512 => "SHA-512",
        HashAlg::Gost34311 => "GOST R 34.11-94",
        HashAlg::Streebog256 => "Streebog-256",
        HashAlg::Streebog512 => "Streebog-512",
    }
}

/// Text that is not the program's own, as the page draws it: control and bidirectional
/// characters gone, at most [`page_text`]'s length.
fn plain(text: &str) -> String {
    crate::view::display_text(text)
}

/// The text parameters a profile reads as an XPath, with the value the user typed for each
/// and what Core resolved into the summary's profile: they must be the same text.
fn typed_sources_agree(
    declared: &Profile,
    resolved: &Profile,
    entered: &[(String, Frozen)],
) -> bool {
    let sources = |p: &Profile| -> Vec<Option<Source>> {
        match p {
            Profile::Xml(x) => vec![x.element.clone(), x.parent.clone()],
            Profile::XmlEx(x) => vec![x.element.clone(), x.parent.clone()],
            _ => Vec::new(),
        }
    };
    let (declared, resolved) = (sources(declared), sources(resolved));
    if declared.len() != resolved.len() {
        return false;
    }
    declared.iter().zip(&resolved).all(|(d, r)| match (d, r) {
        (Some(Source::Param(name)), Some(Source::Fixed(text))) => entered
            .iter()
            .any(|(n, v)| n == name && matches!(v, Frozen::Text(t) if t == text)),
        (Some(Source::Fixed(a)), Some(Source::Fixed(b))) => a == b,
        (None, None) => true,
        _ => false,
    })
}

/// `text` in double quotes with the characters that would be invisible or break the line
/// spelled out: what is shown is exactly what is signed.
fn quoted(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Any other control or invisible character is spelled out, never drawn: even a
            // text that reached here another way than through the form shows no hidden mark.
            c if c.is_control() || crate::view::is_invisible(c) => {
                out.push_str(&format!("\\u{{{:X}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The confirmation page for `input`.
///
/// # Errors
///
/// [`ConsentError::Mismatch`] if Core's summary and the declared operation do not agree.
pub(super) fn compose(input: &ConsentInput<'_>) -> Result<ConsentView, ConsentError> {
    let ConsentInput {
        summary,
        declared,
        offered,
        file_name,
        entered,
        ttl,
        locale: l,
    } = input;
    let l = *l;
    let t = Texts::of(l);
    let workspace = super::super::Texts::of(l);

    // The page is drawn only if what Core prepared is what the registry declares: the same
    // operation (an identifier, checked again here), a kind of key use the operation declares,
    // and the user's typed texts where the profile names them.
    if !is_operation_name(&summary.operation)
        || summary.operation != declared.name()
        || summary.operation != offered.operation
    {
        return Err(ConsentError::Mismatch);
    }
    let declared_use = declared
        .uses()
        .keys()
        .iter()
        .find(|k| k.kind() == summary.kind)
        .ok_or(ConsentError::Mismatch)?;
    if !typed_sources_agree(declared_use.profile(), &summary.profile, entered) {
        return Err(ConsentError::Mismatch);
    }
    // The text that is signed is shown exactly: what the page lists for the content parameter
    // must hash to what Core froze. A different text means the page and Core disagree: nothing
    // is shown to confirm.
    let text_content = entered.iter().find_map(|(n, v)| match v {
        Frozen::Text(text) if *n == summary.content.param => Some(text.as_str()),
        _ => None,
    });
    if let Some(text) = text_content
        && (crate::signing::runner::sha256_of(text.as_bytes()) != summary.content.sha256
            || text.len() as u64 != summary.content.len)
    {
        return Err(ConsentError::Mismatch);
    }
    let lines = declared.consent(None).lines;

    let mut trusted = vec![
        t.c_operation.replace("{0}", &summary.operation),
        t.c_plugin
            .replace("{0}", &plain(&summary.plugin.id))
            .replace("{1}", &plain(&summary.plugin.version)),
        capability_text(&CapabilityLine::KeyUse(kind_line(summary.kind)), l),
        t.c_uses.replace("{0}", &summary.uses.to_string()),
    ];
    if let Some(profile) = lines
        .iter()
        .find(|line| matches!(line, CapabilityLine::KeyProfile(_)))
    {
        trusted.push(capability_text(profile, l));
    }
    trusted.push(match &summary.network {
        ConsentNetwork::None => t.c_network_none.to_owned(),
        ConsentNetwork::Pki { endpoints } => t.c_network_pki.replace(
            "{0}",
            &endpoints
                .iter()
                .map(|e| plain(e))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        // A network this build cannot word is not offered for approval.
        _ => return Err(ConsentError::Mismatch),
    });

    let (package_caption, package_digest) = match summary.plugin.package {
        PackageHash::File(d) => (t.c_package, d),
        PackageHash::Loose(d) => (t.c_package_loose, d),
    };
    let human = super::super::size(workspace, summary.content.len);
    // The exact size too, unless the short form already is it.
    let size = if summary.content.len < 1024 {
        human
    } else {
        format!("{human} ({} {})", summary.content.len, workspace.units[0])
    };
    let (prehash_caption, prehash) = match &summary.content.prehashed {
        Some(p) => (t.c_prehash.replace("{0}", algorithm(p.alg)), hex(&p.digest)),
        None => (String::new(), String::new()),
    };

    let key = &summary.key;
    let key_lines = vec![
        t.c_alias.replace("{0}", &plain(&key.alias)),
        t.c_serial.replace("{0}", &plain(&key.serial_hex)),
        key.subject_cn.as_ref().map_or_else(
            || t.c_no_subject.to_owned(),
            |cn| t.c_subject.replace("{0}", &plain(cn)),
        ),
        t.c_valid.replace("{0}", &super::super::when(key.not_after)),
    ];

    // What the user entered besides the file: the plugin gets it as it is, and none of it is
    // part of what Core approves.
    //
    // The parameters' NAMES are the plugin's own words, so they are never in the host's
    // lines: a value is listed there by its number, and the frame says which field of the
    // plugin each number is.
    let mut inputs: Vec<String> = Vec::new();
    // A choice is the plugin's own string: it is in the plugin's frame, quoted.
    let mut choices: Vec<String> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut signed_number = String::new();
    for (name, value) in entered.iter() {
        let shown = match value {
            Frozen::Document { .. } => continue,
            Frozen::Choice(choice) => {
                choices.push(
                    t.c_choice_line
                        .replace("{0}", name)
                        .replace("{1}", &quoted(&plain(choice))),
                );
                continue;
            }
            // The exact text that is signed or passed: quoted, with line breaks and tab
            // spelled out, nothing cut or cleaned.
            Frozen::Text(text) => quoted(text),
            Frozen::Flag(on) => (if *on { t.c_flag_yes } else { t.c_flag_no }).to_owned(),
            Frozen::Locale(code) => (*code).to_owned(),
        };
        let number = (inputs.len() + 1).to_string();
        inputs.push(
            t.c_input_line
                .replace("{0}", &number)
                .replace("{1}", &shown),
        );
        names.push(
            t.c_input_name
                .replace("{0}", &number)
                .replace("{1}", &quoted(&plain(name))),
        );
        if *name == summary.content.param {
            signed_number = number;
        }
    }

    Ok(ConsentView {
        title: t.consent_title.to_owned(),
        lead: t.consent_lead.to_owned(),
        trusted,
        package_caption: package_caption.to_owned(),
        package_sha: hex(&package_digest),
        file_lines: if text_content.is_some() {
            vec![
                t.c_text_signed.replace("{0}", &signed_number),
                t.c_size.replace("{0}", &size),
            ]
        } else {
            vec![
                t.c_file.replace("{0}", &plain(file_name)),
                t.c_size.replace("{0}", &size),
            ]
        },
        file_sha_caption: if text_content.is_some() {
            t.c_sha_text.to_owned()
        } else {
            t.c_sha.to_owned()
        },
        file_sha: hex(&summary.content.sha256),
        prehash_caption,
        prehash,
        key_heading: t.c_key_heading.to_owned(),
        key_lines,
        fingerprint_caption: t.c_fingerprint.to_owned(),
        fingerprint: hex(&key.fingerprint_sha256),
        inputs_caption: if inputs.is_empty() {
            String::new()
        } else {
            t.c_inputs.to_owned()
        },
        inputs,
        ttl_line: t.c_ttl.replace("{0}", &ttl.as_secs().to_string()),
        trust_note: t.c_trust_note.to_owned(),
        frame: FrameView {
            caption: frame_caption(l).to_owned(),
            name_caption: t.frame_name.to_owned(),
            name: untrusted_label(offered.plugin_name.get(l)),
            label: untrusted_label(offered.label.get(l)),
            lines: names
                .into_iter()
                .chain(choices)
                .chain(declared.consent(None).xpaths.iter().map(|x| {
                    frame_xpath(l).replace("{0}", &cut(&page_text(x), MAX_UNTRUSTED_XPATH))
                }))
                .collect(),
        },
        confirm_label: t.confirm_label.replace("{0}", &summary.operation),
        cancel_label: t.consent_cancel.to_owned(),
    })
}

/// The user pressed the button that names the action, on the page that showed `shown`: their
/// confirmation of exactly that summary.
///
/// **The host's duty** (and the only caller in the workspace): call it from the handler of that
/// button after the controller let the press through, with the very summary the page was
/// composed from. Never ahead of time, never from a stored answer.
#[allow(
    clippy::disallowed_methods,
    reason = "the one place in the workspace that makes the user's confirmation"
)]
pub(super) fn user_confirmed(
    shown: &ConsentSummary,
    _pressed: super::confirm::PressToken,
) -> UserConfirmation {
    UserConfirmation::after_user_confirmed(shown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oncl_core::plugins::{ConsentContent, ConsentKey, PluginIdentity, PrehashedDigest};
    use oncl_plugin::Manifest;
    use oncl_plugin::operations::XmlProfile;
    use std::path::Path;

    const ALL: [Locale; 3] = [Locale::Ru, Locale::Kk, Locale::En];

    #[test]
    fn quoted_spells_out_every_control_and_invisible_character() {
        assert_eq!(
            quoted("a\u{202E}b\u{7}c\u{115F}d\u{85}\"\\\n"),
            "\"a\\u{202E}b\\u{7}c\\u{115F}d\\u{85}\\\"\\\\\\n\""
        );
        assert_eq!(quoted("договор №1 \u{4e16}"), "\"договор №1 \u{4e16}\"");
    }

    /// Marks of the plugin author's own text: none may reach the host's lines.
    const EVIL: [&str; 3] = ["EVIL-NAME", "EVIL-LABEL", "EVIL-DESCRIPTION"];

    fn manifest() -> Manifest {
        Manifest::from_toml(
            r#"id = "test.ui"
name.ru = "EVIL-NAME-RU"
name.kk = "EVIL-NAME-KK"
name.en = "EVIL-NAME-EN"
description.ru = "EVIL-DESCRIPTION"
description.kk = "EVIL-DESCRIPTION"
description.en = "EVIL-DESCRIPTION"
version = "1.2.3"
min_core = "0.1.0-alpha.7"
modules = ["test.ui.module"]
[capabilities]
keys = true

[[operations]]
name = "sign-xml"
module = "test.ui.module"
manual = true
request = '{"module":"test.ui.module","method":"m","args":["{file:base64}","{path}","{mode}"]}'
label = { ru = "EVIL-LABEL-RU", kk = "EVIL-LABEL-KK", en = "EVIL-LABEL-EN" }
[[operations.params]]
name = "file"
kind = "document"
max_bytes = 8192
[[operations.params]]
name = "path"
kind = "text"
max_chars = 64
[[operations.params]]
name = "mode"
kind = "choice"
choices = ["fast", "slow"]
[operations.uses]
imports = ["keys_sign_xml", "keys_describe", "keys_chain", "keys_release", "keys_select"]
interactive = ["keys_select"]
network = "pki"
[[operations.uses.key]]
kind = "xml"
content = "param:file"
[operations.uses.key.profile]
element = "param:path"
"#,
        )
        .unwrap()
    }

    fn offered(m: &Manifest) -> OfferedOperation {
        let op = &m.operations()[0];
        OfferedOperation {
            plugin_id: m.id.clone(),
            plugin_version: m.version.to_string(),
            plugin_name: m.name.clone(),
            operation: op.name().to_owned(),
            label: op.label().clone(),
            params: op.params().to_vec(),
            uses_key: true,
            pki_endpoints: Vec::new(),
        }
    }

    fn summary() -> ConsentSummary {
        ConsentSummary {
            plugin: PluginIdentity {
                id: "test.ui".to_owned(),
                package: PackageHash::File([0x9f; 32]),
                version: "1.2.3".to_owned(),
            },
            operation: "sign-xml".to_owned(),
            kind: KeyKind::Xml,
            uses: 1,
            profile: Profile::Xml(XmlProfile {
                element: Some(Source::Fixed("/r/data".to_owned())),
                parent: None,
            }),
            options_sha256: [5; 32],
            content: ConsentContent {
                param: "file".to_owned(),
                len: 1_482_311,
                sha256: [0xab; 32],
                prehashed: None,
            },
            key: ConsentKey {
                alias: "my-key".to_owned(),
                serial_hex: "5c01".to_owned(),
                subject_cn: Some("ИВАНОВ ИВАН".to_owned()),
                fingerprint_sha256: [0xcd; 32],
                not_after: time::OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap(),
            },
            network: ConsentNetwork::Pki {
                endpoints: vec![
                    "http://ocsp.pki.gov.kz/".to_owned(),
                    "http://tsp.pki.gov.kz/".to_owned(),
                ],
            },
        }
    }

    fn entered() -> Vec<(String, Frozen)> {
        vec![
            (
                "file".to_owned(),
                Frozen::Document {
                    file_name: "акт.xml".to_owned(),
                    bytes: vec![1],
                },
            ),
            ("path".to_owned(), Frozen::Text("/r/data".to_owned())),
            ("mode".to_owned(), Frozen::Choice("slow".to_owned())),
        ]
    }

    fn view_with(
        m: &Manifest,
        summary: &ConsentSummary,
        entered: &[(String, Frozen)],
        locale: Locale,
    ) -> Result<ConsentView, ConsentError> {
        let off = offered(m);
        compose(&ConsentInput {
            summary,
            declared: &m.operations()[0],
            offered: &off,
            file_name: "акт.xml",
            entered,
            ttl: Duration::from_secs(120),
            locale,
        })
    }

    fn view(locale: Locale) -> ConsentView {
        let mut s = summary();
        // The user typed this text for the profile's `param:path` source.
        s.profile = Profile::Xml(XmlProfile {
            element: Some(Source::Fixed("/r/data".to_owned())),
            parent: None,
        });
        view_with(&manifest(), &s, &entered(), locale).unwrap()
    }

    #[test]
    fn the_trusted_block_holds_only_the_hosts_words_and_the_frame_the_plugins() {
        for l in ALL {
            let v = view(l);
            for text in v.host_texts() {
                for evil in EVIL {
                    assert!(
                        !text.contains(evil),
                        "{evil} reached the host's text in {l:?}: {text}"
                    );
                }
            }
            // The plugin's words are in the frame, and only there.
            assert!(v.frame.name.contains("EVIL-NAME"), "{l:?}");
            assert!(v.frame.label.contains("EVIL-LABEL"), "{l:?}");
            assert!(!v.frame.caption.is_empty() && !v.frame.name_caption.is_empty());
        }
    }

    #[test]
    fn the_page_says_what_is_approved_in_full() {
        for l in ALL {
            let t = Texts::of(l);
            let v = view(l);
            let all = v.host_texts().join("\n");
            assert!(all.contains("sign-xml"), "{l:?}: the operation's name");
            assert!(all.contains("test.ui"), "{l:?}: the plugin's id");
            assert!(all.contains("1.2.3"), "{l:?}: its version");
            assert_eq!(
                v.package_sha,
                "9f".repeat(32),
                "{l:?}: the whole package hash"
            );
            // The file chosen by the user: its name, its size, its whole SHA-256.
            assert!(all.contains("акт.xml"), "{l:?}");
            assert!(all.contains("1482311"), "{l:?}: the exact size");
            assert_eq!(v.file_sha, "ab".repeat(32), "{l:?}");
            assert_eq!(v.file_sha.len(), 64);
            // The key: alias, serial, owner, whole fingerprint, the end of its validity.
            assert!(all.contains("my-key") && all.contains("5c01"), "{l:?}");
            assert!(all.contains("ИВАНОВ ИВАН"), "{l:?}");
            assert_eq!(v.fingerprint, "cd".repeat(32), "{l:?}");
            assert!(all.contains("2027"), "{l:?}: valid until");
            // The kind of key use and the profile in words (the installation window's lines),
            // the network and the servers it names.
            let kind = capability_text(&CapabilityLine::KeyUse(KeyUseKind::Xml), l);
            assert!(v.trusted.contains(&kind), "{l:?}: {kind}");
            assert!(
                all.contains("ocsp.pki.gov.kz") && all.contains("tsp.pki.gov.kz"),
                "{l:?}"
            );
            // What the user typed is listed as entered, not as approved.
            assert!(v.inputs.iter().any(|i| i.contains("\"/r/data\"")));
            // ... by its number: the plugin's name for the field is its own word, so it is in
            // the frame only (mutation: the name in a host line fails here).
            assert!(
                v.inputs
                    .iter()
                    .chain(&v.trusted)
                    .chain(&v.file_lines)
                    .all(|line| !line.contains("path") && !line.contains("mode")),
                "{l:?}: a plugin's parameter name outside its frame"
            );
            assert!(
                v.frame
                    .lines
                    .iter()
                    .any(|i| i.contains("\"path\"") && i.contains('1')),
                "{l:?}"
            );
            // A choice is the plugin's own string: in its frame, quoted, not among the inputs.
            assert!(
                v.frame
                    .lines
                    .iter()
                    .any(|i| i.contains("mode") && i.contains("\"slow\""))
            );
            assert!(!v.inputs.iter().any(|i| i.contains("slow")));
            assert!(!v.inputs.iter().any(|i| i.contains("file")));
            // The button names the action; it is not a plain OK or Next.
            assert!(
                v.confirm_label.contains("sign-xml"),
                "{l:?}: {}",
                v.confirm_label
            );
            for bad in ["OK", "Ok", "Next", "Далее", "Жалғастыру", "Continue"] {
                assert_ne!(v.confirm_label, bad);
            }
            assert_eq!(v.cancel_label, t.consent_cancel);
            // The approval's time is told.
            assert!(v.ttl_line.contains("120"), "{l:?}");
        }
    }

    #[test]
    fn the_signed_text_is_shown_exactly_and_checked_against_the_summary() {
        fn unquote(q: &str) -> String {
            let inner = &q[1..q.len() - 1];
            let (mut out, mut it) = (String::new(), inner.chars());
            while let Some(c) = it.next() {
                if c != '\\' {
                    out.push(c);
                    continue;
                }
                out.push(match it.next() {
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    Some(o) => o,
                    None => '\\',
                });
            }
            out
        }
        // Lossless, and never a raw line break on the page.
        for text in [
            "a\nb",
            "tab\there",
            "q\"uote\\",
            &"x".repeat(300),
            "кириллица\nи ещё",
        ] {
            let q = quoted(text);
            assert_eq!(unquote(&q), text);
            assert!(!q.contains('\n') && !q.contains('\t'));
        }
        // The page of a text-content operation: the exact text (uncut, 300 characters), and
        // its hash must be the summary's.
        let m = manifest();
        let long = "x".repeat(300);
        let mut s = summary();
        s.content.param = "path".to_owned();
        s.content.len = long.len() as u64;
        s.content.sha256 = crate::signing::runner::sha256_of(long.as_bytes());
        s.profile = Profile::Xml(XmlProfile {
            element: Some(Source::Fixed(long.clone())),
            parent: None,
        });
        let entered = vec![
            ("path".to_owned(), Frozen::Text(long.clone())),
            ("mode".to_owned(), Frozen::Choice("slow".to_owned())),
        ];
        let v = view_with(&m, &s, &entered, Locale::En).unwrap();
        assert!(
            v.inputs.iter().any(|i| i.contains(&long)),
            "the whole text is shown"
        );
        // The line that says which value is signed names it by its number: the plugin's name
        // for the field ("path") is its own word and is not on any line of the host's.
        assert_eq!(
            v.file_lines[0],
            Texts::of(Locale::En).c_text_signed.replace("{0}", "1")
        );
        assert!(
            v.file_lines.iter().all(|line| !line.contains("path")),
            "{:?}",
            v.file_lines
        );
        // Another text than the one Core froze: refused.
        let mut other = s.clone();
        other.content.sha256[0] ^= 1;
        assert_eq!(
            view_with(&m, &other, &entered, Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
    }

    #[test]
    fn the_hash_and_the_length_of_the_signed_text_are_both_checked() {
        let m = manifest();
        let mut s = summary();
        let text = "abc";
        s.content.param = "path".to_owned();
        s.content.len = 3;
        s.content.sha256 = crate::signing::runner::sha256_of(text.as_bytes());
        s.profile = Profile::Xml(XmlProfile {
            element: Some(Source::Fixed(text.to_owned())),
            parent: None,
        });
        let entered = vec![("path".to_owned(), Frozen::Text(text.to_owned()))];
        let v = view_with(&m, &s, &entered, Locale::En).unwrap();
        assert_eq!(v.file_sha_caption, Texts::of(Locale::En).c_sha_text);
        let mut wrong_len = s.clone();
        wrong_len.content.len = 4;
        assert_eq!(
            view_with(&m, &wrong_len, &entered, Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
        let mut wrong_hash = s.clone();
        wrong_hash.content.sha256[0] ^= 1;
        assert_eq!(
            view_with(&m, &wrong_hash, &entered, Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
    }

    #[test]
    fn a_digest_the_key_signs_is_shown_with_its_algorithm() {
        let mut s = summary();
        s.content.prehashed = Some(PrehashedDigest {
            alg: HashAlg::Gost34311,
            digest: vec![0x12; 32],
        });
        let v = view_with(&manifest(), &s, &entered(), Locale::En).unwrap();
        assert!(v.prehash_caption.contains("GOST R 34.11-94"));
        assert_eq!(v.prehash, "12".repeat(32));
        let plain = view(Locale::En);
        assert!(plain.prehash.is_empty() && plain.prehash_caption.is_empty());
    }

    #[test]
    fn network_none_says_the_plugin_cannot_send_anything() {
        let mut s = summary();
        s.network = ConsentNetwork::None;
        for l in ALL {
            let v = view_with(&manifest(), &s, &entered(), l).unwrap();
            assert!(
                v.trusted.contains(&Texts::of(l).c_network_none.to_owned()),
                "{l:?}"
            );
        }
    }

    #[test]
    fn a_summary_that_disagrees_with_the_declaration_is_not_shown() {
        let m = manifest();
        let mut other = summary();
        other.operation = "another".to_owned();
        assert_eq!(
            view_with(&m, &other, &entered(), Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
        // A kind of key use the operation does not declare.
        let mut other = summary();
        other.kind = KeyKind::Cms;
        assert_eq!(
            view_with(&m, &other, &entered(), Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
        // The text Core put into the profile is not the text the user typed.
        let mut other = summary();
        other.profile = Profile::Xml(XmlProfile {
            element: Some(Source::Fixed("/else".to_owned())),
            parent: None,
        });
        assert_eq!(
            view_with(&m, &other, &entered(), Locale::En).unwrap_err(),
            ConsentError::Mismatch
        );
    }

    #[test]
    fn what_is_not_the_programs_own_is_cleaned_before_it_is_drawn() {
        let mut s = summary();
        // A bidirectional override and a line break in an alias and in an owner's name.
        s.key.alias = "evil\u{202E}txt.exe\nmore".to_owned();
        s.key.subject_cn = Some("A\u{2066}B\r\nC".to_owned());
        let off = offered(&manifest());
        let m = manifest();
        let v = compose(&ConsentInput {
            summary: &s,
            declared: &m.operations()[0],
            offered: &off,
            file_name: "name\u{202E}fdp.exe\n",
            entered: &entered(),
            ttl: Duration::from_secs(120),
            locale: Locale::En,
        })
        .unwrap();
        let all = v.host_texts().join("\n");
        for bad in ['\u{202E}', '\u{2066}', '\r'] {
            assert!(!all.contains(bad), "{bad:?} reached the page");
        }
        // Each line is one line.
        for line in v.key_lines.iter().chain(&v.file_lines) {
            assert!(!line.contains('\n'), "{line:?}");
        }
    }

    #[test]
    fn a_long_plugin_label_is_cut_in_its_frame_and_never_in_the_hosts_lines() {
        let mut m = manifest();
        let _ = &mut m;
        let long = "L".repeat(500);
        let mut off = offered(&manifest());
        off.label.en = long.clone();
        let man = manifest();
        let v = compose(&ConsentInput {
            summary: &summary(),
            declared: &man.operations()[0],
            offered: &off,
            file_name: "a",
            entered: &entered(),
            ttl: Duration::from_secs(120),
            locale: Locale::En,
        })
        .unwrap();
        assert!(v.frame.label.chars().count() <= crate::install_plugin::MAX_UNTRUSTED_LABEL + 1);
        assert!(v.frame.label.ends_with('…'));
        assert!(!v.host_texts().join("").contains("LLLLL"));
        let _ = Path::new("");
    }

    #[test]
    fn the_confirmation_is_for_exactly_the_summary_that_was_shown() {
        // Two summaries differing in one byte of the file's hash have different digests, and a
        // confirmation names the digest of the one shown.
        let a = summary();
        let mut b = summary();
        b.content.sha256[0] ^= 1;
        assert_ne!(a.digest(), b.digest());
        let _confirmation =
            user_confirmed(&a, crate::workspace::plugins::confirm::press_for_tests());
    }
}
