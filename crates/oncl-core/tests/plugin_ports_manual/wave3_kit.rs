//! Shared pieces of the wave 3 ports (`energy`, `eproc`, `efactoring`, `market`, `dogovor24`,
//! `qiwi`): the table-driven negative tests of `rating1c.rs` (a tampered profile is refused
//! before the key; every declared import is needed) and the CMS oracle checks. The harness
//! `support/ports.rs` is not touched.
use crate::ports::*;
use base64::Engine as _;
use oncl_core::plugins::{PluginRefusalCode, TicketRefusal};
use oncl_plugin::operations::KeyKind;

pub const IGNORE: &str = "needs the built port wasm: see docs/dev/plugins-manual-tests.md";

/// A port's way of running one declared operation with its fixed example parameters.
pub type Runner<'a> = &'a dyn Fn(&str, &RunOptions) -> PortRun;

pub fn base64_of(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `RunOptions::tampered` for text built at run time: `from` -> `to` once inside the section
/// of `operation`.
pub fn tampered(operation: &str, from: &str, to: &str) -> RunOptions {
    let (operation, from, to) = (operation.to_owned(), from.to_owned(), to.to_owned());
    RunOptions {
        tamper: Some(Box::new(move |text| {
            let start = text
                .find(&format!("name = \"{operation}\"\n"))
                .unwrap_or_else(|| panic!("no operation {operation}"));
            let end = text[start..]
                .find("\n[[operations]]")
                .map_or(text.len(), |n| start + n);
            let at = start
                + text[start..end]
                    .find(&from)
                    .unwrap_or_else(|| panic!("{operation} has no {from:?}"));
            format!("{}{}{}", &text[..at], to, &text[at + from.len()..])
        })),
        key: None,
    }
}

/// The four CMS variants of a port: (name suffix, attached, time-stamped).
pub const CMS_VARIANTS: [(&str, bool, bool); 4] = [
    ("attached-timestamp", true, true),
    ("attached", true, false),
    ("detached-timestamp", false, true),
    ("detached", false, false),
];

/// One tamper per CMS operation: a profile field changed to a value the module does not use.
/// `content` is the operation's `content = "param:.."` line (to give a detached operation,
/// which has no profile table, one).
pub fn cms_tamper(
    operation: &str,
    content: &str,
    attached: bool,
    timestamped: bool,
) -> (String, String, String) {
    let (from, to) = match (attached, timestamped) {
        (true, true) => ("timestamp = \"kalkan\"", "timestamp = \"none\""),
        (true, false) => ("encapsulate = true", "encapsulate = false"),
        (false, true) => ("timestamp = \"kalkan\"", "timestamp = \"basics\""),
        (false, false) => (
            content,
            &*format!("{content}\n\n[operations.uses.key.profile]\nencapsulate = true"),
        ),
    };
    (operation.to_owned(), from.to_owned(), to.to_owned())
}

/// Every tampered declaration is refused with `options-mismatch` before the key is applied.
pub fn assert_tampers_refused(tampers: &[(String, String, String)], run: Runner) {
    assert!(!tampers.is_empty());
    for (operation, from, to) in tampers {
        let run = run(operation, &tampered(operation, from, to));
        assert_refused_before_the_key(&run);
        assert_eq!(run.call.refusals(), [TicketRefusal::Options], "{operation}");
        assert_eq!(
            run.call.subcode(),
            Some(PluginRefusalCode::OptionsMismatch),
            "{operation}"
        );
    }
}

/// Every import an operation declares is needed: with any one deleted the manifest is refused
/// or the call does not succeed (`Denied`, even after the key use for `keys_release`).
pub fn assert_every_import_needed(port: &str, operations: &[String], run: Runner) {
    let manifest = oncl_plugin::Manifest::from_toml(&manifest_text(port)).unwrap();
    for operation in operations {
        let op = manifest
            .operations()
            .iter()
            .find(|o| o.name() == operation)
            .unwrap_or_else(|| panic!("no operation {operation}"));
        for import in op.uses().imports() {
            let name = import.name();
            let operation_name = operation.clone();
            let tamper = move |text: &str| {
                let start = text
                    .find(&format!("name = \"{operation_name}\"\n"))
                    .unwrap();
                let end = text[start..]
                    .find("\n[[operations]]")
                    .map_or(text.len(), |n| start + n);
                let at = start + text[start..end].find("imports = [").unwrap();
                let line_end = at + text[at..].find('\n').unwrap();
                let line = &text[at..line_end];
                let new = line
                    .replace(&format!(", \"{name}\""), "")
                    .replace(&format!("\"{name}\", "), "");
                assert_ne!(new, line, "{operation_name}: {name}");
                format!("{}{}{}", &text[..at], new, &text[line_end..])
            };
            let options = RunOptions {
                tamper: Some(Box::new(tamper)),
                ..RunOptions::default()
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(operation, &options)
            }));
            if let Ok(run) = outcome {
                assert!(
                    run.call.error().is_some() || run.call.applied() != AppliedState::Applied,
                    "{operation} works without {name}"
                );
            }
        }
    }
}

/// The request the host built is exactly this JSON.
pub fn assert_request(run: &PortRun, expected: serde_json::Value) {
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        expected
    );
}

/// A CMS from a CMS operation, checked by openssl and `oncl_pki::cms::verify` over `content`.
pub fn assert_cms(run: &PortRun, cms: &[u8], content: &[u8], attached: bool, timestamped: bool) {
    assert_eq!(run.summary.kind, KeyKind::CmsEx);
    assert_eq!(run.summary.content.len, content.len() as u64);
    let facts = oracle::verify_cms(cms, content, &run.cert, attached);
    assert_eq!(facts.sig_alg, oncl_pki::key::SigAlg::RsaSha256);
    assert_eq!(facts.time_stamped, timestamped, "{facts:?}");
    // Kalkan's TSA binding is a GET; the signer's own OCSP check precedes it.
    let tsa = run
        .http_log
        .iter()
        .any(|l| l.starts_with("GET http://tsp.pki.gov.kz/"));
    assert_eq!(tsa, timestamped, "{:?}", run.http_log);
}

/// `signed` without its `ds:Signature` element.
pub fn without_signature(signed: &str) -> String {
    let start = signed.find("<ds:Signature").expect("a ds:Signature");
    let end = signed.find("</ds:Signature>").unwrap() + "</ds:Signature>".len();
    format!("{}{}", &signed[..start], &signed[end..])
}

/// A declaration the module's real call cannot satisfy: it is added to the manifest by the
/// tamper (the port declares nothing for it), the call is run, and Core refuses it before the
/// key is applied. Returns the run for the caller's assertions.
pub fn probe(port: &str, operation: &str, section: &str, params: &[(&str, oncl_core::plugins::PluginParam<'_>)]) -> PortRun {
    let section = section.to_owned();
    let options = RunOptions {
        tamper: Some(Box::new(move |text| {
            format!("{}\n{section}", with_min_core(text, "0.1.0-alpha.7"))
        })),
        key: None,
    };
    run_port_operation(port, operation, params, &options)
}
