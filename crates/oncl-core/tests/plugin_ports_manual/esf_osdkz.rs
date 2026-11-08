//! `com.osdkz.esf.signer.esfSigner` `signPlainData`: a raw signature of the UTF-8 bytes of a
//! TEXT bound as raw content (the first raw-over-text operation). The request is root-keyed:
//! `{"method","storageName","data"}`. Core refuses control, bidi and invisible characters
//! (other than `\n` and `\t`) in that text. A `raw` profile has no options, so the
//! tampered-profile negative test does not exist for this operation (as for rating1c's raw).
use crate::ports::*;
use oncl_core::plugins::{PluginParam, PluginPrepareError, PluginRequestError};
use oncl_plugin::operations::{KeyKind, Profile};

const PORT: &str = "esf-osdkz";
const OPERATION: &str = "sign-plain-data";
const TEXT: &str = "Счёт-фактура № 12\nсумма: 1 000 ₸\tтест";

fn run_text(text: &str, options: &RunOptions) -> PortRun {
    run_port_operation(
        PORT,
        OPERATION,
        &[("data", PluginParam::Text(text))],
        options,
    )
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn sign_plain_data_is_a_raw_signature_of_the_text_bytes() {
    let run = run_text(TEXT, &RunOptions::default());
    assert_applied(&run);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&run.request).unwrap(),
        serde_json::json!({
            "method": "signPlainData",
            "storageName": "PKCS12",
            "data": TEXT
        })
    );
    assert_eq!(run.summary.kind, KeyKind::Raw);
    assert_eq!(run.summary.profile, Profile::Raw);
    assert_eq!(run.summary.content.len, TEXT.len() as u64);
    let json = reply_json(&run);
    assert_eq!(json["code"], "200", "{json}");
    let object = &json["responseObject"];
    let signature = from_base64(object["signature"].as_str().unwrap());
    oracle::verify_raw_rsa(&run.cert, TEXT.as_bytes(), &signature);
    assert!(
        object["pem"].is_string() && object["keyInfo"].is_object(),
        "{object}"
    );
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn control_bidi_and_invisible_characters_in_the_text_are_refused() {
    for text in ["a\u{0}b", "a\u{7}b", "a\u{202e}b", "a\u{200b}b", "a\rb"] {
        let outcome = try_run_port_operation(
            PORT,
            OPERATION,
            &[("data", PluginParam::Text(text))],
            &RunOptions::default(),
        );
        match outcome {
            Err(PluginPrepareError::Request(PluginRequestError::InvalidValue(name))) => {
                assert_eq!(name, "data", "{text:?}")
            }
            Err(other) => panic!("{text:?}: another refusal: {other:?}"),
            Ok(_) => panic!("{text:?} is accepted"),
        }
    }
}

#[test]
#[ignore = "needs the built port wasm: see docs/dev/plugins-manual-tests.md"]
fn every_declared_import_is_needed() {
    let manifest = oncl_plugin::Manifest::from_toml(&manifest_text(PORT)).unwrap();
    let op = manifest
        .operations()
        .iter()
        .find(|o| o.name() == OPERATION)
        .unwrap();
    for import in op.uses().imports() {
        let name = import.name();
        let tamper = move |text: &str| {
            let start = text.find(&format!("name = \"{OPERATION}\"\n")).unwrap();
            let at = start + text[start..].find("imports = [").unwrap();
            let line_end = at + text[at..].find('\n').unwrap();
            let line = &text[at..line_end];
            let new = line
                .replace(&format!(", \"{name}\""), "")
                .replace(&format!("\"{name}\", "), "");
            assert_ne!(new, line, "{name}");
            format!("{}{}{}", &text[..at], new, &text[line_end..])
        };
        let options = RunOptions {
            tamper: Some(Box::new(tamper)),
            ..RunOptions::default()
        };
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_text(TEXT, &options)));
        if let Ok(run) = outcome {
            assert!(
                run.call.error().is_some() || run.call.applied() != AppliedState::Applied,
                "works without {name}"
            );
        }
    }
}
