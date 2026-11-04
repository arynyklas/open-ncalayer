//! `--token-reader` and named token sources against the existing software-token
//! emulator (`oncl-token` feature `emulator`, loaded by the `token-emulator`
//! feature of this CLI through `ONCL_TOKEN_EMULATOR`). No physical token and no
//! system smart-card service is involved. Synthetic keys only.
mod support;
use der::Encode;
use oncl_pki::private_fs::PrivateDirectory;
use serde_json::json;
use std::{io::Write, path::PathBuf};
use support::*;

const READER: &str = "OpenNCALayer Emulated Kaztoken 0";
const PIN: &str = "123456";

struct Card {
    config: PathBuf,
    pin: PathBuf,
}
fn card(w: &World, keys: &[&PathBuf]) -> Card {
    let entries: String = keys
        .iter()
        .map(|p| {
            format!(
                "    {{ p12 = '{}', password = '{PASSWORD}' }},\n",
                p.display()
            )
        })
        .collect();
    let config = w.dir.path().join("tokens.toml");
    std::fs::write(
        &config,
        format!(
            "[[reader]]\nname = \"{READER}\"\nkind = \"AKKaztokenStore\"\npin = \"{PIN}\"\nkeys = [\n{entries}]\n\n[[reader]]\nname = \"Empty Reader\"\n"
        ),
    )
    .unwrap();
    let private = w.dir.path().join("pin-private");
    let namespace = PrivateDirectory::create(&private).unwrap();
    namespace
        .create_file("pin.secret")
        .unwrap()
        .write_all(PIN.as_bytes())
        .unwrap();
    Card {
        config,
        pin: private.join("pin.secret"),
    }
}
fn env(card: &Card) -> [(&'static str, &str); 1] {
    [("ONCL_TOKEN_EMULATOR", path(&card.config))]
}
fn trust(w: &World) -> Vec<&str> {
    vec![
        "--root",
        path(&w.root),
        "--pki-endpoint",
        &w.origin,
        "--as-of",
        "1793620800",
    ]
}
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
fn token_sign<'a>(
    w: &'a World,
    card: &'a Card,
    alias: &'a str,
    document: &'a std::path::Path,
    output: &'a std::path::Path,
    authorize: bool,
) -> Vec<&'a str> {
    let mut args = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(document),
        "--output",
        path(output),
        "--token-reader",
        READER,
        "--token-kind",
        "kaztoken",
        "--token-alias",
        alias,
        "--secret-file",
        path(&card.pin),
    ];
    if authorize {
        args.push("--authorize");
    }
    args.extend(trust(w));
    args
}
fn verify(w: &World, signature: &std::path::Path, document: &std::path::Path) -> i32 {
    let mut args = vec![
        "verify",
        "--profile",
        "cms",
        "--input",
        path(signature),
        "--detached",
        path(document),
    ];
    args.extend(trust(w));
    run(&args, b"").status.code().unwrap()
}

#[test]
fn token_reader_signs_with_the_emulated_card_and_verifies_valid() {
    let w = world();
    let card = card(&w, &[&w.rsa_key, &w.gost_key]);
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"token document").unwrap();
    for (name, entry) in [("rsa", &w.pki.rsa), ("gost", &w.pki.gost)] {
        let signature = w.dir.path().join(format!("{name}.der"));
        let args = token_sign(&w, &card, &entry.alias, &document, &signature, true);
        let signed = run_env(&args, b"", &env(&card));
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let text = String::from_utf8_lossy(&signed.stderr);
        assert!(text.contains("applied=Applied succeeded=true"), "{text}");
        assert!(!text.contains(PIN), "the PIN never reaches diagnostics");
        // The embedded signer certificate is the one stored on the card.
        assert!(
            contains(
                &std::fs::read(&signature).unwrap(),
                &entry.cert.to_der().unwrap()
            ),
            "{name}"
        );
        assert_eq!(verify(&w, &signature, &document), 0, "{name}");
    }
}
#[test]
fn token_is_fail_closed_without_consent_pin_alias_reader_or_emulator() {
    let w = world();
    let card = card(&w, &[&w.rsa_key]);
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let output = w.dir.path().join("out.der");
    let refused = |args: Vec<&str>, envs: &[(&str, &str)], label: &str, code: &str| {
        let result = run_env(&args, b"", envs);
        assert_eq!(result.status.code(), Some(1), "{label}: {result:?}");
        let text = String::from_utf8_lossy(&result.stderr).trim().to_owned();
        assert!(!text.contains("private_use"), "{label}: {text}");
        assert!(text.contains(code), "{label}: {text}");
        assert!(!output.exists(), "{label}");
    };
    let alias = w.pki.rsa.alias.as_str();
    // No consent: refused before any token I/O.
    refused(
        token_sign(&w, &card, alias, &document, &output, false),
        &env(&card),
        "no --authorize",
        "AuthorityRequired",
    );
    // Wrong alias on a present card: nothing is applied.
    refused(
        token_sign(&w, &card, "no-such-alias", &document, &output, true),
        &env(&card),
        "unknown alias",
        "KeyNotFound",
    );
    // Wrong PIN file content.
    let bad_pin = w.dir.path().join("pin-private").join("bad.secret");
    let namespace = PrivateDirectory::open(&w.dir.path().join("pin-private")).unwrap();
    namespace
        .create_file("bad.secret")
        .unwrap()
        .write_all(b"000000")
        .unwrap();
    let mut args = token_sign(&w, &card, alias, &document, &output, true);
    let at = args.iter().position(|a| *a == path(&card.pin)).unwrap();
    args[at] = path(&bad_pin);
    refused(args, &env(&card), "wrong PIN", "InvalidInput");
    // A reader that does not exist, and an empty reader.
    for reader in ["No Such Reader", "Empty Reader"] {
        let mut args = token_sign(&w, &card, alias, &document, &output, true);
        let at = args.iter().position(|a| *a == READER).unwrap();
        args[at] = reader;
        refused(args, &env(&card), reader, "InvalidInput");
    }
    // An unreadable emulator configuration is a refusal, never a fallback.
    refused(
        token_sign(&w, &card, alias, &document, &output, true),
        &[("ONCL_TOKEN_EMULATOR", "does-not-exist.toml")],
        "missing emulator config",
        "InvalidInput",
    );
}
#[test]
fn named_token_source_signs_and_publishes_public_metadata_without_private_use() {
    let w = world();
    let card = card(&w, &[&w.rsa_key]);
    let alias = w.pki.rsa.alias.as_str();
    let keys = w.dir.path().join("keys.json");
    std::fs::write(
        &keys,
        serde_json::to_vec(&json!({"keys":[
            {"source":"token","name":"card","reader":READER,"kind":"kaztoken","alias":alias}
        ]}))
        .unwrap(),
    )
    .unwrap();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"named token").unwrap();
    let signature = w.dir.path().join("named.der");
    let mut args = vec![
        "sign",
        "--profile",
        "cms",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&signature),
        "--key-name",
        "card",
        "--key-config",
        path(&keys),
        "--secret-file",
        path(&card.pin),
        "--authorize",
    ];
    args.extend(trust(&w));
    let signed = run_env(&args, b"", &env(&card));
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    assert_eq!(verify(&w, &signature, &document), 0);
    // Public metadata of the same named token source: read-only, no private use.
    let inspected = run_env(
        &[
            "inspect",
            "--profile",
            "named-key",
            "--key-name",
            "card",
            "--key-config",
            path(&keys),
            "--secret-file",
            path(&card.pin),
            "--json",
        ],
        b"",
        &env(&card),
    );
    assert_eq!(inspected.status.code(), Some(0), "{inspected:?}");
    let report: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
    assert_eq!(report["applied"], "NotApplied");
    assert_eq!(report["entries"].as_array().unwrap().len(), 1, "{report}");
    assert!(!String::from_utf8_lossy(&inspected.stderr).contains("private_use"));
}
