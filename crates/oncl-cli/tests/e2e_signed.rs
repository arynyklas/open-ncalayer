//! Real private JWS/JWT/WSSE processes through strict loopback PKI.
mod support;
use std::path::Path;
use support::*;

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
fn private<'a>(w: &'a World, key: &'a Path) -> Vec<&'a str> {
    vec![
        "--key",
        path(key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ]
}
fn envelope(namespace: &str) -> Vec<u8> {
    format!("<s:Envelope xmlns:s=\"{namespace}\"><s:Header/><s:Body><a>payload</a></s:Body></s:Envelope>").into_bytes()
}
#[test]
fn jws_and_jwt_sign_end_to_end_with_independent_rs256_oracle() {
    let w = world();
    let payload = w.dir.path().join("payload");
    std::fs::write(&payload, b"jws payload").unwrap();
    let claims = w.dir.path().join("claims.json");
    std::fs::write(
        &claims,
        br#"{"iss":"operator","aud":"service","exp":1793624400,"nbf":1793620800}"#,
    )
    .unwrap();
    for (serialization, detached) in [
        ("compact", false),
        ("flattened", false),
        ("general", false),
        ("compact", true),
    ] {
        let output = w.dir.path().join(format!("{serialization}-{detached}.jws"));
        let mut args = vec![
            "jws",
            "sign",
            "--serialization",
            serialization,
            "--input",
            path(&payload),
            "--output",
            path(&output),
        ];
        if detached {
            args.push("--detached");
        }
        args.extend(private(&w, &w.rsa_key));
        args.extend(trust(&w));
        let signed = run(&args, b"");
        assert_eq!(signed.status.code(), Some(0), "{serialization}: {signed:?}");
        assert!(String::from_utf8_lossy(&signed.stderr).contains("applied=Applied succeeded=true"));
        let mut verify = vec![
            "jws",
            "verify",
            "--serialization",
            serialization,
            "--input",
            path(&output),
            "--json",
        ];
        if detached {
            verify.extend(["--detached-input", path(&payload)]);
        }
        verify.extend(trust(&w));
        let result = run(&verify, b"");
        assert_eq!(
            result.status.code(),
            Some(0),
            "{serialization}/{detached}: {result:?}"
        );
        // Independent oracle: RS256 over the actual protected.payload bytes.
        if serialization == "compact" && !detached {
            let wire = std::fs::read_to_string(&output).unwrap();
            let parts: Vec<&str> = wire.split('.').collect();
            use base64::Engine as _;
            let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[2])
                .unwrap();
            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let public = w.pki.rsa.key.public_key();
            public
                .verify(
                    oncl_pki::key::SigAlg::RsaSha256,
                    signing_input.as_bytes(),
                    &sig,
                )
                .unwrap();
            let openssl = openssl_command();
            use der::Encode;
            let cert = w.dir.path().join("leaf.der");
            std::fs::write(&cert, w.pki.rsa.cert.to_der().unwrap()).unwrap();
            let pubkey = w.dir.path().join("leaf.pub");
            let extract = std::process::Command::new(&openssl)
                .args([
                    "x509",
                    "-inform",
                    "DER",
                    "-in",
                    path(&cert),
                    "-pubkey",
                    "-noout",
                    "-out",
                    path(&pubkey),
                ])
                .status()
                .unwrap();
            assert!(extract.success());
            let (signing, signature) = (
                w.dir.path().join("signing-input"),
                w.dir.path().join("signature"),
            );
            std::fs::write(&signing, signing_input).unwrap();
            std::fs::write(&signature, &sig).unwrap();
            let check = std::process::Command::new(&openssl)
                .args([
                    "dgst",
                    "-sha256",
                    "-verify",
                    path(&pubkey),
                    "-signature",
                    path(&signature),
                    path(&signing),
                ])
                .output()
                .unwrap();
            assert!(
                check.status.success(),
                "{}",
                String::from_utf8_lossy(&check.stderr)
            );
        }
    }
    // JWT encode then claims policy: exact host clock accepts nbf, rejects wrong audience.
    let jwt = w.dir.path().join("token.jwt");
    let mut encode = vec![
        "jwt",
        "encode",
        "--input",
        path(&claims),
        "--output",
        path(&jwt),
    ];
    encode.extend(private(&w, &w.rsa_key));
    encode.extend(trust(&w));
    assert_eq!(run(&encode, b"").status.code(), Some(0));
    let mut ok = vec![
        "jwt",
        "verify",
        "--input",
        path(&jwt),
        "--issuer",
        "operator",
        "--audience",
        "service",
        "--json",
    ];
    ok.extend(trust(&w));
    assert_eq!(run(&ok, b"").status.code(), Some(0));
    let mut wrong = ok.clone();
    wrong[7] = "other-service";
    let rejected = run(&wrong, b"");
    assert_eq!(rejected.status.code(), Some(2), "{rejected:?}");
}
#[test]
fn wsse_sign_verify_options_soap12_role_headers_token_and_timestamp() {
    let w = world();
    let soap11 = w.dir.path().join("soap11.xml");
    let soap12 = w.dir.path().join("soap12.xml");
    std::fs::write(
        &soap11,
        envelope("http://schemas.xmlsoap.org/soap/envelope/"),
    )
    .unwrap();
    std::fs::write(&soap12, envelope("http://www.w3.org/2003/05/soap-envelope")).unwrap();
    for (name, input, extra) in [
        ("default", &soap11, vec![]),
        ("soap12", &soap12, vec!["--soap-version", "soap12"]),
        (
            "bst",
            &soap11,
            vec![
                "--wsse-token-reference",
                "binary-security-token",
                "--wsse-token-id",
                "tok-1",
                "--wsse-body-id",
                "body-1",
            ],
        ),
        (
            "timestamp",
            &soap11,
            vec![
                "--wsse-timestamp-id",
                "ts-1",
                "--wsse-timestamp-created",
                "1793620740",
                "--wsse-timestamp-expires",
                "1793620860",
            ],
        ),
    ] {
        let output = w.dir.path().join(format!("{name}.signed.xml"));
        let mut args = vec![
            "sign",
            "--profile",
            "wsse",
            "--input",
            path(input),
            "--output",
            path(&output),
        ];
        args.extend(private(&w, &w.rsa_key));
        args.extend(trust(&w));
        args.extend(&extra);
        let signed = run(&args, b"");
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let mut verify = vec![
            "verify",
            "--profile",
            "wsse",
            "--input",
            path(&output),
            "--json",
        ];
        verify.extend(trust(&w));
        verify.extend(
            extra
                .iter()
                .filter(|a| matches!(**a, "--soap-version" | "soap12")),
        );
        if name == "timestamp" {
            verify.extend([
                "--wsse-timestamp-required",
                "--wsse-timestamp-max-lifetime",
                "300",
            ]);
        }
        let result = run(&verify, b"");
        assert_eq!(result.status.code(), Some(0), "{name}: {result:?}");
        let signed_text = std::fs::read_to_string(&output).unwrap();
        assert!(signed_text.contains("Signature"), "{name}");
        if name == "soap12" {
            // Wrong host SOAP version never validates a SOAP 1.2 document.
            let mut wrong = vec!["verify", "--profile", "wsse", "--input", path(&output)];
            wrong.extend(trust(&w));
            let refused = run(&wrong, b"");
            assert_eq!(refused.status.code(), Some(1), "{refused:?}");
            assert_eq!(
                String::from_utf8_lossy(&refused.stderr).trim(),
                "oncl: InvalidInput; applied=NotApplied"
            );
        }
    }
}
#[test]
fn unsupported_or_misplaced_wsse_options_fail_before_any_io() {
    for args in [
        vec![
            "verify",
            "--profile",
            "cms",
            "--input",
            "missing",
            "--soap-version",
            "soap12",
        ],
        vec![
            "verify",
            "--profile",
            "wsse",
            "--input",
            "missing",
            "--wsse-token-id",
            "x",
        ],
        vec![
            "sign",
            "--profile",
            "xml",
            "--input",
            "missing",
            "--output",
            "-",
            "--key",
            "k",
            "--authorize",
            "--wsse-role",
            "r",
        ],
        vec![
            "sign",
            "--profile",
            "wsse",
            "--input",
            "missing",
            "--output",
            "-",
            "--key",
            "k",
            "--authorize",
            "--target-id",
            "x",
        ],
        vec![
            "sign",
            "--profile",
            "wsse",
            "--input",
            "missing",
            "--output",
            "-",
            "--key",
            "k",
            "--authorize",
            "--wsse-timestamp-created",
            "10",
        ],
    ] {
        let result = run(&args, b"");
        assert_eq!(result.status.code(), Some(1), "{args:?}: {result:?}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("InvalidCombination"),
            "{args:?}"
        );
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn jws_add_appends_a_second_strict_signature_and_both_verify_valid() {
    let w = world();
    let payload = w.dir.path().join("payload");
    std::fs::write(&payload, b"two signers").unwrap();
    let first = w.dir.path().join("first.jws");
    let mut create = vec![
        "jws",
        "sign",
        "--serialization",
        "general",
        "--input",
        path(&payload),
        "--output",
        path(&first),
    ];
    create.extend(private(&w, &w.rsa_key));
    create.extend(trust(&w));
    assert_eq!(run(&create, b"").status.code(), Some(0));
    let second = w.dir.path().join("second.jws");
    let mut add = vec![
        "jws",
        "sign",
        "--serialization",
        "general",
        "--add",
        "--input",
        path(&first),
        "--output",
        path(&second),
    ];
    add.extend(private(&w, &w.rsa_key));
    add.extend(trust(&w));
    let added = run(&add, b"");
    assert_eq!(added.status.code(), Some(0), "{added:?}");
    let mut verify = vec![
        "jws",
        "verify",
        "--serialization",
        "general",
        "--input",
        path(&second),
        "--json",
    ];
    verify.extend(trust(&w));
    let result = run(&verify, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["signers"].as_array().unwrap().len(), 2);
    // Independent structural oracle: two protected headers, each RS256 signature
    // verified over its own signing input with the leaf public key.
    let wire: serde_json::Value = serde_json::from_slice(&std::fs::read(&second).unwrap()).unwrap();
    let signatures = wire["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 2);
    use base64::Engine as _;
    let public = w.pki.rsa.key.public_key();
    for signature in signatures {
        let signing_input = format!(
            "{}.{}",
            signature["protected"].as_str().unwrap(),
            wire["payload"].as_str().unwrap()
        );
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature["signature"].as_str().unwrap())
            .unwrap();
        public
            .verify(
                oncl_pki::key::SigAlg::RsaSha256,
                signing_input.as_bytes(),
                &bytes,
            )
            .unwrap();
    }
    // Adding to a missing/garbled JWS fails closed with no output.
    let garbled = w.dir.path().join("garbled.jws");
    std::fs::write(&garbled, b"{}").unwrap();
    let rejected = w.dir.path().join("rejected.jws");
    let mut bad = add.clone();
    let at = bad.iter().position(|a| *a == path(&first)).unwrap();
    bad[at] = path(&garbled);
    let at = bad.iter().position(|a| *a == path(&second)).unwrap();
    bad[at] = path(&rejected);
    assert_eq!(run(&bad, b"").status.code(), Some(1));
    assert!(!rejected.exists());
}
