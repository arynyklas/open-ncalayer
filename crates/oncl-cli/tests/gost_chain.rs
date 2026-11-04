//! A chain rooted in a GOST-2015 key (GOST root, GOST OCSP responder and TSA)
//! through the real binary. There is no independent GOST oracle on this
//! machine (OpenSSL has no GOST engine installed): SDK sign + SDK verify with
//! negative contrasts, as for every GOST case.
mod support;
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
#[test]
fn gost_rooted_chain_signs_valid_zero_for_gost_and_rsa_leaves_altered_two_offline_three() {
    let w = world_gost();
    let document = w.dir.path().join("document.bin");
    let altered = w.dir.path().join("altered.bin");
    std::fs::write(&document, b"abc").unwrap();
    std::fs::write(&altered, b"abd").unwrap();
    for (name, key) in [("gost", &w.gost_key), ("rsa", &w.rsa_key)] {
        let signature = w.dir.path().join(format!("{name}.der"));
        let mut sign = vec![
            "sign",
            "--profile",
            "cms",
            "--detached",
            "--input",
            path(&document),
            "--output",
            path(&signature),
            "--key",
            path(key),
            "--secret-file",
            path(&w.secret),
            "--authorize",
        ];
        sign.extend(trust(&w));
        let signed = run(&sign, b"");
        assert_eq!(signed.status.code(), Some(0), "{name}: {signed:?}");
        let mut verify = vec![
            "verify",
            "--profile",
            "cms",
            "--input",
            path(&signature),
            "--detached",
            path(&document),
            "--json",
        ];
        verify.extend(trust(&w));
        let valid = run(&verify, b"");
        assert_eq!(valid.status.code(), Some(0), "{name}: {valid:?}");
        let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
        assert_eq!(report["verdict"], "Valid");
        assert_eq!(report["signers"][0]["chain"], "Passed");
        assert_eq!(report["signers"][0]["revocation"], "Passed");
        let mut offline = verify.clone();
        offline.push("--offline");
        assert_eq!(run(&offline, b"").status.code(), Some(3), "{name}");
        let mut changed = verify.clone();
        changed[6] = path(&altered);
        assert_eq!(run(&changed, b"").status.code(), Some(2), "{name}");
        // The wrong root (the RSA world's) can never anchor this chain.
        let other = world();
        let mut foreign = verify.clone();
        let at = foreign.iter().position(|a| *a == path(&w.root)).unwrap();
        foreign[at] = path(&other.root);
        assert_ne!(run(&foreign, b"").status.code(), Some(0), "{name}");
    }
}
#[test]
fn gost_rooted_cades_t_uses_a_gost_tsa_and_verifies_at_level_t() {
    let w = world_gost();
    let document = w.dir.path().join("document.bin");
    std::fs::write(&document, b"abc").unwrap();
    let signature = w.dir.path().join("cades-t.der");
    let tsa = format!("{}/tsa", w.origin);
    let mut sign = vec![
        "sign",
        "--profile",
        "cades-t",
        "--detached",
        "--input",
        path(&document),
        "--output",
        path(&signature),
        "--key",
        path(&w.gost_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
        "--tsa-url",
        &tsa,
    ];
    sign.extend(trust(&w));
    let signed = run(&sign, b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let mut verify = vec![
        "verify",
        "--profile",
        "cades-t",
        "--input",
        path(&signature),
        "--detached",
        path(&document),
        "--json",
    ];
    verify.extend(trust(&w));
    let valid = run(&verify, b"");
    assert_eq!(valid.status.code(), Some(0), "{valid:?}");
    let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(report["ades_level"], "T");
}
#[test]
fn gost_rooted_jws_and_jwt_sign_and_verify_valid_with_a_gost_key() {
    let w = world_gost();
    let payload = w.dir.path().join("payload");
    std::fs::write(&payload, b"gost jws payload").unwrap();
    let claims = w.dir.path().join("claims.json");
    std::fs::write(
        &claims,
        br#"{"iss":"operator","aud":"service","exp":1793624400,"nbf":1793620800}"#,
    )
    .unwrap();
    let jws = w.dir.path().join("gost.jws");
    let mut sign = vec![
        "jws",
        "sign",
        "--serialization",
        "compact",
        "--input",
        path(&payload),
        "--output",
        path(&jws),
        "--key",
        path(&w.gost_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    sign.extend(trust(&w));
    let signed = run(&sign, b"");
    assert_eq!(signed.status.code(), Some(0), "{signed:?}");
    let wire = std::fs::read_to_string(&jws).unwrap();
    use base64::Engine as _;
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(wire.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_ne!(
        header["alg"], "RS256",
        "a GOST key must not label itself RS256: {header}"
    );
    let mut verify = vec![
        "jws",
        "verify",
        "--serialization",
        "compact",
        "--input",
        path(&jws),
        "--json",
    ];
    verify.extend(trust(&w));
    let result = run(&verify, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["signers"][0]["crypto"], "Passed");
    // A single flipped payload character is Invalid (2).
    let mut parts: Vec<String> = wire.split('.').map(str::to_owned).collect();
    parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"gost jws payloaX");
    let tampered = w.dir.path().join("tampered.jws");
    std::fs::write(&tampered, parts.join(".")).unwrap();
    let mut bad = verify.clone();
    let at = bad.iter().position(|a| *a == path(&jws)).unwrap();
    bad[at] = path(&tampered);
    assert_eq!(run(&bad, b"").status.code(), Some(2));
    // JWT encode + claims verification with the same GOST key.
    let jwt = w.dir.path().join("gost.jwt");
    let mut encode = vec![
        "jwt",
        "encode",
        "--input",
        path(&claims),
        "--output",
        path(&jwt),
        "--key",
        path(&w.gost_key),
        "--secret-file",
        path(&w.secret),
        "--authorize",
    ];
    encode.extend(trust(&w));
    assert_eq!(run(&encode, b"").status.code(), Some(0));
    let mut check = vec![
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
    check.extend(trust(&w));
    let result = run(&check, b"");
    assert_eq!(result.status.code(), Some(0), "{result:?}");
}
