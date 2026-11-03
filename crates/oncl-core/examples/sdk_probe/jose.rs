//! Real J01 SDK signing, independent OpenSSL RS256 oracle, and negative controls.
#[path = "jose_fixtures.rs"]
mod fixtures;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use der::Encode;
use fixtures::*;
use oncl_core::{
    Action,
    jose::{JoseProfile, JwsSerialization, JwsVerifyRequest, JwtValidationPolicy},
    keys::KeyRequest,
};
use oncl_pki::{
    resource::ResourceLimits,
    validation::{CheckStatus, Verdict},
};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, atomic::Ordering},
};

type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;
fn openssl(args: &[&str]) -> Result<std::process::Output> {
    let output = Command::new("openssl").args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "openssl {args:?}: exit={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}
fn p(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| "non-UTF8 oracle path".into())
}
fn json_rsa_compact(wire: &[u8]) -> Result<Vec<u8>> {
    let json: serde_json::Value = serde_json::from_slice(wire)?;
    let signature = json
        .get("signatures")
        .and_then(|s| s.get(0))
        .unwrap_or(&json);
    let protected = signature["protected"]
        .as_str()
        .ok_or("missing protected header")?;
    let signature = signature["signature"].as_str().ok_or("missing signature")?;
    let payload = json
        .get("payload")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    Ok(format!("{protected}.{payload}.{signature}").into_bytes())
}
fn oracle_check(
    out: &Path,
    stem: &str,
    wire: &[u8],
    detached: Option<&[u8]>,
    public_key: &Path,
) -> Result<String> {
    let s = std::str::from_utf8(wire)?;
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("oracle expected compact JWS".into());
    }
    let payload = detached
        .map(|data| URL_SAFE_NO_PAD.encode(data))
        .unwrap_or_else(|| parts[1].to_owned());
    let input = format!("{}.{}", parts[0], payload).into_bytes();
    let signature = URL_SAFE_NO_PAD.decode(parts[2])?;
    let input_path = out.join(format!("{stem}.signing-input"));
    let sig_path = out.join(format!("{stem}.sig"));
    std::fs::write(&input_path, &input)?;
    std::fs::write(&sig_path, &signature)?;
    let positive = openssl(&[
        "dgst",
        "-sha256",
        "-verify",
        p(public_key)?,
        "-signature",
        p(&sig_path)?,
        p(&input_path)?,
    ])?;
    let changed_path = out.join(format!("{stem}.altered-input"));
    let mut changed = input;
    changed.push(b'X');
    std::fs::write(&changed_path, changed)?;
    let negative = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            p(public_key)?,
            "-signature",
            p(&sig_path)?,
            p(&changed_path)?,
        ])
        .output()?;
    if negative.status.success() {
        return Err("OpenSSL accepted changed signing input".into());
    }
    let badsig_path = out.join(format!("{stem}.altered-sig"));
    let mut badsig = signature;
    badsig[0] ^= 1;
    std::fs::write(&badsig_path, badsig)?;
    let badsig = Command::new("openssl")
        .args([
            "dgst",
            "-sha256",
            "-verify",
            p(public_key)?,
            "-signature",
            p(&badsig_path)?,
            p(&input_path)?,
        ])
        .output()?;
    if badsig.status.success() {
        return Err("OpenSSL accepted changed signature".into());
    }
    Ok(format!(
        "{stem}: positive exit={} stdout={} stderr={}\naltered-input exit={} stdout={} stderr={}\naltered-signature exit={} stdout={} stderr={}\n",
        positive.status,
        String::from_utf8_lossy(&positive.stdout).trim(),
        String::from_utf8_lossy(&positive.stderr).trim(),
        negative.status,
        String::from_utf8_lossy(&negative.stdout).trim(),
        String::from_utf8_lossy(&negative.stderr).trim(),
        badsig.status,
        String::from_utf8_lossy(&badsig.stdout).trim(),
        String::from_utf8_lossy(&badsig.stderr).trim()
    ))
}
pub fn run(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    let guard = Arc::new(Guard::default());
    let engine = engine(guard.clone(), ResourceLimits::default(), true, true);
    let rsa = selector("user-rsa-sign");
    let gost = selector("user-gost2015-sign");
    let payload = b"J01 real public detached document\0binary\xff";
    std::fs::write(out.join("payload.bin"), payload)?;
    let rsa_entry = issued("user-rsa-sign");
    let spki = rsa_entry
        .cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()?;
    let public_key = out.join("rsa-public.pem");
    // OpenSSL handles PEM conversion; no hand-written crypto or ASN.1.
    let public_der = out.join("rsa-public.der");
    std::fs::write(&public_der, spki)?;
    openssl(&[
        "pkey",
        "-pubin",
        "-inform",
        "DER",
        "-in",
        p(&public_der)?,
        "-out",
        p(&public_key)?,
    ])?;
    std::fs::write(out.join("signer.der"), rsa_entry.cert.to_der()?)?;
    let mut oracle = String::from_utf8(openssl(&["version"])?.stdout)?;
    let mut summary = String::from(
        "case=J01\nprofile=RFC7515 RS256 / pinned ECGOST3410-2015-512\nprivate_material=none\nclock=host fixed 0; exp required; leeway=0\n",
    );
    for (name, serialization, detached) in [
        ("rsa-compact", JwsSerialization::Compact, false),
        ("rsa-flattened", JwsSerialization::Flattened, false),
        ("rsa-general", JwsSerialization::General, false),
        ("rsa-detached", JwsSerialization::Compact, true),
    ] {
        let profile = JoseProfile::new(serialization, detached);
        let mut wire = Vec::new();
        engine.jws_create(
            profile,
            vec![KeyRequest::new(&rsa, Some("J01 synthetic"))],
            payload,
            &mut wire,
            &mut begin(&engine, &[&rsa], &[Action::Sign]),
        )?;
        let report = engine.jws_verify(
            JwsVerifyRequest::new(profile),
            &wire,
            detached.then_some(payload.as_slice()),
            &mut begin(&engine, &[], &[Action::Verify]),
        )?;
        if report.verdict() != Verdict::Valid {
            return Err(format!("{name} failed: {report:?}").into());
        }
        drop(report);
        std::fs::write(out.join(format!("{name}.jws")), &wire)?;
        let compact;
        let oracle_wire = if serialization == JwsSerialization::Compact {
            wire.as_slice()
        } else {
            compact = json_rsa_compact(&wire)?;
            &compact
        };
        oracle.push_str(&oracle_check(
            out,
            name,
            oracle_wire,
            detached.then_some(payload.as_slice()),
            &public_key,
        )?);
        let mut added = Vec::new();
        engine.jws_add(
            JwsVerifyRequest::new(profile),
            vec![KeyRequest::new(&gost, Some("J01 synthetic"))],
            &wire,
            detached.then_some(payload.as_slice()),
            &mut added,
            &mut begin(&engine, &[&gost], &[Action::Sign]),
        )?;
        let added_profile = JoseProfile::new(JwsSerialization::General, detached);
        let report = engine.jws_verify(
            JwsVerifyRequest::new(added_profile),
            &added,
            detached.then_some(payload.as_slice()),
            &mut begin(&engine, &[], &[Action::Verify]),
        )?;
        if report.verdict() != Verdict::Valid || report.signers().len() != 2 {
            return Err("Add signer verification failed".into());
        }
        drop(report);
        std::fs::write(out.join(format!("{name}-added.jws.json")), &added)?;
        oracle.push_str(&oracle_check(
            out,
            &format!("{name}-added-rsa"),
            &json_rsa_compact(&added)?,
            detached.then_some(payload.as_slice()),
            &public_key,
        )?);
        let mut altered: serde_json::Value = serde_json::from_slice(&added)?;
        altered["signatures"][0]["signature"] = URL_SAFE_NO_PAD.encode([0u8; 256]).into();
        let altered = serde_json::to_vec(&altered)?;
        let before = guard.calls.load(Ordering::SeqCst);
        let mut rejected = Vec::new();
        let rejected_result = engine.jws_add(
            JwsVerifyRequest::new(added_profile),
            vec![KeyRequest::new(&rsa, Some("J01 synthetic"))],
            &altered,
            detached.then_some(payload.as_slice()),
            &mut rejected,
            &mut begin(&engine, &[&rsa], &[Action::Sign]),
        );
        if rejected_result.is_ok()
            || before != guard.calls.load(Ordering::SeqCst)
            || !rejected.is_empty()
        {
            return Err("bad old signer laundered by Add".into());
        }
        summary.push_str(&format!(
            "{name}=verified; Add=2 verified signers; altered-old-signature=refused before guard\n"
        ));
    }
    let mut policy = JwtValidationPolicy::new(0);
    policy.expected_issuer = Some("J01 issuer".into());
    policy.expected_audience = Some("J01 audience".into());
    for (name, claims, expected) in [
        (
            "rsa",
            br#"{"iss":"J01 issuer","aud":"J01 audience","exp":1,"nbf":0}"#.as_slice(),
            Verdict::Valid,
        ),
        (
            "rsa-wrong-aud",
            br#"{"iss":"J01 issuer","aud":"wrong","exp":1,"nbf":0}"#.as_slice(),
            Verdict::Invalid,
        ),
        (
            "rsa-exp-boundary",
            br#"{"iss":"J01 issuer","aud":"J01 audience","exp":0}"#.as_slice(),
            Verdict::Invalid,
        ),
    ] {
        let mut token = Vec::new();
        engine.jwt_encode(
            KeyRequest::new(&rsa, Some("J01 synthetic")),
            claims,
            &mut token,
            &mut begin(&engine, &[&rsa], &[Action::Sign]),
        )?;
        let report = engine.jwt_verify(
            None,
            &token,
            &policy,
            &mut begin(&engine, &[], &[Action::Verify]),
        )?;
        if report.jws().verdict() != Verdict::Valid || report.verdict() != expected {
            return Err("claims/crypto isolation failed".into());
        }
        summary.push_str(&format!(
            "{name}.jwt crypto=Valid trust=Valid claims={:?} aggregate={:?}\n",
            report.claims().verdict(),
            report.verdict()
        ));
        drop(report);
        std::fs::write(out.join(format!("{name}.jwt")), &token)?;
        oracle.push_str(&oracle_check(out, name, &token, None, &public_key)?);
    }
    // New independent standard RS256 vectors: signed by OpenSSL, then parsed and
    // cryptographically/trust/claims verified by the SDK. Temporary synthetic
    // private fixture is never an output artifact and is deleted on scope exit.
    let scratch = tempfile::tempdir()?;
    let private = scratch.path().join("synthetic.pk8");
    std::fs::write(&private, rsa_entry.key.to_pkcs8_der()?.as_slice())?;
    for (name, header, payload) in [
        (
            "openssl-vector-jws",
            br#"{"alg":"RS256"}"#.as_slice(),
            b"independent OpenSSL J01 public vector".as_slice(),
        ),
        (
            "openssl-vector-jwt",
            br#"{"alg":"RS256","typ":"JWT"}"#.as_slice(),
            br#"{"iss":"J01 issuer","aud":"J01 audience","exp":1,"nbf":0}"#.as_slice(),
        ),
    ] {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let input_path = out.join(format!("{name}.signing-input"));
        let sig_path = out.join(format!("{name}.sig"));
        std::fs::write(&input_path, input.as_bytes())?;
        let signed = openssl(&[
            "dgst",
            "-sha256",
            "-keyform",
            "DER",
            "-sign",
            p(&private)?,
            "-out",
            p(&sig_path)?,
            p(&input_path)?,
        ])?;
        oracle.push_str(&format!(
            "{name} independent sign exit={} stdout={} stderr={}\n",
            signed.status,
            String::from_utf8_lossy(&signed.stdout),
            String::from_utf8_lossy(&signed.stderr)
        ));
        let token = format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(std::fs::read(&sig_path)?)
        );
        let profile = JoseProfile::new(JwsSerialization::Compact, false);
        let request = JwsVerifyRequest {
            profile,
            certificate: Some(&rsa_entry.cert),
        };
        let report = engine.jws_verify(
            request,
            token.as_bytes(),
            None,
            &mut begin(&engine, &[], &[Action::Verify]),
        )?;
        if report.verdict() != Verdict::Valid || report.signers()[0].crypto() != CheckStatus::Passed
        {
            return Err("SDK rejected independent OpenSSL vector".into());
        }
        drop(report);
        if name.ends_with("jwt") {
            let report = engine.jwt_verify(
                Some(&rsa_entry.cert),
                token.as_bytes(),
                &policy,
                &mut begin(&engine, &[], &[Action::Verify]),
            )?;
            if report.verdict() != Verdict::Valid {
                return Err("independent JWT claims failed".into());
            }
        }
        std::fs::write(out.join(format!("{name}.jws")), token.as_bytes())?;
        oracle.push_str(&oracle_check(
            out,
            name,
            token.as_bytes(),
            None,
            &public_key,
        )?);
        let altered = token.replacen(
            &URL_SAFE_NO_PAD.encode(payload),
            &URL_SAFE_NO_PAD.encode(b"changed"),
            1,
        );
        let report = engine.jws_verify(
            request,
            altered.as_bytes(),
            None,
            &mut begin(&engine, &[], &[Action::Verify]),
        )?;
        if report.verdict() != Verdict::Invalid {
            return Err("SDK accepted altered independent vector".into());
        }
        summary.push_str(&format!(
            "{name}=OpenSSL signed / SDK verified / altered payload rejected\n"
        ));
    }
    summary.push_str("oracle=OpenSSL RS256 positive/altered-input/altered-signature controls; GOST uses accepted PKI+legacy wire profile, no new external GOST oracle claim\nlimits=bounded JOSE only; no 10GiB/RSS/platform acceptance claim\n");
    std::fs::write(out.join("oracle-verification.txt"), oracle)?;
    std::fs::write(out.join("summary.txt"), &summary)?;
    println!("{summary}");
    Ok(())
}
