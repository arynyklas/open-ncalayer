//! Our own additions to the NCANode families: hashes, RFC 3161 timestamps, plugin calls.

use std::path::Path;

use anyhow::{Context, ensure};
use oncl_pdk::abi::{self, Import};
use serde_json::Value;

use super::super::kalkan;
use super::super::oncl::path_str;
use super::super::tools::hex;
use super::super::world::{NOW, Profile};
use super::super::{Case, Ctx, Observed};
use super::common::{
    CONTENT, b64, grade, kalkan_algorithm, kalkan_raw_discriminates, nc_key, unb64,
};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("hash-sha256", |ctx| hash(ctx, "sha256")),
        Case::new("hash-gost2015-512", |ctx| hash(ctx, "gost2015-512")),
        Case::new("hash-gost2004", |ctx| hash(ctx, "gost2004")),
        Case::new("timestamp-sha256", |ctx| timestamp(ctx, "sha256", false)),
        Case::new("timestamp-tamper-sha256", |ctx| {
            timestamp(ctx, "sha256", true)
        }),
        Case::new("timestamp-gost2015-512", |ctx| {
            timestamp(ctx, "gost2015-512", false)
        }),
        Case::new("plugin-hash-sha256", plugin_hash),
        Case::new("plugin-sign-raw-rsa", |ctx| plugin_sign(ctx, Profile::Rsa)),
        Case::new("plugin-sign-raw-gost2015", |ctx| {
            plugin_sign(ctx, Profile::Gost2015)
        }),
    ]
}

/// A deterministic, non-repeating-looking 3 MiB input.
fn big() -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def0_u64;
    (0..3 << 20)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn oncl_hash(ctx: &Ctx, algorithm: &str, file: &Path) -> anyhow::Result<String> {
    let out = ctx.oncl.run(&[
        "hash".to_owned(),
        "--algorithm".into(),
        algorithm.into(),
        "--input".into(),
        path_str(file)?.into(),
    ])?;
    ensure!(out.ok(), "oncl hash: {}", out.brief());
    Ok(out.stdout_text().trim().to_owned())
}

/// `oncl hash` over empty, short and 3 MiB inputs against OpenSSL (SHA-256), gostcrypto
/// (Streebog-512) and the messageDigest Kalkan wrote into a CMS of the same content.
fn hash(ctx: &mut Ctx, algorithm: &str) -> anyhow::Result<Observed> {
    let inputs: [(&str, Vec<u8>); 3] = [
        ("empty", Vec::new()),
        ("abc", b"abc".to_vec()),
        ("3mib", big()),
    ];
    let mut judged = Vec::new();
    for (name, bytes) in &inputs {
        let file = ctx.write(&format!("{name}.bin"), bytes)?;
        let ours = oncl_hash(ctx, algorithm, &file)?;
        match algorithm {
            "sha256" => {
                let out = ctx.openssl(&[
                    "dgst".to_owned(),
                    "-sha256".into(),
                    "-r".into(),
                    path_str(&file)?.into(),
                ])?;
                ensure!(out.ok(), "openssl dgst: {}", out.brief());
                let theirs = out
                    .stdout_text()
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                ensure!(ours == theirs, "{name}: oncl {ours}, OpenSSL {theirs}");
            }
            "gost2015-512" => {
                let script = ctx.py_json(&[
                    "hash".to_owned(),
                    "streebog512".to_owned(),
                    path_str(&file)?.to_owned(),
                ])?;
                ensure!(
                    ours == script["digest"].as_str().unwrap_or(""),
                    "{name}: oncl {ours}, gostcrypto {script}"
                );
            }
            _ => {}
        }
        judged.push(*name);
    }
    let mut kalkan = String::new();
    if algorithm != "sha256" {
        // Kalkan's own digest of the same content: the messageDigest of its detached CMS.
        let profile = if algorithm == "gost2015-512" {
            Profile::Gost2015
        } else {
            Profile::Gost2004
        };
        let key = nc_key(profile)?;
        let (status, answer) = ctx.nc_post(
            "/cms/sign",
            &serde_json::json!({ "data": b64(CONTENT), "signers": [key.request()], "cadesLevel": "B", "detached": true }),
        )?;
        ensure!(status == 200, "NCANode /cms/sign: HTTP {status} {answer}");
        let cms = ctx.write(
            "kalkan.p7s",
            &unb64(answer["cms"].as_str().context("no cms")?)?,
        )?;
        let info = ctx.py_json(&["cms-info".to_owned(), path_str(&cms)?.to_owned()])?;
        let digest = info["signers"][0]["message_digest_hex"]
            .as_str()
            .unwrap_or("")
            .to_owned();
        let content = ctx.write("content.bin", CONTENT)?;
        let ours = oncl_hash(ctx, algorithm, &content)?;
        ensure!(ours == digest, "oncl {ours}, Kalkan messageDigest {digest}");
        kalkan = "equal(Kalkan messageDigest)".to_owned();
    }
    let mut verdicts = vec![("inputs", judged.join("+"))];
    verdicts.push((
        "independent",
        match algorithm {
            "sha256" => "OpenSSL dgst equal".to_owned(),
            "gost2015-512" => format!("gostcrypto streebog512 equal; {kalkan}"),
            _ => kalkan,
        },
    ));
    Ok(Observed {
        grade: grade(&verdicts),
        ours: "digests equal".to_owned(),
        oracle: "see grade".to_owned(),
        detail: String::new(),
    })
}

/// `oncl timestamp acquire|verify` against the loopback TSA: OpenSSL `ts -verify` (SHA-256)
/// and the Python token oracle (imprint and RSA signature of the token; Streebog-512 via
/// gostcrypto).
fn timestamp(ctx: &mut Ctx, algorithm: &str, tamper: bool) -> anyhow::Result<Observed> {
    let data = ctx.write("data.bin", CONTENT)?;
    let token = ctx.file("token.tst");
    let mut args = ctx.world.trust_args();
    args.extend([
        "timestamp".to_owned(),
        "acquire".into(),
        "--input".into(),
        path_str(&data)?.into(),
        "--output".into(),
        path_str(&token)?.into(),
        "--tsa".into(),
        ctx.world.tsa_url(),
        "--algorithm".into(),
        algorithm.into(),
    ]);
    let out = ctx.oncl.run(&args)?;
    ensure!(out.ok(), "oncl timestamp acquire: {}", out.brief());
    let judged = if tamper {
        let mut d = CONTENT.to_vec();
        d[0] ^= 1;
        ctx.write("altered.bin", &d)?
    } else {
        data.clone()
    };
    let mut vargs = ctx.world.trust_args();
    vargs.extend([
        "timestamp".to_owned(),
        "verify".into(),
        "--input".into(),
        path_str(&token)?.into(),
        "--data".into(),
        path_str(&judged)?.into(),
        "--algorithm".into(),
        algorithm.into(),
    ]);
    let ours = ctx.oncl.run(&vargs)?;
    let mut verdicts = Vec::new();
    if tamper {
        ensure!(
            !ours.ok(),
            "oncl accepted a token for altered data: {}",
            ours.brief()
        );
        verdicts.push(("ours", "rejected".to_owned()));
    } else {
        ensure!(ours.ok(), "oncl timestamp verify: {}", ours.brief());
        verdicts.push(("ours", "verified".to_owned()));
    }
    let info = ctx.py_json(&[
        "tst-verify".to_owned(),
        path_str(&token)?.to_owned(),
        "--data".into(),
        path_str(&judged)?.to_owned(),
    ])?;
    if tamper {
        ensure!(
            info["imprint_ok"] == false,
            "independent imprint check accepted altered data: {info}"
        );
        verdicts.push(("independent-imprint", "mismatch".to_owned()));
    } else {
        ensure!(
            info["imprint_ok"] == true && info["signature_ok"] == true,
            "independent token check: {info}"
        );
        verdicts.push((
            "independent",
            format!(
                "imprint+RSA signature ok ({})",
                info["imprint_alg"].as_str().unwrap_or("?")
            ),
        ));
    }
    if algorithm == "sha256" {
        let pem = ctx.world.root_pem.clone();
        let verify = ctx.openssl(&[
            "ts".to_owned(),
            "-verify".into(),
            "-in".into(),
            path_str(&token)?.into(),
            "-token_in".into(),
            "-data".into(),
            path_str(&judged)?.into(),
            "-CAfile".into(),
            path_str(&pem)?.into(),
            "-attime".into(),
            NOW.to_string(),
        ])?;
        if tamper {
            ensure!(!verify.ok(), "OpenSSL accepted the altered data");
            verdicts.push(("openssl-ts", "rejected".to_owned()));
        } else {
            ensure!(verify.ok(), "openssl ts -verify: {}", verify.brief());
            verdicts.push(("openssl-ts", "verified".to_owned()));
        }
    }
    Ok(Observed {
        grade: grade(&verdicts),
        ours: ours.brief(),
        oracle: "see grade".to_owned(),
        detail: String::new(),
    })
}

const MANIFEST: &str = "id = \"test.interop\"\nname.ru = \"interop\"\nname.kk = \"interop\"\nname.en = \"interop\"\nversion = \"1.0.0\"\nmin_core = \"0.1.0\"\nmodules = [\"test.interop.module\"]\n[capabilities]\nkeys = true\ndialogs = true\n";

/// A guest that calls one import with fixed CBOR arguments and returns the hex of the result
/// (the shape of the CLI plugin tests' module).
fn guest(import: Import, args: &[u8]) -> anyhow::Result<Vec<u8>> {
    let escaped: String = args.iter().map(|b| format!("\\{b:02x}")).collect();
    let name = import.name();
    let heap = (1024 + args.len()).div_ceil(65536).max(1) * 65536;
    let text = format!(
        r#"(module (import "oncl" "{name}" (func ${name} (param i32 i32) (result i64)))
      (memory (export "memory") 16 16)
      (global $heap (mut i32) (i32.const {heap}))
      (func (export "oncl_abi_version") (result i32) (i32.const 1))
      (func (export "oncl_alloc") (param $n i32) (result i32) (local $p i32)
        (local.set $p (global.get $heap))
        (global.set $heap (i32.add (local.get $p) (local.get $n))) (local.get $p))
      (func (export "oncl_free") (param i32 i32))
      (data (i32.const 1024) "{escaped}") (data (i32.const 512) "0123456789abcdef")
      (func (export "oncl_process") (param i32 i32) (result i64)
        (local $r i64) (local $src i32) (local $len i32) (local $i i32) (local $b i32) (local $out i32) (local $hex i32)
        (local.set $r (call ${name} (i32.const 1024) (i32.const {len})))
        (local.set $src (i32.wrap_i64 (i64.shr_u (local.get $r) (i64.const 32))))
        (local.set $len (i32.wrap_i64 (local.get $r)))
        (local.set $out (global.get $heap))
        (i32.store8 (local.get $out) (i32.const 0xa1))
        (i32.store8 offset=1 (local.get $out) (i32.const 0x68))
        (i64.store offset=2 (local.get $out) (i64.const 0x65736e6f70736572))
        (i32.store8 offset=10 (local.get $out) (i32.const 0x7a))
        (local.set $hex (i32.shl (local.get $len) (i32.const 1)))
        (i32.store8 offset=11 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 24)))
        (i32.store8 offset=12 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 16)))
        (i32.store8 offset=13 (local.get $out) (i32.shr_u (local.get $hex) (i32.const 8)))
        (i32.store8 offset=14 (local.get $out) (local.get $hex))
        (block $done (loop $next
          (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
          (local.set $b (i32.load8_u (i32.add (local.get $src) (local.get $i))))
          (i32.store8 offset=15 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.shr_u (local.get $b) (i32.const 4))))
          (i32.store8 offset=16 (i32.add (local.get $out) (i32.shl (local.get $i) (i32.const 1)))
            (i32.load8_u offset=512 (i32.and (local.get $b) (i32.const 15))))
          (local.set $i (i32.add (local.get $i) (i32.const 1))) (br $next)))
        (i64.or (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
          (i64.extend_i32_u (i32.add (local.get $hex) (i32.const 15))))))"#,
        len = args.len()
    );
    wat::parse_str(text).context("assembling the guest module")
}

/// Runs `oncl plugin call` of a guest that calls `import`; the guest's answer is the call's
/// result as hex text.
fn plugin_call(
    ctx: &Ctx,
    import: Import,
    args: &[u8],
    extra: &[String],
) -> anyhow::Result<super::super::tools::Out> {
    let manifest = ctx.write("plugin.toml", MANIFEST.as_bytes())?;
    let module = ctx.write("plugin.wasm", &guest(import, args)?)?;
    let arguments = ctx.write("args.json", b"{}")?;
    let mut all = ctx.world.trust_args();
    all.extend([
        "plugin".to_owned(),
        "call".into(),
        "--manifest".into(),
        path_str(&manifest)?.into(),
        "--module".into(),
        path_str(&module)?.into(),
        "--operation".into(),
        "sign".into(),
        "--caller".into(),
        "cli-operator".into(),
        "--args-file".into(),
        path_str(&arguments)?.into(),
        "--output".into(),
        "-".into(),
    ]);
    all.extend(extra.iter().cloned());
    ctx.oncl.run(&all)
}

/// The hex the guest returned, decoded (the output is `"<hex>"` of the CBOR text).
fn decoded(stdout: &str) -> anyhow::Result<Vec<u8>> {
    let text = stdout.trim();
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).context("odd hex")?, 16).context("not hex"))
        .collect()
}

/// The bytes of the host's `{"Ok": <byte string>}` answer (CBOR) the guest returned.
fn ok_bytes(answer: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(
        answer.starts_with(&[0xa1, 0x62, b'O', b'k']),
        "not an Ok answer: {}",
        hex(answer)
    );
    let rest = &answer[4..];
    let (length, body) = match rest.first().copied().context("empty")? {
        n @ 0x40..=0x57 => (usize::from(n - 0x40), &rest[1..]),
        0x58 => (usize::from(*rest.get(1).context("short")?), &rest[2..]),
        0x59 => (
            usize::from(u16::from_be_bytes([
                *rest.get(1).context("short")?,
                *rest.get(2).context("short")?,
            ])),
            &rest[3..],
        ),
        other => anyhow::bail!("not a byte string: {other:#x}"),
    };
    ensure!(
        body.len() == length,
        "length {length} but {} bytes",
        body.len()
    );
    Ok(body.to_vec())
}

fn plugin_hash(ctx: &mut Ctx) -> anyhow::Result<Observed> {
    let args = abi::encode(&abi::HashArgs {
        alg: abi::HashAlg::Sha256,
        data: b"abc".to_vec().into(),
    });
    let granted = plugin_call(
        ctx,
        Import::Hash,
        &args,
        &["--allow-import".to_owned(), "hash".to_owned()],
    )?;
    ensure!(granted.ok(), "plugin call: {}", granted.brief());
    let digest = ok_bytes(&decoded(&granted.stdout_text())?)?;
    let file = ctx.write("abc.bin", b"abc")?;
    let out = ctx.openssl(&[
        "dgst".to_owned(),
        "-sha256".into(),
        "-r".into(),
        path_str(&file)?.into(),
    ])?;
    let theirs = out
        .stdout_text()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_owned();
    ensure!(
        hex(&digest) == theirs,
        "plugin hash {} vs OpenSSL {theirs}",
        hex(&digest)
    );
    let denied = plugin_call(ctx, Import::Hash, &args, &[])?;
    ensure!(
        denied.code == Some(1)
            && denied.stderr.contains("PermissionDenied")
            && denied.stdout.is_empty(),
        "an ungranted import must be denied: {}",
        denied.brief()
    );
    Ok(Observed {
        grade: grade(&[
            ("granted", "digest equals OpenSSL".to_owned()),
            ("ungranted", "PermissionDenied, no output".to_owned()),
        ]),
        ours: granted.brief(),
        oracle: "OpenSSL dgst -sha256".to_owned(),
        detail: String::new(),
    })
}

/// A plugin signs with the operator-bound key (`keys_sign_raw`, handle 1): OpenSSL (RSA) or
/// Kalkan (GOST) verifies the signature; for RSA, another handle or a missing `--authorize`
/// never reaches the key.
fn plugin_sign(ctx: &mut Ctx, profile: Profile) -> anyhow::Result<Observed> {
    let signer = ctx.world.signer(profile);
    let key = vec![
        "--key".to_owned(),
        path_str(&signer.p12)?.to_owned(),
        "--secret-file".into(),
        path_str(&ctx.world.secret)?.to_owned(),
        "--allow-import".into(),
        "keys_sign_raw".into(),
        "--plugin-pki-endpoint".into(),
        format!("GET={}/ocsp", ctx.world.origin),
        "--plugin-pki-endpoint".into(),
        format!("POST={}/ocsp", ctx.world.origin),
    ];
    let mut authorized = key.clone();
    authorized.push("--authorize".to_owned());
    let args = abi::encode(&abi::SignRawArgs {
        handle: 1,
        data: b"plugin message".to_vec().into(),
    });
    let run = plugin_call(ctx, Import::KeysSignRaw, &args, &authorized)?;
    ensure!(
        run.ok() && run.stderr.contains("applied=Applied succeeded=true"),
        "plugin call: {}",
        run.brief()
    );
    let signature = ok_bytes(&decoded(&run.stdout_text())?)?;
    if profile != Profile::Rsa {
        let cert = signer.cert_der.clone();
        kalkan_raw_discriminates(
            ctx,
            profile,
            &cert,
            b"plugin message",
            &signature,
            "the plugin",
        )?;
        return Ok(Observed {
            grade: grade(&[
                ("crypto", "ok".to_owned()),
                ("kalkan", "verified, altered data rejected".to_owned()),
            ]),
            ours: run.brief(),
            oracle: format!(
                "Kalkan {} with the signer certificate ({} signature bytes); {}",
                kalkan_algorithm(profile)?,
                signature.len(),
                kalkan::LABEL
            ),
            detail: String::new(),
        });
    }
    let cert = signer.cert_der.clone();
    let pubkey = ctx.file("plugin.pub");
    let x = ctx.openssl(&[
        "x509".to_owned(),
        "-inform".into(),
        "DER".into(),
        "-in".into(),
        path_str(&cert)?.into(),
        "-pubkey".into(),
        "-noout".into(),
        "-out".into(),
        path_str(&pubkey)?.into(),
    ])?;
    ensure!(x.ok(), "openssl x509: {}", x.brief());
    let data = ctx.write("plugin.data", b"plugin message")?;
    let sig = ctx.write("plugin.sig", &signature)?;
    let check = ctx.openssl(&[
        "dgst".to_owned(),
        "-sha256".into(),
        "-verify".into(),
        path_str(&pubkey)?.into(),
        "-signature".into(),
        path_str(&sig)?.into(),
        path_str(&data)?.into(),
    ])?;
    ensure!(
        check.ok(),
        "OpenSSL rejected the plugin's signature: {}",
        check.brief()
    );
    let other = abi::encode(&abi::SignRawArgs {
        handle: 2,
        data: b"plugin message".to_vec().into(),
    });
    let denied = plugin_call(ctx, Import::KeysSignRaw, &other, &authorized)?;
    ensure!(
        denied.code == Some(1)
            && denied.stderr.contains("PermissionDenied")
            && !denied.stderr.contains("private_use"),
        "another handle: {}",
        denied.brief()
    );
    let unauthorized = plugin_call(ctx, Import::KeysSignRaw, &args, &key)?;
    ensure!(
        unauthorized.code == Some(1) && unauthorized.stderr.contains("AuthorityRequired"),
        "without --authorize: {}",
        unauthorized.brief()
    );
    let _: Option<Value> = None;
    Ok(Observed {
        grade: grade(&[
            ("crypto", "ok".to_owned()),
            ("openssl", "RSA signature verified".to_owned()),
            ("other-handle", "PermissionDenied, key unused".to_owned()),
            ("no-authorize", "AuthorityRequired".to_owned()),
        ]),
        ours: run.brief(),
        oracle: "OpenSSL dgst -sha256 -verify".to_owned(),
        detail: String::new(),
    })
}
