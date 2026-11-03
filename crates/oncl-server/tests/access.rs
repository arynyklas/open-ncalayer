mod server_support;
use oncl_core::keys::{KeyId, KeyProvider, KeyRequest, KeySelector};
use oncl_core::{Action, Engine, EngineServices, OperationPolicy};
use oncl_pki::resource::ResourceLimits;
use oncl_server::{
    auth::{AccessPolicy, TokenRecord, TokenSecret},
    config::ServerConfig,
    executor::Cancellation,
    keys::{KeyBinding, OperatorKeys},
};
use std::sync::Arc;

#[test]
fn token_revocation_and_foreign_key() {
    let secret = TokenSecret::generate().unwrap();
    let policy = AccessPolicy::new(vec![
        TokenRecord::new(
            "actor",
            secret.verifier(),
            vec![Action::Hash, Action::Sign],
            vec!["key-a".into()],
        )
        .unwrap(),
    ])
    .unwrap();
    let principal = policy.authenticate(secret.bearer().as_bytes()).unwrap();
    let grant = policy
        .authorize(&principal, Action::Sign, Some("key-a"), None)
        .unwrap();
    assert!(grant.allows_key(&KeyId::new("key-a").unwrap()));
    assert!(
        policy
            .authorize(&principal, Action::Sign, Some("key-b"), None)
            .is_err()
    );
    // The configured source disappears after operator selection. A foreign grant
    // must still be rejected by the actual provider before file open/decode.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("container.p12");
    std::fs::write(&path, b"not a container").unwrap();
    let keys = OperatorKeys::new(
        vec![KeyBinding::file("key-b", path.clone(), None, "synthetic".into()).unwrap()],
        None,
        false,
    )
    .unwrap();
    std::fs::remove_file(path).unwrap();
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = engine
        .begin(
            grant,
            OperationPolicy::strict_online(),
            Arc::new(Cancellation::new()),
        )
        .unwrap();
    let selector = KeySelector::named(KeyId::new("key-b").unwrap());
    assert!(matches!(
        keys.open(&KeyRequest::new(&selector, None), &mut ctx),
        Err(oncl_core::OperationError::PermissionDenied)
    ));
    policy.revoke("actor").unwrap();
    assert!(policy.authenticate(secret.bearer().as_bytes()).is_err());
    assert!(
        policy
            .authorize(&principal, Action::Hash, None, None)
            .is_err()
    );
    assert!(ctx.grant().allows(Action::Sign));
}

#[test]
fn nested_selector_mismatch() {
    let secret = TokenSecret::generate().unwrap();
    let policy = AccessPolicy::new(vec![
        TokenRecord::new(
            "actor",
            secret.verifier(),
            vec![Action::Hash, Action::Sign],
            vec!["key-a".into()],
        )
        .unwrap(),
    ])
    .unwrap();
    let principal = policy.authenticate(secret.bearer().as_bytes()).unwrap();
    assert!(
        policy
            .authorize(&principal, Action::Hash, None, Some((Action::Sign, None)))
            .is_err()
    );
    assert!(
        policy
            .authorize(
                &principal,
                Action::Sign,
                Some("key-a"),
                Some((Action::Sign, Some("key-b")))
            )
            .is_err()
    );
    assert!(
        policy
            .authorize(&principal, Action::Hash, Some("key-a"), None)
            .is_err()
    );
}

#[test]
fn unsafe_lan_is_refused() {
    let mut config = ServerConfig {
        enabled: true,
        bind: "0.0.0.0:0".parse().unwrap(),
        ..ServerConfig::default()
    };
    assert!(config.validate().is_err());
    config.bind = "127.0.0.1:0".parse().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn disabled_means_no_listener() {
    use std::{io::Write, process::Command};
    let dir = server_support::sandbox();
    let operator_path = dir.path().join("operator");
    let operator = oncl_pki::private_fs::PrivateDirectory::create(&operator_path).unwrap();
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    operator
        .create_file("disabled.toml")
        .unwrap()
        .write_all(format!("bind = '{address}'\nenabled = false\n").as_bytes())
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
        .args(["serve", "--config"])
        .arg(operator_path.join("disabled.toml"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(std::net::TcpStream::connect(address).is_err());
    let output = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    eprintln!("standalone: enabled=false/no-command exit=0 and socket refused");
}

#[test]
fn real_process_hash_auth_and_unknown_length() {
    use std::io::{Read, Write};
    let process = server_support::Process::start("input_bytes = 3");
    server_support::runtime().block_on(async {
        let (status, bytes) = server_support::request(
            process.address,
            &process.token,
            "/v1/hash",
            b"abc",
            &[],
            None,
        )
        .await;
        assert_eq!(status, 200);
        let report: oncl_api::dto::HashResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report.bytes_in, 3);
        assert_eq!(
            report.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let (status, bytes) = server_support::request(
            process.address,
            &"00".repeat(32),
            "/v1/hash",
            b"abc",
            &[],
            None,
        )
        .await;
        assert_eq!(status, 403);
        let error: oncl_api::error::ApiError = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error.code, oncl_api::error::ErrorCode::PermissionDenied);
        assert_eq!(error.applied, oncl_api::error::AppliedState::NotApplied);
        assert_eq!(
            server_support::request(
                process.address,
                &process.token,
                "/v1/hash?operation=sign&key=foreign",
                b"abc",
                &[],
                None
            )
            .await
            .0,
            400
        );
        assert_eq!(
            server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[("x-oncl-key", "foreign")],
                None
            )
            .await
            .0,
            400
        );
        assert_eq!(
            server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[("x-oncl-operation", "sign")],
                None
            )
            .await
            .0,
            400
        );
    });
    // Real HTTP/1 chunked intake has no Content-Length; N+1 is still refused.
    let mut socket = std::net::TcpStream::connect(process.address).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    write!(socket,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n",process.address,*process.token).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 413"));
    assert!(response.contains("\"code\":\"InputLimit\""));
    // Malformed and truncated declared lengths are not successful hashes.
    for length in ["not-a-length", "4"] {
        let mut socket = std::net::TcpStream::connect(process.address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        write!(socket,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: {length}\r\n\r\nabc",process.address,*process.token).unwrap();
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(!response.starts_with("HTTP/1.1 200"));
    }
    eprintln!(
        "standalone: authenticated abc SHA256/3 correct, bad token refused, unknown N+1 refused, malformed length no success"
    );
    process.stop();
}

#[test]
fn proxy_header_not_authority() {
    let process =
        server_support::Process::start("exposure = { mode = 'trusted_proxy', peers = ['::1'] }");
    server_support::runtime().block_on(async {
        let (status, _) = server_support::request(
            process.address,
            &process.token,
            "/v1/hash",
            b"abc",
            &[
                ("forwarded", "for=127.0.0.1;by=\"[::1]\""),
                ("x-forwarded-for", "::1"),
                ("origin", "https://trusted.example"),
            ],
            None,
        )
        .await;
        assert_eq!(status, 403);
    });
    process.stop();
    let process = server_support::Process::start(
        "exposure = { mode = 'trusted_proxy', peers = ['127.0.0.1'] }",
    );
    server_support::runtime().block_on(async {
        assert_eq!(
            server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[],
                None
            )
            .await
            .0,
            200
        );
        assert_eq!(
            server_support::request(
                process.address,
                &"00".repeat(32),
                "/v1/hash",
                b"abc",
                &[("origin", "https://trusted.example")],
                None
            )
            .await
            .0,
            403
        );
    });
    process.stop();
}

#[test]
fn real_tls_listener_does_not_install_trust() {
    use std::io::Write;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    // The certificate/key live solely inside this test's target sandbox.
    let staging = server_support::sandbox();
    let cert_path = staging.path().join("server.crt");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    let secret_dir = staging.path().join("secrets");
    let secrets = oncl_pki::private_fs::PrivateDirectory::create(&secret_dir).unwrap();
    secrets
        .create_file("server.key")
        .unwrap()
        .write_all(key.serialize_pem().as_bytes())
        .unwrap();
    let extra = format!(
        "hosts = ['localhost']\nexposure = {{ mode = 'tls', certificate = {}, private_key = {{ directory = {}, name = 'server.key' }} }}",
        server_support::toml_path(&cert_path),
        server_support::toml_path(&secret_dir)
    );
    let process = server_support::Process::start_at(&extra, "0.0.0.0:0");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    server_support::runtime().block_on(async {
        assert_eq!(
            server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[("host", "localhost")],
                Some(Arc::new(client))
            )
            .await
            .0,
            200
        );
    });
    eprintln!("standalone: real rustls HTTPS abc accepted with target-only synthetic trust");
    process.stop();
}

#[test]
fn inline_permission_never_authorizes_client_file_or_token_selectors() {
    use oncl_core::ExecutionGrant;
    let directory = server_support::sandbox();
    let path = directory.path().join("removed.p12");
    std::fs::write(&path, b"synthetic").unwrap();
    let file = KeySelector::file(&path, None).unwrap();
    std::fs::remove_file(path).unwrap();
    let token = KeySelector::token(
        oncl_token::execution::TokenDeviceId::new("never-open-reader").unwrap(),
        oncl_token::TokenKind::Kaztoken,
        "never-open-alias".into(),
    );
    let provider = OperatorKeys::new(Vec::new(), None, true).unwrap();
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    for selector in [&file, &token] {
        let grant = ExecutionGrant::new([Action::Sign]).with_keys([selector.key_id()]);
        let mut ctx = engine
            .begin(
                grant,
                OperationPolicy::strict_online(),
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        assert!(
            matches!(
                provider.open(
                    &KeyRequest::new(selector, Some("synthetic-secret")),
                    &mut ctx
                ),
                Err(oncl_core::OperationError::PermissionDenied)
            ),
            "inline permission reached a client-selected non-inline source"
        );
    }
}

#[test]
fn inline_global_and_client_right_bind_exact_source() {
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    let bytes = oncl_testkit::read(fixture.path);
    let secret = TokenSecret::generate().unwrap();
    let policy = AccessPolicy::new(vec![
        TokenRecord::new("actor", secret.verifier(), vec![Action::Sign], Vec::new()).unwrap(),
    ])
    .unwrap();
    let principal = policy.authenticate(secret.bearer().as_bytes()).unwrap();
    let selector = KeySelector::inline(bytes, Some(fixture.aliases[0].clone()));
    assert!(
        policy
            .authorize_inline(&principal, Action::Sign, &selector, true)
            .is_err()
    );
    let policy = AccessPolicy::new(vec![
        TokenRecord::new("actor", secret.verifier(), vec![Action::Sign], Vec::new())
            .unwrap()
            .with_inline_pkcs12(true),
    ])
    .unwrap();
    let principal = policy.authenticate(secret.bearer().as_bytes()).unwrap();
    assert!(
        policy
            .authorize_inline(&principal, Action::Sign, &selector, false)
            .is_err()
    );
    let grant = policy
        .authorize_inline(&principal, Action::Sign, &selector, true)
        .unwrap();
    let engine = Engine::new(EngineServices::hash_only(ResourceLimits::default())).unwrap();
    let mut ctx = engine
        .begin(
            grant,
            OperationPolicy::strict_online(),
            Arc::new(Cancellation::new()),
        )
        .unwrap();
    let disabled = OperatorKeys::new(Vec::new(), None, false).unwrap();
    assert!(matches!(
        disabled.open(
            &KeyRequest::new(&selector, Some(&fixture.password)),
            &mut ctx
        ),
        Err(oncl_core::OperationError::PermissionDenied)
    ));
    let enabled = OperatorKeys::new(Vec::new(), None, true).unwrap();
    let actual = enabled
        .open(
            &KeyRequest::new(&selector, Some(&fixture.password)),
            &mut ctx,
        )
        .unwrap();
    drop(actual);
    let other = KeySelector::inline(vec![0, 1, 2], None);
    assert!(matches!(
        enabled.open(&KeyRequest::new(&other, Some("unused")), &mut ctx),
        Err(oncl_core::OperationError::PermissionDenied)
    ));
    let temp_limit = ctx.resources().limits().temp_bytes;
    assert!(
        ctx.resources().reserve_temp(temp_limit).is_ok(),
        "inline source never consumes document spool"
    );
}

#[test]
fn live_revocation_refuses_new_http_requests_not_original_grant() {
    server_support::runtime().block_on(async {
        let directory = server_support::sandbox();
        let token = TokenSecret::generate().unwrap();
        let mut config = ServerConfig::default();
        config.audit_directory = directory.path().join("audit");
        config.tokens = vec![oncl_server::config::TokenConfig {
            id: "actor".into(),
            verifier: token.verifier().encoded(),
            actions: vec![oncl_server::config::Permission::Hash],
            keys: Vec::new(),
            inline_pkcs12: false,
        }];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let host = oncl_server::service::ServiceHost::new(config)
            .unwrap()
            .for_listener(address)
            .unwrap();
        let principal = host.policy.authenticate(token.bearer().as_bytes()).unwrap();
        let (mut original, _) = host
            .begin(
                &principal,
                Action::Hash,
                None,
                Arc::new(Cancellation::new()),
            )
            .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(oncl_server::service::serve(
            listener,
            host.clone(),
            None,
            async {
                let _ = stopped.await;
            },
        ));
        assert_eq!(
            server_support::request(address, &token.bearer(), "/v1/hash", b"abc", &[], None)
                .await
                .0,
            200
        );
        host.policy
            .replace(vec![
                TokenRecord::new(
                    "actor",
                    token.verifier(),
                    vec![Action::Sign],
                    vec!["key-a".into()],
                )
                .unwrap(),
            ])
            .unwrap();
        assert_eq!(
            server_support::request(address, &token.bearer(), "/v1/hash", b"abc", &[], None)
                .await
                .0,
            403
        );
        assert!(
            host.policy
                .authorize(&principal, Action::Hash, None, None)
                .is_err()
        );
        let updated = host.policy.authenticate(token.bearer().as_bytes()).unwrap();
        assert!(
            host.policy
                .authorize(&updated, Action::Sign, Some("key-a"), None)
                .is_ok()
        );
        host.policy.revoke("actor").unwrap();
        assert_eq!(
            server_support::request(address, &token.bearer(), "/v1/hash", b"abc", &[], None)
                .await
                .0,
            403
        );
        assert!(
            host.policy
                .authorize(&principal, Action::Hash, None, None)
                .is_err()
        );
        let report = host
            .engine
            .hash(
                oncl_pki::key::HashAlg::Sha256,
                oncl_pki::io::Source::sequential(&mut std::io::Cursor::new(b"abc"), Some(3)),
                &mut original,
            )
            .unwrap();
        assert_eq!(report.bytes_in, 3);
        drop(original);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    });
}

#[test]
fn named_operator_bindings_use_only_authorized_audit_labels() {
    use std::io::Write;
    let directory = server_support::sandbox();
    let operator_path = directory.path().join("operator");
    let operator = oncl_pki::private_fs::PrivateDirectory::create(&operator_path).unwrap();
    let fixture = oncl_testkit::synthetic("user-rsa-sign");
    operator
        .create_file("key.p12")
        .unwrap()
        .write_all(&oncl_testkit::read(fixture.path))
        .unwrap();
    operator
        .create_file("password")
        .unwrap()
        .write_all(fixture.password.as_bytes())
        .unwrap();
    let secret = TokenSecret::generate().unwrap();
    let mut config = ServerConfig::default();
    config.audit_directory = directory.path().join("audit");
    config.tokens = vec![oncl_server::config::TokenConfig {
        id: "actor".into(),
        verifier: secret.verifier().encoded(),
        actions: vec![oncl_server::config::Permission::Sign],
        keys: vec!["key-39".into()],
        inline_pkcs12: false,
    }];
    config.keys = (0..40)
        .map(|n| oncl_server::config::KeyConfig::File {
            name: format!("key-{n}"),
            path: operator_path.join("key.p12"),
            alias: Some(fixture.aliases[0].clone()),
            secret: oncl_server::config::SecretMount {
                directory: operator_path.clone(),
                name: "password".into(),
            },
        })
        .collect();
    let host = oncl_server::service::ServiceHost::new(config).unwrap();
    let principal = host
        .policy
        .authenticate(secret.bearer().as_bytes())
        .unwrap();
    let (mut ctx, binding) = host
        .begin(
            &principal,
            Action::Sign,
            Some("key-39"),
            Arc::new(Cancellation::new()),
        )
        .unwrap();
    let selector = KeySelector::named(KeyId::new("key-39").unwrap());
    let actual = host
        .keys
        .open(&KeyRequest::new(&selector, None), &mut ctx)
        .unwrap();
    drop(actual);
    drop(binding);
    drop(ctx);
    assert!(
        host.audit
            .records()
            .unwrap()
            .iter()
            .all(|r| r.kind != oncl_server::audit::RecordKind::Begin)
    );
}

#[test]
fn duplicate_verifiers_are_not_ambiguous_identities() {
    let secret = TokenSecret::generate().unwrap();
    assert!(
        AccessPolicy::new(vec![
            TokenRecord::new("a", secret.verifier(), vec![Action::Hash], Vec::new()).unwrap(),
            TokenRecord::new(
                "b",
                secret.verifier(),
                vec![Action::Sign],
                vec!["key-a".into()]
            )
            .unwrap()
        ])
        .is_err()
    );
}

#[test]
fn foreign_policy_principal_cannot_mint_authority() {
    let a = TokenSecret::generate().unwrap();
    let b = TokenSecret::generate().unwrap();
    let first = AccessPolicy::new(vec![
        TokenRecord::new("actor", a.verifier(), vec![Action::Hash], Vec::new()).unwrap(),
    ])
    .unwrap();
    let second = AccessPolicy::new(vec![
        TokenRecord::new("actor", b.verifier(), vec![Action::Hash], Vec::new()).unwrap(),
    ])
    .unwrap();
    let foreign = first.authenticate(a.bearer().as_bytes()).unwrap();
    assert!(
        second
            .authorize(&foreign, Action::Hash, None, None)
            .is_err()
    );
}
