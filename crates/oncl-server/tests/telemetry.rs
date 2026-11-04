//! O01: opt-in OTLP metrics/traces against a REAL local OTLP/HTTP protobuf receiver
//! (`telemetry_support`), never a mock of the SDK. Requests are real HTTP requests to
//! the real server (in-process listener or the real `oncl-server` binary) whose
//! strict-online signing runs against a loopback OCSP/CRL responder.
#[path = "server_support/mod.rs"]
mod server_support;
mod telemetry_support;

mod telemetry {
    use super::{
        server_support,
        telemetry_support::{self as collector, Collector, Mode, pki::Pki},
    };
    use oncl_pki::private_fs::PrivateDirectory;
    use oncl_server::{
        audit::{AuditConfig, AuditHealth, DurableAuditGuard, RecordKind},
        auth::TokenSecret,
        config::{KeyConfig, Permission, PkiEndpoint, SecretMount, ServerConfig, TokenConfig},
        service::{ServiceHost, serve},
        telemetry::{Telemetry, TelemetryConfig},
    };
    use std::{
        io::{BufRead, BufReader, Write},
        net::SocketAddr,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::Arc,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;

    const CANARY_IIN: &str = "900101300123";
    const CANARY_PATH: &str = "/home/CANARY-user/docs/secret.pdf";
    const CANARY_ITEM: &str = "item-CANARY-42";
    const CANARY_DOC: &str = "doc-CANARY-name";
    const CANARY_KEY: &str = "key-CANARY-9c1d";
    const CANARY_ACTOR: &str = "actor-CANARY-7f3a";
    const CANARY_TSA_PATH: &str = "tsa-CANARY-endpoint";
    const CANARY_BAD_BEARER: &str = "CANARY-bad-bearer-5b2e";
    const INLINE_PASSWORD: &str = "inline-CANARY-p4ssw0rd";
    const OPERATOR_PASSWORD: &str = "operator-CANARY-held-pw";
    const COLLECTOR_HEADER: &str = "x-collector-key";
    const COLLECTOR_SECRET: &str = "collector-secret-CANARY-8d1f";

    fn enabled(collector: &Collector) -> TelemetryConfig {
        TelemetryConfig {
            enabled: true,
            endpoint: collector.url(),
            service_name: "oncl-test".into(),
            headers: [(COLLECTOR_HEADER.to_owned(), COLLECTOR_SECRET.to_owned())].into(),
            export_interval_ms: 100,
            export_timeout_ms: 500,
            connect_timeout_ms: 300,
            shutdown_timeout_ms: 2_000,
            ..TelemetryConfig::default()
        }
    }
    /// A port nothing listens on: connections are refused.
    fn closed_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    struct Rig {
        address: SocketAddr,
        host: Arc<ServiceHost>,
        admin: Zeroizing<String>,
        weak: Zeroizing<String>,
        task: tokio::task::JoinHandle<std::io::Result<()>>,
        stop: tokio::sync::oneshot::Sender<()>,
        _directory: tempfile::TempDir,
        _pki: Pki,
    }
    impl Rig {
        /// `unreachable_tsa`: the TSA is a closed loopback port (a network failure).
        async fn start(telemetry: TelemetryConfig, unreachable_tsa: bool) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let operator_path = directory.path().join("operator");
            let operator = PrivateDirectory::create(&operator_path).unwrap();
            let pki = Pki::start();
            let leaf = pki.leaf("user-rsa-sign");
            operator
                .create_file("key.p12")
                .unwrap()
                .write_all(&collector::pki::container(&leaf, OPERATOR_PASSWORD))
                .unwrap();
            operator
                .create_file("password")
                .unwrap()
                .write_all(OPERATOR_PASSWORD.as_bytes())
                .unwrap();
            let (admin, weak) = (
                TokenSecret::generate().unwrap(),
                TokenSecret::generate().unwrap(),
            );
            let mut config = ServerConfig {
                enabled: true,
                audit_directory: directory.path().join("audit"),
                scratch_directory: directory.path().join("scratch"),
                metadata_bytes: 67_108_864,
                inline_pkcs12: true,
                telemetry,
                pki: pki.config(directory.path()),
                ..ServerConfig::default()
            };
            config.tokens = vec![
                TokenConfig {
                    id: CANARY_ACTOR.into(),
                    verifier: admin.verifier().encoded(),
                    actions: vec![Permission::Hash, Permission::Sign, Permission::Batch],
                    keys: vec![CANARY_KEY.into()],
                    inline_pkcs12: true,
                    metadata_aliases: vec![],
                },
                TokenConfig {
                    id: "weak".into(),
                    verifier: weak.verifier().encoded(),
                    actions: vec![Permission::Hash],
                    keys: vec![],
                    inline_pkcs12: false,
                    metadata_aliases: vec![],
                },
            ];
            config.keys = vec![KeyConfig::File {
                name: CANARY_KEY.into(),
                path: operator_path.join("key.p12"),
                alias: Some(leaf.alias.clone()),
                secret: SecretMount {
                    directory: operator_path.clone(),
                    name: "password".into(),
                },
            }];
            if unreachable_tsa {
                let port = closed_port();
                let origin = format!("http://127.0.0.1:{port}");
                config.pki.endpoints.push(PkiEndpoint {
                    origin: origin.clone(),
                    addresses: vec![SocketAddr::from(([127, 0, 0, 1], port))],
                });
                config.pki.tsa.as_mut().unwrap().url = format!("{origin}/{CANARY_TSA_PATH}");
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let host = ServiceHost::new(config)
                .unwrap()
                .for_listener(address)
                .unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let served = host.clone();
            let task = tokio::spawn(async move {
                serve(listener, served, None, async {
                    let _ = stopped.await;
                })
                .await
            });
            Self {
                address,
                host,
                admin: admin.bearer(),
                weak: weak.bearer(),
                task,
                stop,
                _directory: directory,
                _pki: pki,
            }
        }
        async fn post(
            &self,
            token: &str,
            path: &str,
            body: Vec<u8>,
            content_type: &str,
        ) -> (u16, Vec<u8>) {
            collector::post(self.address, token, path, body, content_type).await
        }
        async fn stop(self) -> Arc<ServiceHost> {
            let _ = self.stop.send(());
            self.task.await.unwrap().unwrap();
            self.host
        }
    }

    fn multipart(metadata: &str, parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"metadata\"\r\n\r\n{metadata}\r\n"
        )
        .into_bytes();
        for (name, filename, bytes) in parts {
            let file = filename
                .map(|f| format!("; filename=\"{f}\""))
                .unwrap_or_default();
            body.extend_from_slice(
                format!("--b\r\nContent-Disposition: form-data; name=\"{name}\"{file}\r\n\r\n")
                    .as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"--b--\r\n");
        body
    }
    const FORM: &str = "multipart/form-data; boundary=b";
    fn sign_named_metadata(profile: &str) -> String {
        format!(
            r#"{{"items":[{{"id":"{CANARY_ITEM}","operation":{{"kind":"sign","profile":"{profile}","input":"{CANARY_DOC}","keys":[{{"source":"named","name":"{CANARY_KEY}"}}]}}}}],"parts":[{{"name":"{CANARY_DOC}","item_id":"{CANARY_ITEM}","role":"document"}}]}}"#
        )
    }
    fn document() -> Vec<u8> {
        format!("citizen IIN {CANARY_IIN} signs contract").into_bytes()
    }
    /// `status` of the terminal event of a streamed (multipart/mixed) response.
    fn final_status(body: &[u8]) -> String {
        let text = String::from_utf8_lossy(body);
        let at = text.rfind("\"status\":\"").expect("terminal event");
        text[at + 10..].split('"').next().unwrap().to_owned()
    }
    /// HTTP status and terminal status of one named-key signing request.
    async fn sign_named(rig: &Rig, token: &str, profile: &str) -> (u16, String) {
        let body = multipart(
            &sign_named_metadata(profile),
            &[(CANARY_DOC, Some(CANARY_PATH), &document())],
        );
        let (status, response) = rig.post(token, "/v1/operations", body, FORM).await;
        let terminal = if status == 200 {
            final_status(&response)
        } else {
            String::new()
        };
        (status, terminal)
    }
    async fn hash(rig: &Rig) -> u16 {
        rig.post(
            &rig.admin,
            "/v1/hash",
            document(),
            "application/octet-stream",
        )
        .await
        .0
    }
    fn begin_records(host: &ServiceHost) -> usize {
        host.audit
            .records()
            .unwrap()
            .iter()
            .filter(|r| r.kind == RecordKind::Begin)
            .count()
    }

    fn canaries(rig: &Rig) -> Vec<Vec<u8>> {
        let mut list: Vec<Vec<u8>> = [
            CANARY_IIN,
            CANARY_PATH,
            "CANARY-user",
            "secret.pdf",
            CANARY_ITEM,
            CANARY_DOC,
            CANARY_KEY,
            CANARY_ACTOR,
            CANARY_TSA_PATH,
            CANARY_BAD_BEARER,
            INLINE_PASSWORD,
            OPERATOR_PASSWORD,
            "CANARY",
            "citizen",
            "signs contract",
            rig.admin.as_str(),
            rig.weak.as_str(),
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        list.push(rig.address.to_string().into_bytes());
        list
    }
    fn refs(list: &[Vec<u8>]) -> Vec<&[u8]> {
        list.iter().map(Vec::as_slice).collect()
    }
    fn without_credential(received: &[collector::Received]) -> Vec<collector::Received> {
        received
            .iter()
            .cloned()
            .map(|mut r| {
                r.headers.retain(|(k, _)| k != COLLECTOR_HEADER);
                r
            })
            .collect()
    }
    fn attr<'a>(span: &'a collector::SpanFact, key: &str) -> Option<&'a str> {
        span.attributes.get(key).map(String::as_str)
    }

    /// Real requests (hash, JSON operations, named and inline signing, blocked policy,
    /// bad bearer, malformed body, unreachable TSA) carrying canary values; every
    /// received protobuf payload is decoded and scanned.
    #[test]
    fn no_sensitive_attributes() {
        let collector = Collector::start();
        let runtime = server_support::runtime();
        let (rig, tsa_failure) = runtime.block_on(async {
            let rig = Rig::start(enabled(&collector), true).await;
            assert_eq!(hash(&rig).await, 200);
            let json = format!(
                r#"{{"metadata":{{"items":[{{"id":"{CANARY_ITEM}","operation":{{"kind":"hash","algorithm":"sha256","input":"{CANARY_DOC}"}}}}],"parts":[{{"name":"{CANARY_DOC}","item_id":"{CANARY_ITEM}","role":"document"}}]}},"documents":{{"{CANARY_DOC}":"{CANARY_IIN}"}}}}"#
            );
            let (status, _) = rig
                .post(&rig.admin, "/v1/operations", json.into_bytes(), "application/json")
                .await;
            assert_eq!(status, 200);
            assert_eq!(
                sign_named(&rig, &rig.admin, "cms").await,
                (200, "completed".into())
            );
            // Inline PKCS#12 + password secret parts (real secret bytes).
            let leaf = rig._pki.leaf("user-rsa-sign");
            let p12 = collector::pki::container(&leaf, INLINE_PASSWORD);
            let metadata = format!(
                r#"{{"items":[{{"id":"{CANARY_ITEM}","operation":{{"kind":"sign","profile":"cms","input":"{CANARY_DOC}","keys":[{{"source":"inline","container":"p12","password":"pw"}}]}}}}],"parts":[{{"name":"p12","item_id":"{CANARY_ITEM}","role":"secret"}},{{"name":"pw","item_id":"{CANARY_ITEM}","role":"secret"}},{{"name":"{CANARY_DOC}","item_id":"{CANARY_ITEM}","role":"document"}}]}}"#
            );
            let body = multipart(
                &metadata,
                &[
                    ("p12", None, &p12),
                    ("pw", None, INLINE_PASSWORD.as_bytes()),
                    (CANARY_DOC, Some(CANARY_PATH), &document()),
                ],
            );
            let (status, response) = rig.post(&rig.admin, "/v1/operations", body, FORM).await;
            assert_eq!((status, final_status(&response)), (200, "completed".into()));
            // Blocked by policy: the weak token has no sign right.
            assert_eq!(sign_named(&rig, &rig.weak, "cms").await.0, 403);
            // Unknown bearer and malformed body.
            let (status, _) = rig
                .post(
                    CANARY_BAD_BEARER,
                    "/v1/hash",
                    document(),
                    "application/octet-stream",
                )
                .await;
            assert_eq!(status, 403);
            let (status, _) = rig
                .post(
                    &rig.admin,
                    "/v1/operations",
                    format!("{{\"{CANARY_IIN}\":").into_bytes(),
                    "application/json",
                )
                .await;
            assert_eq!(status, 400);
            // Network failure: the TSA is a closed port; the item fails honestly.
            let tsa_failure = sign_named(&rig, &rig.admin, "cades_t").await;
            (rig, tsa_failure)
        });
        assert_eq!(tsa_failure.0, 200);
        assert_eq!(tsa_failure.1, "failed", "unreachable TSA fails the item");
        assert_eq!(rig.host.audit.health(), AuditHealth::Healthy);
        let list = canaries(&rig);
        let host = runtime.block_on(rig.stop());
        assert_eq!(host.telemetry.stats().spans_dropped, 0);
        let received = collector.received();
        assert!(received.iter().any(|r| r.path == "/v1/traces"));
        assert!(received.iter().any(|r| r.path == "/v1/metrics"));
        // The operator's collector credential is the one configured value on the wire,
        // as a header; never in any payload.
        assert!(received.iter().all(|r| {
            r.headers
                .iter()
                .any(|(k, v)| k == COLLECTOR_HEADER && v == COLLECTOR_SECRET)
        }));
        let facts = collector::assert_private(&without_credential(&received), &refs(&list));
        for payload in &received {
            assert!(
                !payload
                    .body
                    .windows(COLLECTOR_SECRET.len())
                    .any(|w| w == COLLECTOR_SECRET.as_bytes()),
                "the collector credential is a header, never payload"
            );
        }
        assert_eq!(
            facts
                .resource_keys
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec!["service.name", "service.version"]
        );

        // Event types actually exported.
        let requests = |route: &str, outcome: &str| {
            facts
                .spans_named("oncl.request")
                .filter(|s| {
                    attr(s, "oncl.route") == Some(route) && attr(s, "oncl.outcome") == Some(outcome)
                })
                .count()
        };
        assert_eq!(requests("hash", "ok"), 1, "{:?}", facts.spans);
        assert_eq!(
            requests("operations", "ok"),
            3,
            "hash + named + inline sign"
        );
        assert_eq!(requests("operations", "failed"), 1, "unreachable TSA");
        // Blocked policy + bad bearer both end as a rejected 403 with a stable code.
        let denied: Vec<_> = facts
            .spans_named("oncl.request")
            .filter(|s| attr(s, "oncl.error.code") == Some("permission_denied"))
            .collect();
        assert_eq!(denied.len(), 2);
        assert!(denied.iter().all(|s| {
            s.errored
                && attr(s, "http.response.status_code") == Some("403")
                && attr(s, "oncl.outcome") == Some("rejected")
        }));
        let signs: Vec<_> = facts
            .spans_named("oncl.operation")
            .filter(|s| {
                attr(s, "oncl.operation.kind") == Some("sign")
                    && attr(s, "oncl.outcome") == Some("ok")
            })
            .collect();
        assert_eq!(signs.len(), 2, "named + inline signing: {:?}", facts.spans);
        assert!(signs.iter().all(|s| {
            attr(s, "oncl.key.applied") == Some("applied")
                && attr(s, "oncl.operation.family") == Some("cms")
        }));
        let failed: Vec<_> = facts
            .spans_named("oncl.operation")
            .filter(|s| attr(s, "oncl.outcome") == Some("failed"))
            .collect();
        assert_eq!(failed.len(), 1, "{:?}", facts.spans);
        assert_eq!(attr(failed[0], "oncl.operation.family"), Some("cades"));
        assert!(failed[0].errored);
        assert!(attr(failed[0], "oncl.error.code").is_some());
        for name in [
            "oncl.admission",
            "oncl.executor.wait",
            "oncl.executor.run",
            "oncl.delivery",
        ] {
            assert!(
                facts.spans_named(name).next().is_some(),
                "missing {name} span"
            );
        }
        // Trace structure: every child belongs to a request span of the same trace.
        let roots: Vec<_> = facts.spans_named("oncl.request").collect();
        for span in facts.spans.iter().filter(|s| s.name != "oncl.request") {
            assert!(
                roots
                    .iter()
                    .any(|r| r.trace_id == span.trace_id && r.span_id == span.parent),
                "orphan {} span",
                span.name
            );
        }
        assert!(roots.iter().all(|r| r.parent.is_empty()));
        // Metrics: counts only, with the closed dimensions.
        assert_eq!(
            facts.metric_total("oncl.requests", &[("oncl.route", "operations")]),
            6.0
        );
        // Named + inline + the CAdES-T item whose key was applied before the TSA failed:
        // a failure after application is counted as applied, never as "not used".
        assert_eq!(
            facts.metric_total(
                "oncl.key.uses",
                &[
                    ("oncl.operation.kind", "sign"),
                    ("oncl.key.applied", "applied")
                ]
            ),
            3.0
        );
        assert_eq!(attr(failed[0], "oncl.key.applied"), Some("applied"));
        assert_eq!(
            facts.metric_total("oncl.operations", &[("oncl.outcome", "failed")]),
            1.0
        );
        assert_eq!(facts.metric_total("oncl.telemetry.dropped", &[]), 0.0);
        // Audit is a separate, complete record of every key use.
        assert_eq!(
            begin_records(&host),
            3,
            "named + inline + the TSA-failed sign each recorded before the key was used"
        );
    }

    /// The scanner is not a tautology: a payload that carries a canary fails it.
    #[test]
    #[should_panic(expected = "leaked")]
    fn scanner_detects_a_leaked_canary() {
        collector::assert_private(
            &[tampered("oncl.route", &format!("path {CANARY_PATH}"))],
            &[CANARY_PATH.as_bytes()],
        );
    }

    /// Same payload without a byte-level canary but a value outside the vocabulary.
    #[test]
    #[should_panic(expected = "attribute value")]
    fn scanner_rejects_values_outside_the_vocabulary() {
        collector::assert_private(&[tampered("oncl.route", "some-new-free-text")], &[]);
    }

    #[test]
    #[should_panic(expected = "attribute key")]
    fn scanner_rejects_unknown_attribute_keys() {
        collector::assert_private(&[tampered("client.id", "hash")], &[]);
    }
    fn tampered(key: &str, value: &str) -> collector::Received {
        use opentelemetry_proto::tonic::{
            collector::trace::v1::ExportTraceServiceRequest,
            common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value::Value},
            trace::v1::{ResourceSpans, ScopeSpans, Span},
        };
        use prost::Message;
        let span = Span {
            name: "oncl.request".into(),
            attributes: vec![KeyValue {
                key: key.into(),
                value: Some(AnyValue {
                    value: Some(Value::StringValue(value.into())),
                }),
                ..Default::default()
            }],
            ..Span::default()
        };
        let body = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "oncl-server".into(),
                        ..Default::default()
                    }),
                    spans: vec![span],
                    ..ScopeSpans::default()
                }],
                ..ResourceSpans::default()
            }],
        }
        .encode_to_vec();
        collector::Received {
            path: "/v1/traces".into(),
            headers: vec![("content-type".into(), "application/x-protobuf".into())],
            body,
        }
    }

    /// Collector refusing, hanging and then healthy again: operations (including key
    /// use with a writable audit) keep their latency, the queue stays bounded, drops are
    /// counted and later exposed as a metric, and shutdown honors its deadline.
    #[test]
    fn collector_down_is_bounded_and_nonblocking() {
        let runtime = server_support::runtime();
        // Refused: nothing listens at all.
        {
            let down = Collector::start();
            let mut config = enabled(&down);
            down.stop();
            config.export_timeout_ms = 2_000;
            runtime.block_on(async {
                let rig = Rig::start(config, false).await;
                for _ in 0..8 {
                    let started = Instant::now();
                    assert_eq!(hash(&rig).await, 200);
                    assert!(started.elapsed() < Duration::from_millis(750));
                }
                assert_eq!(
                    sign_named(&rig, &rig.admin, "cms").await,
                    (200, "completed".into())
                );
                let telemetry = rig.host.telemetry.clone();
                wait_until("refused exports counted", || {
                    telemetry.stats().span_export_failures >= 1
                        && telemetry.stats().metric_export_failures >= 1
                });
                let stats = telemetry.stats();
                assert!(stats.spans_dropped >= 1, "{stats:?}");
                assert!(stats.span_queue_len <= stats.span_queue_capacity);
                assert_eq!(rig.host.audit.health(), AuditHealth::Healthy);
                assert_eq!(begin_records(&rig.host), 1);
                let _ = rig.stop().await;
            });
        }
        // Hanging: connections are accepted, requests read, never answered; exports
        // block for the full HTTP timeout (2s), far longer than any operation.
        let hanging = Collector::start();
        hanging.set_mode(Mode::Hang);
        let mut config = enabled(&hanging);
        config.queue_size = 16;
        config.batch_size = 4;
        config.export_timeout_ms = 2_000;
        config.connect_timeout_ms = 500;
        config.shutdown_timeout_ms = 1_000;
        runtime.block_on(async {
            let rig = Rig::start(config, false).await;
            let mut slowest = Duration::ZERO;
            let mut deepest = 0;
            for _ in 0..60 {
                let started = Instant::now();
                assert_eq!(hash(&rig).await, 200);
                slowest = slowest.max(started.elapsed());
                deepest = deepest.max(rig.host.telemetry.stats().span_queue_len);
            }
            for _ in 0..3 {
                let started = Instant::now();
                assert_eq!(
                    sign_named(&rig, &rig.admin, "cms").await,
                    (200, "completed".into())
                );
                slowest = slowest.max(started.elapsed());
            }
            assert!(
                slowest < Duration::from_secs(1),
                "operations waited on telemetry: slowest {slowest:?} (HTTP timeout is 2s)"
            );
            let stats = rig.host.telemetry.stats();
            assert!(
                deepest <= stats.span_queue_capacity,
                "queue unbounded: {deepest}"
            );
            assert!(stats.spans_dropped > 0, "the queue overflowed: {stats:?}");
            assert_eq!(rig.host.audit.health(), AuditHealth::Healthy);
            assert_eq!(
                begin_records(&rig.host),
                3,
                "every key use has its audit record"
            );
            // Recovery: once the collector answers again the drop counter is exported
            // as a metric, so the loss is observable, not silent.
            let dropped = rig.host.telemetry.stats().spans_dropped;
            hanging.set_mode(Mode::Accept);
            hanging.wait_for("the drop metric", Duration::from_secs(20), |received| {
                collector::decode(received)
                    .metric_total("oncl.telemetry.dropped", &[("oncl.signal", "spans")])
                    >= dropped as f64
            });
            // Hang again: shutdown stays inside its 1s deadline although the final
            // export would take 2s.
            hanging.set_mode(Mode::Hang);
            for _ in 0..4 {
                assert_eq!(hash(&rig).await, 200);
            }
            let telemetry = rig.host.telemetry.clone();
            let started = Instant::now();
            let finished = tokio::task::spawn_blocking(move || telemetry.shutdown())
                .await
                .unwrap();
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(1_800),
                "shutdown took {elapsed:?}"
            );
            assert!(!finished || elapsed < Duration::from_millis(1_000));
            let started = Instant::now();
            let _ = rig.stop().await;
            assert!(started.elapsed() < Duration::from_millis(1_500));
        });
    }

    /// Trace sampling never removes a mandatory audit record; ratio 0 exports no span
    /// while the metrics count every operation and the audit keeps every key use.
    #[test]
    fn sampling_never_drops_audit_records() {
        let collector = Collector::start();
        let mut config = enabled(&collector);
        config.trace_sample_ratio = 0.0;
        let runtime = server_support::runtime();
        let host = runtime.block_on(async {
            let rig = Rig::start(config, false).await;
            for _ in 0..3 {
                assert_eq!(
                    sign_named(&rig, &rig.admin, "cms").await,
                    (200, "completed".into())
                );
            }
            rig.stop().await
        });
        let received = collector.received();
        let facts = collector::assert_private(&without_credential(&received), &[]);
        assert!(facts.spans.is_empty(), "ratio 0 exports no span");
        assert_eq!(
            facts.metric_total("oncl.key.uses", &[("oncl.key.applied", "applied")]),
            3.0
        );
        let records = host.audit.records().unwrap();
        assert_eq!(
            records
                .iter()
                .filter(|r| r.kind == RecordKind::Begin)
                .count(),
            3
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.kind == RecordKind::Final)
                .count(),
            3
        );
        assert_eq!(host.audit.health(), AuditHealth::Healthy);
    }

    /// `/v1/batch` (the SDK's closed batch): items are counted by closed kind/outcome and
    /// key use, the request is a `batch` route, and nothing about the items' identities,
    /// names or sources is exported.
    #[test]
    fn batch_items_are_counted_without_identity() {
        let collector = Collector::start();
        let runtime = server_support::runtime();
        let metadata = format!(
            r#"{{"items":[{{"id":"{CANARY_ITEM}-1","operation":{{"kind":"hash","algorithm":"sha256","input":"{CANARY_DOC}-1"}}}},{{"id":"{CANARY_ITEM}-2","operation":{{"kind":"sign","profile":"cms","input":"{CANARY_DOC}-2","keys":[{{"source":"named","name":"{CANARY_KEY}"}}]}}}}],"parts":[{{"name":"{CANARY_DOC}-1","item_id":"{CANARY_ITEM}-1","role":"document"}},{{"name":"{CANARY_DOC}-2","item_id":"{CANARY_ITEM}-2","role":"document"}}]}}"#
        );
        let body = multipart(
            &metadata,
            &[
                (&format!("{CANARY_DOC}-1"), Some(CANARY_PATH), &document()),
                (&format!("{CANARY_DOC}-2"), Some(CANARY_PATH), &document()),
            ],
        );
        let (rig, status, response) = runtime.block_on(async {
            let rig = Rig::start(enabled(&collector), false).await;
            let (status, response) = rig.post(&rig.admin, "/v1/batch", body, FORM).await;
            (rig, status, response)
        });
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&response));
        assert_eq!(final_status(&response), "completed");
        let list = canaries(&rig);
        let host = runtime.block_on(rig.stop());
        let facts =
            collector::assert_private(&without_credential(&collector.received()), &refs(&list));
        assert!(
            facts
                .spans_named("oncl.request")
                .any(|s| attr(s, "oncl.route") == Some("batch")
                    && attr(s, "oncl.outcome") == Some("ok")),
            "{:?}",
            facts.spans
        );
        assert_eq!(
            facts.metric_total(
                "oncl.operations",
                &[("oncl.operation.kind", "hash"), ("oncl.outcome", "ok")]
            ),
            1.0
        );
        assert_eq!(
            facts.metric_total(
                "oncl.operations",
                &[("oncl.operation.kind", "sign"), ("oncl.outcome", "ok")]
            ),
            1.0
        );
        assert_eq!(
            facts.metric_total("oncl.key.uses", &[("oncl.key.applied", "applied")]),
            1.0
        );
        assert_eq!(begin_records(&host), 1);
    }

    #[test]
    fn disabled_is_the_default_and_unsafe_configuration_is_refused() {
        let default = ServerConfig::default().telemetry;
        assert!(!default.enabled);
        default.validate().unwrap();
        let handle = Telemetry::start(&default).unwrap();
        assert!(!handle.is_enabled());
        assert_eq!(handle.stats().export_threads, 0);
        assert!(handle.shutdown());
        let toml = read_config("").unwrap();
        assert!(!toml.telemetry.enabled);
        let mut ok = TelemetryConfig {
            enabled: true,
            endpoint: "http://127.0.0.1:4318".into(),
            ..TelemetryConfig::default()
        };
        ok.validate().unwrap();
        for mutate in [
            (|c: &mut TelemetryConfig| c.endpoint = "ftp://collector".into()) as fn(&mut _),
            |c| c.endpoint = "http://user:pw@collector:4318".into(),
            |c| c.endpoint = "http://collector:4318/?token=x".into(),
            |c| c.endpoint = String::new(),
            |c| {
                c.metrics = false;
                c.traces = false;
            },
            |c| c.trace_sample_ratio = 1.5,
            |c| c.queue_size = 0,
            |c| c.batch_size = c.queue_size + 1,
            |c| c.export_timeout_ms = 0,
            |c| c.shutdown_timeout_ms = 3_600_000,
            |c| {
                c.headers.insert("content-type".into(), "text/plain".into());
            },
            |c| {
                c.headers.insert("x-ok".into(), "line\r\nbreak".into());
            },
            |c| c.service_name = "a b".into(),
        ] {
            let mut bad = ok.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err());
        }
        ok.metrics = false;
        ok.validate().unwrap();
        // A configuration that is invalid while enabled is rejected by the server.
        let mut config = ServerConfig::default();
        config.telemetry.enabled = true;
        assert!(config.validate().is_err());
        assert!(
            read_config(
                "[telemetry]\nenabled = true\nendpoint = 'http://127.0.0.1:1'\nunknown = 1\n"
            )
            .is_err()
        );
        let parsed = read_config(
            "[telemetry]\nenabled = true\nendpoint = 'https://collector.example:4318/otlp'\ntrace_sample_ratio = 0.25\nheaders = { authorization = 'Bearer x' }\n",
        )
        .unwrap()
        .telemetry;
        assert!(parsed.enabled && parsed.metrics && parsed.traces);
        assert_eq!(parsed.trace_sample_ratio, 0.25);
        assert_eq!(parsed.headers.len(), 1);
    }
    fn read_config(extra: &str) -> std::io::Result<ServerConfig> {
        let directory = tempfile::tempdir().unwrap();
        let operator = PrivateDirectory::create(&directory.path().join("operator")).unwrap();
        operator
            .create_file("server.toml")
            .unwrap()
            .write_all(format!("audit_directory = 'x'\n{extra}").as_bytes())
            .unwrap();
        ServerConfig::read(&directory.path().join("operator").join("server.toml"))
    }

    // ---- real process ---------------------------------------------------------------

    /// Names of all threads of process `pid` (empty string: unnamed).
    #[cfg(windows)]
    fn thread_names(pid: u32) -> Vec<String> {
        use windows_sys::Win32::{
            Foundation::{CloseHandle, LocalFree},
            System::{
                Diagnostics::ToolHelp::{
                    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
                Threading::{GetThreadDescription, OpenThread, THREAD_QUERY_LIMITED_INFORMATION},
            },
        };
        let mut names = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut more = Thread32First(snapshot, &mut entry);
            while more != 0 {
                if entry.th32OwnerProcessID == pid {
                    let mut name = String::new();
                    let handle =
                        OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, entry.th32ThreadID);
                    if !handle.is_null() {
                        let mut text: *mut u16 = std::ptr::null_mut();
                        if GetThreadDescription(handle, &mut text) >= 0 && !text.is_null() {
                            let mut len = 0;
                            while *text.add(len) != 0 {
                                len += 1;
                            }
                            name = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
                            LocalFree(text.cast());
                        }
                        CloseHandle(handle);
                    }
                    names.push(name);
                }
                more = Thread32Next(snapshot, &mut entry);
            }
            CloseHandle(snapshot);
        }
        names.sort();
        names
    }
    #[cfg(unix)]
    fn thread_names(pid: u32) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .map(|task| {
                std::fs::read_to_string(task.unwrap().path().join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            })
            .collect();
        names.sort();
        names
    }

    struct Proc {
        child: Child,
        address: SocketAddr,
        admin: Zeroizing<String>,
        weak: Zeroizing<String>,
        config_path: PathBuf,
        _directory: tempfile::TempDir,
        _pki: Pki,
    }
    fn toml_str(path: &Path) -> String {
        server_support::toml_path(path)
    }
    impl Proc {
        fn start(telemetry: &str, unreachable_tsa: bool) -> Self {
            Self::start_env(telemetry, unreachable_tsa, &[])
        }
        /// `telemetry`: the verbatim `[telemetry]` table text (empty: no table).
        fn start_env(telemetry: &str, unreachable_tsa: bool, envs: &[(&str, &str)]) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let operator_path = directory.path().join("operator");
            let operator = PrivateDirectory::create(&operator_path).unwrap();
            let pki = Pki::start();
            let leaf = pki.leaf("user-rsa-sign");
            operator
                .create_file("key.p12")
                .unwrap()
                .write_all(&collector::pki::container(&leaf, OPERATOR_PASSWORD))
                .unwrap();
            operator
                .create_file("password")
                .unwrap()
                .write_all(OPERATOR_PASSWORD.as_bytes())
                .unwrap();
            let mut tokens = Vec::new();
            for name in ["admin", "weak"] {
                let output = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
                    .args(["token-create", "--directory"])
                    .arg(&operator_path)
                    .args(["--name", name])
                    .output()
                    .unwrap();
                assert!(output.status.success(), "token-create refused");
                let stdout = String::from_utf8(output.stdout).unwrap();
                let verifier = stdout.trim().strip_prefix("verifier=").unwrap().to_owned();
                let bearer = std::fs::read_to_string(operator_path.join(name)).unwrap();
                tokens.push((verifier, Zeroizing::new(bearer)));
            }
            let inter = directory.path().join("inter.cer");
            let config_pki = pki.config(directory.path());
            let (origin, address) = (pki.origin.clone(), pki.address);
            let (tsa_origin, tsa_address) = if unreachable_tsa {
                let port = closed_port();
                (
                    format!("http://127.0.0.1:{port}"),
                    format!("127.0.0.1:{port}"),
                )
            } else {
                (origin.clone(), address.to_string())
            };
            let config = format!(
                "enabled = true\nbind = '127.0.0.1:0'\naudit_directory = {audit}\nscratch_directory = {scratch}\nmetadata_bytes = 67108864\n\n{telemetry}\n\n[pki]\nanchors = [{anchor}]\nintermediates = [{inter}]\n\n[[pki.endpoints]]\norigin = '{origin}'\naddresses = ['{address}']\n\n[[pki.endpoints]]\norigin = '{tsa_origin}'\naddresses = ['{tsa_address}']\n\n[pki.tsa]\nurl = '{tsa_origin}/{CANARY_TSA_PATH}'\npolicy = '1.2.3.4.5'\ntimeout_ms = 1000\n\n[[tokens]]\nid = '{CANARY_ACTOR}'\nverifier = '{admin}'\nactions = ['hash', 'sign']\nkeys = ['{CANARY_KEY}']\n\n[[tokens]]\nid = 'weak'\nverifier = '{weak}'\nactions = ['hash']\n\n[[keys]]\nsource = 'file'\nname = '{CANARY_KEY}'\npath = {key}\nalias = '{alias}'\nsecret = {{ directory = {operator}, name = 'password' }}\n",
                audit = toml_str(&directory.path().join("audit")),
                scratch = toml_str(&directory.path().join("scratch")),
                anchor = toml_str(&config_pki.anchors[0]),
                inter = toml_str(&inter),
                admin = tokens[0].0,
                weak = tokens[1].0,
                key = toml_str(&operator_path.join("key.p12")),
                alias = leaf.alias,
                operator = toml_str(&operator_path),
            );
            operator
                .create_file("server.toml")
                .unwrap()
                .write_all(config.as_bytes())
                .unwrap();
            let config_path = operator_path.join("server.toml");
            let mut child = Command::new(env!("CARGO_BIN_EXE_oncl-server"))
                .args(["serve", "--config"])
                .arg(&config_path)
                .arg("--shutdown-stdin")
                .envs(envs.iter().copied())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.as_mut().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.starts_with("listening "), "startup refused: {line:?}");
            let address: SocketAddr = line
                .trim()
                .strip_prefix("listening ")
                .unwrap()
                .parse()
                .unwrap();
            let [admin, weak]: [_; 2] = tokens
                .into_iter()
                .map(|t| t.1)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            Self {
                child,
                address,
                admin,
                weak,
                config_path,
                _directory: directory,
                _pki: pki,
            }
        }
        fn threads(&self) -> Vec<String> {
            thread_names(self.child.id())
        }
        async fn sign(&self, token: &str, profile: &str) -> (u16, String) {
            let body = multipart(
                &sign_named_metadata(profile),
                &[(CANARY_DOC, Some(CANARY_PATH), &document())],
            );
            let (status, response) =
                collector::post(self.address, token, "/v1/operations", body, FORM).await;
            let terminal = if status == 200 {
                final_status(&response)
            } else {
                String::new()
            };
            (status, terminal)
        }
        /// Graceful stop through the control pipe; returns the time it took.
        fn stop(mut self) -> Duration {
            let started = Instant::now();
            self.child.stdin.take().unwrap().write_all(b"\n").unwrap();
            let deadline = started + Duration::from_secs(30);
            let status = loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "server did not stop");
                std::thread::sleep(Duration::from_millis(20));
            };
            let elapsed = started.elapsed();
            assert!(status.success());
            let mut out = String::new();
            std::io::Read::read_to_string(self.child.stdout.as_mut().unwrap(), &mut out).unwrap();
            assert_eq!(out.trim(), "stopped: owned listener and workers released");
            let mut err = String::new();
            std::io::Read::read_to_string(self.child.stderr.as_mut().unwrap(), &mut err).unwrap();
            assert!(err.is_empty(), "unexpected stderr: {err}");
            let config = ServerConfig::read(&self.config_path).unwrap();
            let journal = DurableAuditGuard::open(
                AuditConfig::new(
                    config.audit_directory,
                    config.audit_segment_bytes,
                    config.audit_quota_bytes,
                    32,
                    2,
                )
                .unwrap(),
            )
            .unwrap();
            journal.recover().unwrap();
            assert_eq!(journal.health(), AuditHealth::Healthy);
            elapsed
        }
    }
    impl Drop for Proc {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
    fn table(collector: &Collector, extra: &str) -> String {
        format!(
            "[telemetry]\nenabled = true\nendpoint = '{}'\nexport_interval_ms = 100\nexport_timeout_ms = 500\nconnect_timeout_ms = 300\nshutdown_timeout_ms = 2000\n{extra}",
            collector.url()
        )
    }

    /// The process environment is not telemetry configuration: `OTEL_*` endpoints/headers
    /// and proxy variables neither redirect the export nor add a header to it.
    #[test]
    fn environment_cannot_redirect_or_extend_export() {
        let collector = Collector::start();
        let decoy = Collector::start();
        let runtime = server_support::runtime();
        let (url, address) = (decoy.url(), decoy.address.to_string());
        let process = Proc::start_env(
            &table(&collector, ""),
            false,
            &[
                ("OTEL_EXPORTER_OTLP_ENDPOINT", &url),
                (
                    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    &format!("{url}/v1/traces"),
                ),
                (
                    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
                    &format!("{url}/v1/metrics"),
                ),
                ("OTEL_EXPORTER_OTLP_HEADERS", "x-evil=1"),
                ("OTEL_EXPORTER_OTLP_TRACES_HEADERS", "x-evil=1"),
                ("OTEL_EXPORTER_OTLP_METRICS_HEADERS", "x-evil=1"),
                ("OTEL_EXPORTER_OTLP_TIMEOUT", "60000"),
                ("HTTP_PROXY", &address),
                ("http_proxy", &address),
                ("ALL_PROXY", &address),
            ],
        );
        assert_eq!(
            runtime.block_on(process.sign(&process.admin, "cms")),
            (200, "completed".into())
        );
        collector.wait_for("export", Duration::from_secs(10), |r| {
            r.iter().any(|p| p.path == "/v1/traces") && r.iter().any(|p| p.path == "/v1/metrics")
        });
        assert!(collector.received().iter().all(|r| {
            r.headers
                .iter()
                .all(|(k, v)| k != "x-evil" && !v.contains("x-evil"))
        }));
        assert_eq!(decoy.connections(), 0, "the environment redirected nothing");
        let _ = process.stop();
    }

    /// Disabled (absent table or `enabled = false` with an endpoint present): the real
    /// server opens no connection to the collector and starts no export thread, and
    /// still signs. The enabled control proves the receiver and probes can see both.
    #[test]
    fn off_has_no_export_connection() {
        let collector = Collector::start();
        let silent = Collector::start();
        let runtime = server_support::runtime();
        let absent = Proc::start("", false);
        let off = Proc::start(
            &format!(
                "[telemetry]\nenabled = false\nendpoint = '{}'\nexport_interval_ms = 100\n",
                silent.url()
            ),
            false,
        );
        let on = Proc::start(&table(&collector, ""), false);
        // Export threads are named; OS-level loader/pool threads are timing dependent,
        // so the proof is by name: none when off, exactly the named ones when on.
        let exporters = |process: &Proc| -> Vec<String> {
            process
                .threads()
                .into_iter()
                .filter(|n| n.starts_with("oncl-otlp") || n.starts_with("OpenTelemetry"))
                .collect()
        };
        assert_eq!(exporters(&absent), Vec::<String>::new());
        assert_eq!(
            exporters(&off),
            Vec::<String>::new(),
            "disabled starts no thread"
        );
        assert_eq!(
            exporters(&on),
            ["OpenTelemetry.Metrics.PeriodicReader", "oncl-otlp-traces"],
            "enabled: one metric reader and one span worker"
        );
        for (extra, name) in [
            ("traces = false\n", "OpenTelemetry.Metrics.PeriodicReader"),
            ("metrics = false\n", "oncl-otlp-traces"),
        ] {
            let single = Proc::start(&table(&collector, extra), false);
            assert_eq!(exporters(&single), [name], "single-signal export");
        }
        runtime.block_on(async {
            for process in [&absent, &off] {
                assert_eq!(
                    process.sign(&process.admin, "cms").await,
                    (200, "completed".into())
                );
                assert_eq!(process.sign(&process.weak, "cms").await.0, 403);
            }
        });
        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(silent.connections(), 0, "disabled: zero connections");
        assert!(silent.received().is_empty());
        let before = thread_names(off.child.id());
        let (a, b) = (absent.stop(), off.stop());
        assert!(a < Duration::from_secs(5) && b < Duration::from_secs(5));
        assert_eq!(silent.connections(), 0);
        assert!(
            before
                .iter()
                .all(|n| !n.starts_with("oncl-otlp") && !n.starts_with("OpenTelemetry")),
            "{before:?}"
        );
        // Control: the enabled process does connect and deliver.
        runtime.block_on(async {
            assert_eq!(on.sign(&on.admin, "cms").await, (200, "completed".into()));
        });
        collector.wait_for("enabled export", Duration::from_secs(10), |r| {
            r.iter().any(|p| p.path == "/v1/traces") && r.iter().any(|p| p.path == "/v1/metrics")
        });
        assert!(collector.connections() >= 1);
        let _ = on.stop();
    }

    /// Smoke O01: real server process -> test collector. Sign, blocked policy (403) and a
    /// network failure; event types and absence of forbidden values are checked; then the
    /// collector is stopped and an actual operation repeats successfully.
    #[test]
    fn process_smoke() {
        let collector = Collector::start();
        let runtime = server_support::runtime();
        let process = Proc::start(
            &table(
                &collector,
                &format!(
                    "headers = {{ {COLLECTOR_HEADER} = '{COLLECTOR_SECRET}' }}\nservice_name = 'org-70'\n"
                ),
            ),
            true,
        );
        let (signed, blocked, network) = runtime.block_on(async {
            (
                process.sign(&process.admin, "cms").await,
                process.sign(&process.weak, "cms").await,
                process.sign(&process.admin, "cades_t").await,
            )
        });
        assert_eq!(signed, (200, "completed".into()));
        assert_eq!(blocked.0, 403);
        assert_eq!(network, (200, "failed".into()), "TSA connection refused");
        collector.wait_for("spans and metrics", Duration::from_secs(10), |received| {
            let facts = collector::decode(received);
            facts.spans_named("oncl.operation").count() >= 2
                && facts.spans_named("oncl.request").count() >= 3
                && facts.metric_total("oncl.requests", &[]) >= 3.0
        });
        let received = collector.received();
        let facts = collector::assert_private(
            &without_credential(&received),
            &[
                CANARY_IIN.as_bytes(),
                CANARY_PATH.as_bytes(),
                CANARY_ITEM.as_bytes(),
                CANARY_DOC.as_bytes(),
                CANARY_KEY.as_bytes(),
                CANARY_ACTOR.as_bytes(),
                CANARY_TSA_PATH.as_bytes(),
                OPERATOR_PASSWORD.as_bytes(),
                process.admin.as_bytes(),
                process.weak.as_bytes(),
                b"CANARY",
            ],
        );
        let kinds: std::collections::BTreeSet<_> = facts
            .spans_named("oncl.request")
            .map(|s| {
                (
                    attr(s, "oncl.outcome").unwrap().to_owned(),
                    attr(s, "oncl.error.code").unwrap_or("-").to_owned(),
                    attr(s, "http.response.status_code").unwrap().to_owned(),
                )
            })
            .collect();
        assert!(
            kinds.contains(&("ok".into(), "-".into(), "200".into())),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&("rejected".into(), "permission_denied".into(), "403".into())),
            "{kinds:?}"
        );
        assert!(
            kinds.contains(&("failed".into(), "-".into(), "200".into())),
            "{kinds:?}"
        );
        assert!(facts.spans_named("oncl.operation").any(|s| {
            attr(s, "oncl.operation.kind") == Some("sign")
                && attr(s, "oncl.outcome") == Some("failed")
                && attr(s, "oncl.operation.family") == Some("cades")
        }));
        println!("smoke event types before collector stop: {kinds:?}");
        // Collector stops; the same real operation still succeeds, promptly.
        collector.stop();
        let started = Instant::now();
        let again = runtime.block_on(process.sign(&process.admin, "cms"));
        assert_eq!(again, (200, "completed".into()));
        assert!(started.elapsed() < Duration::from_secs(2));
        runtime.block_on(async {
            for _ in 0..3 {
                assert_eq!(process.sign(&process.admin, "cms").await.0, 200);
            }
        });
        let stopped = process.stop();
        assert!(stopped < Duration::from_secs(5), "shutdown {stopped:?}");
        println!("smoke: repeated sign with collector down ok; process stopped in {stopped:?}");
    }

    /// Polls `condition` for a bounded time.
    fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
        let end = Instant::now() + Duration::from_secs(20);
        while !condition() {
            assert!(Instant::now() < end, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
