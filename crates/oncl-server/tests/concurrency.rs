mod server_support;
use oncl_core::{
    Action, Engine, EngineServices, ExecutionGrant, OperationContext, OperationPolicy,
};
use oncl_pki::resource::{ProcessingError, ResourceLimits};
use oncl_server::executor::{BoundedExecutor, Cancellation, ExecutorConfig};
use std::{sync::Arc, time::Duration};

fn engine(cap: u64) -> Arc<Engine> {
    Arc::new(
        Engine::new(EngineServices::hash_only(ResourceLimits {
            max_in_flight: cap,
            memory_bytes: 4096,
            temp_bytes: 4096,
            ..ResourceLimits::default()
        }))
        .unwrap(),
    )
}
fn context(engine: &Engine) -> OperationContext {
    engine
        .begin(
            ExecutionGrant::new([Action::Hash]),
            OperationPolicy::strict_online(),
            Arc::new(Cancellation::new()),
        )
        .unwrap()
}
fn executor() -> BoundedExecutor {
    BoundedExecutor::new(ExecutorConfig {
        blocking_workers: 1,
        queue_capacity: 1,
        admission_wait: Duration::from_secs(2),
    })
    .unwrap()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap()
}
#[test]
fn n_requests_shared_cap() {
    use std::io::{Read, Write};
    let process = server_support::Process::start(
        "max_in_flight = 2\nblocking_workers = 2\nqueue_capacity = 1",
    );
    let mut admitted = Vec::new();
    for _ in 0..2 {
        let mut socket = std::net::TcpStream::connect(process.address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(socket,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",process.address,*process.token).unwrap();
        admitted.push(socket);
    }
    server_support::runtime().block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let (status, _) = server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[],
                None,
            )
            .await;
            if status == 503 {
                break;
            }
            assert_eq!(status, 200);
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        let mut attempts = tokio::task::JoinSet::new();
        for _ in 0..6 {
            let address = process.address;
            let token = process.token.clone();
            attempts.spawn(async move {
                server_support::request(address, &token, "/v1/hash", b"abc", &[], None).await
            });
        }
        while let Some(result) = attempts.join_next().await {
            let (status, body) = result.unwrap();
            assert_eq!(status, 503);
            let error: oncl_api::error::ApiError = serde_json::from_slice(&body).unwrap();
            assert_eq!(error.code, oncl_api::error::ErrorCode::CapacityExceeded);
        }
    });
    for mut socket in admitted {
        socket.write_all(b"c\r\n0\r\n\r\n").unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
    }
    eprintln!("standalone: N=8 with shared max_in_flight=2 admits 2 held streams and refuses 6");
    process.stop();
}
#[test]
fn aggregate_memory_and_temp_cap() {
    let engine = engine(2);
    let mut a = context(&engine);
    let mut b = context(&engine);
    let memory = a.resources().reserve_memory(3000).unwrap();
    let temp = a.resources().reserve_temp(3000).unwrap();
    assert!(matches!(
        b.resources().reserve_memory(1097),
        Err(ProcessingError::MemoryLimit)
    ));
    assert!(matches!(
        b.resources().reserve_temp(1097),
        Err(ProcessingError::TempLimit)
    ));
    drop(a);
    assert!(b.resources().reserve_memory(1097).is_err());
    drop(memory);
    drop(temp);
    assert!(b.resources().reserve_memory(4096).is_ok());
    assert!(b.resources().reserve_temp(4096).is_ok());
}
#[test]
fn cancelled_running_worker_keeps_permit() {
    runtime().block_on(async {
        let engine = engine(1);
        let executor = executor();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = executor
            .submit(context(&engine), move |ctx| {
                let reservation = ctx.resources().reserve_temp(4096)?;
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(20)).unwrap();
                drop(reservation);
                Ok(())
            })
            .await
            .unwrap();
        entered_rx.await.unwrap();
        drop(worker);
        assert!(
            engine
                .begin(
                    ExecutionGrant::new([Action::Hash]),
                    OperationPolicy::strict_online(),
                    Arc::new(Cancellation::new())
                )
                .is_err()
        );
        assert_eq!(executor.running(), 1);
        release_tx.send(()).unwrap();
        executor.idle().await;
        assert_eq!(executor.running(), 0);
        drop(context(&engine));
    });
}
#[test]
fn bounded_queue_rejects_or_expires() {
    runtime().block_on(async {
        let engine = engine(4);
        let executor = executor();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = executor
            .submit(context(&engine), move |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(20)).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        entered_rx.await.unwrap();
        let queued = executor.submit(context(&engine), |_| Ok(())).await.unwrap();
        assert_eq!(executor.queued(), 1);
        let rejected = executor.submit(context(&engine), |_| Ok(())).await;
        assert!(matches!(rejected, Err(ProcessingError::CapacityExceeded)));
        drop(queued);
        release_tx.send(()).unwrap();
        first.wait().await.unwrap();
        executor.idle().await;
    });
}
#[test]
fn cpu_work_does_not_block_event_loop() {
    runtime().block_on(async {
        let directory = server_support::sandbox();
        let token = oncl_server::auth::TokenSecret::generate().unwrap();
        let mut config = oncl_server::config::ServerConfig::default();
        config.audit_directory = directory.path().join("audit");
        config.blocking_workers = 1;
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
        let engine = host.engine.clone();
        let executor = host.executor.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(oncl_server::service::serve(listener, host, None, async {
            let _ = stopped.await;
        }));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_release = release.clone();
        let work = executor
            .submit(context(&engine), move |ctx| {
                entered_tx.send(()).unwrap();
                while !worker_release.load(std::sync::atomic::Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                ctx.resources().checkpoint()?;
                Ok(())
            })
            .await
            .unwrap();
        entered_rx.await.unwrap();
        // The only network thread completes an actual authenticated socket health
        // request while the CPU worker demonstrably remains in its barrier.
        assert_eq!(
            server_support::request(address, &token.bearer(), "/health", b"", &[], None)
                .await
                .0,
            200
        );
        assert_eq!(executor.running(), 1);
        release.store(true, std::sync::atomic::Ordering::Release);
        work.wait().await.unwrap();
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    });
}

#[test]
fn queued_work_expires_without_entering_native_worker() {
    runtime().block_on(async {
        let engine = engine(3);
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 1,
            queue_capacity: 1,
            admission_wait: Duration::from_millis(20),
        })
        .unwrap();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, barrier) = std::sync::mpsc::channel();
        let first = executor
            .submit(context(&engine), move |_| {
                entered.send(()).unwrap();
                barrier.recv_timeout(Duration::from_secs(20)).unwrap();
                Ok(())
            })
            .await
            .unwrap();
        ready.await.unwrap();
        let entered_second = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_flag = entered_second.clone();
        let second = executor
            .submit(context(&engine), move |_| {
                second_flag.store(true, std::sync::atomic::Ordering::Release);
                Ok(())
            })
            .await
            .unwrap();
        assert!(matches!(
            second.wait().await,
            Err(ProcessingError::CapacityExceeded)
        ));
        assert!(!entered_second.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(executor.running(), 1);
        release.send(()).unwrap();
        first.wait().await.unwrap();
        executor.idle().await;
    });
}

#[test]
fn token_serialization_is_per_device() {
    use oncl_core::keys::{KeyId, KeyRequest, KeySelector};
    use oncl_pki::{digest::HashState, key::SigAlg};
    use server_support::token::{MESSAGE, TokenRig};
    runtime().block_on(async {
        let mut rig = TokenRig::new();
        let executor = BoundedExecutor::new(ExecutorConfig {
            blocking_workers: 3,
            queue_capacity: 1,
            admission_wait: Duration::from_secs(2),
        })
        .unwrap();
        let mut jobs = Vec::new();
        let mut starts = Vec::new();
        for (name, alg) in [
            ("card-a-rsa", SigAlg::RsaSha256),
            ("card-a-gost", SigAlg::Gost2004),
        ] {
            let engine = rig.engine.clone();
            let (ctx, binding) = rig.begin(name);
            let (entered, ready) = tokio::sync::oneshot::channel();
            let (go, start) = std::sync::mpsc::channel();
            let job = executor
                .submit(ctx, move |ctx| {
                    let _binding = binding;
                    let selector = KeySelector::named(KeyId::new(name).unwrap());
                    let mut signer = engine
                        .signer(&KeyRequest::new(&selector, None), ctx)
                        .unwrap();
                    entered.send(()).unwrap();
                    start.recv_timeout(Duration::from_secs(20)).unwrap();
                    let mut hash = HashState::new(alg.hash_alg());
                    hash.update(MESSAGE);
                    Ok(signer.sign_digest(&hash.finish()))
                })
                .await
                .unwrap();
            ready.await.unwrap();
            jobs.push(job);
            starts.push(go);
        }
        let foreign = rig.emu.foreign_transaction("reader-a");
        rig.arm();
        starts.remove(0).send(()).unwrap();
        assert_eq!(rig.entered.recv().await.unwrap(), "reader-a");
        starts.remove(0).send(()).unwrap();
        let denied = jobs.pop().unwrap().wait().await.unwrap().value.unwrap_err();
        assert_eq!(denied.code(), oncl_core::ErrorCode::CapacityExceeded);
        assert_eq!(
            denied.applied_state(),
            oncl_core::keys::AppliedState::NotApplied
        );
        assert!(rig.emu.exchanges("reader-a").is_empty());
        assert!(rig.entered.try_recv().is_err());
        let engine = rig.engine.clone();
        let (ctx, binding) = rig.begin("card-b-gost");
        let b = executor
            .submit(ctx, move |ctx| {
                let _binding = binding;
                Ok(TokenRig::signer(
                    &engine,
                    ctx,
                    "card-b-gost",
                    SigAlg::Gost2004,
                ))
            })
            .await
            .unwrap()
            .wait()
            .await
            .unwrap()
            .value
            .unwrap();
        TokenRig::verify("user-gost2004-sign", SigAlg::Gost2004, &b);
        assert!(rig.emu.exchanges("reader-a").is_empty());
        drop(foreign);
        let a = jobs.pop().unwrap().wait().await.unwrap().value.unwrap();
        TokenRig::verify("user-rsa-sign", SigAlg::RsaSha256, &a);
        assert!(
            rig.audit
                .records()
                .unwrap()
                .iter()
                .any(|r| r.kind == oncl_server::audit::RecordKind::Final
                    && r.applied == oncl_core::keys::AppliedState::Applied)
        );
        executor.idle().await;
    });
}

#[test]
fn real_hash_output_owns_original_root_until_bytes_are_released() {
    use oncl_api::server::{HashHost, RequestMetadata};
    runtime().block_on(async {
        let directory = server_support::sandbox();
        let token = oncl_server::auth::TokenSecret::generate().unwrap();
        let mut config = oncl_server::config::ServerConfig::default();
        config.max_in_flight = 1;
        config.audit_directory = directory.path().join("audit");
        config.hosts = vec!["127.0.0.1:1234".into()];
        config.tokens = vec![oncl_server::config::TokenConfig {
            id: "actor".into(),
            verifier: token.verifier().encoded(),
            actions: vec![oncl_server::config::Permission::Hash],
            keys: Vec::new(),
            inline_pkcs12: false,
        }];
        let host = oncl_server::service::ServiceHost::new(config).unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("host", "127.0.0.1:1234".parse().unwrap());
        headers.insert(
            "authorization",
            format!("Bearer {}", *token.bearer()).parse().unwrap(),
        );
        let response = host
            .hash(
                RequestMetadata {
                    peer: "127.0.0.1:2345".parse().unwrap(),
                    headers,
                    content_length: Some(3),
                },
                axum::body::Body::from("abc"),
            )
            .await
            .unwrap();
        assert!(
            host.engine
                .begin(
                    ExecutionGrant::new([Action::Hash]),
                    OperationPolicy::strict_online(),
                    Arc::new(Cancellation::new())
                )
                .is_err()
        );
        let bytes = axum::body::to_bytes(response.into_body(), 512)
            .await
            .unwrap();
        assert!(
            host.engine
                .begin(
                    ExecutionGrant::new([Action::Hash]),
                    OperationPolicy::strict_online(),
                    Arc::new(Cancellation::new())
                )
                .is_err()
        );
        drop(bytes);
        drop(context(&host.engine));
    });
}

#[test]
fn actual_process_overload_heartbeat_and_disconnect() {
    use std::io::{Read, Write};
    let process = server_support::Process::start(
        "max_in_flight = 1\nblocking_workers = 1\nqueue_capacity = 1",
    );
    let mut pending = std::net::TcpStream::connect(process.address).unwrap();
    write!(pending,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",process.address,*process.token).unwrap();
    // Synchronize on observable admission, not a sleep or throughput benchmark.
    server_support::runtime().block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let (status, body) = server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[],
                None,
            )
            .await;
            if status == 503 {
                let error: oncl_api::error::ApiError = serde_json::from_slice(&body).unwrap();
                assert_eq!(error.code, oncl_api::error::ErrorCode::CapacityExceeded);
                break;
            }
            assert_eq!(status, 200);
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        assert_eq!(
            server_support::request(process.address, &process.token, "/health", b"", &[], None)
                .await
                .0,
            200
        );
    });
    pending.shutdown(std::net::Shutdown::Both).unwrap();
    drop(pending);
    server_support::runtime().block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let (status, _) = server_support::request(
                process.address,
                &process.token,
                "/v1/hash",
                b"abc",
                &[],
                None,
            )
            .await;
            if status == 200 {
                break;
            }
            assert_eq!(status, 503);
            assert!(tokio::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
    });
    // Invalid authentication is answered without waiting for a declared body.
    let mut denied = std::net::TcpStream::connect(process.address).unwrap();
    denied
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(denied,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nContent-Length: 1000000000\r\n\r\n",process.address,"00".repeat(32)).unwrap();
    let mut answer = String::new();
    denied.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 403"));
    eprintln!(
        "standalone: held body causes CapacityExceeded/NotApplied, health progresses, disconnect releases actual worker/root; bad token refused before body"
    );
    process.stop();
}

#[test]
fn actual_process_deadline_covers_incomplete_intake() {
    use std::io::{Read, Write};
    let process = server_support::Process::start(
        "operation_timeout_ms = 1000\nheader_timeout_ms = 500\nadmission_wait_ms = 100",
    );
    let mut socket = std::net::TcpStream::connect(process.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(socket,"POST /v1/hash HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab",process.address,*process.token).unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 504"));
    assert!(response.contains("\"code\":\"DeadlineExceeded\""));
    assert!(response.contains("\"applied\":\"NotApplied\""));
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
    });
    eprintln!(
        "standalone: incomplete unknown-length intake expires as DeadlineExceeded/NotApplied; next abc succeeds"
    );
    process.stop();
}
