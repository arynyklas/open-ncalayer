//! What a host function's panic leaves behind in the pool of a built-in module: nothing. The
//! call is dropped and its instance goes (it is never put back idle); the locks the call
//! used are not poisoned for anyone, so other connections, and the panicking thread's next
//! call, are answered as usual.

use oncl_builtin_tests::SOURCES;
use oncl_builtin_tests::basics::MODULE_NAME;
use oncl_builtin_tests::panicking::PanicOnKey;
use oncl_flows::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::info::cert_info;
use oncl_pki::pkcs12::load;
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{BuiltinLimits, Builtins, Engine, HostServices};
use oncl_protocol::{AddInfo, Reply};
use oncl_testkit::{read, synthetic};
use serde_json::{Value, json};
use std::sync::Arc;
use std::thread;
use time::OffsetDateTime;

fn rsa_time() -> OffsetDateTime {
    let key = synthetic("user-rsa-sign");
    let entry = load(&read(&key.path), &key.password).unwrap().remove(0);
    let info = cert_info(&entry.cert);
    info.not_before + (info.not_after - info.not_before) / 2
}

/// A storage and a key window answered with the synthetic RSA key, `times` times.
fn rsa(times: usize) -> Vec<Step> {
    let key = synthetic("user-rsa-sign");
    (0..times)
        .flat_map(|_| {
            [
                Step::Storage {
                    path: key.path.clone(),
                    password: key.password.clone(),
                },
                Step::Key(0),
            ]
        })
        .collect()
}

fn request() -> String {
    json!({
        "module": MODULE_NAME,
        "method": "sign",
        "args": {
            "format": "cms",
            "data": "x",
            "signingParams": {},
            "signerParams": {"extKeyUsageOids": [], "chain": []},
        },
    })
    .to_string()
}

fn origin() -> AddInfo {
    AddInfo {
        origin: Some("https://x.kz".to_owned()),
        ..AddInfo::default()
    }
}

fn signed(reply: &Reply) -> bool {
    let reply: Value = serde_json::from_str(reply.text().expect("a text reply")).unwrap();
    reply["status"] == true && reply["body"]["result"][0].is_string()
}

#[test]
fn a_host_functions_panic_spoils_nothing_but_its_call() {
    // The first key window panics. The storage window before it took its answer: only the
    // storage of the first call is scripted, and the key windows of the six that follow.
    let steps = [rsa(1)[..1].to_vec(), rsa(6)].concat();
    let scripted = Arc::new(ScriptedPrompter::new(steps));
    let mut services = HostServices::interactive(
        Arc::new(PanicOnKey::new(scripted.clone(), 1)),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new({
            let key = synthetic("tsa-gost2015");
            load(&read(&key.path), &key.password).unwrap().remove(0)
        })),
        oncl_token::Tokens::disabled(),
    );
    services.clock = rsa_time;
    let builtins = Builtins::load(
        &Engine::new(),
        services,
        SOURCES,
        BuiltinLimits::default(),
        None,
    )
    .unwrap();
    let module = builtins.module(MODULE_NAME).unwrap();
    assert_eq!(builtins.idle(MODULE_NAME), Some(1), "the instance loaded");

    // The panic: the connection is dropped, and the instance that panicked is not kept.
    assert_eq!(module.process(&request(), &origin()), Reply::Drop);
    assert_eq!(
        builtins.idle(MODULE_NAME),
        Some(0),
        "a trapped instance is not pooled"
    );
    assert_eq!(builtins.stats(MODULE_NAME).unwrap().calls, 1);

    // Another connection, on another thread, calls the same module.
    let other = thread::scope(|s| {
        s.spawn(|| module.process(&request(), &origin()))
            .join()
            .unwrap()
    });
    assert!(signed(&other), "{other:?}");
    // A fresh instance did it, and it is kept for the next call.
    assert_eq!(builtins.idle(MODULE_NAME), Some(1));

    // Several connections at once, and the one whose call panicked.
    let replies: Vec<Reply> = thread::scope(|s| {
        let calls: Vec<_> = (0..4)
            .map(|_| s.spawn(|| module.process(&request(), &origin())))
            .collect();
        calls.into_iter().map(|c| c.join().unwrap()).collect()
    });
    assert!(replies.iter().all(signed), "{replies:?}");
    assert!(signed(&module.process(&request(), &origin())));
    assert_eq!(builtins.stats(MODULE_NAME).unwrap().calls, 7);
    assert!(scripted.mismatches().is_empty());
}

#[test]
fn every_call_may_panic_and_the_pool_still_answers() {
    // Panics on all of the first three calls, from three threads at once: the pool is
    // empty after them, and a later call makes an instance again.
    let scripted = Arc::new(ScriptedPrompter::new(
        (0..3)
            .map(|_| Step::Storage {
                path: synthetic("user-rsa-sign").path,
                password: synthetic("user-rsa-sign").password,
            })
            .chain(rsa(1))
            .collect(),
    ));
    let mut services = HostServices::interactive(
        Arc::new(PanicOnKey::new(scripted.clone(), 3)),
        Arc::new(MemoryRecentPath::new(None)),
        Arc::new(MockTsa::new({
            let key = synthetic("tsa-gost2015");
            load(&read(&key.path), &key.password).unwrap().remove(0)
        })),
        oncl_token::Tokens::disabled(),
    );
    services.clock = rsa_time;
    let builtins = Builtins::load(
        &Engine::new(),
        services,
        SOURCES,
        BuiltinLimits::default(),
        None,
    )
    .unwrap();
    let module = builtins.module(MODULE_NAME).unwrap();
    let replies: Vec<Reply> = thread::scope(|s| {
        let calls: Vec<_> = (0..3)
            .map(|_| s.spawn(|| module.process(&request(), &origin())))
            .collect();
        calls.into_iter().map(|c| c.join().unwrap()).collect()
    });
    assert_eq!(replies, [Reply::Drop, Reply::Drop, Reply::Drop]);
    assert_eq!(builtins.idle(MODULE_NAME), Some(0));
    assert!(signed(&module.process(&request(), &origin())));
    assert_eq!(builtins.idle(MODULE_NAME), Some(1));
}
