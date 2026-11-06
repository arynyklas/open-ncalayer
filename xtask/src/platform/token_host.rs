//! `cargo xtask platform-token-host`: the real `oncl-server` service library (`ServiceHost`,
//! the axum router, the bounded executor, the durable audit journal, the token gate
//! registry) hosted with a software card backend that COUNTS concurrent APDU exchanges per
//! reader.
//!
//! The standalone `oncl-server` binary always uses the system PC/SC service, and this
//! Windows stand has no virtual reader, so the per-device serialization of private card use
//! cannot be observed on that binary. This host runs the same service code over the same
//! HTTP router with an emulated card whose reader wrapper records, per reader, the largest
//! number of simultaneous `transmit` calls and of simultaneously open transactions. The
//! proof requires both to be 1. A process in this role is reported as such, never as the
//! standalone binary.

use anyhow::{Context, bail};
use oncl_token::{
    TokenKind,
    backend::{Backend, BackendError, Connection, Protocol, ReaderState},
    emulator::{CardSpec, EmuKey, EmulatorBackend, card},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const PIN: &str = "123456";
pub const READERS: [&str; 2] = ["reader-a", "reader-b"];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReaderStats {
    pub transmits: u64,
    pub transactions: u64,
    pub transmit_now: u32,
    pub transmit_max: u32,
    pub transaction_now: u32,
    pub transaction_max: u32,
}

#[derive(Default)]
pub struct Stats {
    readers: Mutex<BTreeMap<String, ReaderStats>>,
}

impl Stats {
    fn with(&self, reader: &str, f: impl FnOnce(&mut ReaderStats)) {
        f(self.readers.lock().unwrap().entry(reader.to_owned()).or_default());
    }

    pub fn snapshot(&self) -> BTreeMap<String, ReaderStats> {
        self.readers.lock().unwrap().clone()
    }
}

/// A backend that counts the overlap of what its connections do.
pub struct Counting {
    pub inner: Arc<dyn Backend>,
    pub stats: Arc<Stats>,
}

struct CountingConnection {
    inner: Box<dyn Connection>,
    reader: String,
    stats: Arc<Stats>,
}

impl Backend for Counting {
    fn readers(&self) -> Result<Vec<ReaderState>, BackendError> {
        self.inner.readers()
    }

    fn connect(&self, reader: &str) -> Result<Box<dyn Connection>, BackendError> {
        Ok(Box::new(CountingConnection {
            inner: self.inner.connect(reader)?,
            reader: reader.to_owned(),
            stats: self.stats.clone(),
        }))
    }
}

impl Connection for CountingConnection {
    fn protocol(&self) -> Protocol {
        self.inner.protocol()
    }

    fn atr(&self) -> &[u8] {
        self.inner.atr()
    }

    fn begin_transaction(&mut self) -> Result<(), BackendError> {
        let result = self.inner.begin_transaction();
        if result.is_ok() {
            self.stats.with(&self.reader, |s| {
                s.transactions += 1;
                s.transaction_now += 1;
                s.transaction_max = s.transaction_max.max(s.transaction_now);
            });
        }
        result
    }

    fn end_transaction(&mut self) -> Result<(), BackendError> {
        self.stats.with(&self.reader, |s| {
            s.transaction_now = s.transaction_now.saturating_sub(1);
        });
        self.inner.end_transaction()
    }

    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, BackendError> {
        self.stats.with(&self.reader, |s| {
            s.transmits += 1;
            s.transmit_now += 1;
            s.transmit_max = s.transmit_max.max(s.transmit_now);
        });
        let result = self.inner.transmit(apdu);
        self.stats.with(&self.reader, |s| {
            s.transmit_now = s.transmit_now.saturating_sub(1);
        });
        result
    }

    fn reset_on_disconnect(&mut self) {
        self.inner.reset_on_disconnect();
    }

    fn begin_private_operation(&mut self) {
        self.inner.begin_private_operation();
    }
}

/// Two readers, each with a card holding the loopback PKI's RSA signing key.
pub fn emulator(pki_dir: &Path, password: &str) -> anyhow::Result<(Arc<EmulatorBackend>, String)> {
    let emu = Arc::new(EmulatorBackend::new());
    let mut alias = String::new();
    for reader in READERS {
        let entry = oncl_pki::pkcs12::load(&std::fs::read(pki_dir.join("rsa.p12"))?, password)
            .map_err(|e| anyhow::anyhow!("rsa.p12: {e:?}"))?
            .remove(0);
        alias = entry.alias.clone();
        emu.add_reader(reader);
        emu.insert(reader, card(CardSpec::new(TokenKind::Kaztoken, PIN, vec![EmuKey { entry }])));
    }
    Ok((emu, alias))
}

#[derive(clap::Args, Clone, Debug)]
pub struct TokenHostArgs {
    /// The server configuration (TOML), as for `oncl-server serve --config`.
    #[arg(long)]
    pub config: PathBuf,
    /// The loopback PKI directory (`rsa.p12`, `pki.json`).
    #[arg(long)]
    pub pki: PathBuf,
    /// Where the overlap statistics are written when the host stops.
    #[arg(long)]
    pub report: PathBuf,
}

/// Runs the host until a newline arrives on stdin, like `oncl-server serve --shutdown-stdin`.
pub fn run(args: TokenHostArgs) -> anyhow::Result<()> {
    let meta: serde_json::Value = serde_json::from_slice(&std::fs::read(args.pki.join("pki.json"))?)?;
    let password = meta["password"].as_str().context("pki.json password")?.to_owned();
    let (emu, alias) = emulator(&args.pki, &password)?;
    println!("alias={alias}");
    let stats = Arc::new(Stats::default());
    let backend: Arc<dyn Backend> = Arc::new(Counting {
        inner: emu,
        stats: stats.clone(),
    });
    let mut config = oncl_server::config::ServerConfig::read(&args.config)
        .map_err(|e| anyhow::anyhow!("reading the configuration: {e}"))?;
    config.enabled = true;
    config.validate().map_err(|e| anyhow::anyhow!("configuration: {e}"))?;
    let tls = oncl_server::service::tls_configuration(&config)?;
    let host = oncl_server::service::ServiceHost::with_token_backend(config.clone(), backend)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(config.blocking_workers)
        .enable_all()
        .build()?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let control = std::thread::spawn(move || {
        let mut byte = [0];
        while std::io::stdin().read(&mut byte).is_ok_and(|n| n != 0) {
            if byte[0] == b'\n' {
                break;
            }
        }
        let _ = stop_tx.send(());
    });
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(config.bind).await?;
        let address = listener.local_addr()?;
        let host = host.for_listener(address)?;
        println!("listening {address}");
        std::io::stdout().flush()?;
        oncl_server::service::serve(listener, host, tls, async move {
            let _ = stop_rx.await;
        })
        .await
    })?;
    control.join().map_err(|_| anyhow::anyhow!("control thread"))?;
    std::fs::write(&args.report, serde_json::to_vec_pretty(&stats.snapshot())?)?;
    println!("stopped: owned listener and workers released");
    if stats.snapshot().is_empty() {
        bail!("the card backend was never used");
    }
    Ok(())
}
