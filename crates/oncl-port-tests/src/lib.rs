//! The plugin ports of `plugins/` run as the daemon runs them: built for wasm32 once per
//! process ([`oncl_testkit::plugin::ports_built`]), packaged as `xtask plugin pack` packages
//! them ([`port_package`]), checked and instantiated by `oncl_plugin`, their dialogs answered
//! by a [`ScriptedPrompter`] and their PKI requests by the mock TSA, OCSP responder and CRL
//! server of `oncl_pki` ([`Harness`]).

use oncl_basics::Locale;
use oncl_basics::testing::{MemoryRecentPath, ScriptedPrompter, Step};
use oncl_pki::crl::MockCrl;
use oncl_pki::http::{
    HttpError, HttpMethod, HttpReply, HttpRequest, HttpTransport, RouteTransport,
};
use oncl_pki::ocsp::MockOcsp;
use oncl_pki::pkcs12::{self, KeyEntry};
use oncl_pki::pkix::CaSet;
use oncl_pki::tsp::MockTsa;
use oncl_plugin::{Engine, HostServices, Instance, Manifest, Package, SessionContext};
use oncl_protocol::{AddInfo, Reply};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;

/// The password of every synthetic key store.
pub const P12_PASSWORD: &str = "Qwerty12";

/// The directory of the port `short`: `plugins/<short>`.
pub fn port_dir(short: &str) -> PathBuf {
    oncl_testkit::plugin::ports_dir().join(short)
}

/// The `.onclp` of the port `short`: its `plugin.toml` and module, packaged by the code of
/// `cargo xtask plugin pack` ([`oncl_plugin::archive`]).
///
/// # Panics
///
/// If the port does not build or its files are missing.
pub fn port_package(short: &str) -> Vec<u8> {
    let manifest = oncl_testkit::read(port_dir(short).join("plugin.toml"));
    let wasm = oncl_testkit::read(oncl_testkit::plugin::port_wasm(short));
    oncl_plugin::archive(&manifest, &wasm).expect("in memory")
}

/// The synthetic key store `name` (`fixtures/synthetic/<name>.p12`) and its password.
pub fn p12(name: &str) -> (PathBuf, &'static str) {
    (oncl_testkit::synthetic(name).path, P12_PASSWORD)
}

/// The first key of the synthetic key store `name`.
///
/// # Panics
///
/// If the store does not open.
pub fn entry(name: &str) -> KeyEntry {
    let key = oncl_testkit::synthetic(name);
    pkcs12::load(&oncl_testkit::read(&key.path), &key.password)
        .expect("the synthetic store opens")
        .remove(0)
}

/// The CAs of the synthetic PKI (its roots and intermediate), as `ca_list`, `ca_issuer` and
/// `keys_chain` of [`Harness`] see them.
///
/// # Panics
///
/// If a fixture certificate does not parse.
pub fn synthetic_cas() -> CaSet {
    CaSet::new(
        [
            "root-gost2015",
            "inter-gost2015",
            "root-gost2004",
            "root-rsa",
        ]
        .map(|name| {
            oncl_pki::cert::parse(&oncl_testkit::synthetic_cert(name))
                .expect("a fixture certificate parses")
        })
        .to_vec(),
    )
}

/// The fixed time of [`Harness`]: 2026-10-29 12:00 UTC.
pub fn default_clock() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_793_275_200).expect("a valid time")
}

/// HTTP requests of a port: each `GET <url>` or `POST <url>` in order, answered by the
/// routes.
struct Logged {
    routes: RouteTransport,
    log: Mutex<Vec<String>>,
}

impl HttpTransport for Logged {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        let method = match request.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        };
        self.log
            .lock()
            .unwrap()
            .push(format!("{method} {}", request.url));
        self.routes.send(request)
    }
}

/// Ports run with scripted dialogs, mock PKI services and a fixed clock.
pub struct Harness {
    engine: Engine,
    prompter: Arc<ScriptedPrompter>,
    http: Arc<Logged>,
    clock: fn() -> OffsetDateTime,
    locale: Locale,
    pki_hosts: Arc<[String]>,
    settings_dir: Option<PathBuf>,
    tokens: Arc<oncl_token::Tokens>,
}

impl Harness {
    /// A harness answering the dialogs with `steps`; `tsp.pki.gov.kz` is a [`MockTsa`],
    /// `ocsp.pki.gov.kz` a [`MockOcsp`], `crl.pki.gov.kz` a [`MockCrl`] of the synthetic PKI,
    /// `extra` routes (URL prefix, transport) go first.
    pub fn new(steps: Vec<Step>, extra: Vec<(String, Arc<dyn HttpTransport>)>) -> Harness {
        let tsa: Arc<dyn HttpTransport> = Arc::new(MockTsa::new(entry("tsa-gost2015")));
        let ocsp: Arc<dyn HttpTransport> = Arc::new(MockOcsp::new(entry("ocsp-gost2015")));
        let crl: Arc<dyn HttpTransport> = Arc::new(MockCrl::new(entry("inter-gost2015.key")));
        let mut routes = extra;
        for scheme in ["http", "https"] {
            routes.push((format!("{scheme}://tsp.pki.gov.kz"), Arc::clone(&tsa)));
            routes.push((format!("{scheme}://ocsp.pki.gov.kz"), Arc::clone(&ocsp)));
            routes.push((format!("{scheme}://crl.pki.gov.kz"), Arc::clone(&crl)));
        }
        Harness {
            engine: Engine::new(),
            prompter: Arc::new(ScriptedPrompter::new(steps)),
            http: Arc::new(Logged {
                routes: RouteTransport::new(routes),
                log: Mutex::new(Vec::new()),
            }),
            clock: default_clock,
            locale: Locale::Ru,
            pki_hosts: oncl_plugin::nca_pki_hosts(),
            settings_dir: None,
            tokens: oncl_token::Tokens::disabled(),
        }
    }

    /// The same harness with the clock `clock`.
    #[must_use]
    pub fn with_clock(self, clock: fn() -> OffsetDateTime) -> Harness {
        Harness { clock, ..self }
    }

    /// The same harness with the windows' language `locale`.
    #[must_use]
    pub fn with_locale(self, locale: Locale) -> Harness {
        Harness { locale, ..self }
    }

    /// The same harness whose PKI hosts are the NCA's and `extra` (the synthetic PKI's
    /// responders, `ocsp.synthetic.test`).
    #[must_use]
    pub fn with_pki_hosts(self, extra: &[&str]) -> Harness {
        let pki_hosts = oncl_plugin::NCA_PKI_HOSTS
            .iter()
            .chain(extra)
            .map(|h| (*h).to_owned())
            .collect();
        Harness { pki_hosts, ..self }
    }

    /// The same harness with the plugins' settings kept in `dir` (`<dir>/<id>.json`); without
    /// it, `settings_get` and `settings_put` fail.
    #[must_use]
    pub fn with_settings_dir(self, dir: PathBuf) -> Harness {
        Harness {
            settings_dir: Some(dir),
            ..self
        }
    }

    /// The same harness whose hardware tokens are the readers and cards of `emu`, token
    /// support on.
    #[must_use]
    pub fn with_tokens(self, emu: Arc<oncl_token::emulator::EmulatorBackend>) -> Harness {
        Harness {
            tokens: oncl_token::Tokens::new(emu, true),
            ..self
        }
    }

    /// The prompter: the dialogs shown.
    pub fn prompter(&self) -> &ScriptedPrompter {
        &self.prompter
    }

    /// The HTTP requests made so far: `GET <url>`, `POST <url>`.
    pub fn http_log(&self) -> Vec<String> {
        self.http.log.lock().unwrap().clone()
    }

    fn services(&self) -> HostServices {
        let locale = self.locale;
        HostServices {
            clock: self.clock,
            locale: Arc::new(move || locale),
            // The synthetic PKI's CAs, as the ports' keys are synthetic.
            cas: Arc::new(synthetic_cas()),
            pki_hosts: Arc::clone(&self.pki_hosts),
            settings_dir: self.settings_dir.clone(),
            ..HostServices::new(
                Arc::clone(&self.prompter) as _,
                Arc::new(MemoryRecentPath::new(None)),
                Arc::clone(&self.http) as _,
                Arc::clone(&self.tokens),
            )
        }
    }

    /// A session of the port `short`: one instance for several calls.
    ///
    /// # Panics
    ///
    /// If the port's package is invalid or does not load.
    pub fn session(&self, short: &str) -> SessionHandle {
        self.session_of(&port_package(short))
    }

    /// A session of the plugin in the `.onclp` `package`.
    ///
    /// # Panics
    ///
    /// If the package is invalid or does not load.
    pub fn session_of(&self, package: &[u8]) -> SessionHandle {
        let package = Package::read(package).expect("a valid package");
        let compiled = self
            .engine
            .compile(&package.manifest, &package.wasm)
            .expect("the port loads");
        let instance = compiled
            .instantiate(&self.services(), context(&package.manifest))
            .expect("the port instantiates");
        SessionHandle { instance }
    }

    /// One call of the port `short` in a session of its own, from `origin`.
    ///
    /// # Panics
    ///
    /// As [`Harness::session`]; the call fails (`PluginError`).
    pub fn call(&self, short: &str, request: &str, origin: Option<&str>) -> Reply {
        self.session(short).call(request, origin)
    }

    /// `n` sessions of the port `short` from one load of it: what one instance puts with
    /// `shared_put` the others get (as the sessions of several pages do).
    ///
    /// # Panics
    ///
    /// As [`Harness::session`].
    pub fn shared_sessions(&self, short: &str, n: usize) -> Vec<SessionHandle> {
        let package = Package::read(&port_package(short)).expect("a valid package");
        let compiled = self
            .engine
            .compile(&package.manifest, &package.wasm)
            .expect("the port loads");
        let shared: Arc<oncl_plugin::SharedState> = Arc::default();
        (1..=n as u64)
            .map(|session| {
                let context = SessionContext {
                    session,
                    shared: Arc::clone(&shared),
                    ..context(&package.manifest)
                };
                let instance = compiled
                    .instantiate(&self.services(), context)
                    .expect("the port instantiates");
                SessionHandle { instance }
            })
            .collect()
    }
}

fn context(manifest: &Manifest) -> SessionContext {
    SessionContext {
        session: 1,
        plugin_id: manifest.id.clone(),
        plugin_name: manifest.name.clone(),
        shared: Arc::default(),
        trust: oncl_plugin::Trust::Installed,
    }
}

/// An instance of a port.
pub struct SessionHandle {
    instance: Instance,
}

impl SessionHandle {
    /// The reply to `request` from `origin`.
    ///
    /// # Panics
    ///
    /// If the call fails (`PluginError`: the page would get `PLUGIN_ERROR`).
    pub fn call(&mut self, request: &str, origin: Option<&str>) -> Reply {
        let add_info = AddInfo {
            origin: origin.map(str::to_owned),
            session: 1,
        };
        self.instance
            .process(request, &add_info)
            .unwrap_or_else(|e| panic!("the port failed: {e}"))
    }
}
