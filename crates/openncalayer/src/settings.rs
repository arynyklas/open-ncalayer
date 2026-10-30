//! `settings.json` of the data directory ([`oncl_desktop::settings`]): the `recentPath` of the
//! key store dialogs and the settings the daemon starts with; [`LiveProxyTransport`] takes a
//! proxy the settings window saves while the daemon runs.

use std::path::{Path, PathBuf};
use std::sync::{PoisonError, RwLock};

use oncl_basics::RecentPathStore;
use oncl_desktop::ProxySetting;
use oncl_desktop::settings::{self, Settings};
use oncl_pki::http::{HttpError, HttpReply, HttpRequest, HttpTransport, UreqTransport};
use serde_json::Value;

const RECENT_PATH: &str = "recentPath";

/// `recentPath` of `settings.json`, the last opened key store, as a [`RecentPathStore`]. The
/// file's other keys are kept as they are.
pub struct JsonSettings {
    path: PathBuf,
}

impl JsonSettings {
    /// Settings kept in the file `path`; the file and its directory are created on first save.
    pub fn new(path: PathBuf) -> Self {
        JsonSettings { path }
    }
}

impl RecentPathStore for JsonSettings {
    fn load(&self) -> Option<PathBuf> {
        match settings::read(&self.path) {
            Ok(settings) => settings?
                .get(RECENT_PATH)
                .and_then(Value::as_str)
                .map(PathBuf::from),
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "cannot read settings");
                None
            }
        }
    }

    fn save(&self, p: &Path) {
        let Some(p) = p.to_str() else {
            tracing::warn!("key store path is not valid Unicode; not remembered");
            return;
        };
        let saved = settings::update(&self.path, |settings| {
            settings.insert(RECENT_PATH.to_owned(), Value::String(p.to_owned()));
        });
        if let Err(e) = saved {
            tracing::warn!(path = %self.path.display(), error = %e, "cannot write settings");
        }
    }
}

/// The settings in the file `path`; the defaults (logged) if it cannot be read.
pub fn load_settings(path: &Path) -> Settings {
    Settings::load(path).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), error = %e, "cannot read settings; using the defaults");
        Settings::default()
    })
}

/// With feature `e2e-prompter` (test builds, never releases): a PEM file of CA certificates
/// the daemon's and the plugins' HTTPS trusts on top of the webpki roots.
#[cfg(feature = "e2e-prompter")]
pub const E2E_EXTRA_CA_VAR: &str = "ONCL_E2E_EXTRA_CA";

/// The CA certificates (DER) of the file in [`E2E_EXTRA_CA_VAR`], read once; none if the
/// variable is unset, or the file unreadable (logged).
#[cfg(feature = "e2e-prompter")]
fn e2e_extra_ca() -> &'static [Vec<u8>] {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use std::sync::LazyLock;

    static EXTRA: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
        let Some(path) = std::env::var_os(E2E_EXTRA_CA_VAR) else {
            return Vec::new();
        };
        let certs = CertificateDer::pem_file_iter(&path)
            .and_then(|certs| certs.collect::<Result<Vec<_>, _>>());
        match certs {
            Ok(certs) if !certs.is_empty() => certs.into_iter().map(|c| c.to_vec()).collect(),
            Ok(_) => {
                tracing::error!(path = %Path::new(&path).display(), "{E2E_EXTRA_CA_VAR}: no certificate");
                Vec::new()
            }
            Err(e) => {
                tracing::error!(path = %Path::new(&path).display(), error = %e, "{E2E_EXTRA_CA_VAR}: unreadable");
                Vec::new()
            }
        }
    });
    &EXTRA
}

/// The daemon's [`UreqTransport`] through `proxy`; with feature `e2e-prompter`, trusting the
/// CA of [`E2E_EXTRA_CA_VAR`] too.
pub fn daemon_transport(proxy: ProxySetting) -> UreqTransport {
    let transport = UreqTransport::with_proxy(proxy);
    #[cfg(feature = "e2e-prompter")]
    let transport = match e2e_extra_ca() {
        [] => transport,
        extra => transport.with_extra_roots(extra),
    };
    transport
}

/// The daemon's HTTP transport (time stamps, OCSP, CRL, plugins): [`daemon_transport`]
/// through the proxy of the settings, which [`LiveProxyTransport::set_proxy`] changes for
/// the requests that start afterwards.
#[derive(Debug)]
pub struct LiveProxyTransport {
    current: RwLock<UreqTransport>,
}

impl LiveProxyTransport {
    /// A transport through `proxy`.
    pub fn new(proxy: ProxySetting) -> Self {
        LiveProxyTransport {
            current: RwLock::new(daemon_transport(proxy)),
        }
    }

    /// Goes through `proxy` from now on.
    pub fn set_proxy(&self, proxy: ProxySetting) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = daemon_transport(proxy);
    }

    /// The transport of a request starting now.
    fn transport(&self) -> UreqTransport {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl HttpTransport for LiveProxyTransport {
    fn send(&self, request: &HttpRequest<'_>) -> Result<HttpReply, HttpError> {
        self.transport().send(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// `http://` URL of a server that answers one request with `200 ok`.
    fn serve_once() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
        });
        url
    }

    #[test]
    fn a_saved_proxy_applies_to_later_requests() {
        let url = serve_once();
        let http = LiveProxyTransport::new(ProxySetting::Manual("socks5://127.0.0.1:1".to_owned()));
        // An unusable proxy fails the request without connecting directly.
        let e = http.get(&url).unwrap_err();
        assert!(e.message.contains("proxy"), "{e}");
        http.set_proxy(ProxySetting::None);
        let reply = http.get(&url).unwrap();
        assert_eq!(
            (reply.status, reply.body.as_slice()),
            (200, b"ok".as_slice())
        );
    }

    #[test]
    fn other_keys_are_kept_and_garbage_is_replaced() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sub").join("settings.json");
        let s = JsonSettings::new(f.clone());
        s.save(Path::new("a.p12"));
        fs::write(&f, r#"{"other": 1, "recentPath": "a.p12"}"#).unwrap();
        s.save(Path::new("b.p12"));
        let v: Value = serde_json::from_slice(&fs::read(&f).unwrap()).unwrap();
        assert_eq!(v, serde_json::json!({"other": 1, "recentPath": "b.p12"}));

        fs::write(&f, "[").unwrap();
        assert_eq!(s.load(), None);
        s.save(Path::new("c.p12"));
        assert_eq!(s.load(), Some(PathBuf::from("c.p12")));
    }

    #[test]
    fn recent_path_and_settings_share_the_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("settings.json");
        let recent = JsonSettings::new(f.clone());
        recent.save(Path::new("k.p12"));
        let settings = Settings {
            locale: Some("en".to_owned()),
            autostart: true,
            proxy: ProxySetting::None,
            ..Settings::default()
        };
        settings.save(&f).unwrap();
        recent.save(Path::new("l.p12"));
        assert_eq!(load_settings(&f), settings);
        assert_eq!(recent.load(), Some(PathBuf::from("l.p12")));

        fs::write(&f, "{").unwrap();
        assert_eq!(load_settings(&f), Settings::default());
    }
}
