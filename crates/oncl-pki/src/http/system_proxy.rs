//! The system's proxy of [`ProxySetting::System`](super::ProxySetting::System).

use ureq::Proxy;

/// The system's proxy for a request to `url`: the environment's (whose `NO_PROXY` the
/// caller applies), otherwise on Windows the manual proxy of the Internet Options unless
/// they bypass `url`'s host. `None`: connect directly.
pub(super) fn for_url(url: &str) -> Option<Proxy> {
    Proxy::try_from_env().or_else(|| os_proxy(url))
}

#[cfg(windows)]
fn os_proxy(url: &str) -> Option<Proxy> {
    let uri = url.parse::<ureq::http::Uri>().ok()?;
    let scheme = uri.scheme_str()?;
    let port = uri.port_u16().or(match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    })?;
    let options = windows::internet_options(&windows::Keys::system())?;
    let proxy = options.proxy_for(scheme, uri.host()?, port)?;
    Proxy::new(&proxy).ok()
}

#[cfg(not(windows))]
fn os_proxy(_url: &str) -> Option<Proxy> {
    None
}

/// The manual proxy of the Windows Internet Options, when it is on.
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, PartialEq, Eq)]
struct InternetOptions {
    /// `ProxyServer`: `host:port` for every scheme, or `scheme=host:port` entries separated
    /// by `;`.
    server: String,
    /// `ProxyOverride`: patterns separated by `;` of a host, optionally with a scheme
    /// (`http://`) before and a port (`:8080`) after it, `*` matching any characters;
    /// `<local>` stands for every host name without a dot, `<-loopback>` sends loopback
    /// requests through the proxy too.
    bypass: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl InternetOptions {
    /// The proxy URL for a request with `scheme` to `host` and `port`; `None` if the request
    /// bypasses the proxy (loopback hosts do, as in Windows, unless `<-loopback>` is listed)
    /// or no entry covers `scheme`.
    fn proxy_for(&self, scheme: &str, host: &str, port: u16) -> Option<String> {
        let bypass = self.bypass.as_deref().unwrap_or_default();
        let proxied_loopback = bypass
            .split(';')
            .any(|p| p.trim().eq_ignore_ascii_case("<-loopback>"));
        if (loopback(host) && !proxied_loopback) || bypassed(bypass, scheme, host, port) {
            return None;
        }
        let mut common = None;
        let mut per_scheme = false;
        for entry in self.server.split(';').map(str::trim) {
            match entry.split_once('=') {
                Some((key, value)) => {
                    per_scheme = true;
                    let value = value.trim();
                    if key.trim().eq_ignore_ascii_case(scheme) && !value.is_empty() {
                        return Some(with_scheme(value));
                    }
                }
                None if !entry.is_empty() => common = common.or(Some(entry)),
                None => {}
            }
        }
        if per_scheme {
            None
        } else {
            common.map(with_scheme)
        }
    }
}

/// Whether `host` (as in a URL: IPv6 in brackets) is `localhost` or a loopback address.
#[cfg_attr(not(windows), allow(dead_code))]
fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `proxy` as a URL: `http://` unless it names a scheme (the entries of `ProxyServer` are
/// HTTP proxies, `https=` included: HTTPS goes through them as a tunnel). A scheme other
/// than `http://` is refused by the caller.
#[cfg_attr(not(windows), allow(dead_code))]
fn with_scheme(proxy: &str) -> String {
    if proxy.contains("://") {
        proxy.to_owned()
    } else {
        format!("http://{proxy}")
    }
}

/// Whether a pattern of the `ProxyOverride` list `bypass` matches a request with `scheme`
/// to `host` and `port`, ignoring case.
#[cfg_attr(not(windows), allow(dead_code))]
fn bypassed(bypass: &str, scheme: &str, host: &str, port: u16) -> bool {
    let host = host.to_ascii_lowercase();
    bypass
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .any(|p| {
            if p.eq_ignore_ascii_case("<local>") {
                // A name without a dot; IPv6 addresses (with colons) are not local names.
                return !host.contains(['.', ':']);
            }
            let p = p.to_ascii_lowercase();
            let (p_scheme, rest) = match p.split_once("://") {
                Some((s, rest)) => (Some(s), rest),
                None => (None, p.as_str()),
            };
            // A port after the last colon, unless that colon is inside a bare IPv6 address.
            let (p_host, p_port) = match rest.rsplit_once(':') {
                Some((h, port))
                    if !port.is_empty()
                        && port.bytes().all(|b| b.is_ascii_digit())
                        && (!h.contains(':') || h.ends_with(']')) =>
                {
                    (h, port.parse::<u16>().ok())
                }
                _ => (rest, None),
            };
            p_scheme.is_none_or(|s| s.eq_ignore_ascii_case(scheme))
                && p_port.is_none_or(|p| p == port)
                && wildcard_match(p_host.as_bytes(), host.as_bytes())
        })
}

/// Whether `text` matches `pattern`, where `*` matches any run of bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // The last `*` seen and the text position its run of matched bytes ends at.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                // Let the last `*` take one more byte.
                Some((star_p, star_t)) => {
                    p = star_p + 1;
                    t = star_t + 1;
                    star = Some((star_p, star_t + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// The Internet Options in the registry, read only.
#[cfg(windows)]
mod windows {
    use super::InternetOptions;
    use oncl_registry::{Hive, get_dword, get_string};

    const SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    const POLICY: &str = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// Where the options are: the policy choosing per-user or per-machine settings, and
    /// those two.
    pub(super) struct Keys {
        policy: (Hive, String),
        user: (Hive, String),
        machine: (Hive, String),
    }

    impl Keys {
        /// The real keys: the policy and the machine's settings in `HKLM`, the user's in
        /// `HKCU`.
        pub(super) fn system() -> Keys {
            Keys {
                policy: (Hive::LocalMachine, POLICY.to_owned()),
                user: (Hive::CurrentUser, SETTINGS.to_owned()),
                machine: (Hive::LocalMachine, SETTINGS.to_owned()),
            }
        }

        /// All three under `HKCU\<root>\HKCU` and `HKCU\<root>\HKLM`, for tests.
        #[cfg(test)]
        pub(super) fn sandbox(root: &str) -> Keys {
            let hkcu = Hive::CurrentUser;
            Keys {
                policy: (hkcu, format!(r"{root}\HKLM\{POLICY}")),
                user: (hkcu, format!(r"{root}\HKCU\{SETTINGS}")),
                machine: (hkcu, format!(r"{root}\HKLM\{SETTINGS}")),
            }
        }
    }

    /// The manual proxy, if `ProxyEnable` is set and `ProxyServer` names one: the
    /// machine's when the policy `ProxySettingsPerUser` is 0, otherwise the user's. A value
    /// that cannot be read counts as missing.
    pub(super) fn internet_options(keys: &Keys) -> Option<InternetOptions> {
        let (policy_hive, policy) = &keys.policy;
        let per_user = get_dword(*policy_hive, policy, Some("ProxySettingsPerUser"))
            .ok()
            .flatten()
            != Some(0);
        let (hive, key) = if per_user { &keys.user } else { &keys.machine };
        let enabled = get_dword(*hive, key, Some("ProxyEnable")).ok().flatten();
        if enabled.unwrap_or(0) == 0 {
            return None;
        }
        let server = get_string(*hive, key, Some("ProxyServer")).ok().flatten()?;
        Some(InternetOptions {
            server,
            bypass: get_string(*hive, key, Some("ProxyOverride")).ok().flatten(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use oncl_registry::{TestKey, set_dword, set_string};

        #[test]
        fn options_are_read_from_the_user_or_the_machine() {
            let root = TestKey::new();
            let keys = Keys::sandbox(root.path());
            let (user, machine, policy) = (&keys.user.1, &keys.machine.1, &keys.policy.1);
            assert_eq!(internet_options(&keys), None);

            set_string(user, Some("ProxyServer"), "user:3128").unwrap();
            assert_eq!(internet_options(&keys), None, "ProxyEnable is not set");
            set_dword(user, Some("ProxyEnable"), 0).unwrap();
            assert_eq!(internet_options(&keys), None);
            set_dword(user, Some("ProxyEnable"), 1).unwrap();
            assert_eq!(
                internet_options(&keys),
                Some(InternetOptions {
                    server: "user:3128".to_owned(),
                    bypass: None
                })
            );
            set_string(user, Some("ProxyOverride"), "<local>").unwrap();
            assert_eq!(
                internet_options(&keys).unwrap().bypass.as_deref(),
                Some("<local>")
            );

            // The per-machine policy: the machine's settings, even if they are off.
            set_dword(policy, Some("ProxySettingsPerUser"), 0).unwrap();
            assert_eq!(internet_options(&keys), None);
            set_dword(machine, Some("ProxyEnable"), 1).unwrap();
            set_string(machine, Some("ProxyServer"), "http=machine:8080").unwrap();
            assert_eq!(
                internet_options(&keys),
                Some(InternetOptions {
                    server: "http=machine:8080".to_owned(),
                    bypass: None
                })
            );
            set_dword(policy, Some("ProxySettingsPerUser"), 1).unwrap();
            assert_eq!(internet_options(&keys).unwrap().server, "user:3128");
            // A value of the wrong type counts as missing.
            set_string(user, Some("ProxyEnable"), "1").unwrap();
            assert_eq!(internet_options(&keys), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(server: &str, bypass: Option<&str>) -> InternetOptions {
        InternetOptions {
            server: server.to_owned(),
            bypass: bypass.map(str::to_owned),
        }
    }

    #[test]
    fn one_proxy_serves_every_scheme() {
        let o = options("proxy.corp:3128", None);
        let proxy = Some("http://proxy.corp:3128".to_owned());
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz", 80), proxy);
        assert_eq!(o.proxy_for("https", "tsp.pki.gov.kz", 443), proxy);
        assert_eq!(
            options("socks5://proxy.corp:1080", None).proxy_for("http", "x.kz", 80),
            Some("socks5://proxy.corp:1080".to_owned())
        );
        assert_eq!(options(" ; ", None).proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn per_scheme_entries_pick_the_request_scheme() {
        let o = options("HTTP=web:80; https=secure:8443;ftp=f:21;socks=s:1080", None);
        assert_eq!(
            o.proxy_for("http", "x.kz", 80),
            Some("http://web:80".to_owned())
        );
        assert_eq!(
            o.proxy_for("https", "x.kz", 443),
            Some("http://secure:8443".to_owned())
        );
        // A scheme without an entry goes directly.
        let o = options("https=secure:8443", None);
        assert_eq!(o.proxy_for("http", "x.kz", 80), None);
        assert_eq!(options("http=", None).proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn bypass_list_skips_the_proxy() {
        let o = options("p:1", Some("<local>;*.gov.kz; 10.0.*;EXACT.example"));
        assert_eq!(o.proxy_for("http", "intranet", 80), None);
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz", 80), None);
        assert_eq!(o.proxy_for("http", "10.0.3.4", 80), None);
        assert_eq!(o.proxy_for("http", "exact.example", 80), None);
        let proxy = Some("http://p:1".to_owned());
        assert_eq!(o.proxy_for("http", "gov.kz.evil.com", 80), proxy);
        assert_eq!(o.proxy_for("http", "sub.exact.example", 80), proxy);
        assert_eq!(o.proxy_for("http", "10.1.0.4", 80), proxy);
        // `<local>` is about names: an IPv6 address has no dot but is not one.
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 80), proxy);
    }

    #[test]
    fn bypass_patterns_with_scheme_and_port() {
        let o = options(
            "p:1",
            Some("http://*.corp; *.svc:8080; [2001:db8::1]:81; 2001:db8::2"),
        );
        let proxy = Some("http://p:1".to_owned());
        assert_eq!(o.proxy_for("http", "a.corp", 80), None);
        assert_eq!(o.proxy_for("https", "a.corp", 443), proxy);
        assert_eq!(o.proxy_for("http", "a.svc", 8080), None);
        assert_eq!(o.proxy_for("http", "a.svc", 80), proxy);
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 81), None);
        assert_eq!(o.proxy_for("http", "[2001:db8::1]", 80), proxy);
        // A bare IPv6 address: its last group is not a port.
        assert_eq!(o.proxy_for("http", "2001:db8::2", 80), None);
    }

    #[test]
    fn loopback_bypasses_unless_listed() {
        let o = options("p:1", None);
        for host in ["localhost", "LocalHost", "127.0.0.1", "127.8.9.10", "[::1]"] {
            assert_eq!(o.proxy_for("http", host, 80), None, "{host}");
        }
        assert_eq!(
            o.proxy_for("http", "localhost.kz", 80),
            Some("http://p:1".to_owned())
        );
        let o = options("p:1", Some("*.kz; <-Loopback>"));
        assert_eq!(
            o.proxy_for("http", "127.0.0.1", 80),
            Some("http://p:1".to_owned())
        );
        assert_eq!(o.proxy_for("http", "x.kz", 80), None);
    }

    #[test]
    fn wildcards() {
        let m = |p: &str, t: &str| wildcard_match(p.as_bytes(), t.as_bytes());
        assert!(m("*", ""));
        assert!(m("a*c", "abbbc"));
        assert!(m("*.kz", "a.b.kz"));
        assert!(m("a**", "a"));
        assert!(m("*b*b", "abab"));
        assert!(!m("a*c", "abcd"));
        assert!(!m("", "a"));
        assert!(!m("*.kz", "kz"));
    }
}
