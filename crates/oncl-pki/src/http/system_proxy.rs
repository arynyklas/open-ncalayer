//! The system's proxy of [`ProxySetting::System`](super::ProxySetting::System).

use ureq::Proxy;

/// The system's proxy for a request to `url`: the environment's (`ureq` itself skips the
/// hosts of `NO_PROXY`), otherwise on Windows the manual proxy of the Internet Options
/// unless `url`'s host is in their bypass list. `None`: connect directly.
pub(super) fn for_url(url: &str) -> Option<Proxy> {
    Proxy::try_from_env().or_else(|| os_proxy(url))
}

#[cfg(windows)]
fn os_proxy(url: &str) -> Option<Proxy> {
    let uri = url.parse::<ureq::http::Uri>().ok()?;
    let options = windows::internet_options()?;
    let proxy = options.proxy_for(uri.scheme_str()?, uri.host()?)?;
    Proxy::new(&proxy).ok()
}

#[cfg(not(windows))]
fn os_proxy(_url: &str) -> Option<Proxy> {
    None
}

/// The manual proxy of the Windows Internet Options, when it is on.
#[cfg_attr(not(windows), allow(dead_code))]
struct InternetOptions {
    /// `ProxyServer`: `host:port` for every scheme, or `scheme=host:port` entries separated
    /// by `;`.
    server: String,
    /// `ProxyOverride`: host patterns separated by `;`, `*` matching any characters;
    /// `<local>` stands for every host name without a dot, `<-loopback>` sends loopback
    /// requests through the proxy too.
    bypass: Option<String>,
}

#[cfg_attr(not(windows), allow(dead_code))]
impl InternetOptions {
    /// The proxy URL for a request with `scheme` to `host`; `None` if the request bypasses
    /// the proxy (loopback hosts do, as in Windows, unless `<-loopback>` is listed) or no
    /// entry covers `scheme` (SOCKS entries are not used).
    fn proxy_for(&self, scheme: &str, host: &str) -> Option<String> {
        let bypass = self.bypass.as_deref().unwrap_or_default();
        let proxied_loopback = bypass
            .split(';')
            .any(|p| p.trim().eq_ignore_ascii_case("<-loopback>"));
        if (loopback(host) && !proxied_loopback) || bypassed(bypass, host) {
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
/// HTTP proxies, `https=` included: HTTPS goes through them as a tunnel).
#[cfg_attr(not(windows), allow(dead_code))]
fn with_scheme(proxy: &str) -> String {
    if proxy.contains("://") {
        proxy.to_owned()
    } else {
        format!("http://{proxy}")
    }
}

/// Whether `host` matches a pattern of the `ProxyOverride` list `bypass`, ignoring case.
#[cfg_attr(not(windows), allow(dead_code))]
fn bypassed(bypass: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    bypass
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .any(|p| {
            if p.eq_ignore_ascii_case("<local>") {
                !host.contains('.')
            } else {
                wildcard_match(p.to_ascii_lowercase().as_bytes(), host.as_bytes())
            }
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

/// The Internet Options in `HKCU`, read only.
#[cfg(windows)]
mod windows {
    use super::InternetOptions;
    use std::iter::once;
    use std::ptr;
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY_CURRENT_USER, RRF_RT_DWORD, RRF_RT_REG_SZ, RegGetValueW,
    };

    const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    /// The manual proxy, if `ProxyEnable` is set and `ProxyServer` names one.
    pub(super) fn internet_options() -> Option<InternetOptions> {
        if dword("ProxyEnable")? == 0 {
            return None;
        }
        Some(InternetOptions {
            server: string("ProxyServer")?,
            bypass: string("ProxyOverride"),
        })
    }

    /// `s` as a NUL-terminated UTF-16 string.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(once(0)).collect()
    }

    /// The DWORD value `name` of [`KEY`].
    fn dword(name: &str) -> Option<u32> {
        let (key, name) = (wide(KEY), wide(name));
        let mut value = 0u32;
        let mut size = 4u32;
        // SAFETY: `key` and `name` are NUL-terminated; `value` holds the `size` bytes of a
        // DWORD.
        let status = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_DWORD,
                ptr::null_mut(),
                (&raw mut value).cast(),
                &mut size,
            )
        };
        (status == ERROR_SUCCESS).then_some(value)
    }

    /// The string value `name` of [`KEY`].
    fn string(name: &str) -> Option<String> {
        let (key, name) = (wide(KEY), wide(name));
        let mut buf: Vec<u16> = Vec::new();
        loop {
            let mut size = u32::try_from(buf.len() * 2).unwrap_or(u32::MAX);
            let data = if buf.is_empty() {
                ptr::null_mut()
            } else {
                buf.as_mut_ptr().cast()
            };
            // SAFETY: `key` and `name` are NUL-terminated; `data` is null (size query) or
            // `buf`, whose size in bytes `size` holds.
            let status = unsafe {
                RegGetValueW(
                    HKEY_CURRENT_USER,
                    key.as_ptr(),
                    name.as_ptr(),
                    RRF_RT_REG_SZ,
                    ptr::null_mut(),
                    data,
                    &mut size,
                )
            };
            match status {
                ERROR_SUCCESS if !buf.is_empty() => {
                    // `size` counts the bytes written, the terminating NUL included.
                    buf.truncate(size as usize / 2);
                    while buf.last() == Some(&0) {
                        buf.pop();
                    }
                    return String::from_utf16(&buf).ok();
                }
                // The size query, or the value grew since it.
                ERROR_SUCCESS | ERROR_MORE_DATA => {
                    buf = vec![0; (size as usize).div_ceil(2).max(1)];
                }
                _ => return None,
            }
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
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz"), proxy);
        assert_eq!(o.proxy_for("https", "tsp.pki.gov.kz"), proxy);
        assert_eq!(
            options("https://proxy.corp:443", None).proxy_for("http", "x.kz"),
            Some("https://proxy.corp:443".to_owned())
        );
        assert_eq!(options(" ; ", None).proxy_for("http", "x.kz"), None);
    }

    #[test]
    fn per_scheme_entries_pick_the_request_scheme() {
        let o = options("HTTP=web:80; https=secure:8443;ftp=f:21;socks=s:1080", None);
        assert_eq!(
            o.proxy_for("http", "x.kz"),
            Some("http://web:80".to_owned())
        );
        assert_eq!(
            o.proxy_for("https", "x.kz"),
            Some("http://secure:8443".to_owned())
        );
        // A scheme without an entry goes directly.
        let o = options("https=secure:8443", None);
        assert_eq!(o.proxy_for("http", "x.kz"), None);
        assert_eq!(options("http=", None).proxy_for("http", "x.kz"), None);
    }

    #[test]
    fn bypass_list_skips_the_proxy() {
        let o = options("p:1", Some("<local>;*.gov.kz; 10.0.*;EXACT.example"));
        assert_eq!(o.proxy_for("http", "intranet"), None);
        assert_eq!(o.proxy_for("http", "tsp.pki.gov.kz"), None);
        assert_eq!(o.proxy_for("http", "10.0.3.4"), None);
        assert_eq!(o.proxy_for("http", "exact.example"), None);
        let proxy = Some("http://p:1".to_owned());
        assert_eq!(o.proxy_for("http", "gov.kz.evil.com"), proxy);
        assert_eq!(o.proxy_for("http", "sub.exact.example"), proxy);
        assert_eq!(o.proxy_for("http", "10.1.0.4"), proxy);
    }

    #[test]
    fn loopback_bypasses_unless_listed() {
        let o = options("p:1", None);
        for host in ["localhost", "LocalHost", "127.0.0.1", "127.8.9.10", "[::1]"] {
            assert_eq!(o.proxy_for("http", host), None, "{host}");
        }
        assert_eq!(
            o.proxy_for("http", "localhost.kz"),
            Some("http://p:1".to_owned())
        );
        let o = options("p:1", Some("*.kz; <-Loopback>"));
        assert_eq!(
            o.proxy_for("http", "127.0.0.1"),
            Some("http://p:1".to_owned())
        );
        assert_eq!(o.proxy_for("http", "x.kz"), None);
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
