//! URLs as the original's plugins resolved them, and origins.

use url::Url;

/// `new URL(new URL(base), spec).toString()`: an absolute `spec` wins, a relative one is
/// resolved against `base` (`..` and `.` segments removed, `base`'s query kept for an empty
/// `spec`, its fragment dropped). WHATWG parsing (the `url` crate) stands in for
/// `java.net.URL`'s: they agree on the URLs sites send.
///
/// # Errors
///
/// Java's `MalformedURLException` message: `no protocol: <base>` for a `base` that is not an
/// absolute URL, `unknown protocol: <scheme>` for other schemes than `http`/`https`, else
/// the parser's complaint.
pub fn resolve_like_java_url(base: &str, spec: &str) -> Result<String, String> {
    let base = Url::parse(base).map_err(|_| format!("no protocol: {base}"))?;
    let url = base.join(spec).map_err(|e| e.to_string())?;
    match url.scheme() {
        "http" | "https" => Ok(url.to_string()),
        scheme => Err(format!("unknown protocol: {scheme}")),
    }
}

/// Whether `a` and `b` have the same origin: scheme, host and port (the scheme's default
/// port when none is written). Not URLs: `false`.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str().is_some()
                && a.host_str() == b.host_str()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_url_resolution() {
        let base = "https://k2.example.kz/app/page?x=1#top";
        assert_eq!(
            resolve_like_java_url(base, "upload").unwrap(),
            "https://k2.example.kz/app/upload"
        );
        assert_eq!(
            resolve_like_java_url(base, "/fileDownloadServlet?fileId=4368").unwrap(),
            "https://k2.example.kz/fileDownloadServlet?fileId=4368"
        );
        assert_eq!(
            resolve_like_java_url(base, "../a/./b").unwrap(),
            "https://k2.example.kz/a/b"
        );
        assert_eq!(
            resolve_like_java_url(base, "https://other.kz/x").unwrap(),
            "https://other.kz/x"
        );
        assert_eq!(
            resolve_like_java_url(base, "").unwrap(),
            "https://k2.example.kz/app/page?x=1"
        );
        assert_eq!(
            resolve_like_java_url("https://k2.example.kz", "u").unwrap(),
            "https://k2.example.kz/u"
        );
        assert_eq!(
            resolve_like_java_url("null", "u").unwrap_err(),
            "no protocol: null"
        );
        assert_eq!(
            resolve_like_java_url(base, "file:///etc/passwd").unwrap_err(),
            "unknown protocol: file"
        );
    }

    #[test]
    fn origins() {
        assert!(same_origin("https://a.kz", "https://a.kz:443/x"));
        assert!(!same_origin("https://a.kz", "http://a.kz"));
        assert!(!same_origin("https://a.kz", "https://a.kz:8443"));
        assert!(!same_origin("https://a.kz", "https://b.a.kz"));
        assert!(!same_origin("data:x", "data:x"));
    }
}
