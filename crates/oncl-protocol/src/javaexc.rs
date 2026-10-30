//! Java exceptions as the original's replies print them: `toString()` is the class name, then
//! `: ` and the message if there is one.

use std::fmt;

/// A `java.lang.Throwable`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Throwable {
    /// The fully qualified class name: `java.lang.NullPointerException`.
    pub class: String,
    /// `getMessage()`.
    pub message: Option<String>,
    /// `getCause()`.
    pub cause: Option<Box<Throwable>>,
}

impl Throwable {
    /// An exception of `class` with `message`.
    pub fn new(class: impl Into<String>, message: Option<String>) -> Throwable {
        Throwable {
            class: class.into(),
            message,
            cause: None,
        }
    }

    /// An exception of `class` made from `cause` alone (`new RuntimeException(cause)`): its
    /// message is the cause's `toString()`.
    pub fn wrapping(class: impl Into<String>, cause: Throwable) -> Throwable {
        Throwable {
            class: class.into(),
            message: Some(cause.to_string()),
            cause: Some(Box::new(cause)),
        }
    }

    /// The same exception with `cause`.
    #[must_use]
    pub fn with_cause(self, cause: Throwable) -> Throwable {
        Throwable {
            cause: Some(Box::new(cause)),
            ..self
        }
    }

    /// The last of the causes, or this exception if it has none.
    pub fn deepest(&self) -> &Throwable {
        let mut t = self;
        while let Some(cause) = &t.cause {
            t = cause;
        }
        t
    }

    /// `org.json.JSONException` with `message`.
    pub fn json(message: impl Into<String>) -> Throwable {
        Throwable::new("org.json.JSONException", Some(message.into()))
    }

    /// `java.lang.NullPointerException`, without a message.
    pub fn npe() -> Throwable {
        Throwable::new("java.lang.NullPointerException", None)
    }

    /// `java.lang.IllegalArgumentException` with `message`.
    pub fn iae(message: impl Into<String>) -> Throwable {
        Throwable::new("java.lang.IllegalArgumentException", Some(message.into()))
    }

    /// `java.net.UnknownHostException` of `host`.
    pub fn unknown_host(host: impl Into<String>) -> Throwable {
        Throwable::new("java.net.UnknownHostException", Some(host.into()))
    }

    /// `java.net.SocketTimeoutException`: `Read timed out`, or `connect timed out`.
    pub fn socket_timeout(read: bool) -> Throwable {
        let message = if read {
            "Read timed out"
        } else {
            "connect timed out"
        };
        Throwable::new("java.net.SocketTimeoutException", Some(message.to_owned()))
    }

    /// `java.net.ConnectException` of a refused connection, as Java 8 on Windows words it.
    pub fn connect_refused() -> Throwable {
        Throwable::new(
            "java.net.ConnectException",
            Some("Connection refused: connect".to_owned()),
        )
    }
}

/// `toString()`: `class`, or `class: message`.
impl fmt::Display for Throwable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{}: {message}", self.class),
            None => f.write_str(&self.class),
        }
    }
}

impl std::error::Error for Throwable {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_string_is_class_and_message() {
        assert_eq!(
            Throwable::npe().to_string(),
            "java.lang.NullPointerException"
        );
        assert_eq!(
            Throwable::iae("Supported apiVersion is 2").to_string(),
            "java.lang.IllegalArgumentException: Supported apiVersion is 2"
        );
        let wrapped = Throwable::wrapping(
            "java.lang.RuntimeException",
            Throwable::new(
                "java.security.cert.CertificateExpiredException",
                Some("NotAfter".to_owned()),
            ),
        );
        assert_eq!(
            wrapped.to_string(),
            "java.lang.RuntimeException: java.security.cert.CertificateExpiredException: NotAfter"
        );
        assert_eq!(
            wrapped.deepest().class,
            "java.security.cert.CertificateExpiredException"
        );
        assert_eq!(
            Throwable::socket_timeout(true).to_string(),
            "java.net.SocketTimeoutException: Read timed out"
        );
        assert_eq!(
            Throwable::unknown_host("tsp.pki.gov.kz").to_string(),
            "java.net.UnknownHostException: tsp.pki.gov.kz"
        );
    }
}
