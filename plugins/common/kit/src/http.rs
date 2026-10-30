//! HTTP bodies as the original's plugins wrote them by hand.

/// A part of a [`Multipart`] body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The `Content-Disposition` line after `Content-Disposition: `, as the plugin wrote it:
    /// `form-data; name="k"`, or `form-data;name="file"; filename="x.zip"`.
    pub disposition: String,
    /// `Content-Type`, if the part has one.
    pub content_type: Option<String>,
    /// The part's data.
    pub data: Vec<u8>,
}

impl Part {
    /// A form field: `form-data; name="<name>"`.
    pub fn field(name: &str, value: &str) -> Part {
        Part {
            disposition: format!("form-data; name=\"{name}\""),
            content_type: None,
            data: value.as_bytes().to_vec(),
        }
    }
}

/// A `multipart/form-data` body: each part `--<boundary>\r\n`, its headers, an empty line,
/// its data and `\r\n`; then `--<boundary>--\r\n`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multipart {
    /// The boundary as the `Content-Type` header names it.
    pub boundary: String,
    /// The parts in order.
    pub parts: Vec<Part>,
}

impl Multipart {
    /// The `Content-Type` header: `multipart/form-data; boundary=<boundary>`.
    pub fn content_type(&self) -> String {
        format!("multipart/form-data; boundary={}", self.boundary)
    }

    /// The body.
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for part in &self.parts {
            out.extend_from_slice(format!("--{}\r\n", self.boundary).as_bytes());
            out.extend_from_slice(
                format!("Content-Disposition: {}\r\n", part.disposition).as_bytes(),
            );
            if let Some(content_type) = &part.content_type {
                out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
            }
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(&part.data);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{}--\r\n", self.boundary).as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_byte_layout() {
        let body = Multipart {
            boundary: "---------------------------24464570528145".to_owned(),
            parts: vec![
                Part::field("sessionId", "s1"),
                Part {
                    disposition: "form-data;name=\"file\"; filename=\"a.zip\"".to_owned(),
                    content_type: Some("application/zip".to_owned()),
                    data: b"PK".to_vec(),
                },
            ],
        };
        assert_eq!(
            String::from_utf8(body.body()).unwrap(),
            "-----------------------------24464570528145\r\n\
             Content-Disposition: form-data; name=\"sessionId\"\r\n\r\ns1\r\n\
             -----------------------------24464570528145\r\n\
             Content-Disposition: form-data;name=\"file\"; filename=\"a.zip\"\r\n\
             Content-Type: application/zip\r\n\r\nPK\r\n\
             -----------------------------24464570528145--\r\n"
        );
        assert_eq!(
            body.content_type(),
            "multipart/form-data; boundary=---------------------------24464570528145"
        );
    }
}
