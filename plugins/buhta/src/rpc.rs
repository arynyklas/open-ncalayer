//! The messages of `rpc.proto` (package `buhta.cert.ncamodule.rpc.v1alpha1`) for `prost`,
//! with their `JsonFormat` form ([`Json`]).

use crate::json::{self, Json, Printer, Read};
use oncl_pdk::serde_json::{Map, Value};

#[derive(Clone, PartialEq, prost::Message)]
pub struct Metadata {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

impl Json for Metadata {
    fn print(&self, p: &mut Printer) {
        if !self.name.is_empty() {
            p.string("name", &self.name);
        }
        if !self.value.is_empty() {
            p.string("value", &self.value);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "name", "name")? {
            self.name = json::string(v)?;
        }
        if let Some(v) = json::field(obj, "value", "value")? {
            self.value = json::string(v)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct XmlDocument {
    #[prost(string, tag = "1")]
    pub data: String,
}

impl Json for XmlDocument {
    fn print(&self, p: &mut Printer) {
        if !self.data.is_empty() {
            p.string("data", &self.data);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "data", "data")? {
            self.data = json::string(v)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct FileDocument {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
    #[prost(string, optional, tag = "2")]
    pub name: Option<String>,
    #[prost(string, optional, tag = "3")]
    pub mime_type: Option<String>,
    #[prost(bool, tag = "4")]
    pub attached: bool,
}

impl Json for FileDocument {
    fn print(&self, p: &mut Printer) {
        if !self.data.is_empty() {
            p.bytes("data", &self.data);
        }
        if let Some(name) = &self.name {
            p.string("name", name);
        }
        if let Some(mime_type) = &self.mime_type {
            p.string("mimeType", mime_type);
        }
        if self.attached {
            p.boolean("attached", true);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "data", "data")? {
            self.data = json::bytes(v)?;
        }
        if let Some(v) = json::field(obj, "name", "name")? {
            self.name = Some(json::string(v)?);
        }
        if let Some(v) = json::field(obj, "mimeType", "mime_type")? {
            self.mime_type = Some(json::string(v)?);
        }
        if let Some(v) = json::field(obj, "attached", "attached")? {
            self.attached = json::boolean(v)?;
        }
        Ok(())
    }
}

/// The `content` oneof of [`Signable`] and [`SignedDocument`].
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Content {
    #[prost(message, tag = "3")]
    Xml(XmlDocument),
    #[prost(message, tag = "4")]
    File(FileDocument),
}

fn print_content(content: Option<&Content>, p: &mut Printer) {
    match content {
        Some(Content::Xml(xml)) => p.message_field("xml", xml),
        Some(Content::File(file)) => p.message_field("file", file),
        None => {}
    }
}

fn merge_content(obj: &Map<String, Value>, content: &mut Option<Content>) -> Read<()> {
    let xml = json::field(obj, "xml", "xml")?;
    let file = json::field(obj, "file", "file")?;
    *content = match (xml, file) {
        (Some(_), Some(_)) => return Err(json::Invalid),
        (Some(v), None) => Some(Content::Xml(json::message(v)?)),
        (None, Some(v)) => Some(Content::File(json::message(v)?)),
        (None, None) => content.take(),
    };
    Ok(())
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Signable {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(message, repeated, tag = "2")]
    pub meta: Vec<Metadata>,
    #[prost(oneof = "Content", tags = "3, 4")]
    pub content: Option<Content>,
}

impl Json for Signable {
    fn print(&self, p: &mut Printer) {
        if let Some(id) = &self.id {
            p.string("id", id);
        }
        if !self.meta.is_empty() {
            p.repeated("meta", &self.meta);
        }
        print_content(self.content.as_ref(), p);
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "id", "id")? {
            self.id = Some(json::string(v)?);
        }
        if let Some(v) = json::field(obj, "meta", "meta")? {
            self.meta.extend(json::repeated::<Metadata>(v)?);
        }
        merge_content(obj, &mut self.content)
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignedDocument {
    #[prost(string, optional, tag = "1")]
    pub id: Option<String>,
    #[prost(oneof = "Content", tags = "3, 4")]
    pub content: Option<Content>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub x509_cert: Option<Vec<u8>>,
}

impl Json for SignedDocument {
    fn print(&self, p: &mut Printer) {
        if let Some(id) = &self.id {
            p.string("id", id);
        }
        print_content(self.content.as_ref(), p);
        if let Some(cert) = &self.x509_cert {
            p.bytes("x509Cert", cert);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "id", "id")? {
            self.id = Some(json::string(v)?);
        }
        merge_content(obj, &mut self.content)?;
        if let Some(v) = json::field(obj, "x509Cert", "x509_cert")? {
            self.x509_cert = Some(json::bytes(v)?);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignCert {
    #[prost(string, tag = "1")]
    pub cert: String,
}

impl Json for SignCert {
    fn print(&self, p: &mut Printer) {
        if !self.cert.is_empty() {
            p.string("cert", &self.cert);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "cert", "cert")? {
            self.cert = json::string(v)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SelectSignCertArgs {
    #[prost(string, optional, tag = "1")]
    pub tin: Option<String>,
}

impl Json for SelectSignCertArgs {
    fn print(&self, p: &mut Printer) {
        if let Some(tin) = &self.tin {
            p.string("tin", tin);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "tin", "tin")? {
            self.tin = Some(json::string(v)?);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SelectSignCertResult {
    #[prost(message, optional, tag = "1")]
    pub cert: Option<SignCert>,
}

impl Json for SelectSignCertResult {
    fn print(&self, p: &mut Printer) {
        if let Some(cert) = &self.cert {
            p.message_field("cert", cert);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "cert", "cert")? {
            self.cert = Some(json::message(v)?);
        }
        Ok(())
    }
}

/// The `sign` oneof of [`SignDocumentArgs`] and [`BulkSignDocumentArgs`]: a key selected
/// before, or the conditions to select one now.
#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Sign {
    #[prost(string, tag = "1")]
    SignCert(String),
    #[prost(message, tag = "2")]
    SignCertArgs(SelectSignCertArgs),
}

fn print_sign(sign: Option<&Sign>, p: &mut Printer) {
    match sign {
        Some(Sign::SignCert(cert)) => p.string("signCert", cert),
        Some(Sign::SignCertArgs(args)) => p.message_field("signCertArgs", args),
        None => {}
    }
}

fn merge_sign(obj: &Map<String, Value>, sign: &mut Option<Sign>) -> Read<()> {
    let cert = json::field(obj, "signCert", "sign_cert")?;
    let args = json::field(obj, "signCertArgs", "sign_cert_args")?;
    *sign = match (cert, args) {
        (Some(_), Some(_)) => return Err(json::Invalid),
        (Some(v), None) => Some(Sign::SignCert(json::string(v)?)),
        (None, Some(v)) => Some(Sign::SignCertArgs(json::message(v)?)),
        (None, None) => sign.take(),
    };
    Ok(())
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignDocumentArgs {
    #[prost(oneof = "Sign", tags = "1, 2")]
    pub sign: Option<Sign>,
    #[prost(message, optional, tag = "3")]
    pub document: Option<Signable>,
    #[prost(bool, tag = "6")]
    pub include_x509: bool,
}

impl Json for SignDocumentArgs {
    fn print(&self, p: &mut Printer) {
        print_sign(self.sign.as_ref(), p);
        if let Some(document) = &self.document {
            p.message_field("document", document);
        }
        if self.include_x509 {
            p.boolean("includeX509", true);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        merge_sign(obj, &mut self.sign)?;
        if let Some(v) = json::field(obj, "document", "document")? {
            self.document = Some(json::message(v)?);
        }
        if let Some(v) = json::field(obj, "includeX509", "include_x509")? {
            self.include_x509 = json::boolean(v)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BulkSignDocumentArgs {
    #[prost(oneof = "Sign", tags = "1, 2")]
    pub sign: Option<Sign>,
    #[prost(message, repeated, tag = "3")]
    pub documents: Vec<Signable>,
    #[prost(bool, tag = "4")]
    pub include_x509: bool,
}

impl Json for BulkSignDocumentArgs {
    fn print(&self, p: &mut Printer) {
        print_sign(self.sign.as_ref(), p);
        if !self.documents.is_empty() {
            p.repeated("documents", &self.documents);
        }
        if self.include_x509 {
            p.boolean("includeX509", true);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        merge_sign(obj, &mut self.sign)?;
        if let Some(v) = json::field(obj, "documents", "documents")? {
            self.documents.extend(json::repeated::<Signable>(v)?);
        }
        if let Some(v) = json::field(obj, "includeX509", "include_x509")? {
            self.include_x509 = json::boolean(v)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SignDocumentResult {
    #[prost(message, optional, tag = "1")]
    pub document: Option<SignedDocument>,
}

impl Json for SignDocumentResult {
    fn print(&self, p: &mut Printer) {
        if let Some(document) = &self.document {
            p.message_field("document", document);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "document", "document")? {
            self.document = Some(json::message(v)?);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct BulkSignDocumentResult {
    #[prost(message, repeated, tag = "1")]
    pub documents: Vec<SignedDocument>,
}

impl Json for BulkSignDocumentResult {
    fn print(&self, p: &mut Printer) {
        if !self.documents.is_empty() {
            p.repeated("documents", &self.documents);
        }
    }

    fn merge(&mut self, obj: &Map<String, Value>) -> Read<()> {
        if let Some(v) = json::field(obj, "documents", "documents")? {
            self.documents.extend(json::repeated::<SignedDocument>(v)?);
        }
        Ok(())
    }
}
