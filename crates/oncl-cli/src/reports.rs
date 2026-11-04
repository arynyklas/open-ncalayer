//! Serialization borrows the admitted SDK owners; it never clones report trees.
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use std::fmt;

pub struct DebugText<T>(pub T);
impl<T: fmt::Debug> Serialize for DebugText<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        struct DisplayDebug<'a, T>(&'a T);
        impl<T: fmt::Debug> fmt::Display for DisplayDebug<'_, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(self.0, f)
            }
        }
        serializer.collect_str(&DisplayDebug(&self.0))
    }
}
pub struct Hex<'a>(pub &'a [u8]);
impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}
pub fn verdict(value: oncl_pki::validation::Verdict) -> (&'static str, i32) {
    use oncl_pki::validation::Verdict::*;
    match value {
        Valid => ("Valid", 0),
        Invalid => ("Invalid", 2),
        Indeterminate => ("Indeterminate", 3),
    }
}
#[derive(Serialize)]
pub struct Hash<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: &'static str,
    pub digest: Hex<'a>,
    pub bytes_in: u64,
}
#[derive(Serialize)]
pub struct Written<'a> {
    pub operation_id: u64,
    pub code: &'static str,
    pub applied: DebugText<oncl_core::keys::AppliedState>,
    pub profile: DebugText<oncl_core::SignProfile>,
    pub provenance: DebugText<oncl_core::SignProvenance>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub signer_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xml: Option<DebugText<&'a oncl_xml::XmlVerification>>,
}
impl<'a> From<&'a oncl_core::OperationReport> for Written<'a> {
    fn from(r: &'a oncl_core::OperationReport) -> Self {
        Self {
            operation_id: r.id.get(),
            code: "Completed",
            applied: DebugText(r.applied),
            profile: DebugText(r.profile),
            provenance: DebugText(r.provenance),
            bytes_in: r.bytes_in,
            bytes_out: r.bytes_out,
            signer_count: r.signer_count(),
            xml: r.xml().map(DebugText),
        }
    }
}
pub struct Verification<'a>(pub &'a oncl_core::VerificationReport);
impl Serialize for Verification<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let r = self.0;
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("operation_id", &r.id.get())?;
        m.serialize_entry("code", "Completed")?;
        m.serialize_entry("applied", "NotApplied")?;
        m.serialize_entry("verdict", verdict(r.verdict).0)?;
        m.serialize_entry("policy", &DebugText(r.policy))?;
        m.serialize_entry("checked_at", &r.checked_at.unix_timestamp())?;
        m.serialize_entry("ades_level", &r.ades_level.map(DebugText))?;
        m.serialize_entry("signers", &Signers(&r.signers))?;
        if let Some(xml) = &r.xml {
            m.serialize_entry("xml", &DebugText(xml))?;
        }
        if let Some(pdf) = &r.pdf {
            m.serialize_entry("pdf", &DebugText(pdf))?;
        }
        m.end()
    }
}
struct Signers<'a>(&'a [oncl_pki::validation::SignerValidation]);
impl Serialize for Signers<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for signer in self.0 {
            sequence.serialize_element(&Signer(signer))?;
        }
        sequence.end()
    }
}
pub(crate) struct Signer<'a>(pub(crate) &'a oncl_pki::validation::SignerValidation);
impl Serialize for Signer<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("signature", &DebugText(s.signature))?;
        m.serialize_entry("chain", &DebugText(s.chain))?;
        m.serialize_entry("validity", &DebugText(s.validity))?;
        m.serialize_entry("revocation", &DebugText(s.revocation))?;
        m.serialize_entry("timestamp", &DebugText(s.timestamp))?;
        m.serialize_entry("key_usage", &DebugText(s.key_usage))?;
        m.serialize_entry("time_basis", &DebugText(s.time_basis))?;
        m.serialize_entry(
            "claimed_signing_time",
            &s.claimed_signing_time.map(|t| t.unix_timestamp()),
        )?;
        m.serialize_entry("ades_level", &s.ades_level.map(DebugText))?;
        m.serialize_entry("reasons", &DebugText(&s.reasons))?;
        m.end()
    }
}
pub struct Inspection<'a>(pub &'a oncl_core::InspectionReport);
impl Serialize for Inspection<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let r = self.0;
        let mut m = serializer.serialize_map(None)?;
        m.serialize_entry("operation_id", &r.id().get())?;
        m.serialize_entry("code", "Completed")?;
        m.serialize_entry("applied", "NotApplied")?;
        m.serialize_entry("kind", &DebugText(r.kind()))?;
        m.serialize_entry(
            "container_integrity",
            &r.container_integrity().map(DebugText),
        )?;
        m.serialize_entry("entries", &Entries(r.entries()))?;
        if let Some(cms) = r.cms() {
            m.serialize_entry("cms", &DebugText(cms))?;
        }
        m.end()
    }
}
struct Entries<'a>(&'a [oncl_pki::info::PublicEntry]);
impl Serialize for Entries<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Entry<'a> {
            alias: Option<&'a str>,
            certificate_sha256: Option<Hex<'a>>,
            subject_cn: Option<&'a str>,
            serial_hex: Option<&'a str>,
            signature_algorithm_oid: Option<&'a str>,
            public_key_algorithm_oid: Option<&'a str>,
            not_before: Option<i64>,
            not_after: Option<i64>,
        }
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for e in self.0 {
            seq.serialize_element(&Entry {
                alias: e.alias(),
                certificate_sha256: e.fingerprint().map(|d| Hex(d.as_bytes())),
                subject_cn: e.subject_cn(),
                serial_hex: e.serial_hex(),
                signature_algorithm_oid: e.signature_algorithm_oid(),
                public_key_algorithm_oid: e.public_key_algorithm_oid(),
                not_before: e.not_before().map(|t| t.unix_timestamp()),
                not_after: e.not_after().map(|t| t.unix_timestamp()),
            })?;
        }
        seq.end()
    }
}
