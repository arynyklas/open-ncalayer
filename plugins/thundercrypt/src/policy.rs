//! Which certificates may sign: the `certPolicy` tree of the V2 requests and the
//! permission rule of the legacy ones, on the signer's certificate.

use oncl_pdk::orgjson;
use oncl_pdk::serde_json::{Map, Value};

/// The deepest `certPolicy` tree.
const MAX_DEPTH: usize = 10;

/// The NCA's extended key usages a policy names.
const EKUS: [(&str, &str); 6] = [
    ("EMAIL_PROTECTION", "1.3.6.1.5.5.7.3.4"),
    ("PERSON", "1.2.398.3.3.4.1.1"),
    ("EMPLOYEE", "1.2.398.3.3.4.1.2"),
    ("TOP_HEAD", "1.2.398.3.3.4.1.2.1"),
    ("EMPLOYEE_WITH_SIGN_PERM", "1.2.398.3.3.4.1.2.2"),
    ("EMPLOYEE_OF_ORGANIZATION", "1.2.398.3.3.4.1.2.5"),
];

/// The key usage bits a policy names (the original's spellings), by bit index.
const KEY_USAGES: [&str; 9] = [
    "DIGITAL_SIGNATURE_PERMISSION_INDEX",
    "NON_REPUDIATION_PERMISSION_INDEX",
    "KEY_EENCIPHERMENT_PERMISSION_INDEX",
    "DATA_EENCIPHERMENT_PERMISSION_INDEX",
    "KEY_AGREEMENT_PERMISSION_INDEX",
    "KEY_CERT_SIGN_PERMISSION_INDEX",
    "CRL_SIGN_EENCIPHERMENT_PERMISSION_INDEX",
    "ENCIPHER_ONLY_PERMISSION_INDEX",
    "DECIPHER_ONLY_PERMISSION_INDEX",
];

/// The issuers whose certificates count as authentication ones and skip the legacy
/// permission rule: the TTC CA and the CA of the state bodies.
const SPECIAL_ISSUERS: [&str; 2] = [
    "C=KZ, O=TTC, CN=PKI",
    "CN=Удостоверяющий центр Государственных органов,O=Республика Казахстан,C=KZ",
];

/// What a policy looks at in the signer's certificate.
pub struct CertFacts {
    /// The keyUsage bits, by index.
    pub key_usage: [bool; 9],
    /// The extended key usage OIDs.
    pub ekus: Vec<String>,
    /// The signature algorithm OID.
    pub sig_alg: String,
    /// The issuer, as `X500Principal.toString()` and as RFC 2253.
    pub issuer: [String; 2],
}

impl CertFacts {
    fn special_issuer(&self) -> bool {
        self.issuer
            .iter()
            .any(|dn| SPECIAL_ISSUERS.contains(&dn.as_str()))
    }

    /// The purpose `SIGN` (digitalSignature and nonRepudiation) or `AUTH`
    /// (digitalSignature and keyEncipherment, a GOST 2015-512 signature, or a special issuer).
    fn has_purpose(&self, purpose: Purpose) -> bool {
        match purpose {
            Purpose::Sign => self.key_usage[0] && self.key_usage[1],
            Purpose::Auth => {
                (self.key_usage[0] && self.key_usage[2])
                    || self.sig_alg == "1.2.398.3.10.1.1.2.3.2"
                    || self.special_issuer()
            }
        }
    }

    fn has_eku(&self, oid: &str) -> bool {
        self.ekus.iter().any(|e| e == oid)
    }
}

/// A certificate purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Auth,
    Sign,
}

impl Purpose {
    fn name(self) -> &'static str {
        match self {
            Purpose::Auth => "AUTH",
            Purpose::Sign => "SIGN",
        }
    }

    fn parse(name: &str) -> Option<Purpose> {
        match name {
            "AUTH" => Some(Purpose::Auth),
            "SIGN" => Some(Purpose::Sign),
            _ => None,
        }
    }
}

/// A `certPolicy` condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    Purpose(Purpose),
    Eku(&'static str, &'static str),
    KeyUsage(usize),
}

/// The kind of a failed policy, which decides the error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Purpose,
    Eku,
    KeyUsage,
    Structure,
}

impl Kind {
    /// The error code of a policy failure of this kind.
    pub fn code(self) -> &'static str {
        match self {
            Kind::Purpose => "CERTIFICATE_FOR_AUTHENTICATION",
            Kind::Eku | Kind::KeyUsage => "CERTIFICATE_NO_HAVE_PERM_FOR_SIGN",
            Kind::Structure => "CERTIFICATE_POLICY_FAILED",
        }
    }
}

/// Parses `certPolicy`: the tree, or the parser's message.
pub fn parse(value: &Value) -> Result<Cond, String> {
    parse_at(value, 1)
}

fn parse_at(value: &Value, depth: usize) -> Result<Cond, String> {
    if depth > MAX_DEPTH {
        return Err(format!("Policy tree exceeds maximum depth of {MAX_DEPTH}"));
    }
    let Some(object) = value.as_object() else {
        return Err("certPolicy must be a JSON object".to_owned());
    };
    let Some(kind) = object.get("type").and_then(Value::as_str) else {
        return Err("certPolicy field 'type' is required".to_owned());
    };
    let invalid = |e: String| format!("Invalid certPolicy: {e}");
    match kind {
        "and" | "or" => {
            let list = match object.get("conditions") {
                None | Some(Value::Null) => &[][..],
                Some(_) => orgjson::get_array(object, "conditions").map_err(invalid)?,
            };
            if list.is_empty() {
                return Err(if kind == "and" {
                    "'and' requires conditions".to_owned()
                } else {
                    "'or' requires at least one condition".to_owned()
                });
            }
            let conds = list
                .iter()
                .map(|c| parse_at(c, depth + 1))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if kind == "and" {
                Cond::And(conds)
            } else {
                Cond::Or(conds)
            })
        }
        "not" => match object.get("condition") {
            None | Some(Value::Null) => Err("'not' requires a condition".to_owned()),
            Some(_) => {
                let inner = orgjson::get_object(object, "condition").map_err(invalid)?;
                Ok(Cond::Not(Box::new(parse_at(
                    &Value::Object(inner.clone()),
                    depth + 1,
                )?)))
            }
        },
        "purpose" | "eku" | "key_usage" => {
            let value = leaf_value(object)?;
            let unsupported = || format!("Unsupported value '{value}' for {kind}");
            match kind {
                "purpose" => Purpose::parse(value)
                    .map(Cond::Purpose)
                    .ok_or_else(unsupported),
                "eku" => EKUS
                    .iter()
                    .find(|(name, _)| *name == value)
                    .map(|(name, oid)| Cond::Eku(name, oid))
                    .ok_or_else(unsupported),
                _ => KEY_USAGES
                    .iter()
                    .position(|name| *name == value)
                    .map(Cond::KeyUsage)
                    .ok_or_else(unsupported),
            }
        }
        other => Err(format!("Unsupported certPolicy type: {other}")),
    }
}

/// The `value` of a leaf condition.
fn leaf_value(object: &Map<String, Value>) -> Result<&str, String> {
    object
        .get("value")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "certPolicy field 'value' must be a non-empty string".to_owned())
}

impl Cond {
    /// The short description of the condition.
    pub fn describe(&self) -> String {
        match self {
            Cond::And(c) => format!("and({} conditions)", c.len()),
            Cond::Or(c) => format!("or({} conditions)", c.len()),
            Cond::Not(c) => format!("not({})", c.describe()),
            Cond::Purpose(p) => format!("purpose {}", p.name()),
            Cond::Eku(name, _) => format!("eku {name}"),
            Cond::KeyUsage(i) => format!("key_usage {}", KEY_USAGES[*i]),
        }
    }

    /// Whether the certificate meets the condition; why not: the failure's kind and text.
    pub fn eval(&self, cert: &CertFacts) -> Result<(), (Kind, String)> {
        match self {
            Cond::And(conds) => {
                for (i, c) in conds.iter().enumerate() {
                    c.eval(cert).map_err(|(kind, detail)| {
                        (kind, format!("and[{}/{}]: {detail}", i + 1, conds.len()))
                    })?;
                }
                Ok(())
            }
            Cond::Or(conds) => {
                let mut kinds = Vec::new();
                for c in conds {
                    match c.eval(cert) {
                        Ok(()) => return Ok(()),
                        Err((kind, _)) => kinds.push(kind),
                    }
                }
                let kind = if kinds.iter().all(|k| *k == kinds[0]) {
                    kinds[0]
                } else {
                    Kind::Structure
                };
                let described: Vec<String> = conds.iter().map(Cond::describe).collect();
                Err((
                    kind,
                    format!(
                        "or: none of the conditions matched [{}]",
                        described.join(", ")
                    ),
                ))
            }
            Cond::Not(c) => match c.eval(cert) {
                Ok(()) => Err((
                    Kind::Structure,
                    format!("not: certificate unexpectedly matches {}", c.describe()),
                )),
                Err(_) => Ok(()),
            },
            Cond::Purpose(p) => {
                if cert.has_purpose(*p) {
                    Ok(())
                } else {
                    Err((
                        Kind::Purpose,
                        format!(
                            "purpose {}: certificate does not have required purpose",
                            p.name()
                        ),
                    ))
                }
            }
            Cond::Eku(name, oid) => {
                if cert.has_eku(oid) {
                    Ok(())
                } else {
                    Err((
                        Kind::Eku,
                        format!(
                            "eku {name}: certificate does not have required extended key usage"
                        ),
                    ))
                }
            }
            Cond::KeyUsage(i) => {
                if cert.key_usage[*i] {
                    Ok(())
                } else {
                    Err((
                        Kind::KeyUsage,
                        format!(
                            "key_usage {}: certificate does not have required key usage bit",
                            KEY_USAGES[*i]
                        ),
                    ))
                }
            }
        }
    }
}

/// The legacy rule: the purposes `policies` names (absent: signing), then, unless skipped or
/// the issuer is special, an employee's certificate with the right to sign. The error code.
pub fn legacy(cert: &CertFacts, policies: Option<&[String]>, skip: bool) -> Result<(), String> {
    match policies {
        None => {
            if !cert.has_purpose(Purpose::Sign) {
                return Err("CERTIFICATE_FOR_AUTHENTICATION".to_owned());
            }
        }
        Some(names) => {
            let mut purposes = Vec::new();
            for name in names {
                purposes.push(Purpose::parse(name).ok_or_else(|| {
                    format!(
                        "No enum constant asia.dbt.thundercrypt.core.common.CertificatePurpose.{name}"
                    )
                })?);
            }
            if !purposes.iter().any(|p| cert.has_purpose(*p)) {
                return Err("CERTIFICATE_NO_HAVE_PERM".to_owned());
            }
        }
    }
    if skip || cert.special_issuer() {
        return Ok(());
    }
    let employee = cert.has_eku("1.2.398.3.3.4.1.2");
    let may_sign = cert.has_eku("1.2.398.3.3.4.1.2.2") || cert.has_eku("1.2.398.3.3.4.1.2.1");
    if employee && may_sign {
        Ok(())
    } else {
        Err("CERTIFICATE_NO_HAVE_PERM_FOR_SIGN".to_owned())
    }
}
