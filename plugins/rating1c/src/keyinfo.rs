//! The module's own `KeyInfo` bean: what `getKeyInfo` and `TestKeyOwner` answer with, what
//! the owner check reads, and its `toString()` in the replies of the raw signatures.

use oncl_pdk::orgjson::JObject;
use oncl_port_kit::date::format_java;

/// What the bean is made of: the key and its certificate as the host reads them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The alias in the key store.
    pub alias: String,
    /// The subjectKeyIdentifier, hex.
    pub key_id: Option<String>,
    /// Kalkan's name of the key algorithm.
    pub algorithm: Option<String>,
    /// The first subject CN.
    pub subject_cn: Option<String>,
    /// `X500Principal.toString()` of the subject.
    pub subject_dn: String,
    /// The serial number, hex.
    pub serial: String,
    /// The first issuer CN.
    pub issuer_cn: Option<String>,
    /// Kalkan's text of the issuer (`getIssuerDN().getName()`).
    pub issuer_dn: String,
    /// notAfter, Unix milliseconds.
    pub not_after_ms: i64,
    /// notBefore, Unix milliseconds.
    pub not_before_ms: i64,
    /// The authorityKeyIdentifier's keyIdentifier, hex.
    pub aki: Option<String>,
    /// The certificate as PEM.
    pub pem: String,
    /// The subject's OU values, in DER order.
    pub ous: Vec<String>,
    /// The subject's SERIALNUMBER values, in DER order.
    pub serial_numbers: Vec<String>,
}

/// The bean, with the owner's IIN and BIN it computes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    facts: Facts,
    iin: String,
    bin: String,
}

impl KeyInfo {
    /// The bean of `facts`: the IIN is the last 12 characters of SERIALNUMBER, the BIN the
    /// last OU without `BIN`.
    ///
    /// # Errors
    ///
    /// Java's `StringIndexOutOfBoundsException` message for a SERIALNUMBER shorter than 12
    /// characters (none at all is the empty text).
    pub fn new(facts: Facts) -> Result<KeyInfo, String> {
        // Unverified against the original: "last" RDN taken in DER order.
        let serial_number = facts.serial_numbers.last().cloned().unwrap_or_default();
        let units: Vec<u16> = serial_number.encode_utf16().collect();
        let from = units.len() as i64 - 12;
        if from < 0 {
            return Err(format!("String index out of range: {from}"));
        }
        let iin = String::from_utf16_lossy(&units[from as usize..]);
        let bin = facts
            .ous
            .last()
            .map(|ou| ou.replace("BIN", ""))
            .unwrap_or_default();
        Ok(KeyInfo { facts, iin, bin })
    }

    /// `isKeysOwners(bin)`: a 12-character BIN compared with `bin`, else a 12-character
    /// IIN.
    pub fn owned_by(&self, bin: &str) -> bool {
        if self.bin.encode_utf16().count() == 12 {
            self.bin == bin
        } else if self.iin.encode_utf16().count() == 12 {
            self.iin == bin
        } else {
            false
        }
    }

    /// The bean as org.json writes it: its properties in the bean's field order (which
    /// decides the order of keys sharing a `HashMap` bucket); `datefrom` and `dateto` hold
    /// notAfter and notBefore (the bean's setters swap them), as `dd.MM.yyyy (HH:mm)` in
    /// Asia/Almaty; `usage` and `path` are never set for a key from the dialog.
    pub fn bean(&self) -> JObject {
        let f = &self.facts;
        let mut bean = JObject::hash_map();
        bean.put("alias", f.alias.as_str());
        bean.put_opt("keyId", f.key_id.clone());
        bean.put_opt("algorithm", f.algorithm.clone());
        bean.put_opt("subjectCn", f.subject_cn.clone());
        bean.put("subjectDn", f.subject_dn.as_str());
        bean.put("serial", f.serial.as_str());
        bean.put("serialNumber", f.serial.as_str());
        bean.put_opt("issuerCn", f.issuer_cn.clone());
        bean.put("issuerdn", f.issuer_dn.as_str());
        bean.put("certNotAfter", f.not_after_ms.to_string());
        bean.put("certNotBefore", f.not_before_ms.to_string());
        // Unverified against the original: the dates' text in this reply and that the
        // swapping setters fill it.
        bean.put("datefrom", almaty(f.not_after_ms));
        bean.put("dateto", almaty(f.not_before_ms));
        bean.put_opt("authorityKeyIdentifier", f.aki.clone());
        bean.put("pem", f.pem.as_str());
        bean
    }

    /// The bean's `toString()`: its official fields, `issuerDn` always empty, absent values
    /// `null`.
    pub fn lombok(&self) -> String {
        let f = &self.facts;
        let or_null = |v: &Option<String>| v.clone().unwrap_or_else(|| "null".to_owned());
        format!(
            "KeyInfo(alias={}, keyId={}, algorithm={}, subjectCn={}, subjectDn={}, issuerCn={}, \
             issuerDn=, serialNumber={}, certNotAfter={}, certNotBefore={}, \
             authorityKeyIdentifier={}, pem={})",
            f.alias,
            or_null(&f.key_id),
            or_null(&f.algorithm),
            or_null(&f.subject_cn),
            f.subject_dn,
            or_null(&f.issuer_cn),
            f.serial,
            f.not_after_ms,
            f.not_before_ms,
            or_null(&f.aki),
            f.pem,
        )
    }
}

/// `dd.MM.yyyy (HH:mm)` in Asia/Almaty: UTC+6, UTC+5 from 2024-03-01 00:00 local time.
pub fn almaty(unix_ms: i64) -> String {
    const UTC5_FROM_MS: i64 = 1_709_229_600_000;
    let offset = if unix_ms < UTC5_FROM_MS {
        6 * 3600
    } else {
        5 * 3600
    };
    format_java("dd.MM.yyyy (HH:mm)", unix_ms, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            alias: "a".to_owned(),
            subject_dn: "CN=X".to_owned(),
            serial: "01".to_owned(),
            issuer_dn: "CN=CA".to_owned(),
            pem: "P".to_owned(),
            serial_numbers: vec!["IIN123456789011".to_owned()],
            ..Facts::default()
        }
    }

    #[test]
    fn iin_bin_and_owner() {
        let person = KeyInfo::new(facts()).unwrap();
        assert!(person.owned_by("123456789011"));
        assert!(!person.owned_by("123456789021"));
        let legal = KeyInfo::new(Facts {
            ous: vec!["BIN123456789021".to_owned()],
            ..facts()
        })
        .unwrap();
        assert!(legal.owned_by("123456789021"));
        assert!(!legal.owned_by("123456789011"));
    }

    #[test]
    fn short_serial_number_is_javas_error() {
        let none = Facts {
            serial_numbers: vec![],
            ..facts()
        };
        assert_eq!(
            KeyInfo::new(none).unwrap_err(),
            "String index out of range: -12"
        );
        let short = Facts {
            serial_numbers: vec!["IIN1".to_owned()],
            ..facts()
        };
        assert_eq!(
            KeyInfo::new(short).unwrap_err(),
            "String index out of range: -8"
        );
    }

    #[test]
    fn lombok_text() {
        let info = KeyInfo::new(facts()).unwrap();
        assert_eq!(
            info.lombok(),
            "KeyInfo(alias=a, keyId=null, algorithm=null, subjectCn=null, subjectDn=CN=X, \
             issuerCn=null, issuerDn=, serialNumber=01, certNotAfter=0, certNotBefore=0, \
             authorityKeyIdentifier=null, pem=P)"
        );
    }

    #[test]
    fn almaty_dates() {
        // 2024-02-29 17:59 UTC is 23:59 at UTC+6; 2026-10-29 12:00 UTC is 17:00 at UTC+5.
        assert_eq!(almaty(1_709_229_540_000), "29.02.2024 (23:59)");
        assert_eq!(almaty(1_793_275_200_000), "29.10.2026 (17:00)");
    }
}
