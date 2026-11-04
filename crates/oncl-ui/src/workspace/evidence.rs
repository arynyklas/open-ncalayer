//! Public validation material the LT and LTA levels of CAdES and PAdES are built from: the
//! certificates of the chains and the OCSP responses and CRLs that prove their status. The SDK
//! does not fetch it for these formats (it checks what the host hands over and fails when it is
//! not enough, after the key was applied); the desktop therefore asks the user for the files
//! and refuses before any key is used when they are not there, as the command line does.
//! XAdES fetches its own evidence and needs none of this.
//!
//! The files are read here, bounded, once, before anything is frozen or signed. They are
//! public data: nothing in them is trusted, the engine checks every path, status and
//! signature again.

use std::path::PathBuf;

use oncl_pki::cert::Certificate;

use super::controller::{JobError, MissingField};
use super::operations::{evidence_limits, read_limited};

/// The files the user named, by kind.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) certificates: Vec<PathBuf>,
    pub(crate) ocsp: Vec<PathBuf>,
    pub(crate) crls: Vec<PathBuf>,
}

/// `a.der; "b c.der"` → the paths: separated by `;`, surrounding spaces and quotes dropped,
/// empty entries skipped.
pub(crate) fn parse_list(text: &str) -> Vec<PathBuf> {
    text.split(';')
        .map(|p| p.trim().trim_matches('"').trim())
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .collect()
}

impl Evidence {
    /// What the three fields of a page hold.
    pub(crate) fn from_fields(certificates: &str, ocsp: &str, crls: &str) -> Evidence {
        Evidence {
            certificates: parse_list(certificates),
            ocsp: parse_list(ocsp),
            crls: parse_list(crls),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.certificates.is_empty() && self.ocsp.is_empty() && self.crls.is_empty()
    }

    /// The material as one label, which the consent binds.
    pub(crate) fn label(&self) -> String {
        let join = |paths: &[PathBuf]| {
            paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("|")
        };
        format!(
            "cert={};ocsp={};crl={}",
            join(&self.certificates),
            join(&self.ocsp),
            join(&self.crls)
        )
    }

    /// Evidence cannot be built from nothing: the chain certificates and at least one OCSP
    /// response or CRL are needed. Checked before any file is read and before any key is used.
    pub(crate) fn require(&self) -> Result<(), JobError> {
        if self.certificates.is_empty() || (self.ocsp.is_empty() && self.crls.is_empty()) {
            return Err(JobError::Input(MissingField::Evidence));
        }
        Ok(())
    }

    /// Reads the files, within the SDK's own evidence bounds.
    pub(crate) fn load(&self) -> Result<Loaded, JobError> {
        let limits = evidence_limits();
        let count = self.certificates.len() + self.ocsp.len() + self.crls.len();
        if count > limits.max_items {
            return Err(JobError::Operation(oncl_core::ErrorCode::InputLimit));
        }
        let item_limit = usize::try_from(limits.max_item_bytes).unwrap_or(usize::MAX);
        let mut total = 0u64;
        let mut read = |path: &PathBuf| -> Result<Vec<u8>, JobError> {
            let bytes = read_limited(path, item_limit)?;
            total = total.saturating_add(bytes.len() as u64);
            if total > limits.max_bytes {
                return Err(JobError::Operation(oncl_core::ErrorCode::InputLimit));
            }
            Ok(bytes)
        };
        let mut loaded = Loaded::default();
        for path in &self.certificates {
            let bytes = read(path)?;
            loaded.certificates.push(
                oncl_pki::cert::parse(&bytes)
                    .map_err(|_| JobError::Operation(oncl_core::ErrorCode::InvalidInput))?,
            );
        }
        for path in &self.ocsp {
            loaded.ocsp.push(read(path)?);
        }
        for path in &self.crls {
            loaded.crls.push(read(path)?);
        }
        Ok(loaded)
    }
}

/// The material as bytes.
#[derive(Default)]
pub(crate) struct Loaded {
    pub(crate) certificates: Vec<Certificate>,
    ocsp: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
}

impl Loaded {
    pub(crate) fn ocsp_slices(&self) -> Vec<&[u8]> {
        self.ocsp.iter().map(Vec::as_slice).collect()
    }

    pub(crate) fn crl_slices(&self) -> Vec<&[u8]> {
        self.crls.iter().map(Vec::as_slice).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_of_paths_is_split_on_semicolons_and_trimmed() {
        assert_eq!(
            parse_list(r#" a.der ; "b c.der" ;; "#),
            vec![PathBuf::from("a.der"), PathBuf::from("b c.der")]
        );
        assert!(parse_list("  ;  ").is_empty());
    }

    /// Evidence needs the chain and a status: certificates alone, or a status alone, is
    /// refused before any file is read.
    #[test]
    fn evidence_needs_certificates_and_a_status() {
        let e = |c: &str, o: &str, r: &str| Evidence::from_fields(c, o, r);
        for incomplete in [
            e("", "", ""),
            e("a", "", ""),
            e("", "o", ""),
            e("", "", "r"),
        ] {
            assert_eq!(
                incomplete.require(),
                Err(JobError::Input(MissingField::Evidence)),
                "{incomplete:?}"
            );
        }
        assert_eq!(e("a", "o", "").require(), Ok(()));
        assert_eq!(e("a", "", "r").require(), Ok(()));
    }

    #[test]
    fn a_missing_or_unparsable_file_is_refused_when_loading() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.der");
        std::fs::write(&junk, b"not a certificate").unwrap();
        let missing = Evidence {
            certificates: vec![dir.path().join("nope.der")],
            ..Evidence::default()
        };
        assert!(matches!(missing.load(), Err(JobError::Io(_))));
        let unparsable = Evidence {
            certificates: vec![junk],
            ..Evidence::default()
        };
        assert!(matches!(
            unparsable.load(),
            Err(JobError::Operation(oncl_core::ErrorCode::InvalidInput))
        ));
    }
}
