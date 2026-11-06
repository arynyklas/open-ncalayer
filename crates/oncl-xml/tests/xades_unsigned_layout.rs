//! The layout rules of the unsigned signature properties of a recognized archive proof or
//! `TimeStampValidationData`, decided from the structure the scan records (no property is
//! materialised: it may carry a multi-megabyte CRL). Each violation is refused with a
//! typed error; the same documents are refused by the DOM-based implementation this
//! replaced (`ONCL_DUMP_LAYOUT=<dir>` writes them for the differential run).
#[path = "support/xades_pki.rs"]
mod xades_pki;
use oncl_pki::{
    evidence::AdesLevel,
    io::{Source, TemporaryStore},
    resource::{ResourceLimits, SharedBudget},
    validation::{NetworkPolicy, ValidationContext, ValidationPolicy, Verdict},
};
use oncl_xml::{XmlVerifyProfile, verify_source};
use std::{io::Cursor, sync::Arc};
use xades_pki::{Control, NOW, Offline, Pki};

const XADES: &str = "http://uri.etsi.org/01903/v1.3.2#";
const TSVD_CLOSE: &str = "</xades141:TimeStampValidationData>";
fn tsvd_open(id: &str) -> String {
    format!(
        "<xades141:TimeStampValidationData xmlns:xades141=\"http://uri.etsi.org/01903/v1.4.1#\" URI=\"#{id}\">"
    )
}
/// The whole TSVD element opened by `open`.
fn element<'a>(doc: &'a str, open: &str) -> &'a str {
    let start = doc.find(open).expect("TSVD");
    let end = start + doc[start..].find(TSVD_CLOSE).unwrap() + TSVD_CLOSE.len();
    &doc[start..end]
}

fn verify(pki: &Pki, xml: &str) -> Result<Verdict, String> {
    let limits = ResourceLimits::default();
    let budget = Arc::new(SharedBudget::new(limits.clone()).unwrap());
    let mut scope = budget.begin(limits, Arc::new(Control)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = TemporaryStore::new(dir.path()).unwrap();
    let http = Offline;
    let context = ValidationContext {
        policy: ValidationPolicy::OfflineReport,
        now: NOW,
        anchors: &pki.anchors,
        intermediates: &[],
        http: &http,
    };
    verify_source(
        Source::sequential(&mut Cursor::new(xml.as_bytes()), None),
        &XmlVerifyProfile::default(),
        &store,
        &context,
        &NetworkPolicy::deny_all(),
        &mut scope,
    )
    .map(|report| report.validation.verdict)
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn tsvd_and_archive_layout_rules_are_enforced_without_materialising_the_properties() {
    let mut pki = Pki::new();
    let doc = pki.xades(AdesLevel::Lta);
    let first = tsvd_open("sig-T");
    let last = tsvd_open("sig-A1");
    assert!(doc.contains(&first), "LTA layout");
    assert_eq!(verify(&pki, &doc), Ok(Verdict::Valid), "the untouched LTA");
    let no_uri = |open: &str| {
        open.replace(" URI=\"#sig-T\"", "")
            .replace(" URI=\"#sig-A1\"", "")
    };
    let foreign = format!(
        "<xades:SigningTime xmlns:xades=\"{XADES}\">2026-11-02T12:00:00Z</xades:SigningTime>"
    );
    let first_element = element(&doc, &first).to_owned();
    // A current-TSA tail after the archive: here an empty one, which names the archive.
    let tail = |open: &str| format!("{open}{TSVD_CLOSE}");
    let close = "</xades:UnsignedSignatureProperties>";
    let with_tail = doc.replacen(close, &format!("{}{close}", tail(&last)), 1);
    let cases: Vec<(&str, String, bool)> = vec![
        (
            "a trailing TSVD naming the current archive",
            with_tail.clone(),
            true,
        ),
        (
            "an implicit association",
            doc.replacen(&first, &no_uri(&first), 1),
            true,
        ),
        (
            "a property of another kind inside TSVD",
            doc.replacen(&first, &format!("{first}{foreign}"), 1),
            false,
        ),
        (
            "a TSVD child in a foreign namespace",
            doc.replacen(
                &first,
                &format!("{first}<x:RevocationValues xmlns:x=\"urn:x\"/>"),
                1,
            ),
            false,
        ),
        (
            "a URI naming no timestamp",
            doc.replacen("URI=\"#sig-T\"", "URI=\"#nope\"", 1),
            false,
        ),
        (
            "a TSVD without URI before any timestamp",
            doc.replacen(&first_element, "", 1).replacen(
                "<xades:UnsignedSignatureProperties>",
                &format!(
                    "<xades:UnsignedSignatureProperties>{}",
                    first_element.replacen(&first, &no_uri(&first), 1)
                ),
                1,
            ),
            false,
        ),
        (
            "the trailing TSVD naming an older timestamp",
            with_tail.replacen("URI=\"#sig-A1\"", "URI=\"#sig-T\"", 1),
            false,
        ),
        (
            "the trailing TSVD without URI",
            with_tail.replacen(&last, &no_uri(&last), 1),
            false,
        ),
        (
            "a second property after the current archive",
            with_tail.replacen(close, &format!("{}{close}", tail(&last)), 1),
            false,
        ),
        (
            "another kind of property after the current archive",
            with_tail.replacen(
                close,
                &format!("<xades:CertificateValues xmlns:xades=\"{XADES}\"/>{close}"),
                1,
            ),
            false,
        ),
        (
            "a property after the current archive that is not a TSVD",
            doc.replacen(
                close,
                &format!("<xades:CertificateValues xmlns:xades=\"{XADES}\"/>{close}"),
                1,
            ),
            false,
        ),
    ];
    let dump = std::env::var_os("ONCL_DUMP_LAYOUT").map(std::path::PathBuf::from);
    if let Some(dir) = &dump {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("layout-untouched.xml"), &doc).unwrap();
    }
    for (index, (name, mutated, accepted)) in cases.iter().enumerate() {
        assert_ne!(mutated, &doc, "{name}: the mutation did not apply");
        if let Some(dir) = &dump {
            std::fs::write(dir.join(format!("layout-{index}.xml")), mutated).unwrap();
        }
        let result = verify(&pki, mutated);
        if *accepted {
            assert!(result.is_ok(), "{name}: {result:?}");
        } else {
            assert!(result.is_err(), "{name} must be refused: {result:?}");
        }
    }
}
