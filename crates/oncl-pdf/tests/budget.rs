//! Pins the PAdES budget the HTTP preflight depends on: the reservation formulas, the
//! monotonicity of the plan in every input, and `prior_signature_contents` on real
//! signed fixtures (never a silent zero).
use oncl_pdf::{
    PdfError, PdfLimits,
    budget::{self, PlanInputs, PriorSignatures},
};
use oncl_pki::{
    io::Source,
    resource::{
        OperationControl, ProcessingError, Progress, ResourceLimits, ResourceScope, SharedBudget,
    },
};
use std::{io::Cursor, sync::Arc};

struct Control;
impl OperationControl for Control {
    fn checkpoint(&self, _: Progress) -> Result<(), ProcessingError> {
        Ok(())
    }
}
fn scope() -> ResourceScope {
    let limits = ResourceLimits::default();
    Arc::new(SharedBudget::new(limits.clone()).unwrap())
        .begin(limits, Arc::new(Control))
        .unwrap()
}
fn prior(bytes: &[u8]) -> Result<PriorSignatures, PdfError> {
    let mut cursor = Cursor::new(bytes);
    budget::prior_signature_contents(
        Source::seekable(&mut cursor, Some(1)),
        &PdfLimits::default(),
        &mut scope(),
    )
}
/// A real PAdES-B output of the HTTP service (synthetic RSA key): one ETSI.CAdES.detached
/// signature. (`external-*.pdf` use adbe.pkcs7.detached, which the PAdES candidate scan
/// refuses, so they are covered by the unreadable-input test below.)
const SIGNED: &[u8] = include_bytes!("fixtures/pades-b-synthetic.pdf");
const ADOBE: &[u8] = include_bytes!("fixtures/external-two-signatures.pdf");
const UNSIGNED: &[u8] = include_bytes!("fixtures/external-multipage.pdf");

#[test]
fn prior_signature_contents_reads_real_signed_fixtures() {
    let none = prior(UNSIGNED).unwrap();
    assert_eq!(none, PriorSignatures::default(), "an unsigned PDF has no prior signatures");
    let one = prior(SIGNED).unwrap();
    assert_eq!(one.count, 1);
    assert!(one.contents_sum > 0 && one.contents_max > 0, "{one:?}");
    assert_eq!(one.contents_sum, one.contents_max);
    // The signed output keeps the original revision byte-identical and appends.
    assert!(SIGNED.starts_with(UNSIGNED));
}

#[test]
fn prior_signature_contents_reports_unreadable_input_instead_of_zero() {
    // The preflight must be able to refuse, so garbage is an error, not (0, 0, 0).
    assert!(prior(b"this is not a pdf").is_err());
    assert!(prior(&SIGNED[..SIGNED.len() / 3]).is_err());
    // A non-PAdES signature SubFilter is an explicit refusal, not an empty result.
    assert!(matches!(prior(ADOBE), Err(PdfError::Unsupported(_))));
}

#[test]
fn plan_memory_and_metadata_are_pinned_and_monotonic_in_every_input() {
    let limits = PdfLimits::default();
    let none = PlanInputs::default();
    // The pinned numbers (default limits): changing any reservation formula or the
    // default limits is a conscious update of the HTTP profile documentation.
    let memory = budget::plan_memory(&limits, &none).unwrap();
    let metadata = budget::plan_metadata(&limits, &none).unwrap();
    assert_eq!(memory, 397_541_376, "plan_memory with no inputs (default limits)");
    assert_eq!(metadata, 57_802_752, "plan_metadata with no inputs (default limits)");
    // Components are the documented reservation functions.
    let (reader_metadata, reader_memory) = budget::reader(&limits).unwrap();
    assert!(memory >= budget::plan_reservation(&limits).unwrap() + reader_memory);
    assert!(metadata >= budget::plan_metadata_reservation(&limits).unwrap() + reader_metadata);
    assert!(metadata >= budget::sign_metadata(&limits).unwrap() + reader_metadata);
    // Every input only grows the need.
    let grow = |inputs: PlanInputs| {
        (budget::plan_memory(&limits, &inputs).unwrap(), budget::plan_metadata(&limits, &inputs).unwrap())
    };
    for inputs in [
        PlanInputs { prior_contents_sum: 1 << 20, ..none },
        PlanInputs { prior_contents_max: 1 << 20, ..none },
        PlanInputs { evidence_bytes: 1 << 20, ..none },
        PlanInputs { trust_bytes: 1 << 20, ..none },
    ] {
        let (m, md) = grow(inputs);
        assert!(m > memory && md > metadata, "{inputs:?}: {m} {md}");
    }
    // Evidence costs the documented factor per byte (the measured coefficient).
    let (m, _) = grow(PlanInputs { evidence_bytes: 1 << 20, ..none });
    assert_eq!(m - memory, (1 << 20) * budget::EVIDENCE_MEMORY_FACTOR);
    // Overflowing inputs are an error, never a wrapped small number.
    assert!(budget::plan_memory(&limits, &PlanInputs { evidence_bytes: u64::MAX, ..none }).is_err());
    assert!(budget::plan_metadata(&limits, &PlanInputs { prior_contents_sum: u64::MAX, ..none }).is_err());
}
