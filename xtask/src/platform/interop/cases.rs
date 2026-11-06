//! The cases of the matrix, by family. A case produces an artifact with one side, has the
//! other side judge it, and returns the grade it observed; `coverage.toml` says which grade
//! it must be.

use super::Case;

#[path = "cases/cms.rs"]
mod cms;
#[path = "cases/common.rs"]
pub mod common;
#[path = "cases/extras.rs"]
mod extras;
#[path = "cases/jose.rs"]
mod jose;
#[path = "cases/large.rs"]
mod large;
#[path = "cases/pdf.rs"]
mod pdf;
#[path = "cases/wsse.rs"]
mod wsse;
#[path = "cases/x509.rs"]
mod x509;
#[path = "cases/xml.rs"]
mod xml;

/// Every case.
pub fn all() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.extend(cms::cases());
    cases.extend(xml::cases());
    cases.extend(pdf::cases());
    cases.extend(wsse::cases());
    cases.extend(jose::cases());
    cases.extend(x509::cases());
    cases.extend(extras::cases());
    cases.extend(large::cases());
    cases
}
