//! The cases of the matrix, by family. A case produces an artifact with one side, has the
//! other side judge it, and returns the grade it observed; `coverage.toml` says which grade
//! it must be.

use super::Case;

#[path = "cases/cms.rs"]
mod cms;
#[path = "cases/common.rs"]
pub mod common;
#[path = "cases/pdf.rs"]
mod pdf;
#[path = "cases/xml.rs"]
mod xml;

/// Every case.
pub fn all() -> Vec<Case> {
    let mut cases = Vec::new();
    cases.extend(cms::cases());
    cases.extend(xml::cases());
    cases.extend(pdf::cases());
    cases
}
