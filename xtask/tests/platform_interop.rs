//! The committed matrix (`fixtures/platform/coverage.toml`) against the case catalog and the
//! pinned NCANode OpenAPI. The matrix itself runs with `cargo xtask platform-interop` (Linux,
//! Docker, OpenSSL, the pyHanko environment): these tests need no tool, only the fetched
//! fixtures (`cargo xtask fetch-fixtures`), like the other NCANode-based tests.

use xtask::platform_interop::{Coverage, catalog, check_coverage, check_openapi, openapi_routes};

#[test]
fn every_route_capability_case_and_oracle_is_accounted_for() {
    let coverage = Coverage::load().unwrap();
    check_coverage(&coverage, &catalog(), true).unwrap();
}

#[test]
fn the_pinned_openapi_is_the_fetched_one_with_exactly_the_pinned_routes() {
    let coverage = Coverage::load().unwrap();
    let facts = check_openapi(&coverage).unwrap();
    assert_eq!(facts["routes"].as_array().unwrap().len(), 22);
}

#[test]
fn openapi_routes_are_read_from_the_paths_section_only() {
    let yaml = "components:\n  schemas:\n    /not/a/route:\n      type: object\npaths:\n  /cms/sign:\n    post: {}\n  /cms/sign/add:\n    post: {}\nservers:\n- url: \"\"\n";
    assert_eq!(openapi_routes(yaml), ["/cms/sign", "/cms/sign/add"]);
}

#[test]
fn a_row_without_a_case_or_a_case_without_a_row_is_an_inconsistency() {
    let mut coverage = Coverage::load().unwrap();
    let cases = catalog();
    let removed = coverage.case.pop().unwrap();
    let error = check_coverage(&coverage, &cases, true)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&removed.id), "{error}");
    let mut coverage = Coverage::load().unwrap();
    let capability = coverage.capability.pop().unwrap();
    let error = check_coverage(&coverage, &cases, true)
        .unwrap_err()
        .to_string();
    assert!(error.contains(&capability.id), "{error}");
}

/// The matrix is complete only when every pinned family has real cases. This stays red
/// while `[[pending]]` is not empty: a capability without cases is not covered.
#[test]
fn no_capability_is_left_without_cases() {
    let coverage = Coverage::load().unwrap();
    let pending: Vec<&str> = coverage.pending.iter().map(|p| p.id.as_str()).collect();
    assert!(
        pending.is_empty(),
        "capabilities without cases: {pending:?}"
    );
}
