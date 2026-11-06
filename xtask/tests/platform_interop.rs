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

/// A defect row states the DESIRED outcome as `expected` (a concrete grade of the same
/// shape as a passing row, never the buggy output and never prose) and the documented buggy
/// outcome as `defect_observed`; the runner then tells a still-reproducing defect (DEFECT)
/// from a fixed one (FIXED: the marker must go) and from a different failure (CHANGED).
#[test]
fn defect_rows_have_a_concrete_desired_grade_and_a_distinct_documented_observation() {
    let coverage = Coverage::load().unwrap();
    for row in &coverage.case {
        assert!(
            !row.expected.trim().is_empty() && row.expected != "?",
            "row {} has no expected grade",
            row.id
        );
        assert!(
            !row.expected.starts_with('(') && !row.expected.contains("after the fix"),
            "row {}: expected is a placeholder, not a grade: {}",
            row.id,
            row.expected
        );
        let Some(defect) = &row.defect else {
            assert!(
                row.defect_observed.is_none(),
                "row {} has no defect marker",
                row.id
            );
            continue;
        };
        let description = coverage
            .defect
            .iter()
            .find(|d| &d.id == defect)
            .unwrap_or_else(|| panic!("row {} names unknown defect {defect}", row.id));
        assert!(!description.reproduction.is_empty() && !description.observed.is_empty());
        let observed = row
            .defect_observed
            .as_deref()
            .unwrap_or_else(|| panic!("defect row {} documents no observation", row.id));
        assert!(!observed.trim().is_empty());
        assert!(
            !row.expected.contains(observed),
            "defect row {}: the desired grade must not contain the buggy observation `{observed}`",
            row.id
        );
        assert!(
            row.expected.contains('=') && row.expected.len() > 20,
            "defect row {}: the desired outcome is not a grade of a passing row's shape",
            row.id
        );
    }
}
