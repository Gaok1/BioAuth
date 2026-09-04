//! The agent's half of the shared origin table.
//!
//! See `desktop/fillable-origins.json` for why the table exists. The rule is
//! decided here, in the service worker, in the content script and again by the
//! manifest's match patterns; this file pins the first of those, and
//! `desktop/ui/test/fillable-origins.test.js` pins the rest against the same
//! cases.

use serde_json::Value;

#[test]
fn every_shared_case_is_decided_the_way_the_table_says() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fillable-origins.json");
    let table: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read the table"))
            .expect("parse the table");
    let cases = table["cases"].as_array().expect("cases is a list");
    assert!(!cases.is_empty(), "the table is empty");

    for case in cases {
        let origin = case["origin"].as_str().expect("origin is a string");
        let fillable = case["fillable"].as_bool().expect("fillable is a bool");
        let why = case["why"].as_str().unwrap_or_default();
        assert_eq!(
            phone_auth_agent::service::origin_host(origin).is_some(),
            fillable,
            "{origin}: {why}"
        );
    }
}
