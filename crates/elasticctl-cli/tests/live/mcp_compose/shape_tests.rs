use super::samples::{
    case_row, coverage_page, envelope, list_row, missing_list_row, not_found, ok, rule,
};
use super::*;
use serde_json::json;

fn alert_context_sample() -> Value {
    let lists = ["l1", "l2"];
    envelope(
        json!({
            "alert": samples::alert("a1", "r1", "r1 rule"),
            "rule": ok(rule("r1", "r1 rule", true, &lists)),
            "exceptions": ok(json!({"referenced": 2, "truncated": false,
                "lists": [list_row("l1", 2), missing_list_row("l2")]})),
            "cases": ok(json!({"total": 1, "truncated": false, "cases": [case_row("c1", "t1")]})),
            "activity": ok(samples::activity(3, None)),
            "partial": true,
            "findings": ["exception_list_missing", "has_related_case"],
        }),
        Value::Null,
    )
}

fn rule_health_sample() -> Value {
    envelope(
        json!({
            "rule": rule("r1", "r1 rule", true, &["l1"]),
            "alerts": ok(samples::activity(1, Some(vec![samples::alert("a1", "r1", "r1 rule")]))),
            "exceptions": ok(json!({"referenced": 1, "truncated": false, "lists": [list_row("l1", 1)]})),
            "partial": false,
            "findings": [],
        }),
        Value::Null,
    )
}

fn rule_readiness_sample() -> Value {
    envelope(
        json!({
            "rule": {"rule_id": "r1", "name": "r1 rule", "type": "query", "enabled": true},
            "index_source": "index",
            "data_views": ok(json!({"count": 2})),
            "patterns": ok(json!({"total": 3, "truncated": false, "rows": [
                {"pattern": "i", "state": "matches", "indices": 1, "aliases": 0, "data_streams": 0, "data_view_ids": ["v1"]},
                {"pattern": "i-*", "state": "no_match", "indices": 0, "aliases": 0, "data_streams": 0, "data_view_ids": []},
                {"pattern": "-x*", "state": "exclusion", "data_view_ids": []},
            ]})),
            "integrations": ok(json!({"total": 2, "truncated": false, "rows": [
                {"package": "system", "version": "^1.0.0", "status": "ok", "install_status": "installed",
                 "installed_version": "2.0.0", "policies": 1},
                {"package": "nope", "version": "^1.0.0", "status": "unavailable", "error": not_found()},
            ]})),
            "partial": true,
            "findings": [],
        }),
        Value::Null,
    )
}

fn coverage_sample() -> Value {
    envelope(
        json!({
            "group_by": "technique",
            "summary": {"rules": 3, "enabled_rules": 2, "disabled_rules": 1, "unmapped_rules": 1, "groups": 2},
            "rows": [
                {"key": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["TA0002"], "enabled_rules": 2, "disabled_rules": 0},
                {"key": "T1003", "name": "OS Credential Dumping", "tactics": ["TA0006"], "enabled_rules": 0, "disabled_rules": 1},
            ],
        }),
        coverage_page(50, 2, 2),
    )
}

fn rules_list_sample() -> Value {
    envelope(
        json!({"rules": [{"rule_id": "r1", "name": "r1 rule", "type": "query", "enabled": true,
            "severity": "low", "risk_score": 21, "tags": ["elasticctl-live-marker"]}]}),
        coverage_page(10, 1, 1),
    )
}

fn rejects_unknown_at(
    sample: &Value,
    validate: fn(&Value) -> TestResult,
    pointers: &[&str],
    tool: &str,
) {
    validate(sample).unwrap_or_else(|e| panic!("{tool} sample rejected: {e}"));
    for pointer in pointers {
        let mut value = sample.clone();
        value
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .unwrap_or_else(|| panic!("{tool} sample has no object at {pointer}"))
            .insert("secret_sentinel".to_string(), json!(true));
        let error =
            validate(&value).expect_err(&format!("{tool} accepted an unknown field at {pointer}"));
        assert!(!error.contains("secret_sentinel"), "{error}");
    }
}

#[test]
fn each_task_tool_validator_rejects_an_unknown_field() {
    rejects_unknown_at(
        &alert_context_sample(),
        alert_context,
        &[
            "/data",
            "/data/alert",
            "/data/alert/source",
            "/data/rule",
            "/data/rule/value",
            "/data/rule/value/execution",
            "/data/rule/value/execution/metrics",
            "/data/rule/value/exceptions_list/0",
            "/data/exceptions",
            "/data/exceptions/value",
            "/data/exceptions/value/lists/0",
            "/data/exceptions/value/lists/1",
            "/data/exceptions/value/lists/1/error",
            "/data/cases/value",
            "/data/cases/value/cases/0",
            "/data/cases/value/cases/0/case",
            "/data/activity/value",
            "/data/activity/value/by_status",
        ],
        "alert_context",
    );
    rejects_unknown_at(
        &rule_health_sample(),
        rule_health,
        &[
            "/data",
            "/data/rule",
            "/data/rule/execution",
            "/data/alerts",
            "/data/alerts/value",
            "/data/alerts/value/recent/0",
            "/data/alerts/value/recent/0/source",
            "/data/exceptions/value/lists/0",
        ],
        "rule_health",
    );
    rejects_unknown_at(
        &rule_readiness_sample(),
        rule_readiness,
        &[
            "/data",
            "/data/rule",
            "/data/data_views",
            "/data/data_views/value",
            "/data/patterns/value",
            "/data/patterns/value/rows/0",
            "/data/patterns/value/rows/2",
            "/data/integrations/value",
            "/data/integrations/value/rows/0",
            "/data/integrations/value/rows/1",
            "/data/integrations/value/rows/1/error",
        ],
        "rule_readiness",
    );
    rejects_unknown_at(
        &coverage_sample(),
        detection_coverage,
        &[
            "/data",
            "/data/summary",
            "/data/rows/0",
            "/data/rows/1",
            "/page",
        ],
        "detection_coverage",
    );
    rejects_unknown_at(
        &rules_list_sample(),
        |v| rules_list(v, 10),
        &["/data", "/data/rules/0", "/page"],
        "rules_list",
    );
}

#[test]
fn validators_reject_inconsistent_parts_findings_and_rows() {
    type Validate = fn(&Value) -> TestResult;
    let mutations: Vec<(&str, Value, Validate)> = vec![
        (
            "partial flag",
            {
                let mut v = alert_context_sample();
                v["data"]["partial"] = json!(false);
                v
            },
            alert_context,
        ),
        (
            "finding order",
            {
                let mut v = alert_context_sample();
                v["data"]["findings"] = json!(["has_related_case", "exception_list_missing"]);
                v
            },
            alert_context,
        ),
        (
            "unknown finding",
            {
                let mut v = rule_health_sample();
                v["data"]["findings"] = json!(["secret_sentinel"]);
                v
            },
            rule_health,
        ),
        (
            "unknown error message",
            {
                let mut v = alert_context_sample();
                v["data"]["exceptions"]["value"]["lists"][1]["error"]["message"] =
                    json!("secret_sentinel");
                v
            },
            alert_context,
        ),
        (
            "ok row with error",
            {
                let mut v = alert_context_sample();
                v["data"]["exceptions"]["value"]["lists"][0]["error"] = samples::not_found();
                v
            },
            alert_context,
        ),
        (
            "missing execution",
            {
                let mut v = rule_health_sample();
                v["data"]["rule"]
                    .as_object_mut()
                    .unwrap()
                    .remove("execution");
                v
            },
            rule_health,
        ),
        (
            "six recent alerts",
            {
                let mut v = rule_health_sample();
                v["data"]["alerts"]["value"]["recent"] =
                    json!(vec![samples::alert("a", "r1", "n"); 6]);
                v
            },
            rule_health,
        ),
        (
            "counts on an exclusion",
            {
                let mut v = rule_readiness_sample();
                v["data"]["patterns"]["value"]["rows"][2]["indices"] = json!(0);
                v
            },
            rule_readiness,
        ),
        (
            "matches without counts",
            {
                let mut v = rule_readiness_sample();
                v["data"]["patterns"]["value"]["rows"][0]["indices"] = json!(0);
                v
            },
            rule_readiness,
        ),
        (
            "rule data view outside the data view source",
            {
                let mut v = rule_readiness_sample();
                v["data"]["data_views"]["value"]["rule_data_view"] =
                    json!({"id": "v1", "found": true});
                v
            },
            rule_readiness,
        ),
        (
            "rows out of order",
            {
                let mut v = coverage_sample();
                v["data"]["rows"].as_array_mut().unwrap().reverse();
                v
            },
            detection_coverage,
        ),
        (
            "tactics outside the technique grouping",
            {
                let mut v = coverage_sample();
                v["data"]["group_by"] = json!("tactic");
                v
            },
            detection_coverage,
        ),
        (
            "page total disagrees with groups",
            {
                let mut v = coverage_sample();
                v["page"] = coverage_page(50, 2, 3);
                v
            },
            detection_coverage,
        ),
        (
            "page on a single-object tool",
            {
                let mut v = rule_health_sample();
                v["page"] = coverage_page(50, 0, 0);
                v
            },
            rule_health,
        ),
    ];
    for (name, value, validate) in mutations {
        assert!(validate(&value).is_err(), "{name} was accepted");
    }
}

#[test]
fn technique_rows_require_tactics() {
    let mut value = coverage_sample();
    value["data"]["rows"][0]
        .as_object_mut()
        .unwrap()
        .remove("tactics");
    assert!(detection_coverage(&value).is_err());
}

#[test]
fn exclusion_rows_include_ids_when_views_are_available() {
    let mut value = rule_readiness_sample();
    value["data"]["patterns"]["value"]["rows"][2]
        .as_object_mut()
        .unwrap()
        .remove("data_view_ids");
    assert!(rule_readiness(&value).is_err());
}
