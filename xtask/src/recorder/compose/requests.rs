//! The exact requests behind the compose fixtures.
//!
//! Every builder names only marker ids, indices, lists, and cases, so a
//! recorded exchange can never hold an unscoped `_find` or search.

use crate::recorder::compose::{
    ACTIVITY_SINCE, ACTIVITY_SIZE, MISSING_RULE_ID, SORTED_PAGE_SIZE, TECHNIQUE,
    TECHNIQUE_PAGE_SIZE,
};
use crate::recorder::markers::{ALERT_RULE_ID, LIST_ID, NAMESPACE_TYPE};
use elasticctl_core::urlencode;
use serde_json::{Value, json};

pub(super) const RULES_PATH: &str = "/api/detection_engine/rules";
pub(super) const RULES_FIND_PATH: &str = "/api/detection_engine/rules/_find";
pub(super) const ITEMS_FIND_PATH: &str = "/api/exception_lists/items/_find";
pub(super) const CASES_BY_ALERT_PATH: &str = "/api/cases/alerts";
pub(super) const RESOLVE_INDEX_PATH: &str = "/_resolve/index";
pub(super) const PACKAGES_PATH: &str = "/api/fleet/epm/packages";
pub(super) const PREBUILT_STATUS_PATH: &str = "/api/detection_engine/rules/prepackaged/_status";
/// Alerts read per cleanup round. The step makes far fewer.
const SESSION_ALERT_PAGE: u64 = 1_000;

/// One request as the recorder sends it. `target` is what the transport
/// receives; `descriptor` is what a fixture keeps as its `request`.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Planned {
    pub(super) method: &'static str,
    pub(super) path: String,
    pub(super) query: Option<String>,
    pub(super) body: Option<Value>,
}

impl Planned {
    fn get(path: String, query: Option<String>) -> Self {
        Self {
            method: "GET",
            path,
            query,
            body: None,
        }
    }

    pub(super) fn target(&self) -> String {
        match &self.query {
            Some(query) => format!("{}?{query}", self.path),
            None => self.path.clone(),
        }
    }

    pub(super) fn descriptor(&self) -> Value {
        let mut descriptor = json!({"method": self.method, "path": self.path});
        if let Some(query) = &self.query {
            descriptor["query"] = json!(query);
        }
        if let Some(body) = &self.body {
            descriptor["body"] = body.clone();
        }
        descriptor
    }
}

/// The two compose rules, in creation order.
pub(super) const MARKER_RULE_IDS: [&str; 2] = [ALERT_RULE_ID, MISSING_RULE_ID];

/// KQL selecting exactly the two compose rules. Parenthesized so it stays
/// one clause when another clause is ANDed to it.
pub(super) fn marker_rule_filter() -> String {
    let clauses: Vec<String> = MARKER_RULE_IDS
        .iter()
        .map(|id| format!("alert.attributes.params.ruleId: \"{id}\""))
        .collect();
    format!("({})", clauses.join(" OR "))
}

/// The technique clause `rules_list` builds, ANDed with the marker filter.
pub(super) fn technique_filter() -> String {
    format!(
        "alert.attributes.params.threat.technique.id: \"{TECHNIQUE}\" AND {}",
        marker_rule_filter()
    )
}

/// `rule_get_executed` and `rule_get_failed_execution`, and every poll that
/// waits for them.
pub(super) fn rule_get(rule_id: &str) -> Planned {
    Planned::get(
        RULES_PATH.to_string(),
        Some(format!("rule_id={}", urlencode(rule_id))),
    )
}

/// `rules_find_sorted_page`: the `rules::find_window` page shape over the
/// marker rules only.
pub(super) fn rules_find_sorted_page() -> Planned {
    Planned::get(
        RULES_FIND_PATH.to_string(),
        Some(format!(
            "page=1&per_page={SORTED_PAGE_SIZE}&sort_field=created_at&sort_order=asc&filter={}",
            urlencode(&marker_rule_filter())
        )),
    )
}

/// `rules_find_by_technique`: the `rules_list` page shape at its default
/// limit, with the technique clause.
pub(super) fn rules_find_by_technique() -> Planned {
    Planned::get(
        RULES_FIND_PATH.to_string(),
        Some(format!(
            "page=1&per_page={TECHNIQUE_PAGE_SIZE}&sort_field=name&sort_order=asc&filter={}",
            urlencode(&technique_filter())
        )),
    )
}

/// The alert activity body of the composition contract for one rule.
pub(super) fn activity_body(rule_id: &str, since: &str, size: u64) -> Value {
    json!({
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.rule.rule_id": rule_id}},
            {"range": {"@timestamp": {"gte": format!("now-{since}")}}}
        ]}},
        "sort": [{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
        "size": size,
        "track_total_hits": true,
        "aggs": {"status": {"terms": {"field": "kibana.alert.workflow_status", "size": 8}}}
    })
}

/// `signals_search_rule_activity`: the `rule_health` form, `size: 5`.
pub(super) fn signals_activity() -> Planned {
    Planned {
        method: "POST",
        path: elasticctl_api::alerts::SEARCH_PATH.to_string(),
        query: None,
        body: Some(activity_body(ALERT_RULE_ID, ACTIVITY_SINCE, ACTIVITY_SIZE)),
    }
}

/// `cases_by_alert` and `cases_by_alert_none`.
pub(super) fn cases_by_alert(alert_id: &str) -> Planned {
    Planned::get(
        format!("{CASES_BY_ALERT_PATH}/{}", urlencode(alert_id)),
        None,
    )
}

/// `exception_items_count`: the coverage count read on the marker list.
pub(super) fn exception_items_count() -> Planned {
    Planned::get(
        ITEMS_FIND_PATH.to_string(),
        Some(format!(
            "list_id={}&namespace_type={NAMESPACE_TYPE}&page=1&per_page=1",
            urlencode(LIST_ID)
        )),
    )
}

/// The three `resolve_index_*` fixtures, one marker pattern each.
pub(super) fn resolve_index(pattern: &str) -> Planned {
    Planned::get(format!("{RESOLVE_INDEX_PATH}/{}", urlencode(pattern)), None)
}

/// `package_not_installed`, and each probe before it.
pub(super) fn package_status(name: &str) -> Planned {
    Planned::get(format!("{PACKAGES_PATH}/{}", urlencode(name)), None)
}

/// Poll body that counts only this session's alerts: the marker rule id and
/// the rule's per-creation saved-object id together. Never recorded.
pub(super) fn session_alert_count_body(rule_uuid: &str) -> Value {
    json!({
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}},
            {"term": {"kibana.alert.rule.uuid": rule_uuid}}
        ]}},
        "size": 0,
        "track_total_hits": true
    })
}

/// Read body for the private `kibana.alert.case_ids` measurement on one
/// marker alert. Never recorded.
pub(super) fn case_ids_probe_body(alert_id: &str) -> Value {
    json!({
        "query": {"ids": {"values": [alert_id]}},
        "size": 1,
        "_source": ["kibana.alert.case_ids"]
    })
}

/// Cleanup read of the alert ids this run's rule produced that are not yet
/// closed. The rule's per-creation saved-object id keeps alerts of every
/// earlier run out. Never recorded.
pub(super) fn open_session_alerts_body(rule_uuid: &str) -> Value {
    json!({
        "query": {"bool": {
            "filter": [
                {"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}},
                {"term": {"kibana.alert.rule.uuid": rule_uuid}}
            ],
            "must_not": [{"term": {"kibana.alert.workflow_status": "closed"}}]
        }},
        "size": SESSION_ALERT_PAGE,
        "_source": false,
        "track_total_hits": true
    })
}

/// Close exactly the named alerts. Never a query.
pub(super) fn close_alerts_body(alert_ids: &[String]) -> Value {
    json!({"signal_ids": alert_ids, "status": "closed"})
}

/// The marker exception list read.
pub(super) fn list_path() -> String {
    format!(
        "/api/exception_lists?list_id={}&namespace_type={NAMESPACE_TYPE}",
        urlencode(LIST_ID)
    )
}

/// One marker exception item read or delete.
pub(super) fn item_path(item_id: &str) -> String {
    format!(
        "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
        urlencode(item_id)
    )
}

/// Create-only marker document write: Elasticsearch answers 409 when the
/// id already exists instead of overwriting it.
pub(super) fn marker_document_path(index: &str, seq: usize) -> String {
    format!("/{index}/_create/{seq}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::compose::{
        ABSENT_ALERT_ID, MATCH_PATTERN, MISSING_INDEX, NO_MATCH_PATTERN, PACKAGE_CANDIDATES,
    };

    const MARKER_FILTER: &str = "(alert.attributes.params.ruleId: \"elasticctl-sample-alert-probe\" OR alert.attributes.params.ruleId: \"elasticctl-sample-compose-missing-index\")";

    fn decoded_filter(planned: &Planned) -> String {
        let query = planned.query.as_deref().expect("query");
        let encoded = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("filter="))
            .expect("filter parameter");
        percent_decode(encoded)
    }

    fn percent_decode(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("hex");
                out.push(u8::from_str_radix(hex, 16).expect("hex digit"));
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn rule_reads_target_one_marker_rule_id() {
        for (rule_id, query) in [
            (ALERT_RULE_ID, "rule_id=elasticctl-sample-alert-probe"),
            (
                MISSING_RULE_ID,
                "rule_id=elasticctl-sample-compose-missing-index",
            ),
        ] {
            let planned = rule_get(rule_id);
            assert_eq!(planned.method, "GET");
            assert_eq!(planned.path, "/api/detection_engine/rules");
            assert_eq!(planned.query.as_deref(), Some(query));
            assert_eq!(planned.body, None);
        }
    }

    #[test]
    fn sorted_page_uses_the_window_shape_over_marker_ids_only() {
        let planned = rules_find_sorted_page();
        assert_eq!(planned.method, "GET");
        assert_eq!(planned.path, "/api/detection_engine/rules/_find");
        assert_eq!(
            planned.query.as_deref(),
            Some(
                "page=1&per_page=500&sort_field=created_at&sort_order=asc&filter=%28alert.attributes.params.ruleId%3A%20%22elasticctl-sample-alert-probe%22%20OR%20alert.attributes.params.ruleId%3A%20%22elasticctl-sample-compose-missing-index%22%29"
            )
        );
        assert_eq!(decoded_filter(&planned), MARKER_FILTER);
        assert_eq!(planned.body, None);
    }

    #[test]
    fn technique_page_ands_the_technique_clause_with_the_marker_filter() {
        let planned = rules_find_by_technique();
        assert_eq!(planned.method, "GET");
        assert_eq!(planned.path, "/api/detection_engine/rules/_find");
        let query = planned.query.as_deref().expect("query");
        assert!(
            query.starts_with("page=1&per_page=50&sort_field=name&sort_order=asc&filter="),
            "{query}"
        );
        assert_eq!(
            decoded_filter(&planned),
            format!("alert.attributes.params.threat.technique.id: \"T1059\" AND {MARKER_FILTER}")
        );
        assert_eq!(planned.body, None);
    }

    #[test]
    fn signals_activity_sends_the_contract_body_with_size_five() {
        let planned = signals_activity();
        assert_eq!(planned.method, "POST");
        assert_eq!(planned.path, "/api/detection_engine/signals/search");
        assert_eq!(planned.query, None);
        let expected: Value = serde_json::from_str(
            r#"{
              "query": {"bool": {"filter": [
                {"term": {"kibana.alert.rule.rule_id": "elasticctl-sample-alert-probe"}},
                {"range": {"@timestamp": {"gte": "now-24h"}}}
              ]}},
              "sort": [{"@timestamp": {"order": "desc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
              "size": 5,
              "track_total_hits": true,
              "aggs": {"status": {"terms": {"field": "kibana.alert.workflow_status", "size": 8}}}
            }"#,
        )
        .expect("contract body");
        let normalize = |value: &Value| {
            serde_json::from_str::<Value>(&serde_json::to_string(value).expect("encode"))
                .expect("decode")
        };
        assert_eq!(
            normalize(planned.body.as_ref().expect("body")),
            normalize(&expected)
        );
    }

    #[test]
    fn cases_by_alert_names_one_alert_id_as_one_segment() {
        let planned = cases_by_alert(ABSENT_ALERT_ID);
        assert_eq!(planned.method, "GET");
        assert_eq!(
            planned.path,
            "/api/cases/alerts/elasticctl-sample-absent-alert"
        );
        assert_eq!(planned.query, None);
        assert_eq!(planned.body, None);
        assert_eq!(cases_by_alert("a/b").path, "/api/cases/alerts/a%2Fb");
    }

    #[test]
    fn item_count_reads_one_item_of_the_marker_list() {
        let planned = exception_items_count();
        assert_eq!(planned.method, "GET");
        assert_eq!(planned.path, "/api/exception_lists/items/_find");
        assert_eq!(
            planned.query.as_deref(),
            Some("list_id=elasticctl-sample-exceptions&namespace_type=single&page=1&per_page=1")
        );
        assert_eq!(planned.body, None);
    }

    #[test]
    fn resolve_reads_name_only_marker_patterns() {
        for (pattern, path) in [
            (
                MATCH_PATTERN,
                "/_resolve/index/elasticctl-sample-alert-events%2A",
            ),
            (
                NO_MATCH_PATTERN,
                "/_resolve/index/elasticctl-sample-compose-none-%2A",
            ),
            (
                MISSING_INDEX,
                "/_resolve/index/elasticctl-sample-compose-missing",
            ),
        ] {
            let planned = resolve_index(pattern);
            assert_eq!(planned.method, "GET");
            assert_eq!(planned.path, path);
            assert_eq!(planned.query, None);
            assert_eq!(planned.body, None);
        }
    }

    #[test]
    fn package_status_reads_one_named_package() {
        let paths: Vec<String> = PACKAGE_CANDIDATES
            .iter()
            .map(|name| package_status(name).target())
            .collect();
        assert_eq!(
            paths,
            [
                "/api/fleet/epm/packages/apache",
                "/api/fleet/epm/packages/nginx",
                "/api/fleet/epm/packages/mysql",
            ]
        );
    }

    #[test]
    fn every_recorded_request_names_only_marker_objects() {
        let recorded = [
            rule_get(ALERT_RULE_ID),
            rule_get(MISSING_RULE_ID),
            rules_find_sorted_page(),
            rules_find_by_technique(),
            signals_activity(),
            cases_by_alert("elasticctl-fixture-alert-1"),
            cases_by_alert(ABSENT_ALERT_ID),
            exception_items_count(),
            resolve_index(MATCH_PATTERN),
            resolve_index(NO_MATCH_PATTERN),
            resolve_index(MISSING_INDEX),
        ];
        for planned in &recorded {
            let text = format!(
                "{} {}",
                percent_decode(&planned.target()),
                planned
                    .body
                    .as_ref()
                    .map(Value::to_string)
                    .unwrap_or_default()
            );
            // Every quoted identifier and every rule, list, or index value is
            // a marker name.
            for value in quoted_values(&text) {
                if value.starts_with("elasticctl-")
                    || value.starts_with("kibana.alert.")
                    || matches!(
                        value.as_str(),
                        "T1059" | "@timestamp" | "now-24h" | "desc" | "asc"
                    )
                {
                    continue;
                }
                panic!("unexpected quoted value {value:?} in {}", planned.target());
            }
            for key in [
                "rule_id=",
                "list_id=",
                "/_resolve/index/",
                "/api/cases/alerts/",
            ] {
                if let Some((_, rest)) = text.split_once(key) {
                    assert!(rest.starts_with("elasticctl-"), "{text}");
                }
            }
            assert!(!text.contains("ruleId: \"*"), "{text}");
        }
        let body = signals_activity().body.expect("body");
        assert_eq!(
            body["query"]["bool"]["filter"][0]["term"]["kibana.alert.rule.rule_id"],
            ALERT_RULE_ID
        );
    }

    #[test]
    fn unrecorded_poll_bodies_are_scoped_to_the_session() {
        let count = session_alert_count_body("so-1");
        assert_eq!(
            count["query"]["bool"]["filter"],
            json!([
                {"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}},
                {"term": {"kibana.alert.rule.uuid": "so-1"}}
            ])
        );
        assert_eq!(count["size"], 0);
        assert_eq!(
            case_ids_probe_body("a1")["query"],
            json!({"ids": {"values": ["a1"]}})
        );
    }

    #[test]
    fn cleanup_alert_bodies_name_this_run_and_explicit_ids_only() {
        let open = open_session_alerts_body("so-1");
        assert_eq!(
            open["query"]["bool"]["filter"],
            json!([
                {"term": {"kibana.alert.rule.rule_id": ALERT_RULE_ID}},
                {"term": {"kibana.alert.rule.uuid": "so-1"}}
            ])
        );
        assert_eq!(
            open["query"]["bool"]["must_not"],
            json!([{"term": {"kibana.alert.workflow_status": "closed"}}])
        );
        assert_eq!(open["_source"], false);
        let close = close_alerts_body(&["a1".to_string(), "a2".to_string()]);
        assert_eq!(
            close,
            json!({"signal_ids": ["a1", "a2"], "status": "closed"})
        );
        assert!(close.get("query").is_none());
    }

    #[test]
    fn marker_documents_use_the_create_only_route() {
        assert_eq!(
            marker_document_path("elasticctl-sample-alert-events", 3),
            "/elasticctl-sample-alert-events/_create/3"
        );
        assert_eq!(
            item_path("elasticctl-sample-exception-item-2"),
            "/api/exception_lists/items?item_id=elasticctl-sample-exception-item-2&namespace_type=single"
        );
        assert_eq!(
            list_path(),
            "/api/exception_lists?list_id=elasticctl-sample-exceptions&namespace_type=single"
        );
    }

    fn quoted_values(text: &str) -> Vec<String> {
        text.split('"')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, value)| value.to_string())
            .filter(|value| {
                !matches!(
                    value.as_str(),
                    "query"
                        | "bool"
                        | "filter"
                        | "term"
                        | "range"
                        | "gte"
                        | "sort"
                        | "order"
                        | "size"
                        | "track_total_hits"
                        | "aggs"
                        | "status"
                        | "terms"
                        | "field"
                )
            })
            .collect()
    }
}
