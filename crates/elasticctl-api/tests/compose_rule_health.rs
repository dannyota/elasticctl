use elasticctl_api::compose::{
    Part, RECENT_ALERTS,
    rule_health::{HealthFinding, RuleHealth, rule_health},
};
use elasticctl_core::{ErrorKind, Profile, Result, Transport};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const SET: &str = "serverless-9.7.0";
const RULES: &str = "/api/detection_engine/rules";
const FIND: &str = "/api/detection_engine/rules/_find";
const SIGNALS: &str = "/api/detection_engine/signals/search";
const LISTS: &str = "/api/exception_lists";
const ITEMS: &str = "/api/exception_lists/items/_find";
const STATUS: &str = "/api/status";
const PROBE: &str = "elasticctl-sample-alert-probe";
const PROBE_NAME: &str = "elasticctl sample compose rule";

fn recorded(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(SET)
        .join(name);
    serde_json::from_str::<Value>(&std::fs::read_to_string(p).unwrap()).unwrap()["response"].clone()
}

fn profile(uri: String, timeout_secs: u64) -> Profile {
    Profile {
        kibana_url: uri,
        es_url: None,
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs,
    }
}

fn transport(s: &MockServer) -> Transport {
    Transport::new(&profile(s.uri(), 5)).unwrap()
}

fn list_id(i: usize) -> String {
    let base = recorded("rule_get_executed.json")["exceptions_list"][0]["list_id"]
        .as_str()
        .unwrap()
        .to_owned();
    if i == 0 { base } else { format!("{base}-{i}") }
}

fn rule_with_lists(count: usize) -> Value {
    let mut rule = recorded("rule_get_executed.json");
    let template = rule["exceptions_list"][0].clone();
    rule["exceptions_list"] = (0..count)
        .map(|i| {
            let mut r = template.clone();
            r["list_id"] = json!(list_id(i));
            r
        })
        .collect();
    rule
}

fn label(method: &str, path: &str, query: &[(String, String)]) -> Option<String> {
    let q = |k: &str| {
        query
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    Some(match (method, path) {
        (_, STATUS) => return None,
        ("GET", RULES) => format!("rule {}", q("rule_id")),
        ("GET", FIND) => "find".into(),
        ("POST", SIGNALS) => "signals".into(),
        ("GET", LISTS) => format!("list {}", q("list_id")),
        ("GET", ITEMS) => format!("count {}", q("list_id")),
        _ => format!("{method} {path}"),
    })
}

async fn log(s: &MockServer) -> Vec<String> {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|r| {
            let query = r
                .url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect::<Vec<_>>();
            label(r.method.as_str(), r.url.path(), &query)
        })
        .collect()
}

fn plan(lists: usize) -> Vec<String> {
    let mut out = vec![format!("rule {PROBE}"), "signals".into()];
    for i in 0..lists.min(5) {
        out.push(format!("list {}", list_id(i)));
        out.push(format!("count {}", list_id(i)));
    }
    out
}

async fn stack(rule: Value, activity: Value) -> MockServer {
    let s = MockServer::start().await;
    for (verb, route, body) in [
        ("GET", STATUS, recorded("status.json")),
        ("POST", SIGNALS, activity),
        ("GET", LISTS, recorded("exception_list_get.json")),
        ("GET", ITEMS, recorded("exception_items_count.json")),
        ("GET", FIND, recorded("rules_find_sorted_page.json")),
    ] {
        Mock::given(method(verb))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", PROBE))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", PROBE_NAME))
        .respond_with(ResponseTemplate::new(404))
        .mount(&s)
        .await;
    s
}

async fn override_route(
    s: &MockServer,
    verb: &str,
    route: &str,
    list: Option<&str>,
    response: ResponseTemplate,
) {
    let mock = Mock::given(method(verb)).and(path(route));
    let mock = match list {
        Some(id) => mock.and(query_param("list_id", id)),
        None => mock,
    };
    mock.respond_with(response).with_priority(1).mount(s).await;
}

fn activity() -> Value {
    recorded("signals_search_rule_activity.json")
}

#[tokio::test]
async fn rule_id_selector_reads_one_rule_then_activity_then_coverage() {
    let s = stack(rule_with_lists(1), activity()).await;
    let h = rule_health(&transport(&s), PROBE, "24h").await.unwrap();
    assert_eq!(log(&s).await, plan(1));
    let Part::Ok(alerts) = &h.alerts else {
        panic!("alerts part is ok")
    };
    assert_eq!(alerts.window, "24h");
    assert_eq!(
        alerts.total,
        activity()["hits"]["total"]["value"].as_u64().unwrap()
    );
    assert_eq!(alerts.recent.len(), RECENT_ALERTS);
    let Part::Ok(coverage) = &h.exceptions else {
        panic!("exceptions part is ok")
    };
    assert_eq!(coverage.referenced, 1);
    assert_eq!(
        coverage.lists[0].facts.as_ref().unwrap().item_count,
        recorded("exception_items_count.json")["total"]
            .as_u64()
            .unwrap()
    );
    assert!(h.findings().is_empty());
    assert!(!h.partial());
    let requests = s.received_requests().await.unwrap();
    let count = requests.iter().find(|r| r.url.path() == ITEMS).unwrap();
    let q = count
        .url
        .query_pairs()
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!((q["page"].as_ref(), q["per_page"].as_ref()), ("1", "1"));
}

#[tokio::test]
async fn activity_request_asks_for_the_five_newest_alerts() {
    let s = stack(rule_with_lists(0), activity()).await;
    rule_health(&transport(&s), PROBE, "7d").await.unwrap();
    let expected = json!({"query":{"bool":{"filter":[{"term":{"kibana.alert.rule.rule_id":PROBE}},{"range":{"@timestamp":{"gte":"now-7d"}}}]}},"sort":[{"@timestamp":{"order":"desc"}},{"kibana.alert.uuid":{"order":"asc"}}],"size":5,"track_total_hits":true,"aggs":{"status":{"terms":{"field":"kibana.alert.workflow_status","size":8}}}});
    let requests = s.received_requests().await.unwrap();
    let signals = requests.iter().find(|r| r.url.path() == SIGNALS).unwrap();
    let actual: Value = serde_json::from_slice(&signals.body).unwrap();
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    assert_eq!(log(&s).await, plan(0));
}

#[tokio::test]
async fn recent_alerts_stop_at_five() {
    let mut body = activity();
    let hits = body["hits"]["hits"].as_array().unwrap().clone();
    let more = (0..7)
        .map(|i| {
            let mut h = hits[i % hits.len()].clone();
            h["_id"] = json!(format!("{}-{i}", h["_id"].as_str().unwrap()));
            h
        })
        .collect::<Vec<_>>();
    body["hits"]["hits"] = json!(more);
    let s = stack(rule_with_lists(0), body).await;
    let h = rule_health(&transport(&s), PROBE, "24h").await.unwrap();
    let Part::Ok(alerts) = &h.alerts else {
        panic!("alerts part is ok")
    };
    assert_eq!(alerts.recent.len(), 5);
}

#[tokio::test]
async fn name_selector_reads_three_rule_requests() {
    let s = stack(rule_with_lists(1), activity()).await;
    rule_health(&transport(&s), PROBE_NAME, "24h")
        .await
        .unwrap();
    let mut expected = vec![format!("rule {PROBE_NAME}"), "find".into()];
    expected.extend(plan(1));
    assert_eq!(log(&s).await, expected);
}

#[tokio::test]
async fn ambiguous_name_is_a_conflict_with_no_later_request() {
    let s = stack(rule_with_lists(1), activity()).await;
    let mut find = recorded("rules_find_sorted_page.json");
    for rule in find["data"].as_array_mut().unwrap() {
        rule["name"] = json!(PROBE_NAME);
    }
    override_route(
        &s,
        "GET",
        FIND,
        None,
        ResponseTemplate::new(200).set_body_json(find),
    )
    .await;
    let e = rule_health(&transport(&s), PROBE_NAME, "24h")
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Conflict);
    assert_eq!(log(&s).await, [format!("rule {PROBE_NAME}"), "find".into()]);
}

#[tokio::test]
async fn invalid_window_sends_nothing() {
    let s = stack(rule_with_lists(1), activity()).await;
    for since in ["0h", "24", "now-1d", "1H", "24h ", "10000d"] {
        let e = rule_health(&transport(&s), PROBE, since).await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Error, "{since}");
    }
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn maximum_plan_is_fourteen_requests() {
    let s = stack(rule_with_lists(6), activity()).await;
    let h = rule_health(&transport(&s), PROBE_NAME, "24h")
        .await
        .unwrap();
    let mut expected = vec![format!("rule {PROBE_NAME}"), "find".into()];
    expected.extend(plan(6));
    let actual = log(&s).await;
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 14);
    let Part::Ok(coverage) = &h.exceptions else {
        panic!("exceptions part is ok")
    };
    assert_eq!(
        (
            coverage.referenced,
            coverage.truncated,
            coverage.lists.len()
        ),
        (6, true, 5)
    );
}

#[tokio::test]
async fn a_denied_activity_read_still_reads_exceptions() {
    let s = stack(rule_with_lists(2), activity()).await;
    override_route(&s, "POST", SIGNALS, None, ResponseTemplate::new(403)).await;
    let h = rule_health(&transport(&s), PROBE, "24h").await.unwrap();
    assert_eq!(log(&s).await, plan(2));
    assert!(matches!(&h.alerts, Part::Unavailable(e) if e.kind == ErrorKind::Permission));
    let Part::Ok(coverage) = &h.exceptions else {
        panic!("exceptions part is ok")
    };
    assert!(coverage.lists.iter().all(|row| row.facts.is_ok()));
    assert!(h.partial());
    assert!(h.findings().is_empty());
}

#[tokio::test]
async fn a_missing_list_keeps_activity_and_skips_its_count() {
    let s = stack(rule_with_lists(2), activity()).await;
    override_route(
        &s,
        "GET",
        LISTS,
        Some(&list_id(0)),
        ResponseTemplate::new(404),
    )
    .await;
    let h = rule_health(&transport(&s), PROBE, "24h").await.unwrap();
    let mut expected = plan(2);
    expected.remove(3);
    assert_eq!(log(&s).await, expected);
    assert!(matches!(h.alerts, Part::Ok(_)));
    assert!(h.partial());
    assert_eq!(h.findings(), [HealthFinding::ExceptionListMissing]);
}

#[tokio::test]
async fn auth_and_timeout_in_a_part_fail_the_call_with_no_later_request() {
    let stages: [(&str, &str, Option<String>, usize); 4] = [
        ("POST", SIGNALS, None, 2),
        ("GET", LISTS, Some(list_id(0)), 3),
        ("GET", ITEMS, Some(list_id(0)), 4),
        ("GET", LISTS, Some(list_id(1)), 5),
    ];
    for (verb, route, list, sent) in stages {
        for kind in [ErrorKind::Auth, ErrorKind::Timeout] {
            let s = stack(rule_with_lists(2), activity()).await;
            let (response, timeout_secs) = match kind {
                ErrorKind::Auth => (ResponseTemplate::new(401), 5),
                _ => (
                    ResponseTemplate::new(200).set_delay(Duration::from_millis(1_500)),
                    1,
                ),
            };
            override_route(&s, verb, route, list.as_deref(), response).await;
            let t = Transport::new(&profile(s.uri(), timeout_secs)).unwrap();
            let e = rule_health(&t, PROBE, "24h").await.unwrap_err();
            assert_eq!(e.kind, kind, "{route} {list:?}");
            assert_eq!(log(&s).await, plan(2)[..sent], "{route} {list:?} {kind:?}");
        }
    }
}

async fn closing_server(dropped: String) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let n = socket.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(i + 4);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let length = head
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + length {
                let n = socket.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            let mut words = head.split_whitespace();
            let verb = words.next().unwrap_or_default().to_owned();
            let target = words.next().unwrap_or_default().to_owned();
            let (route, query) = target.split_once('?').unwrap_or((&target, ""));
            let query = query
                .split('&')
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect::<Vec<_>>();
            let name = label(&verb, route, &query);
            if let Some(name) = &name {
                log.lock().unwrap().push(name.clone());
            }
            if name.as_deref() == Some(dropped.as_str()) {
                continue;
            }
            let body = match (verb.as_str(), route) {
                (_, STATUS) => recorded("status.json"),
                (_, RULES) => rule_with_lists(2),
                (_, SIGNALS) => activity(),
                (_, LISTS) => recorded("exception_list_get.json"),
                _ => recorded("exception_items_count.json"),
            }
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    (url, seen)
}

#[tokio::test]
async fn a_dropped_connection_in_a_part_fails_the_call_with_no_later_request() {
    for sent in 2..=5 {
        let drop = plan(2)[sent - 1].clone();
        let (url, seen) = closing_server(drop.clone()).await;
        let t = Transport::new(&profile(url, 5)).unwrap();
        let e = rule_health(&t, PROBE, "24h").await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::Connection, "{drop}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*seen.lock().unwrap(), plan(2)[..sent], "{drop}");
    }
}

async fn health_of(rule: Value, activity: Value, missing_list: bool) -> Result<RuleHealth> {
    let s = stack(rule, activity).await;
    if missing_list {
        override_route(&s, "GET", LISTS, None, ResponseTemplate::new(404)).await;
    }
    rule_health(&transport(&s), PROBE, "24h").await
}

fn executed() -> Value {
    rule_with_lists(1)
}

fn with_execution(mut rule: Value, field: &str, value: Value) -> Value {
    rule["execution_summary"]["last_execution"][field] = value;
    rule
}

fn quiet_activity() -> Value {
    let mut body = activity();
    body["hits"]["total"]["value"] = json!(0);
    body["hits"]["hits"] = json!([]);
    body["aggregations"]["status"]["buckets"] = json!([]);
    body
}

#[tokio::test]
async fn one_finding_per_code() {
    use HealthFinding::*;
    let mut disabled = executed();
    disabled["enabled"] = json!(false);
    let mut never = executed();
    never.as_object_mut().unwrap().remove("execution_summary");
    let mut gap = executed();
    gap["execution_summary"]["last_execution"]["metrics"]["execution_gap_duration_s"] = json!(12);
    let mut no_gap = executed();
    no_gap["execution_summary"]["last_execution"]["metrics"]["execution_gap_duration_s"] = json!(0);
    let mut partial = recorded("rule_get_failed_execution.json");
    partial["rule_id"] = json!(PROBE);
    let cases: Vec<(&str, Value, Value, bool, Vec<HealthFinding>)> = vec![
        ("baseline", executed(), activity(), false, vec![]),
        ("disabled", disabled, activity(), false, vec![RuleDisabled]),
        ("never", never, activity(), false, vec![NeverExecuted]),
        (
            "failed",
            with_execution(executed(), "status", json!("failed")),
            activity(),
            false,
            vec![LastExecutionFailed],
        ),
        (
            "partial",
            partial,
            activity(),
            false,
            vec![LastExecutionPartialFailure],
        ),
        ("gap", gap, activity(), false, vec![ExecutionGap]),
        ("no gap", no_gap, activity(), false, vec![]),
        (
            "quiet",
            executed(),
            quiet_activity(),
            false,
            vec![NoAlertsInWindow],
        ),
        (
            "missing",
            executed(),
            activity(),
            true,
            vec![ExceptionListMissing],
        ),
    ];
    for (name, rule, body, missing, expected) in cases {
        let h = health_of(rule, body, missing).await.unwrap();
        assert_eq!(h.findings(), expected, "{name}");
    }
}

#[tokio::test]
async fn unknown_status_yields_no_finding_and_is_returned() {
    let rule = with_execution(executed(), "status", json!("elasticctl-unknown-status"));
    let h = health_of(rule, activity(), false).await.unwrap();
    assert!(h.findings().is_empty());
    assert_eq!(
        h.rule.execution.unwrap().status,
        "elasticctl-unknown-status"
    );
}

#[tokio::test]
async fn disabled_rule_without_execution_is_only_disabled() {
    let mut rule = executed();
    rule["enabled"] = json!(false);
    rule.as_object_mut().unwrap().remove("execution_summary");
    let h = health_of(rule, activity(), false).await.unwrap();
    assert_eq!(h.findings(), [HealthFinding::RuleDisabled]);
}

#[tokio::test]
async fn findings_keep_the_fixed_order() {
    use HealthFinding::*;
    let mut rule = with_execution(executed(), "status", json!("partial failure"));
    rule["enabled"] = json!(false);
    rule["execution_summary"]["last_execution"]["metrics"]["execution_gap_duration_s"] = json!(3);
    let h = health_of(rule, quiet_activity(), true).await.unwrap();
    assert_eq!(
        h.findings(),
        [
            RuleDisabled,
            LastExecutionPartialFailure,
            ExecutionGap,
            NoAlertsInWindow,
            ExceptionListMissing
        ]
    );
}

#[tokio::test]
async fn unavailable_activity_emits_no_window_finding() {
    let s = stack(executed(), quiet_activity()).await;
    override_route(&s, "POST", SIGNALS, None, ResponseTemplate::new(403)).await;
    let h = rule_health(&transport(&s), PROBE, "24h").await.unwrap();
    assert!(h.findings().is_empty());
    assert!(h.partial());
}
