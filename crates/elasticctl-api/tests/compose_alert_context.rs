//! `compose::alert_context`: request plan, part rules, caps, and findings.
//!
//! A small scripted HTTP server stands in for the stack so a test can answer
//! any step with a recorded body, an error status, a dropped connection, or
//! no answer at all, and then compare the exact request sequence.
use elasticctl_api::compose::{
    Part, SkipReason,
    alert_context::{self, AlertFinding},
};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const FIXTURES: &str = "serverless-9.7.0";
const ALERT_ID: &str = "elasticctl-fixture-alert-1";
const RULE_ID: &str = "elasticctl-sample-alert-probe";

fn recorded_file(name: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(FIXTURES)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn fixture(name: &str) -> Value {
    let v = recorded_file(name)["response"].clone();
    assert!(!v.is_null(), "fixture {name} has a response");
    v
}
/// A recorded error body, sent with a chosen status.
fn error_body() -> Value {
    recorded_file("data_view_not_found.json")["error"].clone()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Alert,
    Rule,
    List,
    Count,
    Cases,
    Case,
    Activity,
    Other,
}
use Step::*;

#[derive(Clone, Debug)]
struct Req {
    method: String,
    target: String,
    body: Value,
}
impl Req {
    fn path(&self) -> &str {
        self.target.split('?').next().unwrap()
    }
    fn query(&self, key: &str) -> Option<String> {
        let q = self.target.split_once('?')?.1;
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_owned())
    }
}

enum Act {
    Json(u16, Value),
    Drop,
    Hang,
    Oversized,
}

fn step_of(r: &Req) -> Option<Step> {
    Some(match (r.method.as_str(), r.path()) {
        ("GET", "/api/status") => return None,
        ("POST", "/api/detection_engine/signals/search") if r.body["size"] == 0 => Activity,
        ("POST", "/api/detection_engine/signals/search") => Alert,
        ("GET", "/api/detection_engine/rules") => Rule,
        ("GET", "/api/exception_lists") => List,
        ("GET", "/api/exception_lists/items/_find") => Count,
        ("GET", p) if p.starts_with("/api/cases/alerts/") => Cases,
        ("GET", p) if p.starts_with("/api/cases/") => Case,
        _ => Other,
    })
}

type Route = Arc<dyn Fn(Step, &Req) -> Act + Send + Sync>;
type Log = Arc<Mutex<Vec<Req>>>;

struct Stack {
    url: String,
    log: Log,
}

impl Stack {
    async fn start(route: impl Fn(Step, &Req) -> Act + Send + Sync + 'static) -> Stack {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let route: Route = Arc::new(route);
        let shared = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&route), Arc::clone(&shared)));
            }
        });
        Stack { url, log }
    }
    fn transport(&self, timeout_secs: u64) -> Transport {
        Transport::with_options(
            &Profile {
                kibana_url: self.url.clone(),
                es_url: None,
                api_key: Some("test".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs,
            },
            elasticctl_core::TransportOptions {
                response_body_limit: Some(16_777_216),
                ..Default::default()
            },
        )
        .unwrap()
    }
    /// Every request in arrival order, without the cached capability probe.
    fn requests(&self) -> Vec<Req> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|r| step_of(r).is_some())
            .cloned()
            .collect()
    }
    fn steps(&self) -> Vec<Step> {
        self.requests().iter().filter_map(step_of).collect()
    }
    fn all(&self) -> usize {
        self.log.lock().unwrap().len()
    }
}

async fn serve(mut stream: TcpStream, route: Route, log: Log) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split(' ');
    let method = first.next().unwrap().to_owned();
    let target = first.next().unwrap().to_owned();
    let len = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.trim().parse::<usize>().unwrap());
    while buf.len() < head_end + len {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = serde_json::from_slice(&buf[head_end..head_end + len]).unwrap_or(Value::Null);
    let req = Req {
        method,
        target,
        body,
    };
    log.lock().unwrap().push(req.clone());
    let act = match step_of(&req) {
        None => Act::Json(200, fixture("status.json")),
        Some(step) => route(step, &req),
    };
    match act {
        Act::Json(status, body) => {
            let body = serde_json::to_vec(&body).unwrap();
            let head = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.flush().await;
        }
        Act::Oversized => {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 16777217\r\nconnection: close\r\n\r\n",
                )
                .await;
        }
        Act::Drop => drop(stream),
        Act::Hang => tokio::time::sleep(Duration::from_secs(30)).await,
    }
}

/// The recorded alert as a one-hit search page, with `edit` applied to it.
fn alert_page(edit: impl FnOnce(&mut Value)) -> Value {
    let mut page = fixture("signals_search_rule_activity.json");
    let mut hit = page["hits"]["hits"][0].clone();
    assert_eq!(hit["_id"], ALERT_ID);
    edit(&mut hit);
    page["hits"]["hits"] = json!([hit]);
    page["hits"]["total"]["value"] = json!(1);
    page.as_object_mut().unwrap().remove("aggregations");
    page
}
/// The recorded rule with `n` exception references derived from its first.
fn rule_with_refs(n: usize) -> Value {
    let mut rule = fixture("rule_get_executed.json");
    let first = rule["exceptions_list"][0].clone();
    rule["exceptions_list"] = json!(
        (0..n)
            .map(|i| {
                let mut r = first.clone();
                r["list_id"] = json!(format!("{}-{i}", first["list_id"].as_str().unwrap()));
                r
            })
            .collect::<Vec<_>>()
    );
    rule
}
/// The recorded cases-by-alert answer with `n` rows derived from its first.
fn case_refs(n: usize) -> Value {
    let row = fixture("cases_by_alert.json")[0].clone();
    json!(
        (0..n)
            .map(|i| {
                let mut r = row.clone();
                r["id"] = json!(format!("case-{i}"));
                r["title"] = json!(format!("title-{i}"));
                r
            })
            .collect::<Vec<_>>()
    )
}
fn case_detail(req: &Req) -> Value {
    let mut case = fixture("case_get.json");
    case["id"] = json!(req.path().trim_start_matches("/api/cases/"));
    case
}
/// The recorded activity answer as a `size: 0` search returns it.
fn activity() -> Value {
    let mut body = fixture("signals_search_rule_activity.json");
    body["hits"]["hits"] = json!([]);
    body
}

/// Recorded answers for a rule with `refs` exception references and an
/// alert in `cases` cases.
fn recorded(refs: usize, cases: usize) -> impl Fn(Step, &Req) -> Act + Send + Sync + Clone {
    move |step, req| match step {
        Alert => Act::Json(200, alert_page(|_| ())),
        Rule => Act::Json(200, rule_with_refs(refs)),
        List => Act::Json(200, fixture("exception_list_get.json")),
        Count => Act::Json(200, fixture("exception_items_count.json")),
        Cases => Act::Json(200, case_refs(cases)),
        Case => Act::Json(200, case_detail(req)),
        Activity => Act::Json(200, activity()),
        Other => Act::Json(404, error_body()),
    }
}

fn kind<T>(part: &Part<T>) -> Option<ErrorKind> {
    match part {
        Part::Unavailable(e) => Some(e.kind),
        _ => None,
    }
}
fn skipped<T>(part: &Part<T>) -> Option<SkipReason> {
    match part {
        Part::Skipped(r) => Some(*r),
        _ => None,
    }
}

#[tokio::test]
async fn full_success_follows_the_plan_in_order() {
    let s = Stack::start(recorded(1, 1)).await;
    let t = s.transport(5);
    let c = alert_context::alert_context(&t, ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Rule, List, Count, Cases, Case, Activity]);
    let r = s.requests();
    assert_eq!(
        r[0].body,
        json!({"query":{"ids":{"values":[ALERT_ID]}},"size":1})
    );
    assert_eq!(r[1].query("rule_id").unwrap(), RULE_ID);
    assert_eq!(
        r[2].query("list_id").unwrap(),
        "elasticctl-sample-exceptions-0"
    );
    assert_eq!(
        r[3].query("list_id").unwrap(),
        "elasticctl-sample-exceptions-0"
    );
    assert_eq!(r[3].query("page").unwrap(), "1");
    assert_eq!(r[3].query("per_page").unwrap(), "1");
    assert_eq!(r[4].path(), format!("/api/cases/alerts/{ALERT_ID}"));
    assert_eq!(r[5].path(), "/api/cases/case-0");
    let expected = json!({"query":{"bool":{"filter":[{"term":{"kibana.alert.rule.rule_id":RULE_ID}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},"sort":[{"@timestamp":{"order":"desc"}},{"kibana.alert.uuid":{"order":"asc"}}],"size":0,"track_total_hits":true,"aggs":{"status":{"terms":{"field":"kibana.alert.workflow_status","size":8}}}});
    assert_eq!(r[6].body, expected);

    assert_eq!(c.alert.id, ALERT_ID);
    let Part::Ok(rule) = &c.rule else {
        panic!("rule part")
    };
    assert_eq!(rule.execution.as_ref().unwrap().status, "succeeded");
    let Part::Ok(ex) = &c.exceptions else {
        panic!("exceptions part")
    };
    assert_eq!((ex.referenced, ex.truncated, ex.lists.len()), (1, false, 1));
    assert_eq!(
        ex.lists[0].facts.as_ref().unwrap().item_count,
        fixture("exception_items_count.json")["total"]
            .as_u64()
            .unwrap()
    );
    let Part::Ok(cases) = &c.cases else {
        panic!("cases part")
    };
    assert_eq!((cases.total, cases.truncated), (1, false));
    assert_eq!(cases.cases[0].id, "case-0");
    assert_eq!(cases.cases[0].title.as_deref(), Some("title-0"));
    assert_eq!(cases.cases[0].detail.as_ref().unwrap().id, "case-0");
    let Part::Ok(a) = &c.activity else {
        panic!("activity part")
    };
    let recorded = fixture("signals_search_rule_activity.json");
    assert_eq!(a.window, "24h");
    assert_eq!(
        a.total,
        recorded["hits"]["total"]["value"].as_u64().unwrap()
    );
    assert_eq!((a.open, a.closed, a.acknowledged, a.other), (5, 11, 0, 0));
    assert!(a.recent.is_empty());
    assert!(!c.partial());
    assert_eq!(c.findings(), [AlertFinding::HasRelatedCase]);
}

#[tokio::test]
async fn absent_alert_fails_after_one_request() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| match step {
        Alert => {
            let mut page = alert_page(|_| ());
            page["hits"]["hits"] = json!([]);
            Act::Json(200, page)
        }
        _ => base(step, req),
    })
    .await;
    let e = alert_context::alert_context(&s.transport(5), "absent", "24h")
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::NotFound);
    assert_eq!(s.steps(), [Alert]);
}

#[tokio::test]
async fn alert_without_rule_id_skips_the_rule_parts() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| match step {
        Alert => Act::Json(
            200,
            alert_page(|hit| {
                hit["_source"]
                    .as_object_mut()
                    .unwrap()
                    .remove("kibana.alert.rule.rule_id")
                    .unwrap();
            }),
        ),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Cases, Case]);
    assert_eq!(skipped(&c.rule), Some(SkipReason::NotApplicable));
    assert_eq!(
        skipped(&c.exceptions),
        Some(SkipReason::DependencyUnavailable)
    );
    assert_eq!(
        skipped(&c.activity),
        Some(SkipReason::DependencyUnavailable)
    );
    assert!(matches!(c.cases, Part::Ok(_)));
    assert!(!c.partial());
    assert_eq!(c.findings(), [AlertFinding::HasRelatedCase]);
}

#[tokio::test]
async fn nested_rule_id_is_read_like_alerts_get() {
    let base = recorded(0, 0);
    let s = Stack::start(move |step, req| match step {
        Alert => Act::Json(
            200,
            alert_page(|hit| {
                let source = hit["_source"].as_object_mut().unwrap();
                let id = source.remove("kibana.alert.rule.rule_id").unwrap();
                source.insert("kibana".into(), json!({"alert": {"rule": {"rule_id": id}}}));
            }),
        ),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Rule, Cases, Activity]);
    assert_eq!(s.requests()[1].query("rule_id").unwrap(), RULE_ID);
    assert!(matches!(c.rule, Part::Ok(_)));
    let Part::Ok(cases) = &c.cases else {
        panic!("cases part")
    };
    assert_eq!((cases.total, cases.cases.len()), (0, 0));
    assert!(c.findings().is_empty());
}

#[tokio::test]
async fn missing_rule_is_unavailable_and_cases_still_run() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| match step {
        Rule => Act::Json(404, error_body()),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Rule, Cases, Case]);
    assert_eq!(kind(&c.rule), Some(ErrorKind::NotFound));
    assert_eq!(
        skipped(&c.exceptions),
        Some(SkipReason::DependencyUnavailable)
    );
    assert_eq!(
        skipped(&c.activity),
        Some(SkipReason::DependencyUnavailable)
    );
    assert!(matches!(c.cases, Part::Ok(_)));
    assert!(c.partial());
    assert_eq!(
        c.findings(),
        [AlertFinding::RuleMissing, AlertFinding::HasRelatedCase]
    );
}

#[tokio::test]
async fn seven_cases_read_five_details() {
    let s = Stack::start(recorded(0, 7)).await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(
        s.steps(),
        [Alert, Rule, Cases, Case, Case, Case, Case, Case, Activity]
    );
    let Part::Ok(cases) = &c.cases else {
        panic!("cases part")
    };
    assert_eq!((cases.total, cases.truncated), (7, true));
    let ids: Vec<_> = cases.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["case-0", "case-1", "case-2", "case-3", "case-4"]);
    for (i, req) in s.requests()[3..8].iter().enumerate() {
        assert_eq!(req.path(), format!("/api/cases/case-{i}"));
    }
}

#[tokio::test]
async fn failed_case_detail_keeps_id_and_title() {
    let base = recorded(0, 3);
    let s = Stack::start(move |step, req| match step {
        Case if req.path().ends_with("case-1") => Act::Json(404, error_body()),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Rule, Cases, Case, Case, Case, Activity]);
    let Part::Ok(cases) = &c.cases else {
        panic!("cases part")
    };
    let row = &cases.cases[1];
    assert_eq!(row.id, "case-1");
    assert_eq!(row.title.as_deref(), Some("title-1"));
    assert_eq!(row.detail.as_ref().unwrap_err().kind, ErrorKind::NotFound);
    assert!(cases.cases[0].detail.is_ok() && cases.cases[2].detail.is_ok());
    assert!(c.partial());
    assert_eq!(c.findings(), [AlertFinding::HasRelatedCase]);
}

#[tokio::test]
async fn forbidden_cases_route_degrades_only_cases() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| match step {
        Cases => Act::Json(403, error_body()),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(s.steps(), [Alert, Rule, List, Count, Cases, Activity]);
    assert_eq!(kind(&c.cases), Some(ErrorKind::Permission));
    assert!(matches!(c.rule, Part::Ok(_)));
    assert!(matches!(c.exceptions, Part::Ok(_)));
    assert!(matches!(c.activity, Part::Ok(_)));
    assert!(c.partial());
    assert!(c.findings().is_empty());
}

#[tokio::test]
async fn malformed_cases_route_is_an_http_part_error() {
    let row = fixture("cases_by_alert.json")[0].clone();
    let mut no_id = row.clone();
    no_id.as_object_mut().unwrap().remove("id").unwrap();
    let mut number_id = row.clone();
    number_id["id"] = json!(7);
    let mut dot_id = row.clone();
    dot_id["id"] = json!("..");
    for body in [row, json!([no_id]), json!([number_id]), json!([dot_id])] {
        let base = recorded(1, 1);
        let s = Stack::start(move |step, req| match step {
            Cases => Act::Json(200, body.clone()),
            _ => base(step, req),
        })
        .await;
        let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
            .await
            .unwrap();
        assert_eq!(s.steps(), [Alert, Rule, List, Count, Cases, Activity]);
        assert_eq!(kind(&c.cases), Some(ErrorKind::Http));
        assert!(c.partial());
    }
}

/// Each step answered with a fatal error: the call fails with that kind and
/// no later request is sent.
#[tokio::test]
async fn fatal_errors_at_each_step_fail_the_call() {
    // The cases run one at a time: run together on a loaded runner, a hanging
    // request could time out before it reached the server.
    let plan = [Alert, Rule, List, Count, Cases, Case, Activity];
    for (at, failing) in plan.into_iter().enumerate() {
        for fatal in [ErrorKind::Auth, ErrorKind::Connection, ErrorKind::Timeout] {
            let base = recorded(1, 1);
            let s = Stack::start(move |step, req| {
                if step != failing {
                    return base(step, req);
                }
                match fatal {
                    ErrorKind::Auth => Act::Json(401, error_body()),
                    ErrorKind::Connection => Act::Drop,
                    _ => Act::Hang,
                }
            })
            .await;
            // Only the hanging step relies on the timeout.
            let timeout = if fatal == ErrorKind::Timeout { 2 } else { 30 };
            let e = alert_context::alert_context(&s.transport(timeout), ALERT_ID, "24h")
                .await
                .unwrap_err();
            assert_eq!(e.kind, fatal, "{failing:?}");
            // Leave room for a later request to arrive before counting.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(s.steps(), plan[..=at], "{failing:?} {fatal:?}");
        }
    }
}

#[tokio::test]
async fn maximum_work_sends_nineteen_requests() {
    for (refs, cases) in [(5, 5), (6, 7)] {
        let s = Stack::start(recorded(refs, cases)).await;
        let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
            .await
            .unwrap();
        let mut expected = vec![Alert, Rule];
        for _ in 0..5 {
            expected.extend([List, Count]);
        }
        expected.push(Cases);
        expected.extend([Case; 5]);
        expected.push(Activity);
        assert_eq!(s.steps(), expected);
        assert_eq!(s.steps().len(), 19);
        let r = s.requests();
        for i in 0..5 {
            let list_id = format!("elasticctl-sample-exceptions-{i}");
            assert_eq!(r[2 + 2 * i].query("list_id").unwrap(), list_id);
            assert_eq!(r[3 + 2 * i].query("list_id").unwrap(), list_id);
        }
        let Part::Ok(ex) = &c.exceptions else {
            panic!("exceptions part")
        };
        assert_eq!((ex.referenced, ex.truncated), (refs, refs > 5));
        let Part::Ok(cs) = &c.cases else {
            panic!("cases part")
        };
        assert_eq!((cs.total, cs.truncated), (cases, cases > 5));
        assert!(!c.partial());
        // One cached capability probe precedes the first exception list read.
        assert_eq!(s.all(), 20);
    }
}

#[tokio::test]
async fn missing_list_removes_its_count_request() {
    let base = recorded(2, 1);
    let s = Stack::start(move |step, req| match step {
        List if req.query("list_id").unwrap().ends_with("-0") => Act::Json(404, error_body()),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(
        s.steps(),
        [Alert, Rule, List, List, Count, Cases, Case, Activity]
    );
    let Part::Ok(ex) = &c.exceptions else {
        panic!("exceptions part")
    };
    assert_eq!(
        ex.lists[0].facts.as_ref().unwrap_err().kind,
        ErrorKind::NotFound
    );
    assert!(ex.lists[1].facts.is_ok());
    assert!(c.partial());
    assert_eq!(
        c.findings(),
        [
            AlertFinding::ExceptionListMissing,
            AlertFinding::HasRelatedCase
        ]
    );
}

#[tokio::test]
async fn findings_follow_the_fixed_order() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| match step {
        Alert => Act::Json(
            200,
            alert_page(|hit| hit["_source"]["kibana.alert.workflow_status"] = json!("closed")),
        ),
        Rule => {
            let mut rule = rule_with_refs(1);
            rule["enabled"] = json!(false);
            rule["execution_summary"]["last_execution"]["status"] = json!("failed");
            Act::Json(200, rule)
        }
        List => Act::Json(404, error_body()),
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(
        c.findings(),
        [
            AlertFinding::AlertNotOpen,
            AlertFinding::RuleDisabled,
            AlertFinding::RuleLastExecutionFailed,
            AlertFinding::ExceptionListMissing,
            AlertFinding::HasRelatedCase,
        ]
    );
}

/// A rule over a missing index reports `partial failure`, which is not a
/// failed execution.
#[tokio::test]
async fn partial_failure_is_not_a_failed_execution() {
    let base = recorded(0, 0);
    let s = Stack::start(move |step, req| match step {
        Rule => {
            let mut rule = fixture("rule_get_failed_execution.json");
            rule["rule_id"] = json!(RULE_ID);
            Act::Json(200, rule)
        }
        _ => base(step, req),
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    let Part::Ok(rule) = &c.rule else {
        panic!("rule part")
    };
    assert_eq!(rule.execution.as_ref().unwrap().status, "partial failure");
    assert!(c.findings().is_empty());
}

#[tokio::test]
async fn invalid_inputs_send_nothing() {
    let s = Stack::start(recorded(1, 1)).await;
    let t = s.transport(5);
    for id in ["", ".", ".."] {
        let e = alert_context::alert_context(&t, id, "24h")
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Error, "{id:?}");
    }
    for since in ["0h", "24", "now-1d", "1H", "10000d", "24h "] {
        let e = alert_context::alert_context(&t, ALERT_ID, since)
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::Error, "{since:?}");
    }
    assert_eq!(s.all(), 0);
}

/// The alert id and every case id reach the cases routes as one encoded path
/// segment under the fixed prefix.
#[tokio::test]
async fn ids_arrive_as_one_path_segment() {
    for (id, encoded) in [
        ("a/b?c#d %", "a%2Fb%3Fc%23d%20%25"),
        ("../_bulk", "..%2F_bulk"),
        ("%2e%2e", "%252e%252e"),
        ("...", "..."),
    ] {
        let base = recorded(0, 1);
        let case_id = id.to_owned();
        let s = Stack::start(move |step, req| match step {
            Cases => {
                let mut rows = case_refs(1);
                rows[0]["id"] = json!(case_id);
                Act::Json(200, rows)
            }
            _ => base(step, req),
        })
        .await;
        let c = alert_context::alert_context(&s.transport(5), id, "24h")
            .await
            .unwrap();
        assert_eq!(s.steps(), [Alert, Rule, Cases, Case, Activity], "{id:?}");
        let r = s.requests();
        assert_eq!(r[0].body["query"]["ids"]["values"][0], id);
        assert_eq!(r[2].path(), format!("/api/cases/alerts/{encoded}"));
        assert_eq!(r[3].path(), format!("/api/cases/{encoded}"));
        let Part::Ok(cases) = &c.cases else {
            panic!("cases part")
        };
        assert_eq!(cases.cases[0].id, id);
    }
}

#[tokio::test]
async fn since_reaches_the_activity_window() {
    let s = Stack::start(recorded(0, 0)).await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "9999w")
        .await
        .unwrap();
    let r = s.requests();
    assert_eq!(
        r.last().unwrap().body["query"]["bool"]["filter"][1]["range"]["@timestamp"]["gte"],
        "now-9999w"
    );
    let Part::Ok(a) = &c.activity else {
        panic!("activity part")
    };
    assert_eq!(a.window, "9999w");
}

#[tokio::test]
async fn nonfatal_errors_at_each_part_continue_the_plan() {
    for failing in [Rule, List, Count, Cases, Case, Activity] {
        for (status, expected_kind) in [
            (403, ErrorKind::Permission),
            (404, ErrorKind::NotFound),
            (409, ErrorKind::Conflict),
            (400, ErrorKind::Http),
            (200, ErrorKind::Unsupported),
            (201, ErrorKind::Error),
        ] {
            if status == 201 && !matches!(failing, Rule | List) {
                continue;
            }
            let base = recorded(2, 2);
            let s = Stack::start(move |step, req| {
                if step != failing
                    || (step == List || step == Count)
                        && !req.query("list_id").unwrap().ends_with("-0")
                    || step == Case && !req.path().ends_with("case-0")
                {
                    return base(step, req);
                }
                if status == 201 {
                    let mut body = if failing == Rule {
                        rule_with_refs(2)
                    } else {
                        fixture("exception_list_get.json")
                    };
                    body.as_object_mut().unwrap().remove(if failing == Rule {
                        "rule_id"
                    } else {
                        "list_id"
                    });
                    Act::Json(200, body)
                } else if status == 200 {
                    Act::Oversized
                } else {
                    Act::Json(status, error_body())
                }
            })
            .await;
            let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
                .await
                .unwrap();
            let expected = match failing {
                Rule => vec![Alert, Rule, Cases, Case, Case],
                List => vec![Alert, Rule, List, List, Count, Cases, Case, Case, Activity],
                Cases => vec![Alert, Rule, List, Count, List, Count, Cases, Activity],
                _ => vec![
                    Alert, Rule, List, Count, List, Count, Cases, Case, Case, Activity,
                ],
            };
            assert_eq!(s.steps(), expected, "{failing:?} {expected_kind:?}");
            let error = match failing {
                Rule => kind(&c.rule),
                Cases => kind(&c.cases),
                Activity => kind(&c.activity),
                List | Count => {
                    let Part::Ok(ex) = &c.exceptions else {
                        panic!("exceptions")
                    };
                    assert!(ex.lists[1].facts.is_ok());
                    Some(ex.lists[0].facts.as_ref().unwrap_err().kind)
                }
                Case => {
                    let Part::Ok(cs) = &c.cases else {
                        panic!("cases")
                    };
                    assert!(cs.cases[1].detail.is_ok());
                    Some(cs.cases[0].detail.as_ref().unwrap_err().kind)
                }
                _ => unreachable!(),
            };
            assert_eq!(error, Some(expected_kind));
            if failing == Rule {
                assert_eq!(
                    skipped(&c.exceptions),
                    Some(SkipReason::DependencyUnavailable)
                );
                assert_eq!(
                    skipped(&c.activity),
                    Some(SkipReason::DependencyUnavailable)
                );
            }
            assert!(c.partial());
            let mut findings = Vec::new();
            if expected_kind == ErrorKind::NotFound {
                if failing == Rule {
                    findings.push(AlertFinding::RuleMissing);
                }
                if matches!(failing, List | Count) {
                    findings.push(AlertFinding::ExceptionListMissing);
                }
            }
            if failing != Cases {
                findings.push(AlertFinding::HasRelatedCase);
            }
            assert_eq!(c.findings(), findings);
        }
    }
}

#[tokio::test]
async fn malformed_rule_degrades_before_dependent_reads() {
    let base = recorded(1, 1);
    let s = Stack::start(move |step, req| {
        if step == Rule {
            let mut rule = rule_with_refs(1);
            rule["enabled"] = json!("false");
            Act::Json(200, rule)
        } else {
            base(step, req)
        }
    })
    .await;
    let c = alert_context::alert_context(&s.transport(5), ALERT_ID, "24h")
        .await
        .unwrap();
    assert_eq!(kind(&c.rule), Some(ErrorKind::Http));
    assert_eq!(
        skipped(&c.exceptions),
        Some(SkipReason::DependencyUnavailable)
    );
    assert_eq!(
        skipped(&c.activity),
        Some(SkipReason::DependencyUnavailable)
    );
    assert_eq!(c.alert.id, ALERT_ID);
    assert!(matches!(c.cases, Part::Ok(_)));
    assert!(c.partial());
    assert_eq!(c.findings(), [AlertFinding::HasRelatedCase]);
    assert_eq!(s.steps(), [Alert, Rule, Cases, Case]);
}
