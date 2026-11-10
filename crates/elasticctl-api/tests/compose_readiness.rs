//! `rule_readiness`: the fixed request plan, path safety, parts, and findings.
//!
//! Every mock body copies a recorded fixture; variants are derived in code.
use elasticctl_api::compose::{
    Part, SkipReason,
    readiness::{
        IndexSource, PackageRow, PatternFacts, PatternRow, PatternState, Readiness,
        ReadinessFinding, rule_readiness,
    },
};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use std::time::Duration;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{any, method, path, query_param},
};

const SERVERLESS: &str = "serverless-9.7.0";
const HOSTED: &str = "ech-9.5.6";
const RULES: &str = "/api/detection_engine/rules";
const FIND: &str = "/api/detection_engine/rules/_find";
const VIEWS: &str = "/api/data_views";
const POLICIES: &str = "/api/fleet/package_policies";
const PACKAGES: &str = "/api/fleet/epm/packages/";
const RESOLVE: &str = "/_resolve/index/";
const STATUS: &str = "/api/status";

fn recording(set: &str, name: &str) -> Value {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(set)
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(file).expect("recorded fixture"))
        .expect("fixture JSON")
}

fn response(name: &str) -> Value {
    recording(SERVERLESS, name)["response"].clone()
}

/// An error response derived from the recorded classified 404 of
/// `_resolve/index`. The transport keeps no raw 404 body, so the recording
/// holds the classified error; other statuses reuse its body.
fn error_status(status: u16) -> ResponseTemplate {
    let mut error = recording(SERVERLESS, "resolve_index_not_found.json")["error"].clone();
    assert_eq!(error["http_status"], 404);
    assert_eq!(error["kind"], "not_found");
    error["http_status"] = json!(status);
    ResponseTemplate::new(status).set_body_json(error)
}

fn ok_json(body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

fn resolve_match(set: &str) -> ResponseTemplate {
    ok_json(recording(set, "resolve_index_match.json")["response"].clone())
}

fn resolve_none(set: &str) -> ResponseTemplate {
    ok_json(recording(set, "resolve_index_no_match.json")["response"].clone())
}

/// The recorded marker rule with its index source and packages replaced.
fn rule(index: Option<&[&str]>, data_view_id: Option<&str>, packages: &[(&str, &str)]) -> Value {
    let mut rule = response("rule_get_executed.json");
    let template = rule["related_integrations"][0].clone();
    let map = rule.as_object_mut().unwrap();
    map.remove("index");
    map.remove("data_view_id");
    if let Some(index) = index {
        map.insert("index".into(), json!(index));
    }
    if let Some(id) = data_view_id {
        map.insert("data_view_id".into(), json!(id));
    }
    let related = packages
        .iter()
        .map(|(package, version)| {
            let mut entry = template.clone();
            entry["package"] = json!(package);
            entry["version"] = json!(version);
            entry
        })
        .collect::<Vec<_>>();
    map.insert("related_integrations".into(), json!(related));
    rule
}

fn rule_id(rule: &Value) -> String {
    rule["rule_id"].as_str().unwrap().to_owned()
}

/// The recorded data-view list with rows replaced by `(id, title)` pairs.
fn views(rows: &[(&str, &str)]) -> Value {
    let mut body = response("data_views_list.json");
    let template = body["data_view"][0].clone();
    body["data_view"] = json!(
        rows.iter()
            .map(|(id, title)| {
                let mut row = template.clone();
                row["id"] = json!(id);
                row["title"] = json!(title);
                row
            })
            .collect::<Vec<_>>()
    );
    body
}

/// The recorded integration-policy page with one row per package name.
fn policies(packages: &[&str], total: Option<u64>) -> Value {
    let mut body = response("integration_policies_list.json");
    let template = body["items"][0].clone();
    body["items"] = json!(
        packages
            .iter()
            .enumerate()
            .map(|(i, package)| {
                let mut row = template.clone();
                row["id"] = json!(format!("policy-{i}"));
                row["package"]["name"] = json!(package);
                row
            })
            .collect::<Vec<_>>()
    );
    body["total"] = json!(total.unwrap_or(packages.len() as u64));
    body["page"] = json!(1);
    body["perPage"] = json!(1000);
    body
}

fn installed(name: &str) -> ResponseTemplate {
    let mut body = response("package_system.json");
    body["item"]["name"] = json!(name);
    ok_json(body)
}

fn not_installed(set: &str, name: &str) -> ResponseTemplate {
    let mut body = recording(set, "package_not_installed.json")["response"].clone();
    body["item"]["name"] = json!(name);
    ok_json(body)
}

fn transport(kibana: &str, es: Option<String>, timeout_secs: u64) -> Transport {
    Transport::new(&Profile {
        kibana_url: kibana.to_owned(),
        es_url: es,
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs,
    })
    .unwrap()
}

/// The one non-empty segment after `prefix`, when the path has exactly that.
fn segment<'a>(request: &'a Request, prefix: &str) -> Option<&'a str> {
    request
        .url
        .path()
        .strip_prefix(prefix)
        .filter(|rest| !rest.is_empty() && !rest.contains('/'))
}

struct Stack {
    server: MockServer,
}

impl Stack {
    async fn new() -> Self {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(STATUS))
            .respond_with(ok_json(response("status.json")))
            .mount(&server)
            .await;
        Self { server }
    }

    fn transport(&self) -> Transport {
        transport(&self.server.uri(), Some(self.server.uri()), 5)
    }

    async fn rule(&self, body: Value) {
        Mock::given(method("GET"))
            .and(path(RULES))
            .and(query_param("rule_id", rule_id(&body)))
            .respond_with(ok_json(body))
            .mount(&self.server)
            .await;
    }

    async fn route(&self, route: &str, template: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(template)
            .mount(&self.server)
            .await;
    }

    /// Answer every `_resolve/index` request whose path is exactly one
    /// segment under the prefix, by that raw, still encoded, segment.
    async fn resolve(&self, answer: impl Fn(&str) -> ResponseTemplate + Send + Sync + 'static) {
        Mock::given(method("GET"))
            .and(|r: &Request| segment(r, RESOLVE).is_some())
            .respond_with(move |r: &Request| answer(segment(r, RESOLVE).unwrap()))
            .mount(&self.server)
            .await;
    }

    /// Answer every package status read with an installed package of the
    /// requested name.
    async fn packages_installed(&self) {
        Mock::given(method("GET"))
            .and(|r: &Request| segment(r, PACKAGES).is_some())
            .respond_with(|r: &Request| installed(segment(r, PACKAGES).unwrap()))
            .mount(&self.server)
            .await;
    }

    /// Every received path in order, without the cached capability probe.
    async fn paths(&self) -> Vec<String> {
        let requests = self.server.received_requests().await.unwrap();
        assert!(
            requests.iter().filter(|r| r.url.path() == STATUS).count() <= 1,
            "one cached capability probe at most"
        );
        requests
            .iter()
            .inspect(|r| assert_eq!(r.method.as_str(), "GET"))
            .map(|r| r.url.path().to_owned())
            .filter(|p| p != STATUS)
            .collect()
    }
}

fn ok<T: std::fmt::Debug>(part: &Part<T>) -> &T {
    match part {
        Part::Ok(value) => value,
        other => panic!("expected an ok part, got {other:?}"),
    }
}

fn unavailable_kind<T: std::fmt::Debug>(part: &Part<T>) -> ErrorKind {
    match part {
        Part::Unavailable(error) => error.kind,
        other => panic!("expected an unavailable part, got {other:?}"),
    }
}

fn states(facts: &PatternFacts) -> Vec<PatternState> {
    facts.rows.iter().map(|r| r.state).collect()
}

fn has(report: &Readiness, finding: ReadinessFinding) -> bool {
    report.findings().contains(&finding)
}

fn row<'a>(rows: &'a [PackageRow], package: &str) -> &'a PackageRow {
    rows.iter().find(|r| r.package == package).unwrap()
}

#[tokio::test]
async fn index_source_reads_the_plan_in_order_on_both_flavors() {
    for set in [SERVERLESS, HOSTED] {
        let stack = Stack::new().await;
        let body = rule(
            Some(&["match-*", "none-*", "missing"]),
            None,
            &[("system", "^2.0.0")],
        );
        stack.rule(body.clone()).await;
        stack
            .route(VIEWS, ok_json(response("data_views_list.json")))
            .await;
        stack
            .resolve(move |segment| match segment {
                "match-%2A" => resolve_match(set),
                "none-%2A" => resolve_none(set),
                _ => error_status(404),
            })
            .await;
        stack
            .route(POLICIES, ok_json(policies(&["system"], None)))
            .await;
        stack.packages_installed().await;
        let report = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap();
        assert_eq!(report.rule.rule_id().unwrap(), rule_id(&body));
        assert_eq!(report.index_source, IndexSource::Index);
        let views = ok(&report.data_views);
        assert_eq!(views.count, 1);
        assert!(views.rule_data_view.is_none());
        let patterns = ok(&report.patterns);
        assert_eq!((patterns.total, patterns.truncated), (3, false));
        assert_eq!(
            states(patterns),
            [
                PatternState::Matches,
                PatternState::NoMatch,
                PatternState::NoMatch
            ]
        );
        assert_eq!(patterns.rows[0].counts, Some((1, 0, 0)), "{set}");
        assert_eq!(patterns.rows[1].counts, Some((0, 0, 0)));
        assert_eq!(patterns.rows[2].counts, Some((0, 0, 0)));
        assert!(patterns.rows.iter().all(|r| r.error.is_none()));
        assert!(
            patterns
                .rows
                .iter()
                .all(|r| r.data_view_ids == Some(vec![]))
        );
        let integrations = ok(&report.integrations);
        assert_eq!((integrations.total, integrations.truncated), (1, false));
        let system = row(&integrations.rows, "system");
        assert_eq!(system.version.as_deref(), Some("^2.0.0"));
        let usage = system.status.as_ref().unwrap();
        assert_eq!(usage.install_status, "installed");
        assert_eq!(usage.installed_version.as_deref(), Some("3.5.0"));
        assert_eq!(usage.policies, 1);
        assert!(!report.partial());
        assert!(report.findings().is_empty());
        assert_eq!(
            stack.paths().await,
            [
                RULES,
                VIEWS,
                "/_resolve/index/match-%2A",
                "/_resolve/index/none-%2A",
                "/_resolve/index/missing",
                POLICIES,
                "/api/fleet/epm/packages/system",
            ]
        );
    }
}

#[tokio::test]
async fn data_view_source_resolves_the_title_components() {
    let stack = Stack::new().await;
    let listed = response("data_views_list.json");
    let id = listed["data_view"][0]["id"].as_str().unwrap().to_owned();
    let title = listed["data_view"][0]["title"].as_str().unwrap().to_owned();
    let name = listed["data_view"][0]["name"].as_str().unwrap().to_owned();
    let body = rule(None, Some(&id), &[]);
    stack.rule(body.clone()).await;
    stack.route(VIEWS, ok_json(listed)).await;
    stack.resolve(|_| resolve_match(SERVERLESS)).await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    assert_eq!(report.index_source, IndexSource::DataView);
    let view = ok(&report.data_views).rule_data_view.as_ref().unwrap();
    assert_eq!(view.id, id);
    assert!(view.found);
    assert_eq!(view.title.as_deref(), Some(title.as_str()));
    assert_eq!(view.name.as_deref(), Some(name.as_str()));
    let patterns = ok(&report.patterns);
    assert_eq!(patterns.rows.len(), 1);
    assert_eq!(patterns.rows[0].pattern, title);
    assert_eq!(patterns.rows[0].data_view_ids, Some(vec![id.clone()]));
    let integrations = ok(&report.integrations);
    assert_eq!((integrations.total, integrations.rows.len()), (0, 0));
    assert_eq!(
        stack.paths().await,
        [
            RULES.to_owned(),
            VIEWS.to_owned(),
            format!("{RESOLVE}{}", elasticctl_core::urlencode(&title)),
        ]
    );
}

#[tokio::test]
async fn no_index_source_skips_data_views_and_patterns() {
    let stack = Stack::new().await;
    let mut body = rule(None, None, &[("system", "^2.0.0")]);
    body["enabled"] = json!(false);
    stack.rule(body.clone()).await;
    stack
        .route(POLICIES, ok_json(policies(&["system"], None)))
        .await;
    stack.packages_installed().await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    assert_eq!(report.index_source, IndexSource::None);
    assert!(matches!(
        report.data_views,
        Part::Skipped(SkipReason::NotApplicable)
    ));
    assert!(matches!(
        report.patterns,
        Part::Skipped(SkipReason::NotApplicable)
    ));
    assert_eq!(
        report.findings(),
        [
            ReadinessFinding::RuleDisabled,
            ReadinessFinding::NoIndexSource
        ]
    );
    assert!(!report.partial());
    assert_eq!(
        stack.paths().await,
        [RULES, POLICIES, "/api/fleet/epm/packages/system"]
    );
}

#[tokio::test]
async fn a_missing_or_unreadable_data_view_withholds_the_patterns() {
    for (views_response, missing) in [
        (ok_json(response("data_views_list.json")), true),
        (error_status(403), false),
    ] {
        let stack = Stack::new().await;
        let body = rule(None, Some("absent-view"), &[]);
        stack.rule(body.clone()).await;
        stack.route(VIEWS, views_response).await;
        let report = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap();
        assert_eq!(report.index_source, IndexSource::DataView);
        assert!(matches!(
            report.patterns,
            Part::Skipped(SkipReason::DependencyUnavailable)
        ));
        if missing {
            let view = ok(&report.data_views).rule_data_view.as_ref().unwrap();
            assert_eq!(view.id, "absent-view");
            assert!(!view.found);
            assert!(view.title.is_none() && view.name.is_none());
            assert_eq!(report.findings(), [ReadinessFinding::DataViewMissing]);
            assert!(!report.partial());
        } else {
            assert_eq!(unavailable_kind(&report.data_views), ErrorKind::Permission);
            assert!(report.findings().is_empty());
            assert!(report.partial());
        }
        assert_eq!(stack.paths().await, [RULES, VIEWS]);
    }
}

#[tokio::test]
async fn no_elasticsearch_url_skips_patterns_and_still_reads_integrations() {
    let stack = Stack::new().await;
    let body = rule(Some(&["logs-*"]), None, &[("system", "^2.0.0")]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack
        .route(POLICIES, ok_json(policies(&["system"], None)))
        .await;
    stack.packages_installed().await;
    let t = transport(&stack.server.uri(), None, 5);
    let report = rule_readiness(&t, &rule_id(&body)).await.unwrap();
    assert!(matches!(
        report.patterns,
        Part::Skipped(SkipReason::NotConfigured)
    ));
    assert!(matches!(report.data_views, Part::Ok(_)));
    assert!(matches!(report.integrations, Part::Ok(_)));
    assert_eq!(
        stack.paths().await,
        [RULES, VIEWS, POLICIES, "/api/fleet/epm/packages/system"]
    );
}

#[tokio::test]
async fn patterns_are_capped_and_exclusions_and_invalid_values_send_nothing() {
    let names = (0..17).map(|i| format!("p{i}-*")).collect::<Vec<_>>();
    let index = names.iter().map(String::as_str).collect::<Vec<_>>();
    let stack = Stack::new().await;
    let body = rule(Some(&index), None, &[]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack.resolve(|_| resolve_match(SERVERLESS)).await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    let patterns = ok(&report.patterns);
    assert_eq!((patterns.total, patterns.truncated), (17, true));
    assert_eq!(patterns.rows.len(), 16);
    assert_eq!(patterns.rows[15].pattern, "p15-*");
    assert_eq!(report.findings(), [ReadinessFinding::PatternsTruncated]);
    let paths = stack.paths().await;
    assert_eq!(paths.len(), 2 + 16);
    assert_eq!(paths.last().unwrap(), "/_resolve/index/p15-%2A");

    let long = "a".repeat(1025);
    let index = [
        "-excluded-*",
        "-",
        "",
        "   ",
        "\t\n",
        ".",
        "..",
        "a\u{7}b",
        "a\u{7f}b",
        long.as_str(),
        "ok-*",
    ];
    let stack = Stack::new().await;
    let body = rule(Some(&index), None, &[]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack.resolve(|_| resolve_none(SERVERLESS)).await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    let patterns = ok(&report.patterns);
    let mut expected = vec![PatternState::Exclusion; 2];
    expected.extend([PatternState::Unresolved; 8]);
    expected.push(PatternState::NoMatch);
    assert_eq!(states(patterns), expected);
    for row in &patterns.rows[..10] {
        assert!(row.counts.is_none() && row.error.is_none(), "{row:?}");
    }
    assert_eq!(
        patterns
            .rows
            .iter()
            .map(|r| r.pattern.as_str())
            .collect::<Vec<_>>(),
        index
    );
    assert!(report.partial());
    assert_eq!(report.findings(), [ReadinessFinding::PatternUnresolved]);
    assert_eq!(
        stack.paths().await,
        [RULES, VIEWS, "/_resolve/index/ok-%2A"]
    );
}

#[tokio::test]
async fn pattern_responses_classify_by_kind_and_shape() {
    let stack = Stack::new().await;
    let body = rule(
        Some(&["gone", "denied-*", "malformed-*", "list-*"]),
        None,
        &[],
    );
    stack.rule(body.clone()).await;
    stack.route(VIEWS, error_status(403)).await;
    stack
        .resolve(|segment| match segment {
            "gone" => error_status(404),
            "denied-%2A" => error_status(403),
            "malformed-%2A" => {
                let mut body =
                    recording(SERVERLESS, "resolve_index_no_match.json")["response"].clone();
                body.as_object_mut().unwrap().remove("aliases");
                ok_json(body)
            }
            _ => {
                let mut body =
                    recording(SERVERLESS, "resolve_index_match.json")["response"].clone();
                body["aliases"] = json!("not-an-array");
                ok_json(body)
            }
        })
        .await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    let rows = &ok(&report.patterns).rows;
    assert_eq!(rows[0].state, PatternState::NoMatch);
    assert_eq!(rows[0].counts, Some((0, 0, 0)));
    assert!(rows[0].error.is_none());
    let kinds = rows[1..]
        .iter()
        .map(|r| {
            assert_eq!(r.state, PatternState::Unresolved);
            assert!(r.counts.is_none());
            r.error.as_ref().unwrap().kind
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        [ErrorKind::Permission, ErrorKind::Http, ErrorKind::Http]
    );
    assert!(
        rows.iter().all(|r| r.data_view_ids.is_none()),
        "no data_view_ids without the data_views part"
    );
    assert!(report.partial());
}

async fn patterns_report(count: usize, answer: fn(usize) -> ResponseTemplate) -> Readiness {
    let names = (0..count).map(|i| format!("q{i}-*")).collect::<Vec<_>>();
    let index = names.iter().map(String::as_str).collect::<Vec<_>>();
    let stack = Stack::new().await;
    let body = rule(Some(&index), None, &[]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack
        .resolve(move |segment| {
            let n = segment[1..segment.find('-').unwrap()].parse().unwrap();
            answer(n)
        })
        .await;
    rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap()
}

#[tokio::test]
async fn no_pattern_matches_needs_every_pattern_resolved() {
    let all_denied = patterns_report(16, |_| error_status(403)).await;
    let rows = &ok(&all_denied.patterns).rows;
    assert_eq!(rows.len(), 16);
    assert!(rows.iter().all(|r| r.state == PatternState::Unresolved));
    assert!(all_denied.partial());
    assert_eq!(all_denied.findings(), [ReadinessFinding::PatternUnresolved]);

    let one_denied = patterns_report(16, |n| {
        if n == 7 {
            error_status(403)
        } else {
            resolve_none(SERVERLESS)
        }
    })
    .await;
    assert!(!has(&one_denied, ReadinessFinding::NoPatternMatches));
    assert!(has(&one_denied, ReadinessFinding::PatternUnresolved));
    assert!(one_denied.partial());

    let truncated = patterns_report(17, |_| resolve_none(SERVERLESS)).await;
    assert!(
        ok(&truncated.patterns)
            .rows
            .iter()
            .all(|r| r.state == PatternState::NoMatch)
    );
    assert_eq!(truncated.findings(), [ReadinessFinding::PatternsTruncated]);
    assert!(!truncated.partial());

    let resolved = patterns_report(16, |n| {
        if n % 2 == 0 {
            error_status(404)
        } else {
            resolve_none(SERVERLESS)
        }
    })
    .await;
    assert_eq!(resolved.findings(), [ReadinessFinding::NoPatternMatches]);
    assert!(!resolved.partial());

    let one_match = patterns_report(16, |n| {
        if n == 15 {
            resolve_match(SERVERLESS)
        } else {
            resolve_none(SERVERLESS)
        }
    })
    .await;
    assert!(one_match.findings().is_empty());

    let stack = Stack::new().await;
    let body = rule(Some(&["-only-exclusions-*", "-more-*"]), None, &[]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    let exclusions = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    assert!(exclusions.findings().is_empty());
    assert_eq!(stack.paths().await, [RULES, VIEWS]);
}

#[tokio::test]
async fn data_view_ids_match_whole_title_components_in_sorted_order() {
    let stack = Stack::new().await;
    let body = rule(
        Some(&["logs-*", "metrics-*", "other-*", "-logs-*"]),
        None,
        &[],
    );
    stack.rule(body.clone()).await;
    stack
        .route(
            VIEWS,
            ok_json(views(&[
                ("z-view", "logs-*,metrics-*"),
                ("a-view", "logs-*"),
                ("m-view", "xlogs-*,logs-*x, logs-*,logs-"),
                ("b-view", "metrics-*"),
                ("c-view", "-logs-*,logs-*"),
            ])),
        )
        .await;
    stack.resolve(|_| resolve_match(SERVERLESS)).await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    assert_eq!(ok(&report.data_views).count, 5);
    let ids = ok(&report.patterns)
        .rows
        .iter()
        .map(|r: &PatternRow| r.data_view_ids.clone().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            vec!["a-view", "c-view", "z-view"],
            vec!["b-view", "z-view"],
            vec![],
            vec!["c-view"],
        ]
    );
}

#[tokio::test]
async fn integrations_without_entries_send_no_fleet_request() {
    for related in [None, Some(json!([])), Some(Value::Null)] {
        let stack = Stack::new().await;
        let mut body = rule(None, None, &[]);
        match related {
            None => {
                body.as_object_mut().unwrap().remove("related_integrations");
            }
            Some(value) => body["related_integrations"] = value,
        }
        stack.rule(body.clone()).await;
        let report = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap();
        let facts = ok(&report.integrations);
        assert_eq!(
            (facts.total, facts.truncated, facts.rows.len()),
            (0, false, 0)
        );
        assert_eq!(stack.paths().await, [RULES]);
        assert!(
            stack
                .server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.url.path() != STATUS),
            "no Fleet capability probe"
        );
    }
}

#[tokio::test]
async fn integrations_collapse_duplicates_cap_at_eight_and_count_policies() {
    let stack = Stack::new().await;
    let body = rule(
        None,
        None,
        &[
            ("system", "^2.0.0"),
            ("apache", "^1.0.0"),
            ("system", "^3.0.0"),
            ("nginx", "^1.0.0"),
            ("missing", "^1.0.0"),
            ("Bad", "^1.0.0"),
            ("p6", "1"),
            ("p7", "1"),
            ("p8", "1"),
            ("p9", "1"),
        ],
    );
    stack.rule(body.clone()).await;
    stack
        .route(
            POLICIES,
            ok_json(policies(&["system", "apache", "system", "p6"], None)),
        )
        .await;
    stack
        .route(
            "/api/fleet/epm/packages/apache",
            not_installed(HOSTED, "apache"),
        )
        .await;
    stack
        .route("/api/fleet/epm/packages/missing", error_status(404))
        .await;
    stack.packages_installed().await;
    let report = rule_readiness(&stack.transport(), &rule_id(&body))
        .await
        .unwrap();
    let facts = ok(&report.integrations);
    assert_eq!((facts.total, facts.truncated), (9, true));
    assert_eq!(
        facts
            .rows
            .iter()
            .map(|r| r.package.as_str())
            .collect::<Vec<_>>(),
        [
            "system", "apache", "nginx", "missing", "Bad", "p6", "p7", "p8"
        ]
    );
    let system = row(&facts.rows, "system");
    assert_eq!(system.version.as_deref(), Some("^2.0.0"));
    assert_eq!(system.status.as_ref().unwrap().policies, 2);
    let apache = row(&facts.rows, "apache").status.as_ref().unwrap();
    assert_eq!(apache.install_status, "not_installed");
    assert_eq!(
        (apache.installed_version.as_deref(), apache.policies),
        (None, 1)
    );
    assert_eq!(
        row(&facts.rows, "nginx").status.as_ref().unwrap().policies,
        0
    );
    assert_eq!(row(&facts.rows, "p6").status.as_ref().unwrap().policies, 1);
    assert_eq!(
        row(&facts.rows, "missing")
            .status
            .as_ref()
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert_eq!(
        row(&facts.rows, "Bad").status.as_ref().unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(report.partial());
    assert_eq!(
        report.findings(),
        [
            ReadinessFinding::NoIndexSource,
            ReadinessFinding::IntegrationNotInstalled,
            ReadinessFinding::IntegrationWithoutPolicy,
            ReadinessFinding::IntegrationsTruncated,
        ]
    );
    let packages = ["system", "apache", "nginx", "missing", "p6", "p7", "p8"]
        .map(|p| format!("{PACKAGES}{p}"));
    let mut expected = vec![RULES.to_owned(), POLICIES.to_owned()];
    expected.extend(packages);
    assert_eq!(stack.paths().await, expected);
}

#[tokio::test]
async fn an_unreadable_or_incomplete_policy_list_reads_no_package() {
    for (list, kind) in [
        (error_status(403), ErrorKind::Permission),
        (
            {
                let names = vec!["system"; 1000];
                ok_json(policies(&names, Some(1001)))
            },
            ErrorKind::Unsupported,
        ),
        (
            {
                let mut body = policies(&["system"], None);
                body["perPage"] = json!(20);
                ok_json(body)
            },
            ErrorKind::Http,
        ),
    ] {
        let stack = Stack::new().await;
        let body = rule(None, None, &[("system", "^2.0.0")]);
        stack.rule(body.clone()).await;
        stack.route(POLICIES, list).await;
        stack.packages_installed().await;
        let report = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap();
        assert_eq!(unavailable_kind(&report.integrations), kind);
        assert!(report.partial());
        assert_eq!(report.findings(), [ReadinessFinding::NoIndexSource]);
        assert_eq!(stack.paths().await, [RULES, POLICIES]);
    }
}

#[tokio::test]
async fn the_fleet_feature_floor_makes_integrations_unavailable() {
    let server = MockServer::start().await;
    let mut status = response("status.json");
    status["version"]["number"] = json!("9.4.0");
    Mock::given(path(STATUS))
        .respond_with(ok_json(status))
        .mount(&server)
        .await;
    let body = rule(None, None, &[("system", "^2.0.0")]);
    Mock::given(path(RULES))
        .respond_with(ok_json(body.clone()))
        .mount(&server)
        .await;
    let t = transport(&server.uri(), Some(server.uri()), 5);
    let report = rule_readiness(&t, &rule_id(&body)).await.unwrap();
    assert_eq!(
        unavailable_kind(&report.integrations),
        ErrorKind::Unsupported
    );
    let paths = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(paths, [RULES, STATUS]);
}

/// A fatal kind at any step fails the call, and nothing after it is sent.
#[tokio::test]
async fn fatal_kinds_fail_the_call_with_no_later_request() {
    for step in ["views", "pattern", "policies", "package"] {
        let stack = Stack::new().await;
        let body = rule(
            Some(&["a-*", "b-*"]),
            None,
            &[("system", "1"), ("nginx", "1")],
        );
        stack.rule(body.clone()).await;
        stack
            .route(
                VIEWS,
                if step == "views" {
                    error_status(401)
                } else {
                    ok_json(response("data_views_list.json"))
                },
            )
            .await;
        let fail_pattern = step == "pattern";
        stack
            .resolve(move |segment| {
                if fail_pattern && segment == "a-%2A" {
                    error_status(401)
                } else {
                    resolve_none(SERVERLESS)
                }
            })
            .await;
        stack
            .route(
                POLICIES,
                if step == "policies" {
                    error_status(401)
                } else {
                    ok_json(policies(&["system"], None))
                },
            )
            .await;
        stack
            .route(
                "/api/fleet/epm/packages/system",
                if step == "package" {
                    error_status(401)
                } else {
                    installed("system")
                },
            )
            .await;
        stack.packages_installed().await;
        let error = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Auth, "{step}");
        let expected: &[&str] = match step {
            "views" => &[RULES, VIEWS],
            "pattern" => &[RULES, VIEWS, "/_resolve/index/a-%2A"],
            "policies" => &[
                RULES,
                VIEWS,
                "/_resolve/index/a-%2A",
                "/_resolve/index/b-%2A",
                POLICIES,
            ],
            _ => &[
                RULES,
                VIEWS,
                "/_resolve/index/a-%2A",
                "/_resolve/index/b-%2A",
                POLICIES,
                "/api/fleet/epm/packages/system",
            ],
        };
        assert_eq!(stack.paths().await, expected, "{step}");
    }
}

#[tokio::test]
async fn connection_and_timeout_on_a_pattern_fail_the_call() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_uri = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let stack = Stack::new().await;
    let body = rule(Some(&["a-*", "b-*"]), None, &[("system", "1")]);
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack
        .route(POLICIES, ok_json(policies(&["system"], None)))
        .await;
    stack.packages_installed().await;
    let t = transport(&stack.server.uri(), Some(closed_uri), 5);
    let error = rule_readiness(&t, &rule_id(&body)).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::Connection);
    assert_eq!(stack.paths().await, [RULES, VIEWS]);

    let stack = Stack::new().await;
    stack.rule(body.clone()).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack
        .resolve(|_| resolve_none(SERVERLESS).set_delay(Duration::from_secs(3)))
        .await;
    stack
        .route(POLICIES, ok_json(policies(&["system"], None)))
        .await;
    stack.packages_installed().await;
    let t = transport(&stack.server.uri(), Some(stack.server.uri()), 1);
    let error = rule_readiness(&t, &rule_id(&body)).await.unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    assert_eq!(stack.paths().await, [RULES, VIEWS, "/_resolve/index/a-%2A"]);
}

/// Mount the maximum-work rule, found by display name, and every route its
/// plan reads.
async fn maximum_work_stack(index: &[&str], packages: &[(&str, &str)]) -> (Stack, String) {
    let stack = Stack::new().await;
    let body = rule(Some(index), None, packages);
    let name = body["name"].as_str().unwrap().to_owned();
    Mock::given(method("GET"))
        .and(path(RULES))
        .and(query_param("rule_id", name.as_str()))
        .respond_with(error_status(404))
        .mount(&stack.server)
        .await;
    let mut found = response("rules_find.json");
    found["data"] = json!([body.clone()]);
    found["total"] = json!(1);
    stack.route(FIND, ok_json(found)).await;
    stack.rule(body).await;
    stack
        .route(VIEWS, ok_json(response("data_views_list.json")))
        .await;
    stack.resolve(|_| resolve_match(SERVERLESS)).await;
    stack
        .route(POLICIES, ok_json(policies(&["system"], None)))
        .await;
    stack.packages_installed().await;
    (stack, name)
}

#[tokio::test]
async fn maximum_work_sends_exactly_twenty_nine_requests_in_plan_order() {
    let names = (0..16).map(|i| format!("m{i}-*")).collect::<Vec<_>>();
    let index = names.iter().map(String::as_str).collect::<Vec<_>>();
    let packages = (0..8).map(|i| format!("pkg_{i}")).collect::<Vec<_>>();
    let related = packages
        .iter()
        .map(|p| (p.as_str(), "^1.0.0"))
        .collect::<Vec<_>>();
    let (stack, name) = maximum_work_stack(&index, &related).await;
    let report = rule_readiness(&stack.transport(), &name).await.unwrap();
    assert_eq!(ok(&report.patterns).rows.len(), 16);
    assert_eq!(ok(&report.integrations).rows.len(), 8);
    let mut expected = vec![RULES.to_owned(), FIND.to_owned(), RULES.to_owned()];
    expected.push(VIEWS.to_owned());
    expected.extend((0..16).map(|i| format!("{RESOLVE}m{i}-%2A")));
    expected.push(POLICIES.to_owned());
    expected.extend(packages.iter().map(|p| format!("{PACKAGES}{p}")));
    assert_eq!(expected.len(), 29);
    assert_eq!(stack.paths().await, expected);

    // Inputs far beyond both caps still send 29 requests.
    let names = (0..40).map(|i| format!("o{i}-*")).collect::<Vec<_>>();
    let index = names.iter().map(String::as_str).collect::<Vec<_>>();
    let packages = (0..20).map(|i| format!("over_{i}")).collect::<Vec<_>>();
    let mut related = packages
        .iter()
        .map(|p| (p.as_str(), "^1.0.0"))
        .collect::<Vec<_>>();
    related.extend(related.clone());
    let (stack, name) = maximum_work_stack(&index, &related).await;
    let report = rule_readiness(&stack.transport(), &name).await.unwrap();
    assert_eq!(ok(&report.patterns).total, 40);
    assert_eq!(ok(&report.integrations).total, 20);
    assert_eq!(stack.paths().await.len(), 29);
}

/// Hostile values become exactly one segment under the fixed prefix or send
/// nothing. Any other path fails the test through the catch-all route.
#[tokio::test]
async fn hostile_patterns_and_packages_stay_under_their_fixed_prefix() {
    let long = "a".repeat(1025);
    let longest = "b".repeat(1024);
    let control = "a\u{7}b";
    let patterns = [
        ".",
        "..",
        "../_bulk",
        "a/b",
        "a?b",
        "a#b",
        "%2e%2e",
        "...",
        long.as_str(),
        control,
        longest.as_str(),
    ];
    let package_sets: [&[&str]; 2] = [
        &[".", "..", "../x", "A", "a.b"],
        &[
            "../_bulk",
            "a/b",
            "a?b",
            "a#b",
            "%2e%2e",
            "...",
            long.as_str(),
            control,
        ],
    ];
    for packages in package_sets {
        let stack = Stack::new().await;
        let related = packages.iter().map(|p| (*p, "1")).collect::<Vec<_>>();
        let body = rule(Some(&patterns), None, &related);
        stack.rule(body.clone()).await;
        stack
            .route(VIEWS, ok_json(response("data_views_list.json")))
            .await;
        stack.resolve(|_| resolve_none(SERVERLESS)).await;
        stack
            .route(POLICIES, ok_json(policies(&["system"], None)))
            .await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(418))
            .with_priority(u8::MAX)
            .expect(0)
            .named("any path outside the plan")
            .mount(&stack.server)
            .await;
        let report = rule_readiness(&stack.transport(), &rule_id(&body))
            .await
            .unwrap();
        let rows = &ok(&report.patterns).rows;
        assert_eq!(
            states(ok(&report.patterns)),
            [
                PatternState::Unresolved,
                PatternState::Unresolved,
                PatternState::NoMatch,
                PatternState::NoMatch,
                PatternState::NoMatch,
                PatternState::NoMatch,
                PatternState::NoMatch,
                PatternState::NoMatch,
                PatternState::Unresolved,
                PatternState::Unresolved,
                PatternState::NoMatch,
            ]
        );
        assert!(rows.iter().all(|r| r.error.is_none()));
        let facts = ok(&report.integrations);
        assert_eq!(facts.rows.len(), packages.len());
        for row in &facts.rows {
            assert_eq!(
                row.status.as_ref().unwrap_err().kind,
                ErrorKind::Unsupported,
                "{}",
                row.package
            );
        }
        let mut expected = vec![RULES.to_owned(), VIEWS.to_owned()];
        expected.extend(
            [
                "..%2F_bulk",
                "a%2Fb",
                "a%3Fb",
                "a%23b",
                "%252e%252e",
                "...",
                longest.as_str(),
            ]
            .map(|segment| format!("{RESOLVE}{segment}")),
        );
        expected.push(POLICIES.to_owned());
        assert_eq!(stack.paths().await, expected);
        for request in stack.server.received_requests().await.unwrap() {
            if request.url.path().starts_with(RESOLVE) {
                assert!(request.url.query().is_none(), "{}", request.url);
            }
        }
    }
}

/// Fail one read at the socket boundary while keeping all other reads available.
async fn fatal_stack(
    failed_path: &'static str,
    kind: &'static str,
) -> (
    String,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
    String,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let requests = seen.clone();
    let body = rule(
        Some(&["a-*", "b-*"]),
        None,
        &[("system", "1"), ("nginx", "1")],
    );
    let selector = rule_id(&body);
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let requests = requests.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    header.push(byte[0]);
                }
                let header = String::from_utf8(header).unwrap();
                let route = header
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .split('?')
                    .next()
                    .unwrap();
                assert!(header.starts_with("GET "));
                requests.lock().unwrap().push(route.to_owned());
                if route == failed_path {
                    match kind {
                        "connection" => return,
                        "timeout" => {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            return;
                        }
                        _ => {}
                    }
                }
                let failed = route == failed_path;
                let value = if failed {
                    recording(SERVERLESS, "resolve_index_not_found.json")["error"].clone()
                } else {
                    match route {
                        RULES => body,
                        STATUS => response("status.json"),
                        VIEWS => response("data_views_list.json"),
                        POLICIES => policies(&["system"], None),
                        r if r.starts_with(RESOLVE) => response("resolve_index_no_match.json"),
                        r if r.starts_with(PACKAGES) => response("package_system.json"),
                        _ => panic!("unexpected route {route}"),
                    }
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                let status = if failed { "401 Unauthorized" } else { "200 OK" };
                let header = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(&bytes).await;
            });
        }
    });
    (uri, seen, task, selector)
}

#[tokio::test]
async fn connection_and_timeout_at_every_part_stop_the_plan() {
    let plan = [
        RULES,
        VIEWS,
        "/_resolve/index/a-%2A",
        "/_resolve/index/b-%2A",
        POLICIES,
        "/api/fleet/epm/packages/system",
        "/api/fleet/epm/packages/nginx",
    ];
    for failed in [
        VIEWS,
        "/_resolve/index/a-%2A",
        POLICIES,
        "/api/fleet/epm/packages/system",
    ] {
        for (kind, expected) in [
            ("connection", ErrorKind::Connection),
            ("timeout", ErrorKind::Timeout),
        ] {
            let (uri, seen, task, selector) = fatal_stack(failed, kind).await;
            let t = transport(&uri, Some(uri.clone()), 1);
            let error = rule_readiness(&t, &selector).await.unwrap_err();
            assert_eq!(error.kind, expected, "{kind} at {failed}");
            let paths = seen
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p != STATUS)
                .cloned()
                .collect::<Vec<_>>();
            let end = plan.iter().position(|p| *p == failed).unwrap();
            assert_eq!(paths, plan[..=end], "{kind} at {failed}");
            task.abort();
        }
    }
}
