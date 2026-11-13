use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use elasticctl_api::Rule;
use elasticctl_api::compose::coverage::{
    self, CoverageGroup, CoverageReport, CoverageRow, coverage_from_rules,
};
use elasticctl_api::rules::{self, RuleFilter, RuleSource, WINDOW_PAGE};
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FIND: &str = "/api/detection_engine/rules/_find";

static SORTED_PAGE: LazyLock<Value> = LazyLock::new(|| {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/serverless-9.7.0/rules_find_sorted_page.json"
    ));
    serde_json::from_str::<Value>(text).expect("sorted page fixture is JSON")["response"].clone()
});

static STATUS: LazyLock<Value> = LazyLock::new(|| {
    let text = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/traditional-9.5.1/status.json"
    ));
    serde_json::from_str::<Value>(text).expect("status fixture is JSON")["response"].clone()
});

static MARKER: LazyLock<Value> = LazyLock::new(|| SORTED_PAGE["data"][0].clone());

fn row(rule_id: &str, enabled: bool, fields: Value) -> Value {
    let mut row = MARKER.clone();
    row["rule_id"] = json!(rule_id);
    row["enabled"] = json!(enabled);
    for (key, value) in fields.as_object().expect("fields object") {
        row[key.as_str()] = value.clone();
    }
    row
}

fn without(mut row: Value, keys: &[&str]) -> Value {
    for key in keys {
        row.as_object_mut().expect("rule object").remove(*key);
    }
    row
}

fn rule(row: Value) -> Rule {
    Rule::from_value(row).expect("a rule with a rule_id")
}

fn mitre(tactic: (&str, &str), techniques: &[(&str, &str)]) -> Value {
    let mut entry = MARKER["threat"][0].clone();
    entry["tactic"]["id"] = json!(tactic.0);
    entry["tactic"]["name"] = json!(tactic.1);
    let recorded = entry["technique"][0].clone();
    entry["technique"] = techniques
        .iter()
        .map(|(id, name)| {
            let mut technique = recorded.clone();
            technique["id"] = json!(id);
            technique["name"] = json!(name);
            technique["subtechnique"][0]["id"] = json!(format!("{id}.001"));
            technique
        })
        .collect();
    entry
}

fn with_framework(mut entry: Value, framework: Value) -> Value {
    entry["framework"] = framework;
    entry
}

fn packages(names: &[&str]) -> Value {
    let recorded = MARKER["related_integrations"][0].clone();
    names
        .iter()
        .map(|name| {
            let mut entry = recorded.clone();
            entry["package"] = json!(name);
            entry
        })
        .collect()
}

fn report(rows: Vec<Value>, group_by: CoverageGroup) -> CoverageReport {
    let rules: Vec<Rule> = rows.into_iter().map(rule).collect();
    coverage_from_rules(&rules, group_by).expect("coverage")
}

fn coverage_row(
    key: &str,
    name: Option<&str>,
    tactics: &[&str],
    enabled_rules: u64,
    disabled_rules: u64,
) -> CoverageRow {
    CoverageRow {
        key: key.to_string(),
        name: name.map(str::to_string),
        tactics: tactics.iter().map(|t| t.to_string()).collect(),
        enabled_rules,
        disabled_rules,
    }
}

fn counted(row: &CoverageRow) -> (&str, u64, u64) {
    (row.key.as_str(), row.enabled_rules, row.disabled_rules)
}

#[test]
fn a_technique_under_two_tactics_counts_once_and_reports_both() {
    let interpreter = ("T1059", "Command and Scripting Interpreter");
    let report = report(
        vec![
            row(
                "two-tactics",
                true,
                json!({"threat": [
                    mitre(("TA0002", "Execution"), &[interpreter]),
                    mitre(
                        ("TA0003", "Persistence"),
                        &[interpreter, ("T1053", "Scheduled Task/Job")]
                    ),
                ]}),
            ),
            row(
                "one-tactic",
                false,
                json!({"threat": [mitre(("TA0002", "Execution"), &[interpreter])]}),
            ),
        ],
        CoverageGroup::Technique,
    );
    assert_eq!(report.group_by, CoverageGroup::Technique);
    assert_eq!(
        (
            report.rules,
            report.enabled_rules,
            report.disabled_rules,
            report.unmapped_rules
        ),
        (2, 1, 1, 0)
    );
    assert_eq!(
        report.rows,
        vec![
            coverage_row(
                "T1059",
                Some("Command and Scripting Interpreter"),
                &["TA0002", "TA0003"],
                1,
                1
            ),
            coverage_row("T1053", Some("Scheduled Task/Job"), &["TA0003"], 1, 0),
        ]
    );
}

#[test]
fn subtechniques_roll_up_to_their_parent_technique() {
    let mut two_subtechniques = MARKER["threat"].clone();
    let mut second = two_subtechniques[0]["technique"][0]["subtechnique"][0].clone();
    second["id"] = json!("T1059.003");
    second["name"] = json!("Windows Command Shell");
    two_subtechniques[0]["technique"][0]["subtechnique"]
        .as_array_mut()
        .expect("recorded subtechniques")
        .push(second);
    let report = report(
        vec![
            MARKER.clone(),
            row(
                "two-subtechniques",
                true,
                json!({"threat": two_subtechniques}),
            ),
        ],
        CoverageGroup::Technique,
    );
    assert_eq!(
        report.rows,
        vec![coverage_row(
            "T1059",
            Some("Command and Scripting Interpreter"),
            &["TA0002"],
            2,
            0
        )]
    );
}

#[test]
fn a_non_mitre_framework_is_ignored() {
    let execution = ("TA0002", "Execution");
    let custom = with_framework(
        mitre(
            ("TA9999", "Custom tactic"),
            &[("T9999", "Custom technique")],
        ),
        json!("Custom Framework"),
    );
    let mut unnamed = mitre(("TA9998", "Unnamed"), &[("T9998", "Unnamed technique")]);
    unnamed.as_object_mut().unwrap().remove("framework");
    let rows = vec![
        row("custom-only", true, json!({"threat": [custom.clone()]})),
        row("no-framework", true, json!({"threat": [unnamed]})),
        row(
            "mixed",
            false,
            json!({"threat": [custom, mitre(execution, &[("T1059", "Command and Scripting Interpreter")])]}),
        ),
    ];
    let techniques = report(rows.clone(), CoverageGroup::Technique);
    assert_eq!(
        techniques.rows.iter().map(counted).collect::<Vec<_>>(),
        vec![("T1059", 0, 1)]
    );
    assert_eq!(techniques.rows[0].tactics, vec!["TA0002"]);
    assert_eq!(techniques.unmapped_rules, 2);
    let tactics = report(rows, CoverageGroup::Tactic);
    assert_eq!(
        tactics.rows,
        vec![coverage_row("TA0002", Some("Execution"), &[], 0, 1)]
    );
    assert_eq!(tactics.unmapped_rules, 2);
}

#[test]
fn names_are_the_smallest_seen_in_byte_order() {
    let rows = vec![
        row(
            "lower",
            true,
            json!({"threat": [mitre(("TA0002", "execution"), &[("T1059", "command interpreter")])]}),
        ),
        row(
            "upper",
            true,
            json!({"threat": [mitre(("TA0002", "Execution"), &[("T1059", "Command and Scripting Interpreter")])]}),
        ),
        row(
            "accented",
            true,
            json!({"threat": [mitre(("TA0002", "\u{c9}xecution"), &[("T1059", "\u{c7}ommand")])]}),
        ),
    ];
    let techniques = report(rows.clone(), CoverageGroup::Technique);
    assert_eq!(
        techniques.rows[0].name.as_deref(),
        Some("Command and Scripting Interpreter")
    );
    let tactics = report(rows, CoverageGroup::Tactic);
    assert_eq!(
        tactics.rows,
        vec![coverage_row("TA0002", Some("Execution"), &[], 3, 0)]
    );
}

#[test]
fn a_tactic_row_counts_a_rule_once_and_has_no_tactics() {
    let report = report(
        vec![row(
            "twice",
            true,
            json!({"threat": [
                mitre(("TA0002", "Execution"), &[("T1059", "Command and Scripting Interpreter")]),
                mitre(("TA0002", "Execution"), &[("T1106", "Native API")]),
                mitre(("TA0005", "Defense Evasion"), &[]),
            ]}),
        )],
        CoverageGroup::Tactic,
    );
    assert_eq!(
        report.rows,
        vec![
            coverage_row("TA0002", Some("Execution"), &[], 1, 0),
            coverage_row("TA0005", Some("Defense Evasion"), &[], 1, 0),
        ]
    );
}

#[test]
fn index_pattern_keys_are_unchanged_patterns_or_the_data_view_key() {
    let rows = vec![
        row(
            "patterns",
            true,
            json!({"index": ["logs-*", "logs-*", "LOGS-*"], "data_view_id": "ignored-view"}),
        ),
        row(
            "empty-index",
            true,
            json!({"index": [], "data_view_id": "security-view"}),
        ),
        without(
            row("view-only", false, json!({"data_view_id": "security-view"})),
            &["index"],
        ),
        row(
            "null-index",
            false,
            json!({"index": null, "data_view_id": "security-view"}),
        ),
        without(row("no-source", true, json!({})), &["index"]),
        row("nulls", true, json!({"index": null, "data_view_id": null})),
    ];
    let report = report(rows, CoverageGroup::IndexPattern);
    assert_eq!(
        report.rows,
        vec![
            coverage_row("data_view:security-view", None, &[], 1, 2),
            coverage_row("LOGS-*", None, &[], 1, 0),
            coverage_row("logs-*", None, &[], 1, 0),
        ]
    );
    assert_eq!(report.unmapped_rules, 2);
    assert_eq!(report.rules, 6);
}

#[test]
fn integration_keys_are_each_related_package() {
    let mut no_package = packages(&["windows"]);
    no_package[0].as_object_mut().unwrap().remove("package");
    let mut null_package = packages(&["windows"]);
    null_package[0]["package"] = Value::Null;
    let rows = vec![
        row(
            "duplicated",
            true,
            json!({"related_integrations": packages(&["system", "system", "windows"])}),
        ),
        row(
            "null-package",
            false,
            json!({"related_integrations": null_package}),
        ),
        row(
            "no-package",
            false,
            json!({"related_integrations": no_package}),
        ),
        row("empty", true, json!({"related_integrations": []})),
        without(row("absent", true, json!({})), &["related_integrations"]),
    ];
    let report = report(rows, CoverageGroup::Integration);
    assert_eq!(
        report.rows,
        vec![
            coverage_row("system", None, &[], 1, 0),
            coverage_row("windows", None, &[], 1, 0),
        ]
    );
    assert_eq!(report.unmapped_rules, 4);
}

#[test]
fn rows_sort_by_enabled_then_disabled_descending_then_key_in_byte_order() {
    let rows = vec![
        row(
            "1",
            true,
            json!({"related_integrations": packages(&["b", "a", "c", "B"])}),
        ),
        row("2", true, json!({"related_integrations": packages(&["b"])})),
        row(
            "3",
            false,
            json!({"related_integrations": packages(&["a", "c", "B", "d"])}),
        ),
        row(
            "4",
            false,
            json!({"related_integrations": packages(&["d"])}),
        ),
        row(
            "5",
            false,
            json!({"related_integrations": packages(&["d"])}),
        ),
    ];
    let report = report(rows, CoverageGroup::Integration);
    assert_eq!(
        report.rows.iter().map(counted).collect::<Vec<_>>(),
        vec![
            ("b", 2, 0),
            ("B", 1, 1),
            ("a", 1, 1),
            ("c", 1, 1),
            ("d", 0, 3),
        ]
    );
}

#[test]
fn only_a_true_enabled_counts_as_enabled() {
    let rows = vec![
        row("true", true, json!({})),
        row("false", false, json!({})),
        row("string", true, json!({"enabled": "true"})),
        without(row("absent", true, json!({})), &["enabled"]),
    ];
    let report = report(rows, CoverageGroup::Integration);
    assert_eq!(
        (report.rules, report.enabled_rules, report.disabled_rules),
        (4, 1, 3)
    );
    assert_eq!(report.rows, vec![coverage_row("system", None, &[], 1, 3)]);
}

#[test]
fn every_grouping_counts_rules_without_a_key_as_unmapped() {
    let bare = without(
        row("bare", false, json!({"threat": []})),
        &["index", "related_integrations"],
    );
    for group_by in [
        CoverageGroup::Technique,
        CoverageGroup::Tactic,
        CoverageGroup::IndexPattern,
        CoverageGroup::Integration,
    ] {
        let report = report(vec![MARKER.clone(), bare.clone()], group_by);
        assert_eq!(report.group_by, group_by);
        assert_eq!(report.unmapped_rules, 1, "{group_by:?}");
        assert_eq!(report.rows.len(), 1, "{group_by:?}");
        assert_eq!(counted(&report.rows[0]).1, 1, "{group_by:?}");
        let empty = coverage_from_rules(&[], group_by).unwrap();
        assert_eq!(
            (empty.rules, empty.unmapped_rules, empty.rows.len()),
            (0, 0, 0)
        );
    }
    let report = report(vec![MARKER.clone()], CoverageGroup::IndexPattern);
    assert_eq!(report.rows[0].key, "elasticctl-sample-alert-events");
    assert!(report.rows[0].name.is_none());
    assert!(report.rows[0].tactics.is_empty());
}

#[test]
fn a_present_field_of_the_wrong_type_is_kind_http() {
    let mut technique_text = MARKER["threat"].clone();
    technique_text[0]["technique"] = json!("T1059");
    let mut technique_id = MARKER["threat"].clone();
    technique_id[0]["technique"][0]["id"] = json!(1059);
    let mut technique_name = MARKER["threat"].clone();
    technique_name[0]["technique"][0]["name"] = json!(["Command"]);
    let mut tactic_text = MARKER["threat"].clone();
    tactic_text[0]["tactic"] = json!("TA0002");
    let mut tactic_name = MARKER["threat"].clone();
    tactic_name[0]["tactic"]["name"] = json!(2);
    let mut package_number = packages(&["system"]);
    package_number[0]["package"] = json!(7);
    let cases = [
        (CoverageGroup::Technique, json!({"threat": "T1059"})),
        (CoverageGroup::Tactic, json!({"threat": "TA0002"})),
        (CoverageGroup::Technique, json!({"threat": technique_text})),
        (CoverageGroup::IndexPattern, json!({"index": "logs-*"})),
        (
            CoverageGroup::Integration,
            json!({"related_integrations": "system"}),
        ),
        (CoverageGroup::Technique, json!({"threat": ["T1059"]})),
        (
            CoverageGroup::Technique,
            json!({"threat": [with_framework(MARKER["threat"][0].clone(), json!(1))]}),
        ),
        (CoverageGroup::Technique, json!({"threat": technique_id})),
        (CoverageGroup::Technique, json!({"threat": technique_name})),
        (CoverageGroup::Tactic, json!({"threat": tactic_text})),
        (CoverageGroup::Tactic, json!({"threat": tactic_name})),
        (CoverageGroup::IndexPattern, json!({"index": ["logs-*", 7]})),
        (CoverageGroup::IndexPattern, json!({"index": [null]})),
        (
            CoverageGroup::IndexPattern,
            json!({"index": [], "data_view_id": 7}),
        ),
        (
            CoverageGroup::Integration,
            json!({"related_integrations": ["system"]}),
        ),
        (
            CoverageGroup::Integration,
            json!({"related_integrations": package_number}),
        ),
    ];
    for (group_by, fields) in cases {
        let rules = [
            rule(MARKER.clone()),
            rule(row("wrong", true, fields.clone())),
        ];
        let err = coverage_from_rules(&rules, group_by).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "{group_by:?} {fields}");
    }
}

#[test]
fn fields_of_another_grouping_are_not_read() {
    let rules = [rule(row(
        "other-fields",
        true,
        json!({"index": "logs-*", "related_integrations": "system", "data_view_id": 7}),
    ))];
    for group_by in [CoverageGroup::Technique, CoverageGroup::Tactic] {
        coverage_from_rules(&rules, group_by).expect("threat fields are valid");
    }
    let rules = [rule(row("threat", true, json!({"threat": "T1059"})))];
    for group_by in [CoverageGroup::IndexPattern, CoverageGroup::Integration] {
        coverage_from_rules(&rules, group_by).expect("threat is not read");
    }
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}

fn corpus_rule(n: usize) -> Value {
    let mut row = MARKER.clone();
    row["rule_id"] = json!(format!("coverage-{n:04}"));
    row["name"] = json!(format!("coverage rule {n:04}"));
    row
}

fn page(number: u64, total: u64, ids: impl IntoIterator<Item = usize>) -> Value {
    let mut body = SORTED_PAGE.clone();
    body["page"] = json!(number);
    body["perPage"] = json!(WINDOW_PAGE);
    body["total"] = json!(total);
    body["data"] = ids.into_iter().map(corpus_rule).collect();
    body
}

fn pages(total: usize) -> Vec<Value> {
    let size = WINDOW_PAGE as usize;
    (0..total.div_ceil(size).max(1))
        .map(|n| {
            page(
                n as u64 + 1,
                total as u64,
                n * size..((n + 1) * size).min(total),
            )
        })
        .collect()
}

struct Script {
    bodies: Vec<Value>,
    next: AtomicUsize,
}

impl Respond for Script {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        match self.bodies.get(self.next.fetch_add(1, Ordering::SeqCst)) {
            Some(body) => ResponseTemplate::new(200).set_body_json(body),
            None => ResponseTemplate::new(500).set_body_json(json!({"message": "unscripted"})),
        }
    }
}

async fn scripted(bodies: Vec<Value>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&*STATUS))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(FIND))
        .respond_with(Script {
            bodies,
            next: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;
    server
}

async fn find_queries(server: &MockServer) -> Vec<BTreeMap<String, String>> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| {
            assert_eq!(request.method.as_str(), "GET");
            assert!(
                [FIND, "/api/status"].contains(&request.url.path()),
                "{}",
                request.url
            );
            request.url.path() == FIND
        })
        .map(|request| request.url.query_pairs().into_owned().collect())
        .collect()
}

fn page_numbers(queries: &[BTreeMap<String, String>]) -> Vec<u32> {
    for query in queries {
        assert_eq!(query["per_page"], "500");
        assert_eq!(query["sort_field"], "created_at");
        assert_eq!(query["sort_order"], "asc");
    }
    queries
        .iter()
        .map(|query| query["page"].parse().expect("numeric page"))
        .collect()
}

#[tokio::test]
async fn detection_coverage_reads_the_window_with_the_filter() {
    let server = scripted(pages(1_200)).await;
    let filter = RuleFilter {
        source: RuleSource::Custom,
        enabled: Some(true),
        tag: Some("prod".into()),
        ..Default::default()
    };
    let report = coverage::detection_coverage(&transport(&server), &filter, CoverageGroup::Tactic)
        .await
        .unwrap();
    assert_eq!(report.group_by, CoverageGroup::Tactic);
    assert_eq!(
        (report.rules, report.enabled_rules, report.unmapped_rules),
        (1_200, 1_200, 0)
    );
    assert_eq!(
        report.rows,
        vec![coverage_row("TA0002", Some("Execution"), &[], 1_200, 0)]
    );
    let queries = find_queries(&server).await;
    assert_eq!(page_numbers(&queries), vec![1, 2, 3]);
    for query in &queries {
        assert_eq!(
            query["filter"],
            "alert.attributes.params.immutable: false AND \
             alert.attributes.enabled: true AND \
             alert.attributes.tags: \"prod\""
        );
    }
}

#[tokio::test]
async fn the_request_count_equals_the_page_count() {
    for (total, expected) in [
        (0, vec![1]),
        (1, vec![1]),
        (500, vec![1]),
        (501, vec![1, 2]),
        (1_500, vec![1, 2, 3]),
    ] {
        let server = scripted(pages(total)).await;
        let report = coverage::detection_coverage(
            &transport(&server),
            &RuleFilter::default(),
            CoverageGroup::Technique,
        )
        .await
        .unwrap();
        assert_eq!(report.rules, total as u64);
        let queries = find_queries(&server).await;
        assert_eq!(page_numbers(&queries), expected, "{total}");
        assert!(queries.iter().all(|query| !query.contains_key("filter")));
    }
}

#[tokio::test]
async fn the_corpus_limit_and_the_conflict_surface_unchanged() {
    let above = vec![page(1, 4_001, 0..500), page(2, 4_001, 500..1_000)];
    let duplicated = vec![page(1, 600, 0..500), page(2, 600, 400..500)];
    let twice = [duplicated.clone(), duplicated].concat();
    for (bodies, kind, pages_read) in [
        (above, ErrorKind::Unsupported, vec![1]),
        (twice, ErrorKind::Conflict, vec![1, 2, 1, 2]),
    ] {
        let server = scripted(bodies.clone()).await;
        let err = coverage::detection_coverage(
            &transport(&server),
            &RuleFilter::default(),
            CoverageGroup::Technique,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, kind, "{err}");
        assert_eq!(page_numbers(&find_queries(&server).await), pages_read);
        let direct = scripted(bodies).await;
        let expected = rules::find_window(&transport(&direct), &RuleFilter::default())
            .await
            .unwrap_err();
        assert_eq!(err.kind, expected.kind);
        assert_eq!(err.message, expected.message);
        assert_eq!(err.http_status, expected.http_status);
    }
}

#[tokio::test]
async fn a_4000_rule_corpus_whose_first_pass_fails_sends_16_requests() {
    let mut bodies = pages(4_000);
    bodies[7] = page(8, 4_000, 3_499..3_999);
    bodies.extend(pages(4_000));
    let server = scripted(bodies).await;
    let report = coverage::detection_coverage(
        &transport(&server),
        &RuleFilter::default(),
        CoverageGroup::Integration,
    )
    .await
    .unwrap();
    assert_eq!((report.rules, report.enabled_rules), (4_000, 4_000));
    assert_eq!(
        report.rows,
        vec![coverage_row("system", None, &[], 4_000, 0)]
    );
    let queries = find_queries(&server).await;
    assert_eq!(queries.len(), 16);
    assert_eq!(
        page_numbers(&queries),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]
    );
}
