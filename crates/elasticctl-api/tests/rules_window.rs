//! Threat filters and the verified corpus read (`rules::find_window`).
//!
//! Every mock body copies the shape of the recorded `rules_find.json`
//! response: `page`, `perPage`, `total`, and `data` rows cloned from the
//! recorded rule with only `rule_id` and `name` changed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use elasticctl_api::rules::{self, RuleFilter, RuleSource, WINDOW_MAX_RULES, WINDOW_PAGE};
use elasticctl_api::rules_ops;
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const FIND: &str = "/api/detection_engine/rules/_find";
const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/serverless-9.6.0/rules_find.json"
));

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

/// The recorded rule row with a new identity.
fn rule(id: usize) -> Value {
    let fixture: Value = serde_json::from_str(FIXTURE).expect("rules_find fixture is JSON");
    let mut row = fixture["response"]["data"][0].clone();
    row["rule_id"] = json!(format!("window-{id:04}"));
    row["name"] = json!(format!("window rule {id:04}"));
    row
}

/// A recorded-shape `_find` page holding the rules with these ids.
fn page(number: u64, total: u64, ids: impl IntoIterator<Item = usize>) -> Value {
    let data: Vec<Value> = ids.into_iter().map(rule).collect();
    json!({"page": number, "perPage": WINDOW_PAGE, "total": total, "data": data})
}

/// The correct pages of a corpus of `total` rules, in order.
fn pages(total: usize) -> Vec<Value> {
    let page_size = WINDOW_PAGE as usize;
    (0..total.div_ceil(page_size))
        .map(|n| {
            let end = ((n + 1) * page_size).min(total);
            page(n as u64 + 1, total as u64, n * page_size..end)
        })
        .collect()
}

/// Answers each `_find` request with the next scripted body, in order. A
/// request past the script gets a 500, which fails the read.
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
        .and(path(FIND))
        .respond_with(Script {
            bodies,
            next: AtomicUsize::new(0),
        })
        .mount(&server)
        .await;
    server
}

/// The query of every request, in order. Every request must be a `_find` GET.
async fn find_queries(server: &MockServer) -> Vec<BTreeMap<String, String>> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| {
            assert_eq!(request.method.as_str(), "GET");
            assert_eq!(request.url.path(), FIND);
            request.url.query_pairs().into_owned().collect()
        })
        .collect()
}

/// Each request read the expected page, 500 rules at a time, in creation order.
fn assert_window_pages(queries: &[BTreeMap<String, String>], expected: &[u32]) {
    let read: Vec<u32> = queries
        .iter()
        .map(|query| query["page"].parse().expect("numeric page"))
        .collect();
    assert_eq!(read, expected);
    for query in queries {
        assert_eq!(query["per_page"], "500");
        assert_eq!(query["sort_field"], "created_at");
        assert_eq!(query["sort_order"], "asc");
    }
}

fn ids(rules: &[elasticctl_api::Rule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.rule_id().unwrap().to_string())
        .collect()
}

fn expected_ids(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|id| format!("window-{id:04}")).collect()
}

#[test]
fn window_constants_match_the_design_bounds() {
    assert_eq!(WINDOW_PAGE, 500);
    assert_eq!(WINDOW_MAX_RULES, 4_000);
}

#[test]
fn a_technique_filter_selects_the_technique_id() {
    let filter = RuleFilter {
        technique: Some("T1059".into()),
        ..Default::default()
    };
    assert_eq!(
        filter.to_kql().unwrap(),
        "alert.attributes.params.threat.technique.id: \"T1059\""
    );
}

#[test]
fn a_subtechnique_filter_selects_the_subtechnique_id() {
    let filter = RuleFilter {
        technique: Some("T1059.001".into()),
        ..Default::default()
    };
    assert_eq!(
        filter.to_kql().unwrap(),
        "alert.attributes.params.threat.technique.subtechnique.id: \"T1059.001\""
    );
}

#[test]
fn a_tactic_filter_selects_the_tactic_id() {
    let filter = RuleFilter {
        tactic: Some("TA0002".into()),
        ..Default::default()
    };
    assert_eq!(
        filter.to_kql().unwrap(),
        "alert.attributes.params.threat.tactic.id: \"TA0002\""
    );
}

#[test]
fn threat_clauses_combine_with_the_existing_filters_by_and() {
    let filter = RuleFilter {
        source: RuleSource::Custom,
        enabled: Some(true),
        tag: Some("prod".into()),
        technique: Some("T1059.001".into()),
        tactic: Some("TA0002".into()),
        ..Default::default()
    };
    assert_eq!(
        filter.to_kql().unwrap(),
        "alert.attributes.params.immutable: false AND \
         alert.attributes.enabled: true AND \
         alert.attributes.tags: \"prod\" AND \
         alert.attributes.params.threat.technique.subtechnique.id: \"T1059.001\" AND \
         alert.attributes.params.threat.tactic.id: \"TA0002\""
    );
}

/// `to_kql` is public and does not validate, so the threat values pass
/// through `kql_escape` like every other quoted literal.
#[test]
fn threat_values_are_kql_escaped() {
    let filter = RuleFilter {
        technique: Some("T\"1\\".into()),
        tactic: Some("TA\"".into()),
        ..Default::default()
    };
    assert_eq!(
        filter.to_kql().unwrap(),
        "alert.attributes.params.threat.technique.id: \"T\\\"1\\\\\" AND \
         alert.attributes.params.threat.tactic.id: \"TA\\\"\""
    );
}

const BAD_TECHNIQUES: &[&str] = &[
    "",
    "t1059",
    "T105",
    "T10590",
    "T1059.",
    "T1059.1",
    "T1059.0001",
    "T1059,001",
    "T1059.00a",
    "T1O59",
    "TA0002",
    " T1059",
    "T1059 ",
    "T1059\n",
    "T\u{0661}\u{0660}\u{0665}\u{0669}",
    "T1059*",
];

const BAD_TACTICS: &[&str] = &[
    "",
    "ta0002",
    "Ta0002",
    "TA2",
    "TA00002",
    "T0002",
    "TA0002.001",
    "TA000a",
    " TA0002",
    "TA0002 ",
    "TA*",
];

fn bad_filters() -> Vec<RuleFilter> {
    let long = format!("T{}", "1".repeat(1024));
    let mut filters: Vec<RuleFilter> = BAD_TECHNIQUES
        .iter()
        .map(|v| v.to_string())
        .chain([long.clone()])
        .map(|v| RuleFilter {
            technique: Some(v),
            ..Default::default()
        })
        .collect();
    filters.extend(
        BAD_TACTICS
            .iter()
            .map(|v| v.to_string())
            .chain([long])
            .map(|v| RuleFilter {
                tactic: Some(v),
                ..Default::default()
            }),
    );
    // A valid value does not excuse an invalid one in the other field, and
    // the source feature probe must not run first.
    filters.push(RuleFilter {
        source: RuleSource::Custom,
        technique: Some("T1059".into()),
        tactic: Some("TA2".into()),
        ..Default::default()
    });
    filters
}

#[test]
fn validate_threat_accepts_exactly_the_three_grammars() {
    for (technique, tactic) in [
        (Some("T1059"), None),
        (Some("T1059.001"), None),
        (Some("T0000.000"), None),
        (None, Some("TA0002")),
        (Some("T9999"), Some("TA9999")),
        (None, None),
    ] {
        let filter = RuleFilter {
            technique: technique.map(str::to_string),
            tactic: tactic.map(str::to_string),
            ..Default::default()
        };
        filter
            .validate_threat()
            .unwrap_or_else(|e| panic!("{technique:?} {tactic:?}: {e}"));
    }
    for filter in bad_filters() {
        let err = filter.validate_threat().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Error, "{filter:?}");
    }
}

/// A value outside the grammar fails before the capability probe or any
/// `_find` request, on every read that takes a filter.
#[tokio::test]
async fn a_threat_value_outside_its_grammar_fails_before_any_request() {
    let server = MockServer::start().await;
    let t = transport(&server);
    for filter in bad_filters() {
        let window = rules::find_window(&t, &filter).await.unwrap_err();
        let first = rules::find_first_by_name(&t, &filter, 50)
            .await
            .unwrap_err();
        let page = rules::find_page(&t, &filter, 1, 1).await.unwrap_err();
        let listed = rules_ops::list_page(&t, &filter, 50).await.unwrap_err();
        for err in [window, first, page, listed] {
            assert_eq!(err.kind, ErrorKind::Error, "{filter:?}: {err}");
        }
    }
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "an invalid threat value reached the server"
    );
}

#[tokio::test]
async fn find_window_reads_an_empty_corpus_in_one_request() {
    let server = scripted(vec![page(1, 0, [])]).await;
    let rules = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert!(rules.is_empty());
    assert_window_pages(&find_queries(&server).await, &[1]);
}

#[tokio::test]
async fn find_window_reads_one_page() {
    let server = scripted(pages(3)).await;
    let rules = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(ids(&rules), expected_ids(0..3));
    let queries = find_queries(&server).await;
    assert_window_pages(&queries, &[1]);
    assert!(!queries[0].contains_key("filter"));
}

/// Every page carries the same filter, including the threat clause.
#[tokio::test]
async fn find_window_reads_three_pages_in_order_with_the_filter() {
    let server = scripted(pages(1_200)).await;
    let filter = RuleFilter {
        technique: Some("T1059".into()),
        ..Default::default()
    };
    let rules = rules::find_window(&transport(&server), &filter)
        .await
        .unwrap();
    assert_eq!(ids(&rules), expected_ids(0..1_200));
    let queries = find_queries(&server).await;
    assert_window_pages(&queries, &[1, 2, 3]);
    for query in &queries {
        assert_eq!(
            query["filter"],
            "alert.attributes.params.threat.technique.id: \"T1059\""
        );
    }
}

#[tokio::test]
async fn find_window_refuses_a_corpus_above_the_limit_after_page_one() {
    let server = scripted(vec![page(1, 4_001, 0..500), page(2, 4_001, 500..1_000)]).await;
    let err = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported, "{err}");
    assert_window_pages(&find_queries(&server).await, &[1]);
}

#[tokio::test]
async fn find_window_reads_exactly_the_limit_in_eight_pages() {
    let server = scripted(pages(4_000)).await;
    let rules = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(ids(&rules), expected_ids(0..4_000));
    assert_window_pages(&find_queries(&server).await, &[1, 2, 3, 4, 5, 6, 7, 8]);
}

/// A row repeated across pages is the default-order paging failure measured
/// on Hosted. The first pass is discarded and the second is returned.
#[tokio::test]
async fn a_duplicate_rule_id_triggers_one_second_pass_at_the_request_cap() {
    let mut first = pages(4_000);
    first[7] = page(8, 4_000, 3_499..3_999);
    first.extend(pages(4_000));
    let server = scripted(first).await;
    let rules = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(ids(&rules), expected_ids(0..4_000));
    let queries = find_queries(&server).await;
    assert_eq!(queries.len(), 16);
    assert_window_pages(&queries, &[1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
}

#[tokio::test]
async fn two_failed_passes_are_a_conflict() {
    let duplicated = vec![page(1, 600, 0..500), page(2, 600, 400..500)];
    let server = scripted([duplicated.clone(), duplicated].concat()).await;
    let err = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict, "{err}");
    assert_window_pages(&find_queries(&server).await, &[1, 2, 1, 2]);
}

/// Distinct rows whose count equals the first total still fail when a later
/// page reports another total.
#[tokio::test]
async fn totals_that_differ_between_pages_fail_verification() {
    let changed = vec![page(1, 600, 0..500), page(2, 601, 500..600)];
    let server = scripted([changed.clone(), changed].concat()).await;
    let err = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict, "{err}");
    assert_window_pages(&find_queries(&server).await, &[1, 2, 1, 2]);
}

#[tokio::test]
async fn a_short_page_fails_verification() {
    let short = vec![page(1, 600, 0..500), page(2, 600, 500..599)];
    let server = scripted([short.clone(), short].concat()).await;
    let err = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict, "{err}");
    assert_window_pages(&find_queries(&server).await, &[1, 2, 1, 2]);
}

/// A short first pass is discarded; a complete second pass is returned.
#[tokio::test]
async fn a_short_first_pass_recovers_on_the_second() {
    let mut bodies = vec![page(1, 600, 0..500), page(2, 600, 500..599)];
    bodies.extend(pages(600));
    let server = scripted(bodies).await;
    let rules = rules::find_window(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(ids(&rules), expected_ids(0..600));
    assert_window_pages(&find_queries(&server).await, &[1, 2, 1, 2]);
}

async fn find_count(stack: &MockStack) -> usize {
    stack
        .requests()
        .await
        .iter()
        .filter(|request| request.path == FIND)
        .count()
}

/// A threat filter narrows the selection, so an empty result does not run
/// the source proof.
#[tokio::test]
async fn an_empty_source_and_technique_page_sends_one_request() {
    let stack = MockStack::with_source_totals(0, 2, 2).await;
    for filter in [
        RuleFilter {
            source: RuleSource::Custom,
            technique: Some("T1059".into()),
            ..Default::default()
        },
        RuleFilter {
            source: RuleSource::Prebuilt,
            tactic: Some("TA0002".into()),
            ..Default::default()
        },
    ] {
        let before = find_count(&stack).await;
        let page = rules_ops::list_page(stack.transport(), &filter, 50)
            .await
            .unwrap();
        assert!(page.rules.is_empty());
        assert_eq!(page.total, 0);
        assert_eq!(find_count(&stack).await - before, 1, "{filter:?}");
    }
}

/// A source-only empty page still proves the partition: the page plus the
/// three reads of `verify_source_partition`.
#[tokio::test]
async fn an_empty_source_only_page_still_sends_four_requests() {
    let stack = MockStack::with_source_totals(0, 2, 2).await;
    let filter = RuleFilter {
        source: RuleSource::Custom,
        ..Default::default()
    };
    let page = rules_ops::list_page(stack.transport(), &filter, 50)
        .await
        .unwrap();
    assert!(page.rules.is_empty());
    assert_eq!(find_count(&stack).await, 4);
}
