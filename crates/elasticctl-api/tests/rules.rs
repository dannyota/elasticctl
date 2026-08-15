use elasticctl_api::model::Rule;
use elasticctl_api::rules::{self, BulkAction, RuleFilter, RuleSource};
use elasticctl_api::{Format, rules_ops};
use elasticctl_api_test_support::MockStack;
use elasticctl_core::{ErrorKind, Profile, Transport};
use serde_json::json;
use wiremock::matchers::{
    body_partial_json, method, path, path_regex, query_param, query_param_is_missing,
};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn profile_for(server: &MockServer) -> Profile {
    Profile {
        kibana_url: server.uri(),
        es_url: None,
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    }
}

fn transport(server: &MockServer) -> Transport {
    Transport::new(&profile_for(server)).unwrap()
}

fn rule_json(id: &str) -> serde_json::Value {
    json!({"rule_id": id, "name": format!("rule {id}"), "type": "query", "risk_score": 21})
}

/// A `_find` response with `total` and exactly these rules. Partition tests
/// need one returned rule per counted rule to avoid a short-read failure.
fn find_body(total: u64, data: Vec<serde_json::Value>) -> serde_json::Value {
    json!({"page": 1, "perPage": 10000, "total": total, "data": data})
}

#[tokio::test]
async fn source_feature_refuses_an_unverified_stack_before_the_route() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.0", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "message": "the source-filtered route must not be called"
        })))
        .mount(&server)
        .await;

    let error = rules::find_page(
        &transport(&server),
        &RuleFilter {
            source: RuleSource::Custom,
            ..Default::default()
        },
        1,
        1,
    )
    .await
    .unwrap_err();

    assert_eq!(error.kind, ErrorKind::Unsupported);
    assert!(error.message.contains("rule source scoping"), "{error}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/detection_engine/rules/_find")
            .count(),
        0
    );
}

#[tokio::test]
async fn source_feature_does_not_gate_an_all_rules_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(0, vec![])))
        .mount(&server)
        .await;

    let (rules, total) = rules::find_page(&transport(&server), &RuleFilter::default(), 1, 1)
        .await
        .unwrap();

    assert!(rules.is_empty());
    assert_eq!(total, 0);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.url.path() == "/api/status")
            .count(),
        0
    );
}

#[test]
fn find_envelope_rejects_malformed_required_fields_and_count_relationships() {
    // Each case catches a decoder regression back to the old missing-field or
    // wrong-type fallback behavior.
    struct Case {
        name: &'static str,
        body: serde_json::Value,
        field_or_relation: &'static str,
    }

    let valid = || json!({"data": [], "total": 0, "page": 1, "perPage": 1});
    let mut cases = vec![
        Case {
            name: "response is not an object",
            body: json!([]),
            field_or_relation: "response",
        },
        Case {
            name: "data is missing",
            body: json!({"total": 0, "page": 1, "perPage": 1}),
            field_or_relation: "data",
        },
        Case {
            name: "data is a scalar",
            body: json!({"data": "not an array", "total": 0, "page": 1, "perPage": 1}),
            field_or_relation: "data",
        },
        Case {
            name: "data is an object",
            body: json!({"data": {}, "total": 0, "page": 1, "perPage": 1}),
            field_or_relation: "data",
        },
    ];

    for field in ["total", "page", "perPage"] {
        let mut missing = valid();
        missing.as_object_mut().unwrap().remove(field);
        cases.push(Case {
            name: match field {
                "total" => "total is missing",
                "page" => "page is missing",
                "perPage" => "perPage is missing",
                _ => unreachable!(),
            },
            body: missing,
            field_or_relation: field,
        });

        for (name, value) in [
            ("a scalar", json!("not a number")),
            ("an object", json!({})),
            ("an array", json!([])),
            ("negative", json!(-1)),
            ("floating", json!(1.5)),
        ] {
            let mut body = valid();
            body[field] = value;
            cases.push(Case {
                name: match (field, name) {
                    ("total", "a scalar") => "total is a scalar",
                    ("total", "an object") => "total is an object",
                    ("total", "an array") => "total is an array",
                    ("total", "negative") => "total is negative",
                    ("total", "floating") => "total is floating",
                    ("page", "a scalar") => "page is a scalar",
                    ("page", "an object") => "page is an object",
                    ("page", "an array") => "page is an array",
                    ("page", "negative") => "page is negative",
                    ("page", "floating") => "page is floating",
                    ("perPage", "a scalar") => "perPage is a scalar",
                    ("perPage", "an object") => "perPage is an object",
                    ("perPage", "an array") => "perPage is an array",
                    ("perPage", "negative") => "perPage is negative",
                    ("perPage", "floating") => "perPage is floating",
                    _ => unreachable!(),
                },
                body,
                field_or_relation: field,
            });
        }
    }

    let mut per_page_alias = valid();
    per_page_alias.as_object_mut().unwrap().remove("perPage");
    per_page_alias["per_page"] = json!(1);
    cases.push(Case {
        name: "per_page does not alias perPage",
        body: per_page_alias,
        field_or_relation: "perPage",
    });

    let mut zero_page = valid();
    zero_page["page"] = json!(0);
    cases.push(Case {
        name: "page is zero",
        body: zero_page,
        field_or_relation: "page",
    });

    let mut zero_per_page = valid();
    zero_per_page["perPage"] = json!(0);
    cases.push(Case {
        name: "perPage is zero",
        body: zero_per_page,
        field_or_relation: "perPage",
    });

    cases.extend([
        Case {
            name: "data is longer than total",
            body: json!({
                "data": [rule_json("too-many-total")],
                "total": 0,
                "page": 1,
                "perPage": 1,
            }),
            field_or_relation: "data.len() > total",
        },
        Case {
            name: "data is longer than perPage",
            body: json!({
                "data": [rule_json("too-many-per-page-a"), rule_json("too-many-per-page-b")],
                "total": 2,
                "page": 1,
                "perPage": 1,
            }),
            field_or_relation: "data.len() > perPage",
        },
    ]);

    for case in cases {
        let err = rules::decode_find(&case.body).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Http, "{}: {err}", case.name);
        assert!(
            err.message.contains("rule _find") && err.message.contains(case.field_or_relation),
            "{}: {err}",
            case.name
        );
    }
}

#[test]
fn find_envelope_accepts_unknown_fields() {
    let body = json!({
        "data": [],
        "total": 0,
        "page": 1,
        "perPage": 1,
        "a_new_server_field": {"is": "ignored"},
    });

    let (rules, total) = rules::decode_find(&body).unwrap();
    assert!(rules.is_empty());
    assert_eq!(total, 0);
}

/// `count` rules named `{prefix}-0` through `{prefix}-{count - 1}`. The slice
/// data matches its total exactly.
fn rules_of(prefix: &str, count: u64) -> Vec<serde_json::Value> {
    (0..count)
        .map(|i| rule_json(&format!("{prefix}-{i}")))
        .collect()
}

#[test]
fn an_empty_filter_produces_no_kql() {
    assert_eq!(RuleFilter::default().to_kql(), None);
}

#[test]
fn filters_combine_with_and() {
    let f = RuleFilter {
        enabled: Some(true),
        severity: Some("high".into()),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    assert!(kql.contains("alert.attributes.enabled: true"), "{kql}");
    assert!(
        kql.contains("alert.attributes.params.severity: \"high\""),
        "{kql}"
    );
    assert!(kql.contains(" AND "), "{kql}");
}

#[test]
fn a_name_filter_produces_the_recorded_kql_path() {
    let f = RuleFilter {
        name: Some("Suspicious PowerShell".into()),
        ..Default::default()
    };
    assert_eq!(
        f.to_kql().unwrap(),
        "alert.attributes.name: \"Suspicious PowerShell\""
    );
}

#[test]
fn a_name_filter_escapes_a_quote() {
    let f = RuleFilter {
        name: Some("a\"b".into()),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    let mut expected = String::from("alert.attributes.name: \"a");
    expected.push('\\');
    expected.push('"');
    expected.push_str("b\"");
    assert_eq!(kql, expected);
}

#[test]
fn a_name_filter_combines_with_the_others() {
    let f = RuleFilter {
        name: Some("X".into()),
        enabled: Some(true),
        ..Default::default()
    };
    let kql = f.to_kql().unwrap();
    assert!(kql.contains("alert.attributes.name: \"X\""), "{kql}");
    assert!(kql.contains(" AND "), "{kql}");
}

#[tokio::test]
async fn find_page_returns_rules_and_the_total() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 20, "total": 2, "data": [rule_json("a"), rule_json("b")]
        })))
        .mount(&server)
        .await;

    let (rules, total) = rules::find_page(&transport(&server), &RuleFilter::default(), 1, 20)
        .await
        .unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(total, 2);
}

/// The corpus is read once at the result window, not paged. `.expect(1)` fails
/// if page walking returns.
#[tokio::test]
async fn find_all_reads_the_corpus_in_one_request_at_the_result_window() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "10000"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 3,
            "data": [rule_json("a"), rule_json("b"), rule_json("c")]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let all = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
}

/// A corpus above the window is read once per rule type. Six types hold one
/// rule and `new_terms` holds 9,995, so seven slices return all 10,001 rules.
#[tokio::test]
async fn find_all_partitions_a_corpus_above_the_window_by_rule_type() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param_is_missing("filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    for (rule_type, count) in [
        ("query", 1u64),
        ("eql", 1),
        ("esql", 1),
        ("threshold", 1),
        ("threat_match", 1),
        ("machine_learning", 1),
        ("new_terms", 9995),
    ] {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .and(query_param(
                "filter",
                format!("alert.attributes.params.type: \"{rule_type}\""),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(find_body(count, rules_of(rule_type, count))),
            )
            .mount(&server)
            .await;
    }

    let all = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 10001);
    assert!(
        all.iter().any(|r| r.rule_id().unwrap() == "query-0"),
        "the first type's rules must come back"
    );
    assert!(
        all.iter().any(|r| r.rule_id().unwrap() == "new_terms-9994"),
        "the last type's rules must come back too"
    );
}

/// Spec 5.2 + 5.5: when `--source` is active, a partitioned read compares its
/// slice totals against the *filtered* total, not the corpus total. The source
/// clause is carried into every type slice, and the seven slices sum to the
/// scoped total (10,001) rather than any larger unfiltered corpus.
#[tokio::test]
async fn a_scoped_partition_checks_slices_against_the_filtered_total() {
    let server = MockServer::start().await;
    let filter = RuleFilter {
        source: RuleSource::Custom,
        ..Default::default()
    };

    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.immutable: false",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    for (rule_type, count) in [
        ("query", 1u64),
        ("eql", 1),
        ("esql", 1),
        ("threshold", 1),
        ("threat_match", 1),
        ("machine_learning", 1),
        ("new_terms", 9995),
    ] {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .and(query_param(
                "filter",
                format!(
                    "alert.attributes.params.immutable: false AND \
                     alert.attributes.params.type: \"{rule_type}\""
                ),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(find_body(count, rules_of(rule_type, count))),
            )
            .mount(&server)
            .await;
    }

    let all = rules::find_all(&transport(&server), &filter).await.unwrap();
    assert_eq!(all.len(), 10001);
}

/// A type still over the window is partitioned by `enabled`. A caller's
/// `rule_type` selects one type slice before that partition.
#[tokio::test]
async fn find_all_splits_an_oversized_type_by_enabled() {
    let server = MockServer::start().await;
    let filter = RuleFilter {
        rule_type: Some("query".into()),
        ..Default::default()
    };

    // The initial read and type slice use the same oversized filter.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.type: \"query\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.enabled: true AND alert.attributes.params.type: \"query\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(2, rules_of("on", 2))))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.enabled: false AND alert.attributes.params.type: \"query\"",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(find_body(9999, rules_of("off", 9999))),
        )
        .mount(&server)
        .await;

    let all = rules::find_all(&transport(&server), &filter).await.unwrap();
    assert_eq!(all.len(), 10001);
}

/// Slice totals must equal the corpus total. Here seven slices return 7 rules
/// for a corpus of 10,001, so the short read is refused.
#[tokio::test]
async fn find_all_refuses_slice_totals_that_do_not_sum_to_the_corpus() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param_is_missing("filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    for rule_type in [
        "query",
        "eql",
        "esql",
        "threshold",
        "threat_match",
        "machine_learning",
        "new_terms",
    ] {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .and(query_param(
                "filter",
                format!("alert.attributes.params.type: \"{rule_type}\""),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(find_body(1, rules_of(rule_type, 1))),
            )
            .mount(&server)
            .await;
    }

    let err = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
    assert!(
        err.message.contains("10001") && err.message.contains("sum to 7"),
        "the error must name both the corpus count and the slice sum: {}",
        err.message
    );
}

/// A slice above the window after both partitions cannot be served. The error
/// names the count and limit, without suggesting `rules export` as an escape.
#[tokio::test]
async fn find_all_refuses_a_slice_still_over_the_window() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param_is_missing("filter"))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.type: \"query\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.enabled: true AND alert.attributes.params.type: \"query\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(find_body(10001, vec![])))
        .mount(&server)
        .await;

    let err = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);
    assert!(
        err.message.contains("10001") && err.message.contains("10000"),
        "the error must name both the slice size and the window limit: {}",
        err.message
    );
    assert!(
        !err.message.contains("rules export"),
        "the error must not point at a command with its own 10,000 cap: {}",
        err.message
    );
}

/// A server that counts more rules than it serves contradicts itself. A short
/// list is indistinguishable from deleted rules.
#[tokio::test]
async fn find_all_refuses_a_short_read() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 999, "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = rules::find_all(&transport(&server), &RuleFilter::default())
        .await
        .unwrap_err();
    assert!(
        err.message.contains("999"),
        "the error must name the count the server claimed: {}",
        err.message
    );
}

/// An empty space is not a short read.
#[tokio::test]
async fn find_all_accepts_an_honestly_empty_corpus() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 0, "data": []
        })))
        .mount(&server)
        .await;

    assert!(
        rules::find_all(&transport(&server), &RuleFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
}

/// An empty prebuilt slice is valid when the custom and prebuilt totals still
/// account for the whole corpus.
#[tokio::test]
async fn a_custom_only_stack_has_a_valid_empty_prebuilt_scope() {
    let stack = MockStack::with_rules(vec![
        json!({"rule_id": "custom-0", "name": "custom 0", "type": "query", "immutable": false}),
        json!({"rule_id": "custom-1", "name": "custom 1", "type": "query", "immutable": false}),
        json!({"rule_id": "custom-2", "name": "custom 2", "type": "query", "immutable": false}),
    ])
    .await;
    let report = rules_ops::list(
        stack.transport(),
        &RuleFilter {
            source: RuleSource::Prebuilt,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.total, 0);
}

/// An accepted empty source export is an empty typed outcome, not an unscoped
/// export request.
#[tokio::test]
async fn an_exhaustively_empty_source_export_sends_no_unscoped_request() {
    let stack = MockStack::with_rules(vec![
        json!({"rule_id": "prebuilt-0", "name": "prebuilt 0", "type": "query", "immutable": true}),
        json!({"rule_id": "prebuilt-1", "name": "prebuilt 1", "type": "query", "immutable": true}),
        json!({"rule_id": "prebuilt-2", "name": "prebuilt 2", "type": "query", "immutable": true}),
    ])
    .await;
    let outcome = rules_ops::export_rules(
        stack.transport(),
        &[],
        None,
        RuleSource::Custom,
        Format::Ndjson,
    )
    .await
    .unwrap();

    assert_eq!(outcome.exported, 0);
    assert!(outcome.missing.is_empty());
    assert!(outcome.body.is_empty());
    assert!(
        !stack
            .write_paths()
            .await
            .iter()
            .any(|path| { path == "POST /api/detection_engine/rules/_export" })
    );
}

/// An old stack is unsupported only when custom and prebuilt do not partition
/// its unfiltered corpus.
#[tokio::test]
async fn a_non_exhaustive_immutable_partition_is_refused() {
    let stack = MockStack::with_source_totals(0, 2, 3).await;
    let err = rules_ops::list(
        stack.transport(),
        &RuleFilter {
            source: RuleSource::Custom,
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Unsupported);
    for count in ["0", "2", "3"] {
        assert!(err.message.contains(count), "{}", err.message);
    }
    assert!(err.message.contains("--source all"), "{}", err.message);
}

/// The empty-scope guard must not blame `immutable` for an emptiness a narrower
/// clause caused. Here `--source custom --tag nomatch` returns nothing because
/// the tag misses, while the source-only scope is non-empty, so `list` returns
/// an empty result rather than an error naming `immutable`.
#[tokio::test]
async fn a_narrowing_clause_does_not_trigger_the_empty_scope_guard() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "version": {"number": "9.5.1", "build_flavor": "traditional"}
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.immutable: false AND alert.attributes.tags: \"nomatch\"",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": 0, "data": []
        })))
        .mount(&server)
        .await;

    // The source-only read is non-empty, so the guard stays silent.
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .and(query_param(
            "filter",
            "alert.attributes.params.immutable: false",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 1, "total": 2, "data": [rule_json("a"), rule_json("b")]
        })))
        .mount(&server)
        .await;

    let filter = RuleFilter {
        source: RuleSource::Custom,
        tag: Some("nomatch".into()),
        ..Default::default()
    };
    let report = rules_ops::list(&transport(&server), &filter).await.unwrap();

    assert_eq!(report.total, 0, "the tag missed, so nothing is listed");
}

#[tokio::test]
async fn get_queries_by_rule_id_not_by_server_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .and(query_param("rule_id", "abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("abc")))
        .mount(&server)
        .await;

    let r = rules::get(&transport(&server), "abc").await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "abc");
}

/// An API rule with volatile fields that create and update must not forward.
fn rule_with_volatile_fields(id: &str) -> Rule {
    Rule::from_value(json!({
        "rule_id": id, "name": format!("rule {id}"), "type": "query", "risk_score": 21,
        "id": "server-side-id", "created_at": "2026-01-01T00:00:00.000Z",
        "created_by": "someone", "updated_at": "2026-01-01T00:00:00.000Z",
        "updated_by": "someone", "revision": 3, "version": 4
    }))
    .unwrap()
}

#[tokio::test]
async fn create_posts_to_the_rules_endpoint_and_returns_the_parsed_rule() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    let rule = Rule::from_value(rule_json("a")).unwrap();
    let r = rules::create(&transport(&server), &rule).await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "a");
}

#[tokio::test]
async fn create_strips_volatile_fields_from_the_request_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    rules::create(&transport(&server), &rule_with_volatile_fields("a"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert!(body.get("id").is_none(), "volatile id must not be sent");
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_by").is_none());
    assert_eq!(body["rule_id"], "a", "the stable identity must survive");
}

#[tokio::test]
async fn update_puts_to_the_rules_endpoint_and_returns_the_parsed_rule() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    let rule = Rule::from_value(rule_json("a")).unwrap();
    let r = rules::update(&transport(&server), &rule).await.unwrap();
    assert_eq!(r.rule_id().unwrap(), "a");
}

#[tokio::test]
async fn update_strips_volatile_fields_from_the_request_body() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(rule_json("a")))
        .mount(&server)
        .await;

    rules::update(&transport(&server), &rule_with_volatile_fields("a"))
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    assert!(body.get("id").is_none(), "volatile id must not be sent");
    assert!(body.get("created_at").is_none());
    assert!(body.get("updated_by").is_none());
    assert_eq!(body["rule_id"], "a", "the stable identity must survive");
}

#[tokio::test]
async fn patch_targets_the_stable_rule_id() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/detection_engine/rules"))
        .and(body_partial_json(
            json!({"rule_id": "abc", "enabled": true}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "abc", "name": "r", "enabled": true
        })))
        .mount(&server)
        .await;

    let r = rules::patch(&transport(&server), "abc", &json!({"enabled": true}))
        .await
        .unwrap();
    assert!(r.enabled());
}

#[tokio::test]
async fn bulk_targets_rule_ids_through_the_query_form() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(body_partial_json(json!({"action": "disable"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "rules_count": 2,
            "attributes": {"summary": {"succeeded": 2, "failed": 0, "skipped": 0, "total": 2}}
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string()];
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Disable, &ids, false)
        .await
        .unwrap();
    assert_eq!(out.succeeded, 2);
    assert_eq!(out.total, 2);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = requests[0].body_json().unwrap();
    let query = body["query"].as_str().unwrap();
    assert!(
        query.contains("alert.attributes.params.ruleId"),
        "must target the stable rule_id through the query form: {query}"
    );
    assert!(
        query.contains("\"a\"") && query.contains("\"b\""),
        "both ids must appear in the query: {query}"
    );
    assert!(
        body.get("ids").is_none(),
        "must not target the volatile server-side ids"
    );
}

#[tokio::test]
async fn bulk_dry_run_sets_the_query_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .and(query_param("dry_run", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attributes": {"summary": {"succeeded": 1, "failed": 0, "skipped": 0, "total": 1}}
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string()];
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Enable, &ids, true)
        .await
        .unwrap();
    assert_eq!(out.succeeded, 1);
}

#[tokio::test]
async fn bulk_with_no_targets_makes_no_request() {
    // An empty selection must not query every rule.
    let server = MockServer::start().await;
    let out = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Delete, &[], false)
        .await
        .unwrap();
    assert_eq!(out.total, 0);
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "no request may be sent"
    );
}

#[test]
fn bulk_outcome_rejects_malformed_success_bodies() {
    for body in [
        json!({}),
        json!({"attributes":{"summary":{"succeeded":1}}}),
        json!({"attributes":{"summary":{"succeeded":1,"failed":0,"skipped":0,"total":"1"}}}),
        json!({"attributes":{"summary":{"succeeded":1,"failed":0,"skipped":0,"total":2}}}),
    ] {
        let error = rules::decode_bulk_outcome(&body).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http);
    }
}

#[tokio::test]
async fn bulk_by_rule_ids_rejects_a_malformed_success_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_bulk_action"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "attributes": {"summary": {"succeeded": 1, "failed": 0, "skipped": 0, "total": 2}}
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string()];
    let err = rules::bulk_by_rule_ids(&transport(&server), BulkAction::Delete, &ids, false)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
}

#[tokio::test]
async fn export_separates_rules_from_the_trailer() {
    let server = MockServer::start().await;
    let body = format!(
        "{}\n{}\n",
        serde_json::to_string(&rule_json("a")).unwrap(),
        r#"{"exported_count":1,"exported_rules_count":1,"missing_rules_count":0}"#
    );
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;

    let bundle = rules::export(&transport(&server), None).await.unwrap();
    assert_eq!(bundle.rules.len(), 1);
    assert_eq!(bundle.summary.unwrap().exported_rules_count, 1);
}

#[tokio::test]
async fn a_scoped_export_sends_the_objects_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .and(body_partial_json(
            json!({"objects": [{"rule_id": "a"}, {"rule_id": "b"}]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"rule_id":"a","name":"A"}"#,
            "\n",
            r#"{"exported_count":1,"exported_rules_count":1,"missing_rules":[{"rule_id":"b"}],"missing_rules_count":1}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string()];
    let bundle = rules::export(&transport(&server), Some(&ids))
        .await
        .unwrap();
    assert_eq!(bundle.rules.len(), 1);
    let summary = bundle.summary.unwrap();
    assert_eq!(summary.missing_rules_count, 1);
    assert_eq!(summary.missing_rules[0]["rule_id"], "b");
}

/// An unscoped export posts no body, preserving the established request shape.
#[tokio::test]
async fn an_unscoped_export_sends_no_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "{\"exported_count\":0,\"exported_rules_count\":0,\"missing_rules_count\":0}\n",
        ))
        .mount(&server)
        .await;

    rules::export(&transport(&server), None).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0].body.is_empty(),
        "an unscoped export must post no body: {:?}",
        String::from_utf8_lossy(&requests[0].body)
    );
}

/// A rule that references an exception list exports a four-line bundle. The
/// orchestration must re-encode the whole bundle; encoding rules only would
/// silently drop the list and item (spec 5.2: silent truncation).
#[tokio::test]
async fn export_rules_carries_the_exception_bundle() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"rule_id":"r","name":"R","type":"query","exceptions_list":[{"id":"L","list_id":"l","type":"detection","namespace_type":"single"}]}"#,
            "\n",
            r#"{"id":"L","list_id":"l","type":"detection","name":"L","namespace_type":"single","tie_breaker_id":"t"}"#,
            "\n",
            r#"{"id":"I","item_id":"i","list_id":"l","type":"simple","name":"I","namespace_type":"single","entries":[]}"#,
            "\n",
            r#"{"exported_count":2,"exported_rules_count":1,"missing_rules":[],"missing_rules_count":0,"exported_exception_list_count":1,"exported_exception_list_item_count":1,"missing_exception_lists":[],"missing_exception_list_items":[]}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let outcome = rules_ops::export_rules(
        &transport(&server),
        &[],
        None,
        RuleSource::All,
        Format::Ndjson,
    )
    .await
    .unwrap();

    assert_eq!(outcome.exported, 1);
    assert!(
        outcome.body.contains("\"list_id\":\"l\""),
        "the exception list must survive export: {}",
        outcome.body
    );
    assert!(
        outcome.body.contains("\"item_id\":\"i\""),
        "the exception item must survive export: {}",
        outcome.body
    );
}

/// A YAML export of an exception-free selection still encodes the rules; the
/// refusal path must not fire when there is nothing to represent.
#[tokio::test]
async fn export_rules_yaml_without_exceptions_still_encodes_rules() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"rule_id":"a","name":"A","type":"query"}"#,
            "\n",
            r#"{"exported_count":1,"exported_rules_count":1,"missing_rules_count":0}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let outcome = rules_ops::export_rules(
        &transport(&server),
        &[],
        None,
        RuleSource::All,
        Format::Yaml,
    )
    .await
    .unwrap();

    let rules = elasticctl_api::codec::decode_yaml(&outcome.body).unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_id().unwrap(), "a");
}

/// A YAML export cannot represent exception lists or items, so a bundle is
/// refused with the fix named, rather than silently truncated (spec 5.2).
#[tokio::test]
async fn export_rules_yaml_refuses_a_bundle_with_exceptions() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_export"))
        .respond_with(ResponseTemplate::new(200).set_body_string(concat!(
            r#"{"rule_id":"r","name":"R","type":"query","exceptions_list":[{"id":"L","list_id":"l","type":"detection","namespace_type":"single"}]}"#,
            "\n",
            r#"{"id":"L","list_id":"l","type":"detection","name":"L","namespace_type":"single","tie_breaker_id":"t"}"#,
            "\n",
            r#"{"id":"I","item_id":"i","list_id":"l","type":"simple","name":"I","namespace_type":"single","entries":[]}"#,
            "\n",
            r#"{"exported_count":2,"exported_rules_count":1,"missing_rules":[],"missing_rules_count":0,"exported_exception_list_count":1,"exported_exception_list_item_count":1,"missing_exception_lists":[],"missing_exception_list_items":[]}"#,
            "\n"
        )))
        .mount(&server)
        .await;

    let err = rules_ops::export_rules(
        &transport(&server),
        &[],
        None,
        RuleSource::All,
        Format::Yaml,
    )
    .await
    .unwrap_err();

    assert_eq!(err.kind, ErrorKind::Unsupported);
    assert!(err.message.contains("ndjson"), "{}", err.message);
    assert!(err.message.contains("1 exception list"), "{}", err.message);
    assert!(err.message.contains("1 item"), "{}", err.message);
}

#[tokio::test]
async fn existing_rule_ids_reports_only_the_ids_the_server_knows() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 3, "total": 1, "data": [rule_json("b")]
        })))
        .mount(&server)
        .await;

    let ids = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    let found = rules::existing_rule_ids(&transport(&server), &ids)
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert!(found.contains("b"));
}

#[tokio::test]
async fn existing_rule_ids_sends_no_request_for_an_empty_list() {
    let server = MockServer::start().await;
    assert!(
        rules::existing_rule_ids(&transport(&server), &[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "an empty list must never become an unscoped find"
    );
}

#[tokio::test]
async fn import_reflects_overwrite_true_in_the_query_string() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .and(query_param("overwrite", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("a")).unwrap());
    let result = rules::import(&transport(&server), &ndjson, true)
        .await
        .unwrap();
    assert_eq!(result["success_count"], 1);
}

#[tokio::test]
async fn import_reflects_overwrite_false_in_the_query_string() {
    // Overwrite replaces existing rules, so the settings must stay distinct.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .and(query_param("overwrite", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("a")).unwrap());
    let result = rules::import(&transport(&server), &ndjson, false)
        .await
        .unwrap();
    assert_eq!(result["success_count"], 1);
}

#[tokio::test]
async fn import_sends_the_ndjson_as_a_multipart_upload() {
    // Kibana import requires a multipart file upload, not a JSON body.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true, "success_count": 1, "errors": []
        })))
        .mount(&server)
        .await;

    let ndjson = format!("{}\n", serde_json::to_string(&rule_json("abc")).unwrap());
    rules::import(&transport(&server), &ndjson, true)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let content_type = requests[0]
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("multipart/form-data"),
        "{content_type}"
    );
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("\"rule_id\":\"abc\""), "{body}");
}

#[tokio::test]
async fn a_failing_import_is_a_classified_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules/_import"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": "invalid ndjson"
        })))
        .mount(&server)
        .await;

    let err = rules::import(&transport(&server), "not ndjson", true)
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Http);
    assert!(err.message.contains("invalid ndjson"), "{}", err.message);
}

#[tokio::test]
async fn a_404_from_get_is_a_not_found_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "not found"})))
        .mount(&server)
        .await;

    let err = rules::get(&transport(&server), "missing")
        .await
        .unwrap_err();
    assert_eq!(err.kind, elasticctl_core::ErrorKind::NotFound);
}

/// Replay the recorded exchange. A hand-written mock would test assumptions,
/// not the preview alerts index response.
#[tokio::test]
async fn preview_hits_parses_the_recorded_response() {
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/serverless-9.6.0/rules_preview_hits.json"
        ))
        .expect("rules_preview_hits fixture"),
    )
    .expect("fixture is JSON");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/\.preview\.alerts-security\.alerts-default/_search$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture["response"].clone()))
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let hits = rules::preview_hits(&t, "default", "pv-1", 3).await.unwrap();
    assert!(hits.total >= 1, "the recorded response carries hits");
    assert!(!hits.sample.is_empty(), "a sample must carry the documents");
    assert!(
        hits.sample[0].get("_source").is_some(),
        "a sample entry is the alert document, not a summary of it: {:?}",
        hits.sample[0]
    );
}

#[tokio::test]
async fn preview_hits_queries_the_space_scoped_preview_index_by_preview_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.preview.alerts-security.alerts-soc/_search"))
        .and(body_partial_json(json!({
            "size": 0,
            "track_total_hits": true,
            "query": {"term": {"kibana.alert.rule.uuid": "pv-9"}}
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 302, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;

    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let hits = rules::preview_hits(&t, "soc", "pv-9", 0).await.unwrap();
    assert_eq!(hits.total, 302);
    assert!(hits.sample.is_empty(), "size 0 asks for no documents");
}

#[tokio::test]
async fn preview_hits_treats_an_empty_space_as_default() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.preview.alerts-security.alerts-default/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0}, "hits": []}
        })))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    assert_eq!(
        rules::preview_hits(&t, "", "pv-1", 0).await.unwrap().total,
        0
    );
}

#[tokio::test]
async fn preview_hits_rejects_a_malformed_success_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/.preview.alerts-security.alerts-default/_search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": "1"}, "hits": []}
        })))
        .mount(&server)
        .await;
    let mut profile = profile_for(&server);
    profile.es_url = Some(server.uri());
    let t = Transport::new(&profile).unwrap();

    let err = rules::preview_hits(&t, "default", "pv-1", 0)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Http);
}

#[test]
fn decode_preview_hits_checked_rejects_malformed_bodies() {
    for body in [
        json!({}),
        json!({"hits": {"total": {"value": "1"}, "hits": []}}),
        json!({"hits": {"total": {}, "hits": []}}),
        json!({"hits": {"total": {"value": 1}}}),
        json!({"hits": {"total": {"value": 1}, "hits": "not-an-array"}}),
    ] {
        let error = rules::decode_preview_hits_checked(&body).unwrap_err();
        assert_eq!(error.kind, ErrorKind::Http);
    }
}
