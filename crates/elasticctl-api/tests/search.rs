use elasticctl_api::search::{dataview, dsl, esql, has_source, prepend_from, rewrite_from};
use elasticctl_core::Transport;
use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

fn test_transport(uri: &str) -> Transport {
    Transport::new(&elasticctl_core::Profile {
        kibana_url: uri.to_string(),
        es_url: Some(uri.to_string()),
        api_key: Some("essu_test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .expect("transport")
}

#[test]
fn decodes_a_sync_esql_response() {
    let body = json!({
        "took": 39,
        "is_partial": false,
        "columns": [
            {"name": "seq", "type": "long"},
            {"name": "message", "type": "text"}
        ],
        "values": [[1, "hello 1"], [2, "hello 2"]]
    });
    let decoded = esql::decode(&body).expect("decode");
    assert_eq!(decoded.columns.len(), 2);
    assert_eq!(decoded.columns[0].name, "seq");
    assert_eq!(decoded.columns[0].r#type, "long");
    assert_eq!(decoded.values.len(), 2);
    assert_eq!(decoded.values[0][0], json!(1));
    assert!(!decoded.is_partial);
}

#[test]
fn decodes_a_columnar_esql_response_into_row_objects() {
    let body = json!({
        "is_partial": false,
        "columns": [
            {"name": "seq", "type": "long"},
            {"name": "message", "type": "text"}
        ],
        "values": [
            [1, 2, 3],
            ["a", "b", "c"]
        ]
    });
    let decoded = esql::decode_columnar(&body).expect("decode columnar");
    assert_eq!(decoded.columns.len(), 2);
    assert_eq!(decoded.values.len(), 3);
    assert_eq!(decoded.values[0], vec![json!(1), json!("a")]);
    assert_eq!(decoded.values[1], vec![json!(2), json!("b")]);
    assert_eq!(decoded.values[2], vec![json!(3), json!("c")]);
}

#[test]
fn decodes_an_empty_columnar_response_as_zero_rows() {
    let body = json!({
        "is_partial": false,
        "columns": [
            {"name": "seq", "type": "long"},
            {"name": "message", "type": "text"}
        ],
        "values": []
    });
    let decoded = esql::decode_columnar(&body).expect("decode empty columnar");
    assert_eq!(decoded.columns.len(), 2);
    assert!(decoded.values.is_empty());
}

#[test]
fn rejects_a_response_without_columns() {
    let body = json!({"values": [[1]]});
    let err = esql::decode(&body).expect_err("must fail");
    assert!(
        err.to_envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("decoding esql response")
    );
}

#[test]
fn rejects_a_values_row_whose_width_mismatches_columns() {
    let body = json!({
        "columns": [{"name": "seq", "type": "long"}],
        "values": [[1, 2]]
    });
    let err = esql::decode(&body).expect_err("must fail");
    assert!(
        err.to_envelope()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("decoding esql response")
    );
}

#[test]
fn decodes_a_search_hit_page() {
    let body = json!({
        "took": 12,
        "hits": {
            "total": {"value": 3, "relation": "eq"},
            "hits": [
                {"_index": "idx", "_id": "a", "_score": 1.0, "_source": {"seq": 1}, "sort": [1, 0]}
            ]
        }
    });
    let page = dsl::decode(&body).expect("decode");
    assert_eq!(page.total, Some(3));
    assert_eq!(page.hits.len(), 1);
    assert_eq!(page.hits[0].source, json!({"seq": 1}));
    assert_eq!(page.hits[0].sort, Some(vec![json!(1), json!(0)]));
}

#[test]
fn decode_keeps_hit_metadata() {
    let body = json!({
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {"_index": "idx", "_id": "a", "_score": 1.5, "_source": {"seq": 1}}
            ]
        }
    });
    let page = dsl::decode(&body).expect("decode");
    let hit = &page.hits[0];
    assert_eq!(hit.id.as_deref(), Some("a"));
    assert_eq!(hit.index.as_deref(), Some("idx"));
    assert_eq!(hit.score, Some(1.5));
}

#[test]
fn decode_treats_missing_or_null_metadata_as_none() {
    let body = json!({
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "hits": [
                {"_id": null, "_index": "idx", "_score": null, "_source": {"seq": 1}}
            ]
        }
    });
    let page = dsl::decode(&body).expect("decode");
    let hit = &page.hits[0];
    assert_eq!(hit.id, None);
    assert_eq!(hit.index.as_deref(), Some("idx"));
    assert_eq!(hit.score, None);
}

#[tokio::test]
async fn run_stream_pages_with_search_after() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());

    Mock::given(method("POST"))
        .and(path("/idx/_pit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "pit-1"})))
        .mount(&server)
        .await;

    // Page 2: the first page ends on sort [2, 1], so the next search_after
    // returns the third and final hit.
    Mock::given(method("POST"))
        .and(path("/_search"))
        .and(body_partial_json(json!({"search_after": [2, 1]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 3, "relation": "eq"}, "hits": [
                {"_source": {"seq": 3}, "sort": [3, 2]}
            ]}
        })))
        .mount(&server)
        .await;

    // Page 3: search_after [3, 2] is past the last document, so the page is
    // empty and the loop ends.
    Mock::given(method("POST"))
        .and(path("/_search"))
        .and(body_partial_json(json!({"search_after": [3, 2]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;

    // Page 1: the first request carries size 1000 and no search_after. This
    // matcher is mounted last so the more specific search_after mocks above
    // win for later pages.
    Mock::given(method("POST"))
        .and(path("/_search"))
        .and(body_partial_json(json!({"size": 1000})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 3, "relation": "eq"}, "hits": [
                {"_source": {"seq": 1}, "sort": [1, 0]},
                {"_source": {"seq": 2}, "sort": [2, 1]}
            ]}
        })))
        .mount(&server)
        .await;

    // The PIT close is a DELETE carrying the id in the JSON body.
    Mock::given(method("DELETE"))
        .and(path("/_pit"))
        .and(body_partial_json(json!({"id": "pit-1"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"succeeded": true, "num_freed": 1})),
        )
        .mount(&server)
        .await;

    let hits = dsl::run_stream(
        &t,
        "idx",
        &json!({"match_all": {}}),
        &json!([{"seq": "asc"}, {"_shard_doc": "asc"}]),
        None,
    )
    .await
    .expect("stream");
    assert_eq!(hits.len(), 3);
    assert_eq!(hits[2].source, json!({"seq": 3}));
}

#[tokio::test]
async fn run_stream_appends_a_shard_doc_tiebreaker() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());

    Mock::given(method("POST"))
        .and(path("/idx/_pit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "pit-1"})))
        .mount(&server)
        .await;

    // The operator's sort is a single object with no `_shard_doc`; the client
    // must page over a total order, so the _search body carries the tiebreaker.
    Mock::given(method("POST"))
        .and(path("/_search"))
        .and(body_partial_json(
            json!({"sort": [{"seq": "asc"}, {"_shard_doc": "asc"}]}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/_pit"))
        .and(body_partial_json(json!({"id": "pit-1"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"succeeded": true, "num_freed": 1})),
        )
        .mount(&server)
        .await;

    let hits = dsl::run_stream(
        &t,
        "idx",
        &json!({"match_all": {}}),
        &json!({"seq": "asc"}),
        None,
    )
    .await
    .expect("stream");
    assert!(hits.is_empty());
}

#[tokio::test]
async fn run_stream_uses_the_limit_as_the_page_size() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());

    Mock::given(method("POST"))
        .and(path("/idx/_pit"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "pit-1"})))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/_search"))
        .and(body_partial_json(json!({"size": 5})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/_pit"))
        .and(body_partial_json(json!({"id": "pit-1"})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"succeeded": true, "num_freed": 1})),
        )
        .mount(&server)
        .await;

    let hits = dsl::run_stream(
        &t,
        "idx",
        &json!({"match_all": {}}),
        &json!([{"seq": "asc"}, {"_shard_doc": "asc"}]),
        Some(5),
    )
    .await
    .expect("stream");
    assert!(hits.is_empty());
}

#[tokio::test]
async fn run_async_sends_columnar() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .and(body_partial_json(json!({"columnar": true})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1, 2]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let resp = esql::run_async(&t, "FROM x | LIMIT 2")
        .await
        .expect("async");
    assert_eq!(resp.values.len(), 2);
}

#[tokio::test]
async fn run_async_polls_until_complete() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    // First poll: still running, served exactly once. Mounted before the
    // terminal mock, so at equal priority wiremock matches it first (FIFO);
    // `up_to_n_times(1)` exhausts it and the second poll falls through to the
    // terminal mock. A runner with no loop would decode this body (no
    // `columns`/`values`) and fail.
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .and(|req: &Request| req.url.query().is_none())
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    // Terminal poll: `is_running: false` with the result.
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .and(|req: &Request| req.url.query().is_none())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1, 2]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .mount(&server)
        .await;

    let resp = esql::run_async(&t, "FROM x | LIMIT 2")
        .await
        .expect("async");
    assert_eq!(resp.values.len(), 2);
}

#[tokio::test]
async fn run_async_decodes_an_inline_complete_response_without_id() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "is_running": false, "is_partial": false,
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1, 2]]
        })))
        .mount(&server)
        .await;

    let resp = esql::run_async(&t, "FROM x | LIMIT 2")
        .await
        .expect("async");
    assert_eq!(resp.values.len(), 2);
}

#[tokio::test]
async fn run_async_deletes_the_id_from_an_inline_complete_start() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "a1", "is_running": false, "is_partial": false,
            "columns": [{"name": "seq", "type": "long"}],
            "values": [[1, 2]]
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;

    let resp = esql::run_async(&t, "FROM x | LIMIT 2")
        .await
        .expect("async");
    assert_eq!(resp.values.len(), 2);
}

#[tokio::test]
async fn run_async_deletes_on_a_poll_error() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    Mock::given(method("POST"))
        .and(path("/_query/async"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/_query/async/a1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
        .expect(1)
        .mount(&server)
        .await;

    let err = esql::run_async(&t, "FROM x | LIMIT 2")
        .await
        .expect_err("must fail");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Http);
}

#[tokio::test]
async fn poll_until_complete_times_out_after_its_budget() {
    let server = MockServer::start().await;
    let t = test_transport(&server.uri());
    // Every poll reports still-running, so the runner exhausts its poll budget.
    Mock::given(method("GET"))
        .and(path("/_query/async/a1"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"id": "a1", "is_running": true})),
        )
        .mount(&server)
        .await;

    let err = esql::poll_until_complete(&t, "a1", 3, std::time::Duration::from_millis(1))
        .await
        .expect_err("must time out");
    assert_eq!(err.kind, elasticctl_core::ErrorKind::Timeout);
}

#[test]
fn resolves_a_data_view_by_name_to_its_title() {
    let body = json!({
        "data_view": [
            {"id": "security-solution-alert-default", "name": "Security solution alert default", "title": ".alerts-security.alerts-default", "namespaces": ["default"]}
        ]
    });
    assert_eq!(
        dataview::resolve_title(&body, "Security solution alert default").unwrap(),
        ".alerts-security.alerts-default"
    );
    assert_eq!(
        dataview::resolve_title(&body, "security-solution-alert-default").unwrap(),
        ".alerts-security.alerts-default"
    );
}

#[test]
fn rejects_an_ambiguous_data_view_name() {
    let body = json!({
        "data_view": [
            {"id": "a", "name": "Dup", "title": "x"},
            {"id": "b", "name": "Dup", "title": "y"}
        ]
    });
    assert!(dataview::resolve_title(&body, "Dup").is_err());
}

#[test]
fn rewrite_from_replaces_a_leading_from_source() {
    assert_eq!(
        rewrite_from("FROM logs-* | LIMIT 10", "new-index"),
        "FROM new-index | LIMIT 10"
    );
    assert_eq!(rewrite_from("from logs-*", "new-index"), "FROM new-index");
    assert_eq!(
        rewrite_from("  FROM a, b | WHERE x", "new-index"),
        "  FROM new-index | WHERE x"
    );
}

#[test]
fn rewrite_from_passes_through_queries_without_a_from_clause() {
    assert_eq!(rewrite_from("ROW a = 1", "new-index"), "ROW a = 1");
    assert_eq!(rewrite_from("SHOW INFO", "new-index"), "SHOW INFO");
    assert_eq!(rewrite_from("METRICS idx", "new-index"), "METRICS idx");
}

#[test]
fn rewrite_from_prepends_a_pipe_for_a_command_fragment() {
    assert_eq!(
        rewrite_from("SORT seq ASC | LIMIT 2", "new-index"),
        "FROM new-index | SORT seq ASC | LIMIT 2"
    );
    assert_eq!(
        rewrite_from("| SORT seq ASC", "new-index"),
        "FROM new-index | SORT seq ASC"
    );
}

#[test]
fn comment_prefixed_queries_classify_their_real_source() {
    assert!(has_source("// hunt note\nFROM logs-* | LIMIT 10"));
    assert!(has_source("/* hunt note */ FROM logs-*"));
    assert_eq!(
        prepend_from("// hunt note\nFROM logs-* | LIMIT 10", "new-index"),
        "// hunt note\nFROM logs-* | LIMIT 10"
    );
    assert_eq!(
        prepend_from("/* hunt note */ FROM logs-*", "new-index"),
        "/* hunt note */ FROM logs-*"
    );
}

#[test]
fn rewrite_from_rewrites_a_comment_prefixed_from() {
    assert_eq!(
        rewrite_from("// hunt note\nFROM logs-* | LIMIT 10", "new-index"),
        "// hunt note\nFROM new-index | LIMIT 10"
    );
    assert_eq!(
        rewrite_from("/* hunt note */ FROM logs-*", "new-index"),
        "/* hunt note */ FROM new-index"
    );
}
