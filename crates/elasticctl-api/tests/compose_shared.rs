use elasticctl_api::{cases, compose::*};
use elasticctl_core::{Error, ErrorKind, Profile, Transport};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};
fn fixture(name: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let preferred = root.join("traditional-9.5.1").join(name);
    let p = if preferred.exists() {
        preferred
    } else {
        let mut dirs = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        dirs.sort();
        dirs.into_iter()
            .map(|d| d.join(name))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("missing recorded fixture {name}"))
    };
    serde_json::from_str::<Value>(&std::fs::read_to_string(p).unwrap()).unwrap()["response"].clone()
}
fn transport(s: &MockServer) -> Transport {
    Transport::new(&Profile {
        kibana_url: s.uri(),
        es_url: None,
        api_key: Some("test".into()),
        username: None,
        password: None,
        space: "default".into(),
        verify: true,
        timeout_secs: 5,
    })
    .unwrap()
}
#[test]
fn grammars() {
    for s in ["1s", "24h", "9999w"] {
        assert!(validate_since(s).is_ok());
    }
    for s in ["0h", "24", "h", "10000d", "now-1d", "1H", "24h ", "١h"] {
        assert!(validate_since(s).is_err());
    }
    for s in ["", ".", ".."] {
        assert!(!is_path_segment(s));
    }
    for s in ["...", ".a", "a..b"] {
        assert!(is_path_segment(s));
    }
}
#[test]
fn degradation() {
    for k in [
        ErrorKind::Auth,
        ErrorKind::Connection,
        ErrorKind::Timeout,
        ErrorKind::Permission,
        ErrorKind::NotFound,
        ErrorKind::Conflict,
        ErrorKind::Unsupported,
        ErrorKind::Http,
        ErrorKind::Error,
    ] {
        let fatal = matches!(
            k,
            ErrorKind::Auth | ErrorKind::Connection | ErrorKind::Timeout
        );
        assert_eq!(is_fatal(k), fatal);
        let r = degrade::<()>(Err(Error::new(k, "secret")));
        assert_eq!(r.is_err(), fatal);
        if !fatal {
            assert!(matches!(r.unwrap(), Part::Unavailable(_)));
        }
    }
    assert!(matches!(degrade(Ok(7)).unwrap(), Part::Ok(7)));
}
#[tokio::test]
async fn snapshot_existing_and_mismatch() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let body = fixture("rule_get_executed.json");
    let last = body["execution_summary"]["last_execution"].clone();
    let id = body["rule_id"].as_str().unwrap().to_owned();
    Mock::given(method("GET"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    let snap = snapshot_by_id(&t, &id).await.unwrap();
    let e = snap.execution.unwrap();
    assert_eq!(e.status, last["status"].as_str().unwrap());
    assert_eq!(e.date, last["date"].as_str().unwrap());
    assert_eq!(e.status_order, last["status_order"].as_i64());
    assert_eq!(e.message.as_deref(), last["message"].as_str());
    assert!(!e.message_truncated);
    assert_eq!(
        e.metrics.total_search_duration_ms,
        last["metrics"]["total_search_duration_ms"].as_f64()
    );
    assert_eq!(
        e.metrics.total_indexing_duration_ms,
        last["metrics"]["total_indexing_duration_ms"].as_f64()
    );
    assert!(!snap.rule.as_map().contains_key("execution_summary"));
    assert_eq!(
        snap.rule,
        elasticctl_api::rules_ops::get_one(&t, &id).await.unwrap()
    );
    assert_eq!(
        snapshot_by_id(&t, "other").await.unwrap_err().kind,
        ErrorKind::NotFound
    );
}
#[tokio::test]
async fn a_null_execution_summary_reads_as_never_run() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let mut body = fixture("rules_get.json");
    let id = body["rule_id"].as_str().unwrap().to_owned();
    body["execution_summary"] = Value::Null;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    let snap = snapshot_by_id(&t, &id).await.unwrap();
    assert!(snap.execution.is_none());
    assert!(!snap.rule.as_map().contains_key("execution_summary"));
}
#[tokio::test]
async fn execution_variants() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let mut body = fixture("rules_get.json");
    let id = body["rule_id"].as_str().unwrap().to_owned();
    body["execution_summary"] = json!({"last_execution":{"status":"failed","date":"today","message":"界".repeat(1000),"metrics":{"unknown":7,"total_search_duration_ms":2}}});
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
        .mount(&s)
        .await;
    let e = snapshot_by_id(&t, &id).await.unwrap().execution.unwrap();
    assert_eq!(e.message.unwrap().len(), 2046);
    assert!(e.message_truncated);
    assert_eq!(e.metrics.total_search_duration_ms, Some(2.0));
    s.reset().await;
    body["execution_summary"]["last_execution"]
        .as_object_mut()
        .unwrap()
        .remove("status");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    assert_eq!(
        snapshot_by_id(&t, &id).await.unwrap_err().kind,
        ErrorKind::Http
    );
}
#[tokio::test]
async fn path_encoding_and_invalid_cases() {
    let s = MockServer::start().await;
    let t = transport(&s);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("cases_find.json")))
        .mount(&s)
        .await;
    for id in [".", "..", ""] {
        assert_eq!(
            cases::by_alert(&t, id).await.unwrap_err().kind,
            ErrorKind::Error
        );
    }
    assert!(s.received_requests().await.unwrap().is_empty());
    for (id, encoded) in [
        ("a/b?c#d %", "a%2Fb%3Fc%23d%20%25"),
        ("...", "..."),
        ("%2e%2e", "%252e%252e"),
    ] {
        assert_eq!(
            cases::by_alert(&t, id).await.unwrap_err().kind,
            ErrorKind::Http
        );
        assert_eq!(
            s.received_requests()
                .await
                .unwrap()
                .last()
                .unwrap()
                .url
                .path(),
            format!("/api/cases/alerts/{encoded}")
        );
    }
}
#[tokio::test]
async fn activity_body_and_missing_aggregations() {
    let s = MockServer::start().await;
    let t = transport(&s);
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/signals/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("signals_search.json")))
        .mount(&s)
        .await;
    assert_eq!(
        alert_activity(&t, "r1", "24h", 0).await.unwrap_err().kind,
        ErrorKind::Http
    );
    let expected = json!({"query":{"bool":{"filter":[{"term":{"kibana.alert.rule.rule_id":"r1"}},{"range":{"@timestamp":{"gte":"now-24h"}}}]}},"sort":[{"@timestamp":{"order":"desc"}},{"kibana.alert.uuid":{"order":"asc"}}],"size":0,"track_total_hits":true,"aggs":{"status":{"terms":{"field":"kibana.alert.workflow_status","size":8}}}});
    let reqs = s.received_requests().await.unwrap();
    let actual: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(
        serde_json::to_vec(&actual).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
}
#[tokio::test]
async fn recorded_execution() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let body = fixture("rule_get_executed.json");
    let id = body["rule_id"].as_str().unwrap().to_owned();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    assert!(snapshot_by_id(&t, &id).await.unwrap().execution.is_some());
}
#[tokio::test]
async fn activity_buckets() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let mut body = fixture("signals_search_rule_activity.json");
    let template = body["aggregations"]["status"]["buckets"][0].clone();
    assert!(template.is_object());
    body["aggregations"]["status"]["buckets"] = json!(
        ["open", "acknowledged", "closed", "custom"]
            .into_iter()
            .enumerate()
            .map(|(i, key)| {
                let mut b = template.clone();
                b["key"] = json!(key);
                b["doc_count"] = json!(i + 1);
                b
            })
            .collect::<Vec<_>>()
    );
    body["aggregations"]["status"]["sum_other_doc_count"] = json!(9);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
        .mount(&s)
        .await;
    let a = alert_activity(&t, "r1", "24h", 5).await.unwrap();
    assert_eq!(a.total, body["hits"]["total"]["value"].as_u64().unwrap());
    assert!(a.recent.len() <= 5);
    let mut expected = [0u64; 4];
    for b in body["aggregations"]["status"]["buckets"]
        .as_array()
        .unwrap()
    {
        let i = match b["key"].as_str().unwrap() {
            "open" => 0,
            "acknowledged" => 1,
            "closed" => 2,
            _ => 3,
        };
        expected[i] += b["doc_count"].as_u64().unwrap();
    }
    expected[3] += body["aggregations"]["status"]["sum_other_doc_count"]
        .as_u64()
        .unwrap();
    assert_eq!([a.open, a.acknowledged, a.closed, a.other], expected);
    for replacement in [json!("gte"), json!(null), json!("bad_count")] {
        s.reset().await;
        let mut bad = body.clone();
        if replacement.is_null() {
            bad.as_object_mut().unwrap().remove("aggregations");
        } else if replacement == "bad_count" {
            bad["aggregations"]["status"]["buckets"][0]["doc_count"] = json!("1");
        } else {
            bad["hits"]["total"]["relation"] = replacement;
        }
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(bad))
            .mount(&s)
            .await;
        assert_eq!(
            alert_activity(&t, "r1", "24h", 0).await.unwrap_err().kind,
            ErrorKind::Http
        );
    }
}
async fn status(s: &MockServer, version: &str) {
    let mut body = fixture("status.json");
    body["version"]["number"] = json!(version);
    Mock::given(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(s)
        .await;
}
#[tokio::test]
async fn bounded_policies() {
    use elasticctl_api::fleet::integration_policy_ops::list_first_page;
    for (count, total, wrong, duplicate) in [
        (3, 3, false, false),
        (1000, 1001, false, false),
        (3, 3, true, false),
        (3, 3, false, true),
    ] {
        let s = MockServer::start().await;
        status(&s, "9.5.1").await;
        let t = transport(&s);
        let mut body = fixture("integration_policies_list.json");
        let row = body["items"][0].clone();
        body["items"] = json!(
            (0..count)
                .map(|i| {
                    let mut r = row.clone();
                    r["id"] = json!(if duplicate { 0 } else { i }.to_string());
                    r
                })
                .collect::<Vec<_>>()
        );
        body["total"] = json!(total);
        body["page"] = json!(if wrong { 2 } else { 1 });
        body["perPage"] = json!(1000);
        Mock::given(path("/api/fleet/package_policies"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&s)
            .await;
        let result = list_first_page(&t).await;
        if wrong || duplicate {
            assert_eq!(result.unwrap_err().kind, ErrorKind::Http);
        } else if total > count {
            assert!(result.unwrap().is_none());
        } else {
            assert_eq!(result.unwrap().unwrap().len(), count);
        }
        assert_eq!(
            s.received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path() == "/api/fleet/package_policies")
                .count(),
            1
        );
    }
    let s = MockServer::start().await;
    status(&s, "9.4.0").await;
    assert_eq!(
        list_first_page(&transport(&s)).await.unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert_eq!(s.received_requests().await.unwrap().len(), 1);
}
#[tokio::test]
async fn exception_bounds_and_order() {
    let s = MockServer::start().await;
    status(&s, "9.5.1").await;
    let t = transport(&s);
    let mut body = fixture("rules_get.json");
    body["exceptions_list"] = json!([]);
    let r = elasticctl_api::Rule::from_value(body.clone()).unwrap();
    assert_eq!(exception_coverage(&t, &r).await.unwrap().referenced, 0);
    assert!(s.received_requests().await.unwrap().is_empty());
    let list = fixture("exception_list_get.json");
    let items = fixture("exception_list_items_find.json");
    Mock::given(path("/api/exception_lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(list))
        .mount(&s)
        .await;
    Mock::given(path("/api/exception_lists/items/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(items.clone()))
        .mount(&s)
        .await;
    let namespace = |i: usize| {
        if i.is_multiple_of(2) {
            "single"
        } else {
            "agnostic"
        }
    };
    body["exceptions_list"]=json!((0..6).map(|i|json!({"list_id":format!("list-{i}"),"namespace_type":namespace(i),"type":"detection"})).collect::<Vec<_>>());
    let r = elasticctl_api::Rule::from_value(body).unwrap();
    let c = exception_coverage(&t, &r).await.unwrap();
    assert_eq!(c.referenced, 6);
    assert!(c.truncated);
    assert_eq!(c.lists.len(), 5);
    for (i, row) in c.lists.into_iter().enumerate() {
        assert_eq!(row.key.list_id, format!("list-{i}"));
        assert_eq!(row.key.namespace_type, namespace(i));
        assert_eq!(
            row.facts.unwrap().item_count,
            items["total"].as_u64().unwrap()
        );
    }
    let req = s.received_requests().await.unwrap();
    let req = req
        .iter()
        .filter(|r| r.url.path() != "/api/status")
        .collect::<Vec<_>>();
    assert_eq!(req.len(), 10);
    for (i, pair) in req.chunks(2).enumerate() {
        assert_eq!(pair[0].url.path(), "/api/exception_lists");
        assert_eq!(pair[1].url.path(), "/api/exception_lists/items/_find");
        for request in pair {
            let q = request
                .url
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(q["list_id"], format!("list-{i}"));
            assert_eq!(q["namespace_type"], namespace(i));
        }
        let q = pair[1]
            .url
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(q["page"], "1");
        assert_eq!(q["per_page"], "1");
    }
}
#[tokio::test]
async fn exception_failures() {
    for (code, kind, count_failure) in [
        (404, ErrorKind::NotFound, false),
        (401, ErrorKind::Auth, false),
        (401, ErrorKind::Auth, true),
    ] {
        let s = MockServer::start().await;
        status(&s, "9.5.1").await;
        let t = transport(&s);
        let mut body = fixture("rules_get.json");
        body["exceptions_list"] =
            json!([{"list_id":"missing","namespace_type":"single","type":"detection"}]);
        Mock::given(path("/api/exception_lists"))
            .respond_with(
                ResponseTemplate::new(if count_failure { 200 } else { code }).set_body_json(
                    fixture(if count_failure {
                        "exception_list_get.json"
                    } else {
                        "case_conflict.json"
                    }),
                ),
            )
            .mount(&s)
            .await;
        if count_failure {
            Mock::given(path("/api/exception_lists/items/_find"))
                .respond_with(
                    ResponseTemplate::new(401).set_body_json(fixture("case_conflict.json")),
                )
                .mount(&s)
                .await;
        }
        let result = exception_coverage(&t, &elasticctl_api::Rule::from_value(body).unwrap()).await;
        if code == 401 {
            assert_eq!(result.unwrap_err().kind, kind);
        } else {
            assert_eq!(
                result.unwrap().lists.pop().unwrap().facts.unwrap_err().kind,
                kind
            );
        }
        assert_eq!(
            s.received_requests()
                .await
                .unwrap()
                .iter()
                .filter(|r| r.url.path().ends_with("/_find"))
                .count(),
            usize::from(count_failure)
        );
    }
}
#[tokio::test]
async fn recorded_cases_and_malformed_rows() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let body = fixture("cases_by_alert.json");
    for variant in 0..4 {
        s.reset().await;
        let mut b = body.clone();
        match variant {
            1 => b[0]
                .as_object_mut()
                .unwrap()
                .remove("id")
                .map(|_| ())
                .unwrap(),
            2 => b[0]["id"] = json!(".."),
            3 => b[0]["title"] = json!(3),
            _ => (),
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(b))
            .mount(&s)
            .await;
        let result = cases::by_alert(&t, "a1").await;
        if variant == 0 {
            assert_eq!(result.unwrap().len(), body.as_array().unwrap().len());
        } else {
            assert_eq!(result.unwrap_err().kind, ErrorKind::Http);
        }
    }
}
#[tokio::test]
async fn recorded_no_cases() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("cases_by_alert_none.json")))
        .mount(&s)
        .await;
    assert!(
        cases::by_alert(&transport(&s), "a1")
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn cases_decoding_variants_from_recorded_find() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let body = fixture("cases_find.json")["cases"].clone();
    assert!(!body.as_array().unwrap().is_empty());
    for variant in 0..5 {
        s.reset().await;
        let mut b = body.clone();
        match variant {
            1 => {
                b[0].as_object_mut().unwrap().remove("id");
            }
            2 => b[0]["id"] = json!(".."),
            3 => b[0]["id"] = json!(""),
            4 => b[0]["title"] = json!(5),
            _ => (),
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(b))
            .mount(&s)
            .await;
        let result = cases::by_alert(&t, "a1").await;
        if variant == 0 {
            assert_eq!(result.unwrap().len(), body.as_array().unwrap().len());
        } else {
            assert_eq!(result.unwrap_err().kind, ErrorKind::Http);
        }
    }
}

#[tokio::test]
async fn recorded_failed_execution() {
    let s = MockServer::start().await;
    let t = transport(&s);
    let body = fixture("rule_get_failed_execution.json");
    let id = body["rule_id"].as_str().unwrap().to_owned();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&s)
        .await;
    assert_eq!(
        snapshot_by_id(&t, &id)
            .await
            .unwrap()
            .execution
            .unwrap()
            .status,
        // A rule over a missing index reports a partial failure, not a
        // failure (tasks design section 11.2, M4).
        "partial failure"
    );
}
