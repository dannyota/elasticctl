use super::conformance::{checked, fixture, setup, spawn};
use super::*;

async fn mount(server: &MockServer, verb: &str, route: &str, body: Value) {
    Mock::given(method(verb))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn exercise(kind: &str, protocol: McpProtocolPath, variant: &str) {
    let (server, _dir, config) = setup().await;
    let mut s = spawn(&config, protocol, true, true);
    let mut case = fixture("case_get");
    if kind == "cases_set_status" && variant == "open" {
        case["status"] = json!("closed");
    }
    let case_id = case["id"].as_str().unwrap();
    mount(
        &server,
        "GET",
        &format!("/api/cases/{case_id}"),
        case.clone(),
    )
    .await;
    let mut search = fixture("signals_search");
    search["hits"]["hits"].as_array_mut().unwrap().truncate(1);
    let alert = search["hits"]["hits"][0]["_id"]
        .as_str()
        .unwrap()
        .to_owned();
    mount(
        &server,
        "POST",
        "/api/detection_engine/signals/search",
        search,
    )
    .await;
    let token = "elasticctl-live-created";
    s.owned
        .extend([case_id.into(), alert.clone(), token.into()]);
    let (args, targets, operation, verb, route, mut response, created) = match kind {
        "alerts_set_status" => (
            json!({"alert_ids":[alert],"status":variant}),
            vec![alert.clone()],
            json!({"alert_ids":[alert],"status":variant,"reason":null}),
            "POST",
            "/api/detection_engine/signals/status".into(),
            fixture("signals_status_ids"),
            Value::Null,
        ),
        "alerts_set_tags" => {
            let args = if variant == "add" {
                json!({"alert_ids":[alert],"add":[LIVE_TAG],"remove":[]})
            } else {
                json!({"alert_ids":[alert],"add":[],"remove":[LIVE_TAG]})
            };
            (
                args.clone(),
                vec![alert.clone()],
                args,
                "POST",
                "/api/detection_engine/signals/tags".into(),
                fixture("signals_tags"),
                Value::Null,
            )
        }
        "cases_create" => {
            let args = json!({"title":token,"description":LIVE_TAG,"tags":[LIVE_TAG,token],"severity":"low"});
            let mut op = args.clone();
            op["sync_alerts"] = json!(false);
            (
                args,
                vec![],
                op,
                "POST",
                "/api/cases".into(),
                fixture("case_create"),
                json!({"case_id":case_id}),
            )
        }
        "cases_comment" => (
            json!({"id":case_id,"message":LIVE_TAG}),
            vec![case_id.into()],
            json!({"case_id":case_id,"message":LIVE_TAG}),
            "POST",
            format!("/api/cases/{case_id}/comments"),
            fixture("case_comment"),
            Value::Null,
        ),
        "cases_set_status" => (
            json!({"ids":[case_id],"status":variant}),
            vec![case_id.into()],
            json!({"status":variant,"updates":[{"id":case_id,"version":case["version"]}],"resolved":1}),
            "PATCH",
            "/api/cases".into(),
            fixture("case_update_status"),
            Value::Null,
        ),
        "rules_create" => {
            let body = rule_body(token, "elasticctl-live-index").unwrap();
            let args = json!({"rule":body});
            Mock::given(method("GET"))
                .and(path("/api/detection_engine/rules"))
                .and(query_param("rule_id", token))
                .respond_with(
                    ResponseTemplate::new(404)
                        .set_body_json(json!({"message":"absent","status_code":404})),
                )
                .mount(&server)
                .await;
            let mut response = fixture("rules_create");
            response["rule_id"] = json!(token);
            response["enabled"] = json!(false);
            (
                args.clone(),
                vec![token.into()],
                args,
                "POST",
                "/api/detection_engine/rules".into(),
                response,
                json!({"rule_id":token}),
            )
        }
        _ => unreachable!(),
    };
    if kind == "cases_set_status" {
        response[0]["status"] = json!(variant);
    }
    mount(&server, verb, &route, response).await;
    let owner = if targets.is_empty() {
        token
    } else {
        &targets[0]
    }
    .to_owned();
    let tool = format!("{kind}_plan");
    let version = case["version"].as_str().unwrap();
    let built = extension::change_view(&tool, &args, Some(version));
    assert_eq!(built, (targets, operation));
    let result = s.extension_change(&tool, args, &owner, Some(version));
    let result = checked(result, &s);
    assert_eq!(
        result["data"]["outcome"],
        json!({"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true,"created":created})
    );
    s.child.child.shutdown().unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.method != "GET" && !r.url.path().ends_with("/signals/search"))
            .count(),
        1,
        "{requests:?}"
    );
}

macro_rules! contract {
    ($name:ident, $kind:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            for protocol in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
                let variants: &[&str] = match $kind {
                    "alerts_set_status" => &["acknowledged", "open", "closed"],
                    "alerts_set_tags" => &["add", "remove"],
                    "cases_set_status" => &["closed", "open"],
                    _ => &[""],
                };
                for variant in variants {
                    exercise($kind, protocol, variant).await;
                }
            }
        }
    };
}
contract!(alert_status_frames, "alerts_set_status");
contract!(alert_tags_frames, "alerts_set_tags");
contract!(case_create_frames, "cases_create");
contract!(case_comment_frames, "cases_comment");
contract!(case_status_frames, "cases_set_status");
contract!(rule_create_frames, "rules_create");

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_alerts_refusal_frames() {
    for protocol in [McpProtocolPath::Current, McpProtocolPath::Legacy] {
        let (server, _dir, config) = setup().await;
        let mut case = fixture("case_get");
        case["settings"]["syncAlerts"] = json!(true);
        case["totalAlerts"] = json!(1);
        let id = case["id"].as_str().unwrap().to_owned();
        mount(&server, "GET", &format!("/api/cases/{id}"), case).await;
        let mut s = spawn(&config, protocol, true, true);
        let result = s.call(
            "cases_set_status_plan",
            json!({"ids":[id],"status":"closed"}),
        );
        let frame = checked(result, &s);
        let content = checked(frames::content(frame, protocol), &s);
        checked(frames::code(&content, "case_sync_alerts"), &s);
        assert!(content.get("data").is_none(), "{content}");
        assert!(s.plans.is_empty());
        s.child.child.shutdown().unwrap();
        assert!(
            server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|r| r.method == "GET")
        );
    }
}
