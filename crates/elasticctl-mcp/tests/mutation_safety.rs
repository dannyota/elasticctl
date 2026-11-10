#[path = "mutation_confirm_current.rs"]
mod common;
use serde_json::json;
#[tokio::test]
async fn argument_confirmation_is_rejected_without_requests() {
    let (s, mut h) = common::setup().await;
    for key in ["confirm", "yes", "apply", "inputResponses", "requestState"] {
        let mut args = json!({"plan_id":"pln_invalid"});
        args[key] = json!(true);
        let r = common::call(&mut h, "plan_apply", args, json!({})).await;
        assert_eq!(
            r["result"]["structuredContent"]["error"]["code"], "invalid_argument",
            "{r}"
        );
    }
    assert!(s.received_requests().await.unwrap().is_empty());
    h.close_input();
    h.join().await.unwrap();
}
#[tokio::test]
async fn full_flow_has_one_write_and_five_safe_audit_events() {
    let (s, mut h) = common::setup().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200)
                .set_body_json(common::fixture("rules_bulk_disable")),
        )
        .mount(&s)
        .await;
    let id = common::plan(&mut h).await;
    let q = common::question(&mut h, &id).await;
    let r=common::call(&mut h,"plan_apply",json!({"plan_id":id}),json!({"requestState":q["requestState"],"inputResponses":{"confirm":{"action":"accept","content":{"apply":true,"extra":"ignored"}}}})).await;
    assert_eq!(
        r["result"]["structuredContent"]["data"]["outcome"]["complete"],
        true
    );
    let requests = s.received_requests().await.unwrap();
    let writes: Vec<_> = requests.iter().filter(|r| r.method != "GET").collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].method, "POST");
    assert_eq!(
        writes[0].url.path(),
        "/api/detection_engine/rules/_bulk_action"
    );
    let lines = h.audit.lock().unwrap().clone();
    assert_eq!(
        lines
            .iter()
            .map(|v| v["audit"]["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "plan_created",
            "confirmation_requested",
            "confirmation_answered",
            "apply_started",
            "apply_finished"
        ]
    );
    for line in lines {
        assert!(!line.to_string().contains("name-sentinel"));
        for key in ["action", "details", "name"] {
            assert!(line["audit"].get(key).is_none());
        }
    }
    h.close_input();
    h.join().await.unwrap();
}
