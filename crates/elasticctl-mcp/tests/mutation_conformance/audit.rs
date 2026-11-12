//! End-to-end expiry delivery is not covered: `src/server/runtime.rs:158-170`
//! runs each session on a separate thread with a fresh runtime, beyond the test runtime's paused clock.
//! `src/plan/store.rs` and `src/plan/audit.rs` cover expiry and its line format at unit level.
use super::*;

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn flow(scenario: &str) {
    let before = unix_seconds();
    let (s, mut h) = setup().await;
    let p = plan(&mut h).await;
    let id = &p["plan_id"];
    let mut expected = vec![("plan_created", json!({"targets":["r"]}))];
    match scenario {
        "discarded" => {
            let r = call(&mut h, "plan_discard", json!({"plan_id":id})).await;
            assert_eq!(data(&r)["plan"]["state"], "discarded");
            expected.push(("plan_closed", json!({"state":"discarded"})));
        }
        "stale" => {
            let mut rule = fixture("rules_get");
            rule["rule_id"] = json!("r");
            rule["name"] = json!("changed");
            Mock::given(method("GET"))
                .and(path("/api/detection_engine/rules"))
                .respond_with(ResponseTemplate::new(200).set_body_json(rule))
                .with_priority(1)
                .mount(&s)
                .await;
            let r = call(&mut h, "plan_apply", json!({"plan_id":id})).await;
            assert_eq!(code(&r), "plan_stale");
            expected.push(("plan_closed", json!({"state":"stale"})));
        }
        _ => {
            let q = question(&mut h, id).await;
            expected.push(("confirmation_requested", json!({"prompt":1})));
            let response = match scenario {
                "decline" => json!({"action":"decline"}),
                "dismiss" => json!({"action":"cancel"}),
                _ => accept(),
            };
            let writes = !matches!(scenario, "decline" | "dismiss");
            let status = match scenario {
                "failed" => 403,
                "unknown" => 503,
                _ => 200,
            };
            write_mock(&s, u64::from(writes), status).await;
            send(&mut h, 2, answer(id, &q, response)).await;
            let r = receive(&mut h).await;
            expected.push((
                "confirmation_answered",
                json!({"result":match scenario {
                    "decline" => "declined", "dismiss" => "not_confirmed", _ => "confirmed"
                }}),
            ));
            match scenario {
                "decline" => {
                    assert_eq!(code(&r), "plan_declined");
                    expected.push(("plan_closed", json!({"state":"declined"})));
                }
                "dismiss" => assert_eq!(code(&r), "not_confirmed"),
                _ => {
                    expected.push(("apply_started", json!({})));
                    let state = match scenario {
                        "failed" => "failed",
                        "unknown" => "unknown",
                        _ => "applied",
                    };
                    let outcome = if scenario == "accept" {
                        json!({"requested":1,"updated":1,"unchanged":0,"failed":0,"complete":true})
                    } else {
                        Value::Null
                    };
                    expected.push(("apply_finished", json!({"state":state,"outcome":outcome,"http_status":if status==200 {Value::Null} else {json!(status)}})));
                    if scenario == "accept" {
                        assert_eq!(data(&r)["plan"]["state"], "applied", "{r}");
                    } else {
                        assert!(content(&r)["error"].is_object(), "{r}");
                    }
                }
            }
            assert_writes(&s, usize::from(writes)).await;
        }
    }
    let sink = h.audit.clone();
    finish(h).await;
    let after = unix_seconds();
    let lines = sink.lock().unwrap().clone();
    assert_eq!(lines.len(), expected.len(), "{scenario}: {lines:?}");
    for (line, (event, extra)) in lines.iter().zip(expected) {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
        let a = &value["audit"];
        let mut exact = json!({"ts":a["ts"],"event":event,"plan_id":id,"hash":p["hash"],
            "kind":"rules_set_enabled","class":"rules-toggle","profile":"test",
            "host":s.address().to_string(),"space":"default","credential":p["credential"],"protocol":"2026-07-28"});
        let window = before..=after;
        assert!(
            window.contains(&a["ts"].as_u64().unwrap()),
            "{scenario}: {line}"
        );
        assert!(!window.contains(&1));
        assert!(!window.contains(&(before * 1000)));
        for (k, v) in extra.as_object().unwrap() {
            exact[k] = v.clone();
        }
        assert_eq!(a, &exact, "{scenario}: {line}");
    }
    if matches!(scenario, "stale" | "discarded") {
        assert_writes(&s, 0).await;
    }
}
/// Extends mutation_apply::accepted_write_and_replay and write_status_classification_and_malformed_success:
/// the complete accept, failed and unknown audit sequences contain exactly the allowed fields.
#[tokio::test]
async fn accept_failed_unknown_audit_is_exact() {
    for scenario in ["accept", "failed", "unknown"] {
        flow(scenario).await;
    }
}
/// Extends mutation_confirm_current::decline_closes_and_protocol_errors_stay_static
/// and current_question_and_answers with complete decline and dismiss audit sequences.
#[tokio::test]
async fn decline_dismiss_audit_is_exact() {
    for scenario in ["decline", "dismiss"] {
        flow(scenario).await;
    }
}
/// Extends mutation_apply::drift_and_identity_alias_at_both_checks with exact stale and discarded audit sequences through the router.
#[tokio::test]
async fn stale_discarded_audit_is_exact() {
    for scenario in ["stale", "discarded"] {
        flow(scenario).await;
    }
}
