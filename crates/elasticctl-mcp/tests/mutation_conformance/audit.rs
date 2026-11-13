use super::*;

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn flow(scenario: &str) {
    let before = unix_seconds();
    let (s, mut h) = if scenario == "expired" {
        let s = stack().await;
        let h = Harness::start_with_plan_life(target(&s), options(), Some(Duration::from_secs(1)));
        (s, h)
    } else {
        setup().await
    };
    let p = plan(&mut h).await;
    let received_plan = tokio::time::Instant::now();
    let id = &p["plan_id"];
    let mut expected = vec![("plan_created", json!({"targets":["r"]}))];
    match scenario {
        "expired" => {
            tokio::time::timeout(Duration::from_secs(2), async {
                while received_plan.elapsed() < Duration::from_secs(1) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("plan life passes within the wait bound");
            let r = call(&mut h, "plan_apply", json!({"plan_id":id})).await;
            assert_eq!(code(&r), "plan_expired", "{r}");
            expected.push(("plan_closed", json!({"state":"expired"})));
        }
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
    let lines = sink.lock().unwrap().clone();
    let base = base(&p, &s, "rules_set_enabled", "rules-toggle");
    assert_lines(scenario, &lines, base, expected, before..=unix_seconds());
    if matches!(scenario, "stale" | "discarded" | "expired") {
        assert_writes(&s, 0).await;
    }
}
#[tokio::test]
async fn expired_audit_is_exact() {
    flow("expired").await;
}
fn base(p: &Value, s: &MockServer, kind: &str, class: &str) -> Value {
    json!({"plan_id":p["plan_id"],"hash":p["hash"],"kind":kind,"class":class,"profile":"test",
        "host":s.address().to_string(),"space":"default","credential":p["credential"],"protocol":"2026-07-28"})
}
fn assert_lines(
    label: &str,
    lines: &[String],
    base: Value,
    expected: Vec<(&str, Value)>,
    window: std::ops::RangeInclusive<u64>,
) {
    assert_eq!(lines.len(), expected.len(), "{label}: {lines:?}");
    assert!(!window.contains(&1));
    assert!(!window.contains(&(window.start() * 1000)));
    for (line, (event, extra)) in lines.iter().zip(expected) {
        let value: Value = serde_json::from_str(line).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 1);
        let a = &value["audit"];
        assert!(
            window.contains(&a["ts"].as_u64().unwrap()),
            "{label}: {line}"
        );
        let mut exact = base.clone();
        exact["ts"] = a["ts"].clone();
        exact["event"] = json!(event);
        for (k, v) in extra.as_object().unwrap() {
            exact[k] = v.clone();
        }
        assert_eq!(a, &exact, "{label}: {line}");
    }
}
#[tokio::test]
async fn accept_failed_unknown_audit_is_exact() {
    for scenario in ["accept", "failed", "unknown"] {
        flow(scenario).await;
    }
}
#[tokio::test]
async fn decline_dismiss_audit_is_exact() {
    for scenario in ["decline", "dismiss"] {
        flow(scenario).await;
    }
}
#[tokio::test]
async fn stale_discarded_audit_is_exact() {
    for scenario in ["stale", "discarded"] {
        flow(scenario).await;
    }
}
#[tokio::test]
async fn write_conflict_stale_audit_is_exact() {
    let before = unix_seconds();
    let (s, mut h) = setup().await;
    let r = call(
        &mut h,
        "rules_create_plan",
        json!({"rule":{"rule_id":"new-rule","name":"New rule","type":"query","query":"event.kind: event"}}),
    )
    .await;
    let p = data(&r)["plan"].clone();
    assert_eq!(p["state"], "open", "{r}");
    let id = &p["plan_id"];
    let q = question(&mut h, id).await;
    Mock::given(method("POST"))
        .and(path("/api/detection_engine/rules"))
        .respond_with(
            ResponseTemplate::new(409).set_body_json(json!({"status_code":409,"message":"exists"})),
        )
        .expect(1)
        .mount(&s)
        .await;
    send(&mut h, 2, answer(id, &q, accept())).await;
    let r = receive(&mut h).await;
    assert_eq!(code(&r), "plan_stale", "{r}");
    let sink = h.audit.clone();
    finish(h).await;
    let lines = sink.lock().unwrap().clone();
    let expected = vec![
        ("plan_created", json!({"targets":["new-rule"]})),
        ("confirmation_requested", json!({"prompt":1})),
        ("confirmation_answered", json!({"result":"confirmed"})),
        ("apply_started", json!({})),
        (
            "apply_finished",
            json!({"state":"stale","outcome":null,"http_status":409}),
        ),
        ("plan_closed", json!({"state":"stale"})),
    ];
    let base = base(&p, &s, "rules_create", "rules-create");
    assert_lines(
        "write conflict",
        &lines,
        base,
        expected,
        before..=unix_seconds(),
    );
    let writes: Vec<_> = s
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method != "GET")
        .collect();
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0].url.path(), "/api/detection_engine/rules");
}
