use super::*;

#[derive(Clone, Copy)]
enum Fault {
    Body,
    Cleanup,
    InitialBaseline,
    FinalBaseline,
    None,
}

fn exercise(fault: Fault) {
    let rt = runtime().unwrap();
    let server = rt.block_on(MockServer::start());
    rt.block_on(async {
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"total":0})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
    });
    let profile: Profile =
        serde_json::from_value(json!({"kibana_url":server.uri(),"api_key":"offline"})).unwrap();
    let transport = Transport::new(&profile).unwrap();
    let cleanup = cleanup_transport(&profile).unwrap();
    let mut registry = Registry::default();
    let mut baselines = 0;
    run_classified(|started| {
        orchestrate(
            &rt,
            &transport,
            &cleanup,
            &mut registry,
            || {
                baselines += 1;
                if matches!(fault, Fault::InitialBaseline) && baselines == 1
                    || matches!(fault, Fault::FinalBaseline) && baselines == 2
                {
                    Err("baseline fault".into())
                } else {
                    Ok(())
                }
            },
            |registry| {
                started.set(true);
                if matches!(fault, Fault::Cleanup) {
                    registry.rules.insert("elasticctl-live-owned-token".into());
                }
                if matches!(fault, Fault::Body) {
                    Err("body fault".into())
                } else {
                    Ok(())
                }
            },
        )
    });
}

fn assert_failure(fault: Fault, class: &str, detail: &str) {
    let payload = std::panic::catch_unwind(|| exercise(fault)).unwrap_err();
    let text = panic_payload_text(payload);
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(
        lines,
        [
            format!("elasticctl-conformance-class:{class}"),
            detail.into()
        ]
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("elasticctl-conformance-class:"))
            .count(),
        1
    );
}

#[test]
fn body_failure_is_contract() {
    assert_failure(Fault::Body, "contract", "contract");
}
#[test]
fn cleanup_failure_is_cleanup() {
    assert_failure(Fault::Cleanup, "cleanup", "cleanup_failed");
}
#[test]
fn initial_baseline_failure_is_harness() {
    assert_failure(Fault::InitialBaseline, "harness", "baseline_failed");
}
#[test]
fn final_baseline_failure_is_cleanup() {
    assert_failure(Fault::FinalBaseline, "cleanup", "baseline_failed");
}
#[test]
fn successful_run_does_not_panic() {
    exercise(Fault::None);
}
#[test]
fn live_contract_uses_classification() {
    let source = include_str!("../mcp_mutations.rs");
    let body = source
        .split("pub(super) fn run_contract() {")
        .nth(1)
        .unwrap()
        .split("\npub(super) fn run_measurements()")
        .next()
        .unwrap();
    assert!(body.contains("run_classified(|started| live_run(false, started));"));
}
