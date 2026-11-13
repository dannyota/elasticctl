use super::*;

fn emitted(
    initial: Result<(), ()>,
    body: StepResult,
    cleanup: Result<(), ()>,
    baseline: Result<(), ()>,
    expected: &str,
) {
    let payload =
        std::panic::catch_unwind(|| run_classified(|| classify(initial, body, cleanup, baseline)))
            .unwrap_err();
    let text = panic_payload_text(payload);
    assert_eq!(text.lines().next(), Some(expected));
}

#[test]
fn contract_failure_emits_contract_line() {
    emitted(
        Ok(()),
        Err(StepError::NotWired(3)),
        Ok(()),
        Ok(()),
        "elasticctl-conformance-class:contract",
    );
}
#[test]
fn cleanup_failure_emits_cleanup_line() {
    emitted(
        Ok(()),
        Err(StepError::Failed),
        Err(()),
        Err(()),
        "elasticctl-conformance-class:cleanup",
    );
}
#[test]
fn initial_baseline_failure_emits_harness_line() {
    emitted(
        Err(()),
        Err(StepError::Failed),
        Ok(()),
        Ok(()),
        "elasticctl-conformance-class:harness",
    );
}
#[test]
fn final_baseline_failure_emits_cleanup_line() {
    emitted(
        Ok(()),
        Ok(()),
        Ok(()),
        Err(()),
        "elasticctl-conformance-class:cleanup",
    );
}
