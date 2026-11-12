use super::tests::FakeChild;
use super::*;

fn failure_line(class: &str, started: bool) -> String {
    let mut child = FakeChild::default();
    let failure = child.receive().map(|_| ()).map_err(|_| class.to_string());
    let payload = std::panic::catch_unwind(|| finish_contract(failure, started)).unwrap_err();
    panic_payload_text(payload)
        .lines()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn fake_child_contract_failure_has_class_line() {
    assert_eq!(
        failure_line("contract", true),
        "elasticctl-conformance-class:contract"
    );
}

#[test]
fn fake_child_cleanup_failure_has_class_line() {
    assert_eq!(
        failure_line("cleanup_failed", true),
        "elasticctl-conformance-class:cleanup"
    );
}

#[test]
fn fake_child_initial_baseline_failure_has_harness_line() {
    assert_eq!(
        failure_line("baseline_failed", false),
        "elasticctl-conformance-class:harness"
    );
}

#[test]
fn fake_child_final_baseline_failure_has_cleanup_line() {
    assert_eq!(
        failure_line("baseline_failed", true),
        "elasticctl-conformance-class:cleanup"
    );
}
