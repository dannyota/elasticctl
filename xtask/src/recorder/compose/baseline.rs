//! What the target holds before the first write, and the audit that
//! requires the same after cleanup.
//!
//! The same marker identity reads serve the preflight and the audit, so a
//! check cannot be added to one and forgotten in the other.

use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::recorder::cases::require_no_marker_cases;
use crate::recorder::compose::requests::{PREBUILT_STATUS_PATH, item_path, list_path, rule_get};
use crate::recorder::compose::{COMPOSE_ITEM_ID, MISSING_INDEX, MISSING_RULE_ID};
use crate::recorder::markers::{ALERT_PROBE_INDEX, ALERT_RULE_ID, ITEM_ID};
use elasticctl_core::{ErrorKind, Transport};
use serde_json::Value;

/// The state the audit compares against.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Baseline {
    prebuilt_rules: u64,
}

#[derive(Clone, Copy)]
enum Stage {
    Preflight,
    Audit,
}

impl Stage {
    fn present(self, object: &'static str) -> elasticctl_core::Error {
        recording_error(match self {
            Stage::Preflight => {
                format!("refusing to record: {object} already exists and is not cleanup-owned")
            }
            Stage::Audit => format!("{object} is present after cleanup"),
        })
    }

    fn read_failed(self, error: elasticctl_core::Error) -> elasticctl_core::Error {
        safe_recording_transport_error(
            match self {
                Stage::Preflight => "compose preflight read failed",
                Stage::Audit => "baseline audit read failed",
            },
            error,
        )
    }
}

/// Every fixed identity the step writes, with the read that proves it
/// absent. Elasticsearch reads are marked.
fn marker_identities() -> [(&'static str, String, bool); 7] {
    [
        (
            "rule elasticctl-sample-alert-probe",
            rule_get(ALERT_RULE_ID).target(),
            false,
        ),
        (
            "rule elasticctl-sample-compose-missing-index",
            rule_get(MISSING_RULE_ID).target(),
            false,
        ),
        ("the marker exception list", list_path(), false),
        ("exception item 1", item_path(ITEM_ID), false),
        ("exception item 2", item_path(COMPOSE_ITEM_ID), false),
        (
            "index elasticctl-sample-alert-events",
            format!("/{ALERT_PROBE_INDEX}"),
            true,
        ),
        (
            "index elasticctl-sample-compose-missing",
            format!("/{MISSING_INDEX}"),
            true,
        ),
    ]
}

async fn require_markers_absent(t: &Transport, stage: Stage) -> elasticctl_core::Result<()> {
    for (object, path, elasticsearch) in marker_identities() {
        let read = if elasticsearch {
            t.get_absolute_es(&path).await
        } else {
            t.get(&path).await
        };
        match read {
            Ok(_) => return Err(stage.present(object)),
            Err(error) if error.kind == ErrorKind::NotFound => {}
            Err(error) => return Err(stage.read_failed(error)),
        }
    }
    match require_no_marker_cases(t).await {
        Ok(()) => Ok(()),
        // The shared refusal carries no server text, but it names its own
        // remediation; keep only the static fact here.
        Err(error) if error.http_status.is_none() && error.kind == ErrorKind::Error => {
            Err(stage.present("a marker case"))
        }
        Err(error) => Err(stage.read_failed(error)),
    }
}

/// Installed prebuilt rules, from the prebuilt status route. The body holds
/// counters only, never rule content.
async fn prebuilt_rules(t: &Transport, stage: Stage) -> elasticctl_core::Result<u64> {
    let status = t
        .get(PREBUILT_STATUS_PATH)
        .await
        .map_err(|error| stage.read_failed(error))?;
    status
        .get("rules_installed")
        .and_then(Value::as_u64)
        .ok_or_else(|| recording_error("prebuilt status did not report rules_installed"))
}

/// Prove every marker identity is absent, then capture the prebuilt count.
pub(super) async fn capture(t: &Transport) -> elasticctl_core::Result<Baseline> {
    require_markers_absent(t, Stage::Preflight).await?;
    Ok(Baseline {
        prebuilt_rules: prebuilt_rules(t, Stage::Preflight).await?,
    })
}

/// Require the captured state again: no marker identity and the same
/// prebuilt count.
pub(super) async fn audit(t: &Transport, baseline: &Baseline) -> elasticctl_core::Result<()> {
    require_markers_absent(t, Stage::Audit).await?;
    if prebuilt_rules(t, Stage::Audit).await? != baseline.prebuilt_rules {
        return Err(recording_error("the prebuilt rule count changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn absent_stack(prebuilt: Vec<u64>) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/cases/_find"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"cases": [], "total": 0, "page": 1, "per_page": 100})),
            )
            .mount(&server)
            .await;
        for count in prebuilt {
            Mock::given(method("GET"))
                .and(path(PREBUILT_STATUS_PATH))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"rules_installed": count})),
                )
                .up_to_n_times(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn an_unchanged_target_passes_the_audit() {
        let server = absent_stack(vec![2263, 2263]).await;
        let t = mock_transport(&server);
        let baseline = capture(&t).await.expect("baseline");
        audit(&t, &baseline).await.expect("audit");
    }

    #[tokio::test]
    async fn a_changed_prebuilt_count_fails_the_audit() {
        let server = absent_stack(vec![2263, 2262]).await;
        let t = mock_transport(&server);
        let baseline = capture(&t).await.expect("baseline");
        let error = audit(&t, &baseline).await.expect_err("mismatch");
        assert_eq!(error.message, "the prebuilt rule count changed");
    }

    #[tokio::test]
    async fn a_marker_left_behind_fails_the_audit_with_a_static_message() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{MISSING_INDEX}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"private": "x"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let baseline = Baseline { prebuilt_rules: 1 };
        let error = audit(&t, &baseline).await.expect_err("present");
        assert_eq!(
            error.message,
            "index elasticctl-sample-compose-missing is present after cleanup"
        );
    }
}
