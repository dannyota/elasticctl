use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::recorder::cases::require_no_marker_cases;
use crate::recorder::compose::alert_search::{SearchError, open_session_alerts};
use crate::recorder::compose::requests::{
    PREBUILT_STATUS_PATH, item_path, list_path, marker_index_inventory, marker_list_inventory,
    marker_rule_inventory, rule_get,
};
use crate::recorder::compose::{COMPOSE_ITEM_ID, MISSING_INDEX, MISSING_RULE_ID};
use crate::recorder::markers::{ALERT_PROBE_INDEX, ALERT_RULE_ID, ITEM_ID};
use elasticctl_core::{ErrorKind, Transport};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Baseline {
    prebuilt_rules: u64,
    inventory: Inventory,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Inventory {
    rules: u64,
    lists: u64,
    indices: Option<u64>,
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
        Err(error) if error.http_status.is_none() && error.kind == ErrorKind::Error => {
            Err(stage.present("a marker case"))
        }
        Err(error) => Err(stage.read_failed(error)),
    }
}

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

async fn find_total(t: &Transport, path: &str, stage: Stage) -> elasticctl_core::Result<u64> {
    let page = t
        .get(path)
        .await
        .map_err(|error| stage.read_failed(error))?;
    page.get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| recording_error("a marker inventory page did not report total"))
}

fn resolved_names(body: &Value) -> Option<u64> {
    ["indices", "aliases", "data_streams"]
        .iter()
        .map(|key| body.get(*key).and_then(Value::as_array).map(Vec::len))
        .sum::<Option<usize>>()
        .map(|count| count as u64)
}

async fn inventory(t: &Transport, stage: Stage) -> elasticctl_core::Result<Inventory> {
    let rules = find_total(t, &marker_rule_inventory(), stage).await?;
    let lists = find_total(t, &marker_list_inventory(), stage).await?;
    let indices =
        if t.has_es_url() {
            let body = t
                .get_absolute_es(&marker_index_inventory())
                .await
                .map_err(|error| stage.read_failed(error))?;
            Some(resolved_names(&body).ok_or_else(|| {
                recording_error("the marker index inventory is not a resolve answer")
            })?)
        } else {
            None
        };
    Ok(Inventory {
        rules,
        lists,
        indices,
    })
}

pub(super) async fn capture(t: &Transport) -> elasticctl_core::Result<Baseline> {
    require_markers_absent(t, Stage::Preflight).await?;
    Ok(Baseline {
        prebuilt_rules: prebuilt_rules(t, Stage::Preflight).await?,
        inventory: inventory(t, Stage::Preflight).await?,
    })
}

pub(super) async fn audit(
    t: &Transport,
    baseline: &Baseline,
    rule_uuid: Option<&str>,
) -> elasticctl_core::Result<()> {
    require_markers_absent(t, Stage::Audit).await?;
    if prebuilt_rules(t, Stage::Audit).await? != baseline.prebuilt_rules {
        return Err(recording_error("the prebuilt rule count changed"));
    }
    let now = inventory(t, Stage::Audit).await?;
    for (changed, kind) in [
        (now.rules != baseline.inventory.rules, "rule"),
        (now.lists != baseline.inventory.lists, "exception list"),
        (now.indices != baseline.inventory.indices, "index"),
    ] {
        if changed {
            return Err(recording_error(format!(
                "the marker {kind} inventory changed"
            )));
        }
    }
    let Some(rule_uuid) = rule_uuid else {
        return Ok(());
    };
    match open_session_alerts(t, rule_uuid).await {
        Ok(open) if open.total == 0 => Ok(()),
        Ok(_) => Err(recording_error("open session alerts remain after cleanup")),
        Err(SearchError::Request(error)) => Err(Stage::Audit.read_failed(error)),
        Err(SearchError::Incomplete(reason)) => Err(recording_error(format!(
            "the search for the session alerts was incomplete: {reason}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ok(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    async fn mount_in_order(server: &MockServer, route: &str, answers: Vec<Value>) {
        let last = answers.len() - 1;
        for (n, body) in answers.into_iter().enumerate() {
            let mock = Mock::given(method("GET"))
                .and(path(route.to_string()))
                .respond_with(ok(body));
            let mock = if n < last {
                mock.up_to_n_times(1)
            } else {
                mock
            };
            mock.mount(server).await;
        }
    }

    async fn absent_stack(prebuilt: Vec<u64>, rules: Vec<u64>) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/cases/_find"))
            .respond_with(ok(
                json!({"cases": [], "total": 0, "page": 1, "per_page": 100}),
            ))
            .mount(&server)
            .await;
        mount_in_order(
            &server,
            PREBUILT_STATUS_PATH,
            prebuilt
                .into_iter()
                .map(|count| json!({"rules_installed": count}))
                .collect(),
        )
        .await;
        mount_in_order(
            &server,
            "/api/detection_engine/rules/_find",
            rules
                .into_iter()
                .map(|total| json!({"page": 1, "perPage": 1, "total": total, "data": []}))
                .collect(),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/api/exception_lists/_find"))
            .respond_with(ok(
                json!({"page": 1, "per_page": 1, "total": 1, "data": []}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/_resolve/index/%2Aelasticctl-sample%2A"))
            .respond_with(ok(
                json!({"indices": [], "aliases": [], "data_streams": []}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404})))
            .mount(&server)
            .await;
        server
    }

    async fn mount_alert_search(server: &MockServer, page: Value) {
        Mock::given(method("POST"))
            .and(path(elasticctl_api::alerts::SEARCH_PATH))
            .respond_with(ok(page))
            .mount(server)
            .await;
    }

    fn alert_page(timed_out: bool, total: u64, ids: &[&str]) -> Value {
        let hits: Vec<Value> = ids.iter().map(|id| json!({"_id": id})).collect();
        json!({"took": 1, "timed_out": timed_out,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits}})
    }

    #[tokio::test]
    async fn an_unchanged_target_passes_the_audit() {
        let server = absent_stack(vec![2263, 2263], vec![3, 3]).await;
        mount_alert_search(&server, alert_page(false, 0, &[])).await;
        let t = mock_transport(&server);
        let baseline = capture(&t).await.expect("baseline");
        audit(&t, &baseline, Some("so-1")).await.expect("audit");
    }

    #[tokio::test]
    async fn a_changed_prebuilt_count_fails_the_audit() {
        let server = absent_stack(vec![2263, 2262], vec![0, 0]).await;
        let t = mock_transport(&server);
        let baseline = capture(&t).await.expect("baseline");
        let error = audit(&t, &baseline, None).await.expect_err("mismatch");
        assert_eq!(error.message, "the prebuilt rule count changed");
    }

    #[tokio::test]
    async fn a_changed_marker_rule_inventory_fails_the_audit() {
        let server = absent_stack(vec![2263, 2263], vec![3, 4]).await;
        let t = mock_transport(&server);
        let baseline = capture(&t).await.expect("baseline");
        let error = audit(&t, &baseline, None).await.expect_err("changed");
        assert_eq!(error.message, "the marker rule inventory changed");
    }

    #[tokio::test]
    async fn an_open_or_unprovable_session_alert_fails_the_audit() {
        for (page, message) in [
            (
                alert_page(false, 1, &["a1"]),
                "open session alerts remain after cleanup",
            ),
            (
                alert_page(true, 0, &[]),
                "the search for the session alerts was incomplete: it timed out",
            ),
        ] {
            let server = absent_stack(vec![2263, 2263], vec![0, 0]).await;
            mount_alert_search(&server, page).await;
            let t = mock_transport(&server);
            let baseline = capture(&t).await.expect("baseline");
            let error = audit(&t, &baseline, Some("so-1"))
                .await
                .expect_err("alerts");
            assert_eq!(error.message, message);
        }
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
        let baseline = Baseline {
            prebuilt_rules: 1,
            inventory: Inventory {
                rules: 0,
                lists: 0,
                indices: Some(0),
            },
        };
        let error = audit(&t, &baseline, None).await.expect_err("present");
        assert_eq!(
            error.message,
            "index elasticctl-sample-compose-missing is present after cleanup"
        );
    }
}
