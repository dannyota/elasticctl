//! Marker objects for the compose recording and their cleanup.
//!
//! Every object is claimed in `CleanupOwnership` before the request that
//! creates it, so a lost create response still leaves it cleanup-owned.
//! Session cleanup re-reads each object and deletes it only when its marker
//! fields still match.

use crate::clock::now_rfc3339;
use crate::diagnostics::{
    recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::recorder::cases::require_no_marker_cases;
use crate::recorder::compose::requests::{RULES_PATH, package_status, rule_get};
use crate::recorder::compose::{
    ALERT_DOCS, COMPOSE_ITEM_ID, COMPOSE_RULE_NAME, MISSING_INDEX, MISSING_RULE_ID,
    MISSING_RULE_NAME, PACKAGE_CANDIDATES,
};
use crate::recorder::markers::{
    ALERT_MARKER_TAG, ALERT_PROBE_INDEX, ALERT_RULE_ID, CASE_TAG, CASE_TITLE, ITEM_ID, LIST_ID,
    MARKER_TAGS, NAMESPACE_TYPE,
};
use crate::recorder::ownership::{
    owns_alert_index, owns_alert_rule, owns_case, owns_item, owns_list, require_absent_alert_index,
    require_absent_alert_rule, require_absent_item, require_absent_list,
};
use crate::recorder::session::RecordingSession;
use elasticctl_core::{ErrorKind, Transport, urlencode};
use serde_json::{Value, json};

/// Server ids of the created marker objects. They stay in memory and only
/// ever reach a fixture as placeholders.
pub(super) struct Provisioned {
    pub(super) list_id: String,
    pub(super) rule_uuid: String,
    pub(super) missing_rule_uuid: String,
}

/// Tags on the marker list and items: the shared fixture tags the existing
/// ownership checks require, plus the sample marker.
fn list_tags() -> Vec<&'static str> {
    let mut tags = MARKER_TAGS.to_vec();
    tags.push(ALERT_MARKER_TAG);
    tags
}

fn has_sample_tag(value: &Value) -> bool {
    value
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter()
                .any(|tag| tag.as_str() == Some(ALERT_MARKER_TAG))
        })
}

pub(super) fn owns_missing_rule(value: &Value) -> bool {
    value.get("rule_id").and_then(Value::as_str) == Some(MISSING_RULE_ID) && has_sample_tag(value)
}

pub(super) fn owns_compose_item(value: &Value) -> bool {
    value.get("item_id").and_then(Value::as_str) == Some(COMPOSE_ITEM_ID)
        && value.get("list_id").and_then(Value::as_str) == Some(LIST_ID)
        && value
            .get("namespace_type")
            .and_then(Value::as_str)
            .unwrap_or("single")
            == NAMESPACE_TYPE
        && has_sample_tag(value)
}

fn item_path(item_id: &str) -> String {
    format!(
        "/api/exception_lists/items?item_id={}&namespace_type={NAMESPACE_TYPE}",
        urlencode(item_id)
    )
}

fn missing_rule_path() -> String {
    rule_get(MISSING_RULE_ID).target()
}

async fn require_not_found(
    t: &Transport,
    path: &str,
    elasticsearch: bool,
    label: &'static str,
) -> elasticctl_core::Result<()> {
    let read = if elasticsearch {
        t.get_absolute_es(path).await
    } else {
        t.get(path).await
    };
    match read {
        Ok(_) => Err(recording_error(format!(
            "refusing to record: {label} already exists and is not cleanup-owned"
        ))),
        Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(safe_recording_transport_error(
            "compose preflight read failed",
            error,
        )),
    }
}

fn preflight_error(error: elasticctl_core::Error) -> elasticctl_core::Error {
    // The shared preflights return their own static refusal or a raw
    // transport error. Keep a refusal; reduce a transport error to its class.
    if error.http_status.is_none()
        && error.kind == ErrorKind::Error
        && error.message.starts_with("refusing to record")
    {
        error
    } else {
        safe_recording_transport_error("compose preflight read failed", error)
    }
}

/// Prove every marker identity this step writes is absent before any write.
pub(super) async fn preflight(t: &Transport) -> elasticctl_core::Result<()> {
    require_absent_alert_rule(t)
        .await
        .map_err(preflight_error)?;
    require_absent_alert_index(t)
        .await
        .map_err(preflight_error)?;
    require_absent_list(t).await.map_err(preflight_error)?;
    require_absent_item(t).await.map_err(preflight_error)?;
    require_not_found(t, &item_path(COMPOSE_ITEM_ID), false, "exception item 2").await?;
    require_not_found(
        t,
        &missing_rule_path(),
        false,
        "the compose missing-index rule",
    )
    .await?;
    require_not_found(
        t,
        &format!("/{MISSING_INDEX}"),
        true,
        "the missing marker index",
    )
    .await?;
    require_no_marker_cases(t).await.map_err(preflight_error)
}

/// Read each candidate package and keep the first whose status is
/// `not_installed`. A candidate the registry does not know is skipped; no
/// package is ever installed or removed.
pub(super) async fn probe_not_installed_package(
    t: &Transport,
) -> elasticctl_core::Result<(&'static str, Value)> {
    for name in PACKAGE_CANDIDATES {
        let body = match t.get(&package_status(name).target()).await {
            Ok(body) => body,
            Err(error) if error.kind == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(safe_recording_transport_error(
                    "reading package status failed",
                    error,
                ));
            }
        };
        let item = &body["item"];
        if item["name"].as_str() == Some(name) && item["status"].as_str() == Some("not_installed") {
            return Ok((name, body));
        }
    }
    Err(recording_error(
        "refusing to record package_not_installed: none of apache, nginx, or mysql reports status not_installed",
    ))
}

fn create_error(
    context: &'static str,
) -> impl FnOnce(elasticctl_core::Error) -> elasticctl_core::Error {
    move |error| safe_recording_transport_error(context, error)
}

/// Index the marker documents and refresh. The index is claimed before the
/// first document write.
pub(super) async fn create_index(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<()> {
    let t = session.transport;
    session.ownership.alert_index = true;
    session.ownership.alert_index_claimed = true;
    for seq in 1..=ALERT_DOCS {
        let doc = json!({
            "@timestamp": now_rfc3339(),
            "marker": ALERT_MARKER_TAG,
            "message": format!("elasticctl sample compose event {seq}"),
        });
        t.post_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/{seq}"), &doc)
            .await
            .map_err(create_error("writing a marker document failed"))?;
    }
    let proof = t
        .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
        .await
        .map_err(create_error("reading a marker document failed"))?;
    if !owns_alert_index(&proof) {
        return Err(recording_error(
            "marker index write did not prove the fixed marker identity",
        ));
    }
    // `_refresh` rejects a body, so use the GET form, which sends none.
    t.get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_refresh"))
        .await
        .map_err(create_error("refreshing the marker index failed"))?;
    Ok(())
}

pub(super) fn list_body() -> Value {
    json!({
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": "elasticctl sample exceptions",
        "description": "Recorded by cargo xtask record-compose. Safe to delete.",
        "type": "detection",
        "tags": list_tags(),
    })
}

pub(super) fn item_body(item_id: &str, value: &str) -> Value {
    json!({
        "item_id": item_id,
        "list_id": LIST_ID,
        "namespace_type": NAMESPACE_TYPE,
        "name": format!("elasticctl sample exception item {value}"),
        "description": "Recorded by cargo xtask record-compose. Safe to delete.",
        "type": "simple",
        "entries": [{
            "field": "process.name",
            "operator": "included",
            "type": "match",
            "value": value,
        }],
        "tags": list_tags(),
    })
}

/// The marker rule over the marker index: a MITRE ATT&CK mapping, one
/// related integration, and a reference to the marker list.
pub(super) fn rule_body(list_server_id: &str) -> Value {
    json!({
        "rule_id": ALERT_RULE_ID,
        "name": COMPOSE_RULE_NAME,
        "description": "Recorded by cargo xtask record-compose. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "marker: elasticctl-sample",
        "index": [ALERT_PROBE_INDEX],
        "severity": "low",
        "risk_score": 21,
        "enabled": true,
        "from": "now-10m",
        "interval": "1m",
        "tags": [ALERT_MARKER_TAG],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": "TA0002",
                "name": "Execution",
                "reference": "https://attack.mitre.org/tactics/TA0002/"
            },
            "technique": [{
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "reference": "https://attack.mitre.org/techniques/T1059/",
                "subtechnique": [{
                    "id": "T1059.001",
                    "name": "PowerShell",
                    "reference": "https://attack.mitre.org/techniques/T1059/001/"
                }]
            }]
        }],
        "related_integrations": [{"package": "system", "version": "^2.0.0"}],
        "exceptions_list": [{
            "id": list_server_id,
            "list_id": LIST_ID,
            "namespace_type": NAMESPACE_TYPE,
            "type": "detection",
        }],
    })
}

/// The second marker rule, enabled over a marker index name that never
/// exists.
pub(super) fn missing_rule_body() -> Value {
    json!({
        "rule_id": MISSING_RULE_ID,
        "name": MISSING_RULE_NAME,
        "description": "Recorded by cargo xtask record-compose. Safe to delete.",
        "type": "query",
        "language": "kuery",
        "query": "marker: elasticctl-sample",
        "index": [MISSING_INDEX],
        "severity": "low",
        "risk_score": 21,
        "enabled": true,
        "from": "now-10m",
        "interval": "1m",
        "tags": [ALERT_MARKER_TAG],
    })
}

fn server_id(value: &Value, label: &'static str) -> elasticctl_core::Result<String> {
    value
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| recording_error(format!("{label} create response is missing id")))
}

/// Create the list, its two items, and both rules, in that order. Each
/// ownership flag is set before its create request.
pub(super) async fn create_objects(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<Provisioned> {
    let t = session.transport;

    session.ownership.list = true;
    let list = t
        .post("/api/exception_lists", Some(&list_body()))
        .await
        .map_err(create_error("creating the marker list failed"))?;
    if !owns_list(&list) {
        return Err(recording_error(
            "exception list create response did not prove the fixed marker identity",
        ));
    }
    let list_id = server_id(&list, "exception list")?;

    session.ownership.item = true;
    let item = t
        .post(
            "/api/exception_lists/items",
            Some(&item_body(ITEM_ID, "elasticctl-sample-1.exe")),
        )
        .await
        .map_err(create_error("creating marker item 1 failed"))?;
    if !owns_item(&item) {
        return Err(recording_error(
            "exception item 1 create response did not prove the fixed marker identity",
        ));
    }

    session.ownership.compose_item = true;
    let item = t
        .post(
            "/api/exception_lists/items",
            Some(&item_body(COMPOSE_ITEM_ID, "elasticctl-sample-2.exe")),
        )
        .await
        .map_err(create_error("creating marker item 2 failed"))?;
    if !owns_compose_item(&item) {
        return Err(recording_error(
            "exception item 2 create response did not prove the fixed marker identity",
        ));
    }

    session.ownership.alert_rule = true;
    session.ownership.alert_rule_claimed = true;
    let rule = t
        .post(RULES_PATH, Some(&rule_body(&list_id)))
        .await
        .map_err(create_error("creating the marker rule failed"))?;
    if !owns_alert_rule(&rule) {
        return Err(recording_error(
            "marker rule create response did not prove the fixed marker identity",
        ));
    }
    let rule_uuid = server_id(&rule, "marker rule")?;

    session.ownership.compose_rule = true;
    let missing_rule = t
        .post(RULES_PATH, Some(&missing_rule_body()))
        .await
        .map_err(create_error("creating the missing-index rule failed"))?;
    if !owns_missing_rule(&missing_rule) {
        return Err(recording_error(
            "missing-index rule create response did not prove the fixed marker identity",
        ));
    }
    let missing_rule_uuid = server_id(&missing_rule, "missing-index rule")?;

    Ok(Provisioned {
        list_id,
        rule_uuid,
        missing_rule_uuid,
    })
}

/// The marker case body. No assignee, so no user profile is involved.
pub(super) fn case_body() -> Value {
    json!({
        "title": CASE_TITLE,
        "description": CASE_TITLE,
        "tags": [CASE_TAG],
        "severity": "low",
        "assignees": [],
        "connector": {"id": "none", "name": "none", "type": ".none", "fields": null},
        "settings": {"syncAlerts": false},
        "owner": elasticctl_api::cases::OWNER,
    })
}

/// Create the marker case. `case` is claimed before the create; cleanup
/// finds a case whose response was lost by its title and tag.
pub(super) async fn create_case(
    session: &mut RecordingSession<'_>,
) -> elasticctl_core::Result<Value> {
    session.ownership.case = true;
    let created = session
        .transport
        .post(elasticctl_api::cases::CASES_PATH, Some(&case_body()))
        .await
        .map_err(create_error("creating the marker case failed"))?;
    if !owns_case(&created) {
        return Err(recording_error(
            "case create response did not prove the fixed marker identity",
        ));
    }
    Ok(created)
}

/// Delete the marker case by its exact id and prove no marker case remains.
pub(super) async fn delete_case(
    session: &mut RecordingSession<'_>,
    case_id: &str,
) -> elasticctl_core::Result<()> {
    let t = session.transport;
    elasticctl_api::cases::delete(t, &[case_id.to_string()])
        .await
        .map_err(create_error("deleting the marker case failed"))?;
    match t.get(&elasticctl_api::cases::case_path(case_id)).await {
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Ok(_) => return Err(recording_error("marker case still exists after delete")),
        Err(error) => {
            return Err(safe_recording_transport_error(
                "verifying the marker case delete failed",
                error,
            ));
        }
    }
    require_no_marker_cases(t).await.map_err(preflight_error)?;
    session.ownership.case = false;
    Ok(())
}

/// Delete one owned object by exact id after its marker fields still match,
/// then prove it is gone. A not-found first read means it is already gone.
async fn delete_owned(
    t: &Transport,
    path: &str,
    owns: fn(&Value) -> bool,
    label: &'static str,
) -> Result<(), String> {
    match t.get(path).await {
        Ok(value) if owns(&value) => {
            t.delete(path).await.map_err(|error| {
                format!("deleting {label}: {}", safe_recording_error_summary(&error))
            })?;
            match t.get(path).await {
                Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
                Ok(_) => Err(format!("{label} still exists after delete")),
                Err(error) => Err(format!(
                    "verifying {label} deletion: {}",
                    safe_recording_error_summary(&error)
                )),
            }
        }
        Ok(_) => Err(format!(
            "refusing to delete {label}: its marker fields do not match"
        )),
        Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "checking {label}: {}",
            safe_recording_error_summary(&error)
        )),
    }
}

impl RecordingSession<'_> {
    /// Delete the compose rule over the missing index and the second marker
    /// item. Each stays owned until a read after its delete is not found.
    /// The shared slots (marker rule, index, list, first item, case) are
    /// removed by the rest of session cleanup.
    pub(crate) async fn cleanup_compose(&mut self, errors: &mut Vec<String>) {
        if self.ownership.compose_rule {
            match delete_owned(
                self.transport,
                &missing_rule_path(),
                owns_missing_rule,
                "the compose missing-index rule",
            )
            .await
            {
                Ok(()) => self.ownership.compose_rule = false,
                Err(error) => errors.push(error),
            }
        }
        if self.ownership.compose_item {
            match delete_owned(
                self.transport,
                &item_path(COMPOSE_ITEM_ID),
                owns_compose_item,
                "exception item 2",
            )
            .await
            {
                Ok(()) => self.ownership.compose_item = false,
                Err(error) => errors.push(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::session::CleanupOwnership;
    use crate::recorder::test_support::mock_transport;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn ok(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    fn not_found() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "error": "Not Found",
            "message": "private.example.internal holds no such object"
        }))
    }

    fn sequence(responses: Vec<ResponseTemplate>) -> impl Fn(&Request) -> ResponseTemplate {
        let responses = Mutex::new(responses.into_iter());
        move |_: &Request| {
            let next = responses.lock().expect("responses").next();
            next.expect("unexpected request")
        }
    }

    async fn requests(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .map(|r| match r.url.query() {
                Some(query) => format!("{} {}?{query}", r.method, r.url.path()),
                None => format!("{} {}", r.method, r.url.path()),
            })
            .collect()
    }

    fn package(name: &str, status: &str) -> Value {
        json!({"item": {"name": name, "version": "1.0.0", "status": status,
            "readme": "/package/readme.md", "data_streams": [{"dataset": "x"}]}})
    }

    async fn mount_package(server: &MockServer, name: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/api/fleet/epm/packages/{name}")))
            .respond_with(response)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn package_probe_keeps_the_first_not_installed_candidate_in_order() {
        let server = MockServer::start().await;
        mount_package(&server, "apache", ok(package("apache", "installed"))).await;
        mount_package(&server, "nginx", ok(package("nginx", "not_installed"))).await;
        mount_package(&server, "mysql", ok(package("mysql", "not_installed"))).await;
        let t = mock_transport(&server);

        let (name, body) = probe_not_installed_package(&t).await.expect("probe");

        assert_eq!(name, "nginx");
        assert_eq!(body["item"]["status"], "not_installed");
        assert_eq!(
            requests(&server).await,
            [
                "GET /api/fleet/epm/packages/apache",
                "GET /api/fleet/epm/packages/nginx"
            ]
        );
    }

    #[tokio::test]
    async fn package_probe_skips_an_unknown_package_and_fails_when_none_qualifies() {
        let server = MockServer::start().await;
        mount_package(&server, "apache", not_found()).await;
        mount_package(&server, "nginx", ok(package("nginx", "installed"))).await;
        mount_package(&server, "mysql", ok(package("mysql", "install_failed"))).await;
        let t = mock_transport(&server);

        let error = probe_not_installed_package(&t).await.expect_err("none");

        assert!(error.message.contains("none of apache, nginx, or mysql"));
        assert_eq!(
            requests(&server).await,
            [
                "GET /api/fleet/epm/packages/apache",
                "GET /api/fleet/epm/packages/nginx",
                "GET /api/fleet/epm/packages/mysql"
            ]
        );
        assert!(requests(&server).await.iter().all(|r| r.starts_with("GET")));
    }

    #[tokio::test]
    async fn package_probe_refuses_a_status_for_a_different_name() {
        let server = MockServer::start().await;
        mount_package(&server, "apache", ok(package("other", "not_installed"))).await;
        mount_package(&server, "nginx", ok(package("other", "not_installed"))).await;
        mount_package(&server, "mysql", ok(package("other", "not_installed"))).await;
        let t = mock_transport(&server);

        assert!(probe_not_installed_package(&t).await.is_err());
    }

    #[tokio::test]
    async fn package_probe_stops_on_a_fatal_read_without_server_text() {
        let server = MockServer::start().await;
        mount_package(
            &server,
            "apache",
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "private.example.internal"})),
        )
        .await;
        let t = mock_transport(&server);

        let error = probe_not_installed_package(&t).await.expect_err("auth");

        assert_eq!(error.kind, ErrorKind::Auth);
        assert!(!error.message.contains("private"), "{}", error.message);
        assert_eq!(requests(&server).await.len(), 1);
    }

    fn missing_rule() -> Value {
        json!({"rule_id": MISSING_RULE_ID, "tags": [ALERT_MARKER_TAG], "id": "so-2"})
    }

    fn compose_item() -> Value {
        json!({"item_id": COMPOSE_ITEM_ID, "list_id": LIST_ID, "namespace_type": "single",
            "tags": list_tags()})
    }

    async fn mount_rule(server: &MockServer, http: &'static str, response: impl Respond + 'static) {
        Mock::given(method(http))
            .and(path(RULES_PATH))
            .and(query_param("rule_id", MISSING_RULE_ID))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn mount_item(server: &MockServer, http: &'static str, response: impl Respond + 'static) {
        Mock::given(method(http))
            .and(path("/api/exception_lists/items"))
            .and(query_param("item_id", COMPOSE_ITEM_ID))
            .respond_with(response)
            .mount(server)
            .await;
    }

    fn owned_session(t: &Transport) -> RecordingSession<'_> {
        RecordingSession {
            transport: t,
            ownership: CleanupOwnership {
                compose_rule: true,
                compose_item: true,
                ..CleanupOwnership::default()
            },
        }
    }

    #[tokio::test]
    async fn cleanup_deletes_both_compose_objects_by_exact_id_and_verifies() {
        let server = MockServer::start().await;
        mount_rule(
            &server,
            "GET",
            sequence(vec![ok(missing_rule()), not_found()]),
        )
        .await;
        mount_rule(&server, "DELETE", ok(missing_rule())).await;
        mount_item(
            &server,
            "GET",
            sequence(vec![ok(compose_item()), not_found()]),
        )
        .await;
        mount_item(&server, "DELETE", ok(compose_item())).await;
        let t = mock_transport(&server);
        let mut session = owned_session(&t);

        let mut errors = Vec::new();
        session.cleanup_compose(&mut errors).await;

        assert!(errors.is_empty(), "{errors:?}");
        assert!(!session.ownership.compose_rule);
        assert!(!session.ownership.compose_item);
        assert_eq!(
            requests(&server).await,
            [
                "GET /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index",
                "DELETE /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index",
                "GET /api/detection_engine/rules?rule_id=elasticctl-sample-compose-missing-index",
                "GET /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2&namespace_type=single",
                "DELETE /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2&namespace_type=single",
                "GET /api/exception_lists/items?item_id=elasticctl-sample-exception-item-2&namespace_type=single",
            ]
        );
    }

    #[tokio::test]
    async fn cleanup_refuses_objects_whose_marker_fields_changed() {
        let server = MockServer::start().await;
        mount_rule(
            &server,
            "GET",
            ok(json!({"rule_id": MISSING_RULE_ID, "tags": ["other"]})),
        )
        .await;
        mount_item(
            &server,
            "GET",
            ok(json!({"item_id": COMPOSE_ITEM_ID, "list_id": "other", "tags": list_tags()})),
        )
        .await;
        let t = mock_transport(&server);
        let mut session = owned_session(&t);

        let mut errors = Vec::new();
        session.cleanup_compose(&mut errors).await;

        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(session.ownership.compose_rule);
        assert!(session.ownership.compose_item);
        assert!(requests(&server).await.iter().all(|r| r.starts_with("GET")));
    }

    #[tokio::test]
    async fn cleanup_keeps_ownership_when_a_delete_fails_or_the_object_survives() {
        let server = MockServer::start().await;
        mount_rule(&server, "GET", ok(missing_rule())).await;
        mount_rule(
            &server,
            "DELETE",
            ResponseTemplate::new(400)
                .set_body_json(json!({"message": "private.example.internal"})),
        )
        .await;
        mount_item(&server, "GET", ok(compose_item())).await;
        mount_item(&server, "DELETE", ok(compose_item())).await;
        let t = mock_transport(&server);
        let mut session = owned_session(&t);

        let mut errors = Vec::new();
        session.cleanup_compose(&mut errors).await;

        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors[0].starts_with("deleting the compose missing-index rule: class="));
        assert_eq!(errors[1], "exception item 2 still exists after delete");
        assert!(errors.iter().all(|e| !e.contains("private")));
        assert!(session.ownership.compose_rule);
        assert!(session.ownership.compose_item);
    }

    #[tokio::test]
    async fn cleanup_releases_objects_that_are_already_gone() {
        let server = MockServer::start().await;
        mount_rule(&server, "GET", not_found()).await;
        mount_item(&server, "GET", not_found()).await;
        let t = mock_transport(&server);
        let mut session = owned_session(&t);

        let mut errors = Vec::new();
        session.cleanup_compose(&mut errors).await;

        assert!(errors.is_empty(), "{errors:?}");
        assert!(!session.ownership.compose_rule);
        assert!(!session.ownership.compose_item);
        assert_eq!(requests(&server).await.len(), 2);
    }

    #[test]
    fn every_created_object_carries_the_sample_marker() {
        assert!(owns_list(&list_body()));
        assert!(owns_item(&item_body(ITEM_ID, "a")));
        assert!(owns_compose_item(&item_body(COMPOSE_ITEM_ID, "b")));
        let rule = rule_body("list-so-id");
        assert!(owns_alert_rule(&rule));
        assert!(owns_missing_rule(&missing_rule_body()));
        assert!(owns_case(&case_body()));
        for value in [
            rule["rule_id"].clone(),
            missing_rule_body()["rule_id"].clone(),
        ] {
            assert!(
                value
                    .as_str()
                    .is_some_and(|id| id.starts_with("elasticctl-sample-"))
            );
        }
        assert_eq!(rule["index"], json!([ALERT_PROBE_INDEX]));
        assert_eq!(missing_rule_body()["index"], json!([MISSING_INDEX]));
        for index in [ALERT_PROBE_INDEX, MISSING_INDEX] {
            assert!(index.contains("elasticctl-sample"));
        }
        assert_eq!(rule["exceptions_list"][0]["list_id"], LIST_ID);
        assert_eq!(
            rule["related_integrations"],
            json!([{"package": "system", "version": "^2.0.0"}])
        );
        assert_eq!(rule["threat"][0]["tactic"]["id"], "TA0002");
        assert_eq!(rule["threat"][0]["technique"][0]["id"], "T1059");
        assert_eq!(
            rule["threat"][0]["technique"][0]["subtechnique"][0]["id"],
            "T1059.001"
        );
        assert!(!owns_missing_rule(
            &json!({"rule_id": MISSING_RULE_ID, "tags": []})
        ));
        assert!(!owns_compose_item(
            &json!({"item_id": ITEM_ID, "list_id": LIST_ID, "tags": list_tags()})
        ));
    }
}
