//! Marker objects for the compose recording.
//!
//! Every object is claimed in `CleanupOwnership` and marked unresolved
//! before the request that creates it. A definite success resolves the
//! claim; a definite conflict means another run holds the fixed identity,
//! so the claim is released and cleanup never touches the object. Any other
//! end, a timeout, a connection error, a 5xx or other failure, an
//! interrupt, or a panic, leaves the claim unresolved for cleanup's settle
//! window.
//!
//! Every create is create-only and sent once, so a retry can never turn this
//! run's applied write into a conflict. The marker index is created
//! explicitly and its UUID kept: the index is this run's only while it still
//! reports that UUID, which is read again before every marker document
//! write, before the refresh, and before cleanup deletes it.

use crate::clock::now_rfc3339;
use crate::diagnostics::{recording_error, safe_recording_transport_error};
use crate::recorder::agent_policies::reduce_package_status_item;
use crate::recorder::compose::cleanup::{
    CASE, COMPOSE_ITEM, INDEX, ITEM, LIST, MISSING_RULE, RULE,
};
use crate::recorder::compose::evidence::PrivateLog;
use crate::recorder::compose::requests::{
    RULES_PATH, index_uuid_path, marker_document_path, marker_index_path, package_status,
};
use crate::recorder::compose::settle::Unresolved;
use crate::recorder::compose::{
    ALERT_DOCS, COMPOSE_ITEM_ID, COMPOSE_RULE_NAME, ComposeSession, MISSING_INDEX, MISSING_RULE_ID,
    MISSING_RULE_NAME, PACKAGE_CANDIDATES,
};
use crate::recorder::markers::{
    ALERT_MARKER_TAG, ALERT_PROBE_INDEX, ALERT_RULE_ID, CASE_TAG, CASE_TITLE, ITEM_ID, LIST_ID,
    MARKER_TAGS, NAMESPACE_TYPE,
};
use crate::recorder::ownership::{
    owns_alert_index, owns_alert_rule, owns_case, owns_item, owns_list,
};
use elasticctl_core::{ErrorKind, Transport};
use serde_json::{Value, json};

/// The package the marker rule names in `related_integrations`.
const SYSTEM_PACKAGE: &str = "system";

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

/// Require the `system` package, which the marker rule names, to be
/// installed. Its reduced status is the installed half of the package
/// evidence and goes to the private log only.
pub(super) async fn require_installed_system(
    t: &Transport,
    log: &mut PrivateLog,
) -> elasticctl_core::Result<()> {
    let body = t
        .get(&package_status(SYSTEM_PACKAGE).target())
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading the system package status failed", error)
        })?;
    let item = &body["item"];
    if item["name"].as_str() != Some(SYSTEM_PACKAGE) || item["status"].as_str() != Some("installed")
    {
        return Err(recording_error(
            "refusing to record: the system package is not installed",
        ));
    }
    log.add(
        "responses",
        "package_system",
        reduce_package_status_item(&body).unwrap_or(Value::Null),
    );
    Ok(())
}

fn conflict(object: &'static str) -> elasticctl_core::Error {
    recording_error(format!(
        "refusing to record: {object} already exists and is not this run's"
    ))
}

/// One object's ownership flag and its unresolved flag.
struct Claim<'a> {
    owned: &'a mut bool,
    unresolved: &'a mut bool,
}

impl Claim<'_> {
    /// Set both flags before the request that may create the object.
    fn take(&mut self) {
        *self.owned = true;
        *self.unresolved = true;
    }

    /// A definite success: the object is this run's.
    fn resolve(&mut self) {
        *self.unresolved = false;
    }

    /// A definite conflict: the object is another run's.
    fn release(&mut self) {
        *self.owned = false;
        *self.unresolved = false;
    }
}

/// Send one create exactly once. Only a success or a conflict resolves the
/// claim; every other end leaves it unresolved.
async fn create_once(
    t: &Transport,
    path: &str,
    body: &Value,
    mut claim: Claim<'_>,
    object: &'static str,
    context: &'static str,
) -> elasticctl_core::Result<Value> {
    claim.take();
    match t.post_once(path, Some(body)).await {
        Ok(created) => {
            claim.resolve();
            Ok(created)
        }
        Err(error) if error.kind == ErrorKind::Conflict => {
            claim.release();
            Err(conflict(object))
        }
        Err(error) => Err(safe_recording_transport_error(context, error)),
    }
}

/// Whether an index create failed because the marker index name is taken.
///
/// Elasticsearch answers 400 `resource_already_exists_exception` with the
/// reason `index [<name>/<uuid>] already exists`. The transport keeps the
/// status and that reason, not the type, so the reason must name exactly
/// the marker index. Any other answer is not a definite "already exists".
fn index_already_exists(error: &elasticctl_core::Error) -> bool {
    error.kind == ErrorKind::Http
        && error.http_status == Some(400)
        && error
            .message
            .strip_prefix(&format!("index [{ALERT_PROBE_INDEX}"))
            .and_then(|rest| rest.strip_suffix("] already exists"))
            .is_some_and(|uuid| {
                uuid.is_empty()
                    || uuid
                        .strip_prefix('/')
                        .is_some_and(|uuid| !uuid.is_empty() && !uuid.contains(['/', ']', ' ']))
            })
}

/// The UUID a settings read reports, when the answer names exactly the
/// marker index and nothing else.
pub(super) fn index_uuid(settings: &Value) -> Option<&str> {
    let indices = settings.as_object().filter(|indices| indices.len() == 1)?;
    indices
        .get(ALERT_PROBE_INDEX)?
        .pointer("/settings/index/uuid")?
        .as_str()
        .filter(|uuid| !uuid.is_empty())
}

/// Read the marker index UUID again and require the one this run created.
/// A missing index or another UUID means the index is not this run's.
async fn require_own_index(t: &Transport, uuid: &str) -> elasticctl_core::Result<()> {
    let not_ours = || {
        recording_error(format!(
            "refusing to write: {INDEX} is not the one this run created"
        ))
    };
    match t.get_absolute_es(&index_uuid_path()).await {
        Ok(settings) if index_uuid(&settings) == Some(uuid) => Ok(()),
        Ok(_) => Err(not_ours()),
        Err(error) if error.kind == ErrorKind::NotFound => Err(not_ours()),
        Err(error) => Err(safe_recording_transport_error(
            "reading the marker index UUID failed",
            error,
        )),
    }
}

/// Create the marker index, keep its UUID, then index the marker documents
/// with the create-only route and refresh. The index is claimed before the
/// create, which is sent once. A definite "already exists" releases the
/// claim; the claim resolves only once the UUID is read, and any other end
/// leaves it unresolved. Every document write and the refresh is sent once,
/// right after a read that still shows that UUID; a read that does not
/// stops the writes and keeps the claim.
pub(super) async fn create_index(compose: &mut ComposeSession<'_>) -> elasticctl_core::Result<()> {
    let t = compose.session.transport;
    let mut claim = Claim {
        owned: &mut compose.session.ownership.alert_index,
        unresolved: &mut compose.unresolved.alert_index,
    };
    claim.take();
    match t
        .put_absolute_es_once(&marker_index_path(), &json!({}))
        .await
    {
        Ok(created)
            if created["acknowledged"].as_bool() == Some(true)
                && created["index"].as_str() == Some(ALERT_PROBE_INDEX) => {}
        Ok(_) => {
            return Err(recording_error(
                "the marker index create was not acknowledged",
            ));
        }
        Err(error) if index_already_exists(&error) => {
            claim.release();
            return Err(conflict(INDEX));
        }
        Err(error) => {
            return Err(safe_recording_transport_error(
                "creating the marker index failed",
                error,
            ));
        }
    }
    let settings = t
        .get_absolute_es(&index_uuid_path())
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading the marker index UUID failed", error)
        })?;
    let uuid = index_uuid(&settings)
        .ok_or_else(|| recording_error("the marker index settings did not report its UUID"))?
        .to_owned();
    compose.ids.index_uuid = Some(uuid.clone());
    claim.resolve();

    for seq in 1..=ALERT_DOCS {
        require_own_index(t, &uuid).await?;
        write_document(t, &mut compose.unresolved.index_recreation, seq).await?;
    }
    let proof = t
        .get_absolute_es(&format!("/{ALERT_PROBE_INDEX}/_doc/1"))
        .await
        .map_err(|error| {
            safe_recording_transport_error("reading a marker document failed", error)
        })?;
    if !owns_alert_index(&proof) {
        return Err(recording_error(
            "marker index write did not prove the fixed marker identity",
        ));
    }
    require_own_index(t, &uuid).await?;
    // `_refresh` rejects a body, so none is sent.
    t.post_absolute_es_once(&format!("/{ALERT_PROBE_INDEX}/_refresh"), None)
        .await
        .map_err(|error| {
            safe_recording_transport_error("refreshing the marker index failed", error)
        })?;
    Ok(())
}

/// Write marker document `seq` with the create-only route, exactly once.
///
/// `recreatable` is set before the request and cleared only by a definite
/// answer: the document created, or a conflict. Any other end may leave the
/// write to be applied later, after cleanup has deleted the index, and
/// automatic index creation then makes an index under the marker name again.
/// Cleanup watches the name for that. A conflict fails the step but leaves
/// the index owned: its UUID proves it this run's.
async fn write_document(
    t: &Transport,
    recreatable: &mut bool,
    seq: usize,
) -> elasticctl_core::Result<()> {
    let doc = json!({
        "@timestamp": now_rfc3339(),
        "marker": ALERT_MARKER_TAG,
        "message": format!("elasticctl sample compose event {seq}"),
    });
    *recreatable = true;
    match t
        .post_absolute_es_once(&marker_document_path(ALERT_PROBE_INDEX, seq), Some(&doc))
        .await
    {
        Ok(created) if created["result"].as_str() == Some("created") => {
            *recreatable = false;
            Ok(())
        }
        Ok(_) => Err(recording_error(
            "a marker document write did not report created",
        )),
        Err(error) => {
            if error.kind == ErrorKind::Conflict {
                *recreatable = false;
            }
            Err(safe_recording_transport_error(
                "writing a marker document failed",
                error,
            ))
        }
    }
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
        "related_integrations": [{"package": SYSTEM_PACKAGE, "version": "^2.0.0"}],
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

/// The server id of a create response that proved its marker identity.
fn proven_id(
    created: &Value,
    owns: fn(&Value) -> bool,
    object: &'static str,
) -> elasticctl_core::Result<String> {
    if !owns(created) {
        return Err(recording_error(format!(
            "{object} create response did not prove the fixed marker identity"
        )));
    }
    created
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| recording_error(format!("{object} create response is missing id")))
}

/// Create the list, its two items, and both rules, in that order, keeping
/// each server id for cleanup's re-reads and the fixture placeholders. The
/// alerting rule's alerts are owned from its claim on, since the rule can
/// exist even when its create answer is lost.
pub(super) async fn create_objects(
    compose: &mut ComposeSession<'_>,
) -> elasticctl_core::Result<()> {
    let t = compose.session.transport;
    let owned = &mut compose.session.ownership;
    let unresolved: &mut Unresolved = &mut compose.unresolved;
    let ids = &mut compose.ids;

    let list = create_once(
        t,
        "/api/exception_lists",
        &list_body(),
        Claim {
            owned: &mut owned.list,
            unresolved: &mut unresolved.list,
        },
        LIST,
        "creating the marker list failed",
    )
    .await?;
    let list_id = proven_id(&list, owns_list, LIST)?;
    ids.list = Some(list_id.clone());

    for (item_id, value, claim, owns, object, context, id) in [
        (
            ITEM_ID,
            "elasticctl-sample-1.exe",
            Claim {
                owned: &mut owned.item,
                unresolved: &mut unresolved.item,
            },
            owns_item as fn(&Value) -> bool,
            ITEM,
            "creating marker item 1 failed",
            &mut ids.item,
        ),
        (
            COMPOSE_ITEM_ID,
            "elasticctl-sample-2.exe",
            Claim {
                owned: &mut owned.compose_item,
                unresolved: &mut unresolved.compose_item,
            },
            owns_compose_item,
            COMPOSE_ITEM,
            "creating marker item 2 failed",
            &mut ids.compose_item,
        ),
    ] {
        let body = item_body(item_id, value);
        let item = create_once(
            t,
            "/api/exception_lists/items",
            &body,
            claim,
            object,
            context,
        )
        .await?;
        *id = Some(proven_id(&item, owns, object)?);
    }

    compose.alerts = true;
    let rule = create_once(
        t,
        RULES_PATH,
        &rule_body(&list_id),
        Claim {
            owned: &mut owned.alert_rule,
            unresolved: &mut unresolved.alert_rule,
        },
        RULE,
        "creating the marker rule failed",
    )
    .await;
    if !owned.alert_rule {
        // A conflict: the rule, and so its alerts, are another run's.
        compose.alerts = false;
    }
    ids.rule = Some(proven_id(&rule?, owns_alert_rule, RULE)?);

    let missing_rule = create_once(
        t,
        RULES_PATH,
        &missing_rule_body(),
        Claim {
            owned: &mut owned.compose_rule,
            unresolved: &mut unresolved.compose_rule,
        },
        MISSING_RULE,
        "creating the missing-index rule failed",
    )
    .await?;
    ids.missing_rule = Some(proven_id(&missing_rule, owns_missing_rule, MISSING_RULE)?);
    Ok(())
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

/// Create the marker case and keep its id. `case` is claimed before the
/// create; cleanup finds a case whose answer was lost by title and tag.
pub(super) async fn create_case(
    compose: &mut ComposeSession<'_>,
) -> elasticctl_core::Result<Value> {
    let t = compose.session.transport;
    let created = create_once(
        t,
        elasticctl_api::cases::CASES_PATH,
        &case_body(),
        Claim {
            owned: &mut compose.session.ownership.case,
            unresolved: &mut compose.unresolved.case,
        },
        CASE,
        "creating the marker case failed",
    )
    .await?;
    compose.ids.case = Some(proven_id(&created, owns_case, CASE)?);
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::mock_transport;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ok(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    fn not_found() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({
            "statusCode": 404, "error": "Not Found",
            "message": "private.example.internal holds no such object"
        }))
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

    #[tokio::test]
    async fn the_system_package_must_be_installed() {
        for (response, accepted) in [
            (ok(package("system", "installed")), true),
            (ok(package("system", "not_installed")), false),
            (ok(package("other", "installed")), false),
            (not_found(), false),
        ] {
            let server = MockServer::start().await;
            mount_package(&server, "system", response).await;
            let t = mock_transport(&server);
            let mut log = PrivateLog::default();

            let result = require_installed_system(&t, &mut log).await;

            assert_eq!(result.is_ok(), accepted);
            if let Err(error) = result {
                assert!(error.message.contains("system"), "{}", error.message);
                assert!(!error.message.contains("private"), "{}", error.message);
            } else {
                assert_eq!(
                    log.get("responses").expect("logged")["package_system"]["status"],
                    "installed"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_conflicting_create_releases_its_claim_and_a_lost_answer_keeps_it() {
        for (status, still_claimed) in [(409, false), (500, true), (503, true), (400, true)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/exception_lists"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(json!({"message": "private.example.internal"})),
                )
                .mount(&server)
                .await;
            let t = mock_transport(&server);
            let (mut owned, mut unresolved) = (false, false);

            let error = create_once(
                &t,
                "/api/exception_lists",
                &list_body(),
                Claim {
                    owned: &mut owned,
                    unresolved: &mut unresolved,
                },
                LIST,
                "creating the marker list failed",
            )
            .await
            .expect_err("failed create");

            assert_eq!(owned, still_claimed, "{status}");
            assert_eq!(
                unresolved, still_claimed,
                "{status}: only a conflict is a definite answer"
            );
            assert!(!error.message.contains("private"), "{}", error.message);
            assert_eq!(
                requests(&server).await,
                ["POST /api/exception_lists"],
                "{status}: a create is sent exactly once"
            );
        }
    }

    #[tokio::test]
    async fn a_successful_create_resolves_its_claim() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/exception_lists"))
            .respond_with(ok(list_body()))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let (mut owned, mut unresolved) = (false, false);

        create_once(
            &t,
            "/api/exception_lists",
            &list_body(),
            Claim {
                owned: &mut owned,
                unresolved: &mut unresolved,
            },
            LIST,
            "creating the marker list failed",
        )
        .await
        .expect("created");

        assert!(owned && !unresolved);
    }

    fn already_exists(index: &str) -> Value {
        let reason = format!("index [{index}/AbC-12_xyz] already exists");
        json!({"error": {"root_cause": [{"type": "resource_already_exists_exception",
            "reason": reason}], "type": "resource_already_exists_exception",
            "reason": reason, "index_uuid": "AbC-12_xyz", "index": index}, "status": 400})
    }

    fn settings(index: &str, uuid: &str) -> ResponseTemplate {
        ok(json!({(index): {"settings": {"index": {"uuid": uuid}}}}))
    }

    async fn mount_index_create(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("PUT"))
            .and(path(format!("/{ALERT_PROBE_INDEX}")))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// Mount settings answers for the marker index, one per read, in order.
    async fn mount_uuid_reads(server: &MockServer, answers: Vec<ResponseTemplate>) {
        for answer in answers {
            Mock::given(method("GET"))
                .and(path(format!("/{ALERT_PROBE_INDEX}/_settings/index.uuid")))
                .respond_with(answer)
                .up_to_n_times(1)
                .mount(server)
                .await;
        }
    }

    fn acknowledged() -> ResponseTemplate {
        ok(json!({"acknowledged": true, "shards_acknowledged": true, "index": ALERT_PROBE_INDEX}))
    }

    #[tokio::test]
    async fn an_index_create_answered_already_exists_releases_the_claim_and_sends_no_document() {
        let server = MockServer::start().await;
        mount_index_create(
            &server,
            ResponseTemplate::new(400).set_body_json(already_exists(ALERT_PROBE_INDEX)),
        )
        .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);

        let error = create_index(&mut compose).await.expect_err("taken");

        assert_eq!(
            error.message,
            "refusing to record: index elasticctl-sample-alert-events already exists and is not this run's"
        );
        assert!(!compose.session.ownership.alert_index);
        assert!(!compose.unresolved.alert_index);
        assert_eq!(compose.ids.index_uuid, None);
        assert_eq!(
            requests(&server).await,
            [format!("PUT /{ALERT_PROBE_INDEX}")]
        );
    }

    #[tokio::test]
    async fn an_ambiguous_index_create_leaves_the_claim_unresolved_after_one_request() {
        for (status, body) in [
            (
                503,
                json!({"message": "private.example.internal unavailable"}),
            ),
            (429, json!({"message": "private.example.internal busy"})),
            (
                500,
                json!({"error": {"type": "x", "reason": "private.example.internal"}, "status": 500}),
            ),
            (400, already_exists("elasticctl-sample-alert-events-other")),
            (
                400,
                json!({"error": {"type": "invalid_index_name_exception",
                "reason": "Invalid index name [elasticctl-sample-alert-events], already exists as alias"},
                "status": 400}),
            ),
            (
                200,
                json!({"acknowledged": false, "shards_acknowledged": false,
                "index": ALERT_PROBE_INDEX}),
            ),
        ] {
            let server = MockServer::start().await;
            mount_index_create(&server, ResponseTemplate::new(status).set_body_json(body)).await;
            let t = mock_transport(&server);
            let mut compose = ComposeSession::new(&t);

            let error = create_index(&mut compose).await.expect_err("ambiguous");

            assert!(compose.session.ownership.alert_index, "{status}");
            assert!(compose.unresolved.alert_index, "{status}");
            assert_eq!(compose.ids.index_uuid, None, "{status}");
            assert!(!error.message.contains("private"), "{}", error.message);
            assert_eq!(
                requests(&server).await,
                [format!("PUT /{ALERT_PROBE_INDEX}")],
                "{status}: the create is sent exactly once"
            );
        }
    }

    #[tokio::test]
    async fn a_uuid_read_that_does_not_prove_the_index_sends_no_document() {
        let refused = || {
            ResponseTemplate::new(403).set_body_json(json!({"message": "private.example.internal"}))
        };
        let missing = || {
            ResponseTemplate::new(404).set_body_json(
                json!({"error": {"type": "index_not_found_exception"}, "status": 404}),
            )
        };
        // The reads after the create, and the UUID this run keeps.
        for (reads, kept) in [
            (vec![refused()], None),
            (vec![settings("other-index", "uuid-1")], None),
            (
                vec![
                    settings(ALERT_PROBE_INDEX, "uuid-1"),
                    settings(ALERT_PROBE_INDEX, "uuid-2"),
                ],
                Some("uuid-1"),
            ),
            (
                vec![settings(ALERT_PROBE_INDEX, "uuid-1"), missing()],
                Some("uuid-1"),
            ),
        ] {
            let server = MockServer::start().await;
            mount_index_create(&server, acknowledged()).await;
            let count = reads.len();
            mount_uuid_reads(&server, reads).await;
            let t = mock_transport(&server);
            let mut compose = ComposeSession::new(&t);

            let error = create_index(&mut compose).await.expect_err("unproven");

            assert!(compose.session.ownership.alert_index);
            assert_eq!(
                compose.unresolved.alert_index,
                kept.is_none(),
                "only a recorded UUID resolves the claim"
            );
            assert_eq!(compose.ids.index_uuid.as_deref(), kept);
            assert!(!error.message.contains("private"), "{}", error.message);
            if kept.is_some() {
                assert_eq!(
                    error.message,
                    "refusing to write: index elasticctl-sample-alert-events is not the one this run created"
                );
            }
            let sent = requests(&server).await;
            assert_eq!(sent.len(), 1 + count, "{sent:?}");
            assert!(sent.iter().all(|r| !r.starts_with("POST ")), "{sent:?}");
        }
    }

    #[tokio::test]
    async fn an_ambiguous_document_write_marks_the_index_recreatable_after_one_request() {
        let failure = |status: u16, kind: &str| {
            ResponseTemplate::new(status).set_body_json(json!({"error": {"type": kind,
                "reason": "private.example.internal"}, "status": status}))
        };
        for (response, recreatable) in [
            (failure(503, "unavailable"), true),
            (failure(500, "x"), true),
            (failure(400, "mapper_parsing_exception"), true),
            (ok(json!({"_id": "1", "result": "updated"})), true),
            (failure(409, "version_conflict_engine_exception"), false),
        ] {
            let server = MockServer::start().await;
            mount_index_create(&server, acknowledged()).await;
            mount_uuid_reads(
                &server,
                vec![
                    settings(ALERT_PROBE_INDEX, "uuid-1"),
                    settings(ALERT_PROBE_INDEX, "uuid-1"),
                ],
            )
            .await;
            Mock::given(method("POST"))
                .and(path(marker_document_path(ALERT_PROBE_INDEX, 1)))
                .respond_with(response)
                .mount(&server)
                .await;
            let t = mock_transport(&server);
            let mut compose = ComposeSession::new(&t);

            let error = create_index(&mut compose).await.expect_err("stopped");

            assert_eq!(
                compose.unresolved.index_recreation, recreatable,
                "{error:?}"
            );
            assert!(compose.session.ownership.alert_index);
            assert!(!compose.unresolved.alert_index);
            assert_eq!(compose.ids.index_uuid.as_deref(), Some("uuid-1"));
            assert!(!error.message.contains("private"), "{}", error.message);
            assert_eq!(
                requests(&server).await,
                [
                    format!("PUT /{ALERT_PROBE_INDEX}"),
                    format!("GET {}", index_uuid_path()),
                    format!("GET {}", index_uuid_path()),
                    format!("POST {}", marker_document_path(ALERT_PROBE_INDEX, 1)),
                ],
                "the write is sent once and nothing follows it"
            );
        }
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
