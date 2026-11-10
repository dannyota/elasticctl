//! Compose cleanup: remove exactly what this run created.
//!
//! An object is touched only while its ownership flag is set. Every delete
//! re-reads the object first and requires its marker fields, and the server
//! id when this run learned it. The marker index is deleted only while it
//! reports the UUID this run recorded; one without a recorded UUID is never
//! deleted. The flag clears only after a later read finds the object gone;
//! for a create whose answer was lost, only after it has stayed gone for
//! the whole settle window. Alerts are closed by explicit id until a
//! complete search finds none open. Failure text is built only from static
//! context and an error's class and status.

use crate::diagnostics::safe_recording_error_summary;
use crate::recorder::cases::find_marker_cases;
use crate::recorder::compose::ComposeSession;
use crate::recorder::compose::alert_search::{SearchError, open_session_alerts};
use crate::recorder::compose::provision::{index_uuid, owns_compose_item, owns_missing_rule};
use crate::recorder::compose::requests::{
    ITEMS_FIND_PATH, close_alerts_body, index_uuid_path, item_path, list_path, marker_index_path,
    rule_get,
};
use crate::recorder::compose::settle::{Timing, Watch};
use crate::recorder::compose::{COMPOSE_ITEM_ID, MISSING_RULE_ID};
use crate::recorder::markers::{ALERT_RULE_ID, ITEM_ID, LIST_ID, NAMESPACE_TYPE};
use crate::recorder::ownership::{owns_alert_rule, owns_case, owns_item, owns_list};
use elasticctl_core::{Error, ErrorKind, Transport, urlencode};
use serde_json::Value;
use std::fmt;
use std::time::Instant;

pub(super) const CASE: &str = "the marker case";
pub(super) const RULE: &str = "rule elasticctl-sample-alert-probe";
pub(super) const MISSING_RULE: &str = "rule elasticctl-sample-compose-missing-index";
pub(super) const ALERTS: &str = "the session alerts";
pub(super) const ITEM: &str = "exception item 1";
pub(super) const COMPOSE_ITEM: &str = "exception item 2";
pub(super) const LIST: &str = "the marker exception list";
pub(super) const INDEX: &str = "index elasticctl-sample-alert-events";

/// Close requests sent for the session alerts before cleanup reports any
/// that are still open.
const CLOSE_ROUNDS: u32 = 3;

/// One cleanup failure. Its text holds only static context and an error's
/// class and status, so it is safe to print.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Failure(String);

impl Failure {
    fn refused(object: &'static str) -> Self {
        Self(format!(
            "refusing to delete {object}: its marker fields or id do not match"
        ))
    }

    fn present(object: &'static str) -> Self {
        Self(format!("{object} is still present"))
    }

    fn kept(object: &'static str, reason: &'static str) -> Self {
        Self(format!("keeping {object}: {reason}"))
    }

    fn unrecorded(object: &'static str) -> Self {
        Self(format!(
            "{object} is present without a UUID this run recorded and needs manual recovery"
        ))
    }

    fn request(stage: &'static str, object: &'static str, error: &Error) -> Self {
        Self(format!(
            "{stage} {object}: {}",
            safe_recording_error_summary(error)
        ))
    }

    fn incomplete(object: &'static str, reason: &'static str) -> Self {
        Self(format!("the search for {object} was incomplete: {reason}"))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One fixed-id Kibana object and the reads that prove it this run's, then
/// gone.
struct Target<'a> {
    object: &'static str,
    path: String,
    owns: fn(&Value) -> bool,
    /// The server id this run learned, which a re-read must still show.
    id: Option<&'a str>,
    /// A `_find` whose `total` must be zero before the delete.
    empty: Option<String>,
}

impl Target<'_> {
    fn kibana<'a>(
        object: &'static str,
        path: String,
        owns: fn(&Value) -> bool,
        id: Option<&'a str>,
    ) -> Target<'a> {
        Target {
            object,
            path,
            owns,
            id,
            empty: None,
        }
    }

    fn matches(&self, value: &Value) -> bool {
        (self.owns)(value)
            && self
                .id
                .is_none_or(|id| value.get("id").and_then(Value::as_str) == Some(id))
    }
}

async fn confirm_absent(t: &Transport, target: &Target<'_>) -> Result<(), Failure> {
    match t.get(&target.path).await {
        Err(error) if error.kind == ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(Failure::present(target.object)),
        Err(error) => Err(Failure::request(
            "verifying the removal of",
            target.object,
            &error,
        )),
    }
}

/// Remove one owned object. Returns the read taken before the delete, or
/// `None` when the object was already gone.
async fn remove(t: &Transport, target: &Target<'_>) -> Result<Option<Value>, Failure> {
    let current = match t.get(&target.path).await {
        Ok(value) if target.matches(&value) => value,
        Ok(_) => return Err(Failure::refused(target.object)),
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Failure::request("checking", target.object, &error)),
    };
    if let Some(find) = &target.empty {
        let page = t
            .get(find)
            .await
            .map_err(|error| Failure::request("counting the items on", target.object, &error))?;
        if page.get("total").and_then(Value::as_u64) != Some(0) {
            return Err(Failure::kept(target.object, "it still holds items"));
        }
    }
    match t.delete(&target.path).await {
        Ok(_) => {}
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(Failure::request("deleting", target.object, &error)),
    }
    confirm_absent(t, target).await?;
    Ok(Some(current))
}

/// Remove one owned object. A create whose answer was lost is read again
/// for the settle window: each read that finds it with its marker deletes
/// it and proves it gone, and the window restarts. Returns the last read
/// that showed the object.
async fn reconcile(
    t: &Transport,
    target: &Target<'_>,
    unresolved: bool,
    timing: &Timing,
) -> Result<Option<Value>, Failure> {
    if !unresolved {
        return remove(t, target).await;
    }
    let mut watch = Watch::new(timing.settle_window);
    let mut seen = None;
    loop {
        let read = remove(t, target).await?;
        let removed = read.is_some();
        if removed {
            seen = read;
        }
        if watch.observe(Instant::now(), removed) {
            return Ok(seen);
        }
        tokio::time::sleep(timing.settle_interval).await;
    }
}

/// Remove the marker case. A case has no caller-chosen id: when the create
/// answer was lost, the one marker case is found by title and tag, which
/// the preflight proved absent before, then handled by its exact id.
/// Returns whether a case was deleted.
async fn remove_case(t: &Transport, known: &mut Option<String>) -> Result<bool, Failure> {
    let id = match known.clone() {
        Some(id) => id,
        None => {
            let (cases, total) = find_marker_cases(t)
                .await
                .map_err(|error| Failure::request("finding", CASE, &error))?;
            match cases.as_slice() {
                [] if total == 0 => return Ok(false),
                [case] if total == 1 => case.id.clone(),
                _ => return Err(Failure::kept(CASE, "more than one marker case matches")),
            }
        }
    };
    *known = Some(id.clone());
    let path = elasticctl_api::cases::case_path(&id);
    match t.get(&path).await {
        Ok(case)
            if owns_case(&case) && case.get("id").and_then(Value::as_str) == Some(id.as_str()) => {}
        Ok(_) => return Err(Failure::refused(CASE)),
        Err(error) if error.kind == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(Failure::request("checking", CASE, &error)),
    }
    match elasticctl_api::cases::delete(t, &[id]).await {
        Ok(()) => {}
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(Failure::request("deleting", CASE, &error)),
    }
    match t.get(&path).await {
        Err(error) if error.kind == ErrorKind::NotFound => Ok(true),
        Ok(_) => Err(Failure::present(CASE)),
        Err(error) => Err(Failure::request("verifying the removal of", CASE, &error)),
    }
}

/// The case counterpart of `reconcile`.
async fn reconcile_case(
    t: &Transport,
    known: &mut Option<String>,
    unresolved: bool,
    timing: &Timing,
) -> Result<(), Failure> {
    if !unresolved {
        return remove_case(t, known).await.map(|_| ());
    }
    let mut watch = Watch::new(timing.settle_window);
    loop {
        let removed = remove_case(t, known).await?;
        if watch.observe(Instant::now(), removed) {
            return Ok(());
        }
        tokio::time::sleep(timing.settle_interval).await;
    }
}

/// The UUID one read of the marker index reports: `None` when the index is absent,
/// `Some(None)` when an answer does not name exactly the marker index.
async fn read_index_uuid(
    t: &Transport,
    stage: &'static str,
) -> Result<Option<Option<String>>, Failure> {
    match t.get_absolute_es(&index_uuid_path()).await {
        Ok(settings) => Ok(Some(index_uuid(&settings).map(str::to_owned))),
        Err(error) if error.kind == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Failure::request(stage, INDEX, &error)),
    }
}

/// Remove the marker index only while it reports the UUID this run
/// recorded. An index present without a recorded UUID is never deleted.
/// Returns whether an index was deleted.
async fn remove_index(t: &Transport, recorded: Option<&str>) -> Result<bool, Failure> {
    let Some(current) = read_index_uuid(t, "checking").await? else {
        return Ok(false);
    };
    let Some(recorded) = recorded else {
        return Err(Failure::unrecorded(INDEX));
    };
    if current.as_deref() != Some(recorded) {
        return Err(Failure::refused(INDEX));
    }
    match t.delete_absolute_es_once(&marker_index_path()).await {
        Ok(_) => {}
        Err(error) if error.kind == ErrorKind::NotFound => {}
        Err(error) => return Err(Failure::request("deleting", INDEX, &error)),
    }
    match read_index_uuid(t, "verifying the removal of").await? {
        None => Ok(true),
        Some(_) => Err(Failure::present(INDEX)),
    }
}

/// The index counterpart of `reconcile`. An index whose create answer was
/// lost has no recorded UUID, so one that appears in the settle window is
/// left for manual recovery.
async fn reconcile_index(
    t: &Transport,
    recorded: Option<&str>,
    unresolved: bool,
    timing: &Timing,
) -> Result<(), Failure> {
    if !unresolved {
        return remove_index(t, recorded).await.map(|_| ());
    }
    let mut watch = Watch::new(timing.settle_window);
    loop {
        let removed = remove_index(t, recorded).await?;
        if watch.observe(Instant::now(), removed) {
            return Ok(());
        }
        tokio::time::sleep(timing.settle_interval).await;
    }
}

/// Close the alerts of this run's rule by explicit id until a complete
/// search has found none open for the whole settle window. The ids come
/// from a read scoped to the rule's per-creation id, so no alert of an
/// earlier run is ever closed. The window catches an alert the rule's last
/// execution writes after the rule is deleted.
async fn close_session_alerts(
    t: &Transport,
    rule_uuid: &str,
    timing: &Timing,
) -> Result<(), Failure> {
    let mut watch = Watch::new(timing.settle_window);
    let mut closes = 0;
    loop {
        let open = open_session_alerts(t, rule_uuid)
            .await
            .map_err(|error| match error {
                SearchError::Request(error) => Failure::request("finding", ALERTS, &error),
                SearchError::Incomplete(reason) => Failure::incomplete(ALERTS, reason),
            })?;
        if open.total == 0 {
            if watch.observe(Instant::now(), false) {
                return Ok(());
            }
            tokio::time::sleep(timing.settle_interval).await;
            continue;
        }
        watch.reset();
        if closes == CLOSE_ROUNDS {
            return Err(Failure(format!("{ALERTS} are still open")));
        }
        closes += 1;
        t.post(
            elasticctl_api::alerts::STATUS_PATH,
            Some(&close_alerts_body(&open.ids)),
        )
        .await
        .map_err(|error| Failure::request("closing", ALERTS, &error))?;
        tokio::time::sleep(timing.poll).await;
    }
}

/// Remove every object this run still owns, in dependency order: the case
/// that holds the alert, both rules, the rule's alerts, the items, the list
/// once it is empty, then the index.
pub(super) async fn cleanup(compose: &mut ComposeSession<'_>, timing: &Timing) -> Vec<Failure> {
    let t = compose.session.transport;
    let owned = &mut compose.session.ownership;
    let unresolved = &mut compose.unresolved;
    let ids = &mut compose.ids;
    let alerts = &mut compose.alerts;
    let mut failures = Vec::new();

    if owned.case {
        match reconcile_case(t, &mut ids.case, unresolved.case, timing).await {
            Ok(()) => (owned.case, unresolved.case) = (false, false),
            Err(failure) => failures.push(failure),
        }
    }

    if owned.compose_rule {
        let removed = {
            let path = rule_get(MISSING_RULE_ID).target();
            let target = Target::kibana(
                MISSING_RULE,
                path,
                owns_missing_rule,
                ids.missing_rule.as_deref(),
            );
            reconcile(t, &target, unresolved.compose_rule, timing).await
        };
        match removed {
            Ok(_) => (owned.compose_rule, unresolved.compose_rule) = (false, false),
            Err(failure) => failures.push(failure),
        }
    }
    if owned.alert_rule {
        let removed = {
            let path = rule_get(ALERT_RULE_ID).target();
            let target = Target::kibana(RULE, path, owns_alert_rule, ids.rule.as_deref());
            reconcile(t, &target, unresolved.alert_rule, timing).await
        };
        match removed {
            Ok(read) => {
                (owned.alert_rule, unresolved.alert_rule) = (false, false);
                // A create whose answer was lost still produced alerts under
                // the id the re-read showed.
                if ids.rule.is_none() {
                    ids.rule = read
                        .as_ref()
                        .and_then(|rule| rule.get("id"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                }
            }
            Err(failure) => failures.push(failure),
        }
    }
    if *alerts {
        match ids.rule.as_deref() {
            Some(rule_uuid) => match close_session_alerts(t, rule_uuid, timing).await {
                // While the rule is still owned it can still write alerts.
                Ok(()) => *alerts = owned.alert_rule,
                Err(failure) => failures.push(failure),
            },
            // The rule never existed for this run, so it wrote no alerts.
            None if !owned.alert_rule => *alerts = false,
            None => {}
        }
    }

    for (flag, lost, object, item_id, owns, id) in [
        (
            &mut owned.compose_item,
            &mut unresolved.compose_item,
            COMPOSE_ITEM,
            COMPOSE_ITEM_ID,
            owns_compose_item as fn(&Value) -> bool,
            ids.compose_item.as_deref(),
        ),
        (
            &mut owned.item,
            &mut unresolved.item,
            ITEM,
            ITEM_ID,
            owns_item,
            ids.item.as_deref(),
        ),
    ] {
        if !*flag {
            continue;
        }
        let target = Target::kibana(object, item_path(item_id), owns, id);
        match reconcile(t, &target, *lost, timing).await {
            Ok(_) => (*flag, *lost) = (false, false),
            Err(failure) => failures.push(failure),
        }
    }

    if owned.list {
        if owned.item || owned.compose_item {
            failures.push(Failure::kept(LIST, "an item on it is still owned"));
        } else {
            let removed = {
                let mut target = Target::kibana(LIST, list_path(), owns_list, ids.list.as_deref());
                target.empty = Some(format!(
                    "{ITEMS_FIND_PATH}?list_id={}&namespace_type={NAMESPACE_TYPE}&page=1&per_page=1",
                    urlencode(LIST_ID)
                ));
                reconcile(t, &target, unresolved.list, timing).await
            };
            match removed {
                Ok(_) => (owned.list, unresolved.list) = (false, false),
                Err(failure) => failures.push(failure),
            }
        }
    }

    if owned.alert_index {
        let recorded = ids.index_uuid.as_deref();
        match reconcile_index(t, recorded, unresolved.alert_index, timing).await {
            Ok(_) => (owned.alert_index, unresolved.alert_index) = (false, false),
            Err(failure) => failures.push(failure),
        }
    }
    failures
}

/// The objects this run still owns, for the operator.
pub(super) fn still_owned(compose: &ComposeSession<'_>) -> Vec<&'static str> {
    let owned = &compose.session.ownership;
    [
        (owned.case, CASE),
        (owned.alert_rule, RULE),
        (owned.compose_rule, MISSING_RULE),
        (compose.alerts, ALERTS),
        (owned.compose_item, COMPOSE_ITEM),
        (owned.item, ITEM),
        (owned.list, LIST),
        (owned.alert_index, INDEX),
    ]
    .into_iter()
    .filter_map(|(owned, object)| owned.then_some(object))
    .collect()
}

/// Owned objects whose create answer was lost and that did not settle. Each
/// may still appear, so the operator must check it by hand.
pub(super) fn still_unresolved(compose: &ComposeSession<'_>) -> Vec<&'static str> {
    let unresolved = &compose.unresolved;
    [
        (unresolved.case, CASE),
        (unresolved.alert_rule, RULE),
        (unresolved.compose_rule, MISSING_RULE),
        (unresolved.compose_item, COMPOSE_ITEM),
        (unresolved.item, ITEM),
        (unresolved.list, LIST),
        (unresolved.alert_index, INDEX),
    ]
    .into_iter()
    .filter_map(|(lost, object)| lost.then_some(object))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::markers::{ALERT_MARKER_TAG, ALERT_PROBE_INDEX, CASE_TAG, CASE_TITLE};
    use crate::recorder::test_support::mock_transport;
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ok(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    fn not_found() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({"statusCode": 404}))
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

    async fn mount_rule(server: &MockServer, http: &'static str, response: ResponseTemplate) {
        Mock::given(method(http))
            .and(path("/api/detection_engine/rules"))
            .and(query_param("rule_id", ALERT_RULE_ID))
            .respond_with(response)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn nothing_owned_sends_no_request() {
        let server = MockServer::start().await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert!(failures.is_empty(), "{failures:?}");
        assert!(requests(&server).await.is_empty());
    }

    #[tokio::test]
    async fn an_untagged_rule_under_the_fixed_id_is_never_patched_or_deleted() {
        let server = MockServer::start().await;
        mount_rule(
            &server,
            "GET",
            ok(json!({"rule_id": ALERT_RULE_ID, "tags": [], "id": "so-1"})),
        )
        .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.alert_rule = true;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert_eq!(
            failures,
            [Failure::refused(RULE)],
            "the rule was not refused"
        );
        assert!(compose.session.ownership.alert_rule);
        assert_eq!(
            requests(&server).await,
            ["GET /api/detection_engine/rules?rule_id=elasticctl-sample-alert-probe"]
        );
    }

    #[tokio::test]
    async fn a_rule_whose_server_id_changed_is_refused() {
        let server = MockServer::start().await;
        mount_rule(
            &server,
            "GET",
            ok(json!({"rule_id": ALERT_RULE_ID, "tags": [ALERT_MARKER_TAG], "id": "so-2"})),
        )
        .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.alert_rule = true;
        compose.ids.rule = Some("so-1".into());
        Mock::given(method("POST"))
            .and(path(elasticctl_api::alerts::SEARCH_PATH))
            .respond_with(ok(json!({"hits": {"total": {"value": 0}, "hits": []}})))
            .mount(&server)
            .await;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert_eq!(failures, [Failure::refused(RULE)]);
        assert!(
            requests(&server).await.iter().all(|r| r.starts_with("GET ")
                || r.starts_with("POST /api/detection_engine/signals/search")),
            "a mutation was sent"
        );
    }

    #[tokio::test]
    async fn a_lost_case_create_is_found_by_its_marker_and_removed_by_id() {
        let server = MockServer::start().await;
        let case = json!({"id": "case-1", "title": CASE_TITLE, "tags": [CASE_TAG],
            "description": "x", "status": "open", "version": "v1"});
        Mock::given(method("GET"))
            .and(path("/api/cases/_find"))
            .respond_with(ok(
                json!({"cases": [case.clone()], "total": 1, "page": 1, "per_page": 100}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/cases/case-1"))
            .respond_with(ok(case))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/cases/case-1"))
            .respond_with(not_found())
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api/cases"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.case = true;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert!(failures.is_empty(), "{failures:?}");
        assert!(!compose.session.ownership.case);
        let sent = requests(&server).await;
        assert_eq!(sent.len(), 4, "{sent:?}");
        assert!(sent[0].starts_with("GET /api/cases/_find?"));
        assert_eq!(sent[1], "GET /api/cases/case-1");
        assert_eq!(sent[2], "DELETE /api/cases?ids=%5B%22case-1%22%5D");
        assert_eq!(sent[3], "GET /api/cases/case-1");
    }

    #[tokio::test]
    async fn more_than_one_marker_case_is_left_for_review() {
        let server = MockServer::start().await;
        let case = |id: &str| {
            json!({"id": id, "title": CASE_TITLE, "tags": [CASE_TAG], "description": "x",
                "status": "open", "version": "v1"})
        };
        Mock::given(method("GET"))
            .and(path("/api/cases/_find"))
            .respond_with(ok(
                json!({"cases": [case("a"), case("b")], "total": 2, "page": 1, "per_page": 100}),
            ))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.case = true;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert_eq!(
            failures,
            [Failure::kept(CASE, "more than one marker case matches")]
        );
        assert!(compose.session.ownership.case);
        assert_eq!(requests(&server).await.len(), 1);
    }

    #[tokio::test]
    async fn the_list_is_kept_while_it_still_holds_items() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/exception_lists"))
            .respond_with(ok(json!({"list_id": LIST_ID, "namespace_type": "single",
                "tags": ["elasticctl", "fixture", ALERT_MARKER_TAG], "id": "list-1"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(ITEMS_FIND_PATH))
            .respond_with(ok(
                json!({"data": [{}], "total": 1, "page": 1, "per_page": 1}),
            ))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.list = true;
        compose.ids.list = Some("list-1".into());

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert_eq!(failures, [Failure::kept(LIST, "it still holds items")]);
        assert!(compose.session.ownership.list);
        assert!(
            requests(&server)
                .await
                .iter()
                .all(|r| r.starts_with("GET "))
        );
    }

    #[tokio::test]
    async fn an_index_without_a_recorded_uuid_is_never_deleted() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(index_uuid_path()))
            .respond_with(ok(
                json!({(ALERT_PROBE_INDEX): {"settings": {"index": {"uuid": "uuid-1"}}}}),
            ))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        compose.session.ownership.alert_index = true;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert_eq!(failures, [Failure::unrecorded(INDEX)]);
        assert!(compose.session.ownership.alert_index);
        assert_eq!(
            requests(&server).await,
            [format!("GET {}", index_uuid_path())]
        );
    }

    #[tokio::test]
    async fn objects_already_gone_are_released_after_one_read_each() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(not_found())
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut compose = ComposeSession::new(&t);
        let owned = &mut compose.session.ownership;
        owned.alert_rule = true;
        owned.compose_rule = true;
        owned.item = true;
        owned.compose_item = true;
        owned.list = true;

        let failures = cleanup(&mut compose, &Timing::INSTANT).await;

        assert!(failures.is_empty(), "{failures:?}");
        assert!(still_owned(&compose).is_empty());
        assert_eq!(requests(&server).await.len(), 5);
    }

    #[test]
    fn failure_text_keeps_only_the_class_and_status() {
        let error = Error::with_status(
            ErrorKind::Http,
            500,
            "https://private.example.internal:9243 refused",
        );
        let failure = Failure::request("deleting", RULE, &error);
        assert_eq!(
            failure.to_string(),
            "deleting rule elasticctl-sample-alert-probe: class=http status=500"
        );
    }
}
