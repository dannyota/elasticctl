//! Async columnar ES|QL exchange, as `search esql --out` sends it.

use crate::diagnostics::{
    recording_error, safe_recording_error_summary, safe_recording_transport_error,
};
use crate::fixtures::{RecordedFixture, exchange_fixture, response_fixture};
use crate::recorder::preview::ESQL_ASYNC_VOLATILE_FIELDS;
use crate::recorder::session::RecordingSession;
use crate::scrub::strip_volatile;
use serde_json::{Value, json};
use std::time::Duration;

/// Fixed stand-in for the per-run async query id. The id encodes the
/// coordinating node and task, so a re-record would differ without it.
pub(crate) const ESQL_ASYNC_ID_PLACEHOLDER: &str = "elasticctl-fixture-esql-async";

/// Start attempts before the recorder gives up on the running branch. A query
/// that finishes inside the 1ms wait returns its rows inline, which leaves no
/// poll or delete to record.
const START_ATTEMPTS: usize = 5;

/// Poll budget for the recorded query. The probe reads three documents, so a
/// query still running after this many polls means the stack is unhealthy.
const MAX_POLLS: usize = 30;

/// Production poll interval, matching `elasticctl_api::search::esql::run_async`.
pub(super) const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The body `elasticctl_api::search::esql::run_async` sends.
fn start_body(query: &str) -> Value {
    json!({"query": query, "wait_for_completion_timeout": "1ms", "columnar": true})
}

fn async_path(id: &str) -> String {
    format!("/_query/async/{id}")
}

/// Replace the top-level async id, when present, with the fixed placeholder.
fn redact_async_id(value: &mut Value) {
    if let Some(id) = value.get_mut("id") {
        *id = json!(ESQL_ASYNC_ID_PLACEHOLDER);
    }
}

/// Drop per-run counters and timestamps and pin the async id. `is_running`
/// and `is_partial` stay: they decide whether a client polls.
fn scrub_async(mut body: Value) -> Value {
    strip_volatile(&mut body, ESQL_ASYNC_VOLATILE_FIELDS);
    redact_async_id(&mut body);
    body
}

/// Delete one stored async result. Session ownership of the id ends only when
/// the delete succeeds or the result is already gone.
async fn delete_owned(
    session: &mut RecordingSession<'_>,
    id: &str,
) -> elasticctl_core::Result<Value> {
    let result = session.transport.delete_absolute_es(&async_path(id)).await;
    let released = match &result {
        Ok(_) => true,
        Err(error) => error.kind == elasticctl_core::ErrorKind::NotFound,
    };
    if released {
        session.ownership.esql_async_ids.retain(|owned| owned != id);
    }
    result.map_err(|error| {
        safe_recording_transport_error("deleting async ES|QL result failed", error)
    })
}

/// Record the start, the completed poll, and the delete of one async columnar
/// ES|QL query. Every id a start returns is owned by the session until its
/// delete succeeds, so session cleanup retries any delete that fails here.
pub(super) async fn record_esql_async(
    session: &mut RecordingSession<'_>,
    query: &str,
    flavor: &str,
    version: &str,
    interval: Duration,
) -> elasticctl_core::Result<Vec<RecordedFixture>> {
    let request = start_body(query);
    let mut started = None;
    for _ in 0..START_ATTEMPTS {
        let start = session
            .transport
            .post_absolute_es("/_query/async", &request)
            .await
            .map_err(|error| {
                safe_recording_transport_error("starting async ES|QL query failed", error)
            })?;
        let Some(id) = start.get("id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        session.ownership.esql_async_ids.push(id.clone());
        if start.get("is_running").and_then(Value::as_bool) == Some(true) {
            started = Some((id, start));
            break;
        }
        // A completed query that still returned an id is stored; remove it.
        delete_owned(session, &id).await?;
    }
    let (id, start) = started.ok_or_else(|| {
        recording_error("async ES|QL query finished inside its wait on every start attempt")
    })?;

    let polled = poll(session.transport, &async_path(&id), interval).await;
    let deleted = delete_owned(session, &id).await;
    let complete = polled?;
    let deleted = deleted?;

    Ok(vec![
        exchange_fixture(
            "esql_async_start",
            flavor,
            version,
            request,
            scrub_async(start),
        ),
        response_fixture(
            "esql_async_get",
            flavor,
            version,
            scrub_async(complete),
            None,
        ),
        response_fixture("esql_async_delete", flavor, version, deleted, None),
    ])
}

async fn poll(
    t: &elasticctl_core::Transport,
    path: &str,
    interval: Duration,
) -> elasticctl_core::Result<Value> {
    for _ in 0..MAX_POLLS {
        let response = t.get_absolute_es(path).await.map_err(|error| {
            safe_recording_transport_error("polling async ES|QL query failed", error)
        })?;
        if response.get("is_running").and_then(Value::as_bool) == Some(false) {
            return Ok(response);
        }
        tokio::time::sleep(interval).await;
    }
    Err(recording_error(format!(
        "async ES|QL query still running after {MAX_POLLS} polls"
    )))
}

impl RecordingSession<'_> {
    /// Delete every async ES|QL result the recording still owns. Failures keep
    /// ownership and report only the error class and status.
    pub(crate) async fn cleanup_esql_async(&mut self, errors: &mut Vec<String>) {
        for id in self.ownership.esql_async_ids.clone() {
            if let Err(error) = delete_owned(self, &id).await
                && error.kind != elasticctl_core::ErrorKind::NotFound
            {
                errors.push(format!(
                    "deleting async ES|QL result: {}",
                    safe_recording_error_summary(&error)
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::preview::{SEARCH_MARKER, SEARCH_PROBE_INDEX};
    use crate::recorder::session::CleanupOwnership;
    use crate::recorder::test_support::mock_transport;
    use std::sync::Mutex;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const QUERY: &str = "FROM elasticctl-sample-search | SORT seq ASC | LIMIT 2";

    fn running(id: &str) -> Value {
        json!({"id": id, "is_running": true, "took": 1, "start_time_in_millis": 1,
            "expiration_time_in_millis": 2, "driver_nanos": 3, "columns": [], "values": []})
    }

    fn complete() -> Value {
        json!({"is_running": false, "is_partial": false, "took": 4, "documents_found": 3,
            "completion_time_in_millis": 5, "read_cpu_nanos": 6,
            "columns": [{"name": "seq", "type": "long"}], "values": [[1, 2]]})
    }

    fn inline() -> Value {
        json!({"is_running": false, "columns": [], "values": []})
    }

    fn sequence(responses: Vec<ResponseTemplate>) -> impl Fn(&Request) -> ResponseTemplate {
        let responses = Mutex::new(responses.into_iter());
        move |_: &Request| {
            let next = responses.lock().expect("responses").next();
            next.expect("unexpected request")
        }
    }

    fn ok(body: Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    fn failure(status: u16) -> ResponseTemplate {
        // A body naming a private host, the async id, and an identity must
        // never reach a recorder error.
        ResponseTemplate::new(status).set_body_json(json!({"error": {
            "reason": "a1 on private.example.internal for operator@example.internal"
        }}))
    }

    async fn mount_start(server: &MockServer, responses: Vec<Value>) {
        Mock::given(method("POST"))
            .and(path("/_query/async"))
            .and(body_json(start_body(QUERY)))
            .respond_with(sequence(responses.into_iter().map(ok).collect()))
            .mount(server)
            .await;
    }

    async fn mount_poll(server: &MockServer, id: &str, responses: Vec<ResponseTemplate>) {
        Mock::given(method("GET"))
            .and(path(async_path(id)))
            .respond_with(sequence(responses))
            .mount(server)
            .await;
    }

    async fn mount_delete(server: &MockServer, id: &str, responses: Vec<ResponseTemplate>) {
        Mock::given(method("DELETE"))
            .and(path(async_path(id)))
            .respond_with(sequence(responses))
            .mount(server)
            .await;
    }

    fn acknowledged() -> ResponseTemplate {
        ok(json!({"acknowledged": true}))
    }

    async fn requests(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .expect("requests")
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect()
    }

    async fn record(
        server: &MockServer,
    ) -> (elasticctl_core::Result<Vec<RecordedFixture>>, Vec<String>) {
        let t = mock_transport(server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        let result =
            record_esql_async(&mut session, QUERY, "serverless", "9.7.0", Duration::ZERO).await;
        (result, session.ownership.esql_async_ids)
    }

    fn assert_private_text_absent(error: &elasticctl_core::Error, server: &MockServer) {
        for private in ["a1", "private.example.internal", "operator@", &server.uri()] {
            assert!(!error.message.contains(private), "{}", error.message);
        }
    }

    #[tokio::test]
    async fn records_the_running_branch_and_deletes_the_query() {
        let server = MockServer::start().await;
        mount_start(&server, vec![inline(), running("a1")]).await;
        mount_poll(&server, "a1", vec![ok(running("a1")), ok(complete())]).await;
        mount_delete(&server, "a1", vec![acknowledged()]).await;

        let (fixtures, owned) = record(&server).await;
        let fixtures = fixtures.expect("recorded");

        assert!(owned.is_empty());
        assert_eq!(
            requests(&server).await,
            [
                "POST /_query/async",
                "POST /_query/async",
                "GET /_query/async/a1",
                "GET /_query/async/a1",
                "DELETE /_query/async/a1",
            ]
        );
        let names: Vec<_> = fixtures.iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            ["esql_async_start", "esql_async_get", "esql_async_delete"]
        );
        let start = &fixtures[0].document;
        assert_eq!(start["request"], start_body(QUERY));
        assert_eq!(
            start["response"],
            json!({"id": ESQL_ASYNC_ID_PLACEHOLDER, "is_running": true, "columns": [], "values": []})
        );
        assert_eq!(
            fixtures[1].document["response"],
            json!({"is_running": false, "is_partial": false,
                "columns": [{"name": "seq", "type": "long"}], "values": [[1, 2]]})
        );
        assert_eq!(
            fixtures[2].document["response"],
            json!({"acknowledged": true})
        );
    }

    #[tokio::test]
    async fn a_completed_start_with_an_id_is_deleted_before_retrying() {
        let server = MockServer::start().await;
        let mut stored = complete();
        stored["id"] = json!("done");
        mount_start(&server, vec![stored, running("a1")]).await;
        mount_poll(&server, "a1", vec![ok(complete())]).await;
        mount_delete(&server, "done", vec![acknowledged()]).await;
        mount_delete(&server, "a1", vec![acknowledged()]).await;

        let (result, owned) = record(&server).await;

        result.expect("recorded");
        assert!(owned.is_empty());
        assert_eq!(
            requests(&server).await,
            [
                "POST /_query/async",
                "DELETE /_query/async/done",
                "POST /_query/async",
                "GET /_query/async/a1",
                "DELETE /_query/async/a1",
            ]
        );
    }

    #[tokio::test]
    async fn every_completed_start_is_deleted_and_the_recording_fails() {
        let server = MockServer::start().await;
        let starts = (0..START_ATTEMPTS)
            .map(|n| {
                let mut stored = complete();
                stored["id"] = json!(format!("done{n}"));
                stored
            })
            .collect();
        mount_start(&server, starts).await;
        for n in 0..START_ATTEMPTS {
            mount_delete(&server, &format!("done{n}"), vec![acknowledged()]).await;
        }

        let (result, owned) = record(&server).await;

        let error = result.err().expect("no running start");
        assert!(error.message.contains("every start attempt"));
        assert!(owned.is_empty());
        let deletes = requests(&server)
            .await
            .into_iter()
            .filter(|r| r.starts_with("DELETE"))
            .count();
        assert_eq!(deletes, START_ATTEMPTS);
    }

    #[tokio::test]
    async fn every_inline_start_is_an_error() {
        let server = MockServer::start().await;
        mount_start(&server, vec![inline(); START_ATTEMPTS]).await;

        let (result, owned) = record(&server).await;

        let error = result.err().expect("no running start");
        assert!(error.message.contains("every start attempt"));
        assert!(owned.is_empty());
    }

    #[tokio::test]
    async fn a_failed_poll_still_deletes_the_query_and_hides_server_text() {
        let server = MockServer::start().await;
        mount_start(&server, vec![running("a1")]).await;
        mount_poll(&server, "a1", vec![failure(400)]).await;
        mount_delete(&server, "a1", vec![acknowledged()]).await;

        let (result, owned) = record(&server).await;

        let error = result.err().expect("poll failure");
        assert_private_text_absent(&error, &server);
        assert!(owned.is_empty());
        assert_eq!(
            requests(&server).await.last().map(String::as_str),
            Some("DELETE /_query/async/a1")
        );
    }

    #[tokio::test]
    async fn exhausted_polls_still_delete_the_query() {
        let server = MockServer::start().await;
        mount_start(&server, vec![running("a1")]).await;
        mount_poll(&server, "a1", vec![ok(running("a1")); MAX_POLLS]).await;
        mount_delete(&server, "a1", vec![acknowledged()]).await;

        let (result, owned) = record(&server).await;

        let error = result.err().expect("poll budget exhausted");
        assert!(error.message.contains("still running"));
        assert!(owned.is_empty());
        let reqs = requests(&server).await;
        assert_eq!(
            reqs.iter().filter(|r| r.starts_with("GET")).count(),
            MAX_POLLS
        );
        assert_eq!(
            reqs.last().map(String::as_str),
            Some("DELETE /_query/async/a1")
        );
    }

    #[tokio::test]
    async fn a_failed_delete_stays_owned_until_session_cleanup_removes_it() {
        let server = MockServer::start().await;
        mount_start(&server, vec![running("a1")]).await;
        mount_poll(&server, "a1", vec![ok(complete())]).await;
        mount_delete(&server, "a1", vec![failure(400), acknowledged()]).await;

        let t = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        let error = record_esql_async(&mut session, QUERY, "serverless", "9.7.0", Duration::ZERO)
            .await
            .err()
            .expect("delete failure");
        assert_private_text_absent(&error, &server);
        assert_eq!(session.ownership.esql_async_ids, ["a1"]);

        let mut errors = Vec::new();
        session.cleanup_esql_async(&mut errors).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(session.ownership.esql_async_ids.is_empty());
    }

    #[tokio::test]
    async fn a_failed_cleanup_delete_keeps_ownership_and_reports_only_its_class() {
        let server = MockServer::start().await;
        mount_delete(&server, "a1", vec![failure(400)]).await;
        let t = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        session.ownership.esql_async_ids.push("a1".into());

        let mut errors = Vec::new();
        session.cleanup_esql_async(&mut errors).await;

        assert_eq!(session.ownership.esql_async_ids, ["a1"]);
        assert_eq!(errors.len(), 1);
        for private in ["a1", "private.example.internal", "operator@"] {
            assert!(!errors[0].contains(private), "{}", errors[0]);
        }
    }

    #[tokio::test]
    async fn an_already_gone_result_releases_ownership_in_cleanup() {
        let server = MockServer::start().await;
        mount_delete(&server, "a1", vec![failure(404)]).await;
        let t = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        session.ownership.esql_async_ids.push("a1".into());

        let mut errors = Vec::new();
        session.cleanup_esql_async(&mut errors).await;

        assert!(errors.is_empty(), "{errors:?}");
        assert!(session.ownership.esql_async_ids.is_empty());
    }

    #[tokio::test]
    async fn a_poll_and_delete_failure_is_retried_by_full_session_cleanup() {
        let server = MockServer::start().await;
        mount_start(&server, vec![running("a1")]).await;
        mount_poll(&server, "a1", vec![failure(400)]).await;
        mount_delete(&server, "a1", vec![failure(400), failure(400)]).await;

        let t = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        let error = record_esql_async(&mut session, QUERY, "serverless", "9.7.0", Duration::ZERO)
            .await
            .err()
            .expect("poll failure");
        assert!(error.message.contains("polling"), "{}", error.message);
        assert_eq!(session.ownership.esql_async_ids, ["a1"]);

        let cleanup = session.cleanup().await.err().expect("cleanup failure");
        assert!(
            cleanup
                .message
                .contains("deleting async ES|QL result: class="),
            "{}",
            cleanup.message
        );
        assert_private_text_absent(&cleanup, &server);
        assert_eq!(session.ownership.esql_async_ids, ["a1"]);
        let deletes = requests(&server)
            .await
            .into_iter()
            .filter(|r| r == "DELETE /_query/async/a1")
            .count();
        assert_eq!(deletes, 2);
    }

    #[tokio::test]
    async fn a_failed_delete_of_a_completed_start_stays_owned() {
        let server = MockServer::start().await;
        let mut stored = complete();
        stored["id"] = json!("done");
        mount_start(&server, vec![stored]).await;
        mount_delete(&server, "done", vec![failure(400)]).await;

        let (result, owned) = record(&server).await;

        let error = result.err().expect("delete failure");
        assert_private_text_absent(&error, &server);
        assert_eq!(owned, ["done"]);
    }

    #[tokio::test]
    async fn session_cleanup_deletes_async_results_before_the_search_index() {
        let server = MockServer::start().await;
        mount_delete(&server, "a1", vec![acknowledged()]).await;
        Mock::given(method("GET"))
            .and(path(format!("/{SEARCH_PROBE_INDEX}/_doc/1")))
            .respond_with(ok(json!({"_source": {"marker": SEARCH_MARKER}})))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(format!("/{SEARCH_PROBE_INDEX}")))
            .respond_with(ok(json!({"acknowledged": true})))
            .mount(&server)
            .await;
        let t = mock_transport(&server);
        let mut session = RecordingSession {
            transport: &t,
            ownership: CleanupOwnership::default(),
        };
        session.ownership.esql_async_ids.push("a1".into());
        session.ownership.search_index = true;

        // The unmocked alert baseline audit fails; only the async and search
        // index steps matter here.
        let cleanup = session.cleanup().await.err().expect("unmocked audit");
        assert!(
            !cleanup.message.contains("async ES|QL"),
            "{}",
            cleanup.message
        );
        assert!(
            !cleanup.message.contains(SEARCH_PROBE_INDEX),
            "{}",
            cleanup.message
        );

        assert!(session.ownership.esql_async_ids.is_empty());
        assert!(!session.ownership.search_index);
        let relevant: Vec<String> = requests(&server)
            .await
            .into_iter()
            .filter(|r| r.contains("/_query/async/") || r.contains(SEARCH_PROBE_INDEX))
            .collect();
        assert_eq!(
            relevant,
            [
                "DELETE /_query/async/a1".to_string(),
                format!("GET /{SEARCH_PROBE_INDEX}/_doc/1"),
                format!("DELETE /{SEARCH_PROBE_INDEX}"),
            ]
        );
    }
}
