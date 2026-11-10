//! Async columnar ES|QL exchange, as `search esql --out` sends it.

use crate::diagnostics::recording_error;
use crate::fixtures::{RecordedFixture, exchange_fixture, response_fixture};
use crate::recorder::preview::ESQL_ASYNC_VOLATILE_FIELDS;
use crate::scrub::strip_volatile;
use elasticctl_core::Transport;
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

/// Replace the top-level async id, when present, with the fixed placeholder.
fn redact_async_id(value: &mut Value) {
    if let Some(id) = value.get_mut("id") {
        *id = json!(ESQL_ASYNC_ID_PLACEHOLDER);
    }
}

/// Drop per-run counters and timestamps and pin the async id. `is_running`
/// and `is_partial` stay: they decide whether the client polls.
fn scrub_async(mut body: Value) -> Value {
    strip_volatile(&mut body, ESQL_ASYNC_VOLATILE_FIELDS);
    redact_async_id(&mut body);
    body
}

/// Record the start, the completed poll, and the delete of one async columnar
/// ES|QL query. The async result is deleted on every path that obtained an id.
pub(super) async fn record_esql_async(
    t: &Transport,
    query: &str,
    flavor: &str,
    version: &str,
    interval: Duration,
) -> elasticctl_core::Result<Vec<RecordedFixture>> {
    let request = start_body(query);
    let mut started = None;
    for _ in 0..START_ATTEMPTS {
        let start = t.post_absolute_es("/_query/async", &request).await?;
        let Some(id) = start.get("id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if start.get("is_running").and_then(Value::as_bool) == Some(true) {
            started = Some((id, start));
            break;
        }
        // A completed query that still returned an id is stored; remove it.
        t.delete_absolute_es(&format!("/_query/async/{id}")).await?;
    }
    let (id, start) = started.ok_or_else(|| {
        recording_error("async ES|QL query finished inside its wait on every start attempt")
    })?;
    let path = format!("/_query/async/{id}");

    let polled = poll(t, &path, interval).await;
    let deleted = t.delete_absolute_es(&path).await;
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

async fn poll(t: &Transport, path: &str, interval: Duration) -> elasticctl_core::Result<Value> {
    for _ in 0..MAX_POLLS {
        let response = t.get_absolute_es(path).await?;
        if response.get("is_running").and_then(Value::as_bool) == Some(false) {
            return Ok(response);
        }
        tokio::time::sleep(interval).await;
    }
    Err(recording_error(format!(
        "async ES|QL query still running after {MAX_POLLS} polls"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::mock_transport;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    async fn mount_start(server: &MockServer, responses: Vec<Value>) {
        let responses = std::sync::Mutex::new(responses.into_iter());
        Mock::given(method("POST"))
            .and(path("/_query/async"))
            .and(body_json(start_body(QUERY)))
            .respond_with(move |_: &wiremock::Request| {
                let next = responses.lock().expect("responses").next();
                ResponseTemplate::new(200).set_body_json(next.expect("unexpected start"))
            })
            .mount(server)
            .await;
    }

    async fn mount_delete(server: &MockServer, id: &str, times: u64) {
        Mock::given(method("DELETE"))
            .and(path(format!("/_query/async/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"acknowledged": true})))
            .expect(times)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn records_the_running_branch_and_deletes_the_query() {
        let server = MockServer::start().await;
        let inline = json!({"is_running": false, "columns": [], "values": []});
        mount_start(&server, vec![inline, running("a1")]).await;
        let polls = std::sync::Mutex::new(vec![running("a1"), complete()].into_iter());
        Mock::given(method("GET"))
            .and(path("/_query/async/a1"))
            .respond_with(move |_: &wiremock::Request| {
                let next = polls.lock().expect("polls").next();
                ResponseTemplate::new(200).set_body_json(next.expect("unexpected poll"))
            })
            .expect(2)
            .mount(&server)
            .await;
        mount_delete(&server, "a1", 1).await;

        let t = mock_transport(&server);
        let fixtures = record_esql_async(&t, QUERY, "traditional", "9.5.1", Duration::ZERO)
            .await
            .expect("recorded");

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
        Mock::given(method("GET"))
            .and(path("/_query/async/a1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(complete()))
            .mount(&server)
            .await;
        mount_delete(&server, "done", 1).await;
        mount_delete(&server, "a1", 1).await;

        let t = mock_transport(&server);
        record_esql_async(&t, QUERY, "traditional", "9.5.1", Duration::ZERO)
            .await
            .expect("recorded");
    }

    #[tokio::test]
    async fn a_failed_poll_still_deletes_the_query() {
        let server = MockServer::start().await;
        mount_start(&server, vec![running("a1")]).await;
        Mock::given(method("GET"))
            .and(path("/_query/async/a1"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "boom"})))
            .mount(&server)
            .await;
        mount_delete(&server, "a1", 1).await;

        let t = mock_transport(&server);
        let result = record_esql_async(&t, QUERY, "traditional", "9.5.1", Duration::ZERO).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn every_inline_start_is_an_error() {
        let server = MockServer::start().await;
        let inline = json!({"is_running": false, "columns": [], "values": []});
        mount_start(&server, vec![inline; START_ATTEMPTS]).await;

        let t = mock_transport(&server);
        let error = record_esql_async(&t, QUERY, "traditional", "9.5.1", Duration::ZERO)
            .await
            .err()
            .expect("no running start");
        assert!(error.message.contains("every start attempt"));
    }
}
