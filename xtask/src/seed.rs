use crate::diagnostics::recording_error;
use crate::environment::transport_from_env;
use serde_json::{Value, json};

pub(crate) fn prebuilt_is_current(status: &Value) -> elasticctl_core::Result<bool> {
    let fields = [
        "rules_not_installed",
        "rules_not_updated",
        "timelines_not_installed",
        "timelines_not_updated",
    ];
    fields.iter().try_fold(true, |current, field| {
        let count = status.get(*field).and_then(Value::as_u64).ok_or_else(|| {
            recording_error(format!(
                "prebuilt status field {field} must be a non-negative integer"
            ))
        })?;
        Ok(current && count == 0)
    })
}

#[derive(Debug)]
pub(crate) enum PrebuiltConvergenceError {
    Put {
        attempt: usize,
        error: elasticctl_core::Error,
    },
    Get {
        attempt: usize,
        error: elasticctl_core::Error,
    },
    Schema {
        attempt: usize,
        error: elasticctl_core::Error,
    },
    Exhausted {
        attempts: usize,
        last_status: Value,
    },
}

impl PrebuiltConvergenceError {
    fn public_summary(&self) -> String {
        let (class, attempt, status) = match self {
            Self::Put { attempt, error } => ("put", *attempt, error.http_status),
            Self::Get { attempt, error } => ("get", *attempt, error.http_status),
            Self::Schema { attempt, .. } => ("schema", *attempt, None),
            Self::Exhausted { attempts, .. } => ("exhausted", *attempts, None),
        };
        let status = status.map_or_else(|| "none".to_string(), |value| value.to_string());
        format!("class={class} attempt={attempt} status={status}")
    }

    pub(crate) fn private_detail(&self) -> String {
        match self {
            Self::Put { attempt, error } => {
                format!("prebuilt PUT attempt {attempt}: {}", error.message)
            }
            Self::Get { attempt, error } => {
                format!("prebuilt GET attempt {attempt}: {}", error.message)
            }
            Self::Schema { attempt, error } => {
                format!("prebuilt status attempt {attempt}: {}", error.message)
            }
            Self::Exhausted {
                attempts,
                last_status,
            } => format!("prebuilt convergence exhausted after {attempts} attempts: {last_status}"),
        }
    }
}

const PREBUILT_CONVERGENCE_ATTEMPTS: usize = 5;

pub(crate) async fn converge_prebuilt_rules(
    transport: &elasticctl_core::Transport,
) -> Result<usize, PrebuiltConvergenceError> {
    let mut last_status = Value::Null;
    for attempt in 1..=PREBUILT_CONVERGENCE_ATTEMPTS {
        transport
            .put_once("/api/detection_engine/rules/prepackaged", &json!({}))
            .await
            .map_err(|error| PrebuiltConvergenceError::Put { attempt, error })?;
        let status = transport
            .get("/api/detection_engine/rules/prepackaged/_status")
            .await
            .map_err(|error| PrebuiltConvergenceError::Get { attempt, error })?;
        match prebuilt_is_current(&status) {
            Ok(true) => return Ok(attempt),
            Ok(false) => last_status = status,
            Err(error) => return Err(PrebuiltConvergenceError::Schema { attempt, error }),
        }
    }
    Err(PrebuiltConvergenceError::Exhausted {
        attempts: PREBUILT_CONVERGENCE_ATTEMPTS,
        last_status,
    })
}

pub(crate) fn prebuilt_install_is_noop(response: &Value) -> elasticctl_core::Result<bool> {
    let fields = [
        "rules_installed",
        "rules_updated",
        "timelines_installed",
        "timelines_updated",
    ];
    fields.iter().try_fold(true, |current, field| {
        let count = response
            .get(*field)
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                recording_error(format!(
                    "prebuilt install field {field} must be a non-negative integer"
                ))
            })?;
        Ok(current && count == 0)
    })
}

pub(super) async fn seed() {
    let t = transport_from_env(600);
    match converge_prebuilt_rules(&t).await {
        Ok(attempts) => println!("prebuilt convergence succeeded: attempts={attempts}"),
        Err(error) => {
            eprintln!("prebuilt convergence failed: {}", error.public_summary());
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recorder::test_support::mock_transport;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn prebuilt_status(outstanding: u64) -> Value {
        json!({
            "rules_not_installed": outstanding,
            "rules_not_updated": outstanding,
            "timelines_not_installed": outstanding,
            "timelines_not_updated": outstanding,
        })
    }

    #[test]
    fn prebuilt_current_requires_each_outstanding_counter_to_be_zero_u64() {
        assert!(prebuilt_is_current(&prebuilt_status(0)).expect("all zero"));
        for field in [
            "rules_not_installed",
            "rules_not_updated",
            "timelines_not_installed",
            "timelines_not_updated",
        ] {
            let mut noncurrent = prebuilt_status(0);
            noncurrent[field] = json!(1);
            assert!(!prebuilt_is_current(&noncurrent).expect("valid noncurrent status"));

            let mut malformed = prebuilt_status(0);
            malformed[field] = json!("0");
            assert!(prebuilt_is_current(&malformed).is_err());

            let mut negative = prebuilt_status(0);
            negative[field] = json!(-1);
            assert!(prebuilt_is_current(&negative).is_err());
        }
    }

    #[tokio::test]
    async fn prebuilt_convergence_current_on_first_pair_uses_exact_empty_object() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(prebuilt_status(0)))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            converge_prebuilt_rules(&mock_transport(&server))
                .await
                .unwrap(),
            1
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method.as_str(), "PUT");
        assert_eq!(requests[1].method.as_str(), "GET");
    }

    #[tokio::test]
    async fn prebuilt_convergence_retries_only_valid_false_status_in_order() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(prebuilt_status(1)))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(prebuilt_status(0)))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            converge_prebuilt_rules(&mock_transport(&server))
                .await
                .unwrap(),
            2
        );
        let requests = server.received_requests().await.expect("requests");
        let methods: Vec<_> = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(methods, ["PUT", "GET", "PUT", "GET"]);
    }

    #[tokio::test]
    async fn prebuilt_convergence_stops_after_exactly_five_pairs() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(PREBUILT_CONVERGENCE_ATTEMPTS as u64)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(prebuilt_status(1)))
            .expect(PREBUILT_CONVERGENCE_ATTEMPTS as u64)
            .mount(&server)
            .await;

        let error = converge_prebuilt_rules(&mock_transport(&server))
            .await
            .expect_err("five noncurrent statuses must exhaust");
        assert!(matches!(
            error,
            PrebuiltConvergenceError::Exhausted { attempts: 5, .. }
        ));
        assert_eq!(
            error.public_summary(),
            "class=exhausted attempt=5 status=none"
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 10);
        for (cycle, pair) in requests.chunks_exact(2).enumerate() {
            assert_eq!(pair[0].method.as_str(), "PUT", "cycle {cycle}");
            assert_eq!(
                pair[0].url.path(),
                "/api/detection_engine/rules/prepackaged",
                "cycle {cycle}"
            );
            assert_eq!(
                pair[0].body_json::<Value>().expect("PUT JSON body"),
                json!({}),
                "cycle {cycle}"
            );
            assert_eq!(pair[1].method.as_str(), "GET", "cycle {cycle}");
            assert_eq!(
                pair[1].url.path(),
                "/api/detection_engine/rules/prepackaged/_status",
                "cycle {cycle}"
            );
        }
    }

    #[tokio::test]
    async fn prebuilt_convergence_put_failure_is_one_shot_and_does_not_leak() {
        for response in [
            ResponseTemplate::new(429).set_body_json(json!({"message": "private-put-429"})),
            ResponseTemplate::new(500).set_body_json(json!({"message": "private-put-500"})),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("PUT"))
                .and(path("/api/detection_engine/rules/prepackaged"))
                .and(body_json(json!({})))
                .respond_with(response)
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path("/api/detection_engine/rules/prepackaged"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
                .expect(0)
                .mount(&server)
                .await;
            let error = converge_prebuilt_rules(&mock_transport(&server))
                .await
                .expect_err("one-shot prebuilt PUT failure");
            let summary = error.public_summary();
            assert!(summary.contains("class=put attempt=1"));
            assert!(!summary.contains("private-put-429"));
            assert!(!summary.contains("private-put-500"));
            let requests = server.received_requests().await.expect("requests");
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].method.as_str(), "PUT");
        }
    }

    #[tokio::test]
    async fn prebuilt_convergence_schema_failure_stops_after_one_status_get() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"rules_not_installed": 0})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let error = converge_prebuilt_rules(&mock_transport(&server))
            .await
            .expect_err("schema failure must stop");
        assert!(error.public_summary().contains("class=schema attempt=1"));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method.as_str(), "PUT");
        assert_eq!(requests[1].method.as_str(), "GET");
    }

    #[tokio::test]
    async fn prebuilt_convergence_retries_a_transient_status_get_without_a_second_cycle() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(prebuilt_status(0)))
            .expect(1)
            .mount(&server)
            .await;

        assert_eq!(
            converge_prebuilt_rules(&mock_transport(&server))
                .await
                .unwrap(),
            1
        );
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            ["PUT", "GET", "GET"]
        );
    }

    #[tokio::test]
    async fn prebuilt_convergence_stops_after_terminal_status_get_retries_without_a_second_cycle() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .and(body_json(json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(
                ResponseTemplate::new(503).set_body_json(json!({"message": "private-status-body"})),
            )
            .expect(3)
            .mount(&server)
            .await;

        let error = converge_prebuilt_rules(&mock_transport(&server))
            .await
            .expect_err("terminal status GET failure must stop convergence");
        assert_eq!(error.public_summary(), "class=get attempt=1 status=503");
        assert!(!error.public_summary().contains("private-status-body"));
        let requests = server.received_requests().await.expect("requests");
        assert_eq!(
            requests
                .iter()
                .map(|request| (request.method.as_str(), request.url.path()))
                .collect::<Vec<_>>(),
            [
                ("PUT", "/api/detection_engine/rules/prepackaged"),
                ("GET", "/api/detection_engine/rules/prepackaged/_status"),
                ("GET", "/api/detection_engine/rules/prepackaged/_status"),
                ("GET", "/api/detection_engine/rules/prepackaged/_status"),
            ]
        );
    }
}
