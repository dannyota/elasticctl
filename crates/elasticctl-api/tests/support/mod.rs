//! A `wiremock` stack that records which requests were writes.
//!
//! The log comes from the server's `received_requests`, not from a wrapper
//! around `Transport`. A wrapper would sit in the one place `--debug` must
//! never log, and would have to be maintained alongside it.

use elasticctl_core::{Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RULES: &str = "/api/detection_engine/rules";
const RULES_FIND: &str = "/api/detection_engine/rules/_find";

/// One non-GET request the stack received, in order.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub body: Value,
}

/// A mock Elastic stack with a recording server and a transport pointed at it.
pub struct MockStack {
    server: MockServer,
    transport: Transport,
}

impl MockStack {
    pub async fn new() -> MockStack {
        let server = MockServer::start().await;
        Self::mount_baseline(&server).await;
        let transport = Transport::new(&Self::profile(&server.uri())).expect("mock transport");
        MockStack { server, transport }
    }

    fn profile(uri: &str) -> Profile {
        Profile {
            kibana_url: uri.to_string(),
            es_url: None,
            api_key: Some("essu_test".into()),
            username: None,
            password: None,
            space: "default".into(),
            verify: true,
            timeout_secs: 5,
        }
    }

    /// Serve the endpoints every command needs for a capability probe:
    /// status, spaces, license, and identity.
    async fn mount_baseline(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": {"number": "9.5.1", "build_flavor": "traditional"}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/spaces/space"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": "default"}])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/_license"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "license": {"type": "platinum"}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/_security/_authenticate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "username": "elastic",
                "authentication_realm": {"type": "native"}
            })))
            .mount(server)
            .await;
    }

    /// The server's base URL, e.g. `http://127.0.0.1:PORT`. The `-cli` helper
    /// writes it into the profile it selects.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Every non-GET request the stack received, in order.
    pub async fn write_requests(&self) -> Vec<RecordedRequest> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method != http::Method::GET)
            .map(|r| RecordedRequest {
                method: r.method.to_string(),
                path: r.url.path().to_string(),
                body: r.body_json().unwrap_or(Value::Null),
            })
            .collect()
    }

    /// Just the paths, prefixed by method: "POST /api/…".
    pub async fn write_paths(&self) -> Vec<String> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method != http::Method::GET)
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect()
    }

    /// The JSON body of the most recent write to the rules endpoint.
    pub async fn last_rule_write_body(&self) -> Value {
        self.write_requests()
            .await
            .into_iter()
            .rev()
            .find(|r| r.path == RULES)
            .map(|r| r.body)
            .unwrap_or(Value::Null)
    }

    /// The `item_id` of every DELETE to the exception-list items endpoint.
    pub async fn deleted_item_ids(&self) -> Vec<String> {
        Self::deleted_ids(&self.server, "/api/exception_lists/items", "item_id").await
    }

    /// The `list_id` of every DELETE to the exception-list containers endpoint.
    pub async fn deleted_list_ids(&self) -> Vec<String> {
        Self::deleted_ids(&self.server, "/api/exception_lists", "list_id").await
    }

    async fn deleted_ids(server: &MockServer, path: &str, key: &str) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method == http::Method::DELETE && r.url.path() == path)
            .filter_map(|r| {
                r.url
                    .query_pairs()
                    .find(|(k, _)| k.as_ref() == key)
                    .map(|(_, v)| v.into_owned())
            })
            .collect()
    }

    /// A stack pre-seeded with `rules`: the `_find` corpus and a `rule_id`
    /// lookup for each rule.
    pub async fn with_rules(rules: Vec<Value>) -> MockStack {
        let stack = Self::new().await;
        let total = rules.len();
        let data = rules.clone();

        Mock::given(method("GET"))
            .and(path(RULES_FIND))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "page": 1, "perPage": 10000, "total": total, "data": data
            })))
            .mount(&stack.server)
            .await;

        for rule in rules {
            if let Some(id) = rule.get("rule_id").and_then(Value::as_str) {
                Mock::given(method("GET"))
                    .and(path(RULES))
                    .and(query_param("rule_id", id))
                    .respond_with(ResponseTemplate::new(200).set_body_json(rule))
                    .mount(&stack.server)
                    .await;
            }
        }

        stack
    }

    /// A stack whose exception-list shape is seeded by Task 9. The response
    /// shapes are measured there, so this returns the base stack for now.
    pub async fn with_exception_lists(_n: usize) -> MockStack {
        Self::new().await
    }
}
