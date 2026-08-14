//! A `wiremock` stack that records which requests were writes.
//!
//! The log comes from the server's `received_requests`, not from a wrapper
//! around `Transport`. A wrapper would sit in the one place `--debug` must
//! never log, and would have to be maintained alongside it.

use elasticctl_core::{Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

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

    /// A stack pre-seeded with `n` exception-list containers named `l0..l{n-1}`,
    /// plus a `?list_id=` lookup for each so `resolve_ids` and `get_list` work.
    pub async fn with_exception_lists(n: usize) -> MockStack {
        let stack = Self::new().await;
        let data: Vec<Value> = (0..n).map(list_json).collect();

        Mock::given(method("GET"))
            .and(path("/api/exception_lists/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": data,
                "page": 1,
                "per_page": n,
                "total": n
            })))
            .mount(&stack.server)
            .await;

        for i in 0..n {
            let list = list_json(i);
            Mock::given(method("GET"))
                .and(path("/api/exception_lists"))
                .and(query_param("list_id", format!("l{i}")))
                .and(query_param("namespace_type", "single"))
                .respond_with(ResponseTemplate::new(200).set_body_json(list.clone()))
                .mount(&stack.server)
                .await;
            // The export route resolves `id` first, then posts by both the
            // volatile `id` and the stable identity (fact E). Serve one list
            // line so `exceptions export` produces an importable body.
            Mock::given(method("POST"))
                .and(path("/api/exception_lists/_export"))
                .and(query_param("id", format!("id-l{i}")))
                .and(query_param("list_id", format!("l{i}")))
                .and(query_param("namespace_type", "single"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!("{list}\n")))
                .mount(&stack.server)
                .await;
        }

        stack
    }

    /// A stack pre-seeded with `n` items in container `l` (single namespace).
    /// The `_find` route pages: its `page_size` caps below `n`, so a caller
    /// that reads only the first page silently loses items.
    pub async fn with_exception_items(n: usize) -> MockStack {
        let stack = Self::new().await;
        let items: Vec<Value> = (0..n).map(item_json).collect();
        let page_size = 100;

        Mock::given(method("GET"))
            .and(path("/api/exception_lists/items/_find"))
            .respond_with(PagedItems { items, page_size })
            .mount(&stack.server)
            .await;

        stack
    }
}

fn list_json(i: usize) -> Value {
    json!({
        "id": format!("id-l{i}"),
        "list_id": format!("l{i}"),
        "type": "detection",
        "name": format!("list l{i}"),
        "description": "sample",
        "immutable": false,
        "namespace_type": "single",
        "os_types": [],
        "tags": ["sample"]
    })
}

fn item_json(i: usize) -> Value {
    json!({
        "id": format!("id-i{i}"),
        "item_id": format!("i{i}"),
        "list_id": "l",
        "type": "simple",
        "name": format!("item {i}"),
        "namespace_type": "single",
        "entries": []
    })
}

/// A container body for `list_id`, with an optional live `id`.
fn container_json(list_id: &str, namespace: &str, list_type: &str, id: Option<&str>) -> Value {
    let mut list = json!({
        "list_id": list_id,
        "type": list_type,
        "name": format!("list {list_id}"),
        "namespace_type": namespace,
    });
    if let Some(id) = id {
        list["id"] = json!(id);
    }
    list
}

/// An item body for `item_id` inside `list_id`.
fn item_for(list_id: &str, item_id: &str, namespace: &str) -> Value {
    json!({
        "id": format!("id-{item_id}"),
        "item_id": item_id,
        "list_id": list_id,
        "type": "simple",
        "name": format!("item {item_id}"),
        "namespace_type": namespace,
        "entries": []
    })
}

async fn mount_get_list(
    server: &MockServer,
    list_id: &str,
    namespace: &str,
    list_type: &str,
    id: Option<&str>,
) {
    Mock::given(method("GET"))
        .and(path("/api/exception_lists"))
        .and(query_param("list_id", list_id))
        .and(query_param("namespace_type", namespace))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(container_json(list_id, namespace, list_type, id)),
        )
        .mount(server)
        .await;
}

async fn mount_items(server: &MockServer, list_id: &str, namespace: &str, items: Vec<Value>) {
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/items/_find"))
        .and(query_param("list_id", list_id))
        .and(query_param("namespace_type", namespace))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": items,
            "page": 1,
            "per_page": items.len(),
            "total": items.len()
        })))
        .mount(server)
        .await;
}

/// One rule references `list_id`; the list corpus also holds an orphan the rule
/// does not reference, so `pull` must mirror only the referenced list.
pub async fn mock_stack_with_rule_referencing(list_id: &str) -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "list_id": list_id,
            "type": "detection",
            "namespace_type": "single"
        }]
    });
    let stack = MockStack::with_rules(vec![rule]).await;

    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                container_json(list_id, "single", "detection", None),
                container_json("orphan", "single", "detection", None)
            ],
            "page": 1,
            "per_page": 2,
            "total": 2
        })))
        .mount(&stack.server)
        .await;
    mount_get_list(&stack.server, list_id, "single", "detection", None).await;
    mount_items(&stack.server, list_id, "single", vec![]).await;
    stack
}

/// One rule references a `rule_default` list holding one item.
pub async fn mock_stack_with_rule_default_list() -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "list_id": "rd",
            "type": "rule_default",
            "namespace_type": "single"
        }]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, "rd", "single", "rule_default", Some("id-rd")).await;
    mount_items(
        &stack.server,
        "rd",
        "single",
        vec![item_for("rd", "i1", "single")],
    )
    .await;
    stack
}

/// One rule references the same `list_id` in both namespaces, which collide on
/// a single filename.
pub async fn mock_stack_with_colliding_namespaces(list_id: &str) -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [
            {"list_id": list_id, "type": "detection", "namespace_type": "single"},
            {"list_id": list_id, "type": "detection", "namespace_type": "agnostic"}
        ]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", None).await;
    mount_get_list(&stack.server, list_id, "agnostic", "detection", None).await;
    mount_items(&stack.server, list_id, "single", vec![]).await;
    mount_items(&stack.server, list_id, "agnostic", vec![]).await;
    stack
}

/// An empty rule corpus whose `get_list` for `list_id` returns the given live
/// `id`, so a push can resolve the pointer against this stack.
pub async fn mock_stack_with_list_id(list_id: &str, id: &str) -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", Some(id)).await;
    stack
}

/// An empty rule corpus with container and item create responses mounted, so a
/// push that creates a new list can resolve its live id and order its writes.
pub async fn mock_empty_stack() -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new-live-id",
            "list_id": "newlist",
            "type": "detection",
            "name": "newlist",
            "namespace_type": "single"
        })))
        .mount(&stack.server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "new-item-id",
            "item_id": "i1",
            "list_id": "newlist",
            "type": "simple",
            "name": "item i1",
            "namespace_type": "single",
            "entries": []
        })))
        .mount(&stack.server)
        .await;
    stack
}

/// Serves `total` items across pages of `page_size`, honouring the `page` query
/// parameter so callers that stop after one page come up short.
struct PagedItems {
    items: Vec<Value>,
    page_size: usize,
}

impl Respond for PagedItems {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let page: usize = request
            .url
            .query_pairs()
            .find_map(|(k, v)| (k.as_ref() == "page").then(|| v.into_owned()))
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let start = page.saturating_sub(1) * self.page_size;
        let data: Vec<Value> = self
            .items
            .iter()
            .skip(start)
            .take(self.page_size)
            .cloned()
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "data": data,
            "page": page,
            "per_page": self.page_size,
            "total": self.items.len()
        }))
    }
}
