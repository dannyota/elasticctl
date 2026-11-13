pub mod fleet;

use std::collections::BTreeMap;

use elasticctl_core::{Profile, Transport};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const RULES: &str = "/api/detection_engine/rules";
const RULES_FIND: &str = "/api/detection_engine/rules/_find";

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub body: Value,
    pub body_text: String,
}

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

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn server(&self) -> &MockServer {
        &self.server
    }

    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    pub async fn requests(&self) -> Vec<RecordedRequest> {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(recorded_request)
            .collect()
    }

    pub async fn write_requests(&self) -> Vec<RecordedRequest> {
        self.requests()
            .await
            .into_iter()
            .filter(|request| request.method != http::Method::GET.as_str())
            .collect()
    }

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

    pub async fn last_rule_write_body(&self) -> Value {
        self.write_requests()
            .await
            .into_iter()
            .rev()
            .find(|r| r.path == RULES)
            .map(|r| r.body)
            .unwrap_or(Value::Null)
    }

    pub async fn deleted_item_ids(&self) -> Vec<String> {
        Self::deleted_ids(&self.server, "/api/exception_lists/items", "item_id").await
    }

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

    pub async fn with_rules(rules: Vec<Value>) -> MockStack {
        let stack = Self::new().await;
        let data = rules.clone();

        Mock::given(method("GET"))
            .and(path(RULES_FIND))
            .respond_with(FilteredRules { rules: data })
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

    pub async fn with_source_totals(custom: u64, prebuilt: u64, all: u64) -> MockStack {
        let stack = Self::new().await;
        Mock::given(method("GET"))
            .and(path(RULES_FIND))
            .respond_with(SourceTotalsRules {
                custom,
                prebuilt,
                all,
            })
            .mount(&stack.server)
            .await;
        stack
    }

    pub async fn with_exception_lists(n: usize) -> MockStack {
        let stack = Self::new().await;
        let data: Vec<Value> = (0..n).map(list_json).collect();

        Mock::given(method("GET"))
            .and(path("/api/exception_lists/_find"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": data,
                "page": 1,
                "per_page": n.max(1),
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
            Mock::given(method("POST"))
                .and(path("/api/exception_lists/_export"))
                .and(query_param("id", format!("id-l{i}")))
                .and(query_param("list_id", format!("l{i}")))
                .and(query_param("namespace_type", "single"))
                .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                    "{list}\n{{\"exported_exception_list_count\":1,\"exported_exception_list_item_count\":0,\"missing_exception_lists\":[],\"missing_exception_list_items\":[]}}\n"
                )))
                .mount(&stack.server)
                .await;
        }

        stack
    }

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

    pub async fn with_prebuilt_status(status: Value, customized: u64) -> MockStack {
        let stack = Self::new().await;

        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(status))
            .mount(&stack.server)
            .await;
        Mock::given(method("GET"))
            .and(path(RULES_FIND))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "page": 1, "perPage": 1, "total": customized, "data": []
            })))
            .mount(&stack.server)
            .await;

        stack
    }

    pub async fn with_prebuilt_status_and_failing_find(status: Value) -> MockStack {
        let stack = Self::new().await;

        Mock::given(method("GET"))
            .and(path("/api/detection_engine/rules/prepackaged/_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(status))
            .mount(&stack.server)
            .await;
        Mock::given(method("GET"))
            .and(path(RULES_FIND))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "message": "customized count must not mask a malformed status"
            })))
            .mount(&stack.server)
            .await;

        stack
    }

    pub async fn with_prebuilt_install(
        status: Value,
        customized: u64,
        response: Value,
    ) -> MockStack {
        let stack = Self::with_prebuilt_status(status, customized).await;

        Mock::given(method("PUT"))
            .and(path("/api/detection_engine/rules/prepackaged"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&stack.server)
            .await;

        stack
    }

    pub async fn with_identity(body: Value) -> MockStack {
        let stack = Self::with_rules(vec![]).await;
        Mock::given(method("GET"))
            .and(path("/_security/_authenticate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .with_priority(1)
            .mount(&stack.server)
            .await;
        stack
    }

    pub async fn with_value_lists_absent() -> MockStack {
        let stack = Self::with_rules(vec![]).await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({
                    "statusCode": 404,
                    "error": "Not Found",
                    "message": "data stream .lists-default and data stream .items-default does not exist"
                })),
            )
            .mount(&stack.server)
            .await;
        stack
    }

    pub async fn with_value_lists_bootstrapped() -> MockStack {
        Self::with_value_lists(&[]).await
    }

    pub async fn with_value_list_index(body: Value) -> MockStack {
        let stack = Self::with_rules(vec![]).await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&stack.server)
            .await;
        stack
    }

    pub async fn with_value_lists(ids: &[&str]) -> MockStack {
        let stack = Self::with_value_list_index(json!({
            "list_index": true,
            "list_item_index": true
        }))
        .await;
        for id in ids {
            Mock::given(method("GET"))
                .and(path("/api/lists"))
                .and(query_param("id", *id))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": id,
                    "name": format!("value list {id}")
                })))
                .mount(&stack.server)
                .await;
        }
        stack
    }

    pub async fn value_list_lookups(&self, id: &str) -> usize {
        self.requests()
            .await
            .into_iter()
            .filter(|request| {
                request.method == http::Method::GET.as_str()
                    && request.path == "/api/lists"
                    && request.query.get("id").is_some_and(|value| value == id)
            })
            .count()
    }
}

fn recorded_request(request: Request) -> RecordedRequest {
    let body_text = String::from_utf8_lossy(&request.body).into_owned();
    RecordedRequest {
        method: request.method.to_string(),
        path: request.url.path().to_string(),
        query: request
            .url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        body: request.body_json().unwrap_or(Value::Null),
        body_text,
    }
}

struct FilteredRules {
    rules: Vec<Value>,
}

struct SourceTotalsRules {
    custom: u64,
    prebuilt: u64,
    all: u64,
}

impl Respond for SourceTotalsRules {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let filter = request
            .url
            .query_pairs()
            .find_map(|(k, v)| (k.as_ref() == "filter").then(|| v.into_owned()));
        let total = match filter.as_deref() {
            Some("alert.attributes.params.immutable: false") => self.custom,
            Some("alert.attributes.params.immutable: true") => self.prebuilt,
            None => self.all,
            _ => 0,
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 1, "total": total, "data": []
        }))
    }
}

impl Respond for FilteredRules {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let filter = request
            .url
            .query_pairs()
            .find_map(|(k, v)| (k.as_ref() == "filter").then(|| v.into_owned()));
        let mut data: Vec<Value> = match filter.as_deref() {
            None => self.rules.clone(),
            Some(filter) => self
                .rules
                .iter()
                .filter(|rule| matches_filter(rule, filter))
                .cloned()
                .collect(),
        };
        let param = |key: &str| {
            request
                .url
                .query_pairs()
                .find_map(|(k, v)| (k.as_ref() == key).then(|| v.into_owned()))
        };
        if param("sort_field").as_deref() == Some("name") {
            data.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        }
        let total = data.len();
        let page: usize = param("page").and_then(|v| v.parse().ok()).unwrap_or(1);
        let per_page: usize = param("per_page").and_then(|v| v.parse().ok()).unwrap_or(20);
        let data: Vec<Value> = data
            .into_iter()
            .skip(page.saturating_sub(1) * per_page)
            .take(per_page)
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "page": page, "perPage": per_page, "total": total, "data": data
        }))
    }
}

fn matches_filter(rule: &Value, filter: &str) -> bool {
    filter
        .split(" AND ")
        .all(|and| matches_and_clause(rule, and))
}

fn matches_and_clause(rule: &Value, clause: &str) -> bool {
    clause
        .split(" OR ")
        .any(|sub| matches_simple(rule, sub.trim()))
}

fn matches_simple(rule: &Value, sub: &str) -> bool {
    let Some((field, value)) = sub.split_once(':') else {
        return false;
    };
    let field = field.trim();
    let value = value.trim();

    match field {
        "alert.attributes.params.immutable" => {
            let is_prebuilt = rule.get("immutable").and_then(Value::as_bool) == Some(true);
            if value == "true" {
                is_prebuilt
            } else {
                !is_prebuilt
            }
        }
        "alert.attributes.params.ruleSource.isCustomized" => rule
            .get("rule_source")
            .and_then(Value::as_object)
            .and_then(|rs| rs.get("is_customized"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "alert.attributes.params.ruleId" => {
            rule.get("rule_id").and_then(Value::as_str) == Some(kql_unquote(value).as_str())
        }
        "alert.attributes.params.type" => {
            rule.get("type").and_then(Value::as_str) == Some(kql_unquote(value).as_str())
        }
        "alert.attributes.params.severity" => {
            rule.get("severity").and_then(Value::as_str) == Some(kql_unquote(value).as_str())
        }
        "alert.attributes.enabled" => {
            let enabled = rule
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if value == "true" { enabled } else { !enabled }
        }
        "alert.attributes.name" => {
            rule.get("name").and_then(Value::as_str) == Some(kql_unquote(value).as_str())
        }
        "alert.attributes.tags" => rule
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .any(|t| t.as_str() == Some(kql_unquote(value).as_str()))
            })
            .unwrap_or(false),
        _ => false,
    }
}

fn kql_unquote(s: &str) -> String {
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    inner.replace("\\\"", "\"").replace("\\\\", "\\")
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

fn container_json(list_id: &str, namespace: &str, list_type: &str, id: &str) -> Value {
    json!({
        "id": id,
        "list_id": list_id,
        "type": list_type,
        "name": format!("list {list_id}"),
        "namespace_type": namespace,
        "_version": "WzUsMV0=",
        "tie_breaker_id": "tb",
        "version": 1,
        "created_at": "2026-08-13T23:38:39.519Z",
        "created_by": "452295856",
        "updated_at": "2026-08-13T23:38:39.519Z",
        "updated_by": "452295856"
    })
}

fn item_for(list_id: &str, item_id: &str, namespace: &str) -> Value {
    json!({
        "id": format!("id-{item_id}"),
        "item_id": item_id,
        "list_id": list_id,
        "type": "simple",
        "name": format!("item {item_id}"),
        "namespace_type": namespace,
        "_version": "WzUsMV0=",
        "tie_breaker_id": "tb",
        "created_at": "2026-08-13T23:38:39.519Z",
        "created_by": "452295856",
        "updated_at": "2026-08-13T23:38:39.519Z",
        "updated_by": "452295856",
        "entries": []
    })
}

async fn mount_get_list(
    server: &MockServer,
    list_id: &str,
    namespace: &str,
    list_type: &str,
    id: &str,
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
            "per_page": items.len().max(1),
            "total": items.len()
        })))
        .mount(server)
        .await;
}

pub async fn mock_stack_with_rule_referencing(list_id: &str) -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": "id-shared",
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
                container_json(list_id, "single", "detection", "id-shared"),
                container_json("orphan", "single", "detection", "id-orphan")
            ],
            "page": 1,
            "per_page": 2,
            "total": 2
        })))
        .mount(&stack.server)
        .await;
    mount_get_list(&stack.server, list_id, "single", "detection", "id-shared").await;
    mount_items(&stack.server, list_id, "single", vec![]).await;
    stack
}

pub async fn mock_stack_with_rule_default_list() -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": "id-rd",
            "list_id": "rd",
            "type": "rule_default",
            "namespace_type": "single"
        }]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, "rd", "single", "rule_default", "id-rd").await;
    mount_items(
        &stack.server,
        "rd",
        "single",
        vec![item_for("rd", "i1", "single")],
    )
    .await;
    stack
}

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
    mount_get_list(&stack.server, list_id, "single", "detection", "id-single").await;
    mount_get_list(
        &stack.server,
        list_id,
        "agnostic",
        "detection",
        "id-agnostic",
    )
    .await;
    mount_items(&stack.server, list_id, "single", vec![]).await;
    mount_items(&stack.server, list_id, "agnostic", vec![]).await;
    stack
}

pub async fn mock_stack_with_list_id(list_id: &str, id: &str) -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", id).await;
    stack
}

pub async fn mock_stack_with_two_list_ids() -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    mount_get_list(&stack.server, "one", "single", "detection", "id-one").await;
    mount_get_list(&stack.server, "two", "single", "detection", "id-two").await;
    mount_items(&stack.server, "one", "single", vec![]).await;
    mount_items(&stack.server, "two", "single", vec![]).await;
    stack
}

pub async fn mock_stack_with_list_and_items(list_id: &str, item_ids: &[&str]) -> MockStack {
    let live_id = format!("id-{list_id}");
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": live_id,
            "list_id": list_id,
            "type": "detection",
            "namespace_type": "single"
        }]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", &live_id).await;
    mount_items(
        &stack.server,
        list_id,
        "single",
        item_ids
            .iter()
            .map(|id| item_for(list_id, id, "single"))
            .collect(),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item_id": "created",
            "list_id": list_id,
            "type": "simple",
            "namespace_type": "single"
        })))
        .mount(&stack.server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item_id": "updated",
            "list_id": list_id,
            "type": "simple",
            "namespace_type": "single"
        })))
        .mount(&stack.server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item_id": "deleted",
            "list_id": list_id,
            "type": "simple",
            "namespace_type": "single"
        })))
        .mount(&stack.server)
        .await;
    stack
}

pub async fn mock_stack_with_two_lists_one_mirrored() -> MockStack {
    let rules = vec![
        json!({
            "rule_id": "r",
            "name": "R",
            "type": "query",
            "exceptions_list": [{
                "id": "id-mirrored",
                "list_id": "mirrored",
                "type": "detection",
                "namespace_type": "single"
            }]
        }),
        json!({
            "rule_id": "r2",
            "name": "R2",
            "type": "query",
            "exceptions_list": [{
                "id": "id-unmirrored",
                "list_id": "unmirrored",
                "type": "detection",
                "namespace_type": "single"
            }]
        }),
    ];
    let stack = MockStack::with_rules(rules).await;
    mount_get_list(
        &stack.server,
        "mirrored",
        "single",
        "detection",
        "id-mirrored",
    )
    .await;
    mount_get_list(
        &stack.server,
        "unmirrored",
        "single",
        "detection",
        "id-unmirrored",
    )
    .await;
    mount_items(
        &stack.server,
        "mirrored",
        "single",
        vec![item_for("mirrored", "drop", "single")],
    )
    .await;
    mount_items(
        &stack.server,
        "unmirrored",
        "single",
        vec![item_for("unmirrored", "survivor", "single")],
    )
    .await;
    Mock::given(method("DELETE"))
        .and(path("/api/exception_lists/items"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "item_id": "deleted",
            "list_id": "mirrored",
            "type": "simple",
            "namespace_type": "single"
        })))
        .mount(&stack.server)
        .await;
    stack
}

pub async fn mock_stack_with_dangling_pointer(
    rule_id: &str,
    list_id: &str,
    stored: &str,
) -> MockStack {
    let rule = json!({
        "rule_id": rule_id,
        "name": "R",
        "type": "query",
        "exceptions_list": [{
            "id": stored,
            "list_id": list_id,
            "type": "detection",
            "namespace_type": "single"
        }]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", "id-shared").await;
    mount_items(&stack.server, list_id, "single", vec![]).await;
    stack
}

pub async fn mock_stack_with_matching_pointer(rule_id: &str, list_id: &str) -> MockStack {
    mock_stack_with_dangling_pointer(rule_id, list_id, "id-shared").await
}

pub async fn mock_stack_with_rule_with_two_wrong_pointers() -> MockStack {
    let rule = json!({
        "rule_id": "r",
        "name": "R",
        "type": "query",
        "exceptions_list": [
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "list_id": "one",
                "type": "detection",
                "namespace_type": "single"
            },
            {
                "id": "00000000-0000-0000-0000-000000000000",
                "list_id": "two",
                "type": "detection",
                "namespace_type": "single"
            }
        ]
    });
    let stack = MockStack::with_rules(vec![rule]).await;
    mount_get_list(&stack.server, "one", "single", "detection", "id-one").await;
    mount_get_list(&stack.server, "two", "single", "detection", "id-two").await;
    mount_items(&stack.server, "one", "single", vec![]).await;
    mount_items(&stack.server, "two", "single", vec![]).await;
    Mock::given(method("PUT"))
        .and(path(RULES))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "rule_id": "r",
            "name": "R",
            "type": "query"
        })))
        .mount(&stack.server)
        .await;
    stack
}

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

pub async fn mock_stack_with_failing_item_create() -> MockStack {
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
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "item create failed"})),
        )
        .mount(&stack.server)
        .await;
    stack
}

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
            "per_page": self.page_size.max(1),
            "total": self.items.len()
        }))
    }
}
