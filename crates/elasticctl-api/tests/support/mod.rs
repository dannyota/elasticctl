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

    /// A stack pre-seeded with `rules`: the `_find` corpus (honoring the
    /// `filter` query parameter) and a `rule_id` lookup for each rule.
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

    /// A stack whose prepackaged `_status` route returns `status` and whose
    /// `_find` route reports `customized` customized rules. The `_find` mock
    /// ignores query filters and serves whatever it is seeded with, so a test
    /// must not depend on it honoring the customized filter.
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

    /// A stack whose prepackaged `_status`, `_find`, and install routes return
    /// `status`, `customized`, and `response` respectively.
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

    /// A stack whose value-list data streams are absent: `GET /api/lists/index`
    /// answers 404, the route's way of saying "not bootstrapped" (fact 21).
    /// Built on an empty rule corpus so both `doctor` and `state push` have a
    /// working `_find`.
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

    /// A stack whose value-list data streams are bootstrapped, so
    /// `GET /api/lists/index` reports both indexes present.
    pub async fn with_value_lists_bootstrapped() -> MockStack {
        let stack = Self::with_rules(vec![]).await;
        Mock::given(method("GET"))
            .and(path("/api/lists/index"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "list_index": true,
                "list_item_index": true
            })))
            .mount(&stack.server)
            .await;
        stack
    }
}

/// Serve the seeded rule corpus, honoring the `filter` query parameter.
///
/// The production client emits a small KQL subset: top-level clauses joined by
/// ` AND `, a raw `ruleId` disjunction joined by ` OR `, and a handful of field
/// clauses. This matcher implements exactly that subset so a `--source` test
/// asserts the real split rather than passing against a mock that ignores the
/// filter.
struct FilteredRules {
    rules: Vec<Value>,
}

impl Respond for FilteredRules {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let filter = request
            .url
            .query_pairs()
            .find_map(|(k, v)| (k.as_ref() == "filter").then(|| v.into_owned()));
        let data: Vec<Value> = match filter.as_deref() {
            None => self.rules.clone(),
            Some(filter) => self
                .rules
                .iter()
                .filter(|rule| matches_filter(rule, filter))
                .cloned()
                .collect(),
        };
        ResponseTemplate::new(200).set_body_json(json!({
            "page": 1, "perPage": 10000, "total": data.len(), "data": data
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
        // A rule without `immutable` reads as its server default, `false`: it
        // is a custom rule, so it matches `immutable: false` and not `true`.
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

/// Strip the surrounding quotes (and the two escapes `kql_escape` adds) from a
/// KQL literal. Test values are simple, so a full unparser is not needed.
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

/// A container body for `list_id`, carrying the volatile fields a real
/// `get_list` returns so `canonical_list` stripping is exercised.
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

/// An item body for `item_id` inside `list_id`, with the volatile fields a real
/// `find_items` returns.
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
            "per_page": items.len(),
            "total": items.len()
        })))
        .mount(server)
        .await;
}

/// One rule references `list_id`; the list corpus also holds an orphan the rule
/// does not reference, so `pull` must mirror only the referenced list.
pub async fn mock_stack_with_rule_referencing(list_id: &str) -> MockStack {
    // A real create returns the live pointer in the rule, so the mock carries it
    // too; otherwise the dangling-pointer check would flag a clean pull.
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

/// One rule references a `rule_default` list holding one item.
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

/// An empty rule corpus whose `get_list` for `list_id` returns the given live
/// `id`, so a push can resolve the pointer against this stack.
pub async fn mock_stack_with_list_id(list_id: &str, id: &str) -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    mount_get_list(&stack.server, list_id, "single", "detection", id).await;
    stack
}

/// An empty rule corpus with two live containers, `one` and `two`, each with a
/// distinct id, so a push that injects pointers must resolve every reference.
pub async fn mock_stack_with_two_list_ids() -> MockStack {
    let stack = MockStack::with_rules(vec![]).await;
    mount_get_list(&stack.server, "one", "single", "detection", "id-one").await;
    mount_get_list(&stack.server, "two", "single", "detection", "id-two").await;
    // Both containers exist remotely and are mirrored, so item reconciliation
    // reads their (empty) item sets.
    mount_items(&stack.server, "one", "single", vec![]).await;
    mount_items(&stack.server, "two", "single", vec![]).await;
    stack
}

/// A rule referencing `list_id`, whose live container holds exactly `item_ids`
/// and answers item deletes, so a push can reconcile the items. The rule's
/// stored pointer matches the live container, so the run has no dangling drift.
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

/// Two live containers: `mirrored`, referenced by a remote rule and mirrored
/// locally, holding one item; and `unmirrored`, referenced by a second remote
/// rule but absent locally. The run deletes `mirrored`'s item and must leave
/// the `unmirrored` container alone.
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
    // `unmirrored` carries an item too, so the test's exact-equality assertion
    // on `deleted_item_ids` guards the containment bound: a reconciliation that
    // widened to remote-only containers would delete "survivor" and fail.
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

/// A rule whose stored pointer is `stored` beside a live container `list_id`
/// with id `id-shared`. Used to exercise the raw-remote dangling check.
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

/// A rule whose stored pointer matches the live container id, the clean case.
pub async fn mock_stack_with_matching_pointer(rule_id: &str, list_id: &str) -> MockStack {
    mock_stack_with_dangling_pointer(rule_id, list_id, "id-shared").await
}

/// A rule referencing two live containers, each carrying the same wrong stored
/// id, so the repair path must dedupe one rule rather than emit two writes.
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

/// An empty rule corpus whose container create succeeds but whose item create
/// fails, so a push that reaches the item step records the failure and returns
/// the plan rather than discarding the change ticket.
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

/// Serves `total` items across pages of `page_size`, honoring the `page` query
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
