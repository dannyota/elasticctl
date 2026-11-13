use elasticctl_api::{codec::Format, rules::RuleSource, state};
use elasticctl_core::{Profile, Transport, TransportOptions};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const FLAVORS: [&str; 3] = ["traditional-9.5.1", "ech-9.5.6", "serverless-9.7.0"];
pub const RULES: &str = "/api/detection_engine/rules";
pub const ITEMS: &str = "/api/exception_lists/items/_find";
pub const EXPORT: &str = "/api/lists/items/_export";
type Key = (String, String, Vec<(String, String)>);
type Routes = BTreeMap<Key, VecDeque<ResponseTemplate>>;

fn key(method: &str, path: &str, query: &[(&str, &str)]) -> Key {
    let mut query: Vec<_> = query
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    query.sort();
    (method.into(), path.into(), query)
}

pub fn string(value: &Value, field: &str) -> String {
    value[field].as_str().unwrap().to_owned()
}

pub struct Stack {
    pub server: MockServer,
    pub t: Transport,
    fixtures: BTreeMap<String, Value>,
    routes: Arc<Mutex<Routes>>,
    unmatched: Arc<Mutex<Vec<Key>>>,
}

impl Stack {
    pub async fn new(flavor: &str, single: &str, outside: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(flavor)
            .join("value_lists");
        let mut fixtures: BTreeMap<String, Value> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| {
                let value: Value =
                    serde_json::from_slice(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap();
                (string(&value, "operation"), value)
            })
            .collect();
        for operation in ["authenticate", "rules_find"] {
            let path = root.parent().unwrap().join(format!("{operation}.json"));
            let path = if path.exists() {
                path
            } else {
                root.parent()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("traditional-9.5.1")
                    .join(format!("{operation}.json"))
            };
            let value: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            fixtures.insert(operation.into(), value);
        }
        let server = MockServer::start().await;
        let routes = Arc::new(Mutex::new(Routes::new()));
        let unmatched = Arc::new(Mutex::new(Vec::new()));
        let routes_copy = routes.clone();
        let unmatched_copy = unmatched.clone();
        Mock::given(wiremock::matchers::any())
            .respond_with(move |request: &Request| {
                let pairs: Vec<_> = request.url.query_pairs().collect();
                let query: Vec<_> = pairs
                    .iter()
                    .map(|(k, v)| (k.as_ref(), v.as_ref()))
                    .collect();
                let k = key(request.method.as_str(), request.url.path(), &query);
                let mut routes = routes_copy.lock().unwrap();
                if let Some(responses) = routes.get_mut(&k) {
                    if responses.len() > 1 {
                        responses.pop_front().unwrap()
                    } else {
                        responses.front().unwrap().clone()
                    }
                } else {
                    unmatched_copy.lock().unwrap().push(k);
                    ResponseTemplate::new(404)
                }
            })
            .mount(&server)
            .await;
        let t = Transport::with_options(
            &Profile {
                kibana_url: server.uri(),
                es_url: Some(server.uri()),
                api_key: Some("synthetic".into()),
                username: None,
                password: None,
                space: "default".into(),
                verify: true,
                timeout_secs: 2,
            },
            TransportOptions {
                disable_retries: true,
                ..Default::default()
            },
        )
        .unwrap();
        let s = Self {
            server,
            t,
            fixtures,
            routes,
            unmatched,
        };
        s.route("GET", "/api/status", &[], &[("status", 200)]);
        s.route("GET", "/api/lists/index", &[], &[("index_after", 200)]);
        s.rules("state_rules_full", false);
        for (namespace, container, items, scan) in [
            ("single", "exception_create", single, "state_scan_single"),
            (
                "agnostic",
                "state_outside_get",
                outside,
                "state_scan_agnostic",
            ),
        ] {
            let id = s.id(container, "list_id");
            s.route(
                "GET",
                "/api/exception_lists",
                &[("list_id", &id), ("namespace_type", namespace)],
                &[(container, 200)],
            );
            s.route(
                "GET",
                ITEMS,
                &[
                    ("list_id", &id),
                    ("namespace_type", namespace),
                    ("page", "1"),
                    ("per_page", "10000"),
                ],
                &[(items, 200)],
            );
            s.route(
                "GET",
                "/api/exception_lists/_find",
                &[
                    ("namespace_type", namespace),
                    ("page", "1"),
                    ("per_page", "10000"),
                ],
                &[(scan, 200)],
            );
        }
        for (container, export) in [
            ("container_read", "items_export"),
            ("contain_create", "contain_export"),
            ("spellings_create", "export_s_two_spellings"),
            ("container_p_ip", "export_p_spellings"),
        ] {
            let id = s.id(container, "id");
            s.container(&id, &[(container, 200)]);
            s.exports(&id, &[export]);
        }
        for operation in ["state_rule_r", "state_rule_q"] {
            let id = s.id(operation, "rule_id");
            s.route("GET", RULES, &[("rule_id", &id)], &[(operation, 200)]);
        }
        s
    }

    pub fn body(&self, operation: &str) -> Value {
        self.fixtures[operation]["response"].clone()
    }
    pub fn id(&self, operation: &str, field: &str) -> String {
        string(&self.body(operation), field)
    }
    pub fn data(&self, operation: &str) -> Vec<Value> {
        self.body(operation)["data"].as_array().unwrap().clone()
    }
    pub fn values(&self, operation: &str) -> BTreeSet<String> {
        self.body(operation)
            .as_str()
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    pub fn response(&self, operation: &str, status: u16) -> ResponseTemplate {
        let body = self.body(operation);
        if let Some(text) = body.as_str() {
            ResponseTemplate::new(status).set_body_string(text)
        } else {
            ResponseTemplate::new(status).set_body_json(body)
        }
    }
    pub fn route(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        responses: &[(&str, u16)],
    ) {
        self.routes.lock().unwrap().insert(
            key(method, path, query),
            responses
                .iter()
                .map(|(op, status)| self.response(op, *status))
                .collect(),
        );
    }
    pub fn container(&self, id: &str, responses: &[(&str, u16)]) {
        self.route("GET", "/api/lists", &[("id", id)], responses);
    }
    pub fn exports(&self, id: &str, operations: &[&str]) {
        self.route(
            "POST",
            EXPORT,
            &[("list_id", id)],
            &operations.iter().map(|op| (*op, 200)).collect::<Vec<_>>(),
        );
    }
    pub fn rules(&self, operation: &str, scoped: bool) {
        let filter = if scoped {
            format!(
                "alert.attributes.params.ruleId: \"{}\"",
                self.id("state_rule_r", "rule_id")
            )
        } else {
            "alert.attributes.params.immutable: false".into()
        };
        self.route(
            "GET",
            &format!("{RULES}/_find"),
            &[("page", "1"), ("per_page", "10000"), ("filter", &filter)],
            &[(operation, 200)],
        );
    }
    pub fn items(&self, namespace: &str, operations: &[&str]) {
        let container = if namespace == "single" {
            "exception_create"
        } else {
            "state_outside_get"
        };
        let id = self.id(container, "list_id");
        self.route(
            "GET",
            ITEMS,
            &[
                ("list_id", &id),
                ("namespace_type", namespace),
                ("page", "1"),
                ("per_page", "10000"),
            ],
            &operations.iter().map(|op| (*op, 200)).collect::<Vec<_>>(),
        );
    }
    pub async fn pull(
        &self,
        dir: &Path,
        scoped: bool,
    ) -> elasticctl_core::Result<state::PullReport> {
        let selectors = if scoped {
            vec![self.id("state_rule_r", "rule_id")]
        } else {
            vec![]
        };
        state::pull(
            &self.t,
            dir,
            Format::Yaml,
            &selectors,
            None,
            None,
            RuleSource::Custom,
        )
        .await
    }
    pub async fn plan(&self, dir: &Path, scoped: bool) -> elasticctl_core::Result<state::PushPlan> {
        let selectors = if scoped {
            vec![self.id("state_rule_r", "rule_id")]
        } else {
            vec![]
        };
        state::plan_push(
            &self.t,
            dir,
            &selectors,
            None,
            None,
            RuleSource::Custom,
            &state::StackIdentity {
                profile: "fixture".into(),
                host: self.server.uri(),
                space: "default".into(),
            },
        )
        .await
    }
    pub async fn diff(&self, dir: &Path, scoped: bool) -> state::DiffReport {
        let selectors = if scoped {
            vec![self.id("state_rule_r", "rule_id")]
        } else {
            vec![]
        };
        state::diff(&self.t, dir, &selectors, None, None, RuleSource::Custom)
            .await
            .unwrap()
    }
    pub async fn requests(&self) -> Vec<Request> {
        let unmatched = self.unmatched.lock().unwrap().clone();
        assert!(unmatched.is_empty(), "unmatched requests: {unmatched:?}");
        let requests = self.server.received_requests().await.unwrap();
        for r in &requests {
            if r.url.path().starts_with("/api/") {
                assert_eq!(r.headers["elastic-api-version"], "2023-10-31");
            }
            if r.method != "GET" {
                assert_eq!(r.headers["kbn-xsrf"], "true");
            }
            if r.method == "GET" || r.url.path() == EXPORT || r.method == "DELETE" {
                assert!(r.body.is_empty());
            }
        }
        requests
    }
    pub async fn no_writes(&self) {
        assert!(
            self.requests()
                .await
                .iter()
                .all(|r| r.method == "GET" || r.url.path() == EXPORT)
        );
    }
}

pub fn value_path(dir: &Path, id: &str) -> PathBuf {
    dir.join("value-lists").join(format!("{id}.txt"))
}
pub fn write_values(dir: &Path, id: &str, values: &BTreeSet<String>) {
    std::fs::write(
        value_path(dir, id),
        values.iter().map(|v| format!("{v}\n")).collect::<String>(),
    )
    .unwrap();
}
pub fn edit(dir: &Path, root: &str, id: &str, change: impl FnOnce(&mut Value)) {
    let path = dir.join(root).join(format!("{id}.yaml"));
    let mut value: Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    if root == "rules" && value.is_array() {
        change(
            value
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|r| r["rule_id"] == id)
                .unwrap(),
        );
    } else {
        change(&mut value);
    }
    std::fs::write(path, serde_yaml_ng::to_string(&value).unwrap()).unwrap();
}

pub fn writable(mut value: Value, versioned: bool) -> Value {
    for field in [
        "id",
        "_version",
        "tie_breaker_id",
        "created_at",
        "created_by",
        "updated_at",
        "updated_by",
    ] {
        value.as_object_mut().unwrap().remove(field);
    }
    if !versioned {
        value.as_object_mut().unwrap().remove("version");
    }
    value
}
pub fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    for root in ["rules", "exceptions", "value-lists"] {
        let path = dir.join(root);
        if path.exists() {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                result.insert(
                    path.strip_prefix(dir).unwrap().to_owned(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    result
}
