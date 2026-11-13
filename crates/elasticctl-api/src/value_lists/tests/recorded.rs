use super::super::*;
use super::reads::{fixture, response};
use super::requests::{assert_import, assert_request};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(super) struct Script<'a> {
    flavor: &'a str,
    exchanges: Vec<Exchange>,
}

struct Exchange {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    import: Option<(String, String, String)>,
    response: ResponseTemplate,
    json: Option<serde_json::Value>,
}

impl<'a> Script<'a> {
    pub(super) fn new(flavor: &'a str) -> Self {
        Self {
            flavor,
            exchanges: Vec::new(),
        }
    }

    pub(super) fn empty(
        &mut self,
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        operation: &str,
        status: u16,
    ) {
        self.exchanges.push(Exchange {
            method: method.into(),
            path: path.into(),
            query: query
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            import: None,
            json: None,
            response: response(&fixture(self.flavor, operation), status),
        });
    }

    pub(super) fn import(&mut self, plan: &ListPlan, operation: &str, status: u16) {
        self.empty(
            "POST",
            "/api/lists/items/_import",
            &[("list_id", &plan.local.container.id)],
            operation,
            status,
        );
        self.exchanges.last_mut().unwrap().import = Some((
            plan.local.container.id.clone(),
            plan.local.stem.clone(),
            plan.adds.iter().map(|v| format!("{v}\n")).collect(),
        ));
    }

    pub(super) fn patch(&mut self, plan: &ListPlan, status: u16) {
        let operation = if status == 409 {
            "container_patch_stale"
        } else {
            "container_patch"
        };
        self.empty("PATCH", "/api/lists", &[], operation, status);
        let c = &plan.local.container;
        let mut body = serde_json::json!({
            "id": c.id, "name": c.name, "description": c.description,
            "_version": plan.before.as_ref().unwrap().container.version,
        });
        if let Some(meta) = &c.meta {
            body["meta"] = serde_json::json!(meta);
        }
        self.exchanges.last_mut().unwrap().json = Some(body);
    }

    pub(super) fn export(&mut self, id: &str, operation: &str) {
        self.empty(
            "POST",
            "/api/lists/items/_export",
            &[("list_id", id)],
            operation,
            200,
        );
    }

    pub(super) fn index(&mut self) {
        self.empty("GET", "/api/lists/index", &[], "index_after", 200);
    }

    pub(super) fn read(&mut self, before: &RemoteList, container: &str, export: &str) {
        let id = &before.container.container.id;
        self.empty("GET", "/api/lists", &[("id", id)], container, 200);
        self.export(id, export);
    }

    pub(super) fn scan(&mut self, populated: bool, status: bool) {
        if status {
            self.empty("GET", "/api/status", &[], "status", 200);
        }
        self.empty(
            "GET",
            "/api/exception_lists/_find",
            &[
                ("page", "1"),
                ("per_page", "10000"),
                ("namespace_type", "single"),
            ],
            if populated {
                "exception_lists_find"
            } else {
                "exception_lists_find_agnostic"
            },
            200,
        );
        if populated {
            let list = fixture(self.flavor, "exception_create");
            let id = list["response"]["list_id"].as_str().unwrap();
            self.empty(
                "GET",
                "/api/exception_lists",
                &[("list_id", id), ("namespace_type", "single")],
                "exception_create",
                200,
            );
            self.empty(
                "GET",
                "/api/exception_lists/items/_find",
                &[
                    ("list_id", id),
                    ("namespace_type", "single"),
                    ("page", "1"),
                    ("per_page", "10000"),
                ],
                "exception_items_find",
                200,
            );
        }
        self.empty(
            "GET",
            "/api/exception_lists/_find",
            &[
                ("page", "1"),
                ("per_page", "10000"),
                ("namespace_type", "agnostic"),
            ],
            "exception_lists_find_agnostic",
            200,
        );
    }

    pub(super) fn items(&mut self, id: &str, operation: &str, per_page: &str) {
        self.empty(
            "GET",
            "/api/lists/items/_find",
            &[("list_id", id), ("page", "1"), ("per_page", per_page)],
            operation,
            200,
        );
    }

    pub(super) async fn mount(&self, server: &MockServer) {
        let responses: Vec<_> = self.exchanges.iter().map(|e| e.response.clone()).collect();
        let index = Arc::new(AtomicUsize::new(0));
        Mock::given(wiremock::matchers::any())
            .respond_with(move |_: &wiremock::Request| {
                responses[index
                    .fetch_add(1, Ordering::SeqCst)
                    .min(responses.len() - 1)]
                .clone()
            })
            .mount(server)
            .await;
    }

    pub(super) async fn check(&self, server: &MockServer, repeat_last: bool) {
        let requests = server.received_requests().await.unwrap();
        if repeat_last {
            assert!(requests.len() > self.exchanges.len());
        } else {
            assert_eq!(requests.len(), self.exchanges.len());
        }
        for (index, request) in requests.iter().enumerate() {
            let exchange = &self.exchanges[index.min(self.exchanges.len() - 1)];
            let query: Vec<_> = exchange
                .query
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            assert_request(request, &exchange.method, &exchange.path, &query);
            if let Some((id, stem, payload)) = &exchange.import {
                assert_import(request, id, stem, payload);
            } else if let Some(body) = &exchange.json {
                assert_eq!(request.body_json::<serde_json::Value>().unwrap(), *body);
            } else {
                assert!(request.body.is_empty());
            }
            if request.method != "GET" {
                assert_eq!(request.headers["kbn-xsrf"], "true");
            }
            assert_eq!(request.headers["elastic-api-version"], "2023-10-31");
        }
    }
}

pub(super) fn remote_from(flavor: &str, container: &str, export: &str) -> RemoteList {
    let container = decode_remote_container(&fixture(flavor, container)["response"]).unwrap();
    let stored = decode_export(
        &container.container.list_type,
        fixture(flavor, export)["response"].as_str().unwrap(),
    )
    .unwrap();
    RemoteList { container, stored }
}

pub(super) fn values(flavor: &str, operation: &str) -> ValueSet {
    decode_export(
        &ValueListType::IpRange,
        fixture(flavor, operation)["response"].as_str().unwrap(),
    )
    .unwrap()
    .set()
}
