use serde_json::Value;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub fn fixture(operation: &str) -> Value {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/traditional-9.5.1/value_lists");
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<Value>(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .find(|v| v["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {operation}"))
}

pub fn response(operation: &str, status: u16) -> ResponseTemplate {
    let value = fixture(operation);
    if let Some(body) = value["response"].as_str() {
        ResponseTemplate::new(status).set_body_string(body)
    } else {
        ResponseTemplate::new(status).set_body_json(&value["response"])
    }
}

pub async fn reads(server: &MockServer, present: bool) -> String {
    let id = fixture("container_read")["response"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(response("status", 200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/exception_lists/_find"))
        .respond_with(response("exception_lists_find_agnostic", 200))
        .mount(server)
        .await;
    if present {
        Mock::given(method("GET"))
            .and(path("/api/lists"))
            .and(query_param("id", &id))
            .respond_with(response("container_read", 200))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/lists/items/_export"))
            .and(query_param("list_id", &id))
            .respond_with(response("items_export_after_delete", 200))
            .mount(server)
            .await;
    }
    id
}
