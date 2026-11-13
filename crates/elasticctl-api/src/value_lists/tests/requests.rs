use super::super::*;
use super::reads::fixture;
use serde_json::{Value, json};
use wiremock::{MockServer, Request};

pub(super) fn assert_request(request: &Request, method: &str, path: &str, query: &[(&str, &str)]) {
    assert_eq!(request.method.as_str(), method);
    assert_eq!(request.url.path(), path);
    let mut actual: Vec<_> = request
        .url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let mut expected: Vec<_> = query
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

pub(super) fn assert_import(request: &Request, id: &str, stem: &str, payload: &str) {
    assert_request(
        request,
        "POST",
        "/api/lists/items/_import",
        &[("list_id", id)],
    );
    let boundary = request.headers["content-type"]
        .to_str()
        .unwrap()
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    let expected = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{stem}.txt\"\r\nContent-Type: text/plain\r\n\r\n{payload}\r\n--{boundary}--\r\n"
    );
    assert_eq!(request.body, expected.as_bytes());
}

pub(super) async fn assert_plan_writes(server: &MockServer, flavor: &str, plan: &ListPlan) {
    let c = &plan.local.container;
    let mut deleted = Vec::new();
    for operation in ["items_find_first", "items_find_next"] {
        for item in fixture(flavor, operation)["response"]["data"]
            .as_array()
            .unwrap()
        {
            let value = item["value"].as_str().unwrap();
            if plan.removes.contains(value) {
                deleted.push((value.to_owned(), item["id"].as_str().unwrap().to_owned()));
            }
        }
    }
    deleted.sort();
    let mut deletes = deleted.iter();
    for request in server.received_requests().await.unwrap() {
        match request.url.path() {
            "/api/lists" if request.method != "GET" => {
                let (method, mut expected) = match plan.container_action {
                    ContainerAction::Create => (
                        "POST",
                        json!({"id": c.id, "type": c.list_type, "name": c.name, "description": c.description}),
                    ),
                    ContainerAction::Update => (
                        "PATCH",
                        json!({"id": c.id, "name": c.name, "description": c.description, "_version": plan.before.as_ref().unwrap().container.version}),
                    ),
                    ContainerAction::None => panic!("unexpected container write"),
                };
                if let Some(meta) = &c.meta {
                    expected["meta"] = json!(meta);
                }
                assert_request(&request, method, "/api/lists", &[]);
                assert_eq!(request.body_json::<Value>().unwrap(), expected);
            }
            "/api/lists/items/_import" => {
                let payload: String = plan.adds.iter().map(|value| format!("{value}\n")).collect();
                assert_import(&request, &c.id, &plan.local.stem, &payload);
            }
            "/api/lists/items" => {
                let (_, id) = deletes.next().expect("unexpected item delete");
                assert_request(&request, "DELETE", "/api/lists/items", &[("id", id)]);
                assert!(request.body.is_empty());
            }
            "/api/lists/items/_export" => {
                assert_request(
                    &request,
                    "POST",
                    "/api/lists/items/_export",
                    &[("list_id", &c.id)],
                );
                assert!(request.body.is_empty());
            }
            "/api/lists" => {
                assert_request(&request, "GET", "/api/lists", &[("id", &c.id)]);
                assert!(request.body.is_empty());
            }
            "/api/lists/items/_find" => {
                let operation = if request.url.query_pairs().any(|(key, _)| key == "cursor") {
                    "items_find_next"
                } else {
                    "items_find_first"
                };
                let f = fixture(flavor, operation);
                let expected: Vec<_> = f["request"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            v.as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| v.to_string()),
                        )
                    })
                    .collect();
                let query: Vec<_> = expected
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                assert_request(&request, "GET", "/api/lists/items/_find", &query);
                assert!(request.body.is_empty());
            }
            route => panic!("unexpected request {route}"),
        }
    }
}
