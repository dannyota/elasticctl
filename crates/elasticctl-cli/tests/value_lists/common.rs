use assert_cmd::Command;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const FLAVORS: [&str; 3] = ["traditional-9.5.1", "ech-9.5.6", "serverless-9.7.0"];
pub const ID: &str = "elasticctl-fixture-value-list-id-3";

pub fn fixture(flavor: &str, operation: &str) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(flavor)
        .join("value_lists");
    std::fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            serde_json::from_slice::<Value>(&std::fs::read(entry.unwrap().path()).unwrap()).unwrap()
        })
        .find(|value| value["operation"] == operation)
        .unwrap_or_else(|| panic!("missing {flavor} {operation}"))
}

pub fn response(flavor: &str, operation: &str) -> ResponseTemplate {
    let f = fixture(flavor, operation);
    let status = f["http_status"]
        .as_u64()
        .or_else(|| f["response"]["status_code"].as_u64())
        .unwrap_or(200) as u16;
    if let Some(text) = f["response"].as_str() {
        ResponseTemplate::new(status).set_body_string(text)
    } else {
        ResponseTemplate::new(status).set_body_json(&f["response"])
    }
}

pub async fn server(flavor: &str, ready: bool, delete: &str) -> MockServer {
    let server = MockServer::start().await;
    let flavor = flavor.to_string();
    let delete = delete.to_string();
    Mock::given(|_: &Request| true)
        .respond_with(move |request: &Request| {
            let operation = match (request.method.as_str(), request.url.path()) {
                ("GET", "/api/status") => "status",
                ("GET", "/api/lists/index") => {
                    if ready {
                        "index_after"
                    } else {
                        "index_before"
                    }
                }
                ("GET", "/api/lists") => "container_read",
                ("POST", "/api/lists/items/_export") => "items_export",
                ("DELETE", "/api/lists") => &delete,
                ("GET", "/api/exception_lists/_find") => {
                    if request
                        .url
                        .query_pairs()
                        .any(|(key, value)| key == "namespace_type" && value == "agnostic")
                    {
                        "exception_lists_find_agnostic"
                    } else {
                        "exception_lists_find"
                    }
                }
                ("GET", "/api/exception_lists") => "exception_create",
                ("GET", "/api/exception_lists/items/_find") => "exception_items_find",
                _ => panic!("unexpected request: {} {}", request.method, request.url),
            };
            response(&flavor, operation)
        })
        .mount(&server)
        .await;
    server
}

pub fn local_pair(root: &Path, flavor: &str) -> PathBuf {
    let body = &fixture(flavor, "container_read")["response"];
    let container = json!({"id": body["id"], "type": body["type"], "name": body["name"], "description": body["description"], "meta": body["meta"]});
    let file = root.join(format!("{ID}.yaml"));
    std::fs::write(&file, serde_json::to_vec(&container).unwrap()).unwrap();
    std::fs::write(
        file.with_extension("txt"),
        "10.0.0.5-10.0.0.5\n10.0.0.6/32\n10.0.0.7/32\n",
    )
    .unwrap();
    file
}

pub fn run(root: &Path, uri: &str, args: &[&str]) -> std::process::Output {
    let cfg = crate::common::config_for(root, uri);
    let expanded: Vec<_> = args
        .iter()
        .map(|a| a.replace("ROOT", root.to_str().unwrap()).replace("ID", ID))
        .collect();
    let mut cmd = Command::cargo_bin("elasticctl").unwrap();
    for key in [
        "PROFILE",
        "CONFIG",
        "KIBANA_URL",
        "ES_URL",
        "API_KEY",
        "SPACE",
        "TIMEOUT",
    ] {
        cmd.env_remove(format!("ELASTICCTL_{key}"));
    }
    cmd.current_dir(root)
        .args(["--config", cfg.to_str().unwrap()])
        .args(expanded)
        .output()
        .unwrap()
}

pub fn normalize(root: &Path, uri: &str, bytes: &[u8]) -> String {
    let mut text = String::from_utf8(bytes.to_vec()).unwrap();
    let raw = root.to_str().unwrap().to_string();
    let canonical = std::fs::canonicalize(root)
        .map(|p| p.to_str().unwrap().to_string())
        .unwrap_or_else(|_| raw.clone());
    let mut roots = vec![canonical.clone(), raw.clone()];
    for root in [&canonical, &raw] {
        roots.push(root.replace('\\', "\\\\"));
        if let Some(stripped) = root.strip_prefix(r"\\?\") {
            roots.push(stripped.to_string());
            roots.push(stripped.replace('\\', "\\\\"));
        }
    }
    roots.sort_by_key(|r| std::cmp::Reverse(r.len()));
    for root in roots.iter().filter(|r| !r.is_empty()) {
        text = text.replace(root.as_str(), "ROOT");
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("ROOT") {
        out.push_str(&rest[..at + 4]);
        rest = &rest[at + 4..];
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || "._-/\\".contains(c)))
            .unwrap_or(rest.len());
        out.push_str(&rest[..end].replace("\\\\", "/").replace('\\', "/"));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out.replace("elasticctl.exe", "elasticctl")
        .replace(uri, "HOST")
        .replace(uri.trim_start_matches("http://"), "HOST")
}

pub fn capture(root: &Path, uri: &str, out: &std::process::Output) -> Value {
    let mut stdout = normalize(root, uri, &out.stdout);
    if stdout.contains("ROOT") && !stdout.trim_start().starts_with(['{', '[']) {
        stdout = stdout
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    }
    json!({"code": out.status.code(), "stdout": stdout, "stderr": normalize(root, uri, &out.stderr)})
}

pub async fn assert_read_only(server: &MockServer) {
    for request in server.received_requests().await.unwrap() {
        assert!(
            request.method == "GET"
                || (request.method == "POST" && request.url.path() == "/api/lists/items/_export"),
            "{} {}",
            request.method,
            request.url
        );
    }
}

pub async fn mount_index(
    server: &MockServer,
    flavor: &str,
    operation: &str,
    times: u64,
    priority: u8,
) {
    Mock::given(method("GET"))
        .and(path("/api/lists/index"))
        .respond_with(response(flavor, operation))
        .up_to_n_times(times)
        .with_priority(priority)
        .mount(server)
        .await;
}

pub async fn mount_get(server: &MockServer, flavor: &str, operation: &str, times: u64) {
    Mock::given(method("GET"))
        .and(path("/api/lists"))
        .and(query_param("id", ID))
        .respond_with(response(flavor, operation))
        .up_to_n_times(times)
        .with_priority(1)
        .mount(server)
        .await;
}
