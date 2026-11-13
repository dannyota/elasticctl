use super::vl;
use serde_json::{Value, json};
use std::path::Path;
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const FLAVOR: &str = "traditional-9.5.1";

async fn setup(root: &Path, mode: &str) -> MockServer {
    let server = MockServer::start().await;
    let mirror = root.join("mirror");
    for folder in ["rules", "exceptions", "value-lists"] {
        std::fs::create_dir_all(mirror.join(folder)).unwrap();
    }
    let mut rules = serde_json::from_slice::<Value>(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/traditional-9.5.1/rules_find.json"),
        )
        .unwrap(),
    )
    .unwrap()["response"]
        .clone();
    let mut exception = vl::fixture(FLAVOR, "exception_create")["response"].clone();
    let mut item = vl::fixture(FLAVOR, "exception_item_create")["response"].clone();
    item["entries"].as_array_mut().unwrap().truncate(1);
    let mut later_item = item.clone();
    later_item["item_id"] = json!("later-item");
    for entry in later_item["entries"].as_array_mut().unwrap() {
        entry["list"]["id"] = json!(format!("{}-later", vl::id(FLAVOR)));
    }
    let items = vec![item, later_item];
    rules["data"][0]["exceptions_list"] = json!([{
        "id": exception["id"], "list_id": exception["list_id"],
        "namespace_type": "single", "type": "detection"
    }]);
    std::fs::write(
        mirror.join("rules/rule.ndjson"),
        serde_json::to_vec(&rules["data"][0]).unwrap(),
    )
    .unwrap();
    exception["items"] = json!(items);
    std::fs::write(
        mirror.join("exceptions/list.yaml"),
        serde_json::to_vec(&exception).unwrap(),
    )
    .unwrap();
    let pair = vl::local_pair(&mirror.join("value-lists"), FLAVOR);
    let mut local: Value = serde_json::from_slice(&std::fs::read(&pair).unwrap()).unwrap();
    let mut later = local.clone();
    later["id"] = json!(format!("{}-later", vl::id(FLAVOR)));
    let later_path = pair.with_file_name(format!("{}-later.yaml", vl::id(FLAVOR)));
    std::fs::write(&later_path, serde_json::to_vec(&later).unwrap()).unwrap();
    std::fs::copy(pair.with_extension("txt"), later_path.with_extension("txt")).unwrap();
    if mode == "unknown" {
        let mut values = vl::values(FLAVOR, "items_export");
        values.insert("192.0.2.0/24".into());
        std::fs::write(pair.with_extension("txt"), vl::values_text(&values)).unwrap();
    } else if mode != "unchanged" && mode != "preflight" {
        local["description"] = json!("Updated description");
        std::fs::write(&pair, serde_json::to_vec(&local).unwrap()).unwrap();
    }
    let mode = mode.to_owned();
    let index_reads = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(|_: &Request| true)
        .respond_with(move |request: &Request| {
            match (request.method.as_str(), request.url.path()) {
                ("GET", "/api/detection_engine/rules/_find") => {
                    ResponseTemplate::new(200).set_body_json(&rules)
                }
                ("GET", "/api/exception_lists/_find") => {
                    let operation = if request
                        .url
                        .query_pairs()
                        .any(|(k, v)| k == "namespace_type" && v == "agnostic")
                    {
                        "exception_lists_find_agnostic"
                    } else {
                        "exception_lists_find"
                    };
                    vl::response(FLAVOR, operation)
                }
                ("GET", "/api/exception_lists/items/_find") => {
                    let mut body = vl::fixture(FLAVOR, "exception_items_find")["response"].clone();
                    body["data"] = json!(items);
                    body["total"] = json!(2);
                    ResponseTemplate::new(200).set_body_json(body)
                }
                ("GET", "/api/lists") => {
                    let mut body = vl::fixture(FLAVOR, "container_read")["response"].clone();
                    let id = request
                        .url
                        .query_pairs()
                        .find(|(k, _)| k == "id")
                        .unwrap()
                        .1
                        .into_owned();
                    body["id"] = json!(id);
                    ResponseTemplate::new(200).set_body_json(body)
                }
                ("GET", "/api/lists/index") => vl::response(
                    FLAVOR,
                    if mode == "preflight"
                        && index_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0
                    {
                        "index_before"
                    } else {
                        "index_after"
                    },
                ),
                ("PATCH", "/api/lists") => vl::response(FLAVOR, "container_patch_stale"),
                ("POST", "/api/lists/items/_import") => vl::response(FLAVOR, "container_read"),
                ("GET", "/api/status") => vl::response(FLAVOR, "status"),
                ("GET", "/api/exception_lists") => vl::response(FLAVOR, "exception_create"),
                ("POST", "/api/lists/items/_export") => vl::response(FLAVOR, "items_export"),
                _ => panic!("unexpected request: {} {}", request.method, request.url),
            }
        })
        .mount(&server)
        .await;
    server
}

fn capture(root: &Path, server: &MockServer, output: &std::process::Output, json: bool) -> Value {
    let mut captured = vl::capture(root, &server.uri(), output);
    if !json {
        captured["stdout"] = json!(
            captured["stdout"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        );
    }
    captured
}

async fn stop(mode: &str, json_output: bool, report: bool) {
    let root = tempfile::tempdir().unwrap();
    let server = setup(root.path(), mode).await;
    let mut args = vec!["state", "push", "--dir", "ROOT/mirror", "--yes"];
    if json_output {
        args.push("--json");
    }
    if report {
        args.extend(["--report", "ROOT/report.json"]);
    }
    let output = vl::run(root.path(), &server.uri(), FLAVOR, &args);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error: Value =
        serde_json::from_str(stderr.lines().last().unwrap()).unwrap_or_else(|_| panic!("{stderr}"));
    assert_eq!(
        error["error"]["kind"],
        if mode == "failed" {
            "conflict"
        } else if mode == "preflight" {
            "unsupported"
        } else {
            "http"
        },
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(&vl::id(FLAVOR)));
    assert!(stdout.contains("not_reached"));
    if json_output {
        let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(summary["failed"], 1);
        assert_eq!(
            summary["value_lists"][0]["error"]["message"],
            error["error"]["message"]
        );
        assert_eq!(summary["value_lists"][1]["outcome"], "not_reached");
        if mode == "unknown" {
            let read = &summary["value_lists"][0]["evidence"][1];
            assert_eq!(read["action"], "read_back");
            assert_eq!(read["of"], "values");
            assert_eq!(read["observed"], true);
            assert_eq!(read["missing"], 1);
            assert_eq!(read["extra"], 0);
        }
    }
    if mode == "unknown" {
        assert!(stdout.contains("read_back"));
        for text in [
            "wait",
            "run diff",
            "push again only when its preview is what you expect",
        ] {
            assert!(stdout.contains(text), "{stdout}");
        }
    }
    let mut captured = capture(root.path(), &server, &output, json_output);
    if report {
        let mut body: Value =
            serde_json::from_slice(&std::fs::read(root.path().join("report.json")).unwrap())
                .unwrap();
        assert_eq!(body["entries"][0]["error"]["kind"], error["error"]["kind"]);
        assert_eq!(body["host"], server.uri().trim_start_matches("http://"));
        body["host"] = json!("HOST");
        captured["report"] = body;
    }
    let writes: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method != "GET" && r.url.path() != "/api/lists/items/_export")
        .map(|r| (r.method.to_string(), r.url.path().to_owned()))
        .collect();
    assert_eq!(
        writes,
        match mode {
            "unknown" => vec![("POST".into(), "/api/lists/items/_import".into())],
            "failed" => vec![("PATCH".into(), "/api/lists".into())],
            _ => vec![],
        }
    );
    insta::assert_json_snapshot!(
        format!(
            "state_push_{mode}_{}_{}",
            if json_output { "json" } else { "text" },
            if report { "report" } else { "no_report" }
        ),
        captured
    );
}

#[tokio::test]
async fn unknown_text_without_report() {
    stop("unknown", false, false).await;
}
#[tokio::test]
async fn unknown_text_with_report() {
    stop("unknown", false, true).await;
}
#[tokio::test]
async fn unknown_json_without_report() {
    stop("unknown", true, false).await;
}
#[tokio::test]
async fn unknown_json_with_report() {
    stop("unknown", true, true).await;
}
#[tokio::test]
async fn failed_stop() {
    stop("failed", true, true).await;
}
#[tokio::test]
async fn failed_text_without_report() {
    stop("failed", false, false).await;
}
#[tokio::test]
async fn unchanged_preflight_refusal() {
    stop("preflight", true, true).await;
}

#[tokio::test]
async fn metadata_only_preview() {
    for json_output in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let server = setup(root.path(), "metadata").await;
        let mut args = vec!["state", "push", "--dir", "ROOT/mirror"];
        if json_output {
            args.push("--json");
        }
        let output = vl::run(root.path(), &server.uri(), FLAVOR, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        if json_output {
            let preview: Value = serde_json::from_str(stderr.lines().last().unwrap()).unwrap();
            assert_eq!(preview["lists"][0]["container_action"], "update");
            assert_eq!(preview["lists"][0]["adds"], json!([]));
            assert_eq!(preview["lists"][0]["removes"], json!([]));
            assert_eq!(preview["lists"][0]["phase_order"], "none");
        } else {
            assert!(stderr.contains("container: update"), "{stderr}");
        }
        vl::assert_read_only(&server).await;
        insta::assert_json_snapshot!(
            format!(
                "state_push_metadata_preview_{}",
                if json_output { "json" } else { "text" }
            ),
            capture(root.path(), &server, &output, json_output)
        );
    }
}

#[tokio::test]
async fn unchanged_lists_keep_output() {
    for json_output in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let server = setup(root.path(), "unchanged").await;
        let mut args = vec!["state", "push", "--dir", "ROOT/mirror", "--yes"];
        if json_output {
            args.push("--json");
        }
        let output = vl::run(root.path(), &server.uri(), FLAVOR, &args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        vl::assert_read_only(&server).await;
        insta::assert_json_snapshot!(
            format!(
                "state_push_unchanged_{}",
                if json_output { "json" } else { "text" }
            ),
            capture(root.path(), &server, &output, json_output)
        );
    }
}
