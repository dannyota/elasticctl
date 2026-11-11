use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn run(
    bin: &str,
    flags: &[&str],
    es: bool,
    url: &str,
) -> (std::process::Output, tempfile::TempDir) {
    run_target(bin, flags, es, url, "test", "default")
}

fn run_target(
    bin: &str,
    flags: &[&str],
    es: bool,
    url: &str,
    name: &str,
    space: &str,
) -> (std::process::Output, tempfile::TempDir) {
    run_request(
        bin,
        flags,
        es,
        url,
        name,
        space,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_request(
    bin: &str,
    flags: &[&str],
    es: bool,
    url: &str,
    name: &str,
    space: &str,
    request: Value,
) -> (std::process::Output, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let quoted = |v: &str| {
        let mut text = String::from("\"");
        for c in v.chars() {
            if c.is_control() {
                text.push_str(&format!("\\u{:04x}", c as u32));
            } else {
                text.push(c);
            }
        }
        text.push('"');
        text
    };
    std::fs::write(
        &config,
        format!(
            "current = {}\n[profiles.{}]\nkibana_url = {}\nspace = {}\n{}api_key = \"test\"\n",
            quoted(name),
            quoted(name),
            quoted(url),
            quoted(space),
            if es {
                "es_url = \"http://127.0.0.1:9\"\n"
            } else {
                ""
            }
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut command = Command::new(bin);
    for name in [
        "ELASTICCTL_KIBANA_URL",
        "ELASTICCTL_ES_URL",
        "ELASTICCTL_API_KEY",
        "ELASTICCTL_USERNAME",
        "ELASTICCTL_PASSWORD",
        "ELASTICCTL_SPACE",
        "ELASTICCTL_TIMEOUT",
    ] {
        command.env_remove(name);
    }
    let mut child = command
        .arg("--config")
        .arg(config)
        .args(["mcp", "serve"])
        .args(flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "{request}").ok();
    let mut line = Vec::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_until(b'\n', &mut line)
        .unwrap();
    drop(child.stdin.take());
    let mut output = child.wait_with_output().unwrap();
    output.stdout = line;
    (output, dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_flag_process_contract() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let url = server.uri();
    for bin in [
        env!("CARGO_BIN_EXE_elasticctl"),
        env!("CARGO_BIN_EXE_elkctl"),
    ] {
        for flags in [
            &["--allow-mutations", "rules-toggle"][..],
            &[
                "--allow-mutations",
                "rules-toggle",
                "--allow-mutations",
                "rules-toggle",
            ],
            &["--allow-mutations", "rules-toggle,rules-toggle"],
            &["--allow-mutations", "rules-toggle", "--allow-query-tools"],
        ] {
            let (out, _) = run(bin, flags, true, &url);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stderr, b"{\"warning\":{\"kind\":\"mutations_enabled\",\"message\":\"MCP mutation tools are enabled.\",\"classes\":[\"rules-toggle\"]}}\n");
            let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
            let tools = reply["result"]["tools"].as_array().unwrap();
            for name in [
                "plan_apply",
                "plan_discard",
                "plan_get",
                "plan_list",
                "rules_set_enabled_plan",
            ] {
                assert!(tools.iter().any(|tool| tool["name"] == name), "{name}");
            }
        }
        for value in [
            "",
            "all",
            "*",
            "rules-toggle,",
            ",rules-toggle",
            " rules-toggle",
            "rules-toggle ",
            "sentinel",
        ] {
            let (out, _) = run(bin, &["--allow-mutations", value], true, &url);
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
            assert_eq!(
                out.stderr,
                b"{\"error\":{\"kind\":\"error\",\"message\":\"Invalid MCP serve arguments.\"}}\n"
            );
        }
        let (out, _) = run(bin, &["--allow-mutations", "rules-toggle"], false, &url);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert_eq!(
            out.stderr,
            b"{\"error\":{\"kind\":\"error\",\"message\":\"MCP mutation tools need an Elasticsearch URL. Set es_url in the profile or ELASTICCTL_ES_URL.\"}}\n"
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        let (out, _) = run(bin, &["--allow-mutations"], true, &url);
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(
            out.stderr,
            b"{\"error\":{\"kind\":\"error\",\"message\":\"Invalid MCP serve arguments.\"}}\n"
        );
        let (out, _) = run(
            bin,
            &["--allow-mutations", "rules-toggle"],
            true,
            "ftp://localhost",
        );
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            out.stderr,
            b"{\"error\":{\"kind\":\"error\",\"message\":\"MCP server failed.\"}}\n"
        );
        let (out, _) = run(bin, &[], false, &url);
        assert!(out.status.success());
        let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
        let tools = reply["result"]["tools"].as_array().unwrap();
        for name in [
            "plan_apply",
            "plan_discard",
            "plan_get",
            "plan_list",
            "rules_set_enabled_plan",
        ] {
            assert!(!tools.iter().any(|tool| tool["name"] == name));
        }
        let (out, _) = run(bin, &["--yes"], false, &url);
        assert_eq!(out.status.code(), Some(2));
    }
}

#[test]
fn mutation_target_process_contract() {
    for bin in [
        env!("CARGO_BIN_EXE_elasticctl"),
        env!("CARGO_BIN_EXE_elkctl"),
    ] {
        for control in [
            '\n', '\r', '\t', '\u{7f}', '\u{85}', '\u{2028}', '\u{202e}', '\u{2066}',
        ] {
            for field in ["profile", "host", "space"] {
                let bad = format!("test{control}continued");
                let url = if field == "host" {
                    format!("https://{bad}.example.test")
                } else {
                    "https://kibana.example.test".into()
                };
                let name = if field == "profile" {
                    bad.as_str()
                } else {
                    "test"
                };
                let space = if field == "space" {
                    bad.as_str()
                } else {
                    "default"
                };
                let (out, _) = run_target(
                    bin,
                    &["--allow-mutations", "rules-toggle"],
                    true,
                    &url,
                    name,
                    space,
                );
                assert_eq!(out.status.code(), Some(1), "{field}: {out:?}");
                assert!(out.stdout.is_empty());
                let expected = if field == "space" {
                    "MCP startup configuration could not be resolved."
                } else {
                    "MCP mutation tools need a profile name, host, and space without line breaks or control characters."
                };
                assert_eq!(
                    out.stderr,
                    format!("{}\n", json!({"error":{"kind":"error","message":expected}}))
                        .as_bytes()
                );
                if field == "host" && !matches!(control, '\n' | '\r' | '\t') {
                    continue;
                }
                let (out, _) = run_target(bin, &[], true, &url, name, space);
                if field == "space" {
                    assert_eq!(out.status.code(), Some(1));
                    assert!(out.stdout.is_empty());
                    assert_eq!(out.stderr, b"{\"error\":{\"kind\":\"error\",\"message\":\"MCP startup configuration could not be resolved.\"}}\n");
                    continue;
                }
                assert!(out.status.success(), "{out:?}");
                let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
                assert!(reply["result"]["tools"].is_array());
            }
        }
    }
}

// Captured from unmodified a46f4c38a5de6405ff76824261d077c22e457dd2
// (Task 0 on released 0.9.0), using this process test with
// The capture-only test wrote compact result JSON from tools/list with
// --allow-mutations rules-toggle, with and without --allow-query-tools.
// The committed test only compares those frozen captures.
#[test]
fn toggle_catalog_snapshot() {
    for query in [false, true] {
        let mut flags = vec!["--allow-mutations", "rules-toggle"];
        if query {
            flags.push("--allow-query-tools");
        }
        let (out, _) = run(
            env!("CARGO_BIN_EXE_elasticctl"),
            &flags,
            true,
            "https://kibana.example.test",
        );
        assert!(out.status.success());
        let reply: Value = serde_json::from_slice(&out.stdout).unwrap();
        let actual = serde_json::to_string(&reply["result"]).unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/snapshots/mcp_toggle_{query}.json"));
        assert_eq!(actual, std::fs::read_to_string(path).unwrap());
    }
}

#[test]
fn new_class_process_contract() {
    for value in [
        "alerts-triage",
        "cases",
        "rules-create",
        "rules-toggle,rules-create,cases,alerts-triage",
    ] {
        let (out, _) = run(
            env!("CARGO_BIN_EXE_elasticctl"),
            &["--allow-mutations", value],
            true,
            "https://kibana.example.test",
        );
        assert!(
            out.status.success(),
            "{value}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let warning: Value = serde_json::from_slice(&out.stderr).unwrap();
        let mut names: Vec<_> = value.split(',').collect();
        names.sort_unstable();
        assert_eq!(warning["warning"]["classes"], json!(names));
    }
}

// Read-only results/instructions: tag v0.8.2. Toggle: unmodified a46f4c38 (0.9.0 + Task 0).
// Reproduce by git archive of that revision, cargo build --locked -p elasticctl
// --bin elasticctl --jobs 2, and these direct-start JSON-RPC requests.
#[test]
fn compatibility_results_and_instructions() {
    for toggle in [false, true] {
        let flags = if toggle {
            vec!["--allow-mutations", "rules-toggle"]
        } else {
            vec![]
        };
        let mut captures = Vec::new();
        for method in [
            "server/discover",
            "plan_list",
            "plan_get",
            "plan_discard",
            "plan_apply",
            "rules_set_enabled_plan",
        ] {
            let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}});
            let request = if method == "server/discover" {
                json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"_meta":meta}})
            } else {
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":method,"arguments":{},"_meta":meta}})
            };
            let bin = env!("CARGO_BIN_EXE_elasticctl");
            let (out, _) = run_request(
                bin,
                &flags,
                true,
                "https://kibana.example.test",
                "test",
                "default",
                request,
            );
            assert!(out.status.success());
            if method == "server/discover" {
                let response: Value = serde_json::from_slice(&out.stdout).unwrap();
                captures.push(format!(
                    "{}\n",
                    serde_json::to_string(&response["result"]["instructions"]).unwrap()
                ));
            } else {
                captures.push(String::from_utf8(out.stdout).unwrap());
            }
        }
        let actual = captures.concat();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("tests/snapshots/mcp_compatibility_{toggle}.jsonl"));
        assert_eq!(actual, std::fs::read_to_string(path).unwrap());
    }
}
