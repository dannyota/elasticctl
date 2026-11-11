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
    writeln!(child.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}})).ok();
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
            "alerts-triage",
            "cases",
            "rules-create",
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
