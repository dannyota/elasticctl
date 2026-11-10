use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

fn run(bin: &str, flags: &[&str], es: bool) -> (std::process::Output, tempfile::TempDir) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "current = \"test\"\n[profiles.test]\nkibana_url = \"{url}\"\n{}api_key = \"test\"\n",
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
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    (output, dir)
}

#[test]
fn mutation_flag_process_contract() {
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
            let (out, _) = run(bin, flags, true);
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let warning: Value = serde_json::from_slice(&out.stderr).unwrap();
            assert_eq!(
                warning,
                json!({"warning":{"kind":"mutations_enabled","message":"MCP mutation tools are enabled.","classes":["rules-toggle"]}})
            );
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
            "rules-toggle,",
            ",rules-toggle",
            " rules-toggle",
            "rules-toggle ",
            "sentinel",
        ] {
            let (out, _) = run(bin, &["--allow-mutations", value], true);
            assert_eq!(out.status.code(), Some(2));
            assert!(out.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stderr).unwrap(),
                json!({"error":{"kind":"error","message":"Invalid MCP serve arguments."}})
            );
        }
        let (out, _) = run(bin, &["--allow-mutations", "rules-toggle"], false);
        assert_eq!(out.status.code(), Some(1));
        assert!(out.stdout.is_empty());
        assert_eq!(
            serde_json::from_slice::<Value>(&out.stderr).unwrap(),
            json!({"error":{"kind":"error","message":"MCP mutation tools need an Elasticsearch URL. Set es_url in the profile or ELASTICCTL_ES_URL."}})
        );
        let (out, _) = run(bin, &[], false);
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
        let (out, _) = run(bin, &["--yes"], false);
        assert_eq!(out.status.code(), Some(2));
    }
}
