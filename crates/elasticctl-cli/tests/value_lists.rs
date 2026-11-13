use assert_cmd::Command;

#[test]
fn validate_reads_both_files_without_a_profile() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = dir.path().join("example.yaml");
    std::fs::write(
        &yaml,
        "id: example\ntype: keyword\nname: Example\ndescription: Example list\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("example.txt"), "alpha\nbeta\n").unwrap();
    Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["value-lists", "validate", "--path"])
        .arg(yaml)
        .args(["--json", "--config"])
        .arg(dir.path().join("missing.toml"))
        .assert()
        .success();
}

mod common;
#[path = "value_lists/state_push.rs"]
mod state_push;
#[path = "value_lists/common.rs"]
mod vl;

#[test]
fn help_tree_and_completions_expose_the_complete_group() {
    let root = tempfile::tempdir().unwrap();
    let verbs = [
        "list", "get", "validate", "export", "import", "delete", "init",
    ];
    let output = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["value-lists", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = vl::normalize(root.path(), "http://127.0.0.1:1", &output.stdout);
    for verb in verbs {
        assert!(help.contains(verb), "missing {verb}: {help}");
    }
    insta::assert_snapshot!("help", help);
    for verb in verbs {
        let output = Command::cargo_bin("elasticctl")
            .unwrap()
            .args(["value-lists", verb, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        insta::assert_snapshot!(
            format!("help_{verb}"),
            vl::normalize(root.path(), "http://127.0.0.1:1", &output.stdout)
        );
    }
    let output = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["commands", "--json"])
        .output()
        .unwrap();
    let tree: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let group = tree["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "value-lists")
        .unwrap();
    let children = group["subcommands"].as_array().unwrap();
    assert_eq!(children.len(), 7);
    for verb in verbs {
        let node = children.iter().find(|v| v["name"] == verb).unwrap();
        assert_eq!(
            node["mutates"],
            matches!(verb, "import" | "delete" | "init")
        );
    }
    insta::assert_json_snapshot!("tree", group);
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = Command::cargo_bin("elasticctl")
            .unwrap()
            .args(["completion", shell])
            .output()
            .unwrap();
        assert!(output.status.success());
        let script = String::from_utf8(output.stdout).unwrap();
        assert!(script.contains("value-lists"), "{shell}");
        for verb in verbs {
            assert!(script.contains(verb), "{shell}: {verb}");
        }
    }
}

#[tokio::test]
async fn get_reports_stored_and_distinct_counts_and_optional_values() {
    for flavor in vl::FLAVORS {
        let server = vl::server(flavor, true, "container_delete").await;
        let root = tempfile::tempdir().unwrap();
        for json in [false, true] {
            for values in [false, true] {
                let mut args = vec!["value-lists", "get", "ID"];
                if values {
                    args.push("--values");
                }
                if json {
                    args.push("--json");
                }
                let out = vl::run(root.path(), &server.uri(), flavor, &args);
                assert!(
                    out.status.success(),
                    "{:?}",
                    vl::capture(root.path(), &server.uri(), &out)
                );
                if json {
                    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                    let stored = vl::fixture(flavor, "items_export");
                    assert_eq!(
                        value["distinct_values"],
                        vl::values(flavor, "items_export").len()
                    );
                    assert_eq!(
                        value["stored_values"],
                        stored["response"].as_str().unwrap().lines().count()
                    );
                    assert_eq!(value.get("values").is_some(), values);
                }
                if flavor == vl::FLAVORS[0] {
                    insta::assert_json_snapshot!(
                        format!(
                            "get_{}_{}",
                            if json { "json" } else { "text" },
                            if values { "values" } else { "counts" }
                        ),
                        vl::capture(root.path(), &server.uri(), &out)
                    );
                }
            }
        }
        vl::assert_read_only(&server).await;
    }
}

#[tokio::test]
async fn export_inline_or_files_preserves_the_pair_and_routes_only_the_report() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &["value-lists", "export", "ID", "--json"],
    );
    assert!(
        out.status.success(),
        "{:?}",
        vl::capture(root.path(), &server.uri(), &out)
    );
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        value["values"],
        serde_json::json!(vl::values(flavor, "items_export"))
    );
    assert_eq!(value["container"]["id"], vl::id(flavor));
    assert!(
        !root
            .path()
            .join(format!("{}.yaml", vl::id(flavor)))
            .exists()
    );
    insta::assert_json_snapshot!(
        "export_inline",
        vl::capture(root.path(), &server.uri(), &out)
    );
    for json in [false, true] {
        let dir = if json { "json" } else { "text" };
        let path = format!("ROOT/{dir}");
        let mut args = vec!["value-lists", "export", "ID", "--dir", &path];
        if json {
            args.push("--json");
        }
        let out = vl::run(root.path(), &server.uri(), flavor, &args);
        assert!(out.status.success());
        assert_eq!(
            std::fs::read_to_string(
                root.path()
                    .join(dir)
                    .join(format!("{}.txt", vl::id(flavor)))
            )
            .unwrap(),
            vl::values_text(&vl::values(flavor, "items_export"))
        );
        insta::assert_json_snapshot!(
            format!("export_{dir}"),
            vl::capture(root.path(), &server.uri(), &out)
        );
    }
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &[
            "value-lists",
            "export",
            "ID",
            "--dir",
            "ROOT/routed",
            "--format",
            "csv",
            "--fields",
            "id",
            "--out",
            "ROOT/report",
        ],
    );
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(
        std::fs::read_to_string(
            root.path()
                .join("routed")
                .join(format!("{}.yaml", vl::id(flavor)))
        )
        .unwrap()
        .contains(&format!(
            "type: {}",
            vl::fixture(flavor, "container_read")["response"]["type"]
                .as_str()
                .unwrap()
        ))
    );
    assert!(
        std::fs::read_to_string(root.path().join("report"))
            .unwrap()
            .contains(&vl::id(flavor))
    );
    vl::assert_read_only(&server).await;
}

#[tokio::test]
async fn init_previews_and_applies_only_the_initialize_flow() {
    for flavor in vl::FLAVORS {
        for json in [false, true] {
            let server = vl::server(flavor, false, "container_delete").await;
            let root = tempfile::tempdir().unwrap();
            let mut args = vec!["value-lists", "init"];
            if json {
                args.push("--json");
            }
            let out = vl::run(root.path(), &server.uri(), flavor, &args);
            assert!(
                out.status.success(),
                "{:?}",
                vl::capture(root.path(), &server.uri(), &out)
            );
            vl::assert_read_only(&server).await;
            if json {
                let preview: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
                assert_eq!(preview["flow"], "create-list-indices");
                assert_eq!(preview["lists"], serde_json::json!([]));
                assert_eq!(preview["dry_run"], true);
            }
            if flavor == vl::FLAVORS[0] {
                insta::assert_json_snapshot!(
                    format!("init_preview_{}", if json { "json" } else { "text" }),
                    vl::capture(root.path(), &server.uri(), &out)
                );
            }
            vl::mount_index(&server, flavor, "index_before", 2, 1).await;
            vl::mount_index(&server, flavor, "index_after", 1, 2).await;
            wiremock::Mock::given(wiremock::matchers::method("POST"))
                .and(wiremock::matchers::path(
                    "/api/security_solution/initialize",
                ))
                .and(wiremock::matchers::body_json(
                    serde_json::json!({"flows": ["create-list-indices"]}),
                ))
                .respond_with(vl::response(flavor, "initialize"))
                .with_priority(1)
                .expect(1)
                .mount(&server)
                .await;
            args.push("--yes");
            let out = vl::run(root.path(), &server.uri(), flavor, &args);
            assert!(
                out.status.success(),
                "{:?}",
                vl::capture(root.path(), &server.uri(), &out)
            );
            if flavor == vl::FLAVORS[0] {
                insta::assert_json_snapshot!(
                    format!("init_apply_{}", if json { "json" } else { "text" }),
                    vl::capture(root.path(), &server.uri(), &out)
                );
            }
        }
    }
}

#[tokio::test]
async fn import_and_delete_preview_without_writes_and_publish_apply_evidence() {
    for flavor in vl::FLAVORS {
        for json in [false, true] {
            let server = vl::server(flavor, true, "container_delete").await;
            let root = tempfile::tempdir().unwrap();
            vl::local_pair(root.path(), flavor);
            for apply in [false, true] {
                for verb in ["import", "delete"] {
                    let mut args = vec!["value-lists", verb];
                    if verb == "import" {
                        args.extend(["--path", "ROOT/ID.txt", "--overwrite"]);
                    } else {
                        args.push("ID");
                    }
                    if json {
                        args.push("--json");
                    }
                    if apply {
                        args.push("--yes");
                    }
                    let out = vl::run(root.path(), &server.uri(), flavor, &args);
                    assert!(
                        out.status.success(),
                        "{:?}",
                        vl::capture(root.path(), &server.uri(), &out)
                    );
                    if json {
                        let preview: serde_json::Value =
                            serde_json::from_slice(&out.stderr).unwrap();
                        assert_eq!(preview["dry_run"], !apply);
                        assert_eq!(preview["lists"][0]["id"], vl::id(flavor));
                        assert_eq!(
                            preview["lists"][0]["type"],
                            vl::fixture(flavor, "container_read")["response"]["type"]
                        );
                        assert_eq!(preview["command"], format!("value-lists {verb}"));
                    }
                    if !apply {
                        vl::assert_read_only(&server).await;
                    }
                    if flavor == vl::FLAVORS[0] {
                        insta::assert_json_snapshot!(
                            format!(
                                "{verb}_{}_{}",
                                if apply { "apply" } else { "preview" },
                                if json { "json" } else { "text" }
                            ),
                            vl::capture(root.path(), &server.uri(), &out)
                        );
                    }
                }
            }
            for request in server.received_requests().await.unwrap() {
                if request.method == "DELETE" {
                    assert_eq!(request.url.path(), "/api/lists");
                    assert_eq!(
                        request.url.query().unwrap(),
                        format!("id={}", vl::id(flavor))
                    );
                    assert!(request.body.is_empty());
                }
            }
        }
    }
}

#[tokio::test]
async fn delete_conflict_publishes_evidence_and_the_reference_error_before_exit_one() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete_referenced").await;
    let root = tempfile::tempdir().unwrap();
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &[
            "value-lists",
            "delete",
            "ID",
            "--yes",
            "--json",
            "--out",
            "ROOT/report",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.path().join("report")).unwrap()).unwrap();
    assert_eq!(report["lists"][0]["result"]["outcome"], "failed");
    assert_eq!(report["lists"][0]["result"]["error"]["kind"], "conflict");
    let stderr = String::from_utf8(out.stderr.clone()).unwrap();
    let conflict = vl::fixture(flavor, "container_delete_referenced");
    let references = conflict["response"]["message"]["error"]["references"]
        .as_array()
        .unwrap();
    assert!(!references.is_empty());
    let expected: Vec<_> = references.iter().map(|reference| {
        let item = &reference["exception_item"];
        serde_json::json!({"container": {"list_id": item["list_id"], "namespace_type": item["namespace_type"]}, "item_id": item["item_id"]})
    }).collect();
    assert_eq!(
        report["lists"][0]["references"],
        serde_json::json!(expected)
    );
    for reference in references {
        let item = &reference["exception_item"];
        assert!(stderr.contains(item["item_id"].as_str().unwrap()));
        assert!(stderr.contains(item["list_id"].as_str().unwrap()));
        assert!(stderr.contains(item["namespace_type"].as_str().unwrap()));
    }
    insta::assert_json_snapshot!(
        "delete_conflict",
        vl::capture(root.path(), &server.uri(), &out)
    );
}

#[tokio::test]
async fn import_refuses_existing_without_overwrite_and_rechecks_before_apply() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    vl::local_pair(root.path(), flavor);
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &["value-lists", "import", "--path", "ROOT/ID.yaml", "--json"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--overwrite"));
    insta::assert_json_snapshot!(
        "import_existing",
        vl::capture(root.path(), &server.uri(), &out)
    );
    vl::mount_get(&server, flavor, "container_read", 1).await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/lists"))
        .respond_with(vl::response(flavor, "container_patch"))
        .with_priority(2)
        .mount(&server)
        .await;
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &[
            "value-lists",
            "import",
            "--path",
            "ROOT/ID.yaml",
            "--overwrite",
            "--yes",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("changed since preview"));
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["lists"][0]["outcome"], "failed");
    insta::assert_json_snapshot!(
        "import_changed",
        vl::capture(root.path(), &server.uri(), &out)
    );
    vl::assert_read_only(&server).await;
}

#[test]
fn validate_snapshots_and_import_validation_precedes_context() {
    let root = tempfile::tempdir().unwrap();
    let flavor = vl::FLAVORS[0];
    vl::local_pair(root.path(), flavor);
    for json in [false, true] {
        let mut args = vec!["value-lists", "validate", "--path", "ROOT/ID.yaml"];
        if json {
            args.push("--json");
        }
        let out = vl::run(root.path(), "http://127.0.0.1:1", flavor, &args);
        assert!(out.status.success());
        insta::assert_json_snapshot!(
            format!("validate_{}", if json { "json" } else { "text" }),
            vl::capture(root.path(), "http://127.0.0.1:1", &out)
        );
    }
    let out = Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["value-lists", "import", "--path"])
        .arg(root.path().join("missing.yaml"))
        .args(["--config"])
        .arg(root.path().join("absent.toml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("missing.yaml"));
}

#[tokio::test]
async fn import_preview_includes_every_add_remove_and_phase_reason() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let container = vl::fixture(flavor, "contain_create")["response"].clone();
    let id = container["id"].as_str().unwrap();
    let before = vl::values(flavor, "contain_export");
    let mut desired = vl::values(flavor, "contain_export_after");
    desired.extend(["10.0.0.9/32".to_owned(), "10.0.0.8/32".to_owned()]);
    let adds: std::collections::BTreeSet<_> = desired.difference(&before).cloned().collect();
    let removes: std::collections::BTreeSet<_> = before.difference(&desired).cloned().collect();
    assert!(!adds.is_empty() && !removes.is_empty());
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path("/api/lists"))
        .and(wiremock::matchers::query_param("id", id))
        .respond_with(vl::response(flavor, "contain_create"))
        .with_priority(1)
        .mount(&server)
        .await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/api/lists/items/_export"))
        .and(wiremock::matchers::query_param("list_id", id))
        .respond_with(vl::response(flavor, "contain_export"))
        .with_priority(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(format!("{id}.yaml"));
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({"id": id, "type": container["type"], "name": "Updated", "description": container["description"], "meta": container["meta"]})).unwrap(),
    )
    .unwrap();
    std::fs::write(path.with_extension("txt"), vl::values_text(&desired)).unwrap();
    for json in [false, true] {
        let file = path.to_str().unwrap();
        let mut args = vec!["value-lists", "import", "--path", file, "--overwrite"];
        if json {
            args.push("--json");
        }
        let out = vl::run(root.path(), &server.uri(), flavor, &args);
        assert!(
            out.status.success(),
            "{:?}",
            vl::capture(root.path(), &server.uri(), &out)
        );
        if json {
            let preview: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
            let keys: Vec<_> = preview
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                ["dry_run", "profile", "host", "space", "command", "lists"]
            );
            let list = &preview["lists"][0];
            assert_eq!(list["adds"], serde_json::json!(adds));
            assert_eq!(list["removes"], serde_json::json!(removes));
            assert_eq!(list["container_action"], "update");
            assert_eq!(list["phase_order"], "removes_first");
            assert!(!list["phase_reason"].as_str().unwrap().is_empty());
        }
        insta::assert_json_snapshot!(
            format!("import_changes_{}", if json { "json" } else { "text" }),
            vl::capture(root.path(), &server.uri(), &out)
        );
    }
    vl::assert_read_only(&server).await;
}

#[tokio::test]
async fn export_checks_every_destination_before_writing_any_pair() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("occupied.yaml"), "unchanged").unwrap();
    std::fs::write(root.path().join("occupied.txt"), "unchanged\n").unwrap();
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &[
            "value-lists",
            "export",
            "ID",
            "occupied",
            "--dir",
            "ROOT",
            "--json",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("occupied.yaml") && err.contains("occupied.txt"));
    assert!(
        !root
            .path()
            .join(format!("{}.yaml", vl::id(flavor)))
            .exists()
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("occupied.txt")).unwrap(),
        "unchanged\n"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    insta::assert_json_snapshot!(
        "export_existing",
        vl::capture(root.path(), &server.uri(), &out)
    );
}

#[tokio::test]
async fn init_already_bootstrapped_never_writes_even_with_yes() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    for json in [false, true] {
        let mut args = vec!["value-lists", "init", "--yes"];
        if json {
            args.push("--json");
        }
        let out = vl::run(root.path(), &server.uri(), flavor, &args);
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("already bootstrapped"));
        insta::assert_json_snapshot!(
            format!("init_already_{}", if json { "json" } else { "text" }),
            vl::capture(root.path(), &server.uri(), &out)
        );
    }
    vl::assert_read_only(&server).await;
}

#[tokio::test]
async fn init_non_ready_flow_derived_from_recorded_initialize_fails() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, false, "container_delete").await;
    let mut flow = vl::fixture(flavor, "initialize")["response"].clone();
    flow["flows"]["create-list-indices"]["status"] = serde_json::json!("failed");
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path(
            "/api/security_solution/initialize",
        ))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(flow))
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().unwrap();
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &["value-lists", "init", "--yes", "--json"],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("flow status is failed"));
    insta::assert_json_snapshot!(
        "init_failed_flow",
        vl::capture(root.path(), &server.uri(), &out)
    );
}

#[tokio::test]
async fn import_apply_updates_the_container_once_with_the_apply_time_version() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    let path = vl::local_pair(root.path(), flavor);
    let mut container: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    container["name"] = vl::fixture(flavor, "container_patch")["response"]["name"].clone();
    std::fs::write(&path, serde_json::to_vec(&container).unwrap()).unwrap();
    wiremock::Mock::given(wiremock::matchers::method("PATCH"))
        .and(wiremock::matchers::path("/api/lists"))
        .respond_with(vl::response(flavor, "container_patch"))
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    let out = vl::run(
        root.path(),
        &server.uri(),
        flavor,
        &[
            "value-lists",
            "import",
            "--path",
            "ROOT/ID.yaml",
            "--overwrite",
            "--yes",
            "--json",
        ],
    );
    assert!(
        out.status.success(),
        "{:?}",
        vl::capture(root.path(), &server.uri(), &out)
    );
    let requests = server.received_requests().await.unwrap();
    let writes: Vec<_> = requests
        .iter()
        .filter(|r| r.method != "GET" && r.url.path() != "/api/lists/items/_export")
        .collect();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].method, "PATCH");
    let body: serde_json::Value = serde_json::from_slice(&writes[0].body).unwrap();
    container.as_object_mut().unwrap().remove("type");
    container["_version"] = vl::fixture(flavor, "container_read")["response"]["_version"].clone();
    assert_eq!(body, container);
    insta::assert_json_snapshot!(
        "import_update",
        vl::capture(root.path(), &server.uri(), &out)
    );
}

#[tokio::test]
async fn list_reads_unfiltered_and_filters_locally_with_text_and_json_snapshots() {
    use serde_json::{Value, json};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer};
    for flavor in vl::FLAVORS {
        let f = vl::fixture(flavor, "cli_lists_all");
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/lists/_find"))
            .respond_with(vl::response(flavor, "cli_lists_all"))
            .mount(&server)
            .await;
        let root = tempfile::tempdir().unwrap();
        for (label, flags) in [
            ("all", vec![]),
            ("type", vec!["--type", "ip_range"]),
            ("search", vec!["--search", "ELASTICCTL"]),
            ("empty", vec!["--search", "no-matching-marker"]),
            (
                "combined",
                vec!["--type", "ip_range", "--search", "ELASTICCTL"],
            ),
        ] {
            for json_output in [false, true] {
                let mut args = vec!["value-lists", "list"];
                args.extend(flags.iter().copied());
                if json_output {
                    args.push("--json");
                }
                let out = vl::run(root.path(), &server.uri(), flavor, &args);
                assert!(
                    out.status.success(),
                    "{:?}",
                    vl::capture(root.path(), &server.uri(), &out)
                );
                if json_output {
                    let actual: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
                    let mut expected: Vec<_> = f["response"]["data"].as_array().unwrap().iter()
                        .filter(|row| !flags.contains(&"--type") || row["type"] == "ip_range")
                        .filter(|row| match label {
                            "empty" => false,
                            "search" | "combined" => row["id"].as_str().unwrap().to_lowercase().contains("elasticctl") || row["name"].as_str().unwrap().to_lowercase().contains("elasticctl"),
                            _ => true,
                        })
                        .map(|row| json!({"id": row["id"], "type": row["type"], "name": row["name"], "description": row["description"], "supported": matches!(row["type"].as_str(), Some("keyword" | "text" | "ip" | "ip_range"))})).collect();
                    expected.sort_by_key(|row| row["id"].as_str().unwrap().to_string());
                    assert_eq!(actual, expected);
                    if label == "all" {
                        assert!(
                            actual.iter().any(|row| row["supported"] == false),
                            "recording must include an unsupported list"
                        );
                    }
                }
                if flavor == vl::FLAVORS[0] {
                    insta::assert_json_snapshot!(
                        format!("list_{label}_{}", if json_output { "json" } else { "text" }),
                        vl::capture(root.path(), &server.uri(), &out)
                    );
                }
            }
        }
        for request in server.received_requests().await.unwrap() {
            assert_eq!(request.method, "GET");
            assert_eq!(request.url.path(), "/api/lists/_find");
            assert_eq!(request.url.query().unwrap(), "page=1&per_page=1000");
            assert!(request.body.is_empty());
        }
    }
}

#[tokio::test]
async fn export_refuses_report_paths_that_alias_either_exported_file() {
    let flavor = vl::FLAVORS[0];
    let server = vl::server(flavor, true, "container_delete").await;
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("destination")).unwrap();
    let mut outputs = vec![
        "ROOT/destination/ID.yaml",
        "ROOT/destination/ID.txt",
        "destination/../destination/ID.txt",
    ];
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.path().join("destination"), root.path().join("alias"))
            .unwrap();
        std::os::unix::fs::symlink(
            root.path()
                .join(format!("destination/{}.txt", vl::id(flavor))),
            root.path().join("report-link"),
        )
        .unwrap();
        outputs.extend(["ROOT/alias/ID.txt", "ROOT/report-link"]);
    }
    for output in outputs {
        let out = vl::run(
            root.path(),
            &server.uri(),
            flavor,
            &[
                "value-lists",
                "export",
                "ID",
                "--dir",
                "ROOT/destination",
                "--out",
                output,
            ],
        );
        assert_eq!(
            out.status.code(),
            Some(1),
            "{output}: {:?}",
            vl::capture(root.path(), &server.uri(), &out)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("report path"));
        assert_eq!(
            std::fs::read_dir(root.path().join("destination"))
                .unwrap()
                .count(),
            0
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
