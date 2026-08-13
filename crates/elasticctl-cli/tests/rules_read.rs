use std::fs;

#[test]
fn validate_accepts_a_well_formed_yaml_rule_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.yaml");
    fs::write(
        &path,
        "- rule_id: abc\n  name: A rule\n  type: query\n  query: '*:*'\n  severity: low\n  risk_score: 21\n",
    )
    .unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["valid"], true);
    assert_eq!(v["count"], 1);
}

#[test]
fn validate_reports_a_rule_missing_its_rule_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.yaml");
    fs::write(&path, "- name: no identity\n  type: query\n").unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("rule_id"));
}

#[test]
fn validate_shows_which_server_defaults_would_be_applied() {
    // A sparse file is valid; the operator should still see what it becomes.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sparse.yaml");
    fs::write(&path, "- rule_id: abc\n  name: A rule\n  type: query\n").unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let filled = v["rules"][0]["defaults_applied"].as_array().unwrap();
    assert!(filled.iter().any(|f| f == "max_signals"), "{filled:?}");
    assert!(filled.iter().any(|f| f == "to"), "{filled:?}");
}

#[test]
fn validate_reads_ndjson_by_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.ndjson");
    fs::write(
        &path,
        "{\"rule_id\":\"abc\",\"name\":\"A\",\"type\":\"query\"}\n",
    )
    .unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["count"], 1);
}

#[test]
fn validate_ignores_the_export_trailer_in_an_ndjson_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exported.ndjson");
    fs::write(
        &path,
        "{\"rule_id\":\"abc\",\"name\":\"A\",\"type\":\"query\"}\n{\"exported_count\":1,\"exported_rules_count\":1}\n",
    )
    .unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["count"], 1, "the trailer is not a rule");
}

#[test]
fn validate_of_a_missing_file_is_a_clean_error_not_a_panic() {
    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args([
            "rules",
            "validate",
            "--json",
            "--path",
            "/nonexistent/nope.yaml",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stderr).is_ok());
}

/// `Rule::from_value` only checks that `rule_id` is present, not that it is
/// a string, so an unquoted numeric id — a plausible hand-editing slip —
/// decodes without error. `validate` must still catch it: a blank identity
/// behind "valid": true would be a false clean bill of health.
#[test]
fn validate_reports_a_rule_whose_rule_id_is_not_a_string() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("numeric_id.yaml");
    fs::write(&path, "- rule_id: 123\n  name: A rule\n  type: query\n").unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    assert!(v["error"]["message"].as_str().unwrap().contains("rule_id"));
}

#[test]
fn validate_of_a_mixed_file_names_the_index_of_the_bad_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.yaml");
    fs::write(
        &path,
        "- rule_id: good\n  name: Good rule\n  type: query\n\
         - rule_id: 123\n  name: Bad rule\n  type: query\n",
    )
    .unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--path"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stderr).unwrap();
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("index 1"), "must name the bad index: {msg}");
    assert!(msg.contains("rule_id"), "{msg}");
}

/// `validate` must work with a profile that carries no credential at all —
/// it is a local, offline check and must never require one.
#[test]
fn validate_succeeds_against_a_credential_less_profile() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        "current = \"nocreds\"\n\n\
         [profiles.nocreds]\n\
         kibana_url = \"https://kb.example.com\"\n\
         space = \"default\"\n\
         verify = true\n\
         timeout_secs = 30\n",
    )
    .unwrap();

    let rule_path = dir.path().join("rules.yaml");
    fs::write(
        &rule_path,
        "- rule_id: abc\n  name: A rule\n  type: query\n",
    )
    .unwrap();

    let out = assert_cmd::Command::cargo_bin("elasticctl")
        .unwrap()
        .args(["rules", "validate", "--json", "--config"])
        .arg(&config)
        .args(["--path"])
        .arg(&rule_path)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["valid"], true);
}
