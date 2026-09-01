use assert_cmd::Command;

/// `elkctl` is the short alias binary; the surface is byte-identical to
/// `elasticctl` because both compile from the same entrypoint.
#[test]
fn elkctl_serves_the_same_command_tree() {
    let long = Command::cargo_bin("elasticctl")
        .unwrap()
        .arg("commands")
        .output()
        .unwrap();
    let short = Command::cargo_bin("elkctl")
        .unwrap()
        .arg("commands")
        .output()
        .unwrap();
    assert!(long.status.success() && short.status.success());
    assert_eq!(long.stdout, short.stdout, "one surface, two names");
}

#[test]
fn elkctl_help_succeeds_and_names_the_invoked_binary() {
    let out = Command::cargo_bin("elkctl")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("elkctl"),
        "usage reflects the invoked name: {text}"
    );
}

#[test]
fn elkctl_completions_complete_the_invoked_name() {
    let out = Command::cargo_bin("elkctl")
        .unwrap()
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let script = String::from_utf8_lossy(&out.stdout);
    assert!(script.contains("elkctl"), "{script}");
    assert!(
        !script.contains("elasticctl"),
        "the script must key on the invoked name only: {script}"
    );
}
