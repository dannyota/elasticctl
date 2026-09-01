//! Concurrent runner for the three live conformance legs.
//!
//! `cargo xtask conformance` proves one flavor at a time and is the
//! target-neutral release-evidence entrypoint (design spec 8.3). Recording
//! must run serially against a single stack, but the three conformance
//! targets are independent: proving serverless correctness never depends on
//! the state of Elastic Cloud Hosted or the local lab. This runner spawns
//! each requested flavor's `conformance` invocation as a child of the current
//! executable and joins them, so the release matrix costs roughly the
//! slowest leg's wall clock (usually the self-managed lab boot) instead of
//! the sum of all three.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const FLAVORS: [&str; 3] = ["serverless", "ech", "traditional"];

#[derive(Debug)]
struct Args {
    report_dir: PathBuf,
    flavors: Vec<String>,
}

impl Args {
    fn parse(values: &[String]) -> Result<Self, String> {
        let mut report_dir = None;
        let mut flavors = None;
        let mut index = 0;
        while index < values.len() {
            match values[index].as_str() {
                "--report-dir" => {
                    if report_dir.is_some() {
                        return Err("duplicate --report-dir".to_string());
                    }
                    let value = values
                        .get(index + 1)
                        .ok_or_else(|| "missing value for --report-dir".to_string())?;
                    report_dir = Some(PathBuf::from(value));
                    index += 2;
                }
                "--flavors" => {
                    if flavors.is_some() {
                        return Err("duplicate --flavors".to_string());
                    }
                    let value = values
                        .get(index + 1)
                        .ok_or_else(|| "missing value for --flavors".to_string())?;
                    flavors = Some(parse_flavors(value)?);
                    index += 2;
                }
                _ => return Err("unknown option".to_string()),
            }
        }
        Ok(Self {
            report_dir: report_dir.ok_or_else(|| "missing --report-dir".to_string())?,
            flavors: flavors.unwrap_or_else(|| FLAVORS.iter().map(|f| f.to_string()).collect()),
        })
    }
}

/// Parse a comma-separated flavor list, rejecting an unknown name or a repeat
/// without echoing the offending value, matching `conformance::Args::parse`'s
/// style.
fn parse_flavors(value: &str) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut flavors = Vec::new();
    for raw in value.split(',') {
        let name = raw.trim();
        if !FLAVORS.contains(&name) {
            return Err(
                "invalid flavor in --flavors; expected serverless, ech, or traditional".to_string(),
            );
        }
        if !seen.insert(name) {
            return Err("duplicate flavor in --flavors".to_string());
        }
        flavors.push(name.to_string());
    }
    Ok(flavors)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be inside the workspace")
        .to_path_buf()
}

/// Build the child invocation `conformance --flavor <f> --report-dir <dir>`
/// against the current executable, so a locally built `xtask` and one
/// installed elsewhere both dispatch to themselves rather than a `PATH`
/// lookup.
fn spawn_conformance_child(exe: &Path, flavor: &str, report_dir: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .arg("conformance")
        .arg("--flavor")
        .arg(flavor)
        .arg("--report-dir")
        .arg(report_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Stream a child's stdout and stderr to the parent's stdout, each line
/// prefixed with the flavor name, then wait for it to exit.
///
/// `conformance` writes only public one-line messages (design spec 8.3), so
/// no further redaction happens here. This helper must never be pointed at a
/// process that can print a credential; `lab/up.sh` and `lab/down.sh` are not
/// run through it for exactly that reason.
async fn stream_output(flavor: &str, mut child: Child) -> Result<ExitStatus, String> {
    let stdout = child
        .stdout
        .take()
        .expect("child was spawned with a piped stdout");
    let stderr = child
        .stderr
        .take()
        .expect("child was spawned with a piped stderr");

    let out_flavor = flavor.to_string();
    let stdout_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("[{out_flavor}] {line}");
        }
    });
    let err_flavor = flavor.to_string();
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            println!("[{err_flavor}] {line}");
        }
    });

    let status = child
        .wait()
        .await
        .map_err(|error| format!("waiting for {flavor} leg: {error}"))?;
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    Ok(status)
}

async fn run_serverless_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    // Inherit the parent environment unchanged: the generic `ELASTICCTL_*`
    // vars already point at the Serverless target.
    let child = spawn_conformance_child(&exe, "serverless", &report_dir)
        .spawn()
        .map_err(|error| format!("spawning serverless leg: {error}"))?;
    let status = stream_output("serverless", child).await?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("serverless leg exited with {status}"))
    }
}

/// Map the `ELASTICCTL_ECH_*` target onto the generic `ELASTICCTL_*` names the
/// child expects, the same mapping AGENTS.md documents for the fixture
/// recorder. Fail before spawning anything if a piece is missing.
async fn run_ech_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    let kibana_url = std::env::var("ELASTICCTL_ECH_KIBANA_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_KIBANA_URL".to_string())?;
    let es_url = std::env::var("ELASTICCTL_ECH_ES_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_ES_URL".to_string())?;
    let api_key = std::env::var("ELASTICCTL_ECH_API_KEY")
        .map_err(|_| "missing ELASTICCTL_ECH_API_KEY".to_string())?;

    let mut command = spawn_conformance_child(&exe, "ech", &report_dir);
    command
        .env("ELASTICCTL_KIBANA_URL", kibana_url)
        .env("ELASTICCTL_ES_URL", es_url)
        .env("ELASTICCTL_API_KEY", api_key);
    let child = command
        .spawn()
        .map_err(|error| format!("spawning ech leg: {error}"))?;
    let status = stream_output("ech", child).await?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("ech leg exited with {status}"))
    }
}

/// Mint a fresh Elasticsearch API key against the lab's bootstrap user.
///
/// `lab/up.sh` mints its own key and prints it for a human to paste into
/// `elasticctl config init`, but reading it back here would mean parsing
/// script stdout, which the design brief for this command forbids. Minting a
/// second, independent key sidesteps that parse entirely.
async fn mint_traditional_api_key() -> Result<String, String> {
    let mut profile = elasticctl_core::Profile {
        kibana_url: "http://localhost:9200".to_string(),
        es_url: Some("http://localhost:9200".to_string()),
        api_key: None,
        username: Some("elastic".to_string()),
        password: Some("elasticctl-lab".to_string()),
        space: "default".to_string(),
        verify: true,
        timeout_secs: 30,
    };
    profile.strip_userinfo();
    let transport = elasticctl_core::Transport::new(&profile)
        .map_err(|_| "building lab API key transport failed".to_string())?;
    let response = transport
        .post_absolute_es(
            "/_security/api_key",
            &serde_json::json!({"name": "elasticctl-matrix"}),
        )
        .await
        .map_err(|_| "minting lab API key failed".to_string())?;
    response["encoded"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "lab API key response is missing encoded".to_string())
}

fn lab_log_path(workspace: &Path, name: &str) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join("traditional")
        .join(format!("{name}.log"))
}

/// Write a private log with the same owner-only permissions `conformance`
/// uses for its own private logs (design spec 8.3): this file can hold
/// `lab/up.sh` output, which prints a plaintext API key.
fn write_private_log(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "conformance-matrix private log path is invalid".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "conformance-matrix private log write failed".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "conformance-matrix private log write failed".to_string())?;
        }
    }
    let mut file = options
        .open(path)
        .map_err(|_| "conformance-matrix private log write failed".to_string())?;
    file.write_all(bytes)
        .map_err(|_| "conformance-matrix private log write failed".to_string())
}

/// Run `lab/up.sh` or `lab/down.sh` to completion without ever printing its
/// output. `up.sh` prints a plaintext API key and the target URLs in its
/// final summary block, and the brief for this command forbids printing any
/// env value, not only the key this runner mints itself. Full output goes to
/// a private log instead, the same pattern `conformance` uses to keep
/// contract detail out of its public one-liners.
async fn run_lab_script(script: &Path, workspace: &Path, name: &str) -> Result<(), String> {
    println!("[traditional] {name} starting");
    let output = Command::new(script)
        .output()
        .await
        .map_err(|error| format!("running {name}: {error}"))?;

    let mut log = Vec::new();
    log.extend_from_slice(b"stdout:\n");
    log.extend_from_slice(&output.stdout);
    log.extend_from_slice(b"\nstderr:\n");
    log.extend_from_slice(&output.stderr);
    let log_path = lab_log_path(workspace, name);
    write_private_log(&log_path, &log)?;

    if output.status.success() {
        println!("[traditional] {name} finished");
        Ok(())
    } else {
        let relative = log_path.strip_prefix(workspace).unwrap_or(&log_path);
        Err(format!(
            "{name} exited with {}; private detail is in {}",
            output.status,
            relative.display()
        ))
    }
}

/// Run the self-managed leg: boot the lab, mint a key, run the conformance
/// child, then always tear the lab down.
///
/// Booting dominates wall clock (design spec 9: roughly 20 minutes), so this
/// whole function is one task the scheduler in `run` spawns alongside the
/// other two flavors; nothing here blocks them.
async fn run_traditional_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    let workspace = workspace_root();
    let up_script = workspace.join("lab").join("up.sh");
    let down_script = workspace.join("lab").join("down.sh");

    let result = match run_lab_script(&up_script, &workspace, "lab-up").await {
        Ok(()) => match mint_traditional_api_key().await {
            Ok(api_key) => {
                let mut command = spawn_conformance_child(&exe, "traditional", &report_dir);
                command
                    .env("ELASTICCTL_KIBANA_URL", "http://localhost:5601")
                    .env("ELASTICCTL_ES_URL", "http://localhost:9200")
                    .env("ELASTICCTL_API_KEY", api_key);
                match command.spawn() {
                    Ok(child) => match stream_output("traditional", child).await {
                        Ok(status) if status.success() => Ok(()),
                        Ok(status) => Err(format!("traditional leg exited with {status}")),
                        Err(message) => Err(message),
                    },
                    Err(error) => Err(format!("spawning traditional leg: {error}")),
                }
            }
            Err(message) => Err(message),
        },
        Err(message) => Err(message),
    };

    // Always tear the lab down, whether the boot, the key mint, or the leg
    // itself failed: a partially started compose stack must not survive this
    // command.
    let teardown = run_lab_script(&down_script, &workspace, "lab-down").await;
    match (result, teardown) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(teardown_message)) => Err(teardown_message),
        (Err(message), Ok(())) => Err(message),
        (Err(message), Err(teardown_message)) => {
            Err(format!("{message}; additionally, {teardown_message}"))
        }
    }
}

pub async fn run(values: &[String]) -> Result<(), String> {
    let args = Args::parse(values)?;
    let exe = std::env::current_exe()
        .map_err(|error| format!("resolving the current executable: {error}"))?;

    let mut handles = Vec::with_capacity(args.flavors.len());
    for flavor in &args.flavors {
        let exe = exe.clone();
        let report_dir = args.report_dir.clone();
        let handle = match flavor.as_str() {
            "serverless" => tokio::spawn(run_serverless_leg(exe, report_dir)),
            "ech" => tokio::spawn(run_ech_leg(exe, report_dir)),
            "traditional" => tokio::spawn(run_traditional_leg(exe, report_dir)),
            _ => unreachable!("Args::parse only yields the three known flavors"),
        };
        handles.push((flavor.clone(), handle));
    }

    let mut failed = false;
    for (flavor, handle) in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(message)) => {
                eprintln!("[{flavor}] {message}");
                failed = true;
            }
            Err(join_error) => {
                eprintln!("[{flavor}] leg task failed: {join_error}");
                failed = true;
            }
        }
    }

    if failed {
        Err("one or more conformance-matrix legs failed".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults_and_an_explicit_flavor_subset() {
        let defaults = Args::parse(&["--report-dir".into(), "reports".into()]).unwrap();
        assert_eq!(defaults.report_dir, PathBuf::from("reports"));
        assert_eq!(defaults.flavors, vec!["serverless", "ech", "traditional"]);

        let subset = Args::parse(&[
            "--flavors".into(),
            "ech,serverless".into(),
            "--report-dir".into(),
            "reports".into(),
        ])
        .unwrap();
        assert_eq!(subset.flavors, vec!["ech", "serverless"]);
        assert_eq!(subset.report_dir, PathBuf::from("reports"));
    }

    #[test]
    fn rejects_unknown_and_duplicate_flavors_and_a_missing_report_dir() {
        assert_eq!(
            Args::parse(&[
                "--flavors".into(),
                "bogus".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "invalid flavor in --flavors; expected serverless, ech, or traditional"
        );
        assert_eq!(
            Args::parse(&[
                "--flavors".into(),
                "ech,ech".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "duplicate flavor in --flavors"
        );
        assert_eq!(
            Args::parse(&["--flavors".into(), "ech".into()]).unwrap_err(),
            "missing --report-dir"
        );
    }
}
