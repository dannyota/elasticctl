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

/// Parse a comma-separated flavor list, trimming whitespace and rejecting an
/// unknown name or a repeat without echoing the offending value, matching
/// `conformance::Args::parse`'s style.
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

/// Build the `live` integration test binary once before any leg starts.
///
/// `conformance` shells out to `cargo test --locked --test live <contract>`
/// per contract. If all three legs hit that build for the first time at
/// once, Cargo serializes the concurrent compiles behind its workspace build
/// lock, and the wall-clock win this command exists for stalls into a
/// compile queue instead (design spec 8.3).
///
/// Compiler output is inherited straight through rather than captured: a
/// broken build must not fail silently while the operator waits, and
/// `cargo`'s own diagnostics carry no credentials.
async fn prebuild_live_tests(workspace: &Path) -> Result<(), String> {
    let status = Command::new("cargo")
        .current_dir(workspace)
        .args(["test", "--locked", "--test", "live", "--no-run"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map_err(|error| format!("pre-building the live test binary: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "pre-building the live test binary exited with {status}"
        ))
    }
}

/// Build the child invocation `conformance --flavor <f> --report-dir <dir>`
/// against the current executable, so a locally built `xtask` and one
/// installed elsewhere both dispatch to themselves rather than a `PATH`
/// lookup. `kill_on_drop` limits how long a live-marker-owning child can
/// outlive this runner if a leg's task is aborted or panics — including a
/// Ctrl-C abort of the traditional leg's conformance child mid-mutation,
/// where `lab/down.sh`'s `compose down -v` is what actually disposes of any
/// live-marker residue that leaves behind, since the local lab is destroyed
/// wholesale rather than cleaned up object by object.
fn spawn_conformance_child(exe: &Path, flavor: &str, report_dir: &Path) -> Command {
    let mut command = Command::new(exe);
    command
        .arg("conformance")
        .arg("--flavor")
        .arg(flavor)
        .arg("--report-dir")
        .arg(report_dir)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Stream a child's stdout and stderr to the parent, stdout via `println!`
/// and stderr via `eprintln!`, each line prefixed with the flavor name, then
/// wait for it to exit.
///
/// Reads raw byte segments split on `\n` and lossily converts each one,
/// rather than using `AsyncBufReadExt::lines`, which returns an `Err` and
/// ends the stream on the first invalid UTF-8 byte. That would leave the
/// child's stdout pipe unread; if the child then wrote anything more, it
/// could be killed by `SIGPIPE` mid-contract, leaving live-marker objects
/// behind uncleaned.
///
/// `conformance` writes only public one-line messages (design spec 8.3), so
/// no redaction happens here. This helper must never be pointed at a process
/// that can print a credential; `lab/up.sh` and `lab/down.sh` are not run
/// through it for exactly that reason.
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
        let mut chunks = BufReader::new(stdout).split(b'\n');
        while let Ok(Some(chunk)) = chunks.next_segment().await {
            println!("[{out_flavor}] {}", String::from_utf8_lossy(&chunk));
        }
    });
    let err_flavor = flavor.to_string();
    let stderr_task = tokio::spawn(async move {
        let mut chunks = BufReader::new(stderr).split(b'\n');
        while let Ok(Some(chunk)) = chunks.next_segment().await {
            eprintln!("[{err_flavor}] {}", String::from_utf8_lossy(&chunk));
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
/// recorder. Fail before spawning anything if a required piece is missing.
/// `ELASTICCTL_SPACE` is set explicitly rather than left to inherit the
/// parent's value, since a space configured for another purpose could
/// silently scope this run to the wrong place.
async fn run_ech_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    let kibana_url = std::env::var("ELASTICCTL_ECH_KIBANA_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_KIBANA_URL".to_string())?;
    let es_url = std::env::var("ELASTICCTL_ECH_ES_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_ES_URL".to_string())?;
    let api_key = std::env::var("ELASTICCTL_ECH_API_KEY")
        .map_err(|_| "missing ELASTICCTL_ECH_API_KEY".to_string())?;
    let space = std::env::var("ELASTICCTL_ECH_SPACE").unwrap_or_else(|_| "default".to_string());

    let mut command = spawn_conformance_child(&exe, "ech", &report_dir);
    command
        .env("ELASTICCTL_KIBANA_URL", kibana_url)
        .env("ELASTICCTL_ES_URL", es_url)
        .env("ELASTICCTL_API_KEY", api_key)
        .env("ELASTICCTL_SPACE", space);
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

/// Write a failure's real detail to a private, owner-only log and return a
/// public message that names only its workspace-relative path, mirroring
/// `conformance::private_failure`. The detail can carry an authentication
/// error naming the lab's own request, so it must never be returned as the
/// failure message itself.
fn private_failure(workspace: &Path, name: &str, detail: impl AsRef<[u8]>) -> String {
    let path = lab_log_path(workspace, name);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance-matrix failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "traditional {name} failed; private detail is in {}",
        relative.display()
    )
}

/// Mint a fresh Elasticsearch API key against the lab's bootstrap user.
///
/// `lab/up.sh` mints its own key and prints it for a human to paste into
/// `elasticctl config init`, but reading it back here would mean parsing
/// script stdout, which the design brief for this command forbids. Minting a
/// second, independent key sidesteps that parse entirely.
async fn mint_traditional_api_key(workspace: &Path) -> Result<String, String> {
    let mut profile = elasticctl_core::Profile {
        kibana_url: "http://localhost:5601".to_string(),
        es_url: Some("http://localhost:9200".to_string()),
        api_key: None,
        username: Some("elastic".to_string()),
        // lab/compose.yaml sets ELASTIC_PASSWORD to this value.
        password: Some("elasticctl-lab".to_string()),
        space: "default".to_string(),
        verify: true,
        timeout_secs: 30,
    };
    profile.strip_userinfo();
    let transport = elasticctl_core::Transport::new(&profile)
        .map_err(|error| private_failure(workspace, "lab-mint", error.message.as_bytes()))?;
    let response = transport
        .post_absolute_es(
            "/_security/api_key",
            &serde_json::json!({"name": "elasticctl-matrix"}),
        )
        .await
        .map_err(|error| private_failure(workspace, "lab-mint", error.message.as_bytes()))?;
    response["encoded"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| {
            private_failure(
                workspace,
                "lab-mint",
                "lab API key response is missing encoded",
            )
        })
}

/// Install Elastic's prebuilt rule pack against the freshly minted key, the
/// same request `xtask seed` sends.
///
/// `lab/down.sh` always runs `compose down -v`, so every lab boot starts
/// empty. Without this, `source_scoping` fails on every matrix run because it
/// has no prebuilt rules to partition against custom ones (design spec 8.3).
///
/// The install response alone does not prove success: `PUT .../prepackaged`
/// answers `200` with an all-zero `{"rules_installed":0,...}` body when the
/// Fleet package fetch itself fails, which would otherwise reproduce the
/// original empty-lab symptom silently. Follow it with the same status check
/// `xtask record` uses (`crate::prebuilt_is_current`) and fail through the
/// private log unless it reports the pack current.
async fn install_prebuilt_rules(workspace: &Path, api_key: &str) -> Result<(), String> {
    let mut profile = elasticctl_core::Profile {
        kibana_url: "http://localhost:5601".to_string(),
        es_url: Some("http://localhost:9200".to_string()),
        api_key: Some(api_key.to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        // A prepackaged install can exceed the normal 60-second timeout on a
        // fresh stack; `xtask seed` uses the same 600-second allowance.
        timeout_secs: 600,
    };
    profile.strip_userinfo();
    let transport = elasticctl_core::Transport::new(&profile)
        .map_err(|error| private_failure(workspace, "lab-seed", error.message.as_bytes()))?;
    transport
        .put(
            "/api/detection_engine/rules/prepackaged",
            &serde_json::json!({}),
        )
        .await
        .map_err(|error| private_failure(workspace, "lab-seed", error.message.as_bytes()))?;

    let status = transport
        .get("/api/detection_engine/rules/prepackaged/_status")
        .await
        .map_err(|error| private_failure(workspace, "lab-seed", error.message.as_bytes()))?;
    match crate::prebuilt_is_current(&status) {
        Ok(true) => Ok(()),
        Ok(false) => {
            let detail = format!("prebuilt install did not report current: {status}");
            Err(private_failure(workspace, "lab-seed", detail.as_bytes()))
        }
        Err(error) => Err(private_failure(
            workspace,
            "lab-seed",
            error.message.as_bytes(),
        )),
    }
}

fn lab_log_path(workspace: &Path, name: &str) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join("traditional")
        .join(format!("{name}.log"))
}

/// Redact any line containing `ELASTICCTL_API_KEY=` from captured script
/// output before it reaches a log file. `lab/up.sh` prints the key it mints
/// in its final summary block; this runner mints its own key independently
/// (see `mint_traditional_api_key`) and must not let the lab's
/// superuser-derived key leak into a file either, even one meant to be read
/// in the clear otherwise.
fn redact_lab_output(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    text.lines()
        .map(|line| {
            if line.contains("ELASTICCTL_API_KEY=") {
                "[redacted line containing ELASTICCTL_API_KEY]"
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes()
}

/// Write a private log with the same owner-only permissions `conformance`
/// uses for its own private logs (design spec 8.3): this file can hold
/// redacted `lab/up.sh` output or a raw transport error.
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
/// output live. `up.sh` prints a plaintext API key and the target URLs in its
/// final summary block, and the brief for this command forbids printing any
/// env value, not only the key this runner mints itself. Redacted output
/// goes to a private log instead, the same pattern `conformance` uses to keep
/// contract detail out of its public one-liners. `kill_on_drop` gives the
/// script's immediate process a chance to die if this call is ever aborted
/// mid-flight, though a `compose` grandchild it spawned can still be left
/// running; `lab/down.sh` is what actually reconciles that.
async fn run_lab_script(script: &Path, workspace: &Path, name: &str) -> Result<(), String> {
    println!("[traditional] {name} starting");
    let output = Command::new(script)
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|error| format!("running {name}: {error}"))?;

    let mut log = Vec::new();
    log.extend_from_slice(b"stdout:\n");
    log.extend_from_slice(&redact_lab_output(&output.stdout));
    log.extend_from_slice(b"\nstderr:\n");
    log.extend_from_slice(&redact_lab_output(&output.stderr));
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

/// Run the self-managed leg's boot-through-conformance sequence: `lab/up.sh`,
/// minting a lab API key, installing the prebuilt rule pack so
/// `source_scoping` has rules to partition, activating a user profile so the
/// `triage` contract's assign/unassign step has one to resolve, then the
/// conformance child.
///
/// This runs as its own spawned task (see `run_traditional_leg`) so a panic
/// anywhere in it surfaces there as a `JoinError` instead of unwinding past
/// the teardown that must always follow.
async fn run_traditional_boot_and_leg(
    exe: PathBuf,
    report_dir: PathBuf,
    up_script: PathBuf,
    workspace: PathBuf,
) -> Result<(), String> {
    run_lab_script(&up_script, &workspace, "lab-up").await?;
    let api_key = mint_traditional_api_key(&workspace).await?;
    install_prebuilt_rules(&workspace, &api_key).await?;
    // Serverless and Hosted already carry an activated profile from the
    // operator's own SSO login; the lab boots headless, with no browser
    // session ever logging in, so without this the triage contract's
    // assign/unassign step finds no profile to resolve on this leg alone
    // (design spec `elasticctl-triage-design.md` section 10).
    // lab/compose.yaml sets ELASTIC_PASSWORD to this value.
    crate::activation::activate_profile("http://localhost:5601", "elastic", "elasticctl-lab")
        .await
        .map_err(|error| private_failure(&workspace, "lab-activate", error.message.as_bytes()))?;

    let mut command = spawn_conformance_child(&exe, "traditional", &report_dir);
    command
        .env("ELASTICCTL_KIBANA_URL", "http://localhost:5601")
        .env("ELASTICCTL_ES_URL", "http://localhost:9200")
        .env("ELASTICCTL_API_KEY", api_key)
        .env("ELASTICCTL_SPACE", "default");
    let child = command
        .spawn()
        .map_err(|error| format!("spawning traditional leg: {error}"))?;
    let status = stream_output("traditional", child).await?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("traditional leg exited with {status}"))
    }
}

/// Run the self-managed leg: boot the lab, mint a key, install the prebuilt
/// rule pack, run the conformance child, then always tear the lab down.
///
/// The boot-through-conformance sequence races against Ctrl-C, and either
/// outcome is followed by `lab/down.sh`; the same select's `JoinError`
/// branch covers a plain panic in that sequence for the same reason. Booting
/// dominates wall clock (design spec 9: roughly 20 minutes), so this whole
/// function is one task the scheduler in `run` spawns alongside the other
/// two flavors; nothing here blocks them.
async fn run_traditional_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    let workspace = workspace_root();
    let up_script = workspace.join("lab").join("up.sh");
    let down_script = workspace.join("lab").join("down.sh");

    let inner_workspace = workspace.clone();
    let mut handle = tokio::spawn(run_traditional_boot_and_leg(
        exe,
        report_dir,
        up_script,
        inner_workspace,
    ));
    let abort_handle = handle.abort_handle();

    // Racing the whole sequence against Ctrl-C, rather than only the
    // conformance child, means an interrupt during the up-to-20-minute lab
    // boot also reaches the teardown below instead of killing the process
    // outright. Polling `&mut handle` (instead of moving it in) leaves it
    // ours to await again below if the ctrl_c branch wins.
    let result = tokio::select! {
        joined = &mut handle => match joined {
            Ok(inner_result) => inner_result,
            Err(join_error) => Err(format!("traditional leg task panicked: {join_error}")),
        },
        ctrl_c = tokio::signal::ctrl_c() => {
            abort_handle.abort();
            // Wait for the aborted task to actually stop before teardown
            // starts, so `lab/down.sh` always runs after the boot, mint,
            // install, or conformance child has fully unwound rather than
            // racing it. A `compose` grandchild the aborted conformance
            // child may have influenced can still outlive the abort itself;
            // `down.sh` is what reconciles that, not this wait.
            let _ = handle.await;
            match ctrl_c {
                Ok(()) => Err("interrupted by ctrl-c; tearing down the lab".to_string()),
                Err(error) => Err(format!("failed to watch for ctrl-c: {error}")),
            }
        }
    };

    // Always tear the lab down, whether the boot, the key mint, the prebuilt
    // install, the leg itself, or a Ctrl-C interrupt of any of those failed:
    // a partially started compose stack must not survive this command. This
    // covers every case up to the point the select above resolves.
    let teardown = run_lab_script(&down_script, &workspace, "lab-down").await;

    // Installing the `ctrl_c()` listener above replaced the OS's default
    // SIGINT disposition for the whole process, and that listener does not
    // survive past this point. Arm a fresh one-shot listener so a later
    // Ctrl-C — for example while a sibling flavor is still running — still
    // terminates the run instead of being silently swallowed.
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(130)
        }
    });

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
    let workspace = workspace_root();
    prebuild_live_tests(&workspace).await?;

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

    #[test]
    fn rejects_an_unknown_option_a_duplicate_report_dir_and_a_missing_flavors_value() {
        assert_eq!(
            Args::parse(&["--bogus".into(), "x".into()]).unwrap_err(),
            "unknown option"
        );
        assert_eq!(
            Args::parse(&[
                "--report-dir".into(),
                "a".into(),
                "--report-dir".into(),
                "b".into(),
            ])
            .unwrap_err(),
            "duplicate --report-dir"
        );
        assert_eq!(
            Args::parse(&["--flavors".into()]).unwrap_err(),
            "missing value for --flavors"
        );
    }

    #[test]
    fn trims_whitespace_and_rejects_an_empty_or_trailing_comma_flavor() {
        let trimmed = Args::parse(&[
            "--flavors".into(),
            " serverless , ech ".into(),
            "--report-dir".into(),
            "reports".into(),
        ])
        .unwrap();
        assert_eq!(trimmed.flavors, vec!["serverless", "ech"]);

        assert_eq!(
            Args::parse(&[
                "--flavors".into(),
                "".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "invalid flavor in --flavors; expected serverless, ech, or traditional"
        );
        assert_eq!(
            Args::parse(&[
                "--flavors".into(),
                "serverless,".into(),
                "--report-dir".into(),
                "reports".into(),
            ])
            .unwrap_err(),
            "invalid flavor in --flavors; expected serverless, ech, or traditional"
        );
    }

    #[test]
    fn redacts_the_api_key_line_lab_up_sh_actually_prints() {
        // Read the real script rather than a hand-written fixture, so a
        // heredoc reword in `lab/up.sh` breaks this test instead of leaving
        // the redaction silently pointed at a string nothing prints anymore.
        let up_script = std::fs::read_to_string(workspace_root().join("lab").join("up.sh"))
            .expect("lab/up.sh is readable");
        assert!(
            up_script.contains("ELASTICCTL_API_KEY="),
            "lab/up.sh no longer prints ELASTICCTL_API_KEY=; update the redaction target to match"
        );

        let redacted = redact_lab_output(up_script.as_bytes());
        let text = String::from_utf8(redacted).unwrap();
        assert!(!text.contains("ELASTICCTL_API_KEY="));
        assert!(text.contains("[redacted line containing ELASTICCTL_API_KEY]"));
        // Neighboring lines survive: only the key line is blanked.
        assert!(text.contains("ELASTICCTL_KIBANA_URL="));
        assert!(text.contains("Waiting for Kibana..."));
    }
}
