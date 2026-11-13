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

async fn run_ech_leg(exe: PathBuf, report_dir: PathBuf) -> Result<(), String> {
    let kibana_url = std::env::var("ELASTICCTL_ECH_KIBANA_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_KIBANA_URL".to_string())?;
    let es_url = std::env::var("ELASTICCTL_ECH_ES_URL")
        .map_err(|_| "missing ELASTICCTL_ECH_ES_URL".to_string())?;
    let api_key = std::env::var("ELASTICCTL_ECH_API_KEY")
        .map_err(|_| "missing ELASTICCTL_ECH_API_KEY".to_string())?;
    let space = std::env::var("ELASTICCTL_ECH_SPACE").unwrap_or_else(|_| "default".to_string());

    let username = std::env::var("ELASTICCTL_ECH_USERNAME")
        .ok()
        .filter(|value| !value.is_empty());
    let password = std::env::var("ELASTICCTL_ECH_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    if let (Some(username), Some(password)) = (username, password) {
        let workspace = workspace_root();
        crate::activation::activate_profile(&kibana_url, &username, &password)
            .await
            .map_err(|error| {
                private_failure(&workspace, "ech", "activate", error.message.as_bytes())
            })?;
    }

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

fn private_failure(workspace: &Path, flavor: &str, name: &str, detail: impl AsRef<[u8]>) -> String {
    let path = private_log_path(workspace, flavor, name);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance-matrix failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "{flavor} {name} failed; private detail is in {}",
        relative.display()
    )
}

fn traditional_password_from(environment: Option<String>, dotenv: &str) -> Result<String, String> {
    let value = environment.or_else(|| {
        dotenv.lines().rev().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            if name.trim() != "ELASTIC_PASSWORD" {
                return None;
            }
            let value = value.trim();
            Some(
                value
                    .strip_prefix('\'')
                    .and_then(|value| value.strip_suffix('\''))
                    .map(|value| value.replace("\\'", "'"))
                    .unwrap_or_else(|| value.to_string()),
            )
        })
    });
    value.filter(|value| !value.is_empty()).ok_or_else(|| {
        "ELASTIC_PASSWORD is required in the environment or lab/.env; run lab/up.sh".to_string()
    })
}

fn traditional_password(workspace: &Path) -> Result<String, String> {
    let environment = std::env::var("ELASTIC_PASSWORD").ok();
    if environment.is_some() {
        return traditional_password_from(environment, "");
    }
    let dotenv = match std::fs::read_to_string(workspace.join("lab/.env")) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return Err("cannot read ELASTIC_PASSWORD from lab/.env".to_string()),
    };
    traditional_password_from(None, &dotenv)
}

async fn mint_traditional_api_key(workspace: &Path) -> Result<String, String> {
    let mut profile = elasticctl_core::Profile {
        kibana_url: "http://localhost:5601".to_string(),
        es_url: Some("http://localhost:9200".to_string()),
        api_key: None,
        username: Some("elastic".to_string()),
        password: Some(traditional_password(workspace)?),
        space: "default".to_string(),
        verify: true,
        timeout_secs: 30,
    };
    profile.strip_userinfo();
    let transport = elasticctl_core::Transport::new(&profile).map_err(|error| {
        private_failure(
            workspace,
            "traditional",
            "lab-mint",
            error.message.as_bytes(),
        )
    })?;
    let response = transport
        .post_absolute_es(
            "/_security/api_key",
            &serde_json::json!({"name": "elasticctl-matrix"}),
        )
        .await
        .map_err(|error| {
            private_failure(
                workspace,
                "traditional",
                "lab-mint",
                error.message.as_bytes(),
            )
        })?;
    response["encoded"]
        .as_str()
        .map(|key| {
            if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
                println!("::add-mask::{key}");
            }
            key.to_string()
        })
        .ok_or_else(|| {
            private_failure(
                workspace,
                "traditional",
                "lab-mint",
                "lab API key response is missing encoded",
            )
        })
}

async fn install_prebuilt_rules(workspace: &Path, api_key: &str) -> Result<(), String> {
    let mut profile = elasticctl_core::Profile {
        kibana_url: "http://localhost:5601".to_string(),
        es_url: Some("http://localhost:9200".to_string()),
        api_key: Some(api_key.to_string()),
        username: None,
        password: None,
        space: "default".to_string(),
        verify: true,
        timeout_secs: 600,
    };
    profile.strip_userinfo();
    let transport = elasticctl_core::Transport::new(&profile).map_err(|error| {
        private_failure(
            workspace,
            "traditional",
            "lab-seed",
            error.message.as_bytes(),
        )
    })?;
    crate::converge_prebuilt_rules(&transport)
        .await
        .map(|_| ())
        .map_err(|error| {
            let detail = error.private_detail();
            private_failure(workspace, "traditional", "lab-seed", detail.as_bytes())
        })
}

fn private_log_path(workspace: &Path, flavor: &str, name: &str) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join(flavor)
        .join(format!("{name}.log"))
}

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
    let log_path = private_log_path(workspace, "traditional", name);
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

async fn run_traditional_boot_and_leg(
    exe: PathBuf,
    report_dir: PathBuf,
    up_script: PathBuf,
    workspace: PathBuf,
) -> Result<(), String> {
    run_lab_script(&up_script, &workspace, "lab-up").await?;
    let api_key = mint_traditional_api_key(&workspace).await?;
    install_prebuilt_rules(&workspace, &api_key).await?;
    crate::activation::activate_profile(
        "http://localhost:5601",
        "elastic",
        &traditional_password(&workspace)?,
    )
    .await
    .map_err(|error| {
        private_failure(
            &workspace,
            "traditional",
            "lab-activate",
            error.message.as_bytes(),
        )
    })?;

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

    let result = tokio::select! {
        joined = &mut handle => match joined {
            Ok(inner_result) => inner_result,
            Err(join_error) => Err(format!("traditional leg task panicked: {join_error}")),
        },
        ctrl_c = tokio::signal::ctrl_c() => {
            abort_handle.abort();
            let _ = handle.await;
            match ctrl_c {
                Ok(()) => Err("interrupted by ctrl-c; tearing down the lab".to_string()),
                Err(error) => Err(format!("failed to watch for ctrl-c: {error}")),
            }
        }
    };

    let teardown = run_lab_script(&down_script, &workspace, "lab-down").await;

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
    fn resolves_password_precedence_and_literal_dotenv_without_execution() {
        let generated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        let override_value = format!("{generated}{}", std::process::id());
        let dotenv = format!("# ignored\nELASTIC_PASSWORD='{generated}'\n");
        assert!(traditional_password_from(None, &dotenv).unwrap() == generated);
        assert!(
            traditional_password_from(Some(override_value.clone()), &dotenv).unwrap()
                == override_value
        );
        assert!(traditional_password_from(Some(String::new()), &dotenv).is_err());
        for contents in ["", "# ELASTIC_PASSWORD=", "ELASTIC_PASSWORD=''"] {
            assert!(
                traditional_password_from(None, contents)
                    .unwrap_err()
                    .contains("ELASTIC_PASSWORD")
            );
        }
        let escaped = format!("{generated}\\'{generated}");
        let dotenv = format!("ELASTIC_PASSWORD='{escaped}'");
        assert!(traditional_password_from(None, &dotenv).unwrap() == escaped.replace("\\'", "'"));
    }

    #[test]
    fn redacts_api_key_assignments_defensively() {
        let input = format!(
            "ELASTICCTL_API_KEY={}\nready",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let redacted = String::from_utf8(redact_lab_output(input.as_bytes())).unwrap();
        assert!(!redacted.contains("ELASTICCTL_API_KEY="));
        assert!(redacted.contains("[redacted line containing ELASTICCTL_API_KEY]"));
        assert!(redacted.contains("ready"));
    }

    #[test]
    fn lab_provisioning_uses_the_shared_prebuilt_convergence_helper() {
        let source = include_str!("conformance_matrix.rs");
        let provisioning = source
            .split("fn private_log_path")
            .next()
            .expect("private log helper follows lab provisioning");
        assert!(provisioning.contains("crate::converge_prebuilt_rules(&transport)"));
        assert!(!provisioning.contains("PREBUILT_INSTALL_ATTEMPTS"));
        assert!(!provisioning.contains("stops making progress"));
    }
}
