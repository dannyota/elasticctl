use super::FlavorLabel;
use super::contracts::Contract;
use std::io::Write;
use std::path::PathBuf;

pub(super) fn private_log_path(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    contract: &str,
) -> PathBuf {
    workspace
        .join("target")
        .join("conformance-private")
        .join(flavor.as_str())
        .join(format!("{contract}.log"))
}

pub(super) fn audit_log_path(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    contract: &Contract,
) -> PathBuf {
    private_log_path(workspace, flavor, &format!("audit-{}", contract.name))
}

pub(super) fn write_private_log(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "conformance private log path is invalid".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|_| "conformance private log write failed".to_string())?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        if path.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "conformance private log write failed".to_string())?;
        }
    }
    let mut file = options
        .open(path)
        .map_err(|_| "conformance private log write failed".to_string())?;
    file.write_all(bytes)
        .map_err(|_| "conformance private log write failed".to_string())
}

pub(super) fn report_path(
    report_dir: &std::path::Path,
    flavor: FlavorLabel,
    version: &str,
) -> Result<PathBuf, String> {
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("conformance target version is not safe for a report filename".to_string());
    }
    Ok(report_dir.join(format!("{}-{version}.json", flavor.as_str())))
}

pub(super) fn output_log(output: &std::process::Output) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"stdout:\n");
    bytes.extend_from_slice(&output.stdout);
    bytes.extend_from_slice(b"\nstderr:\n");
    bytes.extend_from_slice(&output.stderr);
    bytes
}

pub(super) fn private_failure(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    stage: &str,
    detail: impl AsRef<[u8]>,
) -> String {
    let path = private_log_path(workspace, flavor, stage);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "conformance {stage} failed; private detail is in {}",
        relative.display()
    )
}

pub(super) fn private_audit_failure(
    workspace: &std::path::Path,
    flavor: FlavorLabel,
    contract: &Contract,
    detail: impl AsRef<[u8]>,
) -> String {
    let path = audit_log_path(workspace, flavor, contract);
    if write_private_log(&path, detail.as_ref()).is_err() {
        return "conformance failed and its private log could not be written".to_string();
    }
    let relative = path.strip_prefix(workspace).unwrap_or(&path);
    format!(
        "conformance audit-{} failed; private detail is in {}",
        contract.name,
        relative.display()
    )
}
