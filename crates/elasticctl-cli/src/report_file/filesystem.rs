use super::{FileOps, JOURNAL, LOCK_SUFFIX, ORIGINAL, TRANSACTION_SUFFIX};
use elasticctl_core::{Error, ErrorKind, Result};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(windows)]
use std::path::Component;
use std::path::{Path, PathBuf};

pub(super) struct FsFileOps;

impl FileOps for FsFileOps {
    fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create(true);
        if append {
            options.append(true);
        } else {
            options.truncate(true);
        }
        options.open(path)?.write_all(bytes)
    }

    fn sync_file(&self, path: &Path) -> io::Result<()> {
        OpenOptions::new().write(true).open(path)?.sync_all()
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        #[cfg(not(windows))]
        {
            File::open(path)?.sync_all()
        }
        #[cfg(windows)]
        {
            let _ = path;
            Ok(())
        }
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}
pub(super) struct ReportPaths {
    pub(super) requested: PathBuf,
    pub(super) target: PathBuf,
    pub(super) parent: PathBuf,
    pub(super) transaction_dir: PathBuf,
    pub(super) lock_path: PathBuf,
}

impl ReportPaths {
    pub(super) fn recheck_parent(&self) -> Result<()> {
        require_directory(&self.parent, &self.requested, "checking report parent")
    }
}

pub(super) fn report_paths(requested: &Path) -> Result<ReportPaths> {
    #[cfg(windows)]
    if matches!(requested.components().next(), Some(Component::Prefix(_))) && !requested.has_root()
    {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "drive-relative report path {} is ambiguous; use an absolute drive path",
                requested.display()
            ),
        ));
    }
    let name = requested
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!(
                    "report destination {} has no final component",
                    requested.display()
                ),
            )
        })?;
    let parent = requested
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)
        .map_err(|e| filesystem_error("resolving report parent for", requested, e))?;
    let paths = ReportPaths {
        requested: requested.to_path_buf(),
        target: parent.join(name),
        transaction_dir: parent.join(hidden_sibling_name(name, TRANSACTION_SUFFIX)),
        lock_path: parent.join(hidden_sibling_name(name, LOCK_SUFFIX)),
        parent,
    };
    paths.recheck_parent()?;
    Ok(paths)
}

#[cfg(test)]
pub(super) fn transaction_dir(path: &Path) -> PathBuf {
    report_paths(path)
        .expect("test paths have a valid report destination")
        .transaction_dir
}

pub(super) fn hidden_sibling_name(name: &std::ffi::OsStr, suffix: &str) -> OsString {
    let mut sibling = OsString::from(".");
    sibling.push(name);
    sibling.push(suffix);
    sibling
}

pub(super) fn acquire_lock(target: &Path, lock_path: &Path) -> Result<File> {
    match metadata(lock_path, "reading report lock")? {
        Some(found) if found.file_type().is_file() => {}
        Some(found) if found.file_type().is_symlink() => {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "report destination {} has a symlinked lock {}",
                    target.display(),
                    lock_path.display()
                ),
            ));
        }
        Some(_) => {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "report destination {} has a non-file lock {}",
                    target.display(),
                    lock_path.display()
                ),
            ));
        }
        None => {}
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)
        .map_err(|e| filesystem_error("opening report lock", lock_path, e))?;
    lock.try_lock().map_err(|e| {
        Error::new(
            ErrorKind::Conflict,
            format!(
                "another state push holds report destination {}: {e}",
                target.display()
            ),
        )
    })?;
    Ok(lock)
}

pub(super) fn target_is_regular_file(path: &Path, requested: &Path) -> Result<bool> {
    match target_metadata(path, requested)? {
        Some(metadata) if metadata.file_type().is_file() => Ok(true),
        Some(_) => non_regular_target(requested),
        None => Ok(false),
    }
}

pub(super) fn target_metadata(path: &Path, requested: &Path) -> Result<Option<fs::Metadata>> {
    metadata(path, "reading report destination").map_err(|error| {
        Error::new(
            error.kind,
            format!(
                "report destination {}: {}",
                requested.display(),
                error.message
            ),
        )
    })
}

pub(super) fn require_regular_file(path: &Path, target: &Path, action: &str) -> Result<()> {
    match metadata(path, action)? {
        Some(found) if found.file_type().is_file() => Ok(()),
        Some(_) => Err(Error::new(
            ErrorKind::Error,
            format!(
                "{action} {}: expected a regular file for report destination {}",
                path.display(),
                target.display()
            ),
        )),
        None => Err(Error::new(
            ErrorKind::Error,
            format!(
                "{action} {}: file does not exist for report destination {}",
                path.display(),
                target.display()
            ),
        )),
    }
}

pub(super) fn non_regular_target<T>(path: &Path) -> Result<T> {
    Err(Error::new(
        ErrorKind::Error,
        format!(
            "report destination {} is not a regular file",
            path.display()
        ),
    ))
}

pub(super) fn create_transaction_dir(
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
) -> Result<()> {
    match fs::create_dir(transaction_dir) {
        Ok(()) => sync_dir(
            ops,
            parent,
            "syncing report directory after transaction creation",
        ),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "report transaction {} already exists",
                transaction_dir.display()
            ),
        )),
        Err(error) => Err(filesystem_error(
            "creating report transaction directory",
            transaction_dir,
            error,
        )),
    }
}

pub(super) fn require_directory(path: &Path, target: &Path, action: &str) -> Result<()> {
    match metadata(path, action)? {
        Some(found) if found.file_type().is_dir() => Ok(()),
        Some(found) if found.file_type().is_symlink() => Err(Error::new(
            ErrorKind::Error,
            format!(
                "{action} {}: symlink refused for report destination {}",
                path.display(),
                target.display()
            ),
        )),
        Some(_) => Err(Error::new(
            ErrorKind::Error,
            format!(
                "{action} {}: expected a directory for report destination {}",
                path.display(),
                target.display()
            ),
        )),
        None => Err(Error::new(
            ErrorKind::Error,
            format!(
                "{action} {}: directory does not exist for report destination {}",
                path.display(),
                target.display()
            ),
        )),
    }
}

pub(super) fn path_exists(path: &Path, action: &str) -> Result<bool> {
    Ok(metadata(path, action)?.is_some())
}

fn metadata(path: &Path, action: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(filesystem_error(action, path, error)),
    }
}

pub(super) fn journal_path(transaction_dir: &Path) -> PathBuf {
    transaction_dir.join(JOURNAL)
}

pub(super) fn original_path(transaction_dir: &Path) -> PathBuf {
    transaction_dir.join(ORIGINAL)
}
pub(super) fn write(
    ops: &dyn FileOps,
    path: &Path,
    bytes: &[u8],
    append: bool,
    target: &Path,
    action: &str,
) -> Result<()> {
    ops.write(path, bytes, append)
        .map_err(|e| filesystem_error(action, target, e))
}

pub(super) fn sync_file(ops: &dyn FileOps, path: &Path, target: &Path, action: &str) -> Result<()> {
    ops.sync_file(path)
        .map_err(|e| filesystem_error(action, target, e))
}

pub(super) fn sync_dir(ops: &dyn FileOps, path: &Path, action: &str) -> Result<()> {
    ops.sync_dir(path)
        .map_err(|e| filesystem_error(action, path, e))
}

pub(super) fn rename(
    ops: &dyn FileOps,
    from: &Path,
    to: &Path,
    target: &Path,
    action: &str,
) -> Result<()> {
    ops.rename(from, to)
        .map_err(|e| filesystem_error(action, target, e))
}

pub(super) fn remove_file(
    ops: &dyn FileOps,
    path: &Path,
    target: &Path,
    action: &str,
) -> Result<()> {
    ops.remove_file(path)
        .map_err(|e| filesystem_error(action, target, e))
}

pub(super) fn remove_transaction(
    target: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
) -> Result<()> {
    if !path_exists(transaction_dir, "checking report transaction")? {
        return Ok(());
    }
    require_directory(transaction_dir, target, "removing report transaction")?;
    ops.remove_dir_all(transaction_dir)
        .map_err(|e| filesystem_error("removing report transaction", transaction_dir, e))?;
    match sync_dir(
        ops,
        parent,
        "syncing report directory after transaction removal",
    ) {
        Ok(()) => Ok(()),
        Err(_) if !path_exists(transaction_dir, "checking removed report transaction")? => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn filesystem_error(action: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorKind::Error,
        format!("{action} {}: {error}", path.display()),
    )
}
