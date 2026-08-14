//! Crash-recoverable change-report publication for `state push`.

use elasticctl_api::ChangeReport;
use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const JOURNAL: &str = "journal.ndjson";
const TRANSACTION_SUFFIX: &str = ".elasticctl-report-txn";
const LOCK_SUFFIX: &str = ".elasticctl-report.lock";

/// A prepared local report destination. The target-specific sibling lock stays
/// held from preflight through publication so another push cannot mistake its
/// transaction for a crashed predecessor.
pub(crate) struct PreparedReport {
    target: PathBuf,
    transaction_dir: PathBuf,
    staged_path: PathBuf,
    backup_path: PathBuf,
    _lock_file: File,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Serialize, PartialEq)]
enum Phase {
    Prepared,
    BackingUp,
    BackedUp,
    Installing,
    Installed,
}

#[derive(Deserialize, Serialize)]
struct PreparedRecord {
    existed_before: bool,
    phase: Phase,
}

#[derive(Deserialize, Serialize)]
struct PhaseRecord {
    phase: Phase,
}

struct Journal {
    existed_before: bool,
    phase: Phase,
}

/// The mutation points are isolated so the journal can be pressure-tested at
/// every write, sync, rename, and rollback boundary without a special
/// filesystem.
trait FileOps {
    fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()>;
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
}

struct FsFileOps;

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
        File::open(path)?.sync_all()
    }

    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        #[cfg(not(windows))]
        {
            File::open(path)?.sync_all()
        }
        #[cfg(windows)]
        {
            // Windows exposes no directory fsync through `File`; every report
            // payload and journal record is individually synced above.
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

/// Prepare a report before the mutation guard. This can fail safely after the
/// remote read/plan but before any remote write, and it never changes an
/// existing target.
pub(crate) fn prepare_report(path: &Path, report: &ChangeReport) -> Result<PreparedReport> {
    prepare_report_with(path, report, &FsFileOps)
}

impl PreparedReport {
    /// Replace the report after the dry run or remote apply has produced its
    /// final typed value.
    pub(crate) fn publish(self, report: &ChangeReport) -> Result<()> {
        publish_report_with(self, report, &FsFileOps)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.target
    }
}

fn prepare_report_with(
    path: &Path,
    report: &ChangeReport,
    ops: &dyn FileOps,
) -> Result<PreparedReport> {
    let (parent, transaction_dir, lock_path) = report_paths(path)?;
    let lock_file = acquire_lock(path, &lock_path)?;

    recover_report_locked(path, &transaction_dir, &parent, ops)?;
    let existed_before = target_is_regular_file(path)?;
    if path_exists(&transaction_dir, "checking report transaction")? {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "a report transaction is already present at {}; recover it before publishing",
                transaction_dir.display()
            ),
        ));
    }

    let staged_path = transaction_dir.join("staged.json");
    let backup_path = transaction_dir.join("backup.json");
    let result = (|| {
        create_transaction_dir(&transaction_dir, &parent, ops)?;
        let bytes = serialize_report(report)?;
        write(
            ops,
            &staged_path,
            &bytes,
            false,
            path,
            "staging change report",
        )?;
        sync_file(ops, &staged_path, path, "syncing staged change report")?;
        sync_dir(
            ops,
            &transaction_dir,
            "syncing report transaction directory",
        )?;

        let record = PreparedRecord {
            existed_before,
            phase: Phase::Prepared,
        };
        let journal = journal_path(&transaction_dir);
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report journal: {e}")))?;
        write(
            ops,
            &journal,
            &with_newline(bytes),
            false,
            path,
            "writing prepared report journal",
        )?;
        sync_file(ops, &journal, path, "syncing prepared report journal")?;
        sync_dir(
            ops,
            &transaction_dir,
            "syncing report transaction directory",
        )
    })();

    match result {
        Ok(()) => Ok(PreparedReport {
            target: path.to_path_buf(),
            transaction_dir,
            staged_path,
            backup_path,
            _lock_file: lock_file,
        }),
        Err(error) => finish_failed_preparation(path, &transaction_dir, &parent, ops, error),
    }
}

fn publish_report_with(
    prepared: PreparedReport,
    report: &ChangeReport,
    ops: &dyn FileOps,
) -> Result<()> {
    let parent = report_parent(&prepared.target)?;
    let result = (|| {
        let journal = read_journal(&prepared.transaction_dir)?.ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!(
                    "report journal {} has no prepared record",
                    journal_path(&prepared.transaction_dir).display()
                ),
            )
        })?;
        if journal.phase != Phase::Prepared {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "report transaction {} is not ready to publish",
                    prepared.transaction_dir.display()
                ),
            ));
        }
        let exists_now = target_is_regular_file(&prepared.target)?;
        if exists_now != journal.existed_before {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report target {} changed after preflight",
                    prepared.target.display()
                ),
            ));
        }
        require_regular_file(
            &prepared.staged_path,
            &prepared.target,
            "reading staged change report",
        )?;
        if path_exists(&prepared.backup_path, "checking report backup")? {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report transaction {} already has a backup",
                    prepared.transaction_dir.display()
                ),
            ));
        }

        let bytes = serialize_report(report)?;
        write(
            ops,
            &prepared.staged_path,
            &bytes,
            false,
            &prepared.target,
            "restaging change report",
        )?;
        sync_file(
            ops,
            &prepared.staged_path,
            &prepared.target,
            "syncing restaged change report",
        )?;
        sync_dir(
            ops,
            &prepared.transaction_dir,
            "syncing report transaction directory",
        )?;

        append_phase(
            &prepared.transaction_dir,
            Phase::BackingUp,
            &prepared.target,
            ops,
        )?;
        if journal.existed_before {
            rename(
                ops,
                &prepared.target,
                &prepared.backup_path,
                &prepared.target,
                "backing up change report",
            )?;
            sync_dir(ops, &parent, "syncing report directory after backup")?;
            sync_dir(
                ops,
                &prepared.transaction_dir,
                "syncing report transaction directory after backup",
            )?;
        }
        append_phase(
            &prepared.transaction_dir,
            Phase::BackedUp,
            &prepared.target,
            ops,
        )?;

        append_phase(
            &prepared.transaction_dir,
            Phase::Installing,
            &prepared.target,
            ops,
        )?;
        if target_is_regular_file(&prepared.target)? {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report target {} appeared during publication",
                    prepared.target.display()
                ),
            ));
        }
        rename(
            ops,
            &prepared.staged_path,
            &prepared.target,
            &prepared.target,
            "installing change report",
        )?;
        sync_dir(ops, &parent, "syncing report directory after installation")?;
        sync_dir(
            ops,
            &prepared.transaction_dir,
            "syncing report transaction directory after installation",
        )?;
        append_phase(
            &prepared.transaction_dir,
            Phase::Installed,
            &prepared.target,
            ops,
        )?;

        // Removing this directory discards the only rollback evidence. From
        // this explicit boundary forward the installed report is committed.
        remove_transaction(&prepared.target, &prepared.transaction_dir, &parent, ops)
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => finish_failed_publication(
            &prepared.target,
            &prepared.transaction_dir,
            &parent,
            ops,
            error,
        ),
    }
}

#[cfg(test)]
fn recover_report(path: &Path) -> Result<()> {
    let (parent, transaction_dir, lock_path) = report_paths(path)?;
    let _lock_file = acquire_lock(path, &lock_path)?;
    recover_report_locked(path, &transaction_dir, &parent, &FsFileOps)
}

fn recover_report_locked(
    path: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
) -> Result<()> {
    if !path_exists(transaction_dir, "checking report transaction")? {
        return Ok(());
    }
    require_directory(
        transaction_dir,
        path,
        "reading report transaction directory",
    )?;
    let Some(journal) = read_journal(transaction_dir)? else {
        // No synced Prepared record authorizes no target rename. This is only
        // transaction-owned staging data, so removing it cannot touch a report.
        return remove_transaction(path, transaction_dir, parent, ops);
    };

    if journal.existed_before {
        recover_existing_target(path, transaction_dir, parent, ops, journal.phase)?;
    } else {
        recover_absent_target(path, transaction_dir, parent, ops, journal.phase)?;
    }
    remove_transaction(path, transaction_dir, parent, ops)
}

fn recover_existing_target(
    path: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
    phase: Phase,
) -> Result<()> {
    let backup = transaction_dir.join("backup.json");
    if path_exists(&backup, "checking report backup")? {
        require_regular_file(&backup, path, "reading report backup")?;
        match target_metadata(path)? {
            Some(metadata) if metadata.file_type().is_file() => {
                remove_file(
                    ops,
                    path,
                    path,
                    "removing replacement report during rollback",
                )?;
                sync_dir(ops, parent, "syncing report directory during rollback")?;
            }
            Some(_) => return non_regular_target(path),
            None => {}
        }
        rename(ops, &backup, path, path, "restoring previous change report")?;
        sync_dir(ops, parent, "syncing report directory during rollback")?;
        sync_dir(
            ops,
            transaction_dir,
            "syncing report transaction directory during rollback",
        )?;
    } else if matches!(
        phase,
        Phase::BackedUp | Phase::Installing | Phase::Installed
    ) {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} lost the backup needed to recover {}",
                transaction_dir.display(),
                path.display()
            ),
        ));
    } else if !target_is_regular_file(path)? {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} cannot find the previous report {}",
                transaction_dir.display(),
                path.display()
            ),
        ));
    }
    Ok(())
}

fn recover_absent_target(
    path: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
    phase: Phase,
) -> Result<()> {
    let staged = transaction_dir.join("staged.json");
    if matches!(phase, Phase::Installing | Phase::Installed)
        && !path_exists(&staged, "checking staged change report")?
    {
        match target_metadata(path)? {
            Some(metadata) if metadata.file_type().is_file() => {
                // The missing staged side plus the durable Installing record
                // proves this target came from this transaction.
                remove_file(
                    ops,
                    path,
                    path,
                    "removing newly installed change report during rollback",
                )?;
                sync_dir(ops, parent, "syncing report directory during rollback")?;
            }
            Some(_) => return non_regular_target(path),
            None => {}
        }
    }
    Ok(())
}

fn append_phase(
    transaction_dir: &Path,
    phase: Phase,
    target: &Path,
    ops: &dyn FileOps,
) -> Result<()> {
    let bytes = serde_json::to_vec(&PhaseRecord { phase })
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report journal: {e}")))?;
    let journal = journal_path(transaction_dir);
    write(
        ops,
        &journal,
        &with_newline(bytes),
        true,
        target,
        "appending report journal",
    )?;
    sync_file(ops, &journal, target, "syncing report journal")?;
    sync_dir(ops, transaction_dir, "syncing report transaction directory")
}

fn read_journal(transaction_dir: &Path) -> Result<Option<Journal>> {
    let journal = journal_path(transaction_dir);
    if !path_exists(&journal, "checking report journal")? {
        return Ok(None);
    }
    require_regular_file(&journal, transaction_dir, "reading report journal")?;
    let bytes =
        fs::read(&journal).map_err(|e| filesystem_error("reading report journal", &journal, e))?;
    let mut records = bytes.split_inclusive(|byte| *byte == b'\n');
    let Some(first) = records.next() else {
        return Ok(None);
    };
    if !first.ends_with(b"\n") {
        return Ok(None);
    }
    let prepared: PreparedRecord = serde_json::from_slice(first).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("reading prepared report journal {}: {e}", journal.display()),
        )
    })?;
    if prepared.phase != Phase::Prepared {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "report journal {} has a non-prepared first record",
                journal.display()
            ),
        ));
    }

    let mut phase = Phase::Prepared;
    for record in records {
        if !record.ends_with(b"\n") {
            // A crash can leave only the final append incomplete. It cannot
            // hide any later record because the incomplete slice is final.
            break;
        }
        let update: PhaseRecord = serde_json::from_slice(record).map_err(|e| {
            Error::new(
                ErrorKind::Error,
                format!("reading report journal {}: {e}", journal.display()),
            )
        })?;
        let expected = match phase {
            Phase::Prepared => Phase::BackingUp,
            Phase::BackingUp => Phase::BackedUp,
            Phase::BackedUp => Phase::Installing,
            Phase::Installing => Phase::Installed,
            Phase::Installed => {
                return Err(Error::new(
                    ErrorKind::Error,
                    format!(
                        "report journal {} has records after installation",
                        journal.display()
                    ),
                ));
            }
        };
        if update.phase != expected {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "report journal {} has an invalid phase transition",
                    journal.display()
                ),
            ));
        }
        phase = update.phase;
    }
    Ok(Some(Journal {
        existed_before: prepared.existed_before,
        phase,
    }))
}

fn finish_failed_preparation<T>(
    path: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
    original: Error,
) -> Result<T> {
    match recover_report_locked(path, transaction_dir, parent, ops) {
        Ok(()) => Err(original),
        Err(recovery) => Err(Error::new(
            ErrorKind::Error,
            format!("{original}; rollback failed: {}", recovery.message),
        )),
    }
}

fn finish_failed_publication(
    path: &Path,
    transaction_dir: &Path,
    parent: &Path,
    ops: &dyn FileOps,
    original: Error,
) -> Result<()> {
    match recover_report_locked(path, transaction_dir, parent, ops) {
        Ok(()) => Err(original),
        Err(recovery) => Err(Error::new(
            ErrorKind::Error,
            format!("{original}; rollback failed: {}", recovery.message),
        )),
    }
}

fn report_paths(path: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let parent = report_parent(path)?;
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!(
                    "report destination {} has no final component",
                    path.display()
                ),
            )
        })?;
    Ok((
        parent.clone(),
        parent.join(hidden_sibling_name(name, TRANSACTION_SUFFIX)),
        parent.join(hidden_sibling_name(name, LOCK_SUFFIX)),
    ))
}

#[cfg(test)]
fn transaction_dir(path: &Path) -> PathBuf {
    report_paths(path)
        .expect("test paths have a valid report destination")
        .1
}

fn hidden_sibling_name(name: &std::ffi::OsStr, suffix: &str) -> OsString {
    let mut sibling = OsString::from(".");
    sibling.push(name);
    sibling.push(suffix);
    sibling
}

fn report_parent(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    require_directory_chain(path, parent)
}

fn require_directory_chain(target: &Path, parent: &Path) -> Result<PathBuf> {
    let absolute = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| filesystem_error("reading current directory", target, e))?
            .join(parent)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(component) => {
                current.push(component);
                match metadata(&current, "reading report parent")? {
                    Some(found) if found.file_type().is_dir() => {}
                    Some(found) if found.file_type().is_symlink() => {
                        return Err(Error::new(
                            ErrorKind::Error,
                            format!(
                                "report destination {} has a symlinked parent {}",
                                target.display(),
                                current.display()
                            ),
                        ));
                    }
                    Some(_) => {
                        return Err(Error::new(
                            ErrorKind::Error,
                            format!(
                                "report destination {} has a non-directory parent {}",
                                target.display(),
                                current.display()
                            ),
                        ));
                    }
                    None => {
                        return Err(Error::new(
                            ErrorKind::Error,
                            format!(
                                "report destination {} has a missing parent {}",
                                target.display(),
                                current.display()
                            ),
                        ));
                    }
                }
            }
        }
    }
    Ok(parent.to_path_buf())
}

fn acquire_lock(target: &Path, lock_path: &Path) -> Result<File> {
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

fn target_is_regular_file(path: &Path) -> Result<bool> {
    match target_metadata(path)? {
        Some(metadata) if metadata.file_type().is_file() => Ok(true),
        Some(_) => non_regular_target(path),
        None => Ok(false),
    }
}

fn target_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    metadata(path, "reading report destination")
}

fn require_regular_file(path: &Path, target: &Path, action: &str) -> Result<()> {
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

fn non_regular_target<T>(path: &Path) -> Result<T> {
    Err(Error::new(
        ErrorKind::Error,
        format!(
            "report destination {} is not a regular file",
            path.display()
        ),
    ))
}

fn create_transaction_dir(transaction_dir: &Path, parent: &Path, ops: &dyn FileOps) -> Result<()> {
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

fn require_directory(path: &Path, target: &Path, action: &str) -> Result<()> {
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

fn path_exists(path: &Path, action: &str) -> Result<bool> {
    Ok(metadata(path, action)?.is_some())
}

fn metadata(path: &Path, action: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(filesystem_error(action, path, error)),
    }
}

fn journal_path(transaction_dir: &Path) -> PathBuf {
    transaction_dir.join(JOURNAL)
}

fn with_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(b'\n');
    bytes
}

fn serialize_report(report: &ChangeReport) -> Result<Vec<u8>> {
    serde_json::to_string_pretty(report)
        .map(|body| body.into_bytes())
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

fn write(
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

fn sync_file(ops: &dyn FileOps, path: &Path, target: &Path, action: &str) -> Result<()> {
    ops.sync_file(path)
        .map_err(|e| filesystem_error(action, target, e))
}

fn sync_dir(ops: &dyn FileOps, path: &Path, action: &str) -> Result<()> {
    ops.sync_dir(path)
        .map_err(|e| filesystem_error(action, path, e))
}

fn rename(ops: &dyn FileOps, from: &Path, to: &Path, target: &Path, action: &str) -> Result<()> {
    ops.rename(from, to)
        .map_err(|e| filesystem_error(action, target, e))
}

fn remove_file(ops: &dyn FileOps, path: &Path, target: &Path, action: &str) -> Result<()> {
    ops.remove_file(path)
        .map_err(|e| filesystem_error(action, target, e))
}

fn remove_transaction(
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
        // The journal has already been removed. Do not report a rollbackable
        // failure after the irreversible cleanup boundary.
        Err(_) if !path_exists(transaction_dir, "checking removed report transaction")? => Ok(()),
        Err(error) => Err(error),
    }
}

fn filesystem_error(action: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorKind::Error,
        format!("{action} {}: {error}", path.display()),
    )
}

/// Explain a local report failure after `apply_push` without changing its
/// stable error kind or the command's stdout report shape.
pub(crate) fn report_publication_error(applied: bool, path: &Path, error: Error) -> Error {
    if applied {
        Error::new(
            error.kind,
            format!(
                "remote changes completed, but writing change report {} failed: {}",
                path.display(),
                error.message
            ),
        )
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elasticctl_api::ChangeReport;
    use std::cell::Cell;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    use std::path::Path;

    fn report(applied: bool) -> ChangeReport {
        ChangeReport {
            profile: "default".into(),
            host: "kibana.example.test".into(),
            space: "default".into(),
            applied,
            entries: vec![],
        }
    }

    fn serialized(report: &ChangeReport) -> Vec<u8> {
        serde_json::to_string_pretty(report).unwrap().into_bytes()
    }

    fn sync_test_directory(path: &Path) -> io::Result<()> {
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

    struct FailingFileOps {
        operation: &'static str,
        fail_at: Vec<usize>,
        calls: Cell<usize>,
    }

    impl FailingFileOps {
        fn once(operation: &'static str, fail_at: usize) -> Self {
            Self {
                operation,
                fail_at: vec![fail_at],
                calls: Cell::new(0),
            }
        }

        fn at(operation: &'static str, fail_at: &[usize]) -> Self {
            Self {
                operation,
                fail_at: fail_at.to_vec(),
                calls: Cell::new(0),
            }
        }

        fn fail(&self, operation: &'static str) -> io::Result<()> {
            if operation != self.operation {
                return Ok(());
            }
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if self.fail_at.contains(&call) {
                return Err(io::Error::other(format!("injected {operation} failure")));
            }
            Ok(())
        }
    }

    impl FileOps for FailingFileOps {
        fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()> {
            self.fail("write")?;
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
            self.fail("sync_file")?;
            File::open(path)?.sync_all()
        }

        fn sync_dir(&self, path: &Path) -> io::Result<()> {
            self.fail("sync_dir")?;
            sync_test_directory(path)
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.fail("rename")?;
            fs::rename(from, to)
        }

        fn remove_file(&self, path: &Path) -> io::Result<()> {
            self.fail("remove_file")?;
            fs::remove_file(path)
        }

        fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
            self.fail("remove_dir_all")?;
            fs::remove_dir_all(path)
        }
    }

    fn seed_report_transaction(target: &Path, phase: Phase) {
        let transaction = transaction_dir(target);
        let staged = transaction.join("staged.json");
        let backup = transaction.join("backup.json");
        fs::write(target, b"{\"previous\":true}").unwrap();
        fs::create_dir(&transaction).unwrap();
        fs::write(&staged, b"{\"replacement\":true}").unwrap();

        if matches!(
            phase,
            Phase::BackedUp | Phase::Installing | Phase::Installed
        ) {
            fs::rename(target, &backup).unwrap();
        }
        if matches!(phase, Phase::Installing | Phase::Installed) {
            fs::rename(&staged, target).unwrap();
        }

        let mut journal = with_newline(
            serde_json::to_vec(&PreparedRecord {
                existed_before: true,
                phase: Phase::Prepared,
            })
            .unwrap(),
        );
        if phase != Phase::Prepared {
            for recorded_phase in [
                Phase::BackingUp,
                Phase::BackedUp,
                Phase::Installing,
                Phase::Installed,
            ] {
                journal.extend(with_newline(
                    serde_json::to_vec(&PhaseRecord {
                        phase: recorded_phase,
                    })
                    .unwrap(),
                ));
                if recorded_phase == phase {
                    break;
                }
            }
        }
        fs::write(transaction.join(JOURNAL), journal).unwrap();
    }

    #[test]
    fn preparation_stages_a_dry_run_without_replacing_the_existing_report() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        fs::write(&target, b"{\"previous\":true}").unwrap();
        let dry_run = report(false);

        let prepared = prepare_report(&target, &dry_run).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
        assert_eq!(
            fs::read(&prepared.staged_path).unwrap(),
            serialized(&dry_run)
        );
        assert!(prepared.transaction_dir.join(JOURNAL).is_file());
        drop(prepared);
        recover_report(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
    }

    #[test]
    fn failed_report_operations_restore_old_bytes_or_leave_a_recoverable_journal() {
        enum Failure {
            ManifestWrite,
            ManifestSync,
            BackupRename,
            InstallRename,
            RollbackRename,
        }

        for failure in [
            Failure::ManifestWrite,
            Failure::ManifestSync,
            Failure::BackupRename,
            Failure::InstallRename,
            Failure::RollbackRename,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            let old = b"{\"previous\":true}";
            fs::write(&target, old).unwrap();

            match failure {
                Failure::ManifestWrite => {
                    let ops = FailingFileOps::once("write", 2);
                    assert!(prepare_report_with(&target, &report(false), &ops).is_err());
                }
                Failure::ManifestSync => {
                    let ops = FailingFileOps::once("sync_file", 2);
                    assert!(prepare_report_with(&target, &report(false), &ops).is_err());
                }
                Failure::BackupRename => {
                    let prepared = prepare_report(&target, &report(false)).unwrap();
                    let ops = FailingFileOps::once("rename", 1);
                    assert!(publish_report_with(prepared, &report(true), &ops).is_err());
                }
                Failure::InstallRename => {
                    let prepared = prepare_report(&target, &report(false)).unwrap();
                    let ops = FailingFileOps::once("rename", 2);
                    assert!(publish_report_with(prepared, &report(true), &ops).is_err());
                }
                Failure::RollbackRename => {
                    let prepared = prepare_report(&target, &report(false)).unwrap();
                    let ops = FailingFileOps::at("rename", &[2, 3]);
                    assert!(publish_report_with(prepared, &report(true), &ops).is_err());
                    assert!(transaction_dir(&target).exists());
                }
            }

            recover_report(&target).unwrap();
            recover_report(&target).unwrap();
            assert_eq!(fs::read(&target).unwrap(), old);
            assert!(!transaction_dir(&target).exists());
        }
    }

    #[test]
    fn recovery_restores_the_old_report_at_every_journal_phase() {
        for phase in [
            Phase::Prepared,
            Phase::BackingUp,
            Phase::BackedUp,
            Phase::Installing,
            Phase::Installed,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, phase);

            recover_report(&target).unwrap();
            recover_report(&target).unwrap();

            assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
            assert!(!transaction_dir(&target).exists());
        }
    }

    #[test]
    fn applied_report_failure_names_the_completed_remote_changes() {
        let error = report_publication_error(
            true,
            Path::new("report.json"),
            elasticctl_core::Error::new(elasticctl_core::ErrorKind::Error, "synthetic I/O error"),
        );

        assert!(
            error.message.starts_with(
                "remote changes completed, but writing change report report.json failed"
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn preparation_refuses_symlink_parents_and_non_regular_targets() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let linked_parent = dir.path().join("linked-parent");
        symlink(&outside, &linked_parent).unwrap();
        let parent_error = match prepare_report(&linked_parent.join("report.json"), &report(false))
        {
            Ok(_) => panic!("symlinked report parent was accepted"),
            Err(error) => error,
        };
        assert_eq!(parent_error.kind, elasticctl_core::ErrorKind::Error);

        let target = dir.path().join("report.json");
        symlink("missing-report", &target).unwrap();
        let target_error = match prepare_report(&target, &report(false)) {
            Ok(_) => panic!("non-regular report target was accepted"),
            Err(error) => error,
        };
        assert_eq!(target_error.kind, elasticctl_core::ErrorKind::Error);
    }
}
