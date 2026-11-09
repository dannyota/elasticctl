//! Crash-recoverable change-report publication for `state push`.

use elasticctl_api::ChangeReport;
use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(windows)]
use std::path::Component;
use std::path::{Path, PathBuf};

const JOURNAL: &str = "journal.ndjson";
const ORIGINAL: &str = "original.json";
const TRANSACTION_SUFFIX: &str = ".elasticctl-report-txn";
const LOCK_SUFFIX: &str = ".elasticctl-report.lock";

/// A prepared local report destination. The target-specific sibling lock stays
/// held from preflight through publication so another push cannot mistake its
/// transaction for a crashed predecessor.
pub(crate) struct PreparedReport {
    paths: ReportPaths,
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
    /// Recovery has committed to restoring a saved report, before it mutates
    /// either side of the backup-to-target rename.
    Restoring,
    /// The original bytes are durably back at the target. Cleanup may now
    /// discard the transaction without making a later recovery guess.
    Restored,
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
        OpenOptions::new().write(true).open(path)?.sync_all()
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

    pub(crate) fn requested_path(&self) -> &Path {
        &self.paths.requested
    }
}

fn prepare_report_with(
    path: &Path,
    report: &ChangeReport,
    ops: &dyn FileOps,
) -> Result<PreparedReport> {
    let paths = report_paths(path)?;
    let parent = &paths.parent;
    let transaction_dir = &paths.transaction_dir;
    let requested = &paths.requested;
    let path = &paths.target;
    let lock_file = acquire_lock(requested, &paths.lock_path)?;

    recover_report_locked(&paths, ops)?;
    let existed_before = target_is_regular_file(path, requested)?;
    if path_exists(transaction_dir, "checking report transaction")? {
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
        create_transaction_dir(transaction_dir, parent, ops)?;
        let bytes = serialize_report(report)?;
        write(
            ops,
            &staged_path,
            &bytes,
            false,
            requested,
            "staging change report",
        )?;
        sync_file(ops, &staged_path, requested, "syncing staged change report")?;
        sync_dir(ops, transaction_dir, "syncing report transaction directory")?;

        let record = PreparedRecord {
            existed_before,
            phase: Phase::Prepared,
        };
        let journal = journal_path(transaction_dir);
        let bytes = serde_json::to_vec(&record)
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report journal: {e}")))?;
        write(
            ops,
            &journal,
            &with_newline(bytes),
            false,
            requested,
            "writing prepared report journal",
        )?;
        sync_file(ops, &journal, requested, "syncing prepared report journal")?;
        sync_dir(ops, transaction_dir, "syncing report transaction directory")
    })();

    match result {
        Ok(()) => Ok(PreparedReport {
            paths,
            staged_path,
            backup_path,
            _lock_file: lock_file,
        }),
        Err(error) => finish_failed_preparation(&paths, ops, error),
    }
}

fn publish_report_with(
    prepared: PreparedReport,
    report: &ChangeReport,
    ops: &dyn FileOps,
) -> Result<()> {
    let paths = &prepared.paths;
    paths.recheck_parent()?;
    let parent = &paths.parent;
    let target = &paths.target;
    let requested = &paths.requested;
    let transaction_dir = &paths.transaction_dir;
    let result = (|| {
        let journal = read_journal(transaction_dir)?.ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!(
                    "report journal {} has no prepared record",
                    journal_path(transaction_dir).display()
                ),
            )
        })?;
        if journal.phase != Phase::Prepared {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "report transaction {} is not ready to publish",
                    transaction_dir.display()
                ),
            ));
        }
        let exists_now = target_is_regular_file(target, requested)?;
        if exists_now != journal.existed_before {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report target {} changed after preflight",
                    requested.display()
                ),
            ));
        }
        require_regular_file(
            &prepared.staged_path,
            requested,
            "reading staged change report",
        )?;
        if path_exists(&prepared.backup_path, "checking report backup")? {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report transaction {} already has a backup",
                    transaction_dir.display()
                ),
            ));
        }

        let bytes = serialize_report(report)?;
        write(
            ops,
            &prepared.staged_path,
            &bytes,
            false,
            requested,
            "restaging change report",
        )?;
        sync_file(
            ops,
            &prepared.staged_path,
            requested,
            "syncing restaged change report",
        )?;
        sync_dir(ops, transaction_dir, "syncing report transaction directory")?;

        if journal.existed_before {
            snapshot_original(paths, ops)?;
        }
        append_phase(transaction_dir, Phase::BackingUp, requested, ops)?;
        if journal.existed_before {
            rename(
                ops,
                target,
                &prepared.backup_path,
                requested,
                "backing up change report",
            )?;
            sync_dir(ops, parent, "syncing report directory after backup")?;
            sync_dir(
                ops,
                transaction_dir,
                "syncing report transaction directory after backup",
            )?;
        }
        append_phase(transaction_dir, Phase::BackedUp, requested, ops)?;

        append_phase(transaction_dir, Phase::Installing, requested, ops)?;
        if target_is_regular_file(target, requested)? {
            return Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "report target {} appeared during publication",
                    requested.display()
                ),
            ));
        }
        rename(
            ops,
            &prepared.staged_path,
            target,
            requested,
            "installing change report",
        )?;
        sync_dir(ops, parent, "syncing report directory after installation")?;
        sync_dir(
            ops,
            transaction_dir,
            "syncing report transaction directory after installation",
        )?;
        append_phase(transaction_dir, Phase::Installed, requested, ops)?;

        // Removing this directory discards the only rollback evidence. From
        // this explicit boundary forward the installed report is committed.
        remove_transaction(requested, transaction_dir, parent, ops)
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => finish_failed_publication(paths, ops, error),
    }
}

#[cfg(test)]
fn recover_report(path: &Path) -> Result<()> {
    let paths = report_paths(path)?;
    let _lock_file = acquire_lock(&paths.requested, &paths.lock_path)?;
    recover_report_locked(&paths, &FsFileOps)
}

fn recover_report_locked(paths: &ReportPaths, ops: &dyn FileOps) -> Result<()> {
    paths.recheck_parent()?;
    let requested = &paths.requested;
    let transaction_dir = &paths.transaction_dir;
    let parent = &paths.parent;
    if !path_exists(transaction_dir, "checking report transaction")? {
        return Ok(());
    }
    require_directory(
        transaction_dir,
        requested,
        "reading report transaction directory",
    )?;
    let Some(journal) = read_journal(transaction_dir)? else {
        // No synced Prepared record authorizes no target rename. This is only
        // transaction-owned staging data, so removing it cannot touch a report.
        return remove_transaction(requested, transaction_dir, parent, ops);
    };

    if journal.existed_before {
        recover_existing_target(paths, ops, journal.phase)?;
    } else {
        recover_absent_target(paths, ops, journal.phase)?;
    }
    remove_transaction(requested, transaction_dir, parent, ops)
}

fn recover_existing_target(paths: &ReportPaths, ops: &dyn FileOps, phase: Phase) -> Result<()> {
    let path = &paths.target;
    let transaction_dir = &paths.transaction_dir;
    let parent = &paths.parent;
    let requested = &paths.requested;
    let backup = transaction_dir.join("backup.json");
    let backup_exists = path_exists(&backup, "checking report backup")?;
    match (phase, backup_exists) {
        (Phase::Restored, false) => target_matches_original(paths),
        (Phase::Restored, true) => Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} says {} was restored, but its backup remains",
                transaction_dir.display(),
                requested.display()
            ),
        )),
        (Phase::Restoring, false) => {
            target_matches_original(paths)?;
            finish_restoration(paths, ops)
        }
        (Phase::Prepared, true) => Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} has a backup before recording BackingUp for {}",
                transaction_dir.display(),
                requested.display()
            ),
        )),
        (_, true) => {
            require_regular_file(&backup, requested, "reading report backup")?;
            read_original(paths)?;
            if phase != Phase::Restoring {
                append_phase(transaction_dir, Phase::Restoring, requested, ops)?;
            }
            match target_metadata(path, requested)? {
                Some(metadata) if metadata.file_type().is_file() => {
                    remove_file(
                        ops,
                        path,
                        requested,
                        "removing replacement report during rollback",
                    )?;
                    sync_dir(ops, parent, "syncing report directory during rollback")?;
                }
                Some(_) => return non_regular_target(requested),
                None => {}
            }
            rename(
                ops,
                &backup,
                path,
                requested,
                "restoring previous change report",
            )?;
            finish_restoration(paths, ops)
        }
        (Phase::Prepared | Phase::BackingUp, false) if target_is_regular_file(path, requested)? => {
            Ok(())
        }
        (_, false) => Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} lost the backup needed to recover {}",
                transaction_dir.display(),
                requested.display()
            ),
        )),
    }
}

/// Finish a rollback after the backup rename. This is deliberately separate
/// from the rename: if either directory sync or the final journal append
/// fails, `Restoring` plus a regular target proves the retry must complete
/// these steps rather than looking for a backup that has already moved.
fn finish_restoration(paths: &ReportPaths, ops: &dyn FileOps) -> Result<()> {
    let transaction_dir = &paths.transaction_dir;
    let parent = &paths.parent;
    let requested = &paths.requested;
    target_matches_original(paths)?;
    sync_dir(
        ops,
        parent,
        "syncing report directory after rollback restoration",
    )?;
    sync_dir(
        ops,
        transaction_dir,
        "syncing report transaction directory after rollback restoration",
    )?;
    append_phase(transaction_dir, Phase::Restored, requested, ops)
}

fn recover_absent_target(paths: &ReportPaths, ops: &dyn FileOps, phase: Phase) -> Result<()> {
    let path = &paths.target;
    let requested = &paths.requested;
    let transaction_dir = &paths.transaction_dir;
    let parent = &paths.parent;
    if matches!(phase, Phase::Restoring | Phase::Restored) {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} has recovery-only phase {phase:?} for a report that did not exist",
                transaction_dir.display()
            ),
        ));
    }
    let staged = transaction_dir.join("staged.json");
    if matches!(phase, Phase::Installing | Phase::Installed)
        && !path_exists(&staged, "checking staged change report")?
    {
        match target_metadata(path, requested)? {
            Some(metadata) if metadata.file_type().is_file() => {
                // The missing staged side plus the durable Installing record
                // proves this target came from this transaction.
                remove_file(
                    ops,
                    path,
                    requested,
                    "removing newly installed change report during rollback",
                )?;
                sync_dir(ops, parent, "syncing report directory during rollback")?;
            }
            Some(_) => return non_regular_target(requested),
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
        if !is_valid_transition(phase, update.phase) {
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

fn is_valid_transition(from: Phase, to: Phase) -> bool {
    match from {
        Phase::Prepared => to == Phase::BackingUp,
        Phase::BackingUp => matches!(to, Phase::BackedUp | Phase::Restoring),
        Phase::BackedUp => matches!(to, Phase::Installing | Phase::Restoring),
        Phase::Installing => matches!(to, Phase::Installed | Phase::Restoring),
        Phase::Installed => to == Phase::Restoring,
        Phase::Restoring => to == Phase::Restored,
        Phase::Restored => false,
    }
}

/// Copy the target immediately before its backup rename. The artifact is only
/// used by recovery after that backup has disappeared, when its bytes are the
/// sole unambiguous proof that the regular target is the original report.
fn snapshot_original(paths: &ReportPaths, ops: &dyn FileOps) -> Result<()> {
    let path = &paths.target;
    let transaction_dir = &paths.transaction_dir;
    let requested = &paths.requested;
    let original = original_path(transaction_dir);
    if path_exists(&original, "checking original change report")? {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "report transaction {} already has an original report artifact",
                transaction_dir.display()
            ),
        ));
    }
    require_regular_file(path, requested, "reading original change report")?;
    let bytes = fs::read(path)
        .map_err(|e| filesystem_error("reading original change report", requested, e))?;
    write(
        ops,
        &original,
        &bytes,
        false,
        requested,
        "snapshotting original change report",
    )?;
    sync_file(ops, &original, requested, "syncing original change report")?;
    sync_dir(
        ops,
        transaction_dir,
        "syncing report transaction directory after original snapshot",
    )
}

fn target_matches_original(paths: &ReportPaths) -> Result<()> {
    let path = &paths.target;
    let transaction_dir = &paths.transaction_dir;
    let requested = &paths.requested;
    let original = read_original(paths)?;
    require_regular_file(path, requested, "reading restored change report")?;
    let target = fs::read(path)
        .map_err(|e| filesystem_error("reading restored change report", requested, e))?;
    if target == original {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Error,
            format!(
                "report transaction {} found target {} that does not match its original report artifact",
                transaction_dir.display(),
                requested.display()
            ),
        ))
    }
}

fn read_original(paths: &ReportPaths) -> Result<Vec<u8>> {
    let transaction_dir = &paths.transaction_dir;
    let requested = &paths.requested;
    let original = original_path(transaction_dir);
    require_regular_file(&original, requested, "reading original change report")?;
    fs::read(&original)
        .map_err(|e| filesystem_error("reading original change report", &original, e))
}

fn finish_failed_preparation<T>(
    paths: &ReportPaths,
    ops: &dyn FileOps,
    original: Error,
) -> Result<T> {
    match recover_report_locked(paths, ops) {
        Ok(()) => Err(original),
        Err(recovery) => Err(Error::new(
            ErrorKind::Error,
            format!("{original}; rollback failed: {}", recovery.message),
        )),
    }
}

fn finish_failed_publication(
    paths: &ReportPaths,
    ops: &dyn FileOps,
    original: Error,
) -> Result<()> {
    match recover_report_locked(paths, ops) {
        Ok(()) => Err(original),
        Err(recovery) => Err(Error::new(
            ErrorKind::Error,
            format!("{original}; rollback failed: {}", recovery.message),
        )),
    }
}

/// Resolve once, then carry this identity while the sibling lock is held.
struct ReportPaths {
    requested: PathBuf,
    target: PathBuf,
    parent: PathBuf,
    transaction_dir: PathBuf,
    lock_path: PathBuf,
}

impl ReportPaths {
    fn recheck_parent(&self) -> Result<()> {
        require_directory(&self.parent, &self.requested, "checking report parent")
    }
}

fn report_paths(requested: &Path) -> Result<ReportPaths> {
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
fn transaction_dir(path: &Path) -> PathBuf {
    report_paths(path)
        .expect("test paths have a valid report destination")
        .transaction_dir
}

fn hidden_sibling_name(name: &std::ffi::OsStr, suffix: &str) -> OsString {
    let mut sibling = OsString::from(".");
    sibling.push(name);
    sibling.push(suffix);
    sibling
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

fn target_is_regular_file(path: &Path, requested: &Path) -> Result<bool> {
    match target_metadata(path, requested)? {
        Some(metadata) if metadata.file_type().is_file() => Ok(true),
        Some(_) => non_regular_target(requested),
        None => Ok(false),
    }
}

fn target_metadata(path: &Path, requested: &Path) -> Result<Option<fs::Metadata>> {
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

fn original_path(transaction_dir: &Path) -> PathBuf {
    transaction_dir.join(ORIGINAL)
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
    use std::fs::{self, OpenOptions};
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
            fs::File::open(path)?.sync_all()
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
            OpenOptions::new().write(true).open(path)?.sync_all()
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

    fn seed_report_transaction(
        target: &Path,
        existed_before: bool,
        phase: Phase,
        backup_moved: bool,
        staged_installed: bool,
    ) {
        let transaction = transaction_dir(target);
        let staged = transaction.join("staged.json");
        let backup = transaction.join("backup.json");
        if existed_before {
            fs::write(target, b"{\"previous\":true}").unwrap();
        }
        fs::create_dir(&transaction).unwrap();
        if existed_before {
            fs::write(transaction.join("original.json"), b"{\"previous\":true}").unwrap();
        }
        fs::write(&staged, b"{\"replacement\":true}").unwrap();

        if backup_moved {
            fs::rename(target, &backup).unwrap();
        }
        if staged_installed {
            fs::rename(&staged, target).unwrap();
        }

        let mut journal = with_newline(
            serde_json::to_vec(&PreparedRecord {
                existed_before,
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
                Phase::Restoring,
                Phase::Restored,
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
        assert!(prepared.paths.transaction_dir.join(JOURNAL).is_file());
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
    fn publication_snapshots_the_bytes_present_immediately_before_backup() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        fs::write(&target, b"{\"prepared\":true}").unwrap();
        let prepared = prepare_report(&target, &report(false)).unwrap();
        fs::write(&target, b"{\"at_backup\":true}").unwrap();

        let ops = FailingFileOps::at("rename", &[2, 3]);
        assert!(publish_report_with(prepared, &report(true), &ops).is_err());
        assert_eq!(
            fs::read(transaction_dir(&target).join(ORIGINAL)).unwrap(),
            b"{\"at_backup\":true}"
        );

        recover_report(&target).unwrap();
        recover_report(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"{\"at_backup\":true}");
        assert!(!transaction_dir(&target).exists());
    }

    #[test]
    fn recovery_restores_the_old_report_on_both_sides_of_each_rename() {
        for (phase, backup_moved, staged_installed) in [
            (Phase::Prepared, false, false),
            (Phase::BackingUp, false, false),
            (Phase::BackingUp, true, false),
            (Phase::BackedUp, true, false),
            (Phase::Installing, true, false),
            (Phase::Installing, true, true),
            (Phase::Installed, true, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, true, phase, backup_moved, staged_installed);

            recover_report(&target).unwrap();
            recover_report(&target).unwrap();

            assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
            assert!(!transaction_dir(&target).exists());
        }
    }

    #[test]
    fn recovery_removes_an_installed_report_that_was_absent_before() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        seed_report_transaction(&target, false, Phase::Installing, false, true);

        recover_report(&target).unwrap();
        recover_report(&target).unwrap();

        assert!(!target.exists());
        assert!(!transaction_dir(&target).exists());
    }

    #[test]
    fn failed_sync_after_backup_restore_remains_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        seed_report_transaction(&target, true, Phase::Installed, true, true);
        let paths = report_paths(&target).unwrap();
        let lock = acquire_lock(&target, &paths.lock_path).unwrap();
        let ops = FailingFileOps::once("sync_dir", 3);

        assert!(recover_report_locked(&paths, &ops).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
        drop(lock);

        recover_report(&target).unwrap();
        recover_report(&target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
        assert!(!transaction_dir(&target).exists());
    }

    #[test]
    fn failures_after_the_restore_rename_remain_recoverable() {
        for (operation, fail_at) in [
            ("sync_dir", 3),
            ("sync_dir", 4),
            ("write", 2),
            ("sync_file", 2),
            ("sync_dir", 5),
            ("remove_dir_all", 1),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, true, Phase::Installed, true, true);
            let paths = report_paths(&target).unwrap();
            let transaction = &paths.transaction_dir;
            let lock = acquire_lock(&target, &paths.lock_path).unwrap();
            let ops = FailingFileOps::once(operation, fail_at);

            assert!(recover_report_locked(&paths, &ops).is_err());
            assert!(transaction.exists(), "{operation} call {fail_at}");
            drop(lock);

            recover_report(&target).unwrap();
            recover_report(&target).unwrap();
            assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
            assert!(!transaction_dir(&target).exists());
        }
    }

    #[test]
    fn restoring_without_a_backup_preserves_ambiguous_recovery_evidence() {
        for non_regular_target in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, true, Phase::Restoring, false, false);
            fs::remove_file(&target).unwrap();
            if non_regular_target {
                fs::create_dir(&target).unwrap();
            }

            let error = recover_report(&target).unwrap_err();

            assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
            assert!(transaction_dir(&target).exists());
        }
    }

    #[test]
    fn restoring_without_a_backup_requires_the_original_bytes() {
        for replacement in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, true, Phase::Restoring, false, false);
            if replacement {
                fs::write(&target, b"{\"replacement\":true}").unwrap();

                let error = recover_report(&target).unwrap_err();

                assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
                assert!(transaction_dir(&target).exists());
            } else {
                recover_report(&target).unwrap();
                recover_report(&target).unwrap();
                assert_eq!(fs::read(&target).unwrap(), b"{\"previous\":true}");
                assert!(!transaction_dir(&target).exists());
            }
        }
    }

    #[test]
    fn restoring_without_a_backup_requires_a_regular_original_artifact() {
        for non_regular_original in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, true, Phase::Restoring, false, false);
            let original = transaction_dir(&target).join(ORIGINAL);
            fs::remove_file(&original).unwrap();
            if non_regular_original {
                fs::create_dir(&original).unwrap();
            }

            let error = recover_report(&target).unwrap_err();

            assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
            assert!(transaction_dir(&target).exists());
        }
    }

    #[test]
    fn recovery_refuses_recovery_only_phases_for_previously_absent_reports() {
        for phase in [Phase::Restoring, Phase::Restored] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("report.json");
            seed_report_transaction(&target, false, phase, false, true);

            let error = recover_report(&target).unwrap_err();

            assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
            assert!(target.is_file());
            assert!(transaction_dir(&target).exists());
        }
    }

    #[test]
    fn journal_rejects_a_prepared_to_restoring_transition() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        let transaction = transaction_dir(&target);
        fs::create_dir(&transaction).unwrap();
        let mut journal = with_newline(
            serde_json::to_vec(&PreparedRecord {
                existed_before: true,
                phase: Phase::Prepared,
            })
            .unwrap(),
        );
        journal.extend(with_newline(
            serde_json::to_vec(&PhaseRecord {
                phase: Phase::Restoring,
            })
            .unwrap(),
        ));
        fs::write(transaction.join(JOURNAL), journal).unwrap();

        let error = recover_report(&target).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert!(transaction.exists());
    }

    #[test]
    fn report_lock_stays_held_until_preparation_is_recovered_or_published() {
        let dir = tempfile::tempdir().unwrap();
        let first_target = dir.path().join("first.json");
        let second_target = dir.path().join("second.json");
        let prepared = prepare_report(&first_target, &report(false)).unwrap();

        let same_target = match prepare_report(&first_target, &report(false)) {
            Ok(_) => panic!("a second report preparation acquired the same lock"),
            Err(error) => error,
        };
        assert_eq!(same_target.kind, elasticctl_core::ErrorKind::Conflict);
        let resolved = report_paths(&first_target).unwrap().target;
        assert_eq!(preparation_error(&resolved).kind, ErrorKind::Conflict);
        let other = prepare_report(&second_target, &report(false)).unwrap();
        drop(other);
        drop(prepared);

        recover_report(&first_target).unwrap();
        let retried = prepare_report(&first_target, &report(false)).unwrap();
        drop(retried);
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
    fn preparation_accepts_symlink_parents() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let alias = dir.path().join("alias");
        symlink(&outside, &alias).unwrap();
        let prepared = prepare_report(&alias.join("report.json"), &report(false)).unwrap();
        assert_eq!(
            preparation_error(&outside.join("report.json")).kind,
            ErrorKind::Conflict
        );
        prepared.publish(&report(true)).unwrap();
        assert_eq!(
            fs::read(outside.join("report.json")).unwrap(),
            serialized(&report(true))
        );
    }

    #[cfg(unix)]
    #[test]
    fn preparation_refuses_dangling_final_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        symlink("missing-report", &target).unwrap();
        assert_eq!(preparation_error(&target).kind, ErrorKind::Error);
    }

    fn preparation_error(target: &Path) -> Error {
        match prepare_report(target, &report(false)) {
            Ok(_) => panic!("unexpectedly accepted {}", target.display()),
            Err(error) => error,
        }
    }

    #[test]
    fn preparation_refuses_directories_missing_parents_and_roots() {
        let dir = tempfile::tempdir().unwrap();
        for target in [
            dir.path().to_path_buf(),
            dir.path().join("missing/report.json"),
        ] {
            let error = preparation_error(&target);
            assert!(error.message.contains(&target.display().to_string()));
        }
        fs::write(dir.path().join("file"), b"file").unwrap();
        assert!(report_paths(&dir.path().join("file/report.json")).is_err());
        assert!(report_paths(Path::new("")).is_err());
        #[cfg(unix)]
        assert!(report_paths(Path::new("/")).is_err());
    }

    #[test]
    fn relative_and_absolute_paths_share_identity_and_lock() {
        let cwd = std::env::current_dir().unwrap();
        let dir = tempfile::tempdir_in(&cwd).unwrap();
        let absolute = dir.path().join("report.json");
        let relative = absolute.strip_prefix(&cwd).unwrap();
        let prepared = prepare_report(relative, &report(false)).unwrap();
        assert_eq!(prepared.requested_path(), relative);
        assert_eq!(
            prepared.paths.target,
            report_paths(&absolute).unwrap().target
        );
        assert_eq!(preparation_error(&absolute).kind, ErrorKind::Conflict);
        prepared.publish(&report(true)).unwrap();
        assert_eq!(fs::read(absolute).unwrap(), serialized(&report(true)));
    }

    #[cfg(unix)]
    #[test]
    fn ancestor_aliases_share_lock_and_transaction_identity() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir_all(real.join("nested")).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        let target = real.join("nested/report.json");
        let requested = alias.join("nested/report.json");
        let prepared = prepare_report(&requested, &report(false)).unwrap();
        assert_eq!(preparation_error(&target).kind, ErrorKind::Conflict);
        assert_eq!(
            recover_report(&target).unwrap_err().kind,
            ErrorKind::Conflict
        );
        assert_eq!(transaction_dir(&requested), transaction_dir(&target));
        prepared.publish(&report(true)).unwrap();
        assert_eq!(fs::read(&target).unwrap(), serialized(&report(true)));
    }

    #[cfg(unix)]
    #[test]
    fn alias_retargeting_cannot_redirect_publication() {
        use std::os::unix::fs::symlink;
        for existed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let original = dir.path().join("original");
            let other = dir.path().join("other");
            fs::create_dir(&original).unwrap();
            fs::create_dir(&other).unwrap();
            if existed {
                fs::write(original.join("report.json"), b"old").unwrap();
            }
            fs::write(other.join("report.json"), b"untouched").unwrap();
            let alias = dir.path().join("alias");
            symlink(&original, &alias).unwrap();
            let prepared = prepare_report(&alias.join("report.json"), &report(false)).unwrap();
            fs::remove_file(&alias).unwrap();
            symlink(&other, &alias).unwrap();
            prepared.publish(&report(true)).unwrap();
            assert_eq!(
                fs::read(original.join("report.json")).unwrap(),
                serialized(&report(true))
            );
            assert_eq!(fs::read(other.join("report.json")).unwrap(), b"untouched");
        }
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_publication_recovers_through_another_alias() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let other = dir.path().join("other");
        fs::create_dir(&real).unwrap();
        fs::create_dir(&other).unwrap();
        fs::write(real.join("report.json"), b"old").unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        symlink(&real, &first).unwrap();
        symlink(&real, &second).unwrap();
        let prepared = prepare_report(&first.join("report.json"), &report(false)).unwrap();
        fs::remove_file(&first).unwrap();
        symlink(&other, &first).unwrap();
        let ops = FailingFileOps::at("rename", &[2, 3]);
        assert!(publish_report_with(prepared, &report(true), &ops).is_err());
        assert!(transaction_dir(&second.join("report.json")).exists());
        recover_report(&second.join("report.json")).unwrap();
        recover_report(&second.join("report.json")).unwrap();
        assert_eq!(fs::read(real.join("report.json")).unwrap(), b"old");
        assert!(!other.join("report.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn alias_parent_dot_dot_uses_filesystem_semantics() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("real/nested");
        fs::create_dir_all(&nested).unwrap();
        let alias = dir.path().join("alias");
        symlink(&nested, &alias).unwrap();
        prepare_report(&alias.join("../report.json"), &report(false))
            .unwrap()
            .publish(&report(true))
            .unwrap();
        assert!(dir.path().join("real/report.json").is_file());
        assert!(!dir.path().join("report.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn final_symlinks_locks_and_parent_loops_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        fs::write(real.join("original"), b"untouched").unwrap();
        let target = alias.join("report.json");
        symlink("original", real.join("report.json")).unwrap();
        assert!(
            preparation_error(&target)
                .message
                .contains(&target.display().to_string())
        );
        fs::remove_file(real.join("report.json")).unwrap();
        fs::remove_file(report_paths(&target).unwrap().lock_path).unwrap();
        symlink(
            "original",
            real.join(hidden_sibling_name(
                std::ffi::OsStr::new("report.json"),
                LOCK_SUFFIX,
            )),
        )
        .unwrap();
        assert!(
            preparation_error(&target)
                .message
                .contains("symlinked lock")
        );
        let looping = dir.path().join("loop");
        symlink("loop", &looping).unwrap();
        assert!(report_paths(&looping.join("report.json")).is_err());
        assert_eq!(fs::read(real.join("original")).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn stored_parent_is_rechecked_before_publication_and_recovery() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        let moved = dir.path().join("moved");
        let other = dir.path().join("other");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&other).unwrap();
        let prepared = prepare_report(&parent.join("report.json"), &report(false)).unwrap();
        let paths = report_paths(&parent.join("report.json")).unwrap();
        fs::rename(&parent, &moved).unwrap();
        symlink(&other, &parent).unwrap();
        assert!(prepared.publish(&report(true)).is_err());
        assert!(recover_report_locked(&paths, &FsFileOps).is_err());
        assert!(!other.join("report.json").exists());
        fs::remove_file(&parent).unwrap();
        fs::rename(&moved, &parent).unwrap();
        recover_report(&parent.join("report.json")).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_and_tmp_backed_tempdirs_publish_without_normalizing_inputs() {
        for dir in [
            tempfile::tempdir().unwrap(),
            tempfile::tempdir_in("/tmp").unwrap(),
        ] {
            let target = dir.path().join("report.json");
            prepare_report(&target, &report(false))
                .unwrap()
                .publish(&report(true))
                .unwrap();
            assert_eq!(fs::read(&target).unwrap(), serialized(&report(true)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_relative_and_root_paths_are_rejected_before_io() {
        for target in [
            r"C:report.json",
            r"C:",
            r"C:\",
            r"\",
            r"\\unreachable\share\",
            r"\\?\C:\",
        ] {
            assert!(report_paths(Path::new(target)).is_err(), "{target}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_extended_length_paths_preserve_parent_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        let paths = report_paths(&target).unwrap();
        assert!(
            paths
                .parent
                .as_os_str()
                .to_string_lossy()
                .starts_with(r"\\?\")
        );
        let extended = paths.target.clone();
        let prepared = prepare_report(&target, &report(false)).unwrap();
        assert_eq!(preparation_error(&extended).kind, ErrorKind::Conflict);
        prepared.publish(&report(true)).unwrap();
        assert_eq!(fs::read(extended).unwrap(), serialized(&report(true)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_directory_aliases_share_identity_when_supported() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = dir.path().join("alias");
        if let Err(error) = std::os::windows::fs::symlink_dir(&real, &alias) {
            if error.kind() == io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("creating directory alias: {error}");
        }
        let prepared = prepare_report(&alias.join("report.json"), &report(false)).unwrap();
        assert_eq!(
            preparation_error(&real.join("report.json")).kind,
            ErrorKind::Conflict
        );
        prepared.publish(&report(true)).unwrap();
        assert!(real.join("report.json").is_file());
    }
}
