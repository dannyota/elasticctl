//! Crash-recoverable replacement for the files written by `state pull`.
//!
//! The transaction lives below the mirror so staged bytes and backups cannot
//! cross a filesystem boundary. Its journal is append-only: a crash can lose
//! at most its final, unterminated record, never the prepared manifest.

use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

const TRANSACTION_DIR: &str = ".elasticctl-pull-txn";
const JOURNAL: &str = "journal.ndjson";

pub(crate) struct PullLock {
    root: PathBuf,
    _lock_file: File,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum Phase {
    Prepared,
    BackingUp,
    BackedUp,
    Installing,
    Installed,
}

#[derive(Deserialize, Serialize)]
struct JournalEntry {
    relative: PathBuf,
    existed_before: bool,
    phase: Phase,
}

#[derive(Deserialize, Serialize)]
struct PhaseRecord {
    entry: usize,
    phase: Phase,
}

#[derive(Deserialize, Serialize)]
struct PreparedRecord {
    entries: Vec<JournalEntry>,
}

pub(crate) struct StagedFile {
    /// Relative to the mirror root and under rules/ or exceptions/.
    pub relative: PathBuf,
    pub bytes: Vec<u8>,
}

/// The mutation points are isolated so failure tests can verify that recovery
/// works across every rename boundary without a special filesystem.
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
            // Windows does not provide a directory fsync through `File`.
            // Every file payload and journal append is still synced above.
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

pub(crate) fn acquire_pull(root: &Path) -> Result<PullLock> {
    let parent = mirror_parent(root)?;
    let mirror_name = root.file_name().ok_or_else(|| {
        Error::new(
            ErrorKind::Error,
            format!("mirror path {} has no final component", root.display()),
        )
    })?;
    let mut lock_name = OsString::from(".");
    lock_name.push(mirror_name);
    lock_name.push(".elasticctl-pull.lock");
    let lock_path = parent.join(lock_name);
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| filesystem_error("opening pull lock", &lock_path, e))?;
    lock_file.try_lock().map_err(|e| {
        Error::new(
            ErrorKind::Conflict,
            format!("another state pull holds {}: {e}", lock_path.display()),
        )
    })?;
    Ok(PullLock {
        root: root.to_path_buf(),
        _lock_file: lock_file,
    })
}

pub(crate) fn recover_pull(lock: &PullLock) -> Result<()> {
    recover_pull_with(lock, &FsFileOps)
}

pub(crate) fn replace_staged_files(lock: &PullLock, files: &[StagedFile]) -> Result<()> {
    replace_staged_files_with(lock, files, &FsFileOps)
}

fn replace_staged_files_with(
    lock: &PullLock,
    files: &[StagedFile],
    ops: &dyn FileOps,
) -> Result<()> {
    let existed_before = validate_replacement(lock, files)?;
    ensure_mirror_root(lock, ops)?;
    let transaction = transaction_dir(lock);
    if path_exists(&transaction)? {
        return Err(Error::new(
            ErrorKind::Conflict,
            format!(
                "a pull transaction is already present at {}; recover it before replacing files",
                transaction.display()
            ),
        ));
    }

    let prepare = || -> Result<Vec<JournalEntry>> {
        ensure_directory(&transaction, ops, "creating pull transaction directory")?;
        ensure_directory(
            &transaction.join("staged"),
            ops,
            "creating pull staging directory",
        )?;
        ensure_directory(
            &transaction.join("backups"),
            ops,
            "creating pull backup directory",
        )?;

        let mut entries = Vec::with_capacity(files.len());
        for (index, file) in files.iter().enumerate() {
            let staged = staged_path(&transaction, index);
            write(ops, &staged, &file.bytes, false, &file.relative, "staging")?;
            sync_file(ops, &staged, &file.relative, "syncing staged file")?;
            entries.push(JournalEntry {
                relative: file.relative.clone(),
                existed_before: existed_before[index],
                phase: Phase::Prepared,
            });
        }
        sync_dir(
            ops,
            &transaction.join("staged"),
            "syncing pull staging directory",
        )?;

        let prepared = serde_json::to_vec(&PreparedRecord { entries })
            .map_err(|e| Error::new(ErrorKind::Error, format!("encoding pull journal: {e}")))?;
        let journal = journal_path(&transaction);
        write(
            ops,
            &journal,
            &with_newline(prepared),
            false,
            &transaction,
            "writing pull journal",
        )?;
        sync_file(ops, &journal, &transaction, "syncing pull journal")?;
        sync_dir(ops, &transaction, "syncing pull transaction directory")?;
        read_journal(&transaction)?.ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!(
                    "pull journal {} lost its prepared record before commit",
                    journal_path(&transaction).display()
                ),
            )
        })
    };

    let entries = match prepare() {
        Ok(entries) => entries,
        Err(error) => return finish_failed_replacement(lock, ops, error),
    };

    for (index, entry) in entries.iter().enumerate() {
        if let Err(error) = replace_one(lock, &transaction, index, entry, ops) {
            return finish_failed_replacement(lock, ops, error);
        }
    }

    if let Err(error) = remove_transaction(lock, ops) {
        return finish_failed_replacement(lock, ops, error);
    }
    Ok(())
}

fn finish_failed_replacement(lock: &PullLock, ops: &dyn FileOps, original: Error) -> Result<()> {
    match recover_pull_with(lock, ops) {
        Ok(()) => Err(original),
        Err(recovery) => Err(Error::new(
            ErrorKind::Error,
            format!("{original}; rollback failed: {}", recovery.message),
        )),
    }
}

fn replace_one(
    lock: &PullLock,
    transaction: &Path,
    index: usize,
    entry: &JournalEntry,
    ops: &dyn FileOps,
) -> Result<()> {
    append_phase(transaction, index, Phase::BackingUp, ops)?;
    let target = lock.root.join(&entry.relative);
    let backup = backup_path(transaction, index);
    if entry.existed_before {
        let target_parent = ensure_target_parent(lock, &entry.relative, ops)?;
        if !target_is_regular_file(lock, &entry.relative)? {
            return Err(Error::new(
                ErrorKind::Error,
                format!(
                    "backing up {}: expected an existing regular file",
                    entry.relative.display()
                ),
            ));
        }
        rename(ops, &target, &backup, &entry.relative, "backing up")?;
        sync_dir(ops, &target_parent, "syncing target directory")?;
        sync_dir(
            ops,
            &transaction.join("backups"),
            "syncing pull backup directory",
        )?;
    }
    append_phase(transaction, index, Phase::BackedUp, ops)?;

    append_phase(transaction, index, Phase::Installing, ops)?;
    let target_parent = ensure_target_parent(lock, &entry.relative, ops)?;
    let staged = staged_path(transaction, index);
    if target_is_regular_file(lock, &entry.relative)? {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "installing {}: target appeared during pull transaction",
                entry.relative.display()
            ),
        ));
    }
    rename(ops, &staged, &target, &entry.relative, "installing")?;
    sync_dir(ops, &target_parent, "syncing target directory")?;
    sync_dir(
        ops,
        &transaction.join("staged"),
        "syncing pull staging directory",
    )?;
    append_phase(transaction, index, Phase::Installed, ops)
}

fn recover_pull_with(lock: &PullLock, ops: &dyn FileOps) -> Result<()> {
    mirror_parent(&lock.root)?;
    let transaction = transaction_dir(lock);
    if !path_exists(&transaction)? {
        return Ok(());
    }
    require_directory(&transaction, "reading pull transaction directory")?;
    let journal = journal_path(&transaction);
    if !journal.exists() {
        // No prepared record exists, so no target rename was permitted. This
        // directory contains only transaction-owned staging bytes.
        return remove_transaction(lock, ops);
    }
    let Some(entries) = read_journal(&transaction)? else {
        // The first record was never fully appended, so no prepared manifest
        // existed and no target rename was allowed to start.
        return remove_transaction(lock, ops);
    };
    for entry in &entries {
        validate_relative(&entry.relative)?;
    }

    let mut first_error = None;
    for (index, entry) in entries.iter().enumerate() {
        if let Err(error) = recover_one(lock, &transaction, index, entry, ops)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    remove_transaction(lock, ops)
}

fn recover_one(
    lock: &PullLock,
    transaction: &Path,
    index: usize,
    entry: &JournalEntry,
    ops: &dyn FileOps,
) -> Result<()> {
    let target = lock.root.join(&entry.relative);
    let staged = staged_path(transaction, index);
    if entry.existed_before {
        let backup = backup_path(transaction, index);
        if backup.exists() {
            let target_parent = ensure_target_parent(lock, &entry.relative, ops)?;
            if target_is_regular_file(lock, &entry.relative)? {
                remove_file(
                    ops,
                    &target,
                    &entry.relative,
                    "removing replacement during rollback",
                )?;
                sync_dir(ops, &target_parent, "syncing target directory")?;
            }
            rename(ops, &backup, &target, &entry.relative, "restoring backup")?;
            sync_dir(ops, &target_parent, "syncing target directory")?;
            sync_dir(
                ops,
                &transaction.join("backups"),
                "syncing pull backup directory",
            )?;
        }
    } else if matches!(entry.phase, Phase::Installing | Phase::Installed) && !staged.exists() {
        let target_parent = ensure_target_parent(lock, &entry.relative, ops)?;
        if target_is_regular_file(lock, &entry.relative)? {
            // A staged file disappearing proves the transaction performed the
            // install. Do not remove a target while the staged side still
            // exists: an interrupted pre-rename must leave an absent target
            // untouched.
            remove_file(
                ops,
                &target,
                &entry.relative,
                "removing newly created replacement during rollback",
            )?;
            sync_dir(ops, &target_parent, "syncing target directory")?;
        }
    }
    Ok(())
}

fn append_phase(transaction: &Path, entry: usize, phase: Phase, ops: &dyn FileOps) -> Result<()> {
    let record = serde_json::to_vec(&PhaseRecord { entry, phase })
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding pull journal: {e}")))?;
    let journal = journal_path(transaction);
    write(
        ops,
        &journal,
        &with_newline(record),
        true,
        transaction,
        "appending pull journal",
    )?;
    sync_file(ops, &journal, transaction, "syncing pull journal")?;
    sync_dir(ops, transaction, "syncing pull transaction directory")
}

fn read_journal(transaction: &Path) -> Result<Option<Vec<JournalEntry>>> {
    let journal = journal_path(transaction);
    let bytes =
        fs::read(&journal).map_err(|e| filesystem_error("reading pull journal", &journal, e))?;
    let mut records = bytes.split_inclusive(|byte| *byte == b'\n');
    let Some(first) = records.next() else {
        return Ok(None);
    };
    if !first.ends_with(b"\n") {
        return Ok(None);
    }
    let PreparedRecord { mut entries } = serde_json::from_slice(first).map_err(|e| {
        Error::new(
            ErrorKind::Error,
            format!("reading prepared pull journal {}: {e}", journal.display()),
        )
    })?;
    if entries
        .iter()
        .any(|entry| !matches!(entry.phase, Phase::Prepared))
    {
        return Err(Error::new(
            ErrorKind::Error,
            format!(
                "pull journal {} has a non-prepared manifest entry",
                journal.display()
            ),
        ));
    }
    for record in records {
        if !record.ends_with(b"\n") {
            // A crash can only leave the final append incomplete. No later
            // record exists, because this is the final unterminated slice.
            break;
        }
        let update: PhaseRecord = serde_json::from_slice(record).map_err(|e| {
            Error::new(
                ErrorKind::Error,
                format!("reading pull journal {}: {e}", journal.display()),
            )
        })?;
        let entry = entries.get_mut(update.entry).ok_or_else(|| {
            Error::new(
                ErrorKind::Error,
                format!("pull journal {} names an unknown entry", journal.display()),
            )
        })?;
        entry.phase = update.phase;
    }
    Ok(Some(entries))
}

fn validate_replacement(lock: &PullLock, files: &[StagedFile]) -> Result<Vec<bool>> {
    mirror_parent(&lock.root)?;
    let mut planned = BTreeSet::new();
    let mut existed_before = Vec::with_capacity(files.len());
    for file in files {
        validate_relative(&file.relative)?;
        validate_target_ancestors(&lock.root, &file.relative)?;
        if !planned.insert(file.relative.clone()) {
            return Err(Error::new(
                ErrorKind::Error,
                format!("pull plans {} more than once", file.relative.display()),
            ));
        }
        existed_before.push(target_is_regular_file(lock, &file.relative)?);
    }
    Ok(existed_before)
}

fn validate_relative(relative: &Path) -> Result<()> {
    let mut components = relative.components();
    let Some(Component::Normal(first)) = components.next() else {
        return invalid_relative(relative);
    };
    if first != "rules" && first != "exceptions" {
        return invalid_relative(relative);
    }
    let mut has_file_component = false;
    for component in components {
        match component {
            Component::Normal(_) => has_file_component = true,
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return invalid_relative(relative);
            }
        }
    }
    if !has_file_component {
        return invalid_relative(relative);
    }
    Ok(())
}

fn invalid_relative(relative: &Path) -> Result<()> {
    Err(Error::new(
        ErrorKind::Error,
        format!(
            "pull replacement path {} must be a relative rules/ or exceptions/ file",
            relative.display()
        ),
    ))
}

fn ensure_mirror_root(lock: &PullLock, ops: &dyn FileOps) -> Result<()> {
    mirror_parent(&lock.root)?;
    ensure_directory(&lock.root, ops, "creating mirror root")
}

fn ensure_target_parent(lock: &PullLock, relative: &Path, ops: &dyn FileOps) -> Result<PathBuf> {
    let parent = relative
        .parent()
        .expect("validated replacement path has a parent");
    require_directory(&lock.root, "reading mirror root")?;
    let mut current = lock.root.clone();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            unreachable!("validated replacement path has normal components");
        };
        current.push(component);
        ensure_directory(&current, ops, "creating pull target directory")?;
    }
    Ok(current)
}

fn validate_target_ancestors(root: &Path, relative: &Path) -> Result<()> {
    match path_metadata(root, "reading mirror root")? {
        None => return Ok(()),
        Some(metadata) if metadata.file_type().is_dir() => {}
        Some(_) => return non_directory(root, "mirror root"),
    }

    let parent = relative
        .parent()
        .expect("validated replacement path has a parent");
    let mut current = root.to_path_buf();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            unreachable!("validated replacement path has normal components");
        };
        current.push(component);
        match path_metadata(&current, "reading pull target directory")? {
            None => return Ok(()),
            Some(metadata) if metadata.file_type().is_dir() => {}
            Some(_) => return non_directory(&current, "pull target directory"),
        }
    }
    Ok(())
}

fn target_is_regular_file(lock: &PullLock, relative: &Path) -> Result<bool> {
    validate_target_ancestors(&lock.root, relative)?;
    let target = lock.root.join(relative);
    match path_metadata(&target, "reading pull target")? {
        None => Ok(false),
        Some(metadata) if metadata.file_type().is_file() => Ok(true),
        Some(_) => Err(Error::new(
            ErrorKind::Error,
            format!("pull target {} is not a regular file", relative.display()),
        )),
    }
}

fn ensure_directory(path: &Path, ops: &dyn FileOps, action: &str) -> Result<()> {
    let parent = path
        .parent()
        .expect("a created pull directory has a parent");
    require_directory(parent, action)?;
    match path_metadata(path, action)? {
        Some(metadata) if metadata.file_type().is_dir() => Ok(()),
        Some(_) => non_directory(path, action),
        None => match fs::create_dir(path) {
            Ok(()) => sync_dir(ops, parent, "syncing parent after directory creation"),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                require_directory(path, action)
            }
            Err(error) => Err(filesystem_error(action, path, error)),
        },
    }
}

fn require_directory(path: &Path, action: &str) -> Result<()> {
    match path_metadata(path, action)? {
        Some(metadata) if metadata.file_type().is_dir() => Ok(()),
        Some(_) => non_directory(path, action),
        None => Err(Error::new(
            ErrorKind::Error,
            format!("{action} {}: directory does not exist", path.display()),
        )),
    }
}

fn non_directory(path: &Path, action: &str) -> Result<()> {
    Err(Error::new(
        ErrorKind::Error,
        format!("{action} {} is not a directory", path.display()),
    ))
}

fn path_metadata(path: &Path, action: &str) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(filesystem_error(action, path, error)),
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    Ok(path_metadata(path, "checking pull transaction")?.is_some())
}

fn mirror_parent(root: &Path) -> Result<PathBuf> {
    let parent = root.parent().filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    match path_metadata(parent, "reading mirror parent")? {
        Some(metadata) if metadata.file_type().is_dir() => Ok(parent.to_path_buf()),
        Some(_) => Err(Error::new(
            ErrorKind::Error,
            format!("mirror parent {} is not a directory", parent.display()),
        )),
        None => Err(Error::new(
            ErrorKind::Error,
            format!("mirror parent {} does not exist", parent.display()),
        )),
    }
}

fn transaction_dir(lock: &PullLock) -> PathBuf {
    lock.root.join(TRANSACTION_DIR)
}

fn journal_path(transaction: &Path) -> PathBuf {
    transaction.join(JOURNAL)
}

fn staged_path(transaction: &Path, index: usize) -> PathBuf {
    transaction.join("staged").join(index.to_string())
}

fn backup_path(transaction: &Path, index: usize) -> PathBuf {
    transaction.join("backups").join(index.to_string())
}

fn with_newline(mut record: Vec<u8>) -> Vec<u8> {
    record.push(b'\n');
    record
}

fn write(
    ops: &dyn FileOps,
    path: &Path,
    bytes: &[u8],
    append: bool,
    named: &Path,
    action: &str,
) -> Result<()> {
    ops.write(path, bytes, append)
        .map_err(|e| filesystem_error(action, named, e))
}

fn sync_file(ops: &dyn FileOps, path: &Path, named: &Path, action: &str) -> Result<()> {
    ops.sync_file(path)
        .map_err(|e| filesystem_error(action, named, e))
}

fn sync_dir(ops: &dyn FileOps, path: &Path, action: &str) -> Result<()> {
    ops.sync_dir(path)
        .map_err(|e| filesystem_error(action, path, e))
}

fn rename(ops: &dyn FileOps, from: &Path, to: &Path, relative: &Path, action: &str) -> Result<()> {
    ops.rename(from, to)
        .map_err(|e| filesystem_error(action, relative, e))
}

fn remove_file(ops: &dyn FileOps, path: &Path, relative: &Path, action: &str) -> Result<()> {
    ops.remove_file(path)
        .map_err(|e| filesystem_error(action, relative, e))
}

fn remove_transaction(lock: &PullLock, ops: &dyn FileOps) -> Result<()> {
    let transaction = transaction_dir(lock);
    if path_exists(&transaction)? {
        require_directory(&transaction, "removing pull transaction")?;
        ops.remove_dir_all(&transaction)
            .map_err(|e| filesystem_error("removing pull transaction", &transaction, e))?;
        sync_dir(
            ops,
            &lock.root,
            "syncing mirror directory after transaction removal",
        )?;
    }
    Ok(())
}

fn filesystem_error(action: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorKind::Error,
        format!("{action} {}: {error}", path.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Write};
    use std::path::Path;

    struct FailingFileOps {
        operation: &'static str,
        fail_at: usize,
        calls: Cell<usize>,
    }

    impl FailingFileOps {
        fn once(operation: &'static str, fail_at: usize) -> Self {
            Self {
                operation,
                fail_at,
                calls: Cell::new(0),
            }
        }

        fn fail(&self, operation: &'static str) -> io::Result<()> {
            if operation != self.operation {
                return Ok(());
            }
            let call = self.calls.get() + 1;
            self.calls.set(call);
            if call == self.fail_at {
                return Err(io::Error::other(format!("injected {operation} failure")));
            }
            Ok(())
        }
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
            std::io::Write::write_all(&mut options.open(path)?, bytes)
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

    struct RecordingFileOps {
        synced_directories: RefCell<Vec<PathBuf>>,
    }

    impl RecordingFileOps {
        fn new() -> Self {
            Self {
                synced_directories: RefCell::new(Vec::new()),
            }
        }

        fn synced_directories(&self) -> Vec<PathBuf> {
            self.synced_directories.borrow().clone()
        }
    }

    impl FileOps for RecordingFileOps {
        fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()> {
            let mut options = OpenOptions::new();
            options.write(true).create(true);
            if append {
                options.append(true);
            } else {
                options.truncate(true);
            }
            std::io::Write::write_all(&mut options.open(path)?, bytes)
        }

        fn sync_file(&self, path: &Path) -> io::Result<()> {
            File::open(path)?.sync_all()
        }

        fn sync_dir(&self, path: &Path) -> io::Result<()> {
            self.synced_directories
                .borrow_mut()
                .push(path.to_path_buf());
            sync_test_directory(path)
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

    fn staged(relative: &str, bytes: &[u8]) -> StagedFile {
        StagedFile {
            relative: relative.into(),
            bytes: bytes.to_vec(),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum TreeEntry {
        Directory,
        File(Vec<u8>),
        Symlink(PathBuf),
        Other,
    }

    fn mirror_tree(root: &Path) -> Vec<(PathBuf, TreeEntry)> {
        fn visit(root: &Path, directory: &Path, tree: &mut Vec<(PathBuf, TreeEntry)>) {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let kind = entry.file_type().unwrap();
                let value = if kind.is_dir() {
                    TreeEntry::Directory
                } else if kind.is_file() {
                    TreeEntry::File(fs::read(&path).unwrap())
                } else if kind.is_symlink() {
                    TreeEntry::Symlink(fs::read_link(&path).unwrap())
                } else {
                    TreeEntry::Other
                };
                if kind.is_dir() {
                    visit(root, &path, tree);
                }
                tree.push((relative, value));
            }
        }

        let mut tree = Vec::new();
        if root.exists() {
            visit(root, root, &mut tree);
        }
        tree.sort_by(|left, right| left.0.cmp(&right.0));
        tree
    }

    #[test]
    fn replacement_refuses_a_directory_target_before_creating_a_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let target = root.join("rules/a.ndjson");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("operator-note"), b"keep\n").unwrap();
        fs::write(root.join("rules/unselected.ndjson"), b"also keep\n").unwrap();
        let before = mirror_tree(&root);
        let lock = acquire_pull(&root).unwrap();

        let error = replace_staged_files(&lock, &[staged("rules/a.ndjson", b"new\n")]).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert_eq!(mirror_tree(&root), before);
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_refuses_a_dangling_symlink_target_before_creating_a_transaction() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let target = root.join("rules/a.ndjson");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        symlink("missing-target", &target).unwrap();
        fs::write(root.join("rules/unselected.ndjson"), b"also keep\n").unwrap();
        let before = mirror_tree(&root);
        let lock = acquire_pull(&root).unwrap();

        let error = replace_staged_files(&lock, &[staged("rules/a.ndjson", b"new\n")]).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert_eq!(mirror_tree(&root), before);
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    #[cfg(unix)]
    #[test]
    fn replacement_refuses_a_symlinked_target_parent_before_creating_a_transaction() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("a.ndjson"), b"outside old\n").unwrap();
        fs::create_dir_all(&root).unwrap();
        symlink(&outside, root.join("rules")).unwrap();
        let before = mirror_tree(&root);
        let outside_before = fs::read(outside.join("a.ndjson")).unwrap();
        let lock = acquire_pull(&root).unwrap();

        let error = replace_staged_files(&lock, &[staged("rules/a.ndjson", b"new\n")]).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert_eq!(mirror_tree(&root), before);
        assert_eq!(fs::read(outside.join("a.ndjson")).unwrap(), outside_before);
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    #[test]
    fn transaction_syncs_each_new_directory_from_parent_to_child_and_after_removal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let transaction = root.join(".elasticctl-pull-txn");
        let rules = root.join("rules");
        let lock = acquire_pull(&root).unwrap();
        let ops = RecordingFileOps::new();

        replace_staged_files_with(&lock, &[staged("rules/nested/a.ndjson", b"new\n")], &ops)
            .unwrap();

        let synced = ops.synced_directories();
        assert_eq!(
            &synced[..4],
            [
                dir.path().to_path_buf(),
                root.clone(),
                transaction.clone(),
                transaction.clone(),
            ]
        );
        assert!(
            synced
                .windows(2)
                .any(|pair| pair == [root.clone(), rules.clone()]),
            "target directory creations must sync root before rules: {synced:?}"
        );
        assert_eq!(synced.last(), Some(&root));
    }

    #[test]
    fn a_failed_second_replace_restores_the_complete_old_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        fs::create_dir_all(root.join("rules")).unwrap();
        fs::write(root.join("rules/a.ndjson"), b"old a\n").unwrap();
        fs::write(root.join("rules/b.ndjson"), b"old b\n").unwrap();
        fs::write(root.join("rules/unselected.ndjson"), b"keep\n").unwrap();
        let lock = acquire_pull(&root).unwrap();

        let error = replace_staged_files_with(
            &lock,
            &[
                staged("rules/a.ndjson", b"new a\n"),
                staged("rules/b.ndjson", b"new b\n"),
                staged("exceptions/new.ndjson", b"new exception\n"),
            ],
            &FailingFileOps::once("rename", 4),
        )
        .unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert!(
            error.message.contains("rules/b.ndjson"),
            "{}",
            error.message
        );
        assert_eq!(fs::read(root.join("rules/a.ndjson")).unwrap(), b"old a\n");
        assert_eq!(fs::read(root.join("rules/b.ndjson")).unwrap(), b"old b\n");
        assert_eq!(
            fs::read(root.join("rules/unselected.ndjson")).unwrap(),
            b"keep\n"
        );
        assert!(!root.join("exceptions/new.ndjson").exists());
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    fn write_journal(root: &Path, existed_before: bool, phase: Phase) {
        let txn = root.join(".elasticctl-pull-txn");
        fs::create_dir_all(txn.join("staged")).unwrap();
        fs::create_dir_all(txn.join("backups")).unwrap();
        let entry = JournalEntry {
            relative: "rules/a.ndjson".into(),
            existed_before,
            phase: Phase::Prepared,
        };
        let prepared = serde_json::json!({ "entries": [entry] });
        let update = PhaseRecord { entry: 0, phase };
        fs::write(
            txn.join("journal.ndjson"),
            format!(
                "{}\n{}\n",
                serde_json::to_string(&prepared).unwrap(),
                serde_json::to_string(&update).unwrap()
            ),
        )
        .unwrap();
    }

    #[derive(Clone, Copy, Debug)]
    enum RecoveryState {
        TargetAndStaged,
        BackupAndStaged,
        BackupAndTarget,
    }

    fn write_recovery_state(root: &Path, state: RecoveryState) {
        let txn = root.join(".elasticctl-pull-txn");
        match state {
            RecoveryState::TargetAndStaged => {
                fs::write(root.join("rules/a.ndjson"), b"old\n").unwrap();
                fs::write(txn.join("staged/0"), b"new\n").unwrap();
            }
            RecoveryState::BackupAndStaged => {
                fs::write(txn.join("backups/0"), b"old\n").unwrap();
                fs::write(txn.join("staged/0"), b"new\n").unwrap();
            }
            RecoveryState::BackupAndTarget => {
                fs::write(txn.join("backups/0"), b"old\n").unwrap();
                fs::write(root.join("rules/a.ndjson"), b"new\n").unwrap();
            }
        }
    }

    #[test]
    fn recovery_restores_the_pre_transaction_bytes_for_every_phase_twice() {
        for (phase, state) in [
            (Phase::Prepared, RecoveryState::TargetAndStaged),
            // `BackingUp` is recorded before the rename, so recovery must
            // tolerate both its source and destination sides.
            (Phase::BackingUp, RecoveryState::TargetAndStaged),
            (Phase::BackingUp, RecoveryState::BackupAndStaged),
            (Phase::BackedUp, RecoveryState::BackupAndStaged),
            // `Installing` is likewise recorded before the staged-to-target
            // rename and must recover both observable states.
            (Phase::Installing, RecoveryState::BackupAndStaged),
            (Phase::Installing, RecoveryState::BackupAndTarget),
            (Phase::Installed, RecoveryState::BackupAndTarget),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("mirror");
            fs::create_dir_all(root.join("rules")).unwrap();
            write_journal(&root, true, phase);
            write_recovery_state(&root, state);
            let lock = acquire_pull(&root).unwrap();

            recover_pull(&lock).unwrap();
            recover_pull(&lock).unwrap();

            assert_eq!(fs::read(root.join("rules/a.ndjson")).unwrap(), b"old\n");
            assert!(
                !root.join(".elasticctl-pull-txn").exists(),
                "{phase:?} {state:?}"
            );
        }
    }

    #[test]
    fn recovery_removes_an_installed_target_that_was_absent_before() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        fs::create_dir_all(root.join("rules")).unwrap();
        write_journal(&root, false, Phase::Installing);
        fs::write(
            root.join("rules/a.ndjson"),
            b"transaction-owned replacement\n",
        )
        .unwrap();
        let lock = acquire_pull(&root).unwrap();

        recover_pull(&lock).unwrap();
        recover_pull(&lock).unwrap();

        assert!(!root.join("rules/a.ndjson").exists());
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    #[test]
    fn a_failed_rollback_preserves_the_journal_for_the_next_pull() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        fs::create_dir_all(root.join("rules")).unwrap();
        write_journal(&root, true, Phase::BackedUp);
        write_recovery_state(&root, RecoveryState::BackupAndStaged);
        let lock = acquire_pull(&root).unwrap();

        recover_pull_with(&lock, &FailingFileOps::once("rename", 1)).unwrap_err();
        assert!(root.join(".elasticctl-pull-txn/journal.ndjson").exists());

        recover_pull(&lock).unwrap();
        assert_eq!(fs::read(root.join("rules/a.ndjson")).unwrap(), b"old\n");
        assert!(!root.join(".elasticctl-pull-txn").exists());
    }

    #[test]
    fn recovery_ignores_only_a_final_incomplete_journal_record() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        fs::create_dir_all(root.join("rules")).unwrap();
        write_journal(&root, true, Phase::Installed);
        write_recovery_state(&root, RecoveryState::BackupAndTarget);
        let journal = root.join(".elasticctl-pull-txn/journal.ndjson");
        OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(b"{\"entry\":0")
            .unwrap();
        let lock = acquire_pull(&root).unwrap();

        recover_pull(&lock).unwrap();

        assert_eq!(fs::read(root.join("rules/a.ndjson")).unwrap(), b"old\n");
    }

    #[test]
    fn recovery_discards_a_transaction_with_only_an_incomplete_prepared_record() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let transaction = root.join(".elasticctl-pull-txn");
        fs::create_dir_all(transaction.join("staged")).unwrap();
        fs::write(transaction.join("staged/0"), b"new\n").unwrap();
        fs::write(transaction.join("journal.ndjson"), b"{\"entries\":[").unwrap();
        let lock = acquire_pull(&root).unwrap();

        recover_pull(&lock).unwrap();
        recover_pull(&lock).unwrap();

        assert!(!root.join("rules/a.ndjson").exists());
        assert!(!transaction.exists());
    }

    #[test]
    fn recovery_preserves_a_transaction_with_a_malformed_complete_prepared_record() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let transaction = root.join(".elasticctl-pull-txn");
        fs::create_dir_all(transaction.join("staged")).unwrap();
        fs::write(transaction.join("staged/0"), b"new\n").unwrap();
        fs::write(transaction.join("journal.ndjson"), b"{\"entries\":}\n").unwrap();
        let lock = acquire_pull(&root).unwrap();

        let error = recover_pull(&lock).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert!(transaction.exists());
        assert!(transaction.join("staged/0").exists());
        assert!(!root.join("rules/a.ndjson").exists());
    }

    #[test]
    fn replacement_rejects_an_escape_before_creating_a_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("mirror");
        let lock = acquire_pull(&root).unwrap();

        let error = replace_staged_files(&lock, &[staged("rules/../escape", b"bad")]).unwrap_err();

        assert_eq!(error.kind, elasticctl_core::ErrorKind::Error);
        assert!(!root.exists());
    }
}
