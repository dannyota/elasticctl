use elasticctl_api::ChangeReport;
use elasticctl_core::{Error, ErrorKind, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

mod filesystem;
mod journal;
mod recovery;

use filesystem::*;
use journal::{append_phase, read_journal};
#[cfg(test)]
use recovery::recover_report;
use recovery::{recover_report_locked, snapshot_original};

const JOURNAL: &str = "journal.ndjson";
const ORIGINAL: &str = "original.json";
const TRANSACTION_SUFFIX: &str = ".elasticctl-report-txn";
const LOCK_SUFFIX: &str = ".elasticctl-report.lock";

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
    Restoring,
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

trait FileOps {
    fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()>;
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
}

pub(crate) fn prepare_report(path: &Path, report: &ChangeReport) -> Result<PreparedReport> {
    prepare_report_with(path, report, &FsFileOps)
}

impl PreparedReport {
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

        remove_transaction(requested, transaction_dir, parent, ops)
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => finish_failed_publication(paths, ops, error),
    }
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

fn with_newline(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(b'\n');
    bytes
}

fn serialize_report(report: &ChangeReport) -> Result<Vec<u8>> {
    serde_json::to_string_pretty(report)
        .map(|body| body.into_bytes())
        .map_err(|e| Error::new(ErrorKind::Error, format!("encoding report: {e}")))
}

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
