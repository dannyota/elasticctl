use super::filesystem::*;
use super::journal::{append_phase, read_journal};
use super::{FileOps, Phase};
use elasticctl_core::{Error, ErrorKind, Result};
use std::fs;
#[cfg(test)]
use std::path::Path;

#[cfg(test)]
pub(super) fn recover_report(path: &Path) -> Result<()> {
    let paths = report_paths(path)?;
    let _lock_file = acquire_lock(&paths.requested, &paths.lock_path)?;
    recover_report_locked(&paths, &FsFileOps)
}

pub(super) fn recover_report_locked(paths: &ReportPaths, ops: &dyn FileOps) -> Result<()> {
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
pub(super) fn snapshot_original(paths: &ReportPaths, ops: &dyn FileOps) -> Result<()> {
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
