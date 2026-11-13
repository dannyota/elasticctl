use super::filesystem::*;
use super::{FileOps, Journal, Phase, PhaseRecord, PreparedRecord, with_newline};
use elasticctl_core::{Error, ErrorKind, Result};
use std::fs;
use std::path::Path;

pub(super) fn append_phase(
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

pub(super) fn read_journal(transaction_dir: &Path) -> Result<Option<Journal>> {
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
