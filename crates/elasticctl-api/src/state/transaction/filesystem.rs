use super::{PullLock, StagedFile};
use elasticctl_core::{Error, ErrorKind, Result};
use std::collections::BTreeSet;
#[cfg(not(windows))]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

pub(super) trait FileOps {
    fn write(&self, path: &Path, bytes: &[u8], append: bool) -> io::Result<()>;
    fn sync_file(&self, path: &Path) -> io::Result<()>;
    fn sync_dir(&self, path: &Path) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
}

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
pub(super) fn validate_replacement(lock: &PullLock, files: &[StagedFile]) -> Result<Vec<bool>> {
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

pub(super) fn validate_relative(relative: &Path) -> Result<()> {
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

pub(super) fn ensure_mirror_root(lock: &PullLock, ops: &dyn FileOps) -> Result<()> {
    mirror_parent(&lock.root)?;
    ensure_directory(&lock.root, ops, "creating mirror root")
}

pub(super) fn ensure_target_parent(
    lock: &PullLock,
    relative: &Path,
    ops: &dyn FileOps,
) -> Result<PathBuf> {
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

pub(super) fn target_is_regular_file(lock: &PullLock, relative: &Path) -> Result<bool> {
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

pub(super) fn ensure_directory(path: &Path, ops: &dyn FileOps, action: &str) -> Result<()> {
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

pub(super) fn require_directory(path: &Path, action: &str) -> Result<()> {
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

pub(super) fn path_exists(path: &Path) -> Result<bool> {
    Ok(path_metadata(path, "checking pull transaction")?.is_some())
}

pub(super) fn mirror_parent(root: &Path) -> Result<PathBuf> {
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
pub(super) fn write(
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

pub(super) fn sync_file(ops: &dyn FileOps, path: &Path, named: &Path, action: &str) -> Result<()> {
    ops.sync_file(path)
        .map_err(|e| filesystem_error(action, named, e))
}

pub(super) fn sync_dir(ops: &dyn FileOps, path: &Path, action: &str) -> Result<()> {
    ops.sync_dir(path)
        .map_err(|e| filesystem_error(action, path, e))
}

pub(super) fn rename(
    ops: &dyn FileOps,
    from: &Path,
    to: &Path,
    relative: &Path,
    action: &str,
) -> Result<()> {
    ops.rename(from, to)
        .map_err(|e| filesystem_error(action, relative, e))
}

pub(super) fn remove_file(
    ops: &dyn FileOps,
    path: &Path,
    relative: &Path,
    action: &str,
) -> Result<()> {
    ops.remove_file(path)
        .map_err(|e| filesystem_error(action, relative, e))
}
pub(super) fn filesystem_error(action: &str, path: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorKind::Error,
        format!("{action} {}: {error}", path.display()),
    )
}
