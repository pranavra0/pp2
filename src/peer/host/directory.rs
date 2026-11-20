use std::{
    ffi::CString,
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt},
    },
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    Data,
    peer::{HostProvider, HostResource, PeerError, Result, data_from_json, data_to_json},
};

const PATH_BYTES: usize = 480;
const LIST_WORK: usize = 4096;
const LIST_LIMIT: usize = 64;
const READ_BYTES: usize = 16 * 1024;

/// Linux directory provider. Names are UTF-8 and relative to an explicitly selected directory.
pub struct Directory;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Identity {
    device: String,
    inode: String,
    created: SystemTime,
}

impl Identity {
    fn of(directory: &File) -> Result<Self> {
        let metadata = directory.metadata()?;
        Ok(Self {
            device: metadata.dev().to_string(),
            inode: metadata.ino().to_string(),
            created: metadata.created().map_err(|_| {
                PeerError::Unsupported("directory grants require filesystem birth timestamps")
            })?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Configuration {
    path: PathBuf,
    identity: Identity,
}

impl Directory {
    pub const PROVIDER: &str = "directory";

    /// Records the selected directory's identity. An attempted retarget fails closed.
    pub fn resource(path: &Path) -> Result<HostResource> {
        let path = std::path::absolute(path)?;
        let identity = Identity::of(&root(&path)?)?;
        let config = serde_json::to_value(Configuration { path, identity }).map_err(invalid)?;
        Ok(HostResource {
            provider: Self::PROVIDER.into(),
            configuration: data_from_json(config)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    path: String,
    after: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Read {
    path: String,
    offset: Option<u64>,
    limit: Option<usize>,
}

impl HostProvider for Directory {
    fn read(
        &self,
        configuration: &Data,
        operation: &str,
        input: Data,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Data> {
        let config: Configuration =
            serde_json::from_value(data_to_json(configuration)?).map_err(invalid)?;
        let root = root(&config.path)?;
        if Identity::of(&root)? != config.identity {
            return Err(PeerError::Denied);
        }
        let input = data_to_json(&input)?;
        let result = match operation {
            "list" => list(
                &root,
                serde_json::from_value(input).map_err(invalid)?,
                check,
            )?,
            "read" | "readText" => read(
                &root,
                serde_json::from_value(input).map_err(invalid)?,
                operation == "readText",
                check,
            )?,
            _ => return Err(PeerError::Denied),
        };
        data_from_json(result)
    }
}

fn list(root: &File, request: List, check: &dyn Fn() -> Result<()>) -> Result<serde_json::Value> {
    let path = relative(&request.path, true)?;
    let limit = request.limit.unwrap_or(LIST_LIMIT);
    if !(1..=LIST_LIMIT).contains(&limit) {
        return Err(PeerError::Limit("directory page"));
    }
    if let Some(after) = &request.after {
        relative(after, false)?;
        if after.contains('/') {
            return Err(PeerError::Denied);
        }
    }
    let directory = open(
        root.as_raw_fd(),
        &path,
        libc::O_RDONLY | libc::O_DIRECTORY,
        SCOPED,
    )?;
    // The procfs name refers only to our already-open directory descriptor.
    let mut entries = Vec::new();
    for (index, entry) in fs::read_dir(fd_path(&directory))?.enumerate() {
        check()?;
        if index >= LIST_WORK {
            return Err(PeerError::Limit("entries per directory"));
        }
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if request.after.as_ref().is_some_and(|after| name <= *after) {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_file() || kind.is_dir() {
            entries.push((name, if kind.is_dir() { "directory" } else { "file" }));
        }
    }
    entries.sort_unstable();
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next = more.then(|| &entries.last().expect("positive limit").0);
    Ok(json!({"entries": entries, "next": next}))
}

fn read(
    root: &File,
    request: Read,
    text: bool,
    check: &dyn Fn() -> Result<()>,
) -> Result<serde_json::Value> {
    let path = relative(&request.path, false)?;
    let maximum = if text { READ_BYTES } else { READ_BYTES / 2 };
    let limit = request.limit.unwrap_or(maximum);
    if !(1..=maximum).contains(&limit) || (text && request.offset.is_some()) {
        return Err(PeerError::Limit("file read size or offset"));
    }
    let target = open(root.as_raw_fd(), &path, libc::O_PATH, SCOPED)?;
    let metadata = target.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(PeerError::Denied);
    }
    // The O_PATH descriptor pins the checked inode, so opening it cannot race a path replacement
    // or open a device or FIFO supplied in place of the regular file.
    let file = File::open(fd_path(&target)).map_err(path_error)?;
    let offset = request.offset.unwrap_or(0);
    let mut bytes = vec![0; limit + 1];
    let mut end = 0;
    while end < bytes.len() {
        check()?;
        let position = offset
            .checked_add(end as u64)
            .ok_or(PeerError::Limit("file offset"))?;
        let read = file
            .read_at(&mut bytes[end..], position)
            .map_err(path_error)?;
        if read == 0 {
            break;
        }
        end += read;
    }
    let more = end > limit;
    bytes.truncate(end.min(limit));
    if text {
        if more {
            return Err(PeerError::Limit("whole text file bytes"));
        }
        return Ok(json!(String::from_utf8(bytes).map_err(|_| {
            PeerError::Value("expected a UTF-8 text file".into())
        })?));
    }
    let next = more.then(|| offset + limit as u64);
    Ok(json!({"bytes": bytes, "next": next}))
}

const SCOPED: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;

fn relative(path: &str, allow_root: bool) -> Result<CString> {
    if allow_root && path.is_empty() {
        return Ok(CString::new(".").unwrap());
    }
    if path.len() > PATH_BYTES || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return Err(PeerError::Denied);
    }
    CString::new(path).map_err(|_| PeerError::Denied)
}

fn root(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(PeerError::Denied);
    }
    let path = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| PeerError::Denied)?;
    open(
        libc::AT_FDCWD,
        &path,
        libc::O_PATH | libc::O_DIRECTORY,
        libc::RESOLVE_NO_SYMLINKS,
    )
}

fn open(dir: i32, path: &CString, flags: i32, resolve: u64) -> Result<File> {
    // SAFETY: open_how consists of integer fields, and zero sets the default mode.
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    how.flags = (flags | libc::O_CLOEXEC) as u64;
    how.resolve = resolve;
    // SAFETY: path and how point to initialized data valid for this syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir,
            path.as_ptr(),
            &how,
            size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(path_error(io::Error::last_os_error()));
    }
    // SAFETY: openat2 returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn path_error(error: io::Error) -> PeerError {
    match error.raw_os_error() {
        Some(libc::ENOSYS) => PeerError::Unsupported("directory grants require openat2"),
        Some(libc::ENOENT | libc::ENOTDIR) => {
            PeerError::Value("directory entry unavailable".into())
        }
        Some(libc::EAGAIN) => PeerError::Busy,
        _ => PeerError::Denied,
    }
}

fn invalid(error: serde_json::Error) -> PeerError {
    PeerError::Value(error.to_string())
}
