use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Hash;

use super::{PeerError, ResourceView, Result, effects::Effect, protocol::Metrics};

#[derive(Serialize, Deserialize)]
pub(super) struct Work {
    pub program: Hash,
    pub code: Vec<(Hash, Vec<u8>)>,
    pub input: Vec<u8>,
    pub context: WorkContext,
}

#[derive(Serialize, Deserialize)]
pub(super) enum WorkContext {
    Snapshot {
        hash: Hash,
        bytes: Vec<u8>,
        view: ResourceView,
    },
    Graph(Guest),
}

#[derive(Serialize, Deserialize)]
pub(super) struct Guest {
    pub bindings: Vec<String>,
    pub write: bool,
    pub resource: bool,
    pub revision: u64,
    pub view: ResourceView,
}

pub(super) struct Output {
    pub value: Vec<u8>,
    pub metrics: Metrics,
    pub elapsed_us: u64,
    pub busy_us: u64,
    pub startup_us: u64,
}

#[cfg(target_os = "linux")]
mod linux;

pub(super) fn run(
    executable: &Path,
    work: Work,
    check: impl Fn() -> Result<()>,
    effects: impl FnMut(Effect) -> Result<Vec<u8>>,
) -> Result<Output> {
    #[cfg(target_os = "linux")]
    return linux::run(executable, work, check, effects);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (executable, work, check, effects);
        Err(PeerError::Unsupported("worker isolation requires Linux"))
    }
}

pub(super) fn main(parent: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::main(parent);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = parent;
        Err(PeerError::Unsupported("worker isolation requires Linux"))
    }
}
