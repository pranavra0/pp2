use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Hash;

use super::{PeerError, Result, protocol::Metrics};

#[derive(Serialize, Deserialize)]
pub(super) struct Work {
    pub program: Hash,
    pub code: Vec<(Hash, Vec<u8>)>,
    pub state_hash: Hash,
    pub state: Vec<u8>,
    pub input: Vec<u8>,
}

pub(super) struct Output {
    pub value: Vec<u8>,
    pub metrics: Metrics,
}

#[cfg(target_os = "linux")]
mod linux;

pub(super) fn run(executable: &Path, work: Work, check: impl Fn() -> Result<()>) -> Result<Output> {
    #[cfg(target_os = "linux")]
    return linux::run(executable, work, check);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (executable, work, check);
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
