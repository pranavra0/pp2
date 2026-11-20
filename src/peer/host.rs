use crate::Data;

use super::Result;

#[cfg(target_os = "linux")]
mod directory;
#[cfg(target_os = "linux")]
pub use directory::Directory;

/// A host resource attached to a collection. Configuration stays on its owning peer.
pub struct HostResource {
    pub provider: String,
    pub configuration: Data,
}

/// A trusted, read-only provider. It must validate its configuration and every operation,
/// bound its work and output, and call `check` during work that can take time.
/// Reads can repeat when a durable job retries.
pub trait HostProvider: Send + Sync {
    fn read(
        &self,
        configuration: &Data,
        operation: &str,
        input: Data,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Data>;
}
