use crate::Data;

use super::{PeerError, Result, unix_ms};

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

/// Reads the owning peer's wall clock through an explicit host resource.
pub struct Clock;

impl Clock {
    pub const PROVIDER: &str = "clock";

    pub fn resource() -> HostResource {
        HostResource {
            provider: Self::PROVIDER.into(),
            configuration: Data::Nil,
        }
    }
}

impl HostProvider for Clock {
    fn read(
        &self,
        configuration: &Data,
        operation: &str,
        input: Data,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Data> {
        if *configuration != Data::Nil || operation != "unixMillis" || input != Data::Nil {
            return Err(PeerError::Denied);
        }
        check()?;
        i64::try_from(unix_ms())
            .map(Data::Int)
            .map_err(|_| PeerError::Limit("clock timestamp"))
    }
}
