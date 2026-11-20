//! Authenticated peer execution, durable references, and immutable content exchange.

mod content;
mod discovery;
mod effects;
mod host;
mod native;
mod protocol;
mod replication;
mod storage;
mod transport;
mod typescript;
mod worker;

pub use content::{JavaScript, data_from_json, data_to_json};
pub use discovery::{DiscoveryConfig, PeerIdentity, PeerNetwork, serve_rendezvous};
pub use effects::{
    Binding, BindingSet, GraphBudget, GraphMetrics, PeerEndpoint, validate_binding_names,
};
#[cfg(target_os = "linux")]
pub use host::Directory;
pub use host::{Clock, HostProvider, HostResource};
pub use native::{NativeInstallation, NativePackage, RequestedBinding, TerminalResult};
pub use replication::{
    Consistency, ReplicaAccess, ReplicaStatus, ResourceMode, ResourceRevision, ResourceView,
    SyncReport,
};
pub use storage::{
    Access, ApplicationSpec, ApplicationState, ApplicationStatus, DeliveryOutcome, DeliveryStatus,
    PeerStore, RECEIPT_WINDOW, Revision, SubscriptionSpec, SubscriptionState, SubscriptionStatus,
};
pub use transport::{
    Cancellation, Client, Credentials, DurableEvaluation, Evaluation, EvaluationMode,
    GraphEvaluation, GraphReport, JobStatus, RemoteReport, Server,
};
pub use typescript::{compile_typescript, package_source};

use std::io;

use crate::Hash;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error(transparent)]
    Io(io::Error),
    #[error(transparent)]
    Storage(#[from] rusqlite::Error),
    #[error(transparent)]
    Runtime(#[from] crate::Error),
    #[error("TLS: {0}")]
    Tls(String),
    #[error("invalid peer message: {0}")]
    Protocol(String),
    #[error("capability denied")]
    Denied,
    #[error("no authenticated route to peer {0}")]
    PeerUnavailable(crate::Hash),
    #[error("content is unavailable: {0}")]
    Missing(crate::Hash),
    #[error("reference changed (current revision {0})")]
    Conflict(u64),
    #[error("reference does not exist: {0}")]
    NoReference(String),
    #[error("reference already exists: {0}")]
    ReferenceExists(String),
    #[error("worker failed: {0}")]
    Guest(String),
    #[error("operation exceeded its deadline")]
    Timeout,
    #[error("operation cancelled")]
    Cancelled,
    #[error("peer storage is busy")]
    Busy,
    #[error("resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("invalid value: {0}")]
    Value(String),
    #[error("TypeScript compilation failed\n{0}")]
    TypeScript(String),
}

impl From<io::Error> for PeerError {
    fn from(error: io::Error) -> Self {
        if let Some(error) = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            return Self::Tls(error.to_string());
        }
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            return Self::Timeout;
        }
        Self::Io(error)
    }
}

type Result<T> = std::result::Result<T, PeerError>;

fn random_id() -> Result<Hash> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(Hash(bytes))
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Internal subprocess entry point for binaries hosting a peer server.
#[doc(hidden)]
pub fn worker_main(parent: u32) -> std::result::Result<(), PeerError> {
    worker::main(parent)
}
