//! Authenticated peer execution, durable references, and immutable content exchange.

mod content;
mod protocol;
mod storage;
mod transport;
mod typescript;
mod worker;

pub use content::{JavaScript, data_from_json, data_to_json};
pub use storage::{Access, PeerStore, RECEIPT_WINDOW, Revision};
pub use transport::{
    Cancellation, Client, Credentials, Evaluation, EvaluationMode, RemoteReport, Server,
};
pub use typescript::compile_typescript;

use std::io;

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

/// Internal subprocess entry point for binaries hosting a peer server.
#[doc(hidden)]
pub fn worker_main(parent: u32) -> std::result::Result<(), PeerError> {
    worker::main(parent)
}
