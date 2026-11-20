use std::{
    io::{Read, Write},
    time::Instant,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Hash;

use super::{
    Access, PeerError, Result,
    effects::{GraphBudget, GraphJob, GraphMetrics},
};

const MAGIC: &[u8; 4] = b"PPN1";
const MAX_FRAME: usize = 1028 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvaluationMode {
    #[default]
    Read,
    Update {
        expected_revision: u64,
        operation: Hash,
    },
}

#[derive(Serialize, Deserialize)]
pub(super) struct Job {
    pub grant: Hash,
    pub program: Hash,
    pub mode: EvaluationMode,
    pub input: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(super) enum Request {
    Fetch(Hash),
    Evaluate(Job),
    Delegate {
        grant: Hash,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
    },
    LegacyRun,
    LegacySubprocess,
    Run(GraphJob),
    Forward(Forward),
    Submit(Submission),
    JobStatus(Hash),
    CancelJob(Hash),
    SubmitReaction(Submission),
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Submission {
    pub id: Hash,
    pub graph: GraphJob,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum JobState {
    Pending,
    Running,
    Completed {
        revision: u64,
        value: Vec<u8>,
        graph: GraphMetrics,
    },
    Failed(Failure),
    Cancelled,
    Expired,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Forward {
    pub grant: Hash,
    pub delegated_by: Option<Hash>,
    pub holder: Hash,
    pub access: Access,
    pub program: Hash,
    pub limit: GraphBudget,
    pub expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) enum Reply {
    Block(Vec<u8>),
    NeedProgram(Hash),
    Evaluation {
        revision: u64,
        value: Vec<u8>,
        metrics: Option<Metrics>,
    },
    Delegated(Hash),
    Failed(Failure),
    Graph {
        revision: u64,
        value: Vec<u8>,
        metrics: GraphMetrics,
    },
    Job(JobState),
}

#[derive(Serialize, Deserialize)]
pub(super) enum EffectReply {
    Value(Vec<u8>),
    Failed(Failure),
}

impl From<Result<Vec<u8>>> for EffectReply {
    fn from(result: Result<Vec<u8>>) -> Self {
        match result {
            Ok(value) => Self::Value(value),
            Err(error) => Self::Failed(error.into()),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(super) struct Metrics {
    pub fuel: Option<u64>,
    pub memory: u64,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Failure {
    Denied,
    Missing(Hash),
    Conflict(u64),
    Invalid(String),
    Guest(String),
    Timeout,
    Cancelled,
    Busy,
    Internal,
}

impl From<PeerError> for Failure {
    fn from(err: PeerError) -> Self {
        match err {
            PeerError::Denied => Self::Denied,
            PeerError::Missing(hash) => Self::Missing(hash),
            PeerError::Conflict(revision) => Self::Conflict(revision),
            PeerError::Value(message) | PeerError::Protocol(message) => Self::Invalid(message),
            PeerError::Guest(message) => Self::Guest(message),
            PeerError::Runtime(crate::Error::Timeout) | PeerError::Timeout => Self::Timeout,
            PeerError::Cancelled => Self::Cancelled,
            PeerError::Limit(_) | PeerError::Runtime(_) => Self::Invalid(err.to_string()),
            PeerError::Storage(ref error)
                if matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ) =>
            {
                Self::Busy
            }
            _ => Self::Internal,
        }
    }
}

impl From<Failure> for PeerError {
    fn from(err: Failure) -> Self {
        match err {
            Failure::Denied => Self::Denied,
            Failure::Missing(hash) => Self::Missing(hash),
            Failure::Conflict(revision) => Self::Conflict(revision),
            Failure::Invalid(message) => Self::Value(message),
            Failure::Guest(message) => Self::Guest(message),
            Failure::Timeout => Self::Timeout,
            Failure::Cancelled => Self::Cancelled,
            Failure::Busy => Self::Busy,
            Failure::Internal => Self::Protocol("peer operation failed".into()),
        }
    }
}

pub(super) fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    postcard::to_allocvec(value).map_err(|err| PeerError::Protocol(err.to_string()))
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, rest) =
        postcard::take_from_bytes(bytes).map_err(|err| PeerError::Protocol(err.to_string()))?;
    if !rest.is_empty() {
        return Err(PeerError::Protocol("trailing bytes".into()));
    }
    Ok(value)
}

/// The counter reports application framing bytes, including the eight-byte header.
pub(super) fn send(out: &mut impl Write, value: &impl Serialize) -> Result<u64> {
    let payload = encode(value)?;
    if payload.len() > MAX_FRAME {
        return Err(PeerError::Limit("frame bytes"));
    }
    let mut header = [0; 8];
    header[..4].copy_from_slice(MAGIC);
    header[4..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    out.write_all(&header)?;
    out.write_all(&payload)?;
    out.flush()?;
    Ok((8 + payload.len()) as u64)
}

pub(super) fn receive<T: DeserializeOwned>(input: &mut impl Read) -> Result<(T, u64)> {
    let mut header = [0; 8];
    input.read_exact(&mut header)?;
    if &header[..4] != MAGIC {
        return Err(PeerError::Protocol("unknown protocol version".into()));
    }
    let len = u32::from_be_bytes(header[4..].try_into().expect("header length is fixed")) as usize;
    if len > MAX_FRAME {
        return Err(PeerError::Limit("frame bytes"));
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes)?;
    Ok((decode(&bytes)?, (8 + len) as u64))
}

pub(super) fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_oversized_and_unknown_frames() {
        let mut bytes = Vec::new();
        send(&mut bytes, &Request::Fetch(Hash([1; 32]))).unwrap();
        for length in 0..bytes.len() {
            assert!(receive::<Request>(&mut &bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing[7] += 1;
        trailing.push(0);
        assert!(matches!(
            receive::<Request>(&mut trailing.as_slice()),
            Err(PeerError::Protocol(_))
        ));
        bytes[..4].copy_from_slice(b"PPN0");
        assert!(matches!(
            receive::<Request>(&mut bytes.as_slice()),
            Err(PeerError::Protocol(_))
        ));
        assert!(matches!(
            receive::<Request>(&mut b"PPN1\xff\xff\xff\xff".as_slice()),
            Err(PeerError::Limit(_))
        ));
    }
}
