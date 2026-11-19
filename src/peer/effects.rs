use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{Block, Hash};

use super::{EvaluationMode, PeerError, Result};

pub(super) const MAX_EFFECTS: u16 = 128;
pub(super) const MAX_EFFECT_BYTES: usize = 128 * 1024;
pub(super) const MAX_BINDINGS: usize = 16;
pub(super) const MAX_KEY_BYTES: usize = 512;
pub(super) const MAX_SCAN_ROWS: u16 = 128;

/// Maximum work the root may assign to its descendants, under one wall-clock deadline.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBudget {
    pub timeout_ms: u32,
    pub calls: u16,
    pub depth: u8,
}

impl GraphBudget {
    pub fn validate(self) -> Result<()> {
        if !(1..=8000).contains(&self.timeout_ms) || self.calls > 16 || self.depth > 4 {
            return Err(PeerError::Limit("graph deadline, calls or depth"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct GraphJob {
    pub grant: Hash,
    pub program: Hash,
    pub mode: EvaluationMode,
    pub input: Vec<u8>,
    pub budget: GraphBudget,
    pub bindings: Vec<String>,
}

/// A host-configured capability. The peer verifies the certificate and reference grant
/// independently during each call. These fields never cross the worker boundary.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub address: std::net::SocketAddr,
    pub name: String,
    pub grant: Hash,
    pub program: Hash,
    pub access: super::Access,
}

/// Bindings are addressed by name and scoped to an authenticated caller, entry grant and program.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSet {
    pub holder: Hash,
    pub grant: Hash,
    pub program: Hash,
    pub capabilities: BTreeMap<String, Binding>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum Effect {
    Evaluate(Remote),
    Get(String),
    Scan(Scan),
    Put(String, Vec<u8>),
    Delete(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Remote {
    pub target: String,
    pub input: Vec<u8>,
    pub allowance: u16,
    pub timeout_ms: Option<u16>,
    pub delegate: Vec<String>,
    pub update: Option<(u64, Hash)>,
}

impl Remote {
    fn validate(&self) -> Result<()> {
        if self.input.len() > MAX_EFFECT_BYTES {
            return Err(PeerError::Limit("remote input bytes"));
        }
        if self.timeout_ms.is_some_and(|ms| !(1..=8000).contains(&ms)) {
            return Err(PeerError::Limit("child deadline"));
        }
        validate_binding_names(&self.delegate)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Scan {
    pub prefix: String,
    pub after: Option<String>,
    pub limit: u16,
}

impl Effect {
    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Evaluate(remote) => remote.validate(),
            Self::Get(key) | Self::Delete(key) => check_key(key, false),
            Self::Put(key, value) => {
                check_key(key, false)?;
                if value.len() > MAX_EFFECT_BYTES {
                    return Err(PeerError::Limit("entry bytes"));
                }
                Ok(())
            }
            Self::Scan(scan) => {
                check_key(&scan.prefix, true)?;
                if let Some(after) = &scan.after {
                    check_key(after, false)?;
                    if !after.starts_with(&scan.prefix) {
                        return Err(PeerError::Value("cursor must match the scan prefix".into()));
                    }
                }
                if !(1..=MAX_SCAN_ROWS).contains(&scan.limit) {
                    return Err(PeerError::Limit("scan rows"));
                }
                Ok(())
            }
        }
    }
}

pub(super) fn check_key(key: &str, empty: bool) -> Result<()> {
    if (key.is_empty() && !empty) || key.len() > MAX_KEY_BYTES {
        return Err(PeerError::Value(
            "expected a bounded UTF-8 collection key".into(),
        ));
    }
    Ok(())
}

pub fn validate_binding_names(names: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    if names.len() > MAX_BINDINGS
        || names.iter().any(|name| {
            name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                || !seen.insert(name)
        })
    {
        return Err(PeerError::Value(
            "invalid or repeated capability name".into(),
        ));
    }
    Ok(())
}

pub(super) struct Scope {
    pub budget: GraphBudget,
    pub bindings: Vec<String>,
}

impl Scope {
    pub(super) fn allocate(&mut self, remote: &Remote) -> Result<GraphBudget> {
        remote.validate()?;
        if !self.bindings.contains(&remote.target)
            || remote
                .delegate
                .iter()
                .any(|name| !self.bindings.contains(name))
            || (remote.update.is_some() && (remote.allowance != 0 || !remote.delegate.is_empty()))
        {
            return Err(PeerError::Denied);
        }
        let charged = remote
            .allowance
            .checked_add(1)
            .ok_or(PeerError::Limit("graph calls"))?;
        if self.budget.depth == 0 || charged > self.budget.calls {
            return Err(PeerError::Limit("graph calls or depth"));
        }
        self.budget.calls -= charged;
        Ok(GraphBudget {
            timeout_ms: self.budget.timeout_ms,
            calls: remote.allowance,
            depth: self.budget.depth - 1,
        })
    }
}

/// Counters cover the graph observed by the initiating broker. Byte counters cover
/// pp2 frames between peers, excluding TLS/TCP overhead and the initiating request.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct GraphMetrics {
    pub remote_calls: u16,
    pub remote_failures: u16,
    pub remote_request_bytes: u64,
    pub remote_response_bytes: u64,
    pub storage_effects: u16,
    pub storage_us: u64,
    pub worker_busy_us: u64,
    pub worker_elapsed_us: u64,
    pub worker_startup_us: u64,
}

impl GraphMetrics {
    pub(super) fn add_worker(&mut self, other: Self) {
        self.storage_us = self.storage_us.saturating_add(other.storage_us);
        self.storage_effects = self.storage_effects.saturating_add(other.storage_effects);
        self.worker_busy_us = self.worker_busy_us.saturating_add(other.worker_busy_us);
        self.worker_elapsed_us = self
            .worker_elapsed_us
            .saturating_add(other.worker_elapsed_us);
        self.worker_startup_us = self
            .worker_startup_us
            .saturating_add(other.worker_startup_us);
    }
}

pub(super) fn check_response(bytes: &[u8]) -> Result<()> {
    if bytes.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("effect result bytes"));
    }
    Ok(())
}
