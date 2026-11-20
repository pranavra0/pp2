use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Block, Hash};

use super::{PeerError, PeerIdentity, Result, discovery::Proof, protocol};

pub(super) const MAGIC: &[u8; 4] = b"PPR1";
pub(super) const LEASE_MS: u64 = 24 * 60 * 60 * 1000;
pub(super) const RENEW_MS: u64 = LEASE_MS / 2;
pub(super) const MAX_PLACEMENTS: usize = 32;
pub(super) const MAX_HEADS: usize = 128;
pub(super) const MAX_RETIRED: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMode {
    Immutable,
    SingleWriter,
    MultiWriter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaAccess {
    Store,
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum Consistency {
    #[default]
    Authoritative,
    Replica,
    Revision(Hash),
}

/// The immutable history visible to an invocation. An unreplicated reference has no resource ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceView {
    pub consistency: Consistency,
    pub resource: Option<Hash>,
    pub mode: Option<ResourceMode>,
    pub revision: Option<Hash>,
    pub heads: Vec<Hash>,
}

#[derive(Clone, Debug)]
pub struct ReplicaStatus {
    pub resource: Hash,
    pub owner: Hash,
    pub mode: Option<ResourceMode>,
    pub revision: Option<u64>,
    pub heads: Vec<Hash>,
    pub lease_expires_at_ms: Option<u64>,
    pub revoked: bool,
}

/// One locally verified record, including records outside the accepted history.
#[derive(Clone, Debug)]
pub struct ResourceRevision {
    pub id: Hash,
    pub root: Hash,
    pub parents: Vec<Hash>,
    pub author: Hash,
    pub authored_at_ms: u64,
    pub valid: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SyncReport {
    pub blocks: usize,
    pub bytes: usize,
    pub revisions: usize,
    pub pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Shape {
    Snapshot,
    Collection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Placement {
    pub id: Hash,
    pub peer: Hash,
    pub access: ReplicaAccess,
    pub program: Option<Hash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Retirement {
    pub placement: Placement,
    pub cutoff: Vec<Hash>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Policy {
    pub resource: Hash,
    pub owner: Hash,
    pub mode: ResourceMode,
    pub shape: Shape,
    pub genesis: Hash,
    pub generation: u64,
    pub placements: Vec<Placement>,
    pub retired: Vec<Retirement>,
}

impl Policy {
    pub fn placement(&self, peer: Hash) -> Option<&Placement> {
        self.placements
            .iter()
            .find(|placement| placement.peer == peer)
    }

    pub fn knows(&self, peer: Hash) -> bool {
        self.owner == peer
            || self.placement(peer).is_some()
            || self.retired.iter().any(|item| item.placement.peer == peer)
    }

    pub fn validate(&self) -> Result<()> {
        if self.placements.len() > MAX_PLACEMENTS || self.retired.len() > MAX_RETIRED {
            return Err(PeerError::Limit("replica placements"));
        }
        let mut peers = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for placement in &self.placements {
            if placement.peer == self.owner || !peers.insert(placement.peer) {
                return Err(PeerError::Denied);
            }
        }
        for placement in self
            .placements
            .iter()
            .chain(self.retired.iter().map(|item| &item.placement))
        {
            if !ids.insert(placement.id)
                || (placement.access == ReplicaAccess::Write
                    && self.mode != ResourceMode::MultiWriter)
            {
                return Err(PeerError::Denied);
            }
        }
        for item in &self.retired {
            validate_heads(&item.cutoff)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Lease {
    pub resource: Hash,
    pub placement: Placement,
    pub issued: u64,
    pub expires: u64,
}

impl Lease {
    pub fn covers(&self, resource: Hash, time: u64) -> bool {
        self.resource == resource
            && self.issued <= time
            && time < self.expires
            && self.expires - self.issued <= LEASE_MS
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Signed<T> {
    pub body: T,
    proof: Proof,
}

impl<T: Serialize> Signed<T> {
    pub fn new(domain: &[u8], body: T, key: &PeerIdentity) -> Result<Self> {
        let proof = key.sign(domain, &protocol::encode(&body)?);
        Ok(Self { body, proof })
    }

    pub fn signer(&self, domain: &[u8]) -> Result<Hash> {
        self.proof.verify(domain, &protocol::encode(&self.body)?)
    }
}

pub(super) const POLICY: &[u8] = b"pp2 replica policy v1\0";
pub(super) const LEASE: &[u8] = b"pp2 replica lease v1\0";
const CHANGE: &[u8] = b"pp2 resource revision v1\0";

pub(super) type SignedPolicy = Signed<Policy>;
pub(super) type SignedLease = Signed<Lease>;
pub(super) type Change = Signed<RevisionBody>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RevisionBody {
    pub resource: Hash,
    pub root: Hash,
    pub parents: Vec<Hash>,
    pub authored: u64,
    pub program: Option<Hash>,
    pub lease: Option<SignedLease>,
    pub reaction: bool,
    // Distinguishes even no-op transitions authored within the same millisecond.
    pub nonce: Hash,
}

impl Change {
    pub fn encode(body: RevisionBody, key: &PeerIdentity) -> Result<Vec<u8>> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(protocol::encode(&Self::new(CHANGE, body, key)?)?);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let bytes = bytes.strip_prefix(MAGIC).ok_or(PeerError::Denied)?;
        let change: Self = protocol::decode(bytes)?;
        validate_heads(&change.body.parents)?;
        if protocol::encode(&change)? != bytes {
            return Err(PeerError::Denied);
        }
        Ok(change)
    }

    pub fn author(&self) -> Result<Hash> {
        self.signer(CHANGE)
    }

    /// Verifies provenance. Retirement and parent validity are applied to the history separately.
    pub fn verify(&self, policy: &Policy, id: Hash) -> Result<Option<Hash>> {
        let body = &self.body;
        let author = self.author()?;
        if body.resource != policy.resource
            || (body.parents.is_empty() != (id == policy.genesis))
            || (policy.mode == ResourceMode::Immutable && id != policy.genesis)
            || (policy.mode == ResourceMode::SingleWriter && body.parents.len() > 1)
        {
            return Err(PeerError::Denied);
        }
        if author == policy.owner && body.lease.is_none() {
            return Ok(None);
        }
        let lease = body.lease.as_ref().ok_or(PeerError::Denied)?;
        let placement = &lease.body.placement;
        if policy.mode != ResourceMode::MultiWriter
            || id == policy.genesis
            || lease.signer(LEASE)? != policy.owner
            || !lease.body.covers(policy.resource, body.authored)
            || placement.peer != author
            || placement.access != ReplicaAccess::Write
            || placement
                .program
                .is_some_and(|pin| Some(pin) != body.program)
            || !(policy.placement(author) == Some(placement)
                || policy
                    .retired
                    .iter()
                    .any(|item| &item.placement == placement))
        {
            return Err(PeerError::Denied);
        }
        Ok(Some(placement.id))
    }
}

pub(super) fn validate_heads(heads: &[Hash]) -> Result<()> {
    if heads.len() > MAX_HEADS || heads.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PeerError::Limit("sorted resource heads"));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub(super) struct SyncRequest {
    pub resource: Hash,
    pub lease: Option<SignedLease>,
    pub block: Option<Hash>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Offer {
    pub policy: SignedPolicy,
    pub lease: Option<SignedLease>,
    pub heads: Vec<Hash>,
}

pub(super) fn checked_block(hash: Hash, bytes: &[u8]) -> Result<()> {
    if bytes.len() > Block::MAX_BYTES {
        return Err(PeerError::Limit("resource block bytes"));
    }
    super::content::inspect(hash, bytes)?;
    Ok(())
}

impl ResourceView {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "consistency": match self.consistency {
                Consistency::Authoritative => "authoritative",
                Consistency::Replica => "replica",
                Consistency::Revision(_) => "revision",
            },
            "resource": self.resource.map(|id| id.to_string()),
            "mode": self.mode,
            "revision": self.revision.map(|id| id.to_string()),
            "heads": self.heads.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
        })
    }
}
