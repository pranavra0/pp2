use std::{collections::BTreeMap, net::SocketAddr};

use super::*;
use crate::peer::{
    PeerIdentity,
    replication::{
        Change, Consistency, LEASE, LEASE_MS, Lease, Offer, POLICY, Placement, Policy, RENEW_MS,
        ReplicaAccess, ReplicaStatus, ResourceMode, ResourceRevision, ResourceView, Retirement,
        RevisionBody, Shape, Signed, SignedLease, SignedPolicy, SyncRequest, validate_heads,
    },
};

pub(super) const SCHEMA: &str = "
CREATE TABLE replicas (
    id BLOB PRIMARY KEY, ref TEXT NOT NULL UNIQUE, owner BLOB NOT NULL, local BLOB NOT NULL,
    policy BLOB, lease BLOB, heads BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE replica_versions (
    resource BLOB REFERENCES replicas(id), id BLOB REFERENCES blocks(hash), root BLOB NOT NULL,
    placement BLOB, valid INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(resource, id)
) WITHOUT ROWID;
CREATE INDEX replica_version_id ON replica_versions(id);
CREATE INDEX replica_version_root ON replica_versions(root);
CREATE TABLE replica_parents (
    resource BLOB, child BLOB, parent BLOB, PRIMARY KEY(resource, child, parent),
    FOREIGN KEY(resource, child) REFERENCES replica_versions(resource, id),
    FOREIGN KEY(resource, parent) REFERENCES replica_versions(resource, id)
) WITHOUT ROWID;
CREATE INDEX replica_children ON replica_parents(resource, parent, child);
CREATE INDEX edges_child ON edges(child, parent);
CREATE TABLE replica_pending (
    resource BLOB REFERENCES replicas(id), peer BLOB, tip BLOB,
    PRIMARY KEY(resource, peer, tip)
) WITHOUT ROWID;
CREATE TABLE replica_private (
    hash BLOB PRIMARY KEY REFERENCES blocks(hash) ON DELETE CASCADE
) WITHOUT ROWID;
CREATE TABLE replica_routes (
    resource BLOB REFERENCES replicas(id), peer BLOB, endpoint TEXT,
    PRIMARY KEY(resource, peer)
) WITHOUT ROWID;
ALTER TABLE receipts ADD COLUMN view BLOB;
ALTER TABLE jobs ADD COLUMN replica_grant BLOB;
PRAGMA user_version = 6;
";

pub(super) const RETENTION_SCHEMA: &str = "
ALTER TABLE replicas ADD COLUMN retain_snapshots INTEGER;
ALTER TABLE replica_versions ADD COLUMN retained INTEGER NOT NULL DEFAULT 1;
CREATE INDEX replica_retained ON replica_versions(resource, id) WHERE retained=1;
ALTER TABLE replica_pending ADD COLUMN proofs_only INTEGER NOT NULL DEFAULT 0;
PRAGMA user_version = 7;
";

pub(in crate::peer) struct Replica {
    pub id: Hash,
    pub owner: Hash,
    pub local: Hash,
    pub reference: String,
    pub policy: Option<SignedPolicy>,
    pub lease: Option<SignedLease>,
    pub heads: Vec<Hash>,
}

impl Replica {
    fn policy(&self) -> Result<&Policy> {
        self.policy
            .as_ref()
            .map(|policy| &policy.body)
            .ok_or(PeerError::Denied)
    }

    fn local_lease(&self, now: u64) -> Result<&SignedLease> {
        let lease = self.lease.as_ref().ok_or(PeerError::Denied)?;
        if self.policy()?.placement(self.local) != Some(&lease.body.placement)
            || !lease.body.covers(self.id, now)
        {
            return Err(PeerError::Denied);
        }
        Ok(lease)
    }

    fn check_access(&self, holder: Hash, program: Option<Hash>, access: Access) -> Result<()> {
        if self.owner == self.local {
            return Ok(());
        }
        let placement = &self.local_lease(unix_ms())?.body.placement;
        if holder != self.local
            || placement.access == ReplicaAccess::Store
            || (access == Access::Write && placement.access != ReplicaAccess::Write)
            || placement.program.is_some_and(|pin| Some(pin) != program)
        {
            return Err(PeerError::Denied);
        }
        Ok(())
    }
}

type ReplicaRow = (
    Hash,
    Hash,
    Hash,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Vec<u8>,
);

fn decode_replica(row: ReplicaRow) -> Result<Replica> {
    let (id, owner, local, reference, policy, lease, heads) = row;
    Ok(Replica {
        id,
        owner,
        local,
        reference,
        policy: policy.map(|bytes| protocol::decode(&bytes)).transpose()?,
        lease: lease.map(|bytes| protocol::decode(&bytes)).transpose()?,
        heads: protocol::decode(&heads)?,
    })
}

// The lease starts slightly before the issuer clock to cover normal clock skew.
const CLOCK_SKEW_MS: u64 = 2 * 60 * 1000;

const COLUMNS: &str = "SELECT id, owner, local, ref, policy, lease, heads FROM replicas";

fn read_replica(
    conn: &Connection,
    filter: &str,
    value: impl rusqlite::ToSql,
) -> Result<Option<Replica>> {
    let row = conn
        .query_row(&format!("{COLUMNS} WHERE {filter}=?1"), [value], |row| {
            Ok((
                Hash(row.get(0)?),
                Hash(row.get(1)?),
                Hash(row.get(2)?),
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .optional()?;
    row.map(decode_replica).transpose()
}

fn by_reference(conn: &Connection, reference: &str) -> Result<Option<Replica>> {
    read_replica(conn, "ref", reference)
}

fn by_id(conn: &Connection, id: Hash) -> Result<Replica> {
    read_replica(conn, "id", &id.0[..])?.ok_or(PeerError::Denied)
}

pub(super) fn random_id() -> Result<Hash> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|err| std::io::Error::other(err.to_string()))?;
    Ok(Hash(bytes))
}

impl PeerStore {
    /// Starts a signed history at the reference's current contents.
    pub fn share_replica(
        &mut self,
        owner: &PeerIdentity,
        reference: &str,
        mode: ResourceMode,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let current =
            revision(&tx, reference)?.ok_or_else(|| PeerError::NoReference(reference.into()))?;
        if by_reference(&tx, reference)?.is_some() {
            return Err(PeerError::Value(
                "reference already has a resource identity".into(),
            ));
        }
        let (collection, native) = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM collections WHERE ref=?1),
                    EXISTS(SELECT 1 FROM host_resources WHERE ref=?1)
                    OR EXISTS(SELECT 1 FROM native_installations WHERE ref=?1)",
            [reference],
            |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
        )?;
        if native {
            return Err(PeerError::Denied);
        }
        let (shape, root) = if collection {
            (Shape::Collection, collection_root(&tx, reference)?)
        } else {
            (Shape::Snapshot, current.hash)
        };
        let resource = random_id()?;
        let body = RevisionBody {
            resource,
            root,
            parents: Vec::new(),
            authored: unix_ms(),
            program: None,
            lease: None,
            reaction: false,
            nonce: random_id()?,
        };
        let bytes = Change::encode(body, owner)?;
        let genesis = Hash::digest(&bytes);
        let policy = Signed::new(
            POLICY,
            Policy {
                resource,
                owner: owner.id(),
                mode,
                shape,
                genesis,
                generation: 0,
                placements: Vec::new(),
                retired: Vec::new(),
            },
            owner,
        )?;
        tx.execute(
            "INSERT INTO replicas(id, ref, owner, local, policy, heads)
             VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
            params![
                &resource.0[..],
                reference,
                &owner.id().0[..],
                protocol::encode(&policy)?,
                protocol::encode(&vec![genesis])?
            ],
        )?;
        insert(&tx, genesis, &bytes)?;
        add_version(&tx, &policy.body, genesis, &Change::decode(&bytes)?)?;
        tx.execute(
            "UPDATE refs SET hash=?2 WHERE name=?1",
            params![reference, &root.0[..]],
        )?;
        tx.commit()?;
        Ok(resource)
    }

    /// Explicitly approves one identity, with optional executable pinning.
    pub fn approve_replica(
        &mut self,
        owner: &PeerIdentity,
        resource: Hash,
        peer: Hash,
        access: ReplicaAccess,
        program: Option<Hash>,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let mut policy = owner_policy(&tx, owner, resource)?;
        if policy.placement(peer).is_some() {
            return Err(PeerError::Value("peer already has a placement".into()));
        }
        let id = random_id()?;
        policy.placements.push(Placement {
            id,
            peer,
            access,
            program,
        });
        save_policy(&tx, &policy, owner)?;
        tx.commit()?;
        Ok(id)
    }

    /// Cuts off a placement at the history known to the owner in this transaction.
    pub fn revoke_replica(
        &mut self,
        owner: &PeerIdentity,
        resource: Hash,
        peer: Hash,
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let mut policy = owner_policy(&tx, owner, resource)?;
        let index = policy
            .placements
            .iter()
            .position(|item| item.peer == peer)
            .ok_or(PeerError::Denied)?;
        let placement = policy.placements.remove(index);
        let cutoff = heads(&tx, resource)?;
        policy.retired.push(Retirement { placement, cutoff });
        save_policy(&tx, &policy, owner)?;
        tx.execute(
            "DELETE FROM replica_pending WHERE resource=?1 AND peer=?2",
            params![&resource.0[..], &peer.0[..]],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records the owner's identity and a local reference name before the first synchronization.
    pub fn follow_replica(
        &mut self,
        local: Hash,
        owner: Hash,
        resource: Hash,
        reference: &str,
    ) -> Result<()> {
        check_name(reference)?;
        if owner == local {
            return Err(PeerError::Denied);
        }
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if revision(&tx, reference)?.is_some() || by_reference(&tx, reference)?.is_some() {
            return Err(PeerError::ReferenceExists(reference.into()));
        }
        tx.execute(
            "INSERT INTO replicas(id, ref, owner, local, heads) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &resource.0[..],
                reference,
                &owner.0[..],
                &local.0[..],
                protocol::encode(&Vec::<Hash>::new())?
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Sets an optional authenticated fallback route for a placement.
    pub fn route_replica(&mut self, resource: Hash, peer: Hash, address: SocketAddr) -> Result<()> {
        let replica = by_id(&self.0, resource)?;
        if peer != replica.owner && !replica.policy()?.knows(peer) {
            return Err(PeerError::Denied);
        }
        self.0.execute(
            "INSERT INTO replica_routes VALUES (?1, ?2, ?3)
             ON CONFLICT(resource, peer) DO UPDATE SET endpoint=excluded.endpoint",
            params![&resource.0[..], &peer.0[..], address.to_string()],
        )?;
        Ok(())
    }

    /// Reports local history and lease metadata without releasing resource contents.
    pub fn replica_status(&self, resource: Hash) -> Result<ReplicaStatus> {
        let tx = self.0.unchecked_transaction()?;
        let replica = by_id(&tx, resource)?;
        let policy = replica.policy.as_ref().map(|signed| &signed.body);
        Ok(ReplicaStatus {
            resource,
            owner: replica.owner,
            mode: policy.map(|body| body.mode),
            revision: revision(&tx, &replica.reference)?.map(|row| row.number),
            heads: replica.heads,
            lease_expires_at_ms: replica.lease.map(|lease| lease.body.expires),
            revoked: policy.is_some_and(|body| {
                body.owner != replica.local && body.placement(replica.local).is_none()
            }),
        })
    }

    /// Keeps full state for at most this many revisions on the single-writer chain.
    /// The signed records remain available for ancestry verification.
    pub fn retain_replica_snapshots(&mut self, resource: Hash, keep: u16) -> Result<usize> {
        if keep == 0 {
            return Err(PeerError::Limit("minimum retained snapshots"));
        }
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let replica = by_id(&tx, resource)?;
        if replica.policy()?.mode != ResourceMode::SingleWriter {
            return Err(PeerError::Value(
                "snapshot retention requires a single-writer resource".into(),
            ));
        }
        tx.execute(
            "UPDATE replicas SET retain_snapshots=?2 WHERE id=?1",
            params![&resource.0[..], keep],
        )?;
        let pruned = prune_snapshots(&tx, resource, &replica.heads)?;
        tx.commit()?;
        Ok(pruned)
    }

    /// Lists verified changes in address order for local administration and audit.
    pub fn replica_history(
        &self,
        resource: Hash,
        after: Option<Hash>,
        limit: u16,
    ) -> Result<Vec<ResourceRevision>> {
        if !(1..=128).contains(&limit) {
            return Err(PeerError::Limit("resource history page"));
        }
        let tx = self.0.unchecked_transaction()?;
        by_id(&tx, resource)?;
        let mut query = tx.prepare_cached(
            "SELECT v.id, v.valid, b.bytes, v.retained FROM replica_versions v JOIN blocks b ON b.hash=v.id
             WHERE v.resource=?1 AND (?2 IS NULL OR v.id>?2) ORDER BY v.id LIMIT ?3",
        )?;
        let rows = query.query_map(
            params![&resource.0[..], after.map(|id| id.0), limit],
            |row| {
                Ok((
                    Hash(row.get(0)?),
                    row.get::<_, bool>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (id, valid, bytes, retained) = row?;
            if Hash::digest(&bytes) != id {
                return Err(PeerError::Denied);
            }
            let change = Change::decode(&bytes)?;
            Ok(ResourceRevision {
                id,
                valid,
                author: change.author()?,
                root: change.body.root,
                parents: change.body.parents,
                authored_at_ms: change.body.authored,
                retained,
            })
        })
        .collect()
    }

    pub(in crate::peer) fn replica_targets(
        &self,
        local: Hash,
    ) -> Result<Vec<(Hash, Hash, Option<SocketAddr>)>> {
        let ids = {
            let mut query = self
                .0
                .prepare("SELECT id FROM replicas WHERE local=?1 ORDER BY id")?;
            query
                .query_map([&local.0[..]], |row| Ok(Hash(row.get(0)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut result = Vec::new();
        for id in ids {
            let replica = by_id(&self.0, id)?;
            let peers = replica.policy.iter().flat_map(|policy| {
                policy
                    .body
                    .placements
                    .iter()
                    .map(|placement| placement.peer)
            });
            for peer in std::iter::once(replica.owner)
                .chain(peers)
                .filter(|peer| *peer != local)
            {
                let route = self
                    .0
                    .query_row(
                        "SELECT endpoint FROM replica_routes WHERE resource=?1 AND peer=?2",
                        params![&id.0[..], &peer.0[..]],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()?;
                result.push((
                    id,
                    peer,
                    route
                        .map(|address| address.parse())
                        .transpose()
                        .map_err(|_| PeerError::Value("invalid replica route".into()))?,
                ));
            }
        }
        Ok(result)
    }

    pub(in crate::peer) fn replica_request(
        &self,
        resource: Hash,
        local: Hash,
        peer: Hash,
        block: Option<Hash>,
    ) -> Result<SyncRequest> {
        let replica = by_id(&self.0, resource)?;
        if replica.local != local {
            return Err(PeerError::Denied);
        }
        if peer != replica.owner {
            if replica.policy()?.placement(peer).is_none() {
                return Err(PeerError::Denied);
            }
            if local != replica.owner {
                replica.local_lease(unix_ms())?;
            }
        }
        Ok(SyncRequest {
            resource,
            lease: replica.lease,
            block,
        })
    }

    pub(in crate::peer) fn offer_replica(
        &self,
        local: &PeerIdentity,
        holder: Hash,
        request: &SyncRequest,
    ) -> Result<Offer> {
        let tx = self.0.unchecked_transaction()?;
        let replica = by_id(&tx, request.resource)?;
        let policy = replica.policy()?;
        if replica.local != local.id() || !policy.knows(holder) {
            return Err(PeerError::Denied);
        }
        let owner = policy.owner == local.id();
        let active = holder == policy.owner || policy.placement(holder).is_some();
        if !owner {
            replica.local_lease(unix_ms())?;
        }
        let lease = if owner && active && holder != policy.owner {
            let placement = policy.placement(holder).ok_or(PeerError::Denied)?;
            let now = unix_ms();
            match &request.lease {
                Some(lease)
                    if check_lease(policy, holder, lease, now).is_ok()
                        && lease.body.expires - now > RENEW_MS =>
                {
                    None
                }
                _ => Some(Signed::new(
                    LEASE,
                    Lease {
                        resource: replica.id,
                        placement: placement.clone(),
                        issued: now.saturating_sub(CLOCK_SKEW_MS),
                        expires: now.saturating_sub(CLOCK_SKEW_MS) + LEASE_MS,
                    },
                    local,
                )?),
            }
        } else {
            if active {
                sync_access(&replica, holder, request.lease.as_ref())?;
            }
            None
        };
        Ok(Offer {
            policy: replica.policy.ok_or(PeerError::Denied)?,
            lease,
            heads: if active { replica.heads } else { Vec::new() },
        })
    }

    pub(in crate::peer) fn serve_replica_block(
        &self,
        local: Hash,
        holder: Hash,
        request: &SyncRequest,
        hash: Hash,
    ) -> Result<Vec<u8>> {
        let tx = self.0.unchecked_transaction()?;
        let replica = by_id(&tx, request.resource)?;
        if replica.local != local {
            return Err(PeerError::Denied);
        }
        sync_access(&replica, holder, request.lease.as_ref())?;
        let reachable = tx.query_row(
            "WITH RECURSIVE ancestors(hash) AS (
                VALUES (?1) UNION SELECT edges.parent FROM edges JOIN ancestors ON edges.child=ancestors.hash
                WHERE NOT EXISTS(SELECT 1 FROM replica_versions v
                    WHERE v.resource=?2 AND v.id=edges.parent AND v.root=edges.child
                      AND v.retained=0)
             ) SELECT EXISTS(SELECT 1 FROM ancestors JOIN replica_versions v ON v.id=ancestors.hash
                             WHERE v.resource=?2 AND v.valid=1)",
            params![&hash.0[..], &replica.id.0[..]],
            |row| row.get::<_, bool>(0),
        )?;
        if !reachable {
            return Err(PeerError::Missing(hash));
        }
        let bytes = get(&tx, hash, false)?.ok_or(PeerError::Missing(hash))?;
        content::inspect(hash, &bytes)?;
        Ok(bytes)
    }

    pub(in crate::peer) fn accept_replica_offer(
        &mut self,
        local: Hash,
        peer: Hash,
        resource: Hash,
        offer: Offer,
    ) -> Result<Vec<Hash>> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let replica = by_id(&tx, resource)?;
        let incoming = &offer.policy.body;
        if replica.local != local
            || incoming.resource != resource
            || incoming.owner != replica.owner
            || offer.policy.signer(POLICY)? != replica.owner
            || !incoming.knows(local)
            || !incoming.knows(peer)
        {
            return Err(PeerError::Denied);
        }
        incoming.validate()?;
        validate_heads(&offer.heads)?;
        let newer = match &replica.policy {
            Some(previous) => check_policy_update(&previous.body, incoming)?,
            None => peer == replica.owner,
        };
        if newer {
            tx.execute(
                "UPDATE replicas SET policy=?2 WHERE id=?1",
                params![&resource.0[..], protocol::encode(&offer.policy)?],
            )?;
            if let Some(previous) = &replica.policy {
                for placement in &previous.body.placements {
                    if incoming.placement(placement.peer).is_none() {
                        tx.execute(
                            "DELETE FROM replica_pending WHERE resource=?1 AND peer=?2",
                            params![&resource.0[..], &placement.peer.0[..]],
                        )?;
                    }
                }
            }
            recompute_validity(&tx, incoming)?;
            project(
                &tx,
                &by_id(&tx, resource)?,
                heads(&tx, resource)?,
                true,
                false,
            )?;
        }
        let current = by_id(&tx, resource)?;
        let policy = current.policy()?;
        if let Some(old) = &replica.policy
            && old.body.placement(local).is_some()
            && old.body.placement(local) != policy.placement(local)
        {
            tx.execute(
                "UPDATE replicas SET lease=NULL WHERE id=?1",
                [&resource.0[..]],
            )?;
            tx.execute(
                "DELETE FROM replica_pending WHERE resource=?1",
                [&resource.0[..]],
            )?;
            tx.execute("DELETE FROM grants WHERE ref=?1", [&current.reference])?;
            applications::revoke_unauthorized(&tx)?;
        }
        if let Some(lease) = offer.lease {
            if peer != replica.owner {
                return Err(PeerError::Denied);
            }
            // A newer concurrent renewal or revocation takes precedence over this reply.
            if check_lease(policy, local, &lease, unix_ms()).is_ok()
                && current.lease.as_ref().is_none_or(|old| {
                    old.body.placement != lease.body.placement
                        || old.body.expires < lease.body.expires
                })
            {
                tx.execute(
                    "UPDATE replicas SET lease=?2 WHERE id=?1",
                    params![&resource.0[..], protocol::encode(&lease)?],
                )?;
            }
        }
        if local != policy.owner && policy.placement(local).is_none() {
            tx.execute(
                "UPDATE replicas SET lease=NULL WHERE id=?1",
                [&resource.0[..]],
            )?;
            tx.execute(
                "DELETE FROM replica_pending WHERE resource=?1",
                [&resource.0[..]],
            )?;
            tx.execute("DELETE FROM grants WHERE ref=?1", [&current.reference])?;
            applications::revoke_unauthorized(&tx)?;
            tx.commit()?;
            return Ok(Vec::new());
        }
        let current = by_id(&tx, resource)?;
        if (local != policy.owner && current.local_lease(unix_ms()).is_err())
            || (peer != policy.owner && policy.placement(peer).is_none())
        {
            tx.commit()?;
            return Ok(Vec::new());
        }
        // A peer may advance its heads between passes. Keep partial graphs pinned until
        // their revisions are admitted through a later tip. A tip without a block has
        // no downloaded dependencies to retain.
        tx.execute(
            "DELETE FROM replica_pending WHERE resource=?1 AND peer=?2 AND
             NOT EXISTS(SELECT 1 FROM blocks WHERE hash=tip)",
            params![&resource.0[..], &peer.0[..]],
        )?;
        for tip in &offer.heads {
            if !known(&tx, resource, *tip)? {
                tx.execute(
                    "INSERT OR IGNORE INTO replica_pending(resource, peer, tip) VALUES (?1, ?2, ?3)",
                    params![&resource.0[..], &peer.0[..], &tip.0[..]],
                )?;
            }
        }
        tx.commit()?;
        Ok(offer.heads)
    }

    pub(in crate::peer) fn missing_replica_block(
        &self,
        resource: Hash,
        peer: Hash,
        tip: Hash,
    ) -> Result<Option<Hash>> {
        let tx = self.0.unchecked_transaction()?;
        missing_block(&tx, resource, peer, tip)
    }

    // A source can have discarded an older snapshot. A single-writer receiver can
    // still verify the signed chain, provided it obtains the offered head's full state.
    pub(in crate::peer) fn retry_replica_with_proofs(
        &mut self,
        resource: Hash,
        peer: Hash,
        tip: Hash,
    ) -> Result<bool> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let replica = by_id(&tx, resource)?;
        if replica.policy()?.mode != ResourceMode::SingleWriter {
            return Ok(false);
        }
        let changed = tx.execute(
            "UPDATE replica_pending SET proofs_only=1
             WHERE resource=?1 AND peer=?2 AND tip=?3 AND proofs_only=0",
            params![&resource.0[..], &peer.0[..], &tip.0[..]],
        )?;
        tx.commit()?;
        Ok(changed != 0)
    }

    pub(in crate::peer) fn stage_replica_block(
        &mut self,
        resource: Hash,
        peer: Hash,
        tip: Hash,
        hash: Hash,
        bytes: &[u8],
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if !pending(&tx, resource, peer, tip)? {
            if known(&tx, resource, tip)? {
                // Another synchronization pass admitted the tip while this request was in flight.
                return Ok(());
            }
            return Err(PeerError::Denied);
        }
        let replica = by_id(&tx, resource)?;
        if replica.local != replica.owner {
            replica.local_lease(unix_ms())?;
        }
        if peer != replica.owner && replica.policy()?.placement(peer).is_none() {
            return Err(PeerError::Denied);
        }
        match insert(&tx, hash, bytes)? {
            Kind::Revision => {
                Change::decode(bytes)?.verify(replica.policy()?, hash)?;
            }
            _ if hash == tip => return Err(PeerError::Denied),
            _ => {}
        }
        tx.execute(
            "INSERT OR IGNORE INTO replica_private VALUES (?1)",
            [&hash.0[..]],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(in crate::peer) fn finish_replica_tip(
        &mut self,
        resource: Hash,
        peer: Hash,
        tip: Hash,
    ) -> Result<usize> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if !pending(&tx, resource, peer, tip)? {
            return Ok(0);
        }
        if missing_block(&tx, resource, peer, tip)?.is_some() {
            return Err(PeerError::Denied);
        }
        let replica = by_id(&tx, resource)?;
        let policy = replica.policy()?;
        let proofs_only = pending_proofs_only(&tx, resource, peer, tip)?;
        if replica.local != replica.owner {
            replica.local_lease(unix_ms())?;
        }
        if peer != replica.owner && policy.placement(peer).is_none() {
            return Err(PeerError::Denied);
        }
        let mut stack = vec![(tip, None)];
        let mut added = 0;
        let mut reaction = true;
        while let Some((id, inspected)) = stack.pop() {
            if known(&tx, resource, id)? {
                continue;
            }
            if let Some(change) = inspected {
                let retain = !proofs_only || id == tip;
                record_version(&tx, policy, id, &change, retain)?;
                added += 1;
                reaction &= change.body.reaction;
                continue;
            }
            let bytes = get(&tx, id, false)?.ok_or(PeerError::Missing(id))?;
            let change = Change::decode(&bytes)?;
            change.verify(policy, id)?;
            let parents = change.body.parents.clone();
            stack.push((id, Some(change)));
            stack.extend(parents.into_iter().map(|parent| (parent, None)));
        }
        if !policy.retired.is_empty() {
            recompute_validity(&tx, policy)?;
        }
        project(&tx, &replica, heads(&tx, resource)?, true, reaction)?;
        tx.execute(
            "DELETE FROM replica_pending WHERE resource=?1 AND EXISTS(
                 SELECT 1 FROM replica_versions v WHERE v.resource=?1 AND v.id=tip
             )",
            [&resource.0[..]],
        )?;
        if replica.local != replica.owner {
            replica.local_lease(unix_ms())?;
        }
        tx.commit()?;
        Ok(added)
    }
}

fn owner_policy(conn: &Connection, owner: &PeerIdentity, resource: Hash) -> Result<Policy> {
    let replica = by_id(conn, resource)?;
    if replica.local != owner.id() || replica.owner != owner.id() {
        return Err(PeerError::Denied);
    }
    Ok(replica.policy()?.clone())
}

fn save_policy(conn: &Connection, policy: &Policy, key: &PeerIdentity) -> Result<()> {
    let mut next = policy.clone();
    next.generation = next
        .generation
        .checked_add(1)
        .ok_or(PeerError::Limit("policy revisions"))?;
    next.validate()?;
    let signed = Signed::new(POLICY, next, key)?;
    conn.execute(
        "UPDATE replicas SET policy=?2 WHERE id=?1",
        params![&policy.resource.0[..], protocol::encode(&signed)?],
    )?;
    Ok(())
}

fn check_policy_update(old: &Policy, new: &Policy) -> Result<bool> {
    if old.mode != new.mode
        || old.shape != new.shape
        || old.genesis != new.genesis
        || (new.generation == old.generation && old != new)
    {
        return Err(PeerError::Denied);
    }
    if new.generation > old.generation {
        if !new.retired.starts_with(&old.retired)
            || old.placements.iter().any(|placement| {
                !new.placements.contains(placement)
                    && !new.retired.iter().any(|item| &item.placement == placement)
            })
        {
            return Err(PeerError::Denied);
        }
        return Ok(true);
    }
    Ok(false)
}

fn check_lease(policy: &Policy, holder: Hash, lease: &SignedLease, now: u64) -> Result<()> {
    if policy.placement(holder) != Some(&lease.body.placement)
        || !lease.body.covers(policy.resource, now)
        || lease.signer(LEASE)? != policy.owner
    {
        return Err(PeerError::Denied);
    }
    Ok(())
}

fn sync_access(replica: &Replica, holder: Hash, lease: Option<&SignedLease>) -> Result<()> {
    if replica.local != replica.owner {
        replica.local_lease(unix_ms())?;
    }
    if holder != replica.owner {
        check_lease(
            replica.policy()?,
            holder,
            lease.ok_or(PeerError::Denied)?,
            unix_ms(),
        )?;
    }
    Ok(())
}

fn pending(conn: &Connection, resource: Hash, peer: Hash, tip: Hash) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM replica_pending WHERE resource=?1 AND peer=?2 AND tip=?3)",
        params![&resource.0[..], &peer.0[..], &tip.0[..]],
        |row| row.get(0),
    )?)
}

fn known(conn: &Connection, resource: Hash, id: Hash) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM replica_versions WHERE resource=?1 AND id=?2)",
        params![&resource.0[..], &id.0[..]],
        |row| row.get(0),
    )?)
}

fn pending_proofs_only(conn: &Connection, resource: Hash, peer: Hash, tip: Hash) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT proofs_only FROM replica_pending WHERE resource=?1 AND peer=?2 AND tip=?3",
            params![&resource.0[..], &peer.0[..], &tip.0[..]],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

fn missing_block(conn: &Connection, resource: Hash, peer: Hash, tip: Hash) -> Result<Option<Hash>> {
    if pending_proofs_only(conn, resource, peer, tip)? {
        if known(conn, resource, tip)? {
            return Ok(None);
        }
        let Some(bytes) = get(conn, tip, false)? else {
            return Ok(Some(tip));
        };
        let head = Change::decode(&bytes)?;
        let mut parent = head.body.parents.first().copied();
        while let Some(id) = parent {
            if known(conn, resource, id)? {
                break;
            }
            let Some(bytes) = get(conn, id, false)? else {
                return Ok(Some(id));
            };
            parent = Change::decode(&bytes)?.body.parents.first().copied();
        }
        return missing_graph_block(conn, resource, head.body.root);
    }
    missing_graph_block(conn, resource, tip)
}

fn missing_graph_block(conn: &Connection, resource: Hash, tip: Hash) -> Result<Option<Hash>> {
    Ok(conn
        .query_row(
            "WITH RECURSIVE graph(hash) AS (
            VALUES (?1) UNION
            SELECT edges.child FROM graph JOIN edges ON edges.parent=graph.hash
            WHERE NOT EXISTS(SELECT 1 FROM replica_versions WHERE resource=?2 AND id=graph.hash)
         ) SELECT graph.hash FROM graph WHERE NOT EXISTS(SELECT 1 FROM blocks WHERE hash=graph.hash)
         LIMIT 1",
            params![&tip.0[..], &resource.0[..]],
            |row| Ok(Hash(row.get(0)?)),
        )
        .optional()?)
}

fn heads(conn: &Connection, resource: Hash) -> Result<Vec<Hash>> {
    let mut query = conn.prepare_cached(
        "SELECT v.id FROM replica_versions v WHERE v.resource=?1 AND v.valid=1 AND NOT EXISTS(
             SELECT 1 FROM replica_parents p JOIN replica_versions child
               ON child.resource=p.resource AND child.id=p.child
             WHERE p.resource=v.resource AND p.parent=v.id AND child.valid=1
         ) ORDER BY v.id LIMIT ?2",
    )?;
    let result = query
        .query_map(
            params![
                &resource.0[..],
                (crate::peer::replication::MAX_HEADS + 1) as i64
            ],
            |row| Ok(Hash(row.get(0)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    validate_heads(&result)?;
    Ok(result)
}

fn add_version(conn: &Connection, policy: &Policy, id: Hash, change: &Change) -> Result<()> {
    record_version(conn, policy, id, change, true)
}

fn record_version(
    conn: &Connection,
    policy: &Policy,
    id: Hash,
    change: &Change,
    retained: bool,
) -> Result<()> {
    let placement = change.verify(policy, id)?;
    let root = change.body.root;
    if retained {
        validate_state(conn, policy.shape, root)?;
    }
    conn.execute(
        "INSERT INTO replica_versions(resource, id, root, placement, retained) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &policy.resource.0[..],
            &id.0[..],
            &root.0[..],
            placement.map(|id| id.0),
            retained,
        ],
    )?;
    let mut insert_parent =
        conn.prepare_cached("INSERT INTO replica_parents VALUES (?1, ?2, ?3)")?;
    for parent in &change.body.parents {
        insert_parent.execute(params![&policy.resource.0[..], &id.0[..], &parent.0[..]])?;
    }
    Ok(())
}

fn validate_state(conn: &Connection, shape: Shape, root: Hash) -> Result<()> {
    let bytes = get(conn, root, false)?.ok_or(PeerError::Missing(root))?;
    if content::inspect(root, &bytes)?.0 != Kind::Data {
        return Err(PeerError::Denied);
    }
    match shape {
        Shape::Collection => {
            for (key, hash) in decode_manifest(&bytes)? {
                check_entry(&key, &entry_block(conn, hash)?)?;
            }
        }
        Shape::Snapshot => {
            // Change records are history, and must never be followed through state links.
            let nested = conn.query_row(
                "WITH RECURSIVE graph(hash) AS (
                    VALUES (?1) UNION SELECT edges.child FROM graph JOIN edges ON edges.parent=graph.hash
                 ) SELECT EXISTS(SELECT 1 FROM graph JOIN blocks USING(hash) WHERE substr(bytes,1,4)=?2)",
                params![&root.0[..], &crate::peer::replication::MAGIC[..]],
                |row| row.get::<_, bool>(0),
            )?;
            if nested {
                return Err(PeerError::Denied);
            }
        }
    }
    Ok(())
}

fn prune_snapshots(conn: &Connection, resource: Hash, heads: &[Hash]) -> Result<usize> {
    let [head] = heads else {
        return Ok(0);
    };
    let keep = conn.query_row(
        "SELECT retain_snapshots FROM replicas WHERE id=?1",
        [&resource.0[..]],
        |row| row.get::<_, Option<u16>>(0),
    )?;
    let Some(keep) = keep else {
        return Ok(0);
    };
    Ok(conn.execute(
        "WITH RECURSIVE recent(id) AS (
             VALUES (?2)
             UNION ALL SELECT p.parent FROM recent r JOIN replica_parents p
                ON p.resource=?1 AND p.child=r.id
             LIMIT ?3
         ) UPDATE replica_versions SET retained=0 WHERE resource=?1 AND retained=1
            AND id NOT IN (SELECT id FROM recent)",
        params![&resource.0[..], &head.0[..], keep],
    )?)
}

fn recompute_validity(conn: &Connection, policy: &Policy) -> Result<()> {
    let resource = &policy.resource.0[..];
    conn.execute(
        "UPDATE replica_versions SET valid=1 WHERE resource=?1 AND valid=0",
        [resource],
    )?;
    for retirement in &policy.retired {
        // Only exact ancestors of the signed cutoff are grandfathered.
        let cutoff = serde_json::to_string(
            &retirement
                .cutoff
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| PeerError::Value(error.to_string()))?;
        conn.execute(
            "WITH RECURSIVE accepted(id) AS (
                SELECT unhex(value) FROM json_each(?3)
                UNION SELECT p.parent FROM accepted a JOIN replica_parents p
                    ON p.resource=?1 AND p.child=a.id
             ) UPDATE replica_versions SET valid=0 WHERE resource=?1 AND placement=?2
                   AND id NOT IN (SELECT id FROM accepted)",
            params![resource, &retirement.placement.id.0[..], cutoff],
        )?;
    }
    conn.execute(
        "WITH RECURSIVE rejected(id) AS (
            SELECT id FROM replica_versions WHERE resource=?1 AND valid=0
            UNION SELECT p.child FROM rejected r JOIN replica_parents p
               ON p.resource=?1 AND p.parent=r.id
         ) UPDATE replica_versions SET valid=0 WHERE resource=?1 AND valid=1
                AND id IN (SELECT id FROM rejected)",
        [resource],
    )?;
    Ok(())
}

fn root_at(conn: &Connection, resource: Hash, id: Hash) -> Result<Hash> {
    conn.query_row(
        "SELECT root FROM replica_versions WHERE resource=?1 AND id=?2 AND valid=1 AND retained=1",
        params![&resource.0[..], &id.0[..]],
        |row| Ok(Hash(row.get(0)?)),
    )
    .optional()?
    .ok_or(PeerError::Missing(id))
}

fn project(
    conn: &Connection,
    replica: &Replica,
    heads: Vec<Hash>,
    materialize: bool,
    reaction: bool,
) -> Result<()> {
    if heads == replica.heads {
        return Ok(());
    }
    let root = root_at(conn, replica.id, *heads.first().ok_or(PeerError::Denied)?)?;
    let current = revision(conn, &replica.reference)?;
    let number = match current {
        Some(current) => {
            let number = i64::try_from(current.number + 1)
                .map_err(|_| PeerError::Limit("reference revisions"))?;
            conn.execute(
                "UPDATE refs SET hash=?2, revision=?3 WHERE name=?1",
                params![replica.reference, &root.0[..], number],
            )?;
            number as u64
        }
        None => {
            conn.execute(
                "INSERT INTO refs VALUES (?1, 0, ?2)",
                params![replica.reference, &root.0[..]],
            )?;
            if replica.policy()?.shape == Shape::Collection {
                conn.execute("INSERT INTO collections VALUES (?1)", [&replica.reference])?;
            }
            0
        }
    };
    if materialize
        && replica.policy()?.shape == Shape::Collection
        && current.is_none_or(|current| current.hash != root)
    {
        conn.execute("DELETE FROM entries WHERE ref=?1", [&replica.reference])?;
        let manifest = read_manifest(conn, root)?;
        let mut insert = conn.prepare_cached("INSERT INTO entries VALUES (?1, ?2, ?3)")?;
        for (key, hash) in manifest {
            insert.execute(params![
                replica.reference,
                key.as_bytes(),
                entry_block(conn, hash)?
            ])?;
        }
    }
    conn.execute(
        "UPDATE replicas SET heads=?2 WHERE id=?1",
        params![&replica.id.0[..], protocol::encode(&heads)?],
    )?;
    prune_snapshots(conn, replica.id, &heads)?;
    applications::record_change(conn, &replica.reference, number, reaction)?;
    Ok(())
}

fn collection_root(conn: &Connection, reference: &str) -> Result<Hash> {
    let mut query =
        conn.prepare_cached("SELECT key, value FROM entries WHERE ref=?1 ORDER BY key")?;
    let mut rows = query.query([reference])?;
    let mut manifest = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row.get(0)?;
        let key = String::from_utf8(key).map_err(|error| PeerError::Value(error.to_string()))?;
        let value: Vec<u8> = row.get(1)?;
        let bytes = Block::Data(Data::from_bytes(&value)?).to_bytes()?;
        let hash = Hash::digest(&bytes);
        insert(conn, hash, &bytes)?;
        manifest.insert(key, Data::Link(hash));
        if manifest.len() > 4096 {
            return Err(PeerError::Limit("replicated collection keys"));
        }
    }
    let bytes = Block::Data(Data::Record(manifest)).to_bytes()?;
    let root = Hash::digest(&bytes);
    insert(conn, root, &bytes)?;
    Ok(root)
}

fn decode_manifest(bytes: &[u8]) -> Result<BTreeMap<String, Hash>> {
    let Block::Data(Data::Record(entries)) = Block::from_bytes(bytes)? else {
        return Err(PeerError::Denied);
    };
    if entries.len() > 4096 {
        return Err(PeerError::Limit("replicated collection keys"));
    }
    entries
        .into_iter()
        .map(|(key, value)| match value {
            Data::Link(hash) => Ok((key, hash)),
            _ => Err(PeerError::Denied),
        })
        .collect()
}

pub(super) fn read_manifest(conn: &Connection, root: Hash) -> Result<BTreeMap<String, Hash>> {
    let bytes = get(conn, root, false)?.ok_or(PeerError::Missing(root))?;
    content::inspect(root, &bytes)?;
    decode_manifest(&bytes)
}

pub(super) fn entry_block(conn: &Connection, hash: Hash) -> Result<Vec<u8>> {
    let bytes = get(conn, hash, false)?.ok_or(PeerError::Missing(hash))?;
    content::inspect(hash, &bytes)?;
    let Block::Data(value) = Block::from_bytes(&bytes)? else {
        return Err(PeerError::Denied);
    };
    Ok(value.to_bytes()?)
}

pub(super) fn authorize_view(
    conn: &Connection,
    reference: &str,
    holder: Hash,
    program: Option<Hash>,
    access: Access,
) -> Result<()> {
    if let Some(replica) = by_reference(conn, reference)? {
        replica.check_access(holder, program, access)?;
    }
    Ok(())
}

pub(super) fn can_delegate(conn: &Connection, reference: &str) -> Result<()> {
    if by_reference(conn, reference)?.is_some_and(|replica| replica.local != replica.owner) {
        return Err(PeerError::Denied);
    }
    Ok(())
}

pub(super) fn can_replace_locally(conn: &Connection, reference: &str) -> Result<()> {
    if by_reference(conn, reference)?.is_some() {
        return Err(PeerError::Denied);
    }
    Ok(())
}

pub(super) fn view(
    conn: &Connection,
    reference: &str,
    call: Call,
) -> Result<(ResourceView, Option<Hash>)> {
    let mut view = ResourceView {
        consistency: call.consistency,
        resource: None,
        mode: None,
        revision: None,
        heads: Vec::new(),
    };
    let Some(replica) = by_reference(conn, reference)? else {
        if call.consistency != Consistency::Authoritative {
            return Err(PeerError::Denied);
        }
        return Ok((view, None));
    };
    let policy = replica.policy()?;
    let selected = match call.consistency {
        Consistency::Authoritative
            if replica.local == replica.owner
                && policy.mode != ResourceMode::MultiWriter
                && replica.heads.len() == 1 =>
        {
            replica.heads.first().copied()
        }
        Consistency::Authoritative => return Err(PeerError::Denied),
        Consistency::Replica => replica.heads.first().copied(),
        Consistency::Revision(id) if call.update.is_none() => Some(id),
        Consistency::Revision(_) => return Err(PeerError::Denied),
    }
    .ok_or(PeerError::Denied)?;
    if call.update.is_some()
        && (policy.mode == ResourceMode::Immutable
            || (policy.mode == ResourceMode::SingleWriter
                && call.consistency != Consistency::Authoritative))
    {
        return Err(PeerError::Denied);
    }
    let root = root_at(conn, replica.id, selected)?;
    view.resource = Some(replica.id);
    view.mode = Some(policy.mode);
    view.revision = Some(selected);
    view.heads = replica.heads;
    Ok((view, Some(root)))
}

pub(super) fn check_write(view: &ResourceView, update: Option<Update>) -> Result<()> {
    if let Some(update) = update
        && ((view.heads.len() > 1) != update.merge)
    {
        return Err(PeerError::Value(if update.merge {
            "a merge requires multiple current heads".into()
        } else {
            "concurrent resource revisions require an explicit merge".into()
        }));
    }
    Ok(())
}

pub(super) fn commit(
    conn: &Connection,
    reference: &str,
    key: Option<&PeerIdentity>,
    call: Call,
    snapshot_root: Option<Hash>,
) -> Result<bool> {
    let Some(replica) = by_reference(conn, reference)? else {
        return Ok(false);
    };
    let key = key
        .filter(|key| key.id() == replica.local)
        .ok_or(PeerError::Denied)?;
    let policy = replica.policy()?;
    let now = unix_ms();
    let lease = if replica.local == replica.owner {
        None
    } else {
        Some(replica.local_lease(now)?.clone())
    };
    let root = match snapshot_root {
        Some(root) => root,
        None => collection_root(conn, reference)?,
    };
    let bytes = Change::encode(
        RevisionBody {
            resource: replica.id,
            root,
            parents: replica.heads.clone(),
            authored: now,
            program: Some(call.program),
            lease,
            reaction: call.reaction,
            nonce: random_id()?,
        },
        key,
    )?;
    let id = Hash::digest(&bytes);
    insert(conn, id, &bytes)?;
    add_version(conn, policy, id, &Change::decode(&bytes)?)?;
    // The new revision names every current head as a parent and was authorized
    // against that same view inside the write transaction.
    project(conn, &replica, vec![id], false, call.reaction)?;
    if replica.local != replica.owner {
        replica.local_lease(unix_ms())?;
    }
    Ok(true)
}

pub(super) fn prevent_private_publication(conn: &Connection, hash: Hash) -> Result<()> {
    let private = conn.query_row(
        "WITH RECURSIVE ancestors(hash) AS (
            VALUES (?1) UNION SELECT edges.parent FROM edges JOIN ancestors ON edges.child=ancestors.hash
         ) SELECT EXISTS(SELECT 1 FROM ancestors
             WHERE hash IN (SELECT id FROM replica_versions UNION SELECT tip FROM replica_pending))
           OR EXISTS(SELECT 1 FROM replica_private WHERE hash=?1)",
        [&hash.0[..]], |row| row.get::<_, bool>(0),
    )?;
    if private && get(conn, hash, true)?.is_none() {
        return Err(PeerError::Denied);
    }
    Ok(())
}

pub(super) fn subscription_mode(
    conn: &Connection,
    reference: &str,
) -> Result<protocol::EvaluationMode> {
    Ok(match by_reference(conn, reference)? {
        Some(replica)
            if replica.local != replica.owner
                || replica.policy()?.mode == ResourceMode::MultiWriter =>
        {
            protocol::EvaluationMode::ReadReplica
        }
        _ => protocol::EvaluationMode::Read,
    })
}

pub(super) fn validate_release(conn: &Connection, view: &ResourceView) -> Result<()> {
    if let (Some(resource), Some(revision)) = (view.resource, view.revision) {
        let valid = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM replica_versions WHERE resource=?1 AND id=?2 AND valid=1)",
            params![&resource.0[..], &revision.0[..]],
            |row| row.get::<_, bool>(0),
        )?;
        if !valid {
            return Err(PeerError::Missing(revision));
        }
    }
    Ok(())
}

pub(super) fn authorize_executor(
    conn: &Connection,
    reference: &str,
    executor: Option<Hash>,
) -> Result<()> {
    if by_reference(conn, reference)?.is_some_and(|replica| Some(replica.local) != executor) {
        return Err(PeerError::Denied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::peer::{EvaluationMode, JavaScript};

    fn key(dir: &Path, name: &str) -> PeerIdentity {
        let path = dir.join(name);
        PeerIdentity::generate(&path).unwrap();
        PeerIdentity::load(&path).unwrap()
    }

    fn request(
        source: &PeerStore,
        source_key: &PeerIdentity,
        target: &mut PeerStore,
        local: Hash,
        resource: Hash,
    ) -> Vec<Hash> {
        let peer = source_key.id();
        let request = target.replica_request(resource, local, peer, None).unwrap();
        let offer = source.offer_replica(source_key, local, &request).unwrap();
        target
            .accept_replica_offer(local, peer, resource, offer)
            .unwrap()
    }

    fn download(
        source: &PeerStore,
        source_key: &PeerIdentity,
        target: &mut PeerStore,
        local: Hash,
        resource: Hash,
        tip: Hash,
    ) -> Vec<Hash> {
        let peer = source_key.id();
        let mut received = Vec::new();
        while let Some(hash) = target.missing_replica_block(resource, peer, tip).unwrap() {
            let request = target
                .replica_request(resource, local, peer, Some(hash))
                .unwrap();
            let bytes = match source.serve_replica_block(peer, local, &request, hash) {
                Err(PeerError::Missing(missing))
                    if missing == hash
                        && target
                            .retry_replica_with_proofs(resource, peer, tip)
                            .unwrap() =>
                {
                    continue;
                }
                result => result.unwrap(),
            };
            target
                .stage_replica_block(resource, peer, tip, hash, &bytes)
                .unwrap();
            received.push(hash);
        }
        target.finish_replica_tip(resource, peer, tip).unwrap();
        received
    }

    fn pull(
        source: &PeerStore,
        source_key: &PeerIdentity,
        target: &mut PeerStore,
        local: Hash,
        resource: Hash,
    ) -> Vec<Hash> {
        request(source, source_key, target, local, resource)
            .into_iter()
            .flat_map(|tip| download(source, source_key, target, local, resource, tip))
            .collect()
    }

    fn call(author: Hash, grant: Hash, program: Hash, consistency: Consistency) -> Call {
        Call {
            holder: author,
            grant,
            program,
            update: None,
            graph: None,
            reaction: false,
            consistency,
            executor: Some(author),
        }
    }

    fn update(store: &PeerStore, mut call: Call, merge: bool) -> Call {
        let scope = authority(&store.0, call.holder, call.grant).unwrap();
        let id = random_id().unwrap();
        call.update = Some(Update {
            expected: store.reference(&scope.reference).unwrap().unwrap().number,
            operation: id,
            fingerprint: id,
            merge,
        });
        call
    }

    fn snapshot(store: &mut PeerStore, call: Call) -> Snapshot {
        let EvaluationStart::Snapshot(snapshot) = store.begin(call).unwrap() else {
            panic!("expected snapshot")
        };
        snapshot
    }

    fn write(store: &mut PeerStore, author: &PeerIdentity, call: Call, value: i64) -> Hash {
        let call = update(store, call, false);
        let snapshot = snapshot(store, call);
        store
            .commit(
                call,
                &snapshot,
                Some(author),
                &Block::Data(Data::Int(value)).to_bytes().unwrap(),
                Data::Int(value).to_bytes().unwrap(),
            )
            .unwrap()
            .view
            .unwrap()
            .revision
            .unwrap()
    }

    #[test]
    fn immutable_placement_checks_integrity_and_resumes_after_gc_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let replica = key(dir.path(), "replica");
        let mut origin = PeerStore::open(":memory:").unwrap();
        let child = origin
            .put(&Block::Data(Data::Int(4)).to_bytes().unwrap())
            .unwrap();
        let unrelated = origin
            .put(&Block::Data(Data::Int(5)).to_bytes().unwrap())
            .unwrap();
        let root = origin
            .create_ref("source", &Data::Link(child))
            .unwrap()
            .hash;
        let id = origin
            .share_replica(&owner, "source", ResourceMode::Immutable)
            .unwrap();
        let path = dir.path().join("replica.db");
        let mut copy = PeerStore::open(&path).unwrap();
        copy.follow_replica(replica.id(), owner.id(), id, "copy")
            .unwrap();
        let unauthorized = copy
            .replica_request(id, replica.id(), owner.id(), None)
            .unwrap();
        assert!(matches!(
            origin.offer_replica(&owner, replica.id(), &unauthorized),
            Err(PeerError::Denied)
        ));

        origin
            .approve_replica(&owner, id, replica.id(), ReplicaAccess::Store, None)
            .unwrap();
        let [tip] = request(&origin, &owner, &mut copy, replica.id(), id)[..] else {
            panic!("expected immutable head");
        };
        assert_ne!(tip, root);
        assert_ne!(id, tip);
        let get = copy
            .replica_request(id, replica.id(), owner.id(), Some(tip))
            .unwrap();
        assert!(matches!(
            origin.serve_replica_block(owner.id(), replica.id(), &get, unrelated),
            Err(PeerError::Missing(hash)) if hash == unrelated
        ));
        let bytes = origin
            .serve_replica_block(owner.id(), replica.id(), &get, tip)
            .unwrap();
        assert!(
            copy.stage_replica_block(id, owner.id(), tip, tip, &bytes[..bytes.len() - 1])
                .is_err()
        );
        assert!(copy.get(tip).unwrap().is_none());
        copy.stage_replica_block(id, owner.id(), tip, tip, &bytes)
            .unwrap();
        copy.collect().unwrap();
        drop(copy);

        let mut copy = PeerStore::open(path).unwrap();
        let fetched = pull(&origin, &owner, &mut copy, replica.id(), id);
        assert_eq!(fetched, [root, child]);
        assert!(pull(&origin, &owner, &mut copy, replica.id(), id).is_empty());
        assert_eq!(copy.replica_status(id).unwrap().heads, [tip]);
        for hash in [tip, root, child] {
            assert!(copy.get(hash).unwrap().is_some());
            assert!(copy.public(hash).unwrap().is_none());
            assert!(matches!(copy.publish(hash), Err(PeerError::Denied)));
        }
        assert!(matches!(
            copy.issue("copy", replica.id(), Access::Read, None),
            Err(PeerError::Denied)
        ));
        let program = Hash::digest(b"pin");
        let grant = origin
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let write = update(
            &origin,
            call(owner.id(), grant, program, Consistency::Authoritative),
            false,
        );
        assert!(matches!(origin.begin(write), Err(PeerError::Denied)));
    }

    #[test]
    fn partial_sync_survives_source_advancing_and_collection_before_restart() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let replica = key(dir.path(), "replica");
        let mut origin = PeerStore::open(":memory:").unwrap();
        origin.create_ref("source", &Data::Int(0)).unwrap();
        let id = origin
            .share_replica(&owner, "source", ResourceMode::SingleWriter)
            .unwrap();
        origin
            .approve_replica(&owner, id, replica.id(), ReplicaAccess::Store, None)
            .unwrap();
        let program = Hash::digest(b"update");
        let grant = origin
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let writer = call(owner.id(), grant, program, Consistency::Authoritative);
        let first = write(&mut origin, &owner, writer, 1);

        let path = dir.path().join("replica.db");
        let mut copy = PeerStore::open(&path).unwrap();
        copy.follow_replica(replica.id(), owner.id(), id, "copy")
            .unwrap();
        assert_eq!(
            request(&origin, &owner, &mut copy, replica.id(), id),
            [first]
        );
        let get = copy
            .replica_request(id, replica.id(), owner.id(), Some(first))
            .unwrap();
        let bytes = origin
            .serve_replica_block(owner.id(), replica.id(), &get, first)
            .unwrap();
        copy.stage_replica_block(id, owner.id(), first, first, &bytes)
            .unwrap();

        let second = write(&mut origin, &owner, writer, 2);
        assert_eq!(
            request(&origin, &owner, &mut copy, replica.id(), id),
            [second]
        );
        copy.collect().unwrap();
        drop(copy);

        let mut copy = PeerStore::open(path).unwrap();
        assert_eq!(copy.get(first).unwrap(), Some(bytes));
        let fetched = pull(&origin, &owner, &mut copy, replica.id(), id);
        assert!(fetched.contains(&second));
        assert!(!fetched.contains(&first));
        assert_eq!(copy.replica_status(id).unwrap().heads, [second]);
        assert!(!pending(&copy.0, id, owner.id(), first).unwrap());
    }

    #[test]
    fn version_six_history_survives_upgrade_and_compaction_keeps_receipts_and_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let follower = key(dir.path(), "follower");
        let path = dir.path().join("owner.db");
        let mut origin = PeerStore::open(&path).unwrap();
        origin.create_ref("source", &Data::Int(0)).unwrap();
        let resource = origin
            .share_replica(&owner, "source", ResourceMode::SingleWriter)
            .unwrap();
        origin
            .approve_replica(&owner, resource, follower.id(), ReplicaAccess::Read, None)
            .unwrap();
        let genesis = origin.replica_status(resource).unwrap().heads[0];
        let genesis_root = origin.replica_history(resource, None, 128).unwrap()[0].root;
        let program = Hash::digest(b"update");
        let grant = origin
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let writer = call(owner.id(), grant, program, Consistency::Authoritative);
        let first = update(&origin, writer, false);
        let before = snapshot(&mut origin, first);
        let receipt = origin
            .commit(
                first,
                &before,
                Some(&owner),
                &Block::Data(Data::Int(1)).to_bytes().unwrap(),
                Data::Int(1).to_bytes().unwrap(),
            )
            .unwrap();
        let first_id = receipt.view.as_ref().unwrap().revision.unwrap();
        let first_root = root_at(&origin.0, resource, first_id).unwrap();
        origin
            .create_ref("independent", &Data::Link(genesis))
            .unwrap();
        let second = write(&mut origin, &owner, writer, 2);
        drop(origin);

        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "DROP INDEX replica_retained;
                 ALTER TABLE replica_versions DROP COLUMN retained;
                 ALTER TABLE replicas DROP COLUMN retain_snapshots;
                 ALTER TABLE replica_pending DROP COLUMN proofs_only;
                 PRAGMA user_version = 6;",
            )
            .unwrap();
        drop(legacy);
        let mut origin = PeerStore::open(&path).unwrap();
        assert_eq!(origin.replica_status(resource).unwrap().heads, [second]);
        let records = origin.replica_history(resource, None, 128).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|record| record.retained && record.valid));
        assert_eq!(origin.retain_replica_snapshots(resource, 2).unwrap(), 1);
        let third = write(&mut origin, &owner, writer, 3);
        origin.collect().unwrap();
        assert!(origin.get(genesis_root).unwrap().is_some());
        assert!(origin.get(genesis).unwrap().is_some());
        assert!(origin.get(first_root).unwrap().is_none());
        assert!(
            matches!(root_at(&origin.0, resource, first_id), Err(PeerError::Missing(id)) if id == first_id)
        );
        assert!(matches!(
            origin.begin(Call { consistency: Consistency::Revision(genesis), ..writer }),
            Err(PeerError::Missing(id)) if id == genesis
        ));
        assert!(
            matches!(origin.begin(first), Ok(EvaluationStart::Replayed(old)) if old.revision == receipt.revision)
        );
        let history = origin.replica_history(resource, None, 128).unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history.iter().filter(|entry| entry.retained).count(), 2);

        let path = dir.path().join("follower.db");
        let mut copy = PeerStore::open(&path).unwrap();
        copy.follow_replica(follower.id(), owner.id(), resource, "copy")
            .unwrap();
        assert_eq!(
            request(&origin, &owner, &mut copy, follower.id(), resource),
            [third]
        );
        assert!(
            copy.retry_replica_with_proofs(resource, owner.id(), third)
                .unwrap()
        );
        copy.collect().unwrap();
        drop(copy);
        let mut copy = PeerStore::open(path).unwrap();
        assert!(pending_proofs_only(&copy.0, resource, owner.id(), third).unwrap());
        download(&origin, &owner, &mut copy, follower.id(), resource, third);
        assert_eq!(copy.replica_status(resource).unwrap().heads, [third]);
        let history = copy.replica_history(resource, None, 128).unwrap();
        assert_eq!(history.len(), 4);
        assert!(history.iter().all(|entry| entry.valid));
        assert_eq!(history.iter().filter(|entry| entry.retained).count(), 1);
        assert!(pull(&origin, &owner, &mut copy, follower.id(), resource).is_empty());
        let grant = copy
            .issue("copy", follower.id(), Access::Read, Some(program))
            .unwrap();
        let read = call(follower.id(), grant, program, Consistency::Replica);
        assert_eq!(
            Block::from_bytes(&snapshot(&mut copy, read).bytes).unwrap(),
            Block::Data(Data::Int(3))
        );
    }

    #[test]
    fn a_placement_lease_bounds_local_access_and_only_attests_claimed_revision_time() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let writer = key(dir.path(), "writer");
        let mut origin = PeerStore::open(":memory:").unwrap();
        origin.create_ref("source", &Data::Int(0)).unwrap();
        let resource = origin
            .share_replica(&owner, "source", ResourceMode::MultiWriter)
            .unwrap();
        origin
            .approve_replica(&owner, resource, writer.id(), ReplicaAccess::Write, None)
            .unwrap();
        let replica = by_id(&origin.0, resource).unwrap();
        let policy = replica.policy().unwrap();
        let issued = 1000;
        let expires = 2000;
        let lease = Signed::new(
            LEASE,
            Lease {
                resource,
                placement: policy.placement(writer.id()).unwrap().clone(),
                issued,
                expires,
            },
            &owner,
        )
        .unwrap();
        for (clock, accepted) in [
            (issued - 1, false),
            (issued, true),
            (expires - 1, true),
            (expires, false),
        ] {
            assert_eq!(
                check_lease(policy, writer.id(), &lease, clock).is_ok(),
                accepted
            );
        }
        let bytes = Change::encode(
            RevisionBody {
                resource,
                root: Hash::digest(b"state"),
                parents: replica.heads.clone(),
                authored: issued,
                program: None,
                lease: Some(lease),
                reaction: false,
                nonce: Hash::digest(b"revision"),
            },
            &writer,
        )
        .unwrap();
        let change = Change::decode(&bytes).unwrap();
        assert!(unix_ms() > expires);
        // Signing the record after expiration still verifies its claimed date.
        assert_eq!(
            change.verify(policy, Hash::digest(&bytes)).unwrap(),
            Some(policy.placement(writer.id()).unwrap().id)
        );
    }

    #[test]
    fn storage_exhaustion_preserves_the_last_acknowledged_revision() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let path = dir.path().join("store.db");
        let mut store = PeerStore::open(&path).unwrap();
        store.create_ref("source", &Data::Int(0)).unwrap();
        let resource = store
            .share_replica(&owner, "source", ResourceMode::SingleWriter)
            .unwrap();
        let program = Hash::digest(b"update");
        let grant = store
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let writer = call(owner.id(), grant, program, Consistency::Authoritative);
        let acknowledged = write(&mut store, &owner, writer, 1);
        let pending = update(&store, writer, false);
        let before = snapshot(&mut store, pending);
        let pages = store
            .0
            .query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))
            .unwrap();
        store
            .0
            .pragma_update(None, "max_page_count", pages + 1)
            .unwrap();
        let payload = Block::Data(Data::Text("x".repeat(120_000)))
            .to_bytes()
            .unwrap();
        let Err(failure) = store.commit(pending, &before, Some(&owner), &payload, Vec::new())
        else {
            panic!("update succeeded at the database page limit");
        };
        assert!(
            matches!(protocol::Failure::from(failure), protocol::Failure::Invalid(message) if message.contains("full"))
        );
        drop(store);
        let mut store = PeerStore::open(path).unwrap();
        assert_eq!(
            store.replica_status(resource).unwrap().heads,
            [acknowledged]
        );
        assert_eq!(store.replica_history(resource, None, 128).unwrap().len(), 2);
        assert!(store.get(Hash::digest(&payload)).unwrap().is_none());
        assert!(matches!(
            store.begin(pending),
            Ok(EvaluationStart::Snapshot(_))
        ));
        assert_eq!(
            store
                .commit(pending, &before, Some(&owner), &payload, Vec::new())
                .unwrap()
                .revision,
            2
        );
    }

    #[test]
    fn single_writer_retains_transactions_and_renews_expired_replicas() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let replica = key(dir.path(), "replica");
        let mut origin = PeerStore::open(":memory:").unwrap();
        origin.create_ref("source", &Data::Int(1)).unwrap();
        let id = origin
            .share_replica(&owner, "source", ResourceMode::SingleWriter)
            .unwrap();
        let program = Hash::digest(b"pin");
        assert!(
            origin
                .approve_replica(&owner, id, replica.id(), ReplicaAccess::Write, None)
                .is_err()
        );
        let placement = origin
            .approve_replica(&owner, id, replica.id(), ReplicaAccess::Read, Some(program))
            .unwrap();
        let mut copy = PeerStore::open(":memory:").unwrap();
        copy.follow_replica(replica.id(), owner.id(), id, "copy")
            .unwrap();
        pull(&origin, &owner, &mut copy, replica.id(), id);
        let genesis = copy.replica_status(id).unwrap().heads[0];
        assert!(
            copy.issue("copy", replica.id(), Access::Read, None)
                .is_err()
        );
        assert!(
            copy.issue("copy", owner.id(), Access::Read, Some(program))
                .is_err()
        );
        assert!(
            copy.issue("copy", replica.id(), Access::Write, Some(program))
                .is_err()
        );
        let grant = copy
            .issue("copy", replica.id(), Access::Read, Some(program))
            .unwrap();
        let read = call(replica.id(), grant, program, Consistency::Replica);
        let mut wrong_consistency = read;
        wrong_consistency.consistency = Consistency::Authoritative;
        assert!(matches!(
            copy.begin(wrong_consistency),
            Err(PeerError::Denied)
        ));
        assert!(matches!(
            copy.begin(Call {
                executor: Some(owner.id()),
                ..read
            }),
            Err(PeerError::Denied)
        ));

        let writer = origin
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let writer_call = call(owner.id(), writer, program, Consistency::Authoritative);
        let old_call = update(&origin, writer_call, false);
        let old_snapshot = snapshot(&mut origin, old_call);
        let head = write(&mut origin, &owner, writer_call, 2);
        assert!(matches!(
            origin.commit(old_call, &old_snapshot, Some(&owner), &[], Vec::new()),
            Err(PeerError::Conflict(1))
        ));
        assert_eq!(snapshot(&mut copy, read).view.revision, Some(genesis));
        assert_eq!(snapshot(&mut origin, writer_call).view.revision, Some(head));

        let replica_policy = by_id(&copy.0, id).unwrap();
        let placement_data = replica_policy
            .policy()
            .unwrap()
            .placement(replica.id())
            .unwrap()
            .clone();
        assert_eq!(placement_data.id, placement);
        let now = unix_ms();
        let expired = Signed::new(
            LEASE,
            Lease {
                resource: id,
                placement: placement_data,
                issued: now - LEASE_MS - 1,
                expires: now - 1,
            },
            &owner,
        )
        .unwrap();
        copy.0
            .execute(
                "UPDATE replicas SET lease=?1",
                [protocol::encode(&expired).unwrap()],
            )
            .unwrap();
        assert!(matches!(copy.begin(read), Err(PeerError::Denied)));
        assert_eq!(pull(&origin, &owner, &mut copy, replica.id(), id).len(), 2);
        assert_eq!(snapshot(&mut copy, read).view.revision, Some(head));
        let historic = snapshot(
            &mut copy,
            Call {
                consistency: Consistency::Revision(genesis),
                ..read
            },
        );
        assert_eq!(
            Block::from_bytes(&historic.bytes).unwrap(),
            Block::Data(Data::Int(1))
        );
    }

    #[test]
    fn revocation_excludes_unaccepted_changes_and_descendants_even_if_already_observed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let writer = key(dir.path(), "writer");
        let auditor = key(dir.path(), "auditor");
        let mut original = PeerStore::open(":memory:").unwrap();
        original.create_ref("source", &Data::Int(0)).unwrap();
        let id = original
            .share_replica(&owner, "source", ResourceMode::MultiWriter)
            .unwrap();
        let program = Hash::digest(b"notes");
        for device in [&writer, &auditor] {
            original
                .approve_replica(&owner, id, device.id(), ReplicaAccess::Write, Some(program))
                .unwrap();
        }
        let mut author = PeerStore::open(":memory:").unwrap();
        author
            .follow_replica(writer.id(), owner.id(), id, "notes")
            .unwrap();
        pull(&original, &owner, &mut author, writer.id(), id);
        let mut observer = PeerStore::open(":memory:").unwrap();
        observer
            .follow_replica(auditor.id(), owner.id(), id, "notes")
            .unwrap();
        pull(&original, &owner, &mut observer, auditor.id(), id);
        let grant = author
            .issue("notes", writer.id(), Access::Write, Some(program))
            .unwrap();
        let writing = call(writer.id(), grant, program, Consistency::Replica);
        let keep = write(&mut author, &writer, writing, 1);
        pull(&author, &writer, &mut original, owner.id(), id);

        let reject = write(&mut author, &writer, writing, 2);
        pull(&author, &writer, &mut observer, auditor.id(), id);
        let observer_grant = observer
            .issue("notes", auditor.id(), Access::Write, Some(program))
            .unwrap();
        let reading = call(auditor.id(), observer_grant, program, Consistency::Replica);
        let descendant = write(&mut observer, &auditor, reading, 3);
        assert_eq!(observer.replica_status(id).unwrap().heads, [descendant]);

        original.revoke_replica(&owner, id, writer.id()).unwrap();
        pull(&original, &owner, &mut observer, auditor.id(), id);
        assert_eq!(observer.replica_status(id).unwrap().heads, [keep]);
        let history = observer.replica_history(id, None, 32).unwrap();
        assert!(history.iter().any(|row| row.id == keep && row.valid));
        assert!(history.iter().any(|row| row.id == reject && !row.valid));
        assert!(history.iter().any(|row| row.id == descendant && !row.valid));
        assert!(matches!(
            observer.begin(Call {
                consistency: Consistency::Revision(reject),
                ..reading
            }),
            Err(PeerError::Missing(_))
        ));

        assert!(pull(&original, &owner, &mut author, writer.id(), id).is_empty());
        assert!(author.replica_status(id).unwrap().revoked);
        assert!(matches!(author.begin(writing), Err(PeerError::Denied)));
        assert!(author.get(reject).unwrap().is_some());
    }

    #[test]
    fn synchronized_changes_schedule_replica_subscriptions_and_revocation_cancels_them() {
        let dir = tempfile::tempdir().unwrap();
        let owner = key(dir.path(), "owner");
        let replica = key(dir.path(), "replica");
        let mut source = PeerStore::open(":memory:").unwrap();
        source.create_collection("source", []).unwrap();
        let id = source
            .share_replica(&owner, "source", ResourceMode::SingleWriter)
            .unwrap();
        let code = JavaScript {
            source: "export default () => null".into(),
            imports: Default::default(),
        }
        .to_bytes()
        .unwrap();
        let mut copy = PeerStore::open(":memory:").unwrap();
        let program = copy.put(&code).unwrap();
        source
            .approve_replica(&owner, id, replica.id(), ReplicaAccess::Read, Some(program))
            .unwrap();
        copy.follow_replica(replica.id(), owner.id(), id, "copy")
            .unwrap();
        pull(&source, &owner, &mut copy, replica.id(), id);
        let watch = copy
            .issue("copy", replica.id(), Access::Read, Some(program))
            .unwrap();
        copy.install_application(
            replica.id(),
            ApplicationSpec {
                name: "watcher".into(),
                subscriptions: BTreeMap::from([(
                    "changes".into(),
                    SubscriptionSpec {
                        program,
                        watch_grant: watch,
                        entry_grant: None,
                        budget: GraphBudget {
                            timeout_ms: 1000,
                            calls: 0,
                            depth: 0,
                        },
                        capabilities: BTreeMap::new(),
                        expires_at_ms: unix_ms() + 60_000,
                    },
                )]),
            },
        )
        .unwrap();

        let writer = source
            .issue("source", owner.id(), Access::Write, Some(program))
            .unwrap();
        let call = update(
            &source,
            call(owner.id(), writer, program, Consistency::Authoritative),
            false,
        );
        let ScopedStart::Collection(state) = source.scoped(call, Duration::from_secs(1)).unwrap()
        else {
            panic!("expected writable collection");
        };
        state
            .effect(Effect::Put(
                "test".into(),
                Data::Int(12).to_bytes().unwrap(),
            ))
            .unwrap();
        state
            .finish(Data::Nil.to_bytes().unwrap(), || Ok(()), None, Some(&owner))
            .unwrap();
        pull(&source, &owner, &mut copy, replica.id(), id);
        copy.schedule_subscriptions(replica.id()).unwrap();
        let job = copy.claim_job(replica.id()).unwrap().unwrap();
        assert_eq!(job.graph.mode, EvaluationMode::ReadReplica);
        assert!(copy.check_job(job.key).is_ok());

        source.revoke_replica(&owner, id, replica.id()).unwrap();
        pull(&source, &owner, &mut copy, replica.id(), id);
        assert!(copy.check_job(job.key).is_err());
        assert_eq!(
            copy.application_status("watcher").unwrap().subscriptions["changes"].state,
            SubscriptionState::Revoked
        );
    }
}
