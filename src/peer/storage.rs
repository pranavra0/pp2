use std::{collections::BTreeMap, path::Path, time::Duration};

use rusqlite::{
    Connection, OptionalExtension, Transaction, TransactionBehavior::Immediate, params,
};
use serde::{Deserialize, Serialize};

use crate::{Block, Data, Hash};

use super::{
    Consistency, HostResource, PeerError, PeerIdentity, ResourceView, Result,
    content::{self, Kind},
    effects::{Effect, GraphBudget, GraphMetrics, MAX_EFFECT_BYTES, Scan},
    protocol::{self, Forward, JobState},
    unix_ms,
};

mod applications;
mod jobs;
mod native;
mod replicas;
pub use applications::{
    ApplicationSpec, ApplicationState, ApplicationStatus, DeliveryOutcome, DeliveryStatus,
    SubscriptionSpec, SubscriptionState, SubscriptionStatus,
};
pub(super) use jobs::{JobKey, JobOutcome, QueuedJob};

const MAX_DELEGATION_DEPTH: u8 = 8;
const MAX_GRANTS_PER_REF: u32 = 1024;
const MAX_CACHE_BYTES_PER_HOLDER: i64 = 16 * 1024 * 1024;
const APPLICATION_ID: i64 = 0x70703231;
/// A successful update remains replayable for this many revisions, while its grant is live.
pub const RECEIPT_WINDOW: u64 = 1024;
const SCHEMA: &str = "
CREATE TABLE blocks (hash BLOB PRIMARY KEY, bytes BLOB NOT NULL,
                     published INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TABLE edges (parent BLOB REFERENCES blocks(hash) ON DELETE CASCADE,
                    child BLOB, PRIMARY KEY(parent, child)) WITHOUT ROWID;
CREATE TABLE code_cache (holder BLOB, hash BLOB REFERENCES blocks(hash) ON DELETE CASCADE,
                         PRIMARY KEY(holder, hash)) WITHOUT ROWID;
CREATE INDEX cached_hash ON code_cache(hash);
CREATE TABLE refs (name TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision >= 0),
                   hash BLOB NOT NULL REFERENCES blocks(hash)) WITHOUT ROWID;
CREATE TABLE grants (id BLOB PRIMARY KEY, holder BLOB NOT NULL, ref TEXT NOT NULL REFERENCES refs(name),
                     access INTEGER NOT NULL, program BLOB, depth INTEGER NOT NULL,
                     parent BLOB REFERENCES grants(id) ON DELETE CASCADE) WITHOUT ROWID;
CREATE INDEX grants_parent ON grants(parent);
CREATE INDEX grants_ref ON grants(ref);
CREATE TABLE receipts (grant_id BLOB REFERENCES grants(id) ON DELETE CASCADE, operation BLOB,
                       ref TEXT NOT NULL, request BLOB NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 0),
                       value BLOB NOT NULL, PRIMARY KEY(grant_id, operation)) WITHOUT ROWID;
CREATE INDEX receipts_ref_revision ON receipts(ref, revision);
PRAGMA user_version = 1;
PRAGMA application_id = 0x70703231;
";

const COLLECTIONS: &str = "
CREATE TABLE collections (ref TEXT PRIMARY KEY REFERENCES refs(name)) WITHOUT ROWID;
CREATE TABLE entries (ref TEXT REFERENCES collections(ref), key BLOB,
                      value BLOB NOT NULL, PRIMARY KEY(ref, key)) WITHOUT ROWID;
PRAGMA user_version = 2;
";

const AUTONOMOUS: &str = "
CREATE TABLE graph_grants (
    id BLOB PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE,
    expires INTEGER NOT NULL,
    timeout INTEGER NOT NULL,
    calls INTEGER NOT NULL,
    depth INTEGER NOT NULL,
    presenter BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX graph_grant_expiry ON graph_grants(expires);
CREATE TABLE graph_forward_replays (
    request BLOB PRIMARY KEY,
    grant_id BLOB REFERENCES grants(id) ON DELETE SET NULL,
    expires INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX graph_forward_expiry ON graph_forward_replays(expires);
CREATE TABLE jobs (
    holder BLOB, id BLOB, request BLOB NOT NULL, program BLOB NOT NULL, input BLOB NOT NULL, expires INTEGER NOT NULL,
    ready INTEGER NOT NULL, state INTEGER NOT NULL, spec BLOB, result BLOB,
    PRIMARY KEY(holder, id)
) WITHOUT ROWID;
CREATE INDEX jobs_pending ON jobs(ready, holder, id) WHERE state=0;
CREATE INDEX jobs_active ON jobs(expires) WHERE state<2;
CREATE TABLE job_blocks (
    holder BLOB, id BLOB, hash BLOB REFERENCES blocks(hash),
    PRIMARY KEY(holder, id, hash),
    FOREIGN KEY(holder, id) REFERENCES jobs(holder, id)
) WITHOUT ROWID;
CREATE INDEX job_blocks_hash ON job_blocks(hash);
CREATE TABLE job_effects (
    holder BLOB, id BLOB, ordinal INTEGER, request BLOB NOT NULL, expires INTEGER NOT NULL,
    child BLOB, result BLOB, PRIMARY KEY(holder, id, ordinal),
    FOREIGN KEY(holder, id) REFERENCES jobs(holder, id)
) WITHOUT ROWID;
PRAGMA user_version = 3;
";

/// Read permits evaluation against a reference. Write also permits atomic updates.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Revision {
    pub number: u64,
    pub hash: Hash,
}

pub(super) struct Snapshot {
    pub(super) reference: String,
    pub(super) revision: Revision,
    pub(super) hash: Hash,
    pub(super) bytes: Vec<u8>,
    pub(super) view: ResourceView,
}

pub(super) struct Authority {
    reference: String,
    access: Access,
    program: Option<Hash>,
    depth: u8,
    graph: Option<GraphAccess>,
    reaction_writer: bool,
}

#[derive(Clone, Copy)]
pub(super) struct GraphAccess {
    pub(super) budget: GraphBudget,
    pub(super) expires_at_ms: u64,
    pub(super) delegated_by: Option<Hash>,
}

#[derive(Clone, Copy)]
pub(super) struct Call {
    pub(super) holder: Hash,
    pub(super) grant: Hash,
    pub(super) program: Hash,
    pub(super) update: Option<Update>,
    pub(super) graph: Option<GraphAccess>,
    pub(super) reaction: bool,
    pub(super) consistency: Consistency,
    pub(super) executor: Option<Hash>,
}

#[derive(Clone, Copy)]
pub(super) struct Update {
    pub(super) expected: u64,
    pub(super) operation: Hash,
    pub(super) fingerprint: Hash,
    pub(super) merge: bool,
}

#[derive(Clone)]
pub(super) struct Receipt {
    pub(super) revision: u64,
    pub(super) value: Vec<u8>,
    pub(super) view: Option<ResourceView>,
}

pub(super) enum EvaluationStart {
    Snapshot(Snapshot),
    Replayed(Receipt),
}

/// Local administrator and cache interface for a peer's SQLite file.
/// A database belongs to one machine. Concurrent local handles coordinate through SQLite.
pub struct PeerStore(Connection);

impl PeerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_timeout(path.as_ref(), Duration::from_millis(1500))
    }

    pub(super) fn open_with_timeout(path: &Path, busy: Duration) -> Result<Self> {
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::{fs::OpenOptions, io::ErrorKind, os::unix::fs::OpenOptionsExt};
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(busy)?;
        let version = database_version(&conn)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Bound the main database. Short transactions keep WAL readers from pinning old pages.
        conn.pragma_update(None, "max_page_count", 65_536)?;
        if version < 6 {
            let tx = conn.transaction_with_behavior(Immediate)?;
            let version = database_version(&tx)?;
            if version == 0 {
                tx.execute_batch(SCHEMA)?;
            }
            if version < 2 {
                tx.execute_batch(COLLECTIONS)?;
            }
            if version < 3 {
                tx.execute_batch(AUTONOMOUS)?;
            }
            if version < 4 {
                tx.execute_batch(applications::SCHEMA)?;
            }
            if version < 5 {
                tx.execute_batch(native::SCHEMA)?;
            }
            if version < 6 {
                tx.execute_batch(replicas::SCHEMA)?;
            }
            tx.commit()?;
        }
        Ok(Self(conn))
    }

    /// Stores a verified immutable block and returns its address.
    pub fn put(&mut self, bytes: &[u8]) -> Result<Hash> {
        let hash = Hash::digest(bytes);
        self.import(hash, bytes)?;
        Ok(hash)
    }

    pub fn import(&mut self, hash: Hash, bytes: &[u8]) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        insert(&tx, hash, bytes)?;
        tx.commit()?;
        Ok(())
    }

    pub fn get(&self, hash: Hash) -> Result<Option<Vec<u8>>> {
        let bytes = get(&self.0, hash, false)?;
        if let Some(bytes) = &bytes {
            content::inspect(hash, bytes)?;
        }
        Ok(bytes)
    }

    pub(super) fn public(&self, hash: Hash) -> Result<Option<Vec<u8>>> {
        let bytes = get(&self.0, hash, true)?;
        if let Some(bytes) = &bytes {
            content::inspect(hash, bytes)?;
        }
        Ok(bytes)
    }

    pub(super) fn executable(&self, holder: Hash, hash: Hash) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .query_row(
                "SELECT bytes FROM blocks WHERE hash=?1 AND (published=1 OR
                EXISTS (SELECT 1 FROM code_cache WHERE holder=?2 AND hash=?1))",
                params![&hash.0[..], &holder.0[..]],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(super) fn cache_code<'a>(
        &mut self,
        call: Call,
        blocks: impl IntoIterator<Item = &'a (Hash, Vec<u8>)>,
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        authorize(&tx, call)?;
        let mut used: i64 = tx.query_row(
            "SELECT coalesce(sum(length(bytes)), 0) FROM code_cache JOIN blocks USING(hash) WHERE holder=?1",
            [&call.holder.0[..]], |row| row.get(0),
        )?;
        for (hash, bytes) in blocks {
            let size = bytes.len() as i64;
            if used + size > MAX_CACHE_BYTES_PER_HOLDER {
                continue;
            }
            if !matches!(insert(&tx, *hash, bytes)?, Kind::JavaScript | Kind::Aeb) {
                return Err(PeerError::Value("expected program".into()));
            }
            let inserted = tx.execute(
                "INSERT INTO code_cache VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![&call.holder.0[..], &hash.0[..]],
            )?;
            if inserted != 0 {
                used += size;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Makes one block available for fetch by authenticated peers and retains its graph.
    pub fn publish(&mut self, hash: Hash) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        require_graph(&tx, hash)?;
        if content::inspect(
            hash,
            &get(&tx, hash, false)?.ok_or(PeerError::Missing(hash))?,
        )?
        .0 == Kind::Revision
        {
            return Err(PeerError::Denied);
        }
        replicas::prevent_private_publication(&tx, hash)?;
        tx.execute("UPDATE blocks SET published=1 WHERE hash=?1", [&hash.0[..]])?;
        tx.commit()?;
        Ok(())
    }

    pub fn unpublish(&mut self, hash: Hash) -> Result<bool> {
        Ok(self.0.execute(
            "UPDATE blocks SET published=0 WHERE hash=?1 AND published=1",
            [&hash.0[..]],
        )? != 0)
    }

    /// Creates a reference at revision zero. The initial state must be a complete data block.
    pub fn create_ref(&mut self, name: &str, value: &Data) -> Result<Revision> {
        check_name(name)?;
        let bytes = Block::Data(value.clone()).to_bytes()?;
        let hash = Hash::digest(&bytes);
        let tx = self.0.transaction_with_behavior(Immediate)?;
        insert(&tx, hash, &bytes)?;
        require_graph(&tx, hash)?;
        replicas::can_replace_locally(&tx, name)?;
        let added = tx.execute(
            "INSERT INTO refs VALUES (?1, 0, ?2) ON CONFLICT(name) DO NOTHING",
            params![name, &hash.0[..]],
        )?;
        if added == 0 {
            return Err(PeerError::ReferenceExists(name.to_owned()));
        }
        applications::record_change(&tx, name, 0, false)?;
        tx.commit()?;
        Ok(Revision { number: 0, hash })
    }

    pub fn reference(&self, name: &str) -> Result<Option<Revision>> {
        revision(&self.0, name)
    }

    /// Reads a value and its revision from the same local database snapshot.
    pub fn read_ref(&mut self, name: &str) -> Result<Option<(Revision, Data)>> {
        let tx = self.0.transaction()?;
        let Some(revision) = revision(&tx, name)? else {
            return Ok(None);
        };
        require_kind(&tx, name, false)?;
        let bytes = get(&tx, revision.hash, false)?.ok_or(PeerError::Missing(revision.hash))?;
        if content::inspect(revision.hash, &bytes)?.0 != Kind::Data {
            return Err(PeerError::Value("reference does not contain data".into()));
        }
        let Block::Data(value) = Block::from_bytes(&bytes)? else {
            unreachable!("validated kind");
        };
        tx.commit()?;
        Ok(Some((revision, value)))
    }

    /// Host-side compare-and-swap over a locally administered reference.
    pub fn replace_ref(&mut self, name: &str, expected: u64, next: Data) -> Result<Revision> {
        let bytes = Block::Data(next).to_bytes()?;
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let current =
            revision(&tx, name)?.ok_or_else(|| PeerError::NoReference(name.to_owned()))?;
        require_kind(&tx, name, false)?;
        replicas::can_replace_locally(&tx, name)?;
        if current.number != expected {
            return Err(PeerError::Conflict(current.number));
        }
        let next = replace(&tx, name, current, &bytes)?;
        tx.commit()?;
        Ok(next)
    }

    /// Creates a grant bound to an authenticated holder and optionally one program hash.
    pub fn issue(
        &mut self,
        reference: &str,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
    ) -> Result<Hash> {
        self.issue_grant(reference, holder, access, program, false)
    }

    /// Grants a pinned program the ability to make updates from durable reactions.
    pub fn issue_reaction_writer(
        &mut self,
        reference: &str,
        holder: Hash,
        program: Hash,
    ) -> Result<Hash> {
        self.issue_grant(reference, holder, Access::Write, Some(program), true)
    }

    fn issue_grant(
        &mut self,
        reference: &str,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
        reaction_writer: bool,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if reaction_writer {
            require_kind(&tx, reference, true)?;
        }
        replicas::authorize_view(&tx, reference, holder, program, access)?;
        prune_graph_grants(&tx, unix_ms())?;
        let id = insert_grant(
            &tx,
            holder,
            &Authority {
                reference: reference.into(),
                access,
                program,
                depth: 0,
                graph: None,
                reaction_writer,
            },
            None,
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Revokes a grant and all its descendants in one transaction.
    pub fn revoke(&mut self, grant: Hash) -> Result<bool> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let revoked = tx.execute("DELETE FROM grants WHERE id=?1", [&grant.0[..]])? != 0;
        if revoked {
            applications::revoke_unauthorized(&tx)?;
        }
        tx.commit()?;
        Ok(revoked)
    }

    pub(super) fn delegate(
        &mut self,
        caller: Hash,
        grant: Hash,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let mut scope = authority(&tx, caller, grant)?;
        replicas::can_delegate(&tx, &scope.reference)?;
        if access > scope.access || scope.depth >= MAX_DELEGATION_DEPTH || scope.graph.is_some() {
            return Err(PeerError::Denied);
        }
        if let (Some(parent), Some(child)) = (scope.program, program)
            && parent != child
        {
            return Err(PeerError::Denied);
        }
        scope.program = scope.program.or(program);
        scope.access = access;
        scope.depth += 1;
        prune_graph_grants(&tx, unix_ms())?;
        let id = insert_grant(&tx, holder, &scope, Some(grant))?;
        tx.commit()?;
        Ok(id)
    }

    pub(super) fn forward(&mut self, caller: Hash, forwarded: Forward) -> Result<Hash> {
        let now = unix_ms();
        forwarded.limit.validate()?;
        if forwarded.expires_at_ms <= now
            || forwarded.expires_at_ms - now > super::effects::MAX_JOB_LIFETIME_MS
        {
            return Err(PeerError::Timeout);
        }
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let mut scope = authority(&tx, caller, forwarded.grant)?;
        replicas::can_delegate(&tx, &scope.reference)?;
        require_kind(&tx, &scope.reference, true)?;
        if forwarded.access > scope.access
            || scope
                .program
                .is_some_and(|program| program != forwarded.program)
            || scope.depth >= MAX_DELEGATION_DEPTH
            || forwarded.delegated_by != scope.graph.and_then(|parent| parent.delegated_by)
            || scope.graph.is_some_and(|parent| {
                !forwarded.limit.fits(parent.budget)
                    || forwarded.expires_at_ms > parent.expires_at_ms
            })
        {
            return Err(PeerError::Denied);
        }
        let request = Hash::digest(&protocol::encode(&forwarded)?);
        if let Some(id) = tx
            .query_row(
                "SELECT grant_id FROM graph_forward_replays WHERE request=?1",
                [&request.0[..]],
                |row| Ok(row.get::<_, Option<[u8; 32]>>(0)?.map(Hash)),
            )
            .optional()?
        {
            return id.ok_or(PeerError::Denied);
        }
        let now = unix_ms();
        if forwarded.expires_at_ms <= now {
            return Err(PeerError::Timeout);
        }
        prune_graph_grants(&tx, now)?;
        scope.program = Some(forwarded.program);
        scope.access = forwarded.access;
        scope.depth += 1;
        let id = insert_grant(&tx, forwarded.holder, &scope, Some(forwarded.grant))?;
        tx.execute(
            "INSERT INTO graph_grants VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &id.0[..],
                forwarded.expires_at_ms as i64,
                forwarded.limit.timeout_ms,
                forwarded.limit.calls,
                forwarded.limit.depth,
                &caller.0[..],
            ],
        )?;
        tx.execute(
            "INSERT INTO graph_forward_replays VALUES (?1, ?2, ?3)",
            params![&request.0[..], &id.0[..], forwarded.expires_at_ms as i64],
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub(super) fn begin(&mut self, call: Call) -> Result<EvaluationStart> {
        let tx = self.0.transaction()?;
        let scope = authorize(&tx, call)?;
        require_kind(&tx, &scope.reference, false)?;
        let (view, root) = replicas::view(&tx, &scope.reference, call)?;
        if let Some(update) = call.update
            && let Some(receipt) = replay(&tx, call.grant, update)?
        {
            return Ok(EvaluationStart::Replayed(receipt));
        }
        let revision = revision(&tx, &scope.reference)?.ok_or(PeerError::Denied)?;
        if let Some(update) = call.update
            && revision.number != update.expected
        {
            return Err(PeerError::Conflict(revision.number));
        }
        replicas::check_write(&view, call.update)?;
        let hash = root.unwrap_or(revision.hash);
        let bytes = get(&tx, hash, false)?.ok_or(PeerError::Missing(hash))?;
        let snapshot = Snapshot {
            reference: scope.reference,
            revision,
            hash,
            bytes,
            view,
        };
        tx.commit()?;
        Ok(EvaluationStart::Snapshot(snapshot))
    }

    pub(super) fn confirm_access(&self, call: Call) -> Result<()> {
        authorize(&self.0, call)?;
        Ok(())
    }

    pub(super) fn confirm(&self, call: Call, view: &ResourceView) -> Result<()> {
        let tx = self.0.unchecked_transaction()?;
        authorize(&tx, call)?;
        replicas::validate_release(&tx, view)?;
        Ok(())
    }

    pub(super) fn commit(
        &mut self,
        call: Call,
        snapshot: &Snapshot,
        signer: Option<&PeerIdentity>,
        next: &[u8],
        value: Vec<u8>,
    ) -> Result<Receipt> {
        let update = call.update.ok_or(PeerError::Denied)?;
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let scope = authorize(&tx, call)?;
        if scope.reference != snapshot.reference {
            return Err(PeerError::Denied);
        }
        if let Some(receipt) = replay(&tx, call.grant, update)? {
            return Ok(receipt);
        }
        let current = revision(&tx, &scope.reference)?.ok_or(PeerError::Denied)?;
        if current != snapshot.revision {
            return Err(PeerError::Conflict(current.number));
        }
        let (view, _) = replicas::view(&tx, &scope.reference, call)?;
        replicas::check_write(&view, call.update)?;
        let revision = if view.resource.is_some() {
            let hash = Hash::digest(next);
            if insert(&tx, hash, next)? != Kind::Data {
                return Err(PeerError::Denied);
            }
            require_graph(&tx, hash)?;
            replicas::commit(&tx, &scope.reference, signer, call, Some(hash))?;
            Revision {
                hash,
                number: current.number + 1,
            }
        } else {
            replace(&tx, &scope.reference, current, next)?
        };
        let receipt = Receipt {
            revision: revision.number,
            value,
            view: if view.resource.is_some() {
                Some(replicas::view(&tx, &scope.reference, call)?.0)
            } else {
                None
            },
        };
        save_receipt(&tx, call.grant, &scope.reference, update, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Creates an indexed reference at revision zero and imports its initial entries atomically.
    pub fn create_collection(
        &mut self,
        name: &str,
        entries: impl IntoIterator<Item = Result<(String, Data)>>,
    ) -> Result<Revision> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let revision = create_collection(&tx, name, entries)?;
        tx.commit()?;
        Ok(revision)
    }

    /// Creates an indexed reference with a host resource. The association is immutable.
    pub fn create_host_resource(&mut self, name: &str, resource: HostResource) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        register_resource(&tx, name, resource, false)?;
        tx.commit()?;
        Ok(())
    }

    /// Attaches or reuses an identical resource and grants access to a pinned program.
    pub fn share_host_resource(
        &mut self,
        name: &str,
        resource: HostResource,
        holder: Hash,
        program: Hash,
        access: Access,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        register_resource(&tx, name, resource, true)?;
        prune_graph_grants(&tx, unix_ms())?;
        let id = insert_grant(
            &tx,
            holder,
            &Authority {
                reference: name.into(),
                access,
                program: Some(program),
                depth: 0,
                graph: None,
                reaction_writer: false,
            },
            None,
        )?;
        tx.commit()?;
        Ok(id)
    }

    pub(super) fn probe_collection(&mut self, call: Call) -> Result<Option<Receipt>> {
        let tx = self.0.transaction()?;
        let scope = authorize(&tx, call)?;
        require_kind(&tx, &scope.reference, true)?;
        let (view, _) = replicas::view(&tx, &scope.reference, call)?;
        if let Some(update) = call.update {
            if let Some(receipt) = replay(&tx, call.grant, update)? {
                return Ok(Some(receipt));
            }
            let current = revision(&tx, &scope.reference)?.ok_or(PeerError::Denied)?;
            if update.expected != current.number {
                return Err(PeerError::Conflict(current.number));
            }
            replicas::check_write(&view, call.update)?;
        }
        Ok(None)
    }

    pub(super) fn scoped(&mut self, call: Call, busy: Duration) -> Result<ScopedStart<'_>> {
        self.0.busy_timeout(busy)?;
        let tx = if call.update.is_some() {
            self.0.transaction_with_behavior(Immediate)?
        } else {
            self.0.transaction()?
        };
        let scope = authorize(&tx, call)?;
        require_kind(&tx, &scope.reference, true)?;
        let (view, root) = replicas::view(&tx, &scope.reference, call)?;
        if let Some(update) = call.update
            && let Some(receipt) = replay(&tx, call.grant, update)?
        {
            return Ok(ScopedStart::Replayed(receipt));
        }
        let revision = revision(&tx, &scope.reference)?.ok_or(PeerError::Denied)?;
        if let Some(update) = call.update
            && update.expected != revision.number
        {
            return Err(PeerError::Conflict(revision.number));
        }
        replicas::check_write(&view, call.update)?;
        let historical = if matches!(view.consistency, Consistency::Revision(_)) {
            Some(replicas::read_manifest(
                &tx,
                root.ok_or(PeerError::Denied)?,
            )?)
        } else {
            None
        };
        Ok(ScopedStart::Collection(Collection {
            tx,
            reference: scope.reference,
            revision: revision.number,
            call: Box::new(call),
            view,
            historical,
        }))
    }

    pub(super) fn confirm_collection(&self, call: Call) -> Result<()> {
        let scope = authorize(&self.0, call)?;
        require_kind(&self.0, &scope.reference, true)
    }

    /// Drops blocks unreachable from references and publications in one transaction.
    pub fn collect(&mut self) -> Result<usize> {
        Ok(self.0.execute(
            "WITH RECURSIVE live(hash) AS (
            SELECT hash FROM refs UNION SELECT hash FROM blocks WHERE published=1
            UNION SELECT id FROM replica_versions
            UNION SELECT tip FROM replica_pending
            UNION SELECT hash FROM job_blocks
            UNION SELECT package FROM native_installations
            UNION SELECT s.program FROM subscriptions s JOIN subscription_authority a USING(id)
                  WHERE s.expires>?1
            UNION SELECT edges.child FROM edges JOIN live ON edges.parent=live.hash
        ) DELETE FROM blocks WHERE NOT EXISTS(SELECT 1 FROM live WHERE live.hash=blocks.hash)",
            [unix_ms() as i64],
        )?)
    }
}

pub(super) enum ScopedStart<'a> {
    Collection(Collection<'a>),
    Replayed(Receipt),
}

pub(super) struct Collection<'a> {
    tx: Transaction<'a>,
    reference: String,
    revision: u64,
    call: Box<Call>,
    view: ResourceView,
    historical: Option<BTreeMap<String, Hash>>,
}

impl Collection<'_> {
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn view(&self) -> &ResourceView {
        &self.view
    }

    pub(super) fn host_resource(&self) -> Result<Option<HostResource>> {
        let resource = self
            .tx
            .query_row(
                "SELECT provider, configuration FROM host_resources WHERE ref=?1",
                [&self.reference],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        resource
            .map(|(provider, bytes)| {
                Ok(HostResource {
                    provider,
                    configuration: Data::from_bytes(&bytes)?,
                })
            })
            .transpose()
    }

    pub(super) fn effect(&self, effect: Effect) -> Result<Vec<u8>> {
        use serde_json::json;
        let result = match effect {
            Effect::Get(key) => {
                let bytes: Option<Vec<u8>> = if let Some(entries) = &self.historical {
                    entries
                        .get(&key)
                        .map(|hash| replicas::entry_block(&self.tx, *hash))
                        .transpose()?
                } else {
                    self.tx
                        .query_row(
                            "SELECT value FROM entries WHERE ref=?1 AND key=?2",
                            params![self.reference, key.as_bytes()],
                            |row| row.get(0),
                        )
                        .optional()?
                };
                match bytes {
                    Some(bytes) => json!({"found": true, "value": entry_json(&bytes)?}),
                    None => json!({"found": false}),
                }
            }
            Effect::Scan(scan) => return self.scan(scan),
            Effect::Put(key, bytes) => {
                self.call.update.ok_or(PeerError::Denied)?;
                check_entry(&key, &bytes)?;
                self.tx.execute(
                    "INSERT INTO entries VALUES (?1, ?2, ?3)
                     ON CONFLICT(ref, key) DO UPDATE SET value=excluded.value",
                    params![self.reference, key.as_bytes(), bytes],
                )?;
                json!(null)
            }
            Effect::Delete(key) => {
                self.call.update.ok_or(PeerError::Denied)?;
                let deleted = self.tx.execute(
                    "DELETE FROM entries WHERE ref=?1 AND key=?2",
                    params![self.reference, key.as_bytes()],
                )?;
                json!(deleted != 0)
            }
            Effect::Evaluate(_) | Effect::Host(..) => return Err(PeerError::Denied),
        };
        content::data_from_json(result)?
            .to_bytes()
            .map_err(Into::into)
    }

    fn scan(&self, scan: Scan) -> Result<Vec<u8>> {
        let lower = scan.after.as_deref().unwrap_or(&scan.prefix);
        if let Some(entries) = &self.historical {
            let entries = entries
                .range(lower.to_owned()..)
                .take_while(|(key, _)| key.starts_with(&scan.prefix))
                .map(|(key, hash)| Ok((key.clone(), replicas::entry_block(&self.tx, *hash)?)));
            return Self::scan_rows(&scan, entries);
        }
        // UTF-8 never contains 0xff. BLOB comparison gives a bounded prefix range on the index.
        let mut upper = scan.prefix.as_bytes().to_vec();
        upper.push(0xff);
        let mut stmt = self.tx.prepare_cached(
            "SELECT key, value FROM entries WHERE ref=?1 AND key>=?2 AND key<?3 ORDER BY key",
        )?;
        let rows = stmt.query_map(params![self.reference, lower.as_bytes(), upper], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        Self::scan_rows(
            &scan,
            rows.map(|row| {
                let (key, bytes) = row?;
                let key =
                    String::from_utf8(key).map_err(|err| PeerError::Value(err.to_string()))?;
                Ok((key, bytes))
            }),
        )
    }

    fn scan_rows(
        scan: &Scan,
        rows: impl Iterator<Item = Result<(String, Vec<u8>)>>,
    ) -> Result<Vec<u8>> {
        let mut entries = Vec::new();
        let mut last = None;
        let mut next = None;
        let mut bytes_left = Block::MAX_BYTES - 2048;
        for row in rows {
            let (key, bytes) = row?;
            if scan.after.as_ref() == Some(&key) {
                continue;
            }
            let cost = bytes.len() + key.len() + 32;
            if entries.len() == usize::from(scan.limit) || cost > bytes_left {
                next = last;
                break;
            }
            bytes_left -= cost;
            entries.push(serde_json::json!([key, entry_json(&bytes)?]));
            last = Some(key);
        }
        content::data_from_json(serde_json::json!({"entries": entries, "next": next}))?
            .to_bytes()
            .map_err(Into::into)
    }

    pub(super) fn finish(
        self,
        value: Vec<u8>,
        check: impl Fn() -> Result<()>,
        durable: Option<(JobKey, GraphMetrics)>,
        signer: Option<&PeerIdentity>,
    ) -> Result<Receipt> {
        let mut receipt = Receipt {
            revision: self.revision,
            value,
            view: self.view.resource.is_some().then_some(self.view),
        };
        if let Some(update) = self.call.update {
            receipt.revision += 1;
            let number = receipt.revision;
            let revision =
                i64::try_from(number).map_err(|_| PeerError::Limit("reference revisions"))?;
            if replicas::commit(&self.tx, &self.reference, signer, *self.call, None)? {
                receipt.view = Some(replicas::view(&self.tx, &self.reference, *self.call)?.0);
            } else {
                self.tx.execute(
                    "UPDATE refs SET revision=?1 WHERE name=?2",
                    params![revision, self.reference],
                )?;
                applications::record_change(&self.tx, &self.reference, number, self.call.reaction)?;
            }
            save_receipt(&self.tx, self.call.grant, &self.reference, update, &receipt)?;
            if let Some((key, graph)) = durable {
                jobs::check_running(&self.tx, key)?;
                jobs::end(&self.tx, key, &JobState::completed(receipt.clone(), graph))?;
            }
        }
        check()?;
        self.tx.commit()?;
        Ok(receipt)
    }
}

fn check_entry(key: &str, bytes: &[u8]) -> Result<()> {
    super::effects::check_key(key, false)?;
    if bytes.len() > MAX_EFFECT_BYTES {
        return Err(PeerError::Limit("entry bytes"));
    }
    entry_json(bytes)?;
    Ok(())
}

fn entry_json(bytes: &[u8]) -> Result<serde_json::Value> {
    content::data_to_json(&Data::from_bytes(bytes)?)
}

fn register_resource(
    conn: &Connection,
    name: &str,
    resource: HostResource,
    reuse: bool,
) -> Result<()> {
    replicas::can_replace_locally(conn, name)?;
    super::effects::validate_binding_name(&resource.provider)?;
    let configuration = resource.configuration.to_bytes()?;
    if configuration.len() > MAX_EFFECT_BYTES {
        return Err(PeerError::Limit("host resource configuration"));
    }
    if reuse && conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM host_resources WHERE ref=?1 AND provider=?2 AND configuration=?3)",
        params![name, resource.provider, configuration],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(());
    }
    create_collection(conn, name, [])?;
    conn.execute(
        "INSERT INTO host_resources VALUES (?1, ?2, ?3)",
        params![name, resource.provider, configuration],
    )?;
    Ok(())
}

fn create_collection(
    conn: &Connection,
    name: &str,
    entries: impl IntoIterator<Item = Result<(String, Data)>>,
) -> Result<Revision> {
    check_name(name)?;
    replicas::can_replace_locally(conn, name)?;
    let bytes = Block::Data(Data::Nil).to_bytes()?;
    let hash = Hash::digest(&bytes);
    insert(conn, hash, &bytes)?;
    if conn.execute(
        "INSERT INTO refs VALUES (?1, 0, ?2) ON CONFLICT(name) DO NOTHING",
        params![name, &hash.0[..]],
    )? == 0
    {
        return Err(PeerError::ReferenceExists(name.to_owned()));
    }
    conn.execute("INSERT INTO collections VALUES (?1)", [name])?;
    let mut insert = conn.prepare("INSERT INTO entries VALUES (?1, ?2, ?3)")?;
    for entry in entries {
        let (key, value) = entry?;
        let bytes = value.to_bytes()?;
        check_entry(&key, &bytes)?;
        insert.execute(params![name, key.as_bytes(), bytes])?;
    }
    applications::record_change(conn, name, 0, false)?;
    Ok(Revision { number: 0, hash })
}

fn require_kind(conn: &Connection, name: &str, scoped: bool) -> Result<()> {
    let collection: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM collections WHERE ref=?1)",
        [name],
        |row| row.get(0),
    )?;
    if collection != scoped {
        return Err(PeerError::Value(if scoped {
            "expected an indexed collection reference".into()
        } else {
            "expected a snapshot reference".into()
        }));
    }
    Ok(())
}

fn save_receipt(
    conn: &Connection,
    grant: Hash,
    reference: &str,
    update: Update,
    receipt: &Receipt,
) -> Result<()> {
    let number = receipt.revision as i64;
    conn.execute(
        "INSERT INTO receipts VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &grant.0[..],
            &update.operation.0[..],
            reference,
            &update.fingerprint.0[..],
            number,
            receipt.value,
            receipt.view.as_ref().map(protocol::encode).transpose()?,
        ],
    )?;
    conn.execute(
        "DELETE FROM receipts WHERE ref=?1 AND revision<=?2",
        params![reference, number.saturating_sub(RECEIPT_WINDOW as i64)],
    )?;
    Ok(())
}

fn replace(conn: &Connection, name: &str, current: Revision, next: &[u8]) -> Result<Revision> {
    let hash = Hash::digest(next);
    if insert(conn, hash, next)? != Kind::Data {
        return Err(PeerError::Value("expected data for next state".into()));
    }
    require_graph(conn, hash)?;
    let number =
        i64::try_from(current.number + 1).map_err(|_| PeerError::Limit("reference revisions"))?;
    conn.execute(
        "UPDATE refs SET hash=?1, revision=?2 WHERE name=?3",
        params![&hash.0[..], number, name],
    )?;
    applications::record_change(conn, name, number as u64, false)?;
    Ok(Revision {
        number: number as u64,
        hash,
    })
}

fn database_version(conn: &Connection) -> Result<i64> {
    // Read the identity and version from one SQLite statement so concurrent initialization
    // cannot leave this connection with a mixture of the old and new schema metadata.
    let (application, version, entries): (i64, i64, i64) = conn.query_row(
        "SELECT application_id, user_version, (SELECT count(*) FROM sqlite_schema)
         FROM pragma_application_id, pragma_user_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    match (application, version, entries) {
        (0, 0, 0) => Ok(0),
        (APPLICATION_ID, 1..=6, _) => Ok(version),
        (APPLICATION_ID, _, _) => Err(PeerError::Unsupported("peer database version")),
        _ => Err(PeerError::Unsupported(
            "expected a pp2 database or an empty file",
        )),
    }
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(PeerError::Value("invalid reference name".into()));
    }
    Ok(())
}

fn get(conn: &Connection, hash: Hash, published: bool) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row(
            "SELECT bytes FROM blocks WHERE hash=?1 AND (?2=0 OR published=1)",
            params![&hash.0[..], published],
            |row| row.get(0),
        )
        .optional()?)
}

fn insert(conn: &Connection, hash: Hash, bytes: &[u8]) -> Result<Kind> {
    let (kind, links) = content::inspect(hash, bytes)?;
    let added = conn.execute(
        "INSERT INTO blocks (hash, bytes) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        params![&hash.0[..], bytes],
    )?;
    if added != 0 {
        let mut stmt = conn.prepare("INSERT INTO edges VALUES (?1, ?2)")?;
        for link in links {
            stmt.execute(params![&hash.0[..], &link.0[..]])?;
        }
    }
    Ok(kind)
}

fn require_graph(conn: &Connection, hash: Hash) -> Result<()> {
    let missing = conn
        .query_row(
            "WITH RECURSIVE graph(hash) AS (
        VALUES (?1) UNION SELECT edges.child FROM edges JOIN graph ON edges.parent=graph.hash
    ) SELECT graph.hash FROM graph LEFT JOIN blocks USING(hash) WHERE blocks.hash IS NULL LIMIT 1",
            [&hash.0[..]],
            |row| row.get::<_, [u8; 32]>(0),
        )
        .optional()?;
    if let Some(missing) = missing {
        return Err(PeerError::Missing(Hash(missing)));
    }
    Ok(())
}

fn revision(conn: &Connection, name: &str) -> Result<Option<Revision>> {
    Ok(conn
        .query_row(
            "SELECT revision, hash FROM refs WHERE name=?1",
            [name],
            |row| {
                Ok(Revision {
                    number: row.get::<_, i64>(0)? as u64,
                    hash: Hash(row.get(1)?),
                })
            },
        )
        .optional()?)
}

fn insert_grant(
    conn: &Connection,
    holder: Hash,
    scope: &Authority,
    parent: Option<Hash>,
) -> Result<Hash> {
    check_name(&scope.reference)?;
    let count: u32 = conn.query_row(
        "SELECT count(*) FROM grants WHERE ref=?1",
        [&scope.reference],
        |row| row.get(0),
    )?;
    if count >= MAX_GRANTS_PER_REF {
        return Err(PeerError::Limit("grants per reference"));
    }
    let mut id = [0; 32];
    getrandom::fill(&mut id).map_err(|err| std::io::Error::other(err.to_string()))?;
    conn.execute(
        "INSERT INTO grants VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &id[..],
            &holder.0[..],
            scope.reference,
            u8::from(scope.access == Access::Write),
            scope.program.as_ref().map(|h| &h.0[..]),
            scope.depth,
            parent.as_ref().map(|h| &h.0[..])
        ],
    )?;
    if scope.reaction_writer {
        conn.execute("INSERT INTO reaction_writers VALUES (?1)", [&id[..]])?;
    }
    Ok(Hash(id))
}

fn prune_graph_grants(conn: &Connection, now: u64) -> Result<()> {
    conn.execute(
        "DELETE FROM graph_forward_replays WHERE expires<=?1",
        [now as i64],
    )?;
    conn.execute(
        "DELETE FROM grants WHERE id IN (SELECT id FROM graph_grants WHERE expires<=?1)",
        [now as i64],
    )?;
    Ok(())
}

fn authority(conn: &Connection, holder: Hash, grant: Hash) -> Result<Authority> {
    conn.query_row(
        "SELECT ref, access, program, grants.depth, expires, timeout, calls, graph_grants.depth, presenter,
                EXISTS(SELECT 1 FROM reaction_writers WHERE id=grants.id)
         FROM grants LEFT JOIN graph_grants USING(id)
         WHERE id=?1 AND holder=?2 AND (expires IS NULL OR expires>?3)",
        params![&grant.0[..], &holder.0[..], unix_ms() as i64],
        |row| {
            Ok(Authority {
                reference: row.get(0)?,
                access: if row.get::<_, u8>(1)? == 1 {
                    Access::Write
                } else {
                    Access::Read
                },
                program: row.get::<_, Option<[u8; 32]>>(2)?.map(Hash),
                depth: row.get(3)?,
                graph: match row.get::<_, Option<i64>>(4)? {
                    Some(expires_at_ms) => Some(GraphAccess {
                        expires_at_ms: expires_at_ms as u64,
                        delegated_by: Some(Hash(row.get(8)?)),
                        budget: GraphBudget {
                            timeout_ms: row.get(5)?,
                            calls: row.get(6)?,
                            depth: row.get(7)?,
                        },
                    }),
                    None => None,
                },
                reaction_writer: row.get(9)?,
            })
        },
    )
    .optional()?
    .ok_or(PeerError::Denied)
}

fn authorize(conn: &Connection, call: Call) -> Result<Authority> {
    let scope = authority(conn, call.holder, call.grant)?;
    if scope.program.is_some_and(|allowed| allowed != call.program)
        || (call.update.is_some() && scope.access != Access::Write)
        || (scope.reaction_writer && !call.reaction)
        || (call.reaction && call.update.is_some() && !scope.reaction_writer)
        || call.graph.and_then(|graph| graph.delegated_by)
            != scope.graph.and_then(|limit| limit.delegated_by)
        || scope.graph.is_some_and(|limit| {
            call.graph.is_none_or(|graph| {
                !graph.budget.fits(limit.budget) || graph.expires_at_ms > limit.expires_at_ms
            })
        })
    {
        return Err(PeerError::Denied);
    }
    replicas::authorize_executor(conn, &scope.reference, call.executor)?;
    replicas::authorize_view(
        conn,
        &scope.reference,
        call.holder,
        Some(call.program),
        if call.update.is_some() {
            Access::Write
        } else {
            Access::Read
        },
    )?;
    Ok(scope)
}

fn replay(conn: &Connection, grant: Hash, update: Update) -> Result<Option<Receipt>> {
    let previous = conn
        .query_row(
            "SELECT request, revision, value, view FROM receipts WHERE grant_id=?1 AND operation=?2",
            params![&grant.0[..], &update.operation.0[..]],
            |row| {
                Ok((
                    Hash(row.get(0)?),
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            },
        )
        .optional()?;
    match previous {
        Some((hash, revision, value, view)) if hash == update.fingerprint => {
            let view = view.as_deref().map(protocol::decode).transpose()?;
            if let Some(view) = &view {
                replicas::validate_release(conn, view)?;
            }
            Ok(Some(Receipt {
                revision,
                value,
                view,
            }))
        }
        Some(_) => Err(PeerError::Value(
            "operation ID already used for a different request".into(),
        )),
        None => Ok(None),
    }
}
