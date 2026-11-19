use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior::Immediate, params};
use serde::{Deserialize, Serialize};

use crate::{Block, Data, Hash};

use super::{
    PeerError, Result,
    content::{self, Kind},
};

const MAX_DELEGATION_DEPTH: u8 = 8;
const MAX_GRANTS_PER_REF: u32 = 1024;
const MAX_CACHE_BYTES_PER_CERTIFICATE: i64 = 16 * 1024 * 1024;
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

/// Read permits snapshot evaluation. Write also permits atomic replacement of the reference.
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
    pub(super) bytes: Vec<u8>,
}

pub(super) struct Authority {
    reference: String,
    access: Access,
    program: Option<Hash>,
    depth: u8,
}

#[derive(Clone, Copy)]
pub(super) struct Call {
    pub(super) holder: Hash,
    pub(super) grant: Hash,
    pub(super) program: Hash,
    pub(super) update: Option<Update>,
}

#[derive(Clone, Copy)]
pub(super) struct Update {
    pub(super) expected: u64,
    pub(super) operation: Hash,
    pub(super) fingerprint: Hash,
}

pub(super) struct Receipt {
    pub(super) revision: u64,
    pub(super) value: Vec<u8>,
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
        let path = path.as_ref();
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
        conn.busy_timeout(Duration::from_millis(1500))?;
        let initialize = is_uninitialized(&conn)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        // Bound the main database. Short transactions keep WAL readers from pinning old pages.
        conn.pragma_update(None, "max_page_count", 65_536)?;
        if initialize {
            let tx = conn.transaction_with_behavior(Immediate)?;
            if is_uninitialized(&tx)? {
                tx.execute_batch(SCHEMA)?;
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
            if used + size > MAX_CACHE_BYTES_PER_CERTIFICATE {
                continue;
            }
            if insert(&tx, *hash, bytes)? == Kind::Data {
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
        let added = tx.execute(
            "INSERT INTO refs VALUES (?1, 0, ?2) ON CONFLICT(name) DO NOTHING",
            params![name, &hash.0[..]],
        )?;
        if added == 0 {
            return Err(PeerError::ReferenceExists(name.to_owned()));
        }
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
        if current.number != expected {
            return Err(PeerError::Conflict(current.number));
        }
        let next = replace(&tx, name, current, &bytes)?;
        tx.commit()?;
        Ok(next)
    }

    /// Creates a grant bound to a TLS certificate fingerprint and optionally one program hash.
    pub fn issue(
        &mut self,
        reference: &str,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
    ) -> Result<Hash> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let id = insert_grant(
            &tx,
            holder,
            &Authority {
                reference: reference.into(),
                access,
                program,
                depth: 0,
            },
            None,
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Revokes a grant and all its descendants in one transaction.
    pub fn revoke(&mut self, grant: Hash) -> Result<bool> {
        Ok(self
            .0
            .execute("DELETE FROM grants WHERE id=?1", [&grant.0[..]])?
            != 0)
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
        if access > scope.access || scope.depth >= MAX_DELEGATION_DEPTH {
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
        let id = insert_grant(&tx, holder, &scope, Some(grant))?;
        tx.commit()?;
        Ok(id)
    }

    pub(super) fn begin(&mut self, call: Call) -> Result<EvaluationStart> {
        let tx = self.0.transaction()?;
        let scope = authorize(&tx, call)?;
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
        let bytes = get(&tx, revision.hash, false)?.ok_or(PeerError::Missing(revision.hash))?;
        let snapshot = Snapshot {
            reference: scope.reference,
            revision,
            bytes,
        };
        tx.commit()?;
        Ok(EvaluationStart::Snapshot(snapshot))
    }

    pub(super) fn confirm(&self, call: Call) -> Result<()> {
        authorize(&self.0, call)?;
        Ok(())
    }

    pub(super) fn commit(
        &mut self,
        call: Call,
        snapshot: &Snapshot,
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
        let revision = replace(&tx, &scope.reference, current, next)?;
        let number = revision.number as i64;
        tx.execute(
            "INSERT INTO receipts VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &call.grant.0[..],
                &update.operation.0[..],
                scope.reference,
                &update.fingerprint.0[..],
                number,
                &value
            ],
        )?;
        tx.execute(
            "DELETE FROM receipts WHERE ref=?1 AND revision<=?2",
            params![
                scope.reference,
                number.saturating_sub(RECEIPT_WINDOW as i64)
            ],
        )?;
        tx.commit()?;
        Ok(Receipt {
            revision: revision.number,
            value,
        })
    }

    /// Drops blocks unreachable from references and publications in one transaction.
    pub fn collect(&mut self) -> Result<usize> {
        Ok(self.0.execute(
            "WITH RECURSIVE live(hash) AS (
            SELECT hash FROM refs UNION SELECT hash FROM blocks WHERE published=1
            UNION SELECT edges.child FROM edges JOIN live ON edges.parent=live.hash
        ) DELETE FROM blocks WHERE hash NOT IN (SELECT hash FROM live)",
            [],
        )?)
    }
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
    Ok(Revision {
        number: number as u64,
        hash,
    })
}

fn is_uninitialized(conn: &Connection) -> Result<bool> {
    // Read the identity and version from one SQLite statement so concurrent initialization
    // cannot leave this connection with a mixture of the old and new schema metadata.
    let (application, version, entries): (i64, i64, i64) = conn.query_row(
        "SELECT application_id, user_version, (SELECT count(*) FROM sqlite_schema)
         FROM pragma_application_id, pragma_user_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    match (application, version, entries) {
        (0, 0, 0) => Ok(true),
        (APPLICATION_ID, 1, _) => Ok(false),
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
    Ok(Hash(id))
}

fn authority(conn: &Connection, holder: Hash, grant: Hash) -> Result<Authority> {
    conn.query_row(
        "SELECT ref, access, program, depth FROM grants WHERE id=?1 AND holder=?2",
        params![&grant.0[..], &holder.0[..]],
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
    {
        return Err(PeerError::Denied);
    }
    Ok(scope)
}

fn replay(conn: &Connection, grant: Hash, update: Update) -> Result<Option<Receipt>> {
    let previous = conn
        .query_row(
            "SELECT request, revision, value FROM receipts WHERE grant_id=?1 AND operation=?2",
            params![&grant.0[..], &update.operation.0[..]],
            |row| {
                Ok((
                    Hash(row.get(0)?),
                    Receipt {
                        revision: row.get::<_, i64>(1)? as u64,
                        value: row.get(2)?,
                    },
                ))
            },
        )
        .optional()?;
    match previous {
        Some((hash, receipt)) if hash == update.fingerprint => Ok(Some(receipt)),
        Some(_) => Err(PeerError::Value(
            "operation ID already used for a different request".into(),
        )),
        None => Ok(None),
    }
}
