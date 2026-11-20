use std::collections::BTreeMap;

use super::*;
use crate::peer::{
    Binding,
    content::load_code,
    effects::{
        BoundCapability, GraphBindings, GraphJob, MAX_JOB_LIFETIME_MS, validate_binding_names,
    },
    protocol::EvaluationMode,
};

const MAX_EVENTS: i64 = 4096;
const EVENT_RETENTION_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_SUBSCRIPTIONS: u32 = 128;
const MAX_PER_APPLICATION: usize = 16;

pub(super) const SCHEMA: &str = "
CREATE TABLE change_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event BLOB NOT NULL,
    ref TEXT NOT NULL REFERENCES refs(name),
    revision INTEGER NOT NULL,
    recorded INTEGER NOT NULL,
    reaction INTEGER NOT NULL,
    UNIQUE(ref, revision)
);
CREATE INDEX change_events_recorded ON change_events(recorded);
CREATE TABLE applications (
    name TEXT PRIMARY KEY, holder BLOB NOT NULL, removed INTEGER NOT NULL DEFAULT 0,
    drain_until INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE subscriptions (
    id BLOB PRIMARY KEY, application TEXT NOT NULL REFERENCES applications(name),
    name TEXT NOT NULL, ref TEXT NOT NULL REFERENCES refs(name),
    watch_grant BLOB NOT NULL, entry_grant BLOB NOT NULL, program BLOB NOT NULL,
    budget BLOB NOT NULL, capabilities BLOB NOT NULL, expires INTEGER NOT NULL,
    state INTEGER NOT NULL DEFAULT 0, cursor INTEGER NOT NULL, missed INTEGER NOT NULL DEFAULT 0,
    scheduled INTEGER NOT NULL DEFAULT 0, outcome BLOB,
    UNIQUE(application, name)
) WITHOUT ROWID;
CREATE INDEX subscriptions_active ON subscriptions(application) WHERE state=0;
CREATE TABLE reaction_writers (
    id BLOB PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE
) WITHOUT ROWID;
ALTER TABLE jobs ADD COLUMN reaction INTEGER NOT NULL DEFAULT 0;
ALTER TABLE jobs ADD COLUMN subscription BLOB REFERENCES subscriptions(id);
ALTER TABLE jobs ADD COLUMN event BLOB;
ALTER TABLE jobs ADD COLUMN event_revision INTEGER;
ALTER TABLE jobs ADD COLUMN reaction_input BLOB;
CREATE UNIQUE INDEX job_subscription ON jobs(subscription) WHERE subscription IS NOT NULL;
CREATE INDEX reaction_job_expiry ON jobs(expires) WHERE reaction=1 AND state=2;
CREATE VIEW subscription_authority AS
    SELECT s.id FROM subscriptions s
    JOIN applications a ON a.name=s.application
    JOIN grants watch ON watch.id=s.watch_grant
    JOIN grants entry ON entry.id=s.entry_grant
    WHERE s.state=0 AND a.removed=0;
PRAGMA user_version = 4;
";

const ACTIVE: i64 = 0;
const REVOKED: i64 = 1;
const EXPIRED: i64 = 2;

/// A local installation. Only the database administrator can install an application.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSpec {
    pub name: String,
    pub subscriptions: BTreeMap<String, SubscriptionSpec>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionSpec {
    pub program: Hash,
    /// A program-pinned read grant for the serving peer's certificate.
    pub watch_grant: Hash,
    /// Defaults to the watch grant. A snapshot watch needs an indexed collection entry grant.
    #[serde(default)]
    pub entry_grant: Option<Hash>,
    pub budget: GraphBudget,
    /// Explicit remote grants addressed to the serving peer.
    #[serde(default)]
    pub capabilities: BTreeMap<String, Binding>,
    /// Absolute Unix time in milliseconds.
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationState {
    Installed,
    Removing,
    Removed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionState {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Serialize)]
pub struct ApplicationStatus {
    pub holder: Hash,
    pub state: ApplicationState,
    pub drain_until_ms: Option<u64>,
    pub subscriptions: BTreeMap<String, SubscriptionStatus>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionStatus {
    pub reference: String,
    pub program: Hash,
    pub expires_at_ms: u64,
    pub state: SubscriptionState,
    /// The last revision retired by this subscription, including skipped events.
    pub cursor: u64,
    pub missed: u64,
    pub pending_revision: Option<u64>,
    pub last_delivery: Option<DeliveryStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeliveryStatus {
    pub event_id: String,
    pub revision: u64,
    pub outcome: DeliveryOutcome,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOutcome {
    Completed,
    Failed,
    Cancelled,
    Expired,
}

impl PeerStore {
    pub fn install_application(&mut self, holder: Hash, app: ApplicationSpec) -> Result<()> {
        check_name(&app.name)?;
        if app.subscriptions.is_empty() || app.subscriptions.len() > MAX_PER_APPLICATION {
            return Err(PeerError::Limit("subscriptions per application"));
        }
        // Code is already in this peer's store. Pin it only after the entire installation validates.
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let now = unix_ms();
        let active: u32 = tx.query_row(
            "SELECT count(*) FROM subscription_authority JOIN subscriptions USING(id) WHERE expires>?1",
            [now as i64],
            |row| row.get(0),
        )?;
        if active + app.subscriptions.len() as u32 > MAX_SUBSCRIPTIONS {
            return Err(PeerError::Limit("active subscriptions"));
        }
        if tx.execute(
            "INSERT INTO applications(name, holder) VALUES (?1, ?2)
             ON CONFLICT(name) DO NOTHING",
            params![app.name, &holder.0[..]],
        )? == 0
        {
            return Err(PeerError::Value("application name already used".into()));
        }
        for (name, spec) in app.subscriptions {
            check_name(&name)?;
            let expires = i64::try_from(spec.expires_at_ms)
                .map_err(|_| PeerError::Limit("subscription expiration"))?;
            if spec.expires_at_ms <= now {
                return Err(PeerError::Timeout);
            }
            spec.budget.validate()?;
            validate_binding_names(&spec.capabilities.keys().cloned().collect::<Vec<_>>())?;
            let watch = subscription_grant(&tx, holder, spec.watch_grant, spec.program)?;
            let entry_grant = spec.entry_grant.unwrap_or(spec.watch_grant);
            let entry = subscription_grant(&tx, holder, entry_grant, spec.program)?;
            require_kind(&tx, &entry.reference, true)?;
            let code = load_code(spec.program, false, |hash| get(&tx, hash, false))?;
            if !code[0].1.starts_with(content::MAGIC) {
                return Err(PeerError::Value("subscriptions require JavaScript".into()));
            }
            let cursor = revision(&tx, &watch.reference)?
                .ok_or(PeerError::Denied)?
                .number;
            tx.execute(
                "INSERT INTO subscriptions
                 (id, application, name, ref, watch_grant, entry_grant, program, budget, capabilities, expires, cursor)
                 VALUES (randomblob(32), ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    app.name,
                    name,
                    watch.reference,
                    &spec.watch_grant.0[..],
                    &entry_grant.0[..],
                    &spec.program.0[..],
                    protocol::encode(&spec.budget)?,
                    protocol::encode(&spec.capabilities)?,
                    expires,
                    cursor as i64,
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn application_status(&self, name: &str) -> Result<ApplicationStatus> {
        let tx = self.0.unchecked_transaction()?;
        let (holder, removed, drain_until) = tx
            .query_row(
                "SELECT holder, removed, drain_until FROM applications WHERE name=?1",
                [name],
                |row| {
                    Ok((
                        Hash(row.get(0)?),
                        row.get::<_, bool>(1)?,
                        row.get::<_, i64>(2)? as u64,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| unknown_application(name))?;
        let mut query = tx.prepare(
            "SELECT s.name, s.ref, s.program, s.expires, s.state, s.cursor, s.missed,
                    j.event_revision, s.outcome, authority.id IS NOT NULL
             FROM subscriptions s
             LEFT JOIN jobs j ON j.subscription=s.id
             LEFT JOIN subscription_authority authority ON authority.id=s.id
             WHERE s.application=?1",
        )?;
        let now = unix_ms();
        let mut rows = query.query([name])?;
        let mut subscriptions = BTreeMap::new();
        while let Some(row) = rows.next()? {
            let expires_at_ms = row.get::<_, i64>(3)? as u64;
            let state = match row.get::<_, i64>(4)? {
                EXPIRED => SubscriptionState::Expired,
                REVOKED => SubscriptionState::Revoked,
                _ if !row.get::<_, bool>(9)? => SubscriptionState::Revoked,
                _ if expires_at_ms <= now => SubscriptionState::Expired,
                _ => SubscriptionState::Active,
            };
            let last_delivery = row.get::<_, Option<Vec<u8>>>(8)?;
            subscriptions.insert(
                row.get(0)?,
                SubscriptionStatus {
                    reference: row.get(1)?,
                    program: Hash(row.get(2)?),
                    expires_at_ms,
                    state,
                    cursor: row.get::<_, i64>(5)? as u64,
                    missed: row.get::<_, i64>(6)? as u64,
                    pending_revision: row
                        .get::<_, Option<i64>>(7)?
                        .map(|revision| revision as u64),
                    last_delivery: last_delivery.as_deref().map(protocol::decode).transpose()?,
                },
            );
        }
        let drain_until_ms = (removed && drain_until > now).then_some(drain_until);
        let state = match (removed, drain_until_ms) {
            (false, _) => ApplicationState::Installed,
            (true, Some(_)) => ApplicationState::Removing,
            (true, None) => ApplicationState::Removed,
        };
        Ok(ApplicationStatus {
            holder,
            state,
            drain_until_ms,
            subscriptions,
        })
    }

    pub fn revoke_subscription(&mut self, application: &str, name: &str) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let id = tx
            .query_row(
                "SELECT id FROM subscriptions WHERE application=?1 AND name=?2",
                params![application, name],
                |row| Ok(Hash(row.get(0)?)),
            )
            .optional()?
            .ok_or_else(|| {
                PeerError::Value(format!("unknown subscription {application}/{name}"))
            })?;
        retire(&tx, id, REVOKED, &JobState::Cancelled)?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_application(&mut self, name: &str) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if tx.execute("UPDATE applications SET removed=1 WHERE name=?1", [name])? == 0 {
            return Err(unknown_application(name));
        }
        let ids = {
            let mut query = tx.prepare("SELECT id FROM subscriptions WHERE application=?1")?;
            query
                .query_map([name], |row| Ok(Hash(row.get(0)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for id in ids {
            retire(&tx, id, REVOKED, &JobState::Cancelled)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(in crate::peer) fn schedule_subscriptions(&mut self, holder: Hash) -> Result<()> {
        const CANDIDATES: &str = "
            FROM subscriptions s
            JOIN applications a ON a.name=s.application
            JOIN refs r ON r.name=s.ref
            WHERE s.state=0 AND a.holder=?1 AND (
                s.expires<=?2 OR NOT EXISTS(SELECT 1 FROM subscription_authority WHERE id=s.id)
                OR (s.cursor<r.revision AND NOT EXISTS(SELECT 1 FROM jobs WHERE subscription=s.id)))";
        let now = unix_ms() as i64;
        let cutoff = now.saturating_sub(EVENT_RETENTION_MS);
        // A parent can outlive a child with a shorter deadline and still need its reply.
        let job_cutoff = now.saturating_sub(MAX_JOB_LIFETIME_MS as i64);
        let ready = self.0.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 {CANDIDATES})
                      OR EXISTS(SELECT 1 FROM change_events WHERE recorded<=?3)
                      OR EXISTS(SELECT 1 FROM jobs WHERE reaction=1 AND state=2 AND expires<=?4)"
            ),
            params![&holder.0[..], now, cutoff, job_cutoff],
            |row| row.get::<_, bool>(0),
        )?;
        if !ready {
            return Ok(());
        }

        let tx = self.0.transaction_with_behavior(Immediate)?;
        tx.execute("DELETE FROM change_events WHERE recorded<=?1", [cutoff])?;
        tx.execute(
            "DELETE FROM jobs WHERE reaction=1 AND state=2 AND expires<=?1",
            [job_cutoff],
        )?;
        let candidates = {
            let mut query = tx.prepare(&format!(
                "SELECT s.id, s.ref, s.entry_grant, s.program, s.budget, s.capabilities, s.expires,
                        s.cursor, r.revision, EXISTS(SELECT 1 FROM subscription_authority WHERE id=s.id)
                 {CANDIDATES} ORDER BY s.scheduled, s.id"
            ))?;
            query
                .query_map(params![&holder.0[..], now], |row| {
                    Ok(Candidate {
                        id: Hash(row.get(0)?),
                        reference: row.get(1)?,
                        entry_grant: Hash(row.get(2)?),
                        program: Hash(row.get(3)?),
                        budget: row.get(4)?,
                        capabilities: row.get(5)?,
                        expires: row.get(6)?,
                        cursor: row.get(7)?,
                        latest: row.get(8)?,
                        authorized: row.get(9)?,
                    })
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for candidate in candidates {
            candidate.schedule(&tx, holder, now)?;
        }
        tx.commit()?;
        Ok(())
    }
}

struct Candidate {
    id: Hash,
    reference: String,
    entry_grant: Hash,
    program: Hash,
    budget: Vec<u8>,
    capabilities: Vec<u8>,
    expires: i64,
    cursor: i64,
    latest: i64,
    authorized: bool,
}

impl Candidate {
    fn schedule(self, conn: &Connection, holder: Hash, now: i64) -> Result<()> {
        if !self.authorized {
            return retire(conn, self.id, REVOKED, &JobState::Cancelled);
        }
        if self.expires <= now {
            return retire(conn, self.id, EXPIRED, &JobState::Expired);
        }
        let event = conn
            .query_row(
                "SELECT event, revision, reaction FROM change_events
             WHERE ref=?1 AND revision>?2 ORDER BY revision LIMIT 1",
                params![self.reference, self.cursor],
                |row| {
                    Ok((
                        Hash(row.get(0)?),
                        row.get::<_, i64>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )
            .optional()?;
        let before = event.map_or(self.latest, |(_, revision, _)| revision - 1);
        if before > self.cursor {
            conn.execute(
                "UPDATE subscriptions SET cursor=?2, missed=missed+(?2-cursor) WHERE id=?1",
                params![&self.id.0[..], before],
            )?;
        }
        let Some((event, revision, reaction)) = event else {
            return Ok(());
        };
        if reaction {
            conn.execute(
                "UPDATE subscriptions SET cursor=?2 WHERE id=?1",
                params![&self.id.0[..], revision],
            )?;
            return Ok(());
        }
        if !jobs::has_capacity(conn, holder, now as u64)? {
            return Ok(());
        }
        let input = Data::Record(BTreeMap::from([
            ("id".into(), Data::Text(event.to_string())),
            ("reference".into(), Data::Text(self.reference)),
            ("revision".into(), Data::Text(revision.to_string())),
        ]))
        .to_bytes()?;
        let key = JobKey {
            holder,
            id: Hash::digest(&protocol::encode(&(
                b"pp2 subscription delivery",
                self.id,
                event,
            ))?),
        };
        let graph = GraphJob {
            grant: self.entry_grant,
            program: self.program,
            mode: EvaluationMode::Read,
            input,
            budget: protocol::decode(&self.budget)?,
            expires_at_ms: (self.expires as u64).min(now as u64 + MAX_JOB_LIFETIME_MS),
            delegated_by: None,
            bindings: GraphBindings::Local(Vec::new()),
        };
        let capabilities: BTreeMap<String, Binding> = protocol::decode(&self.capabilities)?;
        let bindings = capabilities
            .into_iter()
            .map(|(name, binding)| {
                (
                    name,
                    BoundCapability {
                        binding,
                        delegated_by: None,
                    },
                )
            })
            .collect();
        let delivery = jobs::Delivery {
            subscription: self.id,
            event,
            revision,
        };
        jobs::enqueue(
            conn,
            key,
            key.id,
            graph,
            bindings,
            jobs::JobOrigin::Subscription(delivery),
            now as u64,
        )?;
        conn.execute(
            "UPDATE subscriptions SET scheduled=?2 WHERE id=?1",
            params![&self.id.0[..], now],
        )?;
        Ok(())
    }
}

pub(super) fn record_change(
    conn: &Connection,
    name: &str,
    revision: u64,
    reaction: bool,
) -> Result<()> {
    conn.execute(
        "INSERT INTO change_events(event, ref, revision, recorded, reaction)
         VALUES (randomblob(32), ?1, ?2, ?3, ?4)",
        params![name, revision as i64, unix_ms() as i64, reaction],
    )?;
    conn.execute(
        "DELETE FROM change_events WHERE seq<=last_insert_rowid()-?1",
        [MAX_EVENTS],
    )?;
    Ok(())
}

pub(super) fn check_subscription(conn: &Connection, id: Hash) -> Result<()> {
    if conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM subscription_authority WHERE id=?1)",
        [&id.0[..]],
        |row| row.get::<_, bool>(0),
    )? {
        Ok(())
    } else {
        Err(PeerError::Cancelled)
    }
}

pub(super) fn complete_delivery(conn: &Connection, key: JobKey, state: &JobState) -> Result<bool> {
    let delivery = conn
        .query_row(
            "SELECT subscription, event, event_revision FROM jobs
         WHERE holder=?1 AND id=?2 AND subscription IS NOT NULL",
            params![&key.holder.0[..], &key.id.0[..]],
            |row| Ok((Hash(row.get(0)?), Hash(row.get(1)?), row.get::<_, i64>(2)?)),
        )
        .optional()?;
    let Some((subscription, event, revision)) = delivery else {
        return Ok(false);
    };
    let (outcome, error) = match state {
        JobState::Completed { .. } => (DeliveryOutcome::Completed, None),
        JobState::Failed(error) => (
            DeliveryOutcome::Failed,
            Some(
                PeerError::from(error.clone())
                    .to_string()
                    .chars()
                    .take(512)
                    .collect(),
            ),
        ),
        JobState::Cancelled => (DeliveryOutcome::Cancelled, None),
        JobState::Expired => (DeliveryOutcome::Expired, None),
        _ => return Err(PeerError::Value("expected terminal delivery status".into())),
    };
    let status = DeliveryStatus {
        event_id: event.to_string(),
        revision: revision as u64,
        outcome,
        error,
    };
    conn.execute(
        "UPDATE subscriptions SET cursor=?2, outcome=?3 WHERE id=?1",
        params![&subscription.0[..], revision, protocol::encode(&status)?],
    )?;
    Ok(true)
}

pub(super) fn record_child_deadline(conn: &Connection, key: JobKey, expires: u64) -> Result<()> {
    conn.execute(
        "UPDATE applications SET drain_until=max(drain_until, ?3)
         WHERE name=(SELECT s.application FROM jobs j JOIN subscriptions s ON s.id=j.subscription
                     WHERE j.holder=?1 AND j.id=?2)",
        params![&key.holder.0[..], &key.id.0[..], expires as i64],
    )?;
    Ok(())
}

fn subscription_grant(
    conn: &Connection,
    holder: Hash,
    id: Hash,
    program: Hash,
) -> Result<Authority> {
    let grant = authority(conn, holder, id)?;
    if grant.program != Some(program)
        || grant.access != Access::Read
        || grant.graph.is_some()
        || grant.reaction_writer
    {
        return Err(PeerError::Denied);
    }
    Ok(grant)
}

pub(super) fn revoke_unauthorized(conn: &Connection) -> Result<()> {
    let ids = {
        let mut query = conn.prepare(
            "SELECT s.id FROM subscriptions s WHERE s.state=0
             AND NOT EXISTS(SELECT 1 FROM subscription_authority WHERE id=s.id)",
        )?;
        query
            .query_map([], |row| Ok(Hash(row.get(0)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for id in ids {
        retire(conn, id, REVOKED, &JobState::Cancelled)?;
    }
    Ok(())
}

fn retire(conn: &Connection, id: Hash, state: i64, outcome: &JobState) -> Result<()> {
    conn.execute(
        "UPDATE subscriptions SET state=?2 WHERE id=?1 AND state=?3",
        params![&id.0[..], state, ACTIVE],
    )?;
    let job = conn
        .query_row(
            "SELECT holder, id FROM jobs WHERE subscription=?1",
            [&id.0[..]],
            |row| {
                Ok(JobKey {
                    holder: Hash(row.get(0)?),
                    id: Hash(row.get(1)?),
                })
            },
        )
        .optional()?;
    if let Some(key) = job {
        jobs::end(conn, key, outcome)?;
    }
    Ok(())
}

fn unknown_application(name: &str) -> PeerError {
    PeerError::Value(format!("unknown application {name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::JavaScript;

    const HOLDER: Hash = Hash([1; 32]);

    fn installed() -> (PeerStore, Hash) {
        let mut store = PeerStore::open(":memory:").unwrap();
        store.create_ref("stock", &Data::Int(0)).unwrap();
        store.create_collection("context", []).unwrap();
        let program = store
            .put(
                &JavaScript {
                    source: "export default (_, event) => event;".into(),
                    imports: Default::default(),
                }
                .to_bytes()
                .unwrap(),
            )
            .unwrap();
        let watch = store
            .issue("stock", HOLDER, Access::Read, Some(program))
            .unwrap();
        let entry = store
            .issue("context", HOLDER, Access::Read, Some(program))
            .unwrap();
        store
            .install_application(
                HOLDER,
                ApplicationSpec {
                    name: "inventory".into(),
                    subscriptions: BTreeMap::from([(
                        "watch".into(),
                        SubscriptionSpec {
                            program,
                            watch_grant: watch,
                            entry_grant: Some(entry),
                            budget: GraphBudget {
                                timeout_ms: 1000,
                                calls: 1,
                                depth: 1,
                            },
                            capabilities: BTreeMap::new(),
                            expires_at_ms: unix_ms() + 300_000,
                        },
                    )]),
                },
            )
            .unwrap();
        (store, watch)
    }

    #[test]
    fn change_and_revision_commit_together_and_retention_accounts_for_gaps() {
        let (mut store, _) = installed();
        store
            .0
            .execute_batch(
                "CREATE TRIGGER fail_event BEFORE INSERT ON change_events
             BEGIN SELECT raise(ABORT, 'event write failed'); END;",
            )
            .unwrap();
        assert!(store.replace_ref("stock", 0, Data::Int(1)).is_err());
        assert_eq!(store.read_ref("stock").unwrap().unwrap().1, Data::Int(0));
        assert_eq!(store.reference("stock").unwrap().unwrap().number, 0);
        store.0.execute_batch("DROP TRIGGER fail_event;").unwrap();

        store.replace_ref("stock", 0, Data::Int(1)).unwrap();
        store.replace_ref("stock", 1, Data::Int(2)).unwrap();
        store
            .0
            .execute(
                "UPDATE change_events SET recorded=0 WHERE ref='stock' AND revision=1",
                [],
            )
            .unwrap();
        store.schedule_subscriptions(HOLDER).unwrap();
        let first = store.claim_job(HOLDER).unwrap().unwrap();
        let pending = store.application_status("inventory").unwrap();
        assert_eq!(pending.subscriptions["watch"].cursor, 1);
        assert_eq!(pending.subscriptions["watch"].missed, 1);
        assert_eq!(pending.subscriptions["watch"].pending_revision, Some(2));

        store.recover_jobs().unwrap();
        let recovered = store.claim_job(HOLDER).unwrap().unwrap();
        assert_eq!(first.key.id, recovered.key.id);
        assert_eq!(first.graph.input, recovered.graph.input);
        store
            .finish_job(
                recovered.key,
                None,
                JobOutcome::Finished(JobState::Failed(protocol::Failure::Guest(
                    "delivery failed".into(),
                ))),
            )
            .unwrap();
        let done = store.application_status("inventory").unwrap();
        assert_eq!(done.subscriptions["watch"].cursor, 2);
        assert_eq!(
            done.subscriptions["watch"]
                .last_delivery
                .as_ref()
                .unwrap()
                .outcome,
            DeliveryOutcome::Failed
        );
        assert!(store.claim_job(HOLDER).unwrap().is_none());
    }

    #[test]
    fn owner_revocation_cancels_queued_work_and_removal_tracks_remote_deadlines() {
        let (mut store, watch) = installed();
        store.replace_ref("stock", 0, Data::Int(1)).unwrap();
        store.schedule_subscriptions(HOLDER).unwrap();
        let queued = store.claim_job(HOLDER).unwrap().unwrap();
        let expires = unix_ms() + 60_000;
        record_child_deadline(&store.0, queued.key, expires).unwrap();

        assert!(store.revoke(watch).unwrap());
        assert!(matches!(
            store.check_job(queued.key),
            Err(PeerError::Cancelled)
        ));
        let status = store.application_status("inventory").unwrap();
        assert_eq!(
            status.subscriptions["watch"].state,
            SubscriptionState::Revoked
        );
        assert_eq!(
            status.subscriptions["watch"]
                .last_delivery
                .as_ref()
                .unwrap()
                .outcome,
            DeliveryOutcome::Cancelled
        );

        store.remove_application("inventory").unwrap();
        let removing = store.application_status("inventory").unwrap();
        assert_eq!(removing.state, ApplicationState::Removing);
        assert_eq!(removing.drain_until_ms, Some(expires));
        store
            .0
            .execute("UPDATE applications SET drain_until=0", [])
            .unwrap();
        assert_eq!(
            store.application_status("inventory").unwrap().state,
            ApplicationState::Removed
        );
        store.replace_ref("stock", 1, Data::Int(2)).unwrap();
        store.schedule_subscriptions(HOLDER).unwrap();
        assert!(store.claim_job(HOLDER).unwrap().is_none());
    }

    #[test]
    fn removal_cancels_a_running_handler_without_requiring_its_grants_to_be_revoked() {
        let (mut store, watch) = installed();
        store.replace_ref("stock", 0, Data::Int(1)).unwrap();
        store.schedule_subscriptions(HOLDER).unwrap();
        let running = store.claim_job(HOLDER).unwrap().unwrap();

        store.remove_application("inventory").unwrap();
        assert!(matches!(
            store.check_job(running.key),
            Err(PeerError::Cancelled)
        ));
        assert!(authority(&store.0, HOLDER, watch).is_ok());
        let removed = store.application_status("inventory").unwrap();
        let subscription = &removed.subscriptions["watch"];
        assert_eq!(removed.state, ApplicationState::Removed);
        assert_eq!(subscription.state, SubscriptionState::Revoked);
        assert_eq!(subscription.pending_revision, None);
        assert_eq!(
            subscription.last_delivery.as_ref().unwrap().outcome,
            DeliveryOutcome::Cancelled
        );
    }
}
