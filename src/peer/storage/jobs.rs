use std::collections::BTreeMap;

use super::*;
use crate::peer::{
    effects::{BoundCapability, GraphBindings, GraphJob, MAX_JOB_LIFETIME_MS},
    protocol::{EvaluationMode, JobState, Submission},
};

const MAX_ACTIVE: u32 = 64;
const MAX_PER_HOLDER: u32 = 32;
const PENDING: i64 = 0;
const RUNNING: i64 = 1;
const TERMINAL: i64 = 2;

#[derive(Clone, Copy)]
pub(in crate::peer) struct JobKey {
    pub(in crate::peer) holder: Hash,
    pub(in crate::peer) id: Hash,
}

#[derive(Deserialize, Serialize)]
struct Specification {
    grant: Hash,
    mode: EvaluationMode,
    delegated_by: Option<Hash>,
    budget: GraphBudget,
    bindings: BTreeMap<String, BoundCapability>,
}

pub(in crate::peer) struct QueuedJob {
    pub(in crate::peer) key: JobKey,
    pub(in crate::peer) graph: GraphJob,
    pub(in crate::peer) bindings: BTreeMap<String, BoundCapability>,
    pub(in crate::peer) reaction: bool,
}

pub(super) struct Delivery {
    pub(super) subscription: Hash,
    pub(super) event: Hash,
    pub(super) revision: i64,
}

pub(super) enum JobOrigin {
    Client,
    Reaction,
    Subscription(Delivery),
}

#[derive(Clone)]
pub(in crate::peer) enum JobOutcome {
    Retry,
    Finished(JobState),
}

pub(in crate::peer) struct RemoteIntent {
    pub(in crate::peer) expires_at_ms: u64,
    pub(in crate::peer) child: Option<(Hash, Submission)>,
    pub(in crate::peer) result: Option<JobState>,
}

impl PeerStore {
    pub(in crate::peer) fn existing_job(
        &self,
        key: JobKey,
        request: Hash,
        executor: Option<Hash>,
    ) -> Result<Option<JobState>> {
        let tx = self.0.unchecked_transaction()?;
        let Some((actual, state)) = job(&tx, key, executor)? else {
            return Ok(None);
        };
        if actual != request {
            return Err(PeerError::Value(
                "job ID already used for a different submission".into(),
            ));
        }
        Ok(Some(state))
    }

    pub(in crate::peer) fn submit(
        &mut self,
        key: JobKey,
        request: Hash,
        call: Call,
        graph: GraphJob,
        bindings: BTreeMap<String, BoundCapability>,
        code: &[(Hash, Vec<u8>)],
    ) -> Result<JobState> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        if let Some((actual, state)) = job(&tx, key, call.executor)? {
            return if actual == request {
                Ok(state)
            } else {
                Err(PeerError::Value(
                    "job ID already used for a different submission".into(),
                ))
            };
        }
        let now = unix_ms();
        if graph.expires_at_ms <= now {
            return Err(PeerError::Timeout);
        }
        if graph.expires_at_ms - now > MAX_JOB_LIFETIME_MS {
            return Err(PeerError::Limit("job lifetime"));
        }
        let authority = authorize(&tx, call)?;
        require_kind(&tx, &authority.reference, true)?;
        if !has_capacity(&tx, key.holder, now)? {
            return Err(if call.reaction {
                PeerError::Busy
            } else {
                PeerError::Limit("active jobs")
            });
        }
        for (hash, bytes) in code {
            insert(&tx, *hash, bytes)?;
        }
        let origin = if call.reaction {
            JobOrigin::Reaction
        } else {
            JobOrigin::Client
        };
        enqueue(&tx, key, request, graph, bindings, origin, now)?;
        tx.commit()?;
        Ok(JobState::Pending)
    }

    pub(in crate::peer) fn job_status(
        &self,
        key: JobKey,
        executor: Option<Hash>,
    ) -> Result<JobState> {
        let tx = self.0.unchecked_transaction()?;
        job(&tx, key, executor)?
            .map(|(_, state)| state)
            .ok_or(PeerError::Denied)
    }

    pub(in crate::peer) fn cancel_job(
        &mut self,
        key: JobKey,
        executor: Option<Hash>,
    ) -> Result<JobState> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let (_, state) = job(&tx, key, executor)?.ok_or(PeerError::Denied)?;
        let state = match state {
            JobState::Pending | JobState::Running => {
                end(&tx, key, &JobState::Cancelled)?;
                JobState::Cancelled
            }
            other => other,
        };
        tx.commit()?;
        Ok(state)
    }

    pub(in crate::peer) fn recover_jobs(&self) -> Result<()> {
        self.0
            .execute("UPDATE jobs SET state=0 WHERE state=1", [])?;
        Ok(())
    }

    pub(in crate::peer) fn claim_job(&mut self, identity: Hash) -> Result<Option<QueuedJob>> {
        let now = unix_ms() as i64;
        if !self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE state=0 AND ready<=?1
                           AND (subscription IS NULL OR holder=?2))
                 OR EXISTS(SELECT 1 FROM jobs WHERE state<2 AND expires<=?1)",
            params![now, &identity.0[..]],
            |row| row.get::<_, bool>(0),
        )? {
            return Ok(None);
        }
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let expired: Vec<JobKey> = {
            let mut query =
                tx.prepare("SELECT holder, id FROM jobs WHERE state<2 AND expires<=?1 LIMIT 64")?;
            query
                .query_map([now], |row| {
                    Ok(JobKey {
                        holder: Hash(row.get(0)?),
                        id: Hash(row.get(1)?),
                    })
                })?
                .collect::<std::result::Result<_, _>>()?
        };
        for key in expired {
            end(&tx, key, &JobState::Expired)?;
        }
        let candidate = tx
            .query_row(
                "SELECT holder, id, expires, program, input, spec, reaction,
                        reaction_input FROM jobs
             WHERE state=0 AND ready<=?1 AND expires>?1 AND (subscription IS NULL OR holder=?2)
             ORDER BY ready, holder, id LIMIT 1",
                params![now, &identity.0[..]],
                |row| {
                    Ok((
                        JobKey {
                            holder: Hash(row.get(0)?),
                            id: Hash(row.get(1)?),
                        },
                        row.get::<_, i64>(2)?,
                        Hash(row.get(3)?),
                        Hash(row.get(4)?),
                        row.get::<_, Vec<u8>>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, Option<Vec<u8>>>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((key, expires, program, input_hash, spec, reaction, reaction_input)) = candidate
        else {
            tx.commit()?;
            return Ok(None);
        };
        let spec: Specification = protocol::decode(&spec)?;
        let input = match reaction_input {
            Some(input) => input,
            None => {
                let bytes = get(&tx, input_hash, false)?.ok_or(PeerError::Missing(input_hash))?;
                let Block::Data(input) = Block::from_bytes(&bytes)? else {
                    return Err(PeerError::Value("expected durable input block".into()));
                };
                input.to_bytes()?
            }
        };
        tx.execute(
            "UPDATE jobs SET state=1 WHERE holder=?1 AND id=?2",
            params![&key.holder.0[..], &key.id.0[..]],
        )?;
        tx.commit()?;
        Ok(Some(QueuedJob {
            key,
            graph: GraphJob {
                grant: spec.grant,
                program,
                mode: spec.mode,
                input,
                budget: spec.budget,
                expires_at_ms: expires as u64,
                delegated_by: spec.delegated_by,
                bindings: GraphBindings::Local(Vec::new()),
            },
            bindings: spec.bindings,
            reaction,
        }))
    }

    pub(in crate::peer) fn check_job(&self, key: JobKey) -> Result<()> {
        check_running(&self.0, key).map(|_| ())
    }

    pub(in crate::peer) fn finish_job(
        &mut self,
        key: JobKey,
        call: Option<Call>,
        outcome: JobOutcome,
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let expires = match check_running(&tx, key) {
            Err(PeerError::Cancelled | PeerError::Timeout) => return Ok(()),
            result => result?,
        };
        match outcome {
            JobOutcome::Retry => {
                tx.execute(
                    "UPDATE jobs SET state=0, ready=?3 WHERE holder=?1 AND id=?2",
                    params![&key.holder.0[..], &key.id.0[..], (unix_ms() + 100) as i64],
                )?;
            }
            JobOutcome::Finished(mut result) => {
                if let Some(call) = call {
                    let confirmed = authorize(&tx, call).and_then(|_| match &result {
                        JobState::ResourceCompleted { view, .. } => {
                            replicas::validate_release(&tx, view)
                        }
                        _ => Ok(()),
                    });
                    if let Err(error) = confirmed {
                        result = JobState::Failed(error.into());
                    }
                }
                end(&tx, key, &result)?;
            }
        }
        if expires <= unix_ms() {
            return Ok(());
        }
        tx.commit()?;
        Ok(())
    }

    pub(in crate::peer) fn job_intent(
        &mut self,
        key: JobKey,
        ordinal: u16,
        request: Hash,
        expires_at_ms: u64,
    ) -> Result<RemoteIntent> {
        // An existing intent is immutable. Insert happens before the first dispatch.
        let tx = self.0.transaction_with_behavior(Immediate)?;
        check_running(&tx, key)?;
        let intent = tx
            .query_row(
                "SELECT request, expires, child, result FROM job_effects
             WHERE holder=?1 AND id=?2 AND ordinal=?3",
                params![&key.holder.0[..], &key.id.0[..], ordinal],
                |row| {
                    Ok((
                        Hash(row.get(0)?),
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((actual, expires, child, result)) = intent {
            if actual != request {
                return Err(PeerError::Value(
                    "durable remote effect changed during recovery".into(),
                ));
            }
            return Ok(RemoteIntent {
                expires_at_ms: expires as u64,
                child: child.as_deref().map(protocol::decode).transpose()?,
                result: result.as_deref().map(protocol::decode).transpose()?,
            });
        }
        tx.execute(
            "INSERT INTO job_effects VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL)",
            params![
                &key.holder.0[..],
                &key.id.0[..],
                ordinal,
                &request.0[..],
                expires_at_ms as i64
            ],
        )?;
        tx.commit()?;
        Ok(RemoteIntent {
            expires_at_ms,
            child: None,
            result: None,
        })
    }

    pub(in crate::peer) fn save_job_child(
        &mut self,
        key: JobKey,
        ordinal: u16,
        child: &(Hash, Submission),
    ) -> Result<()> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        check_running(&tx, key)?;
        let inserted = tx.execute(
            "UPDATE job_effects SET child=?4 WHERE holder=?1 AND id=?2 AND ordinal=?3 AND child IS NULL",
            params![&key.holder.0[..], &key.id.0[..], ordinal, protocol::encode(child)?],
        )?;
        if inserted != 0 {
            applications::record_child_deadline(&tx, key, child.1.graph.expires_at_ms)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(in crate::peer) fn save_job_effect(
        &self,
        key: JobKey,
        ordinal: u16,
        result: &JobState,
    ) -> Result<()> {
        self.0.execute(
            "UPDATE job_effects SET result=?4 WHERE holder=?1 AND id=?2 AND ordinal=?3 AND result IS NULL",
            params![&key.holder.0[..], &key.id.0[..], ordinal, protocol::encode(result)?],
        )?;
        self.check_job(key)
    }

    pub(in crate::peer) fn check_job_effects(&self, key: JobKey, observed: u16) -> Result<()> {
        let extra: bool = self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM job_effects WHERE holder=?1 AND id=?2 AND ordinal>?3)",
            params![&key.holder.0[..], &key.id.0[..], observed],
            |row| row.get(0),
        )?;
        if extra {
            return Err(PeerError::Value(
                "durable remote effect skipped during recovery".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn has_capacity(conn: &Connection, holder: Hash, now: u64) -> Result<bool> {
    let (count, owned): (u32, u32) = conn.query_row(
        "SELECT count(*), count(CASE WHEN holder=?1 THEN 1 END)
         FROM jobs WHERE state<2 AND expires>?2",
        params![&holder.0[..], now as i64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(count < MAX_ACTIVE && owned < MAX_PER_HOLDER)
}

pub(super) fn enqueue(
    conn: &Connection,
    key: JobKey,
    request: Hash,
    graph: GraphJob,
    bindings: BTreeMap<String, BoundCapability>,
    origin: JobOrigin,
    now: u64,
) -> Result<()> {
    let reaction = !matches!(origin, JobOrigin::Client);
    let delivery = match origin {
        JobOrigin::Subscription(delivery) => Some(delivery),
        _ => None,
    };
    let input = Block::Data(Data::from_bytes(&graph.input)?).to_bytes()?;
    let input_hash = Hash::digest(&input);
    if !reaction {
        insert(conn, input_hash, &input)?;
    }
    let spec = Specification {
        grant: graph.grant,
        mode: graph.mode,
        delegated_by: graph.delegated_by,
        budget: graph.budget,
        bindings,
    };
    conn.execute(
        "INSERT INTO jobs (holder, id, request, program, input, expires, ready, state, spec,
                           reaction, subscription, event, event_revision, reaction_input, replica_grant)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11, ?12, ?13,
            (SELECT grants.id FROM grants JOIN replicas USING(ref) WHERE grants.id=?14))",
        params![
            &key.holder.0[..],
            &key.id.0[..],
            &request.0[..],
            &graph.program.0[..],
            &input_hash.0[..],
            graph.expires_at_ms as i64,
            now as i64,
            protocol::encode(&spec)?,
            reaction,
            delivery.as_ref().map(|d| &d.subscription.0[..]),
            delivery.as_ref().map(|d| &d.event.0[..]),
            delivery.as_ref().map(|d| d.revision),
            reaction.then_some(graph.input),
            &graph.grant.0[..],
        ],
    )?;
    for hash in [Some(graph.program), (!reaction).then_some(input_hash)]
        .into_iter()
        .flatten()
    {
        conn.execute(
            "INSERT INTO job_blocks VALUES (?1, ?2, ?3)",
            params![&key.holder.0[..], &key.id.0[..], &hash.0[..]],
        )?;
    }
    Ok(())
}

fn job(conn: &Connection, key: JobKey, executor: Option<Hash>) -> Result<Option<(Hash, JobState)>> {
    conn.query_row(
        "SELECT request, state, expires, result, replica_grant, program FROM jobs WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
        |row| {
            Ok((
                Hash(row.get(0)?),
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, Option<[u8; 32]>>(4)?.map(Hash),
                Hash(row.get(5)?),
            ))
        },
    )
    .optional()?
    .map(|(request, state, expires, result, grant, program)| {
        if let Some(grant) = grant {
            let scope = authority(conn, key.holder, grant)?;
            replicas::authorize_executor(conn, &scope.reference, executor)?;
            replicas::authorize_view(conn, &scope.reference, key.holder, Some(program), Access::Read)?;
        }
        let state = match state {
            TERMINAL => protocol::decode(
                &result.ok_or_else(|| PeerError::Value("missing job result".into()))?,
            )?,
            _ if expires as u64 <= unix_ms() => JobState::Expired,
            PENDING => JobState::Pending,
            _ => JobState::Running,
        };
        if let JobState::ResourceCompleted { view, .. } = &state {
            replicas::validate_release(conn, view)?;
        }
        Ok((request, state))
    })
    .transpose()
}

pub(super) fn check_running(conn: &Connection, key: JobKey) -> Result<u64> {
    let job = conn
        .query_row(
            "SELECT j.state, j.expires, j.subscription FROM jobs j WHERE j.holder=?1 AND j.id=?2",
            params![&key.holder.0[..], &key.id.0[..]],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Option<[u8; 32]>>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((RUNNING, expires, subscription)) = job else {
        return Err(PeerError::Cancelled);
    };
    if expires <= unix_ms() {
        return Err(PeerError::Timeout);
    }
    if let Some(id) = subscription {
        applications::check_subscription(conn, Hash(id))?;
    }
    Ok(expires)
}

pub(super) fn end(conn: &Connection, key: JobKey, outcome: &JobState) -> Result<()> {
    let delivered = applications::complete_delivery(conn, key, outcome)?;
    conn.execute(
        "DELETE FROM job_blocks WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
    )?;
    conn.execute(
        "DELETE FROM job_effects WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
    )?;
    if delivered {
        conn.execute(
            "DELETE FROM jobs WHERE holder=?1 AND id=?2",
            params![&key.holder.0[..], &key.id.0[..]],
        )?;
    } else {
        conn.execute(
            "UPDATE jobs SET state=2, spec=NULL, result=?3, reaction_input=NULL WHERE holder=?1 AND id=?2",
            params![&key.holder.0[..], &key.id.0[..], protocol::encode(outcome)?],
        )?;
    }
    Ok(())
}
