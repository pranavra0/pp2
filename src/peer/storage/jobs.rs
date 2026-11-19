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
    ) -> Result<Option<JobState>> {
        let Some((actual, state)) = job(&self.0, key)? else {
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
        if let Some((actual, state)) = job(&tx, key)? {
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
        let (count, owned): (u32, u32) = tx.query_row(
            "SELECT count(*), count(CASE WHEN holder=?1 THEN 1 END)
             FROM jobs WHERE state<2 AND expires>?2",
            params![&key.holder.0[..], now as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count >= MAX_ACTIVE || owned >= MAX_PER_HOLDER {
            return Err(PeerError::Limit("active jobs"));
        }
        let input = Block::Data(Data::from_bytes(&graph.input)?).to_bytes()?;
        let input_hash = Hash::digest(&input);
        insert(&tx, input_hash, &input)?;
        let spec = Specification {
            grant: graph.grant,
            mode: graph.mode,
            delegated_by: graph.delegated_by,
            budget: graph.budget,
            bindings,
        };
        tx.execute(
            "INSERT INTO jobs VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, NULL)",
            params![
                &key.holder.0[..],
                &key.id.0[..],
                &request.0[..],
                &graph.program.0[..],
                &input_hash.0[..],
                graph.expires_at_ms as i64,
                now as i64,
                protocol::encode(&spec)?
            ],
        )?;
        for (hash, bytes) in code {
            insert(&tx, *hash, bytes)?;
        }
        for hash in [input_hash, graph.program] {
            tx.execute(
                "INSERT INTO job_blocks VALUES (?1, ?2, ?3)",
                params![&key.holder.0[..], &key.id.0[..], &hash.0[..]],
            )?;
        }
        tx.commit()?;
        Ok(JobState::Pending)
    }

    pub(in crate::peer) fn job_status(&self, key: JobKey) -> Result<JobState> {
        job(&self.0, key)?
            .map(|(_, state)| state)
            .ok_or(PeerError::Denied)
    }

    pub(in crate::peer) fn cancel_job(&mut self, key: JobKey) -> Result<JobState> {
        let tx = self.0.transaction_with_behavior(Immediate)?;
        let (_, state) = job(&tx, key)?.ok_or(PeerError::Denied)?;
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

    pub(in crate::peer) fn claim_job(&mut self) -> Result<Option<QueuedJob>> {
        let now = unix_ms() as i64;
        if !self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE state=0 AND ready<=?1)
                 OR EXISTS(SELECT 1 FROM jobs WHERE state<2 AND expires<=?1)",
            [now],
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
                "SELECT holder, id, expires, program, input, spec FROM jobs
             WHERE state=0 AND ready<=?1 AND expires>?1 ORDER BY ready, holder, id LIMIT 1",
                [now],
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
                    ))
                },
            )
            .optional()?;
        let Some((key, expires, program, input_hash, spec)) = candidate else {
            tx.commit()?;
            return Ok(None);
        };
        let spec: Specification = protocol::decode(&spec)?;
        let input = get(&tx, input_hash, false)?.ok_or(PeerError::Missing(input_hash))?;
        let Block::Data(input) = Block::from_bytes(&input)? else {
            return Err(PeerError::Value("expected durable input block".into()));
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
                input: input.to_bytes()?,
                budget: spec.budget,
                expires_at_ms: expires as u64,
                delegated_by: spec.delegated_by,
                bindings: GraphBindings::Local(Vec::new()),
            },
            bindings: spec.bindings,
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
                if let Some(call) = call
                    && let Err(error) = authorize(&tx, call)
                {
                    result = JobState::Failed(error.into());
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
        &self,
        key: JobKey,
        ordinal: u16,
        child: &(Hash, Submission),
    ) -> Result<()> {
        self.0.execute(
            "UPDATE job_effects SET child=?4 WHERE holder=?1 AND id=?2 AND ordinal=?3 AND child IS NULL",
            params![&key.holder.0[..], &key.id.0[..], ordinal, protocol::encode(child)?],
        )?;
        self.check_job(key)
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

fn job(conn: &Connection, key: JobKey) -> Result<Option<(Hash, JobState)>> {
    conn.query_row(
        "SELECT request, state, expires, result FROM jobs WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
        |row| {
            Ok((
                Hash(row.get(0)?),
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        },
    )
    .optional()?
    .map(|(request, state, expires, result)| {
        let state = match state {
            TERMINAL => protocol::decode(
                &result.ok_or_else(|| PeerError::Value("missing job result".into()))?,
            )?,
            _ if expires as u64 <= unix_ms() => JobState::Expired,
            PENDING => JobState::Pending,
            _ => JobState::Running,
        };
        Ok((request, state))
    })
    .transpose()
}

pub(super) fn check_running(conn: &Connection, key: JobKey) -> Result<u64> {
    let (state, expires): (i64, i64) = conn.query_row(
        "SELECT state, expires FROM jobs WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if state != RUNNING {
        return Err(PeerError::Cancelled);
    }
    if expires as u64 <= unix_ms() {
        return Err(PeerError::Timeout);
    }
    Ok(expires as u64)
}

pub(super) fn end(conn: &Connection, key: JobKey, outcome: &JobState) -> Result<()> {
    conn.execute(
        "UPDATE jobs SET state=2, spec=NULL, result=?3 WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..], protocol::encode(outcome)?],
    )?;
    conn.execute(
        "DELETE FROM job_blocks WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
    )?;
    conn.execute(
        "DELETE FROM job_effects WHERE holder=?1 AND id=?2",
        params![&key.holder.0[..], &key.id.0[..]],
    )?;
    Ok(())
}
