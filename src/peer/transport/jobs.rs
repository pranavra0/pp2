use std::{
    cell::{Cell, RefCell},
    rc::Rc,
    sync::atomic::AtomicBool,
};

use super::*;
use crate::peer::{
    Binding, GraphBudget, GraphMetrics,
    effects::{self, GraphBindings, GraphJob, MAX_JOB_LIFETIME_MS},
    protocol::{JobState, Submission},
    storage::{JobKey, JobOutcome, QueuedJob},
};

pub(super) const WORKERS: usize = 4;
const POLL: Duration = Duration::from_millis(50);

/// An immutable submission. Reuse the same ID and arguments after an ambiguous reply.
pub struct DurableEvaluation<'a> {
    pub id: Hash,
    /// Unix time in milliseconds. A new job may live for up to five minutes.
    pub expires_at_ms: u64,
    pub graph: GraphEvaluation<'a>,
}

#[derive(Debug)]
pub enum JobStatus {
    Pending,
    Running,
    Completed {
        revision: u64,
        value: Data,
        graph: GraphMetrics,
    },
    Failed(PeerError),
    Cancelled,
    Expired,
}

impl TryFrom<JobState> for JobStatus {
    type Error = PeerError;
    fn try_from(state: JobState) -> Result<Self> {
        Ok(match state {
            JobState::Pending => Self::Pending,
            JobState::Running => Self::Running,
            JobState::Completed {
                revision,
                value,
                graph,
            } => {
                effects::check_response(&value)?;
                Self::Completed {
                    revision,
                    value: Data::from_bytes(&value)?,
                    graph,
                }
            }
            JobState::Failed(error) => Self::Failed(error.into()),
            JobState::Cancelled => Self::Cancelled,
            JobState::Expired => Self::Expired,
        })
    }
}

impl Client {
    /// Waits for durable acceptance. Execution continues independently of this connection.
    pub fn submit_job(&self, submission: DurableEvaluation<'_>) -> Result<JobStatus> {
        let names = submission.graph.bindings.to_vec();
        self.submit_with_bindings(submission, GraphBindings::Local(names))
    }

    /// Submits a job with recipient-bound grants obtained from their issuing peers.
    pub fn submit_delegated_job(
        &self,
        submission: DurableEvaluation<'_>,
        bindings: BTreeMap<String, Binding>,
    ) -> Result<JobStatus> {
        if !submission.graph.bindings.is_empty() {
            return Err(PeerError::Value(
                "choose one source of job capabilities".into(),
            ));
        }
        effects::validate_binding_names(&bindings.keys().cloned().collect::<Vec<_>>())?;
        self.submit_with_bindings(submission, GraphBindings::Forwarded(bindings))
    }

    fn submit_with_bindings(
        &self,
        submission: DurableEvaluation<'_>,
        bindings: GraphBindings,
    ) -> Result<JobStatus> {
        let DurableEvaluation {
            id,
            expires_at_ms,
            graph,
        } = submission;
        graph.budget.validate()?;
        effects::validate_binding_names(graph.bindings)?;
        let program = graph.evaluation.program;
        let job = Submission {
            id,
            graph: GraphJob {
                grant: graph.evaluation.grant,
                program,
                mode: graph.evaluation.mode,
                input: graph.evaluation.input.to_bytes()?,
                budget: graph.budget,
                expires_at_ms,
                delegated_by: None,
                bindings,
            },
        };
        job_reply(self.exchange_program(
            program,
            Request::Submit(job),
            Activity::new(Instant::now() + DEADLINE),
            None,
            &mut graph::Traffic::default(),
            |hash| {
                graph
                    .evaluation
                    .packages
                    .map(|store| store.get(hash))
                    .transpose()
                    .map(Option::flatten)
            },
        )?)?
        .try_into()
    }

    /// Reads the status or the result of a job submitted under this certificate.
    pub fn job_status(&self, id: Hash) -> Result<JobStatus> {
        self.job_control(Request::JobStatus(id))
    }

    /// Cancels pending or running work. A completion that won the race is returned unchanged.
    pub fn cancel_job(&self, id: Hash) -> Result<JobStatus> {
        self.job_control(Request::CancelJob(id))
    }

    fn job_control(&self, request: Request) -> Result<JobStatus> {
        let mut stream = self.connect(Instant::now())?;
        protocol::send(&mut stream, &request)?;
        job_reply(protocol::receive::<Reply>(&mut stream)?.0)?.try_into()
    }
}

pub(super) fn job_reply(reply: Reply) -> Result<JobState> {
    match reply {
        Reply::Job(state) => Ok(state),
        Reply::Failed(error) => Err(error.into()),
        _ => Err(unexpected_reply()),
    }
}

pub(super) struct Attempt {
    pub(super) key: JobKey,
    pub(super) store: RefCell<PeerStore>,
    pub(super) effects: Cell<u16>,
    failure: RefCell<Option<PeerError>>,
}

impl Attempt {
    fn new(key: JobKey, store: PeerStore) -> Self {
        Self {
            key,
            store: RefCell::new(store),
            effects: Cell::new(0),
            failure: RefCell::new(None),
        }
    }

    pub(super) fn interrupt(&self, error: PeerError) {
        self.failure.replace(Some(error));
    }

    pub(super) fn check(&self) -> Result<()> {
        if self.failure.borrow().is_some() {
            return Err(PeerError::Cancelled);
        }
        self.store.borrow().check_job(self.key)
    }

    pub(super) fn check_effects(&self) -> Result<()> {
        self.store
            .borrow()
            .check_job_effects(self.key, self.effects.get())
    }
}

impl Server {
    pub(super) fn submit_job(
        &self,
        stream: &mut StreamOwned<ServerConnection, Socket>,
        store: &mut PeerStore,
        holder: Hash,
        submission: Submission,
        reaction: bool,
    ) -> Result<Reply> {
        let key = JobKey {
            holder,
            id: submission.id,
        };
        let job = submission.graph;
        let request = if reaction {
            Hash::digest(&protocol::encode(&(b"pp2 reaction", &job))?)
        } else {
            Hash::digest(&protocol::encode(&job)?)
        };
        if let Some(state) = store.existing_job(key, request)? {
            return Ok(Reply::Job(state));
        }
        let remaining = job.expires_at_ms.saturating_sub(unix_ms());
        if remaining == 0 {
            return Err(PeerError::Timeout);
        }
        if remaining > MAX_JOB_LIFETIME_MS {
            return Err(PeerError::Limit("job lifetime"));
        }
        let call = job.call(holder, reaction)?;
        store.confirm_collection(call)?;
        let bindings = self.graph.resolve(call, job.bindings.clone())?;
        let code = receive_code(stream, store, call)?;
        if !code[0].1.starts_with(content::MAGIC) {
            return Err(PeerError::Value(
                "graph evaluation requires JavaScript".into(),
            ));
        }
        store
            .submit(key, request, call, job, bindings, &code)
            .map(Reply::Job)
    }

    pub(super) fn schedule_applications(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            if let Ok(mut store) = PeerStore::open_with_timeout(&self.database, POLL) {
                while !stop.load(Ordering::Relaxed) {
                    if store.schedule_subscriptions(self.identity).is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            }
            thread::sleep(POLL);
        }
    }

    pub(super) fn work_jobs(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            if self.work_job(stop).is_err() {
                thread::sleep(POLL);
            }
        }
    }

    fn work_job(&self, stop: &AtomicBool) -> Result<()> {
        let mut store = PeerStore::open_with_timeout(&self.database, POLL)?;
        while !stop.load(Ordering::Relaxed) {
            let Some(job) = store.claim_job(self.identity)? else {
                thread::sleep(POLL);
                continue;
            };
            let key = job.key;
            let (mut outcome, call) = self.run_job(&mut store, job);
            while let Err(error) = store.finish_job(key, call, outcome.clone()) {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                if retryable(&error) {
                    thread::sleep(POLL);
                    continue;
                }
                // A smaller failure record can still fit after a result exceeds the database quota.
                outcome = JobOutcome::Finished(JobState::Failed(error.into()));
                store.finish_job(key, None, outcome)?;
                break;
            }
        }
        Ok(())
    }

    fn run_job(&self, store: &mut PeerStore, job: QueuedJob) -> (JobOutcome, Option<Call>) {
        let QueuedJob {
            key,
            graph,
            bindings,
            reaction,
        } = job;
        let mut call = None;
        let mut watch = None;
        let run = || -> Result<JobState> {
            let invocation = graph.call(key.holder, reaction)?;
            call = Some(invocation);
            store.confirm_collection(invocation)?;
            let attempt = Rc::new(Attempt::new(
                key,
                PeerStore::open_with_timeout(&self.database, POLL)?,
            ));
            watch = Some(attempt.clone());
            let remaining = graph.expires_at_ms.saturating_sub(unix_ms());
            let mut active = Activity::new(
                Instant::now()
                    + Duration::from_millis(remaining.min(graph.budget.timeout_ms.into())),
            );
            active.job = Some(attempt.clone());
            active.check()?;
            let code = load_code(graph.program, false, |hash| store.get(hash))?;
            let (receipt, metrics) = self.execute_graph(
                store,
                invocation,
                code,
                graph.input,
                bindings,
                active,
                Some(&attempt),
            )?;
            Ok(JobState::Completed {
                revision: receipt.revision,
                value: receipt.value,
                graph: metrics,
            })
        };
        let result = run();
        let error = watch.and_then(|attempt| attempt.failure.take());
        let outcome = match error.map_or(result, Err) {
            Ok(state) => JobOutcome::Finished(state),
            Err(ref error) if retryable(error) => JobOutcome::Retry,
            Err(error) => JobOutcome::Finished(JobState::Failed(error.into())),
        };
        (outcome, call)
    }
}

pub(super) fn retryable(error: &PeerError) -> bool {
    match error {
        PeerError::Busy | PeerError::Io(_) => true,
        PeerError::Storage(error) => matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ),
        _ => false,
    }
}

pub(super) fn child_budget(mut budget: GraphBudget, timeout: Option<u16>) -> GraphBudget {
    if let Some(timeout) = timeout {
        budget.timeout_ms = budget.timeout_ms.min(timeout.into());
    }
    budget
}
