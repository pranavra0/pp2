use super::jobs::{self, Attempt};
use super::*;
use crate::peer::{
    Access, Binding, GraphBudget, GraphMetrics, PeerEndpoint,
    effects::{self, BoundCapability, Effect, GraphBindings, GraphJob, Remote, Scope},
    protocol::{Forward, JobState, Submission},
    storage::{GraphAccess, ScopedStart},
    unix_ms,
    worker::Guest,
};

type Inbound = StreamOwned<ServerConnection, Socket>;

pub struct GraphEvaluation<'a> {
    pub evaluation: Evaluation<'a>,
    pub budget: GraphBudget,
    /// Explicitly requested names from the host configuration for this caller and program.
    pub bindings: &'a [String],
}

#[derive(Debug)]
pub struct GraphReport {
    pub revision: u64,
    pub value: Data,
    pub elapsed_us: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub graph: GraphMetrics,
}

#[derive(Default)]
pub(super) struct Configuration {
    callers: BTreeMap<(Hash, Hash, Hash), BTreeMap<String, Binding>>,
    peers: BTreeMap<Hash, Client>,
}

impl Configuration {
    pub(super) fn new(
        creds: &Credentials,
        bindings: Vec<BindingSet>,
        endpoints: Vec<PeerEndpoint>,
    ) -> Result<Self> {
        let mut peers = BTreeMap::new();
        for endpoint in endpoints {
            let mut client = Client::new(endpoint.address, endpoint.name, creds)?;
            client.fingerprint = Some(endpoint.fingerprint);
            if peers.insert(endpoint.fingerprint, client).is_some() {
                return Err(PeerError::Value("repeated peer directory entry".into()));
            }
        }
        let mut callers = BTreeMap::new();
        for set in bindings {
            effects::validate_binding_names(&set.capabilities.keys().cloned().collect::<Vec<_>>())?;
            if set
                .capabilities
                .values()
                .any(|binding| !peers.contains_key(&binding.peer))
            {
                return Err(PeerError::Value(
                    "missing capability peer directory entry".into(),
                ));
            }
            if callers
                .insert((set.holder, set.grant, set.program), set.capabilities)
                .is_some()
            {
                return Err(PeerError::Value(
                    "repeated graph caller, grant and program".into(),
                ));
            }
        }
        Ok(Self { callers, peers })
    }

    pub(super) fn resolve(
        &self,
        call: Call,
        bindings: GraphBindings,
    ) -> Result<BTreeMap<String, BoundCapability>> {
        match bindings {
            GraphBindings::Local(names) => {
                effects::validate_binding_names(&names)?;
                let configured = self.callers.get(&(call.holder, call.grant, call.program));
                names
                    .into_iter()
                    .map(|name| {
                        let binding = configured
                            .and_then(|bindings| bindings.get(&name))
                            .ok_or(PeerError::Denied)?;
                        Ok((
                            name,
                            BoundCapability {
                                binding: binding.clone(),
                                delegated_by: None,
                            },
                        ))
                    })
                    .collect()
            }
            GraphBindings::Forwarded(bindings) => {
                effects::validate_binding_names(&bindings.keys().cloned().collect::<Vec<_>>())?;
                if !self.peers.contains_key(&call.holder)
                    || bindings
                        .values()
                        .any(|binding| !self.peers.contains_key(&binding.peer))
                {
                    return Err(PeerError::Denied);
                }
                Ok(bindings
                    .into_iter()
                    .map(|(name, binding)| {
                        (
                            name,
                            BoundCapability {
                                binding,
                                delegated_by: Some(call.holder),
                            },
                        )
                    })
                    .collect())
            }
        }
    }
}

impl Client {
    /// Runs JavaScript against one indexed reference with explicitly supplied capabilities.
    pub fn run_graph(
        &self,
        request: GraphEvaluation<'_>,
        cancellation: Option<&Cancellation>,
    ) -> Result<GraphReport> {
        let started = Instant::now();
        request.budget.validate()?;
        effects::validate_binding_names(request.bindings)?;
        let job = GraphJob {
            grant: request.evaluation.grant,
            program: request.evaluation.program,
            mode: request.evaluation.mode,
            input: request.evaluation.input.to_bytes()?,
            budget: request.budget,
            expires_at_ms: unix_ms() + u64::from(request.budget.timeout_ms),
            delegated_by: None,
            bindings: GraphBindings::Local(request.bindings.to_vec()),
        };
        let active =
            Activity::new(started + Duration::from_millis(u64::from(job.budget.timeout_ms)));
        let packages = request.evaluation.packages;
        let mut traffic = Traffic::default();
        let result = self.exchange_program(
            job.program,
            Request::Run(job),
            active,
            cancellation,
            &mut traffic,
            |hash| {
                packages
                    .map(|store| store.get(hash))
                    .transpose()
                    .map(Option::flatten)
            },
        );
        if result.is_err() && cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        let Reply::Graph {
            revision,
            value,
            metrics: graph,
        } = result?
        else {
            return Err(unexpected_reply());
        };
        effects::check_response(&value)?;
        Ok(GraphReport {
            revision,
            value: Data::from_bytes(&value)?,
            elapsed_us: started.elapsed().as_micros() as u64,
            request_bytes: traffic.sent,
            response_bytes: traffic.received,
            graph,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn exchange_program(
        &self,
        program: Hash,
        request: Request,
        active: Activity,
        cancellation: Option<&Cancellation>,
        traffic: &mut Traffic,
        mut get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
    ) -> Result<Reply> {
        if cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        active.check()?;
        let tcp = dial(self.endpoint, &active, cancellation)?;
        let _registration = cancellation
            .map(|handle| handle.register(&tcp))
            .transpose()?;
        let mut stream = self.handshake(tcp, active)?;
        traffic.sent += protocol::send(&mut stream, &request)?;
        let mut code = None;
        let mut requested = BTreeSet::new();
        loop {
            let (reply, bytes) = protocol::receive::<Reply>(&mut stream)?;
            traffic.received += bytes;
            match reply {
                Reply::NeedProgram(hash) => {
                    if requested.len() >= MAX_MODULES || !requested.insert(hash) {
                        return Err(PeerError::Protocol("invalid program negotiation".into()));
                    }
                    let code = match &mut code {
                        Some(code) => code,
                        None => code.insert(
                            load_code(program, true, &mut get)?
                                .into_iter()
                                .collect::<BTreeMap<_, _>>(),
                        ),
                    };
                    traffic.sent += protocol::send(&mut stream, &code.remove(&hash))?;
                }
                Reply::Graph { .. } | Reply::Job(_) => {
                    stream.sock.activity.check()?;
                    return Ok(reply);
                }
                Reply::Failed(error) => return Err(error.into()),
                _ => return Err(unexpected_reply()),
            }
        }
    }
}

// Use one in-flight connect with periodic liveness checks. Reopening the socket on
// each check would cancel legitimate connections on high-latency links.
#[cfg(target_os = "linux")]
pub(super) fn dial(
    endpoint: SocketAddr,
    active: &Activity,
    cancellation: Option<&Cancellation>,
) -> Result<TcpStream> {
    use std::os::fd::FromRawFd;

    let family = if endpoint.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket takes integer arguments and returns a new descriptor on success.
    let fd = unsafe {
        libc::socket(
            family,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: the descriptor is new, and this stream takes sole responsibility for closing it.
    let tcp = unsafe { TcpStream::from_raw_fd(fd) };
    fn connect<T>(fd: i32, address: &T) -> i32 {
        // SAFETY: callers pass the initialized sockaddr layout for the socket's address family.
        unsafe {
            libc::connect(
                fd,
                std::ptr::from_ref(address).cast(),
                size_of::<T>() as libc::socklen_t,
            )
        }
    }
    let status = match endpoint {
        SocketAddr::V4(address) => connect(
            fd,
            &libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: address.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                },
                sin_zero: [0; 8],
            },
        ),
        SocketAddr::V6(address) => connect(
            fd,
            &libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: address.port().to_be(),
                sin6_flowinfo: address.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: address.ip().octets(),
                },
                sin6_scope_id: address.scope_id(),
            },
        ),
    };
    if status != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error.into());
        }
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            active.check()?;
            if cancellation.is_some_and(Cancellation::requested) {
                return Err(PeerError::Cancelled);
            }
            let wait = active.remaining()?.as_millis().clamp(1, 25) as i32;
            // SAFETY: tcp holds the descriptor open and poll receives one initialized pollfd.
            match unsafe { libc::poll(&mut pollfd, 1, wait) } {
                ready if ready > 0 => {
                    if let Some(error) = tcp.take_error()? {
                        return Err(error.into());
                    }
                    break;
                }
                0 => {}
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error.into());
                    }
                }
            }
        }
    }
    active.check()?;
    tcp.set_nonblocking(false)?;
    Ok(tcp)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn dial(
    endpoint: SocketAddr,
    active: &Activity,
    _: Option<&Cancellation>,
) -> Result<TcpStream> {
    Ok(TcpStream::connect_timeout(&endpoint, active.remaining()?)?)
}

#[derive(Default)]
pub(super) struct Traffic {
    pub(super) sent: u64,
    pub(super) received: u64,
}

struct Invocation<'a> {
    server: &'a Server,
    routes: BTreeMap<String, BoundCapability>,
    packages: PeerStore,
    call: Call,
    metrics: GraphMetrics,
}

impl Invocation<'_> {
    fn peer(&self, fingerprint: Hash) -> Result<&Client> {
        self.server
            .graph
            .peers
            .get(&fingerprint)
            .ok_or(PeerError::Denied)
    }

    fn prepare(
        &mut self,
        remote: &Remote,
        budget: GraphBudget,
        expires_at_ms: u64,
        active: &Activity,
    ) -> Result<(Hash, GraphJob)> {
        let target = self.routes.get(&remote.target).ok_or(PeerError::Denied)?;
        let route = &target.binding;
        let mode = match remote.update {
            Some((expected_revision, operation)) if route.access == Access::Write => {
                EvaluationMode::Update {
                    expected_revision,
                    operation,
                }
            }
            Some(_) => return Err(PeerError::Denied),
            None => EvaluationMode::Read,
        };
        let mut bindings = BTreeMap::new();
        for name in &remote.delegate {
            let capability = self.routes.get(name).ok_or(PeerError::Denied)?;
            let source = &capability.binding;
            let limit = GraphBudget {
                timeout_ms: budget.timeout_ms,
                calls: budget.calls.saturating_sub(1),
                depth: budget.depth.saturating_sub(1),
            };
            let mut traffic = Traffic::default();
            let grant = self.peer(source.peer)?.forward(
                Forward {
                    grant: source.grant,
                    delegated_by: capability.delegated_by,
                    holder: route.peer,
                    access: source.access,
                    program: source.program,
                    limit,
                    expires_at_ms,
                },
                active.clone(),
                &mut traffic,
            );
            self.metrics.remote_request_bytes += traffic.sent;
            self.metrics.remote_response_bytes += traffic.received;
            bindings.insert(
                name.clone(),
                Binding {
                    grant: grant?,
                    ..source.clone()
                },
            );
        }
        let bindings = if bindings.is_empty() {
            GraphBindings::Local(Vec::new())
        } else {
            GraphBindings::Forwarded(bindings)
        };
        Ok((
            route.peer,
            GraphJob {
                grant: route.grant,
                program: route.program,
                mode,
                input: remote.input.clone(),
                budget,
                expires_at_ms,
                delegated_by: target.delegated_by,
                bindings,
            },
        ))
    }

    fn invoke(
        &mut self,
        remote: Remote,
        scope: &mut Scope,
        mut active: Activity,
    ) -> Result<Vec<u8>> {
        self.packages.confirm_collection(self.call)?;
        let mut budget = scope.allocate(&remote)?;
        if let Some(timeout) = remote.timeout_ms {
            active.deadline = active
                .deadline
                .min(Instant::now() + Duration::from_millis(timeout.into()));
        }
        let remaining = active.remaining()?.as_millis().max(1) as u32;
        budget.timeout_ms = remaining.min(budget.timeout_ms);
        let expiry = self.call.graph.expect("graph invocation").expires_at_ms;
        let expiry = remote
            .timeout_ms
            .map_or(expiry, |ms| expiry.min(unix_ms() + u64::from(ms)));
        let mut traffic = Traffic::default();
        self.metrics.remote_calls += 1;
        let result = (|| {
            let (peer, job) = self.prepare(&remote, budget, expiry, &active)?;
            match self.peer(peer)?.exchange_program(
                job.program,
                Request::Run(job),
                active,
                None,
                &mut traffic,
                |hash| self.packages.executable(self.call.holder, hash),
            )? {
                Reply::Graph {
                    revision,
                    value,
                    metrics,
                } => {
                    effects::check_response(&value)?;
                    Ok((revision, value, metrics))
                }
                _ => Err(unexpected_reply()),
            }
        })();
        self.metrics.remote_request_bytes += traffic.sent;
        self.metrics.remote_response_bytes += traffic.received;
        match result {
            Ok((revision, bytes, metrics)) => {
                self.metrics.add_descendant(metrics);
                remote_value(revision, &bytes)
            }
            Err(error) => {
                self.metrics.remote_failures += 1;
                Err(error)
            }
        }
    }

    fn invoke_durable(
        &mut self,
        remote: Remote,
        scope: &mut Scope,
        active: Activity,
        attempt: &Attempt,
    ) -> Result<Vec<u8>> {
        self.packages.confirm_collection(self.call)?;
        let budget = jobs::child_budget(scope.allocate(&remote)?, remote.timeout_ms);
        self.metrics.remote_calls += 1;
        let ordinal = attempt.effects.get() + 1;
        attempt.effects.set(ordinal);
        let result = self.durable_effect(&remote, budget, &active, attempt, ordinal);
        let state = match result {
            Ok(state) => state,
            Err(error) => {
                // Journal and transport failures must interrupt the attempt, even if the
                // program catches an effect error or tries to submit another effect.
                attempt.interrupt(error);
                return Err(PeerError::Cancelled);
            }
        };
        let result = match state {
            JobState::Completed {
                revision,
                value,
                graph,
            } => {
                self.metrics.add_descendant(graph);
                return remote_value(revision, &value);
            }
            JobState::Failed(error) => Err(error.into()),
            JobState::Expired => Err(PeerError::Timeout),
            JobState::Cancelled => Err(PeerError::Cancelled),
            JobState::Pending | JobState::Running => {
                attempt.interrupt(PeerError::Busy);
                return Err(PeerError::Cancelled);
            }
        };
        self.metrics.remote_failures += 1;
        result
    }

    fn durable_effect(
        &mut self,
        remote: &Remote,
        budget: GraphBudget,
        active: &Activity,
        attempt: &Attempt,
        ordinal: u16,
    ) -> Result<JobState> {
        let expiry = self.call.graph.expect("graph invocation").expires_at_ms;
        let expiry = remote
            .timeout_ms
            .map_or(expiry, |ms| expiry.min(unix_ms() + u64::from(ms)));
        let fingerprint = Hash::digest(&protocol::encode(remote)?);
        let intent =
            attempt
                .store
                .borrow_mut()
                .job_intent(attempt.key, ordinal, fingerprint, expiry)?;
        if let Some(state) = intent.result {
            return Ok(state);
        }
        let result = (|| {
            let (peer, child) = if let Some(child) = intent.child {
                child
            } else {
                let (peer, graph) = self.prepare(remote, budget, intent.expires_at_ms, active)?;
                let id = Hash::digest(&protocol::encode(&(
                    b"pp2 child job",
                    attempt.key.holder,
                    attempt.key.id,
                    ordinal,
                ))?);
                let child = (peer, Submission { id, graph });
                attempt
                    .store
                    .borrow()
                    .save_job_child(attempt.key, ordinal, &child)?;
                child
            };
            active.check()?;
            let mut traffic = Traffic::default();
            let reply = self.peer(peer)?.exchange_program(
                child.graph.program,
                Request::Submit(child),
                active.clone(),
                None,
                &mut traffic,
                |hash| self.packages.executable(self.call.holder, hash),
            );
            self.metrics.remote_request_bytes += traffic.sent;
            self.metrics.remote_response_bytes += traffic.received;
            jobs::job_reply(reply?)
        })();
        let state = match result {
            Ok(state) => state,
            Err(error) if jobs::retryable(&error) => return Err(error),
            Err(PeerError::Timeout) if unix_ms() < intent.expires_at_ms => {
                return Err(PeerError::Busy);
            }
            Err(error) => {
                active.check().map_err(|active_error| {
                    if matches!(active_error, PeerError::Timeout) {
                        PeerError::Busy
                    } else {
                        active_error
                    }
                })?;
                JobState::Failed(error.into())
            }
        };
        if !matches!(state, JobState::Pending | JobState::Running) {
            attempt
                .store
                .borrow()
                .save_job_effect(attempt.key, ordinal, &state)?;
        }
        Ok(state)
    }
}

fn remote_value(revision: u64, bytes: &[u8]) -> Result<Vec<u8>> {
    let value = Data::from_bytes(bytes)?;
    let revision = i64::try_from(revision).map_err(|_| PeerError::Limit("revision"))?;
    Ok(Data::Record(
        [
            ("revision".into(), Data::Int(revision)),
            ("value".into(), value),
        ]
        .into_iter()
        .collect(),
    )
    .to_bytes()?)
}

impl GraphJob {
    pub(super) fn call(&self, holder: Hash) -> Result<Call> {
        self.budget.validate()?;
        if self.input.len() > Block::MAX_BYTES {
            return Err(PeerError::Limit("input bytes"));
        }
        Data::from_bytes(&self.input)?;
        let update = match self.mode {
            EvaluationMode::Read => None,
            EvaluationMode::Update {
                expected_revision,
                operation,
            } => {
                let empty =
                    matches!(&self.bindings, GraphBindings::Local(names) if names.is_empty());
                if self.budget.calls != 0 || !empty {
                    return Err(PeerError::Denied);
                }
                Some(Update {
                    expected: expected_revision,
                    operation,
                    fingerprint: Hash::digest(&protocol::encode(&(
                        self.program,
                        self.mode,
                        &self.input,
                    ))?),
                })
            }
        };
        Ok(Call {
            holder,
            grant: self.grant,
            program: self.program,
            update,
            graph: Some(GraphAccess {
                budget: self.budget,
                expires_at_ms: self.expires_at_ms,
                delegated_by: self.delegated_by,
            }),
        })
    }
}

impl Client {
    /// Asks the issuing peer for a collection grant pinned to a new holder and program.
    /// The grant can be attached by this certificate until its deadline and is revoked with
    /// the source grant. Retrying the same request recovers the same grant ID.
    pub fn attenuate(
        &self,
        grant: Hash,
        holder: Hash,
        access: Access,
        program: Hash,
        limit: GraphBudget,
        expires_at_ms: u64,
    ) -> Result<Hash> {
        limit.validate()?;
        self.forward(
            Forward {
                grant,
                delegated_by: None,
                holder,
                access,
                program,
                limit,
                expires_at_ms,
            },
            Activity::new(Instant::now() + DEADLINE),
            &mut Traffic::default(),
        )
    }

    fn forward(&self, request: Forward, active: Activity, traffic: &mut Traffic) -> Result<Hash> {
        let tcp = dial(self.endpoint, &active, None)?;
        let mut stream = self.handshake(tcp, active)?;
        traffic.sent += protocol::send(&mut stream, &Request::Forward(request))?;
        let (reply, received) = protocol::receive::<Reply>(&mut stream)?;
        traffic.received += received;
        match reply {
            Reply::Delegated(grant) => Ok(grant),
            Reply::Failed(error) => Err(error.into()),
            _ => Err(unexpected_reply()),
        }
    }
}

impl Server {
    pub(super) fn run_graph(
        &self,
        stream: &mut Inbound,
        store: &mut PeerStore,
        holder: Hash,
        job: GraphJob,
    ) -> Result<Reply> {
        stream.sock.check_active()?;
        let call = job.call(holder)?;
        let bindings = self.graph.resolve(call, job.bindings)?;
        if let Some(receipt) = store.probe_collection(call)? {
            return Ok(graph_reply(receipt, GraphMetrics::default()));
        }
        let code = receive_code(stream, store, call)?;
        let (receipt, metrics) = self.execute_graph(
            store,
            call,
            code,
            job.input,
            bindings,
            stream.sock.active(),
            None,
        )?;
        Ok(graph_reply(receipt, metrics))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_graph(
        &self,
        store: &mut PeerStore,
        call: Call,
        code: Vec<(Hash, Vec<u8>)>,
        input: Vec<u8>,
        bindings: BTreeMap<String, BoundCapability>,
        active: Activity,
        durable: Option<&super::jobs::Attempt>,
    ) -> Result<(super::super::storage::Receipt, GraphMetrics)> {
        if !code[0].1.starts_with(content::MAGIC) {
            return Err(PeerError::Value(
                "graph evaluation requires JavaScript".into(),
            ));
        }
        active.check()?;
        let mut invocation = if bindings.is_empty() {
            None
        } else {
            Some(Invocation {
                server: self,
                routes: bindings.clone(),
                packages: PeerStore::open_with_timeout(&self.database, active.storage_wait()?)?,
                call,
                metrics: GraphMetrics::default(),
            })
        };
        let storage = match store.scoped(call, active.storage_wait()?)? {
            ScopedStart::Collection(storage) => storage,
            ScopedStart::Replayed(receipt) => return Ok((receipt, GraphMetrics::default())),
        };
        let mut scope = Scope {
            budget: call.graph.expect("graph invocation").budget,
            bindings: bindings.into_keys().collect(),
        };
        let mut storage_effects = 0;
        let mut storage_us = 0;
        let output = worker::run(
            &self.worker,
            Work {
                program: call.program,
                code,
                input,
                context: WorkContext::Graph(Guest {
                    bindings: scope.bindings.clone(),
                    write: call.update.is_some(),
                }),
            },
            || active.check(),
            |effect| {
                effect.validate()?;
                let bytes = match effect {
                    Effect::Evaluate(remote) => {
                        let invocation = invocation.as_mut().ok_or(PeerError::Denied)?;
                        match durable {
                            Some(attempt) => invocation.invoke_durable(
                                remote,
                                &mut scope,
                                active.clone(),
                                attempt,
                            )?,
                            None => invocation.invoke(remote, &mut scope, active.clone())?,
                        }
                    }
                    storage_effect => {
                        storage_effects += 1;
                        let started = Instant::now();
                        let result = storage.effect(storage_effect);
                        storage_us += started.elapsed().as_micros() as u64;
                        result?
                    }
                };
                effects::check_response(&bytes)?;
                Ok(bytes)
            },
        )?;
        if let Some(attempt) = durable {
            attempt.check_effects()?;
        }
        let mut metrics =
            invocation.map_or_else(GraphMetrics::default, |invocation| invocation.metrics);
        metrics.add_worker(GraphMetrics {
            storage_effects,
            storage_us,
            worker_busy_us: output.busy_us,
            worker_elapsed_us: output.elapsed_us,
            worker_startup_us: output.startup_us,
            ..GraphMetrics::default()
        });
        let receipt = storage.finish(
            output.value,
            || active.check(),
            durable.map(|job| (job.key, metrics)),
        )?;
        if call.update.is_none() {
            store.confirm_collection(call)?;
            active.check()?;
        }
        Ok((receipt, metrics))
    }
}

fn graph_reply(receipt: crate::peer::storage::Receipt, metrics: GraphMetrics) -> Reply {
    Reply::Graph {
        revision: receipt.revision,
        value: receipt.value,
        metrics,
    }
}
