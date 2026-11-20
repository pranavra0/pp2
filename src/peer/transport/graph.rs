use super::jobs::{self, Attempt};
use super::*;
use crate::peer::{
    Access, Binding, Consistency, GraphBudget, GraphMetrics, HostResource, PeerEndpoint,
    TerminalResult,
    effects::{self, BoundCapability, Effect, GraphBindings, GraphJob, Remote, Scope},
    native::{self, STATE, Terminal},
    protocol::{Forward, JobState, Submission},
    storage::{GraphAccess, StageKind},
    unix_ms,
    worker::Guest,
};

type Inbound = StreamOwned<ServerConnection, Socket>;
const TRACE_EXPORTER: &[u8] = b"EXPORTER-pp2-graph-trace-v1";
const LEAF_BUDGET: GraphBudget = GraphBudget {
    timeout_ms: 3000,
    calls: 0,
    depth: 0,
};

fn trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("PP2_TRACE_GRAPH").as_deref() == Ok("1"))
}

fn failure_class<T>(result: &Result<T>) -> Option<&'static str> {
    use PeerError::*;
    result.as_ref().err().map(|error| match error {
        Denied => "denied",
        PeerUnavailable(_) => "peer-unavailable",
        Tls(_) => "authentication",
        Conflict(_) => "conflict",
        Missing(_) => "missing",
        Timeout => "timeout",
        Cancelled => "cancelled",
        Busy => "busy",
        Storage(_) => "storage",
        Guest(_) => "guest",
        Limit(_) => "limit",
        Io(_) => "io",
        _ => "invalid",
    })
}

pub struct GraphEvaluation<'a> {
    pub evaluation: Evaluation<'a>,
    pub budget: GraphBudget,
    /// Explicitly requested names from the host configuration for this caller and program.
    pub bindings: &'a [String],
}

impl GraphEvaluation<'_> {
    pub(super) fn job(
        &self,
        bindings: GraphBindings,
        expires_at_ms: Option<u64>,
    ) -> Result<GraphJob> {
        self.budget.validate()?;
        effects::validate_binding_names(self.bindings)?;
        Ok(GraphJob {
            grant: self.evaluation.grant,
            program: self.evaluation.program,
            mode: self.evaluation.mode,
            input: self.evaluation.input.to_bytes()?,
            budget: self.budget,
            expires_at_ms: expires_at_ms
                .unwrap_or_else(|| unix_ms() + u64::from(self.budget.timeout_ms)),
            delegated_by: None,
            bindings,
        })
    }
}

#[derive(Debug)]
pub struct GraphReport {
    pub revision: u64,
    pub view: Option<ResourceView>,
    pub value: Data,
    pub elapsed_us: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub graph: GraphMetrics,
}

pub(super) struct Configuration {
    callers: BTreeMap<(Hash, Hash, Hash), BTreeMap<String, Binding>>,
    pub(super) peers: BTreeMap<Hash, Client>,
    stable: bool,
    identity: Hash,
}

impl Configuration {
    pub(super) fn new(
        creds: &Credentials,
        network: Option<&PeerNetwork>,
        identity: Hash,
        bindings: Vec<BindingSet>,
        endpoints: Vec<PeerEndpoint>,
    ) -> Result<Self> {
        let mut peers = BTreeMap::new();
        for endpoint in endpoints {
            let client = if let Some(network) = network {
                Client::for_peer(network, endpoint.fingerprint, Some(endpoint.address))
            } else {
                let mut client = Client::new(endpoint.address, endpoint.name, creds)?;
                client.pin_certificate(endpoint.fingerprint);
                client
            };
            if peers.insert(endpoint.fingerprint, client).is_some() {
                return Err(PeerError::Value("repeated peer directory entry".into()));
            }
        }
        let mut callers = BTreeMap::new();
        for set in bindings {
            effects::validate_binding_names(&set.capabilities.keys().cloned().collect::<Vec<_>>())?;
            if network.is_none()
                && set
                    .capabilities
                    .values()
                    .any(|binding| binding.peer != identity && !peers.contains_key(&binding.peer))
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
        Ok(Self {
            callers,
            peers,
            stable: network.is_some(),
            identity,
        })
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
                if !self.stable
                    && ((call.holder != self.identity && !self.peers.contains_key(&call.holder))
                        || bindings.values().any(|binding| {
                            binding.peer != self.identity && !self.peers.contains_key(&binding.peer)
                        }))
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
    /// Evaluates JavaScript with a program grant and explicitly supplied capabilities.
    pub fn run_graph(
        &self,
        request: GraphEvaluation<'_>,
        cancellation: Option<&Cancellation>,
    ) -> Result<GraphReport> {
        let started = Instant::now();
        let job = request.job(GraphBindings::Local(request.bindings.to_vec()), None)?;
        let active =
            Activity::new(started + Duration::from_millis(u64::from(job.budget.timeout_ms)));
        let mut traffic = Traffic::default();
        let result = self.exchange_program(
            job.program,
            Request::Run(job),
            active,
            cancellation,
            &mut traffic,
            |hash| request.evaluation.package_block(hash),
        );
        if result.is_err() && cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        let (revision, value, graph, view) = graph_result(result?)?;
        effects::check_response(&value)?;
        Ok(GraphReport {
            revision,
            view,
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
        get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
    ) -> Result<Reply> {
        if cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        active.check()?;
        let started = Instant::now();
        let traced = trace_enabled();
        let parent = active.invocation;
        let job = match &request {
            Request::Submit(submission) | Request::SubmitReaction(submission) => {
                Some(submission.id)
            }
            _ => None,
        };
        let mut invocation = None;
        let mut connection = None;
        let mut connect_us = None;
        let result = (|| {
            let (mut stream, _registration, timing) = self.connect_active(active, cancellation)?;
            connect_us = Some(protocol::elapsed_us(started));
            connection = Some(timing);
            if traced {
                invocation = stream
                    .conn
                    .export_keying_material([0; 32], TRACE_EXPORTER, None)
                    .ok()
                    .map(Hash);
            }
            match traffic.exchange(&mut stream, &request, program, get)? {
                reply @ (Reply::Graph { .. } | Reply::ResourceGraph { .. } | Reply::Job(_)) => {
                    stream.sock.activity.check()?;
                    Ok(reply)
                }
                _ => Err(unexpected_reply()),
            }
        })();
        if traced {
            let peer = match &self.destination {
                Destination::Identity { id, .. } => Some(*id),
                Destination::Certificate { fingerprint, .. } => *fingerprint,
            };
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                serde_json::json!({
                    "event": "graph_exchange", "program": program.to_string(),
                    "peer": peer.map(|id| id.to_string()), "invocation": invocation.map(|id| id.to_string()),
                    "parent": parent.map(|id| id.to_string()),
                    "job": job.map(|id| id.to_string()),
                    "elapsed_us": protocol::elapsed_us(started), "connect_us": connect_us,
                    "connection": connection, "postcard_us": traffic.codec_us,
                    "request_bytes": traffic.sent, "response_bytes": traffic.received,
                    "requested_modules": traffic.requested_modules, "failure": failure_class(&result),
                })
            );
        }
        result
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

#[derive(Clone, Copy)]
pub(super) enum Execution<'a> {
    Synchronous,
    Durable(&'a Attempt),
    Terminal(&'a HostResource),
}

struct Invocation<'a> {
    server: &'a Server,
    routes: BTreeMap<String, BoundCapability>,
    packages: PeerStore,
    call: Call,
    native: bool,
    metrics: GraphMetrics,
}

impl Invocation<'_> {
    fn prepare(
        &mut self,
        remote: &Remote,
        budget: GraphBudget,
        expires_at_ms: u64,
        active: &Activity,
    ) -> Result<(Hash, GraphJob)> {
        let target = self.routes.get(&remote.target).ok_or(PeerError::Denied)?;
        let route = &target.binding;
        let mode = match (remote.consistency, remote.update) {
            (_, Some(_)) if route.access != Access::Write => return Err(PeerError::Denied),
            (Consistency::Authoritative, Some((expected_revision, operation))) => {
                EvaluationMode::Update {
                    expected_revision,
                    operation,
                }
            }
            (Consistency::Replica, Some((expected_revision, operation))) => {
                EvaluationMode::UpdateReplica {
                    expected_revision,
                    operation,
                    merge: remote.merge,
                }
            }
            (Consistency::Authoritative, None) => EvaluationMode::Read,
            (Consistency::Replica, None) => EvaluationMode::ReadReplica,
            (Consistency::Revision(id), None) => EvaluationMode::ReadRevision(id),
            (Consistency::Revision(_), Some(_)) => return Err(PeerError::Denied),
        };
        if self.native && remote.delegate.iter().any(|name| name == STATE) {
            return Err(PeerError::Denied);
        }
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
            let request = Forward {
                grant: source.grant,
                delegated_by: capability.delegated_by,
                holder: route.peer,
                access: source.access,
                program: source.program,
                limit,
                expires_at_ms,
            };
            let grant = if source.peer == self.server.identity {
                active.check()?;
                if let Some(network) = &self.server.network {
                    network.check_identity(self.server.identity)?;
                }
                self.packages.forward(self.server.identity, request)
            } else {
                self.server
                    .peer(source.peer)?
                    .forward(request, active.clone(), &mut traffic)
            };
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
        let mut job = GraphJob {
            grant: route.grant,
            program: route.program,
            mode,
            input: remote.input.clone(),
            budget,
            expires_at_ms,
            delegated_by: target.delegated_by,
            bindings,
        };
        let peer = self
            .server
            .place_read(&self.packages, route, &mut job, |call| {
                child_code(&self.packages, call, self.call.holder, self.native, active)
            })?;
        Ok((peer, job))
    }

    fn invoke(
        &mut self,
        remote: Remote,
        scope: &mut Scope,
        mut active: Activity,
    ) -> Result<Vec<u8>> {
        self.packages.confirm_access(self.call)?;
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
        let state = self.native && remote.target == STATE;
        let leaf = remote.delegate.is_empty() && remote.allowance == 0;
        if state && !leaf {
            return Err(PeerError::Denied);
        }
        let (peer, job) = self.prepare(&remote, budget, expiry, &active)?;
        if peer == self.server.identity {
            let holder = if state {
                self.call.holder
            } else {
                self.server.identity
            };
            let call = job.call(
                holder,
                false,
                self.server.network.as_ref().map(PeerNetwork::id),
            )?;
            if let Some(network) = &self.server.network {
                network.check_identity(holder)?;
            }
            let bindings = self.server.graph.resolve(call, job.bindings)?;
            if let Some(receipt) = self.packages.probe_graph(call, !bindings.is_empty())? {
                return remote_value(receipt.revision, &receipt.value, receipt.view.as_ref());
            }
            let code = child_code(&self.packages, call, self.call.holder, self.native, &active)?;
            let (receipt, metrics) = self.server.execute_graph(
                &mut self.packages,
                call,
                code,
                job.input,
                bindings,
                active,
                Execution::Synchronous,
            )?;
            self.metrics.add_descendant(metrics);
            return remote_value(receipt.revision, &receipt.value, receipt.view.as_ref());
        }
        let mut traffic = Traffic::default();
        self.metrics.remote_calls += 1;
        let result = (|| {
            let reply = self.server.peer(peer)?.exchange_program(
                job.program,
                Request::Run(job),
                active,
                None,
                &mut traffic,
                |hash| {
                    if self.native {
                        self.packages.get(hash)
                    } else {
                        self.packages.executable(self.call.holder, hash)
                    }
                },
            )?;
            let (revision, value, metrics, view) = graph_result(reply)?;
            effects::check_response(&value)?;
            Ok((revision, value, metrics, view))
        })();
        self.metrics.remote_request_bytes += traffic.sent;
        self.metrics.remote_response_bytes += traffic.received;
        match result {
            Ok((revision, bytes, metrics, view)) => {
                self.metrics.add_descendant(metrics);
                remote_value(revision, &bytes, view.as_ref())
            }
            Err(error) => {
                self.metrics.remote_failures += 1;
                Err(error)
            }
        }
    }

    fn invoke_batch(
        &mut self,
        reads: Vec<Remote>,
        scope: &mut Scope,
        active: &Activity,
        durable: Option<&Attempt>,
    ) -> Result<Vec<u8>> {
        let mut remaining = scope.clone();
        for read in &reads {
            remaining.allocate(read)?;
        }
        let results = if let Some(attempt) = durable {
            reads
                .into_iter()
                .map(|read| self.invoke_durable(read, scope, active.clone(), attempt))
                .collect::<Result<Vec<_>>>()?
        } else {
            self.packages.confirm_access(self.call)?;
            active.check()?;
            let budget = scope.budget;
            *scope = remaining;
            let server = self.server;
            let call = self.call;
            let deadline = active.deadline;
            let invocation = active.invocation;
            let native = self.native;
            let results = thread::scope(|threads| {
                let workers = reads
                    .into_iter()
                    .map(|read| {
                        let sockets = active.sockets.clone();
                        let routes = BTreeMap::from([(
                            read.target.clone(),
                            self.routes[&read.target].clone(),
                        )]);
                        thread::Builder::new().spawn_scoped(threads, move || {
                            let active = Activity {
                                deadline,
                                sockets,
                                job: None,
                                invocation,
                            };
                            let mut scope = Scope {
                                budget: GraphBudget { calls: 1, ..budget },
                                bindings: vec![read.target.clone()],
                            };
                            let mut invocation = Invocation {
                                server,
                                routes,
                                packages: PeerStore::open_with_timeout(
                                    &server.database,
                                    active.storage_wait()?,
                                )?,
                                call,
                                native,
                                metrics: GraphMetrics::default(),
                            };
                            let value = invocation.invoke(read, &mut scope, active);
                            Ok((value, invocation.metrics))
                        })
                    })
                    .collect::<Vec<_>>();
                workers
                    .into_iter()
                    .map(|worker| -> Result<_> {
                        worker?.join().map_err(|_| {
                            PeerError::Protocol("parallel read thread exited".into())
                        })?
                    })
                    .collect::<Vec<_>>()
            });
            let results = results
                .into_iter()
                .map(|result| {
                    let (result, metrics) = result?;
                    self.metrics.add_descendant(metrics);
                    result
                })
                .collect::<Vec<_>>();
            results.into_iter().collect::<Result<Vec<_>>>()?
        };
        let values = results
            .iter()
            .map(|bytes| Data::from_bytes(bytes))
            .collect::<crate::Result<_>>()?;
        Ok(Data::List(values).to_bytes()?)
    }

    fn invoke_durable(
        &mut self,
        remote: Remote,
        scope: &mut Scope,
        active: Activity,
        attempt: &Attempt,
    ) -> Result<Vec<u8>> {
        self.packages.confirm_access(self.call)?;
        let budget = jobs::child_budget(scope.allocate(&remote)?, remote.timeout_ms);
        let ordinal = attempt.effects.get() + 1;
        attempt.effects.set(ordinal);
        let result = self.durable_effect(&remote, budget, &active, attempt, ordinal);
        let state = match result {
            Ok(state) => state,
            Err(error) => {
                // A guest catch must not swallow journal or transport failures.
                attempt.interrupt(error);
                return Err(PeerError::Cancelled);
            }
        };
        match state {
            JobState::Completed {
                revision,
                value,
                graph,
            } => {
                self.metrics.add_descendant(graph);
                remote_value(revision, &value, None)
            }
            JobState::ResourceCompleted {
                revision,
                value,
                graph,
                view,
            } => {
                self.metrics.add_descendant(graph);
                remote_value(revision, &value, Some(&view))
            }
            JobState::Failed(error) => Err(error.into()),
            JobState::Expired => Err(PeerError::Timeout),
            JobState::Cancelled => Err(PeerError::Cancelled),
            JobState::Pending | JobState::Running => {
                attempt.interrupt(PeerError::Busy);
                Err(PeerError::Cancelled)
            }
        }
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
        // Preserve fingerprints recorded for existing authoritative effects.
        let base = (
            &remote.target,
            &remote.input,
            remote.allowance,
            remote.timeout_ms,
            &remote.delegate,
            remote.update,
        );
        let encoded = if remote.consistency == Consistency::Authoritative {
            protocol::encode(&base)?
        } else {
            protocol::encode(&(base, remote.consistency, remote.merge))?
        };
        let fingerprint = Hash::digest(&encoded);
        let intent =
            attempt
                .store
                .borrow_mut()
                .job_intent(attempt.key, ordinal, fingerprint, expiry)?;
        if let Some(state) = intent.result {
            if matches!(state, JobState::ResourceCompleted { .. })
                && let Some((peer, child)) = &intent.child
                && *peer == self.server.identity
            {
                let key = storage::JobKey {
                    holder: *peer,
                    id: child.id,
                };
                let executor = self.server.network.as_ref().map(PeerNetwork::id);
                return match self.packages.job_status(key, executor) {
                    Ok(state) => Ok(state),
                    Err(error @ (PeerError::Denied | PeerError::Missing(_))) => {
                        Ok(JobState::Failed(error.into()))
                    }
                    Err(error) => Err(error),
                };
            }
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
                    .borrow_mut()
                    .save_job_child(attempt.key, ordinal, &child)?;
                child
            };
            active.check()?;
            if peer == self.server.identity {
                let parent = self.call.holder;
                return self.server.accept_job(
                    &mut self.packages,
                    self.server.identity,
                    child,
                    self.call.reaction,
                    |store, call| child_code(store, call, parent, false, active),
                );
            }
            self.metrics.remote_calls += 1;
            let mut traffic = Traffic::default();
            let program = child.graph.program;
            let request = if self.call.reaction {
                Request::SubmitReaction(child)
            } else {
                Request::Submit(child)
            };
            let reply = self.server.peer(peer)?.exchange_program(
                program,
                request,
                active.clone(),
                None,
                &mut traffic,
                |hash| self.packages.executable(self.call.holder, hash),
            );
            self.metrics.remote_request_bytes += traffic.sent;
            self.metrics.remote_response_bytes += traffic.received;
            let result = reply.and_then(jobs::job_reply);
            if matches!(
                &result,
                Err(_) | Ok(JobState::Failed(_) | JobState::Expired | JobState::Cancelled)
            ) {
                self.metrics.remote_failures += 1;
            }
            result
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

fn child_code(
    store: &PeerStore,
    call: Call,
    parent: Hash,
    native: bool,
    active: &Activity,
) -> Result<Vec<(Hash, Vec<u8>)>> {
    content::load_code(call.program, false, |hash| {
        active.check()?;
        if native {
            return store.get(hash);
        }
        match store.executable(call.holder, hash)? {
            Some(bytes) => Ok(Some(bytes)),
            None => store.executable(parent, hash),
        }
    })
}

fn remote_value(revision: u64, bytes: &[u8], view: Option<&ResourceView>) -> Result<Vec<u8>> {
    let value = Data::from_bytes(bytes)?;
    let revision = i64::try_from(revision).map_err(|_| PeerError::Limit("revision"))?;
    let mut result = BTreeMap::from([
        ("revision".into(), Data::Int(revision)),
        ("value".into(), value),
    ]);
    if let Some(view) = view {
        result.insert("view".into(), content::data_from_json(view.to_json())?);
    }
    Ok(Data::Record(result).to_bytes()?)
}

fn graph_result(reply: Reply) -> Result<(u64, Vec<u8>, GraphMetrics, Option<ResourceView>)> {
    match reply {
        Reply::Graph {
            revision,
            value,
            metrics,
        } => Ok((revision, value, metrics, None)),
        Reply::ResourceGraph {
            revision,
            value,
            metrics,
            view,
        } => Ok((revision, value, metrics, Some(view))),
        _ => Err(unexpected_reply()),
    }
}

impl GraphJob {
    pub(super) fn call(
        &self,
        holder: Hash,
        reaction: bool,
        executor: Option<Hash>,
    ) -> Result<Call> {
        self.budget.validate()?;
        if self.input.len() > Block::MAX_BYTES {
            return Err(PeerError::Limit("input bytes"));
        }
        Data::from_bytes(&self.input)?;
        let update = if let Some((expected, operation, merge)) = self.mode.update() {
            let empty = matches!(&self.bindings, GraphBindings::Local(names) if names.is_empty());
            if self.budget.calls != 0 || !empty {
                return Err(PeerError::Denied);
            }
            Some(Update {
                expected,
                operation,
                merge,
                fingerprint: Hash::digest(&protocol::encode(&(
                    self.program,
                    self.mode,
                    &self.input,
                ))?),
            })
        } else {
            None
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
            reaction,
            consistency: self.mode.consistency(),
            resource: self.mode.resource(),
            executor,
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
        let (mut stream, _, _) = self.connect_active(active, None)?;
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
    fn peer(&self, id: Hash) -> Result<Client> {
        self.graph
            .peers
            .get(&id)
            .cloned()
            .or_else(|| {
                self.network
                    .as_ref()
                    .map(|network| Client::for_peer(network, id, None))
            })
            .ok_or(PeerError::Denied)
    }

    fn place_read(
        &self,
        store: &PeerStore,
        binding: &Binding,
        job: &mut GraphJob,
        load: impl FnOnce(Call) -> Result<Vec<(Hash, Vec<u8>)>>,
    ) -> Result<Hash> {
        let consistency = job.mode.consistency();
        if self.network.is_none()
            || job.delegated_by.is_some()
            || job.mode.update().is_some()
            || job.budget.calls != 0
            || !matches!(&job.bindings, GraphBindings::Local(names) if names.is_empty())
            || consistency == Consistency::Authoritative
        {
            return Ok(binding.peer);
        }
        let Some((resource, grant)) = store.replica_read_route(binding)? else {
            return Ok(binding.peer);
        };
        if job
            .mode
            .resource()
            .is_some_and(|expected| resource != expected)
        {
            return Err(PeerError::Denied);
        }
        job.mode = EvaluationMode::ReadResource {
            resource,
            consistency,
        };
        let mut call = job.call(self.identity, false, Some(self.identity))?;
        call.grant = grant;
        if store.can_read_replica(call)? {
            match load(call) {
                Ok(_) => {
                    job.grant = grant;
                    return Ok(self.identity);
                }
                Err(PeerError::Missing(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(binding.peer)
    }

    /// Evaluates a leaf under an explicit binding, preferring a local authorized replica for replica reads.
    pub fn evaluate_bound(
        &self,
        binding: &Binding,
        mode: EvaluationMode,
        input: &Data,
    ) -> Result<GraphReport> {
        if mode.update().is_some() && binding.access != Access::Write {
            return Err(PeerError::Denied);
        }
        let budget = LEAF_BUDGET;
        let active =
            Activity::new(Instant::now() + Duration::from_millis(budget.timeout_ms.into()));
        let store = PeerStore::open_with_timeout(&self.database, active.storage_wait()?)?;
        let mut request = GraphEvaluation {
            evaluation: Evaluation {
                grant: binding.grant,
                program: binding.program,
                mode,
                input,
                packages: Some(&store),
            },
            budget,
            bindings: &[],
        };
        let mut job = request.job(GraphBindings::Local(Vec::new()), None)?;
        let peer = self.place_read(&store, binding, &mut job, |call| {
            child_code(&store, call, self.identity, true, &active)
        })?;
        if peer == self.identity {
            self.evaluate_local_job(job, Some(&store))
        } else {
            request.evaluation.grant = job.grant;
            request.evaluation.mode = job.mode;
            request.budget.timeout_ms = active.remaining()?.as_millis().max(1) as u32;
            self.peer(peer)?.run_graph(request, None)
        }
    }

    /// Runs a locally available program with no capabilities.
    pub fn evaluate_program(&self, program: Hash, input: &Data) -> Result<GraphReport> {
        let input = input.to_bytes()?;
        let budget = LEAF_BUDGET;
        let expires_at_ms = unix_ms() + u64::from(budget.timeout_ms);
        let grant = PeerStore::open(&self.database)?.issue_compute_with_limit(
            self.identity,
            program,
            Some(GraphAccess {
                budget,
                expires_at_ms,
                delegated_by: Some(self.identity),
            }),
        )?;
        self.evaluate_local_job(
            GraphJob {
                grant,
                program,
                mode: EvaluationMode::Read,
                input,
                budget,
                expires_at_ms,
                delegated_by: Some(self.identity),
                bindings: GraphBindings::Local(Vec::new()),
            },
            None,
        )
    }

    /// Evaluates as this server's identity with the same grant and budget checks as a peer request.
    pub fn evaluate_local(&self, request: GraphEvaluation<'_>) -> Result<GraphReport> {
        let job = request.job(GraphBindings::Local(request.bindings.to_vec()), None)?;
        self.evaluate_local_job(job, request.evaluation.packages)
    }

    fn evaluate_local_job(
        &self,
        job: GraphJob,
        packages: Option<&PeerStore>,
    ) -> Result<GraphReport> {
        let started = Instant::now();
        let remaining = job.expires_at_ms.saturating_sub(unix_ms());
        let active = Activity::new(
            started + Duration::from_millis(remaining.min(job.budget.timeout_ms.into())),
        );
        let call = job.call(
            self.identity,
            false,
            self.network.as_ref().map(PeerNetwork::id),
        )?;
        let mut store = PeerStore::open_with_timeout(&self.database, active.storage_wait()?)?;
        let bindings = self.graph.resolve(call, job.bindings)?;
        let (receipt, graph) =
            if let Some(receipt) = store.probe_graph(call, !bindings.is_empty())? {
                (receipt, GraphMetrics::default())
            } else {
                let code = content::load_code(job.program, false, |hash| {
                    active.check()?;
                    match store.get(hash)? {
                        Some(bytes) => Ok(Some(bytes)),
                        None => match packages {
                            Some(packages) => packages.get(hash),
                            None => Ok(None),
                        },
                    }
                })?;
                self.execute_graph(
                    &mut store,
                    call,
                    code,
                    job.input,
                    bindings,
                    active,
                    Execution::Synchronous,
                )?
            };
        Ok(GraphReport {
            revision: receipt.revision,
            view: receipt.view,
            value: Data::from_bytes(&receipt.value)?,
            elapsed_us: protocol::elapsed_us(started),
            request_bytes: 0,
            response_bytes: 0,
            graph,
        })
    }

    /// Sends one terminal event to the installed program in a local, isolated worker.
    /// Remote calls use the same graph protocol as a network-initiated invocation.
    pub fn run_native(&self, id: Hash, line: &str) -> Result<(TerminalResult, GraphMetrics)> {
        let event = native::terminal_event(line)?;
        let mut store = PeerStore::open(&self.database)?;
        let execution = store.native_execution(id)?;
        let program = execution.installation.manifest.entry;
        let budget = execution.installation.manifest.budget;
        let active =
            Activity::new(Instant::now() + Duration::from_millis(budget.timeout_ms.into()));
        let state = Binding {
            peer: self.identity,
            grant: execution.writer,
            program,
            access: Access::Write,
        };
        let bindings = execution
            .installation
            .bindings
            .into_iter()
            .chain([(STATE.into(), state)])
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
        let job = GraphJob {
            grant: execution.entry,
            program,
            mode: EvaluationMode::Read,
            input: Data::Nil.to_bytes()?,
            budget,
            expires_at_ms: unix_ms() + u64::from(budget.timeout_ms),
            delegated_by: None,
            bindings: GraphBindings::Local(Vec::new()),
        };
        let call = job.call(id, false, self.network.as_ref().map(PeerNetwork::id))?;
        let (receipt, metrics) = self.execute_graph(
            &mut store,
            call,
            execution.code,
            job.input,
            bindings,
            active,
            Execution::Terminal(&event),
        )?;
        Ok((
            TerminalResult::from_data(&Data::from_bytes(&receipt.value)?)?,
            metrics,
        ))
    }

    pub(super) fn run_graph(
        &self,
        stream: &mut Inbound,
        store: &mut PeerStore,
        holder: Hash,
        job: GraphJob,
    ) -> Result<Reply> {
        stream.sock.check_active()?;
        let call = job.call(holder, false, self.network.as_ref().map(PeerNetwork::id))?;
        let bindings = self.graph.resolve(call, job.bindings)?;
        if let Some(receipt) = store.probe_graph(call, !bindings.is_empty())? {
            return Ok(graph_reply(receipt, GraphMetrics::default()));
        }
        let code = self.receive_code(stream, store, call)?;
        let mut active = stream.sock.active();
        if trace_enabled() {
            active.invocation = stream
                .conn
                .export_keying_material([0; 32], TRACE_EXPORTER, None)
                .ok()
                .map(Hash);
        }
        let (receipt, metrics) = self.execute_graph(
            store,
            call,
            code,
            job.input,
            bindings,
            active,
            Execution::Synchronous,
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
        mut active: Activity,
        execution: Execution<'_>,
    ) -> Result<(super::super::storage::Receipt, GraphMetrics)> {
        let started = Instant::now();
        let mut trace = GraphTrace {
            stage: "setup",
            ..GraphTrace::default()
        };
        if let Execution::Durable(attempt) = execution {
            active.invocation = Some(attempt.key.id);
        }
        let invocation = active.invocation;
        let result = self.execute_graph_inner(
            store, call, code, input, bindings, active, execution, &mut trace,
        );
        if trace_enabled() {
            let job = match execution {
                Execution::Durable(attempt) => Some(attempt.key.id.to_string()),
                _ => None,
            };
            let _ = writeln!(
                io::stderr().lock(),
                "{}",
                serde_json::json!({
                    "event": "graph_execution", "peer": self.identity.to_string(),
                    "program": call.program.to_string(), "holder": call.holder.to_string(),
                    "invocation": invocation.map(|id| id.to_string()), "job": job,
                    "elapsed_us": protocol::elapsed_us(started), "trace": trace,
                    "metrics": result.as_ref().ok().map(|(_, metrics)| metrics),
                    "failure": failure_class(&result),
                })
            );
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_graph_inner(
        &self,
        store: &mut PeerStore,
        call: Call,
        code: Vec<(Hash, Vec<u8>)>,
        input: Vec<u8>,
        bindings: BTreeMap<String, BoundCapability>,
        active: Activity,
        execution: Execution<'_>,
        trace: &mut GraphTrace,
    ) -> Result<(super::super::storage::Receipt, GraphMetrics)> {
        if !code[0].1.starts_with(content::MAGIC) {
            return Err(PeerError::Value(
                "graph evaluation requires JavaScript".into(),
            ));
        }
        active.check()?;
        let (durable, event) = match execution {
            Execution::Synchronous => (None, None),
            Execution::Durable(attempt) => (Some(attempt), None),
            Execution::Terminal(event) => (None, Some(event)),
        };
        trace.stage = "storage_open";
        let started = Instant::now();
        let mut storage = match store.scoped(call, active.storage_wait()?)? {
            EvaluationStart::Ready(storage) => storage,
            EvaluationStart::Replayed(receipt) => return Ok((receipt, GraphMetrics::default())),
        };
        if event.is_none() {
            storage.kind().check_bindings(!bindings.is_empty())?;
        }
        let mut invocation = if bindings.is_empty() {
            None
        } else {
            Some(Invocation {
                server: self,
                routes: bindings.clone(),
                packages: PeerStore::open_with_timeout(&self.database, active.storage_wait()?)?,
                call,
                native: event.is_some(),
                metrics: GraphMetrics::default(),
            })
        };
        trace.storage_open_us = protocol::elapsed_us(started);
        let persisted = if event.is_none() {
            storage.host_resource()?
        } else {
            None
        };
        let resource = match (event, persisted.as_ref()) {
            (Some(event), _) => Some((&Terminal as &dyn super::HostProvider, event)),
            (_, Some(resource)) => {
                let provider = self
                    .providers
                    .get(&resource.provider)
                    .ok_or(PeerError::Unsupported("host resource provider unavailable"))?;
                Some((provider.as_ref(), resource))
            }
            _ => None,
        };
        // Read invocations hold a SQLite snapshot, so verify revocation using a fresh
        // view. Update invocations already serialize with revocation on the writer lock.
        let authority = if resource.is_some() && call.update.is_none() {
            Some(PeerStore::open_with_timeout(
                &self.database,
                active.storage_wait()?,
            )?)
        } else {
            None
        };
        let confirm_host = || -> Result<()> {
            active.check()?;
            if let Some(authority) = &authority {
                authority.confirm_access(call)?;
            }
            Ok(())
        };
        let mut scope = Scope {
            budget: call.graph.expect("graph invocation").budget,
            bindings: bindings.into_keys().collect(),
        };
        let mut storage_effects = 0;
        let mut storage_us = 0;
        trace.stage = "worker";
        let output = worker::run(
            &self.worker,
            Work {
                program: call.program,
                code,
                input,
                context: WorkContext::Graph(Guest {
                    bindings: scope.bindings.clone(),
                    write: call.update.is_some(),
                    indexed: storage.kind() == StageKind::Indexed && event.is_none(),
                    root: storage.root(),
                    merge_heads: storage.merge_heads().to_vec(),
                    resource: resource.is_some(),
                    revision: storage.revision(),
                    view: storage.view().clone(),
                }),
            },
            || active.check(),
            |effect| {
                effect.validate()?;
                let bytes =
                    match effect {
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
                        Effect::EvaluateBatch(reads) => invocation
                            .as_mut()
                            .ok_or(PeerError::Denied)?
                            .invoke_batch(reads, &mut scope, &active, durable)?,
                        Effect::Host(operation, input) => {
                            let (provider, resource) = resource.ok_or(PeerError::Denied)?;
                            confirm_host()?;
                            let value = provider.read(
                                &resource.configuration,
                                &operation,
                                Data::from_bytes(&input)?,
                                &confirm_host,
                            );
                            confirm_host()?;
                            value?.to_bytes()?
                        }
                        storage_effect if event.is_none() => {
                            storage_effects += 1;
                            let started = Instant::now();
                            let result = storage.effect(storage_effect);
                            storage_us += started.elapsed().as_micros() as u64;
                            result?
                        }
                        _ => return Err(PeerError::Denied),
                    };
                effects::check_response(&bytes)?;
                Ok(bytes)
            },
        )?;
        trace.worker = Some(output.timing);
        trace.guest_memory_bytes = Some(output.metrics.memory);
        trace.storage_effect_us = storage_us;
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
        trace.stage = "storage_finish";
        let started = Instant::now();
        let receipt = storage.finish(
            output.value,
            || active.check(),
            durable.map(|job| (job.key, metrics)),
            self.network.as_ref().map(PeerNetwork::identity),
        )?;
        trace.storage_finish_us = protocol::elapsed_us(started);
        trace.stage = "release";
        if call.update.is_none() {
            if let Some(view) = &receipt.view {
                store.confirm(call, view)?;
            } else {
                store.confirm_access(call)?;
            }
            active.check()?;
        }
        trace.stage = "complete";
        Ok((receipt, metrics))
    }
}

#[derive(Default, serde::Serialize)]
struct GraphTrace {
    stage: &'static str,
    storage_open_us: u64,
    storage_effect_us: u64,
    storage_finish_us: u64,
    worker: Option<worker::WorkerTiming>,
    guest_memory_bytes: Option<u64>,
}

fn graph_reply(receipt: crate::peer::storage::Receipt, metrics: GraphMetrics) -> Reply {
    let crate::peer::storage::Receipt {
        revision,
        value,
        view,
    } = receipt;
    match view {
        Some(view) => Reply::ResourceGraph {
            revision,
            value,
            metrics,
            view,
        },
        None => Reply::Graph {
            revision,
            value,
            metrics,
        },
    }
}
