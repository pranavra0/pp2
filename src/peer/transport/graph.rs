use std::cell::Cell;

use super::*;
use crate::peer::{
    Access, Binding, GraphBudget, GraphMetrics,
    effects::{self, Effect, GraphJob, Remote, Scope},
    protocol::EffectReply,
    storage::ScopedStart,
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

struct Route {
    client: Client,
    binding: Binding,
}

#[derive(Default)]
pub(super) struct Configuration {
    callers: BTreeMap<(Hash, Hash, Hash), BTreeMap<String, Route>>,
    brokers: BTreeSet<Hash>,
}

impl Configuration {
    pub(super) fn new(
        creds: &Credentials,
        bindings: Vec<BindingSet>,
        brokers: BTreeSet<Hash>,
    ) -> Result<Self> {
        let mut callers = BTreeMap::new();
        for set in bindings {
            effects::validate_binding_names(&set.capabilities.keys().cloned().collect::<Vec<_>>())?;
            let mut routes = BTreeMap::new();
            for (name, binding) in set.capabilities {
                let client = Client::new(binding.address, binding.name.clone(), creds)?;
                routes.insert(name, Route { client, binding });
            }
            if callers
                .insert((set.holder, set.grant, set.program), routes)
                .is_some()
            {
                return Err(PeerError::Value(
                    "repeated graph caller, grant and program".into(),
                ));
            }
        }
        Ok(Self { callers, brokers })
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
            bindings: request.bindings.to_vec(),
        };
        let active =
            Activity::new(started + Duration::from_millis(u64::from(job.budget.timeout_ms)));
        let packages = request.evaluation.packages;
        let mut traffic = Traffic::default();
        let result = self.exchange_graph(
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
            |_, _| Err(unexpected_reply()),
        );
        if result.is_err() && cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        let (revision, value, graph) = result?;
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
    fn exchange_graph(
        &self,
        program: Hash,
        request: Request,
        active: Activity,
        cancellation: Option<&Cancellation>,
        traffic: &mut Traffic,
        mut get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
        mut callback: impl FnMut(Remote, Activity) -> Result<Vec<u8>>,
    ) -> Result<(u64, Vec<u8>, GraphMetrics)> {
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
        let mut callbacks = 0;
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
                Reply::Callback(remote) => {
                    callbacks += 1;
                    if callbacks > effects::MAX_EFFECTS {
                        return Err(PeerError::Limit("callback attempts"));
                    }
                    let reply = EffectReply::from(callback(remote, stream.sock.active()));
                    traffic.sent += protocol::send(&mut stream, &reply)?;
                }
                Reply::Graph {
                    revision,
                    value,
                    metrics,
                } => {
                    stream.sock.activity.check()?;
                    effects::check_response(&value)?;
                    return Ok((revision, value, metrics));
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
fn dial(
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
fn dial(endpoint: SocketAddr, active: &Activity, _: Option<&Cancellation>) -> Result<TcpStream> {
    Ok(TcpStream::connect_timeout(&endpoint, active.remaining()?)?)
}

#[derive(Default)]
struct Traffic {
    sent: u64,
    received: u64,
}

struct Broker<'a> {
    routes: Option<&'a BTreeMap<String, Route>>,
    packages: PeerStore,
    call: Call,
    metrics: Cell<GraphMetrics>,
}

impl Broker<'_> {
    fn invoke(&self, remote: Remote, scope: &mut Scope, mut active: Activity) -> Result<Vec<u8>> {
        self.packages.confirm_collection(self.call)?;
        let mut budget = scope.allocate(&remote)?;
        let route = self
            .routes
            .and_then(|routes| routes.get(&remote.target))
            .ok_or(PeerError::Denied)?;
        let mode = match remote.update {
            Some((expected_revision, operation)) if route.binding.access == Access::Write => {
                EvaluationMode::Update {
                    expected_revision,
                    operation,
                }
            }
            Some(_) => return Err(PeerError::Denied),
            None => EvaluationMode::Read,
        };
        if let Some(timeout) = remote.timeout_ms {
            active.deadline = active
                .deadline
                .min(Instant::now() + Duration::from_millis(timeout.into()));
        }
        active.check()?;
        budget.timeout_ms = active.remaining()?.as_millis().max(1) as u32;
        let mut child = Scope {
            budget,
            bindings: remote.delegate,
        };
        let job = GraphJob {
            grant: route.binding.grant,
            program: route.binding.program,
            mode,
            input: remote.input,
            budget,
            bindings: child.bindings.clone(),
        };
        let mut traffic = Traffic::default();
        let mut metrics = self.metrics.get();
        metrics.remote_calls += 1;
        self.metrics.set(metrics);
        let result = route.client.exchange_graph(
            job.program,
            Request::Subprocess(job),
            active,
            None,
            &mut traffic,
            |hash| self.packages.executable(self.call.holder, hash),
            |request, activity| self.invoke(request, &mut child, activity),
        );
        let mut metrics = self.metrics.get();
        metrics.remote_request_bytes += traffic.sent;
        metrics.remote_response_bytes += traffic.received;
        if let Ok((_, _, worker)) = result.as_ref() {
            // A child reports its own worker only. The broker observes every remote edge itself.
            metrics.add_worker(*worker);
        } else {
            metrics.remote_failures += 1;
        }
        self.metrics.set(metrics);
        let (revision, bytes, _) = result?;
        let value = Data::from_bytes(&bytes)?;
        let result = Data::Record(
            [
                (
                    "revision".into(),
                    Data::Int(i64::try_from(revision).map_err(|_| PeerError::Limit("revision"))?),
                ),
                ("value".into(), value),
            ]
            .into_iter()
            .collect(),
        );
        Ok(result.to_bytes()?)
    }
}

impl Server {
    pub(super) fn run_graph(
        &self,
        stream: &mut Inbound,
        store: &mut PeerStore,
        holder: Hash,
        job: GraphJob,
        subprocess: bool,
    ) -> Result<Reply> {
        stream.sock.check_active()?;
        effects::validate_binding_names(&job.bindings)?;
        if job.input.len() > Block::MAX_BYTES {
            return Err(PeerError::Limit("input bytes"));
        }
        Data::from_bytes(&job.input)?;
        let routes = self.graph.callers.get(&(holder, job.grant, job.program));
        if subprocess {
            if !job.bindings.is_empty() && !self.graph.brokers.contains(&holder) {
                return Err(PeerError::Denied);
            }
        } else if job
            .bindings
            .iter()
            .any(|name| routes.is_none_or(|routes| !routes.contains_key(name)))
        {
            return Err(PeerError::Denied);
        }
        let update = match job.mode {
            EvaluationMode::Read => None,
            EvaluationMode::Update {
                expected_revision,
                operation,
            } => {
                if job.budget.calls != 0 || !job.bindings.is_empty() {
                    return Err(PeerError::Denied);
                }
                // Deadline and placement metadata may change on a retry. Updates cannot issue
                // remote effects, so the program, revision and input fully describe the operation.
                Some(Update {
                    expected: expected_revision,
                    operation,
                    fingerprint: Hash::digest(&protocol::encode(&(
                        job.program,
                        job.mode,
                        &job.input,
                    ))?),
                })
            }
        };
        let call = Call {
            holder,
            grant: job.grant,
            program: job.program,
            update,
        };
        if let Some(receipt) = store.probe_collection(call)? {
            return Ok(graph_reply(receipt, GraphMetrics::default()));
        }
        let code = receive_code(stream, store, call)?;
        if !code[0].1.starts_with(content::MAGIC) {
            return Err(PeerError::Value(
                "graph evaluation requires JavaScript".into(),
            ));
        }

        let active = stream.sock.active();
        active.check()?;
        let broker = if subprocess || job.bindings.is_empty() {
            None
        } else {
            Some(Broker {
                routes,
                packages: PeerStore::open_with_timeout(&self.database, active.storage_wait()?)?,
                call,
                metrics: Cell::new(GraphMetrics::default()),
            })
        };
        let storage = match store.scoped(call, active.storage_wait()?)? {
            ScopedStart::Collection(storage) => storage,
            ScopedStart::Replayed(receipt) => {
                return Ok(graph_reply(receipt, GraphMetrics::default()));
            }
        };
        let mut scope = Scope {
            budget: job.budget,
            bindings: job.bindings,
        };
        let mut storage_effects = 0;
        let mut storage_us = 0;
        let output = worker::run(
            &self.worker,
            Work {
                program: job.program,
                code,
                input: job.input,
                context: WorkContext::Graph(Guest {
                    bindings: scope.bindings.clone(),
                    write: update.is_some(),
                }),
            },
            || active.check(),
            |effect| {
                effect.validate()?;
                let bytes = match effect {
                    Effect::Evaluate(remote) => {
                        if let Some(broker) = &broker {
                            broker.invoke(remote, &mut scope, active.clone())?
                        } else if subprocess && update.is_none() {
                            scope.allocate(&remote)?;
                            protocol::send(stream, &Reply::Callback(remote))?;
                            match protocol::receive::<EffectReply>(stream)?.0 {
                                EffectReply::Value(value) => value,
                                EffectReply::Failed(error) => return Err(error.into()),
                            }
                        } else {
                            return Err(PeerError::Denied);
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
        let receipt = storage.finish(output.value, || active.check())?;
        if update.is_none() {
            store.confirm_collection(call)?;
            active.check()?;
        }
        let mut metrics = broker.map_or_else(GraphMetrics::default, |broker| broker.metrics.get());
        metrics.add_worker(GraphMetrics {
            storage_effects,
            storage_us,
            worker_busy_us: output.busy_us,
            worker_elapsed_us: output.elapsed_us,
            worker_startup_us: output.startup_us,
            ..GraphMetrics::default()
        });
        Ok(graph_reply(receipt, metrics))
    }
}

fn graph_reply(receipt: crate::peer::storage::Receipt, metrics: GraphMetrics) -> Reply {
    Reply::Graph {
        revision: receipt.revision,
        value: receipt.value,
        metrics,
    }
}
