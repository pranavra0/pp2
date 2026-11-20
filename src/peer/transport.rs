use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::WebPkiClientVerifier,
};

use crate::{Block, Data, Hash};

pub use super::protocol::EvaluationMode;
use super::{
    Access, HostProvider, PeerError, PeerNetwork, PeerStore, ResourceView, Result,
    content::{self, MAX_MODULES, load_code},
    discovery::{IDENTITY_ALPN, Route, prove_transport, verify_transport},
    effects::{BindingSet, PeerEndpoint},
    protocol::{self, Job, Reply, Request},
    storage::{self, Call, EvaluationStart, Update},
    unix_ms,
    worker::{self, Work, WorkContext},
};

const ALPN: &[u8] = b"pp2/1";
const SERVER_EXPORTER: &[u8] = b"EXPORTER-pp2-server-identity-v1";
const CLIENT_EXPORTER: &[u8] = b"EXPORTER-pp2-client-identity-v1";
const DEADLINE: Duration = Duration::from_secs(8);
const MAX_CONNECTIONS: usize = 16;

mod graph;
mod jobs;
mod packages;
mod replicas;
pub use graph::{GraphEvaluation, GraphReport};
pub use jobs::{DurableEvaluation, JobStatus};
use packages::ContentSources;

/// TLS root certificates and one peer certificate with its private key.
#[derive(Clone, Debug)]
pub struct Credentials {
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
}

impl Credentials {
    pub fn fingerprint(path: impl AsRef<Path>) -> Result<Hash> {
        Ok(Hash::digest(&certificates(path.as_ref())?[0]))
    }

    fn roots(&self) -> Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        for cert in certificates(&self.ca)? {
            roots.add(cert).map_err(tls)?;
        }
        Ok(roots)
    }

    fn transport_keys(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&self.key)?))?
            .ok_or_else(|| PeerError::Tls("missing private key".into()))?;
        Ok((certificates(&self.certificate)?, key))
    }
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<io::Result<Vec<_>>>()?;
    if certs.is_empty() {
        return Err(PeerError::Tls("missing certificate".into()));
    }
    Ok(certs)
}

fn tls(error: impl std::fmt::Display) -> PeerError {
    PeerError::Tls(error.to_string())
}

#[derive(Clone)]
struct Activity {
    deadline: Instant,
    sockets: Vec<Arc<TcpStream>>,
    job: Option<Rc<jobs::Attempt>>,
    invocation: Option<Hash>,
}

impl Activity {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            sockets: Vec::new(),
            job: None,
            invocation: None,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))
    }

    fn storage_wait(&self) -> Result<Duration> {
        Ok(self.remaining()?.min(Duration::from_millis(100)))
    }

    fn check(&self) -> Result<()> {
        self.remaining()?;
        for tcp in &self.sockets {
            check_connected(tcp)?;
        }
        if let Some(job) = &self.job {
            job.check()?;
        }
        Ok(())
    }
}

fn check_connected(_tcp: &TcpStream) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut fd = libc::pollfd {
            fd: _tcp.as_raw_fd(),
            events: libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: the descriptor is held open and the kernel receives one initialized pollfd.
        if unsafe { libc::poll(&mut fd, 1, 0) } > 0
            && fd.revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR) != 0
        {
            return Err(PeerError::Cancelled);
        }
    }
    Ok(())
}

struct Socket {
    tcp: Arc<TcpStream>,
    activity: Activity,
}

impl Socket {
    fn active(&self) -> Activity {
        let mut active = self.activity.clone();
        active.sockets.push(self.tcp.clone());
        active
    }

    fn check_active(&self) -> Result<()> {
        self.activity.check()?;
        check_connected(&self.tcp)
    }

    fn io<T>(&self, mut operation: impl FnMut(Duration) -> io::Result<T>) -> io::Result<T> {
        let watch = !self.activity.sockets.is_empty() || self.activity.job.is_some();
        loop {
            let mut timeout = self.activity.remaining()?;
            if watch {
                self.activity.check().map_err(|err| match err {
                    PeerError::Timeout => io::Error::from(io::ErrorKind::TimedOut),
                    _ => io::Error::from(io::ErrorKind::ConnectionAborted),
                })?;
                timeout = timeout.min(Duration::from_millis(25));
            }
            match operation(timeout) {
                Err(error)
                    if watch
                        && matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                        ) =>
                {
                    continue;
                }
                result => return result,
            }
        }
    }
}

impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.io(|timeout| {
            self.tcp.set_read_timeout(Some(timeout))?;
            (&*self.tcp).read(bytes)
        })
    }
}

impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.io(|timeout| {
            self.tcp.set_write_timeout(Some(timeout))?;
            (&*self.tcp).write(bytes)
        })
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self.tcp).flush()
    }
}

#[derive(Clone)]
pub struct Client {
    destination: Destination,
    tls: Arc<ClientConfig>,
}

#[derive(Clone)]
enum Destination {
    Certificate {
        address: SocketAddr,
        name: ServerName<'static>,
        fingerprint: Option<Hash>,
    },
    Identity {
        network: PeerNetwork,
        id: Hash,
        fallback: Option<SocketAddr>,
    },
}

type Outbound = StreamOwned<ClientConnection, Socket>;
type Connected<'a> = (Outbound, Option<Registration<'a>>, ConnectionTiming);

#[derive(serde::Serialize)]
struct ConnectionTiming {
    dial_us: u64,
    authentication_us: u64,
}

/// A cancellation handle for one evaluation at a time. Once cancelled it stays cancelled.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<Mutex<CancellationState>>);

#[derive(Default)]
struct CancellationState {
    requested: bool,
    socket: Option<TcpStream>,
}

struct Registration<'a>(&'a Cancellation);

impl Cancellation {
    /// Closes the request connection. Retry an interrupted update with the same operation ID
    /// and revision to learn whether it committed.
    pub fn cancel(&self) {
        let mut state = self.0.lock().expect("cancellation mutex poisoned");
        state.requested = true;
        if let Some(socket) = &state.socket {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn requested(&self) -> bool {
        self.0
            .lock()
            .expect("cancellation mutex poisoned")
            .requested
    }

    fn register(&self, socket: &TcpStream) -> Result<Registration<'_>> {
        let mut state = self.0.lock().expect("cancellation mutex poisoned");
        if state.requested {
            return Err(PeerError::Cancelled);
        }
        if state.socket.is_some() {
            return Err(PeerError::Value(
                "cancellation handle already in use".into(),
            ));
        }
        state.socket = Some(socket.try_clone()?);
        Ok(Registration(self))
    }
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.0.0.lock().expect("cancellation mutex poisoned").socket = None;
    }
}

pub struct Evaluation<'a> {
    pub grant: Hash,
    pub program: Hash,
    pub mode: EvaluationMode,
    pub input: &'a Data,
    /// Local content source for the program and its declared JavaScript dependencies.
    pub packages: Option<&'a PeerStore>,
}

#[derive(Debug)]
pub struct RemoteReport {
    pub revision: u64,
    pub view: Option<ResourceView>,
    pub value: Data,
    pub elapsed_ms: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// None when the peer returned an already-committed receipt.
    pub worker_ms: Option<u64>,
    /// Charged reductions for binary IR. JavaScript is limited by wall time and heap size.
    pub fuel: Option<u64>,
    /// Charged bytes for binary IR, or the JavaScript heap sample at completion.
    pub memory_bytes: Option<u64>,
}

impl Client {
    pub fn new(endpoint: SocketAddr, name: impl Into<String>, creds: &Credentials) -> Result<Self> {
        let (certs, key) = creds.transport_keys()?;
        let name = ServerName::try_from(name.into()).map_err(tls)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(creds.roots()?)
            .with_client_auth_cert(certs, key)
            .map_err(tls)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            destination: Destination::Certificate {
                address: endpoint,
                name,
                fingerprint: None,
            },
            tls: Arc::new(config),
        })
    }

    /// Addresses the destination by its stable identity, with an optional pinned route.
    pub fn for_peer(network: &PeerNetwork, id: Hash, fallback: Option<SocketAddr>) -> Self {
        Self {
            destination: Destination::Identity {
                network: network.clone(),
                id,
                fallback,
            },
            tls: network.tls(),
        }
    }

    fn pin_certificate(&mut self, expected: Hash) {
        if let Destination::Certificate { fingerprint, .. } = &mut self.destination {
            *fingerprint = Some(expected);
        }
    }

    fn connect(&self, started: Instant) -> Result<Outbound> {
        Ok(self
            .connect_active(Activity::new(started + DEADLINE), None)?
            .0)
    }

    fn connect_active<'a>(
        &self,
        active: Activity,
        cancellation: Option<&'a Cancellation>,
    ) -> Result<Connected<'a>> {
        let Destination::Identity {
            network,
            id,
            fallback,
        } = &self.destination
        else {
            let Destination::Certificate { address, .. } = self.destination else {
                unreachable!()
            };
            return self.try_route(Route::Direct(address), active, cancellation);
        };
        network.check_identity(*id)?;
        let mut tried = Vec::new();
        let mut try_routes = |routes: Vec<Route>| -> Result<Option<Connected<'a>>> {
            for route in routes {
                active.check()?;
                if cancellation.is_some_and(Cancellation::requested) {
                    return Err(PeerError::Cancelled);
                }
                if tried.contains(&route) {
                    continue;
                }
                tried.push(route);
                let mut attempt = active.clone();
                attempt.deadline = attempt
                    .deadline
                    .min(Instant::now() + Duration::from_millis(450));
                match self.try_route(route, attempt, cancellation) {
                    Ok((mut stream, registration, timing)) => {
                        stream.sock.activity = active.clone();
                        return Ok(Some((stream, registration, timing)));
                    }
                    Err(
                        error @ (PeerError::Denied | PeerError::Cancelled | PeerError::Value(_)),
                    ) => {
                        return Err(error);
                    }
                    Err(_) => {}
                }
            }
            Ok(None)
        };
        if let Some(stream) = try_routes(network.routes(*id, true))? {
            return Ok(stream);
        }
        if let Some(address) = fallback
            && let Some(stream) = try_routes(vec![Route::Direct(*address)])?
        {
            return Ok(stream);
        }
        if let Some(stream) = try_routes(network.routes(*id, false))? {
            return Ok(stream);
        }
        active.check()?;
        network.refresh_rendezvous(Some(*id), active.deadline);
        if let Some(stream) = try_routes(network.routes(*id, true))? {
            return Ok(stream);
        }
        if let Some(stream) = try_routes(network.routes(*id, false))? {
            return Ok(stream);
        }
        let until = active
            .deadline
            .min(Instant::now() + Duration::from_millis(500));
        while network.can_wait_for_lan() && Instant::now() < until {
            active.check()?;
            if cancellation.is_some_and(Cancellation::requested) {
                return Err(PeerError::Cancelled);
            }
            if let Some(stream) = try_routes(network.routes(*id, true))? {
                return Ok(stream);
            }
            thread::sleep(Duration::from_millis(20));
        }
        active.check()?;
        if cancellation.is_some_and(Cancellation::requested) {
            return Err(PeerError::Cancelled);
        }
        Err(PeerError::PeerUnavailable(*id))
    }

    fn try_route<'a>(
        &self,
        route: Route,
        activity: Activity,
        cancellation: Option<&'a Cancellation>,
    ) -> Result<Connected<'a>> {
        let started = Instant::now();
        let tcp = match route {
            Route::Direct(address) => graph::dial(address, &activity, cancellation)?,
            Route::Relay(address) => {
                let Destination::Identity { network, id, .. } = &self.destination else {
                    return Err(PeerError::Denied);
                };
                network.relay(address, *id, activity.deadline)?
            }
        };
        let registration = cancellation
            .map(|handle| handle.register(&tcp))
            .transpose()?;
        let dial_us = protocol::elapsed_us(started);
        let authentication = Instant::now();
        let stream = self.handshake(tcp, activity)?;
        let timing = ConnectionTiming {
            dial_us,
            authentication_us: protocol::elapsed_us(authentication),
        };
        Ok((stream, registration, timing))
    }

    fn handshake(&self, tcp: TcpStream, activity: Activity) -> Result<Outbound> {
        tcp.set_nodelay(true)?;
        let mut socket = Socket {
            tcp: Arc::new(tcp),
            activity,
        };
        let (name, alpn) = match &self.destination {
            Destination::Certificate { name, .. } => (name.clone(), ALPN),
            Destination::Identity { .. } => (
                ServerName::try_from("pp2.invalid").expect("constant DNS name"),
                IDENTITY_ALPN,
            ),
        };
        let mut conn = ClientConnection::new(self.tls.clone(), name).map_err(tls)?;
        conn.complete_io(&mut socket)?;
        if conn.alpn_protocol() != Some(alpn) {
            return Err(PeerError::Protocol(
                "peer did not negotiate the expected pp2 transport".into(),
            ));
        }
        let mut stream = StreamOwned::new(conn, socket);
        match &self.destination {
            Destination::Certificate { fingerprint, .. } => {
                if fingerprint.is_some_and(|expected| {
                    stream
                        .conn
                        .peer_certificates()
                        .and_then(|certs| certs.first())
                        .is_none_or(|cert| Hash::digest(cert) != expected)
                }) {
                    return Err(PeerError::Denied);
                }
            }
            Destination::Identity { network, id, .. } => {
                let exporter = stream
                    .conn
                    .export_keying_material([0; 32], SERVER_EXPORTER, None)
                    .map_err(tls)?;
                let verified = verify_transport(&mut stream, &exporter).map_err(tls)?;
                if verified != *id {
                    return Err(tls("unexpected pp2 peer identity"));
                }
                let exporter = stream
                    .conn
                    .export_keying_material([0; 32], CLIENT_EXPORTER, None)
                    .map_err(tls)?;
                prove_transport(network.identity(), &mut stream, &exporter)?;
                let mut status = [0];
                stream.read_exact(&mut status)?;
                match status[0] {
                    1 => {}
                    0 => return Err(PeerError::Denied),
                    _ => return Err(unexpected_reply()),
                }
            }
        }
        Ok(stream)
    }

    /// Delegates a subset of a grant to another authenticated identity.
    pub fn delegate(
        &self,
        grant: Hash,
        holder: Hash,
        access: Access,
        program: Option<Hash>,
    ) -> Result<Hash> {
        let mut stream = self.connect(Instant::now())?;
        protocol::send(
            &mut stream,
            &Request::Delegate {
                grant,
                holder,
                access,
                program,
            },
        )?;
        match protocol::receive::<Reply>(&mut stream)?.0 {
            Reply::Delegated(token) => Ok(token),
            Reply::Failed(error) => Err(error.into()),
            _ => Err(unexpected_reply()),
        }
    }

    /// Evaluates a content-addressed program at this peer. The selected grant determines the data location.
    pub fn evaluate(&self, evaluation: Evaluation<'_>) -> Result<RemoteReport> {
        self.evaluate_inner(evaluation, None)
    }

    pub fn evaluate_cancellable(
        &self,
        evaluation: Evaluation<'_>,
        cancellation: &Cancellation,
    ) -> Result<RemoteReport> {
        if cancellation.requested() {
            return Err(PeerError::Cancelled);
        }
        let outcome = self.evaluate_inner(evaluation, Some(cancellation));
        if outcome.is_err() && cancellation.requested() {
            return Err(PeerError::Cancelled);
        }
        outcome
    }

    fn evaluate_inner(
        &self,
        evaluation: Evaluation<'_>,
        cancellation: Option<&Cancellation>,
    ) -> Result<RemoteReport> {
        let started = Instant::now();
        let (mut stream, _registration, _) =
            self.connect_active(Activity::new(started + DEADLINE), cancellation)?;
        let mut sent = protocol::send(
            &mut stream,
            &Request::Evaluate(Job {
                grant: evaluation.grant,
                program: evaluation.program,
                mode: evaluation.mode,
                input: evaluation.input.to_bytes()?,
            }),
        )?;
        let mut received = 0;
        let mut code = None;
        let mut requested = BTreeSet::new();
        loop {
            let (reply, bytes) = protocol::receive::<Reply>(&mut stream)?;
            received += bytes;
            let (reply, view) = match reply {
                Reply::ResourceEvaluation {
                    revision,
                    value,
                    metrics,
                    view,
                } => (
                    Reply::Evaluation {
                        revision,
                        value,
                        metrics,
                    },
                    Some(view),
                ),
                reply => (reply, None),
            };
            match reply {
                Reply::NeedProgram(hash) => {
                    if requested.len() >= MAX_MODULES || !requested.insert(hash) {
                        return Err(PeerError::Protocol("invalid program negotiation".into()));
                    }
                    if code.is_none() {
                        let mut initial = BTreeMap::new();
                        if let Some(packages) = evaluation.packages {
                            initial
                                .extend(load_code(evaluation.program, true, |h| packages.get(h))?);
                        }
                        code = Some(initial);
                    }
                    let bytes = code.as_mut().and_then(|blocks| blocks.remove(&hash));
                    sent += protocol::send(&mut stream, &bytes)?;
                }
                Reply::Evaluation {
                    revision,
                    value,
                    metrics,
                } => {
                    return Ok(RemoteReport {
                        revision,
                        view,
                        value: Data::from_bytes(&value)?,
                        elapsed_ms: protocol::elapsed_ms(started),
                        request_bytes: sent,
                        response_bytes: received,
                        worker_ms: metrics.map(|m| m.elapsed_ms),
                        fuel: metrics.and_then(|m| m.fuel),
                        memory_bytes: metrics.map(|m| m.memory),
                    });
                }
                Reply::Failed(error) => return Err(error.into()),
                _ => return Err(unexpected_reply()),
            }
        }
    }
}

fn evaluation_reply(
    revision: u64,
    value: Vec<u8>,
    metrics: Option<protocol::Metrics>,
    view: Option<ResourceView>,
) -> Reply {
    match view {
        Some(view) => Reply::ResourceEvaluation {
            revision,
            value,
            metrics,
            view,
        },
        None => Reply::Evaluation {
            revision,
            value,
            metrics,
        },
    }
}

fn unexpected_reply() -> PeerError {
    PeerError::Protocol("unexpected peer reply".into())
}

pub struct Server {
    database: PathBuf,
    worker: PathBuf,
    tls: Arc<ServerConfig>,
    graph: graph::Configuration,
    providers: BTreeMap<String, Arc<dyn HostProvider>>,
    identity: Hash,
    network: Option<PeerNetwork>,
}

impl Server {
    /// The worker executable must invoke `pp2::peer::worker_main` for `__worker PARENT_PID`.
    pub fn new(
        database: impl AsRef<Path>,
        worker: impl AsRef<Path>,
        creds: &Credentials,
    ) -> Result<Self> {
        Self::new_inner(database.as_ref(), worker.as_ref(), creds, None)
    }

    /// Serves the stable identity protocol using an independently replaceable TLS certificate.
    pub fn new_discovered(
        database: impl AsRef<Path>,
        worker: impl AsRef<Path>,
        creds: &Credentials,
        network: PeerNetwork,
    ) -> Result<Self> {
        Self::new_inner(database.as_ref(), worker.as_ref(), creds, Some(network))
    }

    fn new_inner(
        database: &Path,
        worker: &Path,
        creds: &Credentials,
        network: Option<PeerNetwork>,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(PeerError::Unsupported("peer server requires Linux"));
        }
        PeerStore::open(database)?;
        let (certs, key) = creds.transport_keys()?;
        let builder = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]);
        let (builder, alpn, identity) = if let Some(network) = &network {
            (builder.with_no_client_auth(), IDENTITY_ALPN, network.id())
        } else {
            let verifier = WebPkiClientVerifier::builder(Arc::new(creds.roots()?))
                .build()
                .map_err(tls)?;
            (
                builder.with_client_cert_verifier(verifier),
                ALPN,
                Hash::digest(&certs[0]),
            )
        };
        let mut config = builder.with_single_cert(certs, key).map_err(tls)?;
        config.alpn_protocols = vec![alpn.to_vec()];
        config.send_tls13_tickets = 0;
        Ok(Self {
            database: database.canonicalize()?,
            worker: worker.canonicalize()?,
            tls: Arc::new(config),
            graph: graph::Configuration::new(creds, network.as_ref(), Vec::new(), Vec::new())?,
            providers: {
                #[cfg(target_os = "linux")]
                {
                    let directory: Arc<dyn HostProvider> = Arc::new(super::Directory);
                    BTreeMap::from([(super::Directory::PROVIDER.into(), directory)])
                }
                #[cfg(not(target_os = "linux"))]
                BTreeMap::new()
            },
            identity,
            network,
        })
    }

    /// Configures named capabilities and optional pinned routes.
    pub fn with_graph(
        mut self,
        creds: &Credentials,
        bindings: Vec<BindingSet>,
        endpoints: Vec<PeerEndpoint>,
    ) -> Result<Self> {
        self.graph = graph::Configuration::new(creds, self.network.as_ref(), bindings, endpoints)?;
        Ok(self)
    }

    /// Registers a provider for administrator-created host resources of this kind.
    pub fn with_host_provider(
        mut self,
        name: &str,
        provider: impl HostProvider + 'static,
    ) -> Result<Self> {
        super::effects::validate_binding_name(name)?;
        if self.providers.contains_key(name) {
            return Err(PeerError::Value("host provider already registered".into()));
        }
        self.providers.insert(name.into(), Arc::new(provider));
        Ok(self)
    }

    pub fn serve(self, listener: TcpListener) -> Result<()> {
        // Separate from SQLite's record locks. Only one daemon can reclaim this queue.
        let database = File::open(&self.database)?;
        database.try_lock().map_err(|error| {
            io::Error::other(format!(
                "could not lock the peer database for serving: {error}"
            ))
        })?;
        PeerStore::open(&self.database)?.recover_jobs()?;
        let bound = listener.local_addr()?;
        let server = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));
        let stop = AtomicBool::new(false);
        let accept = |tcp| server.accept(tcp, &active);
        thread::scope(|scope| {
            if let Some(network) = &server.network {
                scope.spawn(|| network.maintain(bound, &stop));
                network.spawn_relays(scope, &stop, &accept);
                scope.spawn(|| server.synchronize_replicas(network, &stop));
            }
            scope.spawn(|| server.schedule_applications(&stop));
            for _ in 0..jobs::WORKERS {
                scope.spawn(|| server.work_jobs(&stop));
            }
            let result = listener.incoming().try_for_each(|tcp| {
                accept(tcp?);
                Ok(())
            });
            stop.store(true, Ordering::Relaxed);
            result
        })
    }

    fn accept(self: &Arc<Self>, tcp: TcpStream, active: &Arc<AtomicUsize>) {
        if active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < MAX_CONNECTIONS).then_some(n + 1)
            })
            .is_ok()
        {
            let slot = Slot(active.clone());
            let server = self.clone();
            if let Err(error) = thread::Builder::new()
                .name("pp2-peer".into())
                .spawn(move || {
                    let _slot = slot;
                    let _ = server.handle(tcp);
                })
            {
                let _ = writeln!(
                    io::stderr().lock(),
                    "pp2 peer could not start a connection handler ({:?})",
                    error.kind()
                );
            }
        }
    }

    fn handle(&self, tcp: TcpStream) -> Result<()> {
        tcp.set_nodelay(true)?;
        let mut socket = Socket {
            tcp: Arc::new(tcp),
            activity: Activity::new(Instant::now() + DEADLINE),
        };
        let mut conn = ServerConnection::new(self.tls.clone()).map_err(tls)?;
        conn.complete_io(&mut socket)?;
        let alpn = if self.network.is_some() {
            IDENTITY_ALPN
        } else {
            ALPN
        };
        if conn.alpn_protocol() != Some(alpn) {
            return Err(PeerError::Denied);
        }
        let mut stream = StreamOwned::new(conn, socket);
        let holder = if let Some(network) = &self.network {
            let exporter = stream
                .conn
                .export_keying_material([0; 32], SERVER_EXPORTER, None)
                .map_err(tls)?;
            prove_transport(network.identity(), &mut stream, &exporter)?;
            let exporter = stream
                .conn
                .export_keying_material([0; 32], CLIENT_EXPORTER, None)
                .map_err(tls)?;
            let id = verify_transport(&mut stream, &exporter)?;
            let allowed = network.check_identity(id);
            stream.write_all(&[u8::from(allowed.is_ok())])?;
            stream.flush()?;
            allowed?;
            id
        } else {
            let cert = stream
                .conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .ok_or(PeerError::Denied)?;
            Hash::digest(cert)
        };
        let (mut request, _) = protocol::receive(&mut stream)?;
        let outcome = (|| {
            let mut store = if let Request::Run(job) = &mut request {
                job.budget.validate()?;
                let now = unix_ms();
                job.expires_at_ms = job
                    .expires_at_ms
                    .min(now + u64::from(job.budget.timeout_ms));
                let remaining = job.expires_at_ms.saturating_sub(now);
                stream.sock.activity.deadline = stream.sock.activity.deadline.min(
                    Instant::now()
                        + Duration::from_millis(remaining.min(job.budget.timeout_ms.into())),
                );
                stream.sock.check_active()?;
                PeerStore::open_with_timeout(&self.database, stream.sock.activity.storage_wait()?)?
            } else {
                PeerStore::open(&self.database)?
            };
            match request {
                Request::Fetch(hash) => store
                    .public(hash)?
                    .map(Reply::Block)
                    .ok_or(PeerError::Missing(hash)),
                Request::Delegate {
                    grant,
                    holder: delegate,
                    access,
                    program,
                } => store
                    .delegate(holder, grant, delegate, access, program)
                    .map(Reply::Delegated),
                Request::Evaluate(job) => self.evaluate(&mut stream, &mut store, holder, job),
                Request::Run(job) => self.run_graph(&mut stream, &mut store, holder, job),
                Request::Forward(request) => store.forward(holder, request).map(Reply::Delegated),
                Request::Submit(submission) => {
                    self.submit_job(&mut stream, &mut store, holder, submission, false)
                }
                Request::SubmitReaction(submission) => {
                    self.submit_job(&mut stream, &mut store, holder, submission, true)
                }
                Request::JobStatus(id) => store
                    .job_status(
                        storage::JobKey { holder, id },
                        self.network.as_ref().map(PeerNetwork::id),
                    )
                    .map(Reply::Job),
                Request::CancelJob(id) => store
                    .cancel_job(
                        storage::JobKey { holder, id },
                        self.network.as_ref().map(PeerNetwork::id),
                    )
                    .map(Reply::Job),
                Request::Replica(request) => {
                    let network = self.network.as_ref().ok_or(PeerError::Denied)?;
                    match request.block {
                        Some(hash) => store
                            .serve_replica_block(self.identity, holder, &request, hash)
                            .map(Reply::Block),
                        None => store
                            .offer_replica(network.identity(), holder, &request)
                            .map(Box::new)
                            .map(Reply::Replica),
                    }
                }
                Request::LegacyRun | Request::LegacySubprocess => Err(unexpected_reply()),
            }
        })();
        let reply = outcome.unwrap_or_else(|err| Reply::Failed(err.into()));
        protocol::send(&mut stream, &reply)?;
        stream.conn.send_close_notify();
        let _ = stream.flush();
        Ok(())
    }

    fn evaluate(
        &self,
        stream: &mut StreamOwned<ServerConnection, Socket>,
        store: &mut PeerStore,
        holder: Hash,
        job: Job,
    ) -> Result<Reply> {
        if job.input.len() > Block::MAX_BYTES {
            return Err(PeerError::Limit("input bytes"));
        }
        let update = job
            .mode
            .update()
            .map(|(expected, operation, merge)| {
                Ok::<_, PeerError>(Update {
                    expected,
                    operation,
                    merge,
                    fingerprint: Hash::digest(&protocol::encode(&job)?),
                })
            })
            .transpose()?;
        let call = Call {
            holder,
            grant: job.grant,
            program: job.program,
            update,
            graph: None,
            reaction: false,
            consistency: job.mode.consistency(),
            executor: self.network.as_ref().map(PeerNetwork::id),
        };
        let mut snapshot = match store.begin(call)? {
            EvaluationStart::Replayed(receipt) => {
                return Ok(evaluation_reply(
                    receipt.revision,
                    receipt.value,
                    None,
                    receipt.view,
                ));
            }
            EvaluationStart::Snapshot(snapshot) => snapshot,
        };
        Data::from_bytes(&job.input)?;
        let code = self.receive_code(stream, store, call)?;
        stream.sock.check_active()?;
        let output = worker::run(
            &self.worker,
            Work {
                program: job.program,
                code,
                input: job.input,
                context: WorkContext::Snapshot {
                    hash: snapshot.hash,
                    bytes: std::mem::take(&mut snapshot.bytes),
                    view: snapshot.view.clone(),
                },
            },
            || stream.sock.check_active(),
            |_| Err(PeerError::Denied),
        )?;
        let result = Data::from_bytes(&output.value)?;
        stream.sock.check_active()?;
        let (revision, value, view) = if update.is_some() {
            let Data::Record(mut result) = result else {
                return Err(update_result_error());
            };
            let next = result.remove("next").ok_or_else(update_result_error)?;
            let value = result.remove("value").ok_or_else(update_result_error)?;
            if !result.is_empty() {
                return Err(update_result_error());
            }
            let receipt = store.commit(
                call,
                &snapshot,
                self.network.as_ref().map(PeerNetwork::identity),
                &Block::Data(next).to_bytes()?,
                value.to_bytes()?,
            )?;
            (receipt.revision, receipt.value, receipt.view)
        } else {
            store.confirm(call, &snapshot.view)?;
            (
                snapshot.revision.number,
                output.value,
                snapshot.view.resource.is_some().then_some(snapshot.view),
            )
        };
        Ok(evaluation_reply(
            revision,
            value,
            Some(output.metrics),
            view,
        ))
    }

    fn receive_code(
        &self,
        stream: &mut StreamOwned<ServerConnection, Socket>,
        store: &mut PeerStore,
        call: Call,
    ) -> Result<Vec<(Hash, Vec<u8>)>> {
        let mut supplied = BTreeSet::new();
        let mut sources = self
            .network
            .as_ref()
            .map(|network| ContentSources::new(network, stream.sock.active()));
        let code = load_code(call.program, false, |hash| {
            stream.sock.check_active()?;
            if let Some(bytes) = store.executable(call.holder, hash)? {
                return Ok(Some(bytes));
            }
            protocol::send(stream, &Reply::NeedProgram(hash))?;
            let (mut bytes, _) = protocol::receive::<Option<Vec<u8>>>(stream)?;
            if bytes.is_none()
                && let Some(sources) = &mut sources
            {
                match sources.fetch(hash) {
                    Ok(found) => bytes = Some(found),
                    Err(PeerError::Missing(_)) => {}
                    Err(error) => return Err(error),
                }
            }
            if bytes.is_some() {
                supplied.insert(hash);
            }
            Ok(bytes)
        })?;
        stream.sock.check_active()?;
        if supplied.is_empty() {
            store.confirm_access(call)?;
        } else {
            store.cache_code(
                call,
                code.iter().filter(|(hash, _)| supplied.contains(hash)),
            )?;
        }
        Ok(code)
    }
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn update_result_error() -> PeerError {
    PeerError::Value("expected exactly {next, value} from an update".into())
}
