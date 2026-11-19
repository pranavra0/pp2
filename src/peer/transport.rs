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
    Access, PeerError, PeerStore, Result,
    content::{self, Kind, MAX_CODE, MAX_MODULES},
    effects::{BindingSet, PeerEndpoint},
    protocol::{self, Job, Reply, Request},
    storage::{self, Call, EvaluationStart, Update},
    unix_ms,
    worker::{self, Work, WorkContext},
};

const ALPN: &[u8] = b"pp2/1";
const DEADLINE: Duration = Duration::from_secs(8);
const MAX_CONNECTIONS: usize = 16;

mod graph;
mod jobs;
pub use graph::{GraphEvaluation, GraphReport};
pub use jobs::{DurableEvaluation, JobStatus};

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

    fn identity(&self) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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
}

impl Activity {
    fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            sockets: Vec::new(),
            job: None,
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
    endpoint: SocketAddr,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    fingerprint: Option<Hash>,
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
        let (certs, key) = creds.identity()?;
        let name = ServerName::try_from(name.into()).map_err(tls)?;
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(creds.roots()?)
            .with_client_auth_cert(certs, key)
            .map_err(tls)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            endpoint,
            name,
            tls: Arc::new(config),
            fingerprint: None,
        })
    }

    fn connect(&self, started: Instant) -> Result<StreamOwned<ClientConnection, Socket>> {
        let tcp = TcpStream::connect_timeout(&self.endpoint, DEADLINE)?;
        self.handshake(tcp, Activity::new(started + DEADLINE))
    }

    fn handshake(
        &self,
        tcp: TcpStream,
        activity: Activity,
    ) -> Result<StreamOwned<ClientConnection, Socket>> {
        tcp.set_nodelay(true)?;
        let mut socket = Socket {
            tcp: Arc::new(tcp),
            activity,
        };
        let mut conn = ClientConnection::new(self.tls.clone(), self.name.clone()).map_err(tls)?;
        conn.complete_io(&mut socket)?;
        if conn.alpn_protocol() != Some(ALPN) {
            return Err(PeerError::Protocol("peer did not negotiate pp2/1".into()));
        }
        if self.fingerprint.is_some_and(|expected| {
            conn.peer_certificates()
                .and_then(|certs| certs.first())
                .is_none_or(|cert| Hash::digest(cert) != expected)
        }) {
            return Err(PeerError::Denied);
        }
        Ok(StreamOwned::new(conn, socket))
    }

    /// Fetches one published block and verifies its content address and format.
    pub fn fetch(&self, hash: Hash) -> Result<Vec<u8>> {
        let mut stream = self.connect(Instant::now())?;
        protocol::send(&mut stream, &Request::Fetch(hash))?;
        match protocol::receive::<Reply>(&mut stream)?.0 {
            Reply::Block(bytes) => {
                content::inspect(hash, &bytes)?;
                Ok(bytes)
            }
            Reply::Failed(error) => Err(error.into()),
            _ => Err(unexpected_reply()),
        }
    }

    /// Checks the local cache, then tries sources in the caller's order of preference.
    pub fn fetch_into(cache: &mut PeerStore, sources: &[Self], hash: Hash) -> Result<Vec<u8>> {
        if let Some(bytes) = cache.get(hash)? {
            return Ok(bytes);
        }
        let mut failure = PeerError::Missing(hash);
        for source in sources {
            match source.fetch(hash) {
                Ok(bytes) => {
                    cache.import(hash, &bytes)?;
                    return Ok(bytes);
                }
                Err(PeerError::Missing(_)) => {}
                Err(error) => failure = error,
            }
        }
        Err(failure)
    }

    /// Resolves a program and its imports from a cache and ordered authenticated sources.
    /// Returns the verified addresses so callers can retain or republish the package.
    pub fn fetch_program(cache: &mut PeerStore, sources: &[Self], root: Hash) -> Result<Vec<Hash>> {
        let graph = load_code(root, false, |hash| {
            Self::fetch_into(cache, sources, hash).map(Some)
        })?;
        Ok(graph.into_iter().map(|(hash, _)| hash).collect())
    }

    /// Delegates a subset of a grant to the holder of another TLS certificate.
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
        let tcp = TcpStream::connect_timeout(&self.endpoint, DEADLINE)?;
        let _registration = cancellation
            .map(|handle| handle.register(&tcp))
            .transpose()?;
        let mut stream = self.handshake(tcp, Activity::new(started + DEADLINE))?;
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

fn unexpected_reply() -> PeerError {
    PeerError::Protocol("unexpected peer reply".into())
}

pub struct Server {
    database: PathBuf,
    worker: PathBuf,
    tls: Arc<ServerConfig>,
    graph: graph::Configuration,
}

impl Server {
    /// The worker executable must invoke `pp2::peer::worker_main` for `__worker PARENT_PID`.
    pub fn new(
        database: impl AsRef<Path>,
        worker: impl AsRef<Path>,
        creds: &Credentials,
    ) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(PeerError::Unsupported("peer server requires Linux"));
        }
        PeerStore::open(database.as_ref())?;
        let (certs, key) = creds.identity()?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(creds.roots()?))
            .build()
            .map_err(tls)?;
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(tls)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.send_tls13_tickets = 0;
        Ok(Self {
            database: database.as_ref().canonicalize()?,
            worker: worker.as_ref().canonicalize()?,
            tls: Arc::new(config),
            graph: graph::Configuration::default(),
        })
    }

    /// Configures named capabilities and the local directory of trusted peer endpoints.
    pub fn with_graph(
        mut self,
        creds: &Credentials,
        bindings: Vec<BindingSet>,
        endpoints: Vec<PeerEndpoint>,
    ) -> Result<Self> {
        self.graph = graph::Configuration::new(creds, bindings, endpoints)?;
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
        let server = Arc::new(self);
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            for _ in 0..jobs::WORKERS {
                scope.spawn(|| server.work_jobs(&stop));
            }
            let result = server.serve_connections(listener);
            stop.store(true, Ordering::Relaxed);
            result
        })
    }

    fn serve_connections(self: &Arc<Self>, listener: TcpListener) -> Result<()> {
        let active = Arc::new(AtomicUsize::new(0));
        for tcp in listener.incoming() {
            let tcp = tcp?;
            if active
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < MAX_CONNECTIONS).then_some(n + 1)
                })
                .is_err()
            {
                continue;
            }
            let slot = Slot(active.clone());
            let server = self.clone();
            thread::Builder::new()
                .name("pp2-peer".into())
                .spawn(move || {
                    let _slot = slot;
                    let _ = server.handle(tcp);
                })?;
        }
        Ok(())
    }

    fn handle(&self, tcp: TcpStream) -> Result<()> {
        tcp.set_nodelay(true)?;
        let mut socket = Socket {
            tcp: Arc::new(tcp),
            activity: Activity::new(Instant::now() + DEADLINE),
        };
        let mut conn = ServerConnection::new(self.tls.clone()).map_err(tls)?;
        conn.complete_io(&mut socket)?;
        if conn.alpn_protocol() != Some(ALPN) {
            return Err(PeerError::Denied);
        }
        let cert = conn
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(PeerError::Denied)?;
        let holder = Hash::digest(cert);
        let mut stream = StreamOwned::new(conn, socket);
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
                    self.submit_job(&mut stream, &mut store, holder, submission)
                }
                Request::JobStatus(id) => store
                    .job_status(storage::JobKey { holder, id })
                    .map(Reply::Job),
                Request::CancelJob(id) => store
                    .cancel_job(storage::JobKey { holder, id })
                    .map(Reply::Job),
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
        let update = match job.mode {
            EvaluationMode::Read => None,
            EvaluationMode::Update {
                expected_revision,
                operation,
            } => Some(Update {
                expected: expected_revision,
                operation,
                fingerprint: Hash::digest(&protocol::encode(&job)?),
            }),
        };
        let call = Call {
            holder,
            grant: job.grant,
            program: job.program,
            update,
            graph: None,
        };
        let mut snapshot = match store.begin(call)? {
            EvaluationStart::Replayed(receipt) => {
                return Ok(Reply::Evaluation {
                    revision: receipt.revision,
                    value: receipt.value,
                    metrics: None,
                });
            }
            EvaluationStart::Snapshot(snapshot) => snapshot,
        };
        Data::from_bytes(&job.input)?;
        let code = receive_code(stream, store, call)?;
        stream.sock.check_active()?;
        let output = worker::run(
            &self.worker,
            Work {
                program: job.program,
                code,
                input: job.input,
                context: WorkContext::Snapshot {
                    hash: snapshot.revision.hash,
                    bytes: std::mem::take(&mut snapshot.bytes),
                },
            },
            || stream.sock.check_active(),
            |_| Err(PeerError::Denied),
        )?;
        let result = Data::from_bytes(&output.value)?;
        stream.sock.check_active()?;
        let (revision, value) = if update.is_some() {
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
                &Block::Data(next).to_bytes()?,
                value.to_bytes()?,
            )?;
            (receipt.revision, receipt.value)
        } else {
            store.confirm(call)?;
            (snapshot.revision.number, output.value)
        };
        Ok(Reply::Evaluation {
            revision,
            value,
            metrics: Some(output.metrics),
        })
    }
}

fn receive_code(
    stream: &mut StreamOwned<ServerConnection, Socket>,
    store: &mut PeerStore,
    call: Call,
) -> Result<Vec<(Hash, Vec<u8>)>> {
    let mut supplied = BTreeSet::new();
    let code = load_code(call.program, false, |hash| {
        stream.sock.check_active()?;
        if let Some(bytes) = store.executable(call.holder, hash)? {
            return Ok(Some(bytes));
        }
        protocol::send(stream, &Reply::NeedProgram(hash))?;
        let (bytes, _) = protocol::receive::<Option<Vec<u8>>>(stream)?;
        if bytes.is_some() {
            supplied.insert(hash);
        }
        Ok(bytes)
    })?;
    stream.sock.check_active()?;
    if supplied.is_empty() {
        store.confirm(call)?;
    } else {
        store.cache_code(
            call,
            code.iter().filter(|(hash, _)| supplied.contains(hash)),
        )?;
    }
    Ok(code)
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

fn load_code(
    root: Hash,
    allow_missing: bool,
    mut get: impl FnMut(Hash) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<(Hash, Vec<u8>)>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![root];
    let mut graph = Vec::new();
    let mut bytes_left = MAX_CODE;
    while let Some(hash) = pending.pop() {
        if !seen.insert(hash) {
            continue;
        }
        if seen.len() > MAX_MODULES {
            return Err(PeerError::Limit("module graph count"));
        }
        let Some(bytes) = get(hash)? else {
            if allow_missing {
                continue;
            }
            return Err(PeerError::Missing(hash));
        };
        bytes_left = bytes_left
            .checked_sub(bytes.len())
            .ok_or(PeerError::Limit("module graph bytes"))?;
        match content::inspect(hash, &bytes)? {
            (Kind::JavaScript, imports) => pending.extend(imports),
            (Kind::Aeb, _) if hash == root => {}
            _ => {
                return Err(PeerError::Value(
                    "unexpected block kind in module graph".into(),
                ));
            }
        }
        graph.push((hash, bytes));
    }
    Ok(graph)
}
