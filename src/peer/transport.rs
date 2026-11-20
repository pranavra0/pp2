use super::{
    Hash, Invocation, Peer, PeerError, Result,
    discovery::{self, Route},
    protocol,
};
use rustls::{
    ClientConnection, ServerConfig, ServerConnection, StreamOwned, pki_types::ServerName,
};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const SERVER_EXPORTER: &[u8] = b"EXPORTER-pp2-server-identity-v1";
const CLIENT_EXPORTER: &[u8] = b"EXPORTER-pp2-client-identity-v1";
const DEADLINE: Duration = Duration::from_secs(8);

struct Socket {
    tcp: TcpStream,
    deadline: Instant,
}
impl Socket {
    fn new(tcp: TcpStream, deadline: Instant) -> Result<Self> {
        tcp.set_nodelay(true)?;
        Ok(Self { tcp, deadline })
    }
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(io::ErrorKind::TimedOut.into())
    }
}
impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(self.remaining()?))?;
        self.tcp.read(buf)
    }
}
impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tcp.set_write_timeout(Some(self.remaining()?))?;
        self.tcp.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

impl Peer {
    fn connect(
        &self,
        id: Hash,
        addr: Option<SocketAddr>,
    ) -> Result<StreamOwned<ClientConnection, Socket>> {
        self.network.check_identity(id)?;
        let deadline = Instant::now() + DEADLINE;
        let mut tried = Vec::new();
        let mut refreshed = false;
        let lan_until = Instant::now() + Duration::from_millis(500);
        loop {
            let routes = self
                .network
                .routes(id, true)
                .into_iter()
                .chain(addr.map(Route::Direct))
                .chain(self.network.routes(id, false));
            for route in routes {
                if tried.contains(&route) {
                    continue;
                }
                tried.push(route);
                let attempt = deadline.min(Instant::now() + Duration::from_millis(750));
                let handshake = || -> Result<_> {
                    let tcp = match route {
                        Route::Direct(address) => TcpStream::connect_timeout(
                            &address,
                            attempt.saturating_duration_since(Instant::now()),
                        )?,
                        Route::Relay(address) => discovery::connect_relay(address, id, attempt)?,
                    };
                    let mut sock = Socket::new(tcp, attempt)?;
                    let mut conn = ClientConnection::new(
                        self.network.tls(),
                        ServerName::try_from("pp2.invalid").unwrap(),
                    )?;
                    conn.complete_io(&mut sock)?;
                    if conn.alpn_protocol() != Some(discovery::IDENTITY_ALPN) {
                        return Err(PeerError::Denied);
                    }
                    let server = conn.export_keying_material([0; 32], SERVER_EXPORTER, None)?;
                    let client = conn.export_keying_material([0; 32], CLIENT_EXPORTER, None)?;
                    let mut stream = StreamOwned::new(conn, sock);
                    if discovery::verify_transport(&mut stream, &server)? != id {
                        return Err(PeerError::Denied);
                    }
                    discovery::prove_transport(self.network.identity(), &mut stream, &client)?;
                    let mut status = [0];
                    stream.read_exact(&mut status)?;
                    if status != [1] {
                        return Err(PeerError::Denied);
                    }
                    stream.sock.deadline = deadline;
                    Ok(stream)
                };
                match handshake() {
                    Ok(s) => return Ok(s),
                    Err(PeerError::Denied) => return Err(PeerError::Denied),
                    Err(_) => {}
                }
            }
            if !refreshed {
                self.network.refresh_rendezvous(Some(id), deadline);
                refreshed = true;
            } else if Instant::now() < lan_until && self.network.can_wait_for_lan() {
                thread::sleep(Duration::from_millis(20));
            } else {
                return Err(PeerError::PeerUnavailable(id));
            }
        }
    }
    pub(super) fn remote(
        &self,
        id: Hash,
        address: Option<SocketAddr>,
        call: &Invocation,
    ) -> Result<String> {
        let mut stream = self.connect(id, address)?;
        protocol::send(&mut stream, call)?;
        let reply = protocol::receive::<std::result::Result<String, String>>(&mut stream)?;
        reply.map_err(PeerError::Value)
    }
    fn handle(&self, tcp: TcpStream, config: Arc<ServerConfig>) -> Result<()> {
        let mut socket = Socket::new(tcp, Instant::now() + DEADLINE)?;
        let mut conn = ServerConnection::new(config)?;
        conn.complete_io(&mut socket)?;
        if conn.alpn_protocol() != Some(discovery::IDENTITY_ALPN) {
            return Err(PeerError::Denied);
        }
        let server = conn.export_keying_material([0; 32], SERVER_EXPORTER, None)?;
        let client = conn.export_keying_material([0; 32], CLIENT_EXPORTER, None)?;
        let mut stream = StreamOwned::new(conn, socket);
        discovery::prove_transport(self.network.identity(), &mut stream, &server)?;
        let holder = discovery::verify_transport(&mut stream, &client)?;
        let allowed = self.network.check_identity(holder);
        stream.write_all(&[u8::from(allowed.is_ok())])?;
        stream.flush()?;
        allowed?;
        let call = protocol::receive(&mut stream)?;
        let reply = self
            .execute(holder, call, None)
            .map_err(|err| err.to_string());
        protocol::send(&mut stream, &reply)?;
        Ok(())
    }
    pub fn serve(self, listener: TcpListener) -> Result<()> {
        let certs =
            rustls_pemfile::certs(&mut BufReader::new(File::open(self.home.join("tls.pem"))?))
                .collect::<io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(
            self.home.join("tls.key"),
        )?))?
        .ok_or(PeerError::Invalid("missing TLS key"))?;
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        config.alpn_protocols = vec![discovery::IDENTITY_ALPN.to_vec()];
        config.send_tls13_tickets = 0;
        let config = Arc::new(config);
        let peer = Arc::new(self);
        let active = Arc::new(AtomicUsize::new(0));
        let accept = |tcp| {
            if active
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    (n < 16).then_some(n + 1)
                })
                .is_err()
            {
                return;
            }
            let count = active.clone();
            let config = config.clone();
            let peer = peer.clone();
            if thread::Builder::new()
                .spawn(move || {
                    let _ = peer.handle(tcp, config);
                    count.fetch_sub(1, Ordering::Relaxed);
                })
                .is_err()
            {
                active.fetch_sub(1, Ordering::Relaxed);
            }
        };
        let stop = AtomicBool::new(false);
        let bound = listener.local_addr()?;
        thread::scope(|scope| {
            scope.spawn(|| peer.network.maintain(bound, &stop));
            peer.network.spawn_relays(scope, &stop, &accept);
            let result = listener.incoming().try_for_each(|tcp| {
                accept(tcp?);
                Ok(())
            });
            stop.store(true, Ordering::Relaxed);
            result
        })
    }
}
