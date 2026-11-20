use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};

use crate::Hash;

use super::{PeerError, Result, protocol, unix_ms};

mod directory;
mod identity;
mod rendezvous;

use directory::{Directory, Location, MAX_ENDPOINTS, Record, valid_endpoint};
pub use identity::PeerIdentity;
pub(super) use identity::{IDENTITY_ALPN, prove_transport, verify_transport};
pub use rendezvous::serve_rendezvous;

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 73, 42);
const PORT: u16 = 47342;
const LAN_PACKET: usize = 512;
const BEACON_INTERVAL: Duration = Duration::from_millis(400);
const LAN_WAIT: Duration = Duration::from_millis(500);
const RECORD_LIMIT: usize = 32;
const RELAY_WORKERS: usize = 2;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    pub lan: bool,
    pub lan_interface: Option<Ipv4Addr>,
    pub rendezvous: Option<SocketAddr>,
    pub advertise: Vec<SocketAddr>,
    pub relay: bool,
    pub revoked: BTreeSet<Hash>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            lan: true,
            lan_interface: None,
            rendezvous: None,
            advertise: Vec::new(),
            relay: false,
            revoked: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Route {
    Direct(SocketAddr),
    Relay(SocketAddr),
}

struct Lan {
    socket: UdpSocket,
    interface: Ipv4Addr,
}

impl Lan {
    fn open(interface: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PORT)).into())?;
        socket.join_multicast_v4(&GROUP, &interface)?;
        socket.set_multicast_if_v4(&interface)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: socket.into(),
            interface,
        })
    }

    fn send(&self, record: &Record) -> Result<()> {
        let bytes = protocol::encode(record)?;
        self.socket.send_to(&bytes, (GROUP, PORT))?;
        Ok(())
    }

    fn drain(&self, directory: &mut Directory) {
        let mut bytes = [0; LAN_PACKET + 1];
        for _ in 0..RECORD_LIMIT {
            let Ok((len, address)) = self.socket.recv_from(&mut bytes) else {
                break;
            };
            if len <= LAN_PACKET
                && let Ok(record) = protocol::decode::<Record>(&bytes[..len])
                && record
                    .location
                    .lan
                    .is_some_and(|addr| addr.ip() == address.ip())
            {
                let _ = directory.add(record, Some(address.ip()), unix_ms());
            }
        }
    }
}

fn default_interface() -> Option<Ipv4Addr> {
    let probe = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect((GROUP, PORT)).ok()?;
    match probe.local_addr().ok()?.ip() {
        IpAddr::V4(address) if !address.is_unspecified() => Some(address),
        _ => None,
    }
}

struct State {
    identity: PeerIdentity,
    settings: DiscoveryConfig,
    directory: Mutex<Directory>,
    lan: Mutex<Option<Lan>>,
    tls: Arc<rustls::ClientConfig>,
}

/// Location hints and the local signing identity shared by a daemon and its clients.
#[derive(Clone)]
pub struct PeerNetwork(Arc<State>);

impl PeerNetwork {
    pub fn new(identity: PeerIdentity, settings: DiscoveryConfig) -> Result<Self> {
        if settings.advertise.len() > MAX_ENDPOINTS
            || !settings
                .advertise
                .iter()
                .chain(&settings.rendezvous)
                .all(valid_endpoint)
            || (settings.relay && settings.rendezvous.is_none())
        {
            return Err(PeerError::Value("invalid discovery configuration".into()));
        }
        let network = Self(Arc::new(State {
            identity,
            settings,
            directory: Mutex::new(Directory::default()),
            lan: Mutex::new(None),
            tls: Arc::new(identity::client_tls()),
        }));
        network.refresh_lan(None);
        network.check_identity(network.id())?;
        Ok(network)
    }

    pub fn id(&self) -> Hash {
        self.identity().id()
    }

    pub(super) fn tls(&self) -> Arc<rustls::ClientConfig> {
        self.0.tls.clone()
    }

    pub(super) fn identity(&self) -> &PeerIdentity {
        &self.0.identity
    }

    pub(super) fn check_identity(&self, id: Hash) -> Result<()> {
        if self.0.settings.revoked.contains(&id) {
            return Err(PeerError::Denied);
        }
        Ok(())
    }

    fn refresh_lan(&self, bound: Option<SocketAddr>) {
        if !self.0.settings.lan {
            return;
        }
        let interface = self.0.settings.lan_interface.or_else(|| match bound {
            Some(SocketAddr::V4(address)) if !address.ip().is_unspecified() => Some(*address.ip()),
            _ => default_interface(),
        });
        let mut lan = self.0.lan.lock().expect("LAN socket");
        if lan.as_ref().map(|lan| lan.interface) != interface {
            *lan = interface.and_then(|ip| Lan::open(ip).ok());
        }
    }

    fn drain_lan(&self) {
        if let Some(lan) = &*self.0.lan.lock().expect("LAN socket") {
            lan.drain(&mut self.0.directory.lock().expect("discovery directory"));
        }
    }

    pub(super) fn maintain(&self, bound: SocketAddr, stop: &AtomicBool) {
        let mut last_issued = 0;
        let mut next = Instant::now();
        let mut publish = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            if Instant::now() >= next {
                next = Instant::now() + BEACON_INTERVAL;
                self.refresh_lan(Some(bound));
                let issued = unix_ms().max(last_issued + 1);
                last_issued = issued;
                let lan = self.0.lan.lock().expect("LAN socket");
                let endpoint = lan.as_ref().and_then(|lan| match bound {
                    SocketAddr::V4(address)
                        if address.ip().is_unspecified() || *address.ip() == lan.interface =>
                    {
                        Some(SocketAddr::from((lan.interface, address.port())))
                    }
                    _ => None,
                });
                let record = Record::sign(
                    self.identity(),
                    Location {
                        issued,
                        lan: endpoint,
                        direct: self.0.settings.advertise.clone(),
                        relay: self.0.settings.relay,
                    },
                );
                if let Ok(record) = record {
                    if endpoint.is_some()
                        && let Some(lan) = &*lan
                    {
                        let _ = lan.send(&record);
                    }
                    drop(lan);
                    if Instant::now() >= publish
                        && let Some(address) = self.0.settings.rendezvous
                    {
                        publish = Instant::now() + Duration::from_secs(1);
                        let _ = rendezvous::publish(address, record);
                    }
                }
            }
            self.drain_lan();
            thread::sleep(Duration::from_millis(30));
        }
    }

    pub(super) fn spawn_relays<'scope>(
        &'scope self,
        scope: &'scope thread::Scope<'scope, '_>,
        stop: &'scope AtomicBool,
        accept: &'scope (impl Fn(std::net::TcpStream) -> Result<()> + Sync),
    ) {
        if self.0.settings.relay
            && let Some(address) = self.0.settings.rendezvous
        {
            for _ in 0..RELAY_WORKERS {
                scope.spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        match rendezvous::offer(address, self.identity()) {
                            Ok(tcp) => {
                                let _ = accept(tcp);
                            }
                            Err(_) => thread::sleep(Duration::from_millis(200)),
                        }
                    }
                });
            }
        }
    }

    pub(super) fn refresh_rendezvous(&self, id: Option<Hash>, deadline: Instant) {
        if let Some(address) = self.0.settings.rendezvous
            && let Ok(records) = rendezvous::lookup(address, id, deadline)
        {
            let mut directory = self.0.directory.lock().expect("discovery directory");
            let now = unix_ms();
            for record in records {
                let _ = directory.add(record, None, now);
            }
        }
    }

    pub(super) fn routes(&self, id: Hash, lan: bool) -> Vec<Route> {
        self.drain_lan();
        let mut directory = self.0.directory.lock().expect("discovery directory");
        directory.prune(unix_ms());
        let Some((record, local)) = directory.get(id) else {
            return Vec::new();
        };
        if lan {
            return record
                .location
                .lan
                .iter()
                .filter(|_| local)
                .map(|addr| Route::Direct(*addr))
                .collect();
        }
        let mut routes = record
            .location
            .direct
            .iter()
            .copied()
            .map(Route::Direct)
            .collect::<Vec<_>>();
        if record.location.relay
            && let Some(address) = self.0.settings.rendezvous
        {
            routes.push(Route::Relay(address));
        }
        routes
    }

    pub(super) fn can_wait_for_lan(&self) -> bool {
        self.0.lan.lock().expect("LAN socket").is_some()
    }

    pub(super) fn candidates(&self, deadline: Instant, local_only: bool) -> Vec<Hash> {
        if !local_only {
            self.refresh_rendezvous(None, deadline);
        }
        let lan_until = deadline.min(Instant::now() + LAN_WAIT);
        let own = self.id();
        loop {
            self.drain_lan();
            let peers = {
                let mut directory = self.0.directory.lock().expect("discovery directory");
                directory.prune(unix_ms());
                directory
                    .entries()
                    .filter(|(id, _, local)| {
                        *id != own && (!local_only || *local) && self.check_identity(*id).is_ok()
                    })
                    .map(|(id, _, _)| id)
                    .collect::<Vec<_>>()
            };
            if !local_only || Instant::now() >= lan_until || !self.can_wait_for_lan() {
                return peers;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub(super) fn relay(
        &self,
        address: SocketAddr,
        id: Hash,
        deadline: Instant,
    ) -> Result<std::net::TcpStream> {
        rendezvous::connect(address, id, deadline)
    }
}
