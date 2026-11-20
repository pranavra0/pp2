use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Hash;

use super::{
    super::{PeerError, Result, protocol, unix_ms},
    directory::{Directory, MAX_PEERS, Record},
    identity::{PeerIdentity, Proof, RELAY},
};

const MAX_MESSAGE: usize = 40 * 1024;
const REQUEST_TIME: Duration = Duration::from_millis(750);
const IDLE_TIME: Duration = Duration::from_secs(6);
const TUNNEL_TIME: Duration = Duration::from_secs(12);
const MAX_REQUESTS: usize = 32;
const MAX_TUNNELS: usize = 32;
const MAX_IDLE_PER_PEER: usize = 2;
const MAX_TUNNEL_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
enum Request {
    Publish(Record),
    Lookup(Option<Hash>),
    Offer,
    Connect(Hash),
}

#[derive(Serialize, Deserialize)]
enum Reply {
    Records(Vec<Record>),
    Challenge([u8; 32]),
    Ready,
    Accepted,
    Unavailable,
}

struct Wire {
    tcp: TcpStream,
    deadline: Instant,
}

impl Wire {
    fn open(address: SocketAddr, deadline: Instant) -> Result<Self> {
        let deadline = deadline.min(Instant::now() + REQUEST_TIME);
        let tcp = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
        tcp.set_nodelay(true)?;
        Ok(Self { tcp, deadline })
    }

    fn send(&mut self, value: &impl Serialize) -> Result<()> {
        let bytes = protocol::encode(value)?;
        if bytes.len() > MAX_MESSAGE {
            return Err(PeerError::Limit("rendezvous message bytes"));
        }
        self.write_all(b"PPR1")?;
        self.write_all(&(bytes.len() as u16).to_be_bytes())?;
        self.write_all(&bytes)?;
        Ok(())
    }

    fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut header = [0; 6];
        self.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[4], header[5]]) as usize;
        if &header[..4] != b"PPR1" || len > MAX_MESSAGE {
            return Err(PeerError::Protocol("invalid rendezvous frame".into()));
        }
        let mut bytes = vec![0; len];
        self.read_exact(&mut bytes)?;
        protocol::decode(&bytes)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

impl Read for Wire {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tcp.set_read_timeout(Some(remaining(self.deadline)?))?;
        self.tcp.read(bytes)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tcp
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.tcp.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tcp.flush()
    }
}

pub(super) fn publish(address: SocketAddr, record: Record) -> Result<()> {
    let mut wire = Wire::open(address, Instant::now() + REQUEST_TIME)?;
    wire.send(&Request::Publish(record))?;
    match wire.receive::<Reply>()? {
        Reply::Accepted => Ok(()),
        _ => Err(PeerError::Protocol(
            "rendezvous rejected publication".into(),
        )),
    }
}

pub(super) fn lookup(
    address: SocketAddr,
    id: Option<Hash>,
    deadline: Instant,
) -> Result<Vec<Record>> {
    let mut wire = Wire::open(address, deadline)?;
    wire.send(&Request::Lookup(id))?;
    match wire.receive::<Reply>()? {
        Reply::Records(records) if records.len() <= MAX_PEERS * 2 => Ok(records),
        _ => Err(PeerError::Protocol("invalid rendezvous reply".into())),
    }
}

pub(super) fn connect(address: SocketAddr, id: Hash, deadline: Instant) -> Result<TcpStream> {
    let mut wire = Wire::open(address, deadline)?;
    wire.send(&Request::Connect(id))?;
    match wire.receive::<Reply>()? {
        Reply::Ready => Ok(wire.tcp),
        _ => Err(PeerError::PeerUnavailable(id)),
    }
}

pub(super) fn offer(address: SocketAddr, identity: &PeerIdentity) -> Result<TcpStream> {
    let mut wire = Wire::open(address, Instant::now() + REQUEST_TIME)?;
    wire.send(&Request::Offer)?;
    let Reply::Challenge(challenge) = wire.receive::<Reply>()? else {
        return Err(PeerError::Protocol("relay rejected offer".into()));
    };
    wire.send(&identity.sign(RELAY, &challenge))?;
    match wire.receive::<Reply>()? {
        Reply::Accepted => {}
        _ => return Err(PeerError::PeerUnavailable(identity.id())),
    }
    wire.deadline = Instant::now() + IDLE_TIME;
    match wire.receive::<Reply>()? {
        Reply::Ready => Ok(wire.tcp),
        _ => Err(PeerError::PeerUnavailable(identity.id())),
    }
}

struct RelayOffer {
    socket: Wire,
    expires: Instant,
}

#[derive(Default)]
struct State {
    directory: Directory,
    offers: BTreeMap<Hash, Vec<RelayOffer>>,
}

impl State {
    fn prune(&mut self) {
        self.directory.prune(unix_ms());
        let now = Instant::now();
        self.offers.retain(|id, offers| {
            if !self
                .directory
                .get(*id)
                .is_some_and(|(record, _)| record.location.relay)
            {
                return false;
            }
            offers.retain(|offer| offer.expires > now);
            !offers.is_empty()
        });
    }
}

struct Slot(Arc<AtomicUsize>);
impl Slot {
    fn acquire(count: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(count.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Serves one bounded discovery directory and, optionally, opaque TCP tunnels.
pub fn serve_rendezvous(listener: TcpListener, relay: bool) -> Result<()> {
    listener.set_nonblocking(true)?;
    let state = Arc::new(Mutex::new(State::default()));
    let requests = Arc::new(AtomicUsize::new(0));
    let tunnels = Arc::new(AtomicUsize::new(0));
    let mut next_prune = Instant::now();
    loop {
        if Instant::now() >= next_prune {
            state.lock().expect("rendezvous state").prune();
            next_prune = Instant::now() + Duration::from_millis(250);
        }
        match listener.accept() {
            Ok((tcp, _)) => {
                if let Some(slot) = Slot::acquire(&requests, MAX_REQUESTS) {
                    let state = state.clone();
                    let tunnels = tunnels.clone();
                    thread::Builder::new()
                        .name("pp2-rendezvous".into())
                        .spawn(move || {
                            let _ = serve_request(tcp, &state, relay, &tunnels, slot);
                        })?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn serve_request(
    tcp: TcpStream,
    state: &Mutex<State>,
    relay: bool,
    tunnels: &Arc<AtomicUsize>,
    slot: Slot,
) -> Result<()> {
    tcp.set_nodelay(true)?;
    let mut wire = Wire {
        tcp,
        deadline: Instant::now() + REQUEST_TIME,
    };
    match wire.receive::<Request>()? {
        Request::Publish(record) => {
            let result =
                state
                    .lock()
                    .expect("rendezvous state")
                    .directory
                    .add(record, None, unix_ms());
            match result {
                Ok(()) => wire.send(&Reply::Accepted),
                Err(PeerError::Limit(_)) => wire.send(&Reply::Unavailable),
                Err(error) => Err(error),
            }
        }
        Request::Lookup(id) => {
            let mut state = state.lock().expect("rendezvous state");
            state.directory.prune(unix_ms());
            let records = state
                .directory
                .raw_entries()
                .filter(|(key, _)| id.is_none_or(|id| id == *key))
                .map(|(_, record)| record.clone())
                .collect();
            drop(state);
            wire.send(&Reply::Records(records))
        }
        Request::Offer if relay => {
            let mut challenge = [0; 32];
            getrandom::fill(&mut challenge).map_err(io::Error::other)?;
            wire.send(&Reply::Challenge(challenge))?;
            let id = wire.receive::<Proof>()?.verify(RELAY, &challenge)?;
            wire.send(&Reply::Accepted)?;
            let mut state = state.lock().expect("rendezvous state");
            state.prune();
            if !state
                .directory
                .get(id)
                .is_some_and(|(record, _)| record.location.relay)
            {
                drop(state);
                return wire.send(&Reply::Unavailable);
            }
            let offers = state.offers.entry(id).or_default();
            if offers.len() >= MAX_IDLE_PER_PEER {
                drop(state);
                return wire.send(&Reply::Unavailable);
            }
            offers.push(RelayOffer {
                socket: wire,
                expires: Instant::now() + IDLE_TIME,
            });
            Ok(())
        }
        Request::Connect(id) if relay => {
            let Some(_tunnel) = Slot::acquire(tunnels, MAX_TUNNELS) else {
                return wire.send(&Reply::Unavailable);
            };
            let offer = {
                let mut state = state.lock().expect("rendezvous state");
                state.prune();
                state.offers.get_mut(&id).and_then(Vec::pop)
            };
            let Some(mut offer) = offer else {
                return wire.send(&Reply::Unavailable);
            };
            offer.socket.deadline = wire.deadline;
            offer.socket.send(&Reply::Ready)?;
            wire.send(&Reply::Ready)?;
            drop(slot);
            tunnel(wire.tcp, offer.socket.tcp)
        }
        Request::Offer | Request::Connect(_) => wire.send(&Reply::Unavailable),
    }
}

fn tunnel(left: TcpStream, right: TcpStream) -> Result<()> {
    let deadline = Instant::now() + TUNNEL_TIME;
    let left_read = left.try_clone()?;
    let right_read = right.try_clone()?;
    thread::scope(|scope| {
        let reverse = scope.spawn(move || pump(right_read, left, deadline));
        let forward = pump(left_read, right, deadline);
        let reverse = reverse.join().expect("relay data pump");
        forward.and(reverse)
    })
}

fn pump(input: TcpStream, output: TcpStream, deadline: Instant) -> Result<()> {
    let mut input = Wire {
        tcp: input,
        deadline,
    }
    .take(MAX_TUNNEL_BYTES);
    let mut output = Wire {
        tcp: output,
        deadline,
    };
    let result = io::copy(&mut input, &mut output);
    let _ = output.tcp.shutdown(Shutdown::Write);
    result?;
    Ok(())
}
