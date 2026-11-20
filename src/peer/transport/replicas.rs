use super::*;
use crate::peer::{SyncReport, replication::SyncRequest};

const SYNC_PASS: Duration = Duration::from_secs(2);
const BLOCKS_PER_PASS: usize = 32;
const REQUESTS_PER_PASS: usize = BLOCKS_PER_PASS + 4;
const BYTES_PER_PASS: usize = 4 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(500);

impl Client {
    /// Reconciles one resource with this authenticated placement in bounded, durable passes.
    pub fn sync_replica(&self, store: &mut PeerStore, resource: Hash) -> Result<SyncReport> {
        self.sync_pass(store, resource, DEADLINE)
    }

    fn sync_pass(
        &self,
        store: &mut PeerStore,
        resource: Hash,
        time: Duration,
    ) -> Result<SyncReport> {
        let (local, peer) = self.replica_identities()?;
        let active = Activity::new(Instant::now() + time);
        let request = store.replica_request(resource, local, peer, None)?;
        let (mut connection, _, _) = self.connect_active(active.clone(), None)?;
        protocol::send(&mut connection, &Request::SyncReplica(request))?;
        let (mut stream, reply) = match receive_reply(&mut connection) {
            Ok(reply) => (Some(connection), reply),
            // Older peers close the connection on an unrecognized initial request.
            Err(PeerError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                let request = store.replica_request(resource, local, peer, None)?;
                (
                    None,
                    self.request(Request::Replica(request), active.clone())?,
                )
            }
            Err(error) => return Err(error),
        };
        let Reply::Replica(offer) = reply else {
            return Err(unexpected_reply());
        };
        let tips = store.accept_replica_offer(local, peer, resource, *offer)?;
        let mut report = SyncReport::default();
        let mut requests = 0;
        for tip in tips {
            loop {
                let Some(hash) = store.missing_replica_block(resource, peer, tip)? else {
                    report.revisions += store.finish_replica_tip(resource, peer, tip)?;
                    break;
                };
                if requests == REQUESTS_PER_PASS
                    || report.blocks == BLOCKS_PER_PASS
                    || report.bytes >= BYTES_PER_PASS
                    || active.remaining().is_err()
                {
                    report.pending = true;
                    break;
                }
                requests += 1;
                let reply = if let Some(stream) = &mut stream {
                    protocol::send(stream, &Some(hash)).and_then(|_| receive_reply(stream))
                } else {
                    let request = store.replica_request(resource, local, peer, Some(hash))?;
                    self.request(Request::Replica(request), active.clone())
                };
                if matches!(reply, Err(PeerError::Timeout)) {
                    report.pending = true;
                    break;
                }
                if matches!(reply, Err(PeerError::Missing(missing)) if missing == hash)
                    && store.retry_replica_with_proofs(resource, peer, tip)?
                {
                    continue;
                }
                let Reply::Block(bytes) = reply? else {
                    return Err(unexpected_reply());
                };
                store.stage_replica_block(resource, peer, tip, hash, &bytes)?;
                report.blocks += 1;
                report.bytes += bytes.len();
            }
            if report.pending {
                break;
            }
        }
        if let Some(stream) = &mut stream {
            let _ = protocol::send(stream, &Option::<Hash>::None);
        }
        Ok(report)
    }

    fn replica_identities(&self) -> Result<(Hash, Hash)> {
        match &self.destination {
            Destination::Identity { network, id, .. } => Ok((network.id(), *id)),
            _ => Err(PeerError::Unsupported(
                "replication requires stable peer identities",
            )),
        }
    }
}

impl Server {
    pub(super) fn serve_replica_sync(
        &self,
        stream: &mut StreamOwned<ServerConnection, Socket>,
        holder: Hash,
        mut request: SyncRequest,
    ) -> Result<()> {
        let setup = (|| -> Result<_> {
            let network = self.network.as_ref().ok_or(PeerError::Denied)?;
            if request.block.is_some() {
                return Err(PeerError::Denied);
            }
            let store =
                PeerStore::open_with_timeout(&self.database, stream.sock.activity.storage_wait()?)?;
            let offer = store.offer_replica(network.identity(), holder, &request)?;
            Ok((store, offer))
        })();
        let (store, offer) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                protocol::send(stream, &Reply::Failed(error.into()))?;
                return Ok(());
            }
        };
        if let Some(lease) = &offer.lease {
            request.lease = Some(lease.clone());
        }
        protocol::send(stream, &Reply::Replica(Box::new(offer)))?;
        let mut blocks_sent = 0;
        let mut bytes_sent = 0;
        for _ in 0..REQUESTS_PER_PASS {
            let (hash, _) = protocol::receive::<Option<Hash>>(stream)?;
            let Some(hash) = hash else { break };
            stream.sock.check_active()?;
            let reply = match store.serve_replica_block(self.identity, holder, &request, hash) {
                Ok(bytes) => {
                    blocks_sent += 1;
                    bytes_sent += bytes.len();
                    Reply::Block(bytes)
                }
                Err(error) => Reply::Failed(error.into()),
            };
            protocol::send(stream, &reply)?;
            if blocks_sent == BLOCKS_PER_PASS || bytes_sent >= BYTES_PER_PASS {
                break;
            }
        }
        stream.conn.send_close_notify();
        let _ = stream.flush();
        Ok(())
    }

    pub(super) fn synchronize_replicas(&self, network: &PeerNetwork, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            if let Ok(mut store) = PeerStore::open_with_timeout(&self.database, POLL)
                && let Ok(targets) = store.replica_targets(network.id())
            {
                for (resource, peer, fallback) in targets {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let client = self
                        .graph
                        .peers
                        .get(&peer)
                        .filter(|_| fallback.is_none())
                        .cloned()
                        .unwrap_or_else(|| Client::for_peer(network, peer, fallback));
                    let _ = client.sync_pass(&mut store, resource, SYNC_PASS);
                }
            }
            thread::sleep(POLL);
        }
    }
}
