use super::*;
use crate::peer::{SyncReport, replication::checked_block};

const SYNC_PASS: Duration = Duration::from_secs(2);
const BLOCKS_PER_PASS: usize = 32;
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
        let Reply::Replica(offer) = self.request(Request::Replica(request), active.clone())? else {
            return Err(unexpected_reply());
        };
        let tips = store.accept_replica_offer(local, peer, resource, *offer)?;
        let mut report = SyncReport::default();
        for tip in tips {
            loop {
                let Some(hash) = store.missing_replica_block(resource, peer, tip)? else {
                    report.revisions += store.finish_replica_tip(resource, peer, tip)?;
                    break;
                };
                if report.blocks == BLOCKS_PER_PASS || active.remaining().is_err() {
                    report.pending = true;
                    return Ok(report);
                }
                let request = store.replica_request(resource, local, peer, Some(hash))?;
                let reply = self.request(Request::Replica(request), active.clone());
                if matches!(reply, Err(PeerError::Timeout)) {
                    report.pending = true;
                    return Ok(report);
                }
                if matches!(reply, Err(PeerError::Missing(missing)) if missing == hash)
                    && store.retry_replica_with_proofs(resource, peer, tip)?
                {
                    continue;
                }
                let Reply::Block(bytes) = reply? else {
                    return Err(unexpected_reply());
                };
                checked_block(hash, &bytes)?;
                store.stage_replica_block(resource, peer, tip, hash, &bytes)?;
                report.blocks += 1;
                report.bytes += bytes.len();
            }
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
