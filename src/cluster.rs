use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use crate::{
    Block, BlockKind, Data, Error, Grant, Hash, Limits, NodeId, Result, Route, StoreAccess,
    capability::{Authority, compile_routes},
    store::{Entry, Store},
    vm::Vm,
};

const TRACE_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Link {
    /// One-way propagation latency.
    pub latency_ms: u64,
    pub bytes_per_ms: u64,
    pub lan: bool,
}

impl Link {
    pub(crate) fn transfer_ms(self, bytes: usize) -> u64 {
        self.latency_ms
            .saturating_add((bytes as u64).div_ceil(self.bytes_per_ms))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LocalityPolicy {
    pub max_hops: u16,
    pub max_chain_rtt_ms: u64,
}

impl Default for LocalityPolicy {
    fn default() -> Self {
        Self {
            max_hops: 4,
            max_chain_rtt_ms: 50,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    BlockTransfer {
        from: NodeId,
        to: NodeId,
        hash: Hash,
        kind: BlockKind,
        bytes: usize,
        elapsed_ms: u64,
    },
    EvalRequest {
        from: NodeId,
        to: NodeId,
        data: Hash,
        program: Hash,
        bytes: usize,
    },
    EvalReply {
        from: NodeId,
        to: NodeId,
        bytes: usize,
    },
    Log {
        node: NodeId,
        stream: Arc<str>,
        message: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub struct RunReport {
    pub value: Data,
    pub fuel_used: u64,
    pub allocated_bytes: usize,
    /// Simulated transport time. The host deadline is tracked separately.
    pub elapsed_ms: u64,
}

#[derive(Clone)]
struct Inventory {
    revision: u64,
    blocks: Arc<BTreeMap<Hash, usize>>,
}

#[derive(Default)]
struct Node {
    store: Store,
    inventory: BTreeMap<NodeId, Inventory>,
    neighbors: BTreeMap<NodeId, Link>,
}

pub(crate) struct Transfer {
    from: NodeId,
    to: NodeId,
    hash: Hash,
    entry: Entry,
    pub(crate) elapsed_ms: u64,
}

impl Transfer {
    pub(crate) fn kind(&self) -> BlockKind {
        self.entry.kind
    }

    pub(crate) fn len(&self) -> usize {
        self.entry.bytes.len()
    }
}

/// Multiple isolated stores connected by simulated, symmetric links.
#[derive(Default)]
pub struct Cluster {
    pub(crate) issuer: Arc<()>,
    nodes: Vec<Node>,
    events: VecDeque<Event>,
}

impl Cluster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self) -> Result<NodeId> {
        let id =
            u16::try_from(self.nodes.len()).map_err(|_| Error::Denied("node limit reached"))?;
        self.nodes.push(Node::default());
        Ok(NodeId(id))
    }

    pub fn connect(&mut self, a: NodeId, b: NodeId, link: Link) -> Result<()> {
        if a == b || link.bytes_per_ms == 0 {
            return Err(Error::InvalidLink);
        }
        self.node(a)?;
        self.node(b)?;
        self.nodes[usize::from(a.0)].neighbors.insert(b, link);
        self.nodes[usize::from(b.0)].neighbors.insert(a, link);
        Ok(())
    }

    fn node(&self, id: NodeId) -> Result<&Node> {
        self.nodes
            .get(usize::from(id.0))
            .ok_or(Error::UnknownNode(id))
    }

    pub(crate) fn store_mut(&mut self, id: NodeId) -> Result<&mut Store> {
        self.nodes
            .get_mut(usize::from(id.0))
            .map(|node| &mut node.store)
            .ok_or(Error::UnknownNode(id))
    }

    pub(crate) fn link(&self, from: NodeId, to: NodeId) -> Result<Link> {
        self.node(to)?;
        self.node(from)?
            .neighbors
            .get(&to)
            .copied()
            .ok_or(Error::MissingLink { from, to })
    }

    pub(crate) fn entry(&self, node: NodeId, hash: Hash) -> Result<&Entry> {
        self.node(node)?
            .store
            .get(hash)
            .ok_or(Error::MissingBlock { node, hash })
    }

    pub fn has(&self, node: NodeId, hash: Hash) -> Result<bool> {
        Ok(self.node(node)?.store.get(hash).is_some())
    }

    pub fn put(&mut self, node: NodeId, block: &Block) -> Result<Hash> {
        let bytes: Arc<[u8]> = block.to_bytes()?.into();
        let hash = Hash::digest(&bytes);
        self.store_mut(node)?.insert(hash, bytes)?;
        Ok(hash)
    }

    pub fn import(&mut self, node: NodeId, hash: Hash, bytes: Vec<u8>) -> Result<()> {
        self.store_mut(node)?.insert(hash, bytes.into())
    }

    pub fn pin(&mut self, node: NodeId, hash: Hash) -> Result<()> {
        self.store_mut(node)?.pin(node, hash)
    }

    pub fn unpin(&mut self, node: NodeId, hash: Hash) -> Result<bool> {
        Ok(self.store_mut(node)?.unpin(hash))
    }

    pub fn collect(&mut self, node: NodeId) -> Result<Vec<Hash>> {
        self.store_mut(node)?.collect(node)
    }

    pub fn grant_store(
        &mut self,
        node: NodeId,
        roots: impl IntoIterator<Item = Hash>,
        access: StoreAccess,
    ) -> Result<Grant> {
        let grant = Grant::new(
            &self.issuer,
            node,
            Authority::Store {
                roots: roots.into_iter().collect(),
                access,
            },
        );
        let Authority::Store { roots, .. } = &grant.0.authority else {
            unreachable!("constructed a store grant");
        };
        self.store_mut(node)?.lease(node, roots, &grant)?;
        Ok(grant)
    }

    pub fn attenuate_store(
        &mut self,
        node: NodeId,
        parent: &Grant,
        roots: impl IntoIterator<Item = Hash>,
        access: StoreAccess,
    ) -> Result<Grant> {
        self.node(node)?;
        parent.check(&self.issuer, node)?;
        let Authority::Store {
            roots: allowed,
            access: ceiling,
        } = &parent.0.authority
        else {
            return Err(Error::Denied("expected a store grant"));
        };
        let roots: BTreeSet<_> = roots.into_iter().collect();
        if access > *ceiling || !roots.is_subset(allowed) {
            return Err(Error::Denied(
                "attenuation cannot expand permissions or scope",
            ));
        }
        self.grant_store(node, roots, access)
    }

    pub fn grant_net(&self, node: NodeId, routes: &[Route]) -> Result<Grant> {
        self.node(node)?;
        Ok(Grant::new(
            &self.issuer,
            node,
            Authority::Net(compile_routes(routes, 0)?),
        ))
    }

    pub fn grant_clock(&self, node: NodeId) -> Result<Grant> {
        self.node(node)?;
        Ok(Grant::new(&self.issuer, node, Authority::Clock))
    }

    pub fn grant_log(&self, node: NodeId, stream: &str) -> Result<Grant> {
        self.node(node)?;
        if stream.len() > 256 {
            return Err(Error::Denied("log stream name exceeds size limit"));
        }
        Ok(Grant::new(
            &self.issuer,
            node,
            Authority::Log(Arc::from(stream)),
        ))
    }

    /// One synchronous exchange of current inventories with each direct neighbor.
    pub fn gossip_round(&mut self) {
        for (id, node) in (0_u16..=u16::MAX).zip(&mut self.nodes) {
            let own_id = NodeId(id);
            let blocks: BTreeMap<_, _> = node
                .store
                .hashes()
                .map(|hash| {
                    (
                        hash,
                        node.store
                            .get(hash)
                            .expect("inventory hash exists")
                            .bytes
                            .len(),
                    )
                })
                .collect();
            let revision = match node.inventory.get(&own_id) {
                Some(previous) if *previous.blocks == blocks => continue,
                Some(previous) => previous.revision.saturating_add(1),
                None => 0,
            };
            node.inventory.insert(
                own_id,
                Inventory {
                    revision,
                    blocks: Arc::new(blocks),
                },
            );
        }
        let views: Vec<_> = self
            .nodes
            .iter()
            .map(|node| node.inventory.clone())
            .collect();
        for node in &mut self.nodes {
            for peer in node.neighbors.keys() {
                for (&owner, announced) in &views[usize::from(peer.0)] {
                    if node
                        .inventory
                        .get(&owner)
                        .is_none_or(|known| known.revision < announced.revision)
                    {
                        node.inventory.insert(owner, announced.clone());
                    }
                }
            }
        }
    }

    pub fn advertised_peers(&self, node: NodeId, hash: Hash) -> Result<Vec<NodeId>> {
        Ok(self
            .node(node)?
            .inventory
            .iter()
            .filter(|(peer, view)| **peer != node && view.blocks.contains_key(&hash))
            .map(|(&peer, _)| peer)
            .collect())
    }

    pub(crate) fn neighbor_count(&self, node: NodeId) -> Result<usize> {
        Ok(self.node(node)?.neighbors.len())
    }

    pub(crate) fn offer(&self, to: NodeId, hash: Hash) -> Result<Transfer> {
        let node = self.node(to)?;
        let mut best = None;
        for (&peer, link) in &node.neighbors {
            let announced = node
                .inventory
                .get(&peer)
                .and_then(|view| view.blocks.get(&hash));
            if let Some(&size) = announced {
                // A holder may have collected the block while its advertisement was in flight.
                if let Some(entry) = self.node(peer)?.store.get(hash) {
                    let score = (link.transfer_ms(size), !link.lan, peer);
                    if best.as_ref().is_none_or(|(current, _)| score < *current) {
                        best = Some((score, entry));
                    }
                }
            }
        }
        let ((elapsed_ms, _, from), entry) =
            best.ok_or(Error::UnavailableBlock { node: to, hash })?;
        Ok(Transfer {
            from,
            to,
            hash,
            entry: entry.clone(),
            elapsed_ms,
        })
    }

    pub(crate) fn receive(&mut self, transfer: Transfer) -> Result<()> {
        let Transfer {
            from,
            to,
            hash,
            entry,
            elapsed_ms,
        } = transfer;
        self.store_mut(to)?
            .insert(hash, Arc::from(entry.bytes.as_ref()))?;
        self.record(Event::BlockTransfer {
            from,
            to,
            hash,
            kind: entry.kind,
            bytes: entry.bytes.len(),
            elapsed_ms,
        });
        Ok(())
    }

    /// Fetches one immutable block. Returns the selected source, if a transfer was needed.
    pub fn fetch(&mut self, node: NodeId, hash: Hash) -> Result<Option<NodeId>> {
        if self.has(node, hash)? {
            return Ok(None);
        }
        let transfer = self.offer(node, hash)?;
        let from = transfer.from;
        self.receive(transfer)?;
        Ok(Some(from))
    }

    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.events.iter()
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    pub(crate) fn record(&mut self, event: Event) {
        if self.events.len() == TRACE_LIMIT {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    pub fn run(
        &mut self,
        node: NodeId,
        program: Hash,
        grants: &[Grant],
        limits: Limits,
        locality: LocalityPolicy,
    ) -> Result<RunReport> {
        self.node(node)?;
        for grant in grants {
            grant.check(&self.issuer, node)?;
        }
        Vm::new(self, limits, locality).run(node, program, grants)
    }
}
