use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

use crate::{
    BlockKind, Error, Hash, NodeId, Result,
    capability::{Authority, Grant, GrantInner},
    wire,
};

#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) bytes: Arc<[u8]>,
    pub(crate) kind: BlockKind,
    links: Arc<BTreeSet<Hash>>,
}

#[derive(Default)]
pub(crate) struct Store {
    blocks: BTreeMap<Hash, Entry>,
    pins: BTreeSet<Hash>,
    leases: Vec<Weak<GrantInner>>,
}

impl Store {
    pub(crate) fn get(&self, hash: Hash) -> Option<&Entry> {
        self.blocks.get(&hash)
    }

    pub(crate) fn hashes(&self) -> impl Iterator<Item = Hash> + '_ {
        self.blocks.keys().copied()
    }

    pub(crate) fn insert(&mut self, expected: Hash, bytes: Arc<[u8]>) -> Result<()> {
        if bytes.len() > wire::MAX_BYTES {
            return Err(Error::Wire("message exceeds byte limit"));
        }
        let actual = Hash::digest(&bytes);
        if actual != expected {
            return Err(Error::Integrity { expected, actual });
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = self.blocks.entry(expected) {
            let (kind, links) = wire::inspect_block(&bytes)?;
            slot.insert(Entry {
                bytes,
                kind,
                links: Arc::new(links),
            });
        }
        Ok(())
    }

    fn reachable(
        &self,
        node: NodeId,
        roots: impl IntoIterator<Item = Hash>,
    ) -> Result<BTreeSet<Hash>> {
        let mut marked = BTreeSet::new();
        let mut pending = Vec::new();
        for root in roots {
            if marked.insert(root) {
                pending.push(root);
            }
        }
        while let Some(hash) = pending.pop() {
            let entry = self.get(hash).ok_or(Error::IncompleteGraph {
                node,
                missing: hash,
            })?;
            for &child in entry.links.iter() {
                if marked.insert(child) {
                    pending.push(child);
                }
            }
        }
        Ok(marked)
    }

    pub(crate) fn pin(&mut self, node: NodeId, hash: Hash) -> Result<()> {
        self.reachable(node, [hash])?;
        self.pin_leased(hash);
        Ok(())
    }

    pub(crate) fn pin_leased(&mut self, hash: Hash) {
        self.pins.insert(hash);
    }

    pub(crate) fn unpin(&mut self, hash: Hash) -> bool {
        self.pins.remove(&hash)
    }

    pub(crate) fn lease(
        &mut self,
        node: NodeId,
        roots: &BTreeSet<Hash>,
        grant: &Grant,
    ) -> Result<()> {
        self.reachable(node, roots.iter().copied())?;
        self.leases.push(Arc::downgrade(&grant.0));
        Ok(())
    }

    pub(crate) fn collect(&mut self, node: NodeId) -> Result<Vec<Hash>> {
        let grants: Vec<_> = self.leases.iter().filter_map(Weak::upgrade).collect();
        self.leases.retain(|lease| lease.strong_count() > 0);
        let leased_roots = grants.iter().flat_map(|grant| match &grant.authority {
            Authority::Store { roots, .. } => roots,
            _ => unreachable!("only store grants are leased"),
        });
        let marked = self.reachable(node, self.pins.iter().chain(leased_roots).copied())?;
        let mut removed = Vec::new();
        self.blocks.retain(|hash, _| {
            let keep = marked.contains(hash);
            if !keep {
                removed.push(*hash);
            }
            keep
        });
        Ok(removed)
    }
}
