use std::collections::BTreeSet;

use super::*;

impl Client {
    /// Fetches one published block and verifies its content address and format.
    pub fn fetch(&self, hash: Hash) -> Result<Vec<u8>> {
        self.fetch_active(hash, Activity::new(Instant::now() + DEADLINE))
    }

    fn fetch_active(&self, hash: Hash, active: Activity) -> Result<Vec<u8>> {
        match self.request(Request::Fetch(hash), active)? {
            Reply::Block(bytes) => {
                content::inspect(hash, &bytes)?;
                Ok(bytes)
            }
            _ => Err(unexpected_reply()),
        }
    }

    /// Checks the local cache, then tries sources in the caller's order of preference.
    pub fn fetch_into(cache: &mut PeerStore, sources: &[Self], hash: Hash) -> Result<Vec<u8>> {
        fetch_into(cache, hash, || {
            let mut failure = PeerError::Missing(hash);
            for source in sources {
                match source.fetch(hash) {
                    Ok(bytes) => return Ok(bytes),
                    Err(PeerError::Missing(_)) => {}
                    Err(error) => failure = error,
                }
            }
            Err(failure)
        })
    }

    /// Fetches a complete graph through explicitly configured, authenticated sources.
    pub fn fetch_graph(cache: &mut PeerStore, sources: &[Self], root: Hash) -> Result<Vec<Hash>> {
        let active = Activity::new(Instant::now() + DEADLINE);
        fetch_graph(cache, root, |hash| {
            let mut failure = PeerError::Missing(hash);
            for source in sources {
                active.check()?;
                match source.fetch_active(hash, active.clone()) {
                    Ok(bytes) => return Ok(bytes),
                    Err(PeerError::Missing(_)) => {}
                    Err(error) => failure = error,
                }
            }
            Err(failure)
        })
    }

    /// Resolves a program and its imports from a cache and ordered authenticated sources.
    /// Returns the verified addresses so callers can retain or republish the package.
    pub fn fetch_program(cache: &mut PeerStore, sources: &[Self], root: Hash) -> Result<Vec<Hash>> {
        let graph = load_code(root, false, |hash| {
            Self::fetch_into(cache, sources, hash).map(Some)
        })?;
        Ok(graph.into_iter().map(|(hash, _)| hash).collect())
    }

    /// Searches authenticated peers for an explicitly published block, with a local cache first.
    pub fn fetch_discovered(
        cache: &mut PeerStore,
        network: &PeerNetwork,
        hash: Hash,
    ) -> Result<Vec<u8>> {
        let mut sources = ContentSources::new(network, Activity::new(Instant::now() + DEADLINE));
        fetch_into(cache, hash, || sources.fetch(hash))
    }

    /// Fetches a complete published graph, consulting discovered peers on a cache miss.
    pub fn fetch_discovered_graph(
        cache: &mut PeerStore,
        network: &PeerNetwork,
        root: Hash,
    ) -> Result<Vec<Hash>> {
        let mut sources = ContentSources::new(network, Activity::new(Instant::now() + DEADLINE));
        fetch_graph(cache, root, |hash| sources.fetch(hash))
    }

    /// Resolves and verifies an immutable program and its declared imports by hash.
    pub fn fetch_discovered_program(
        cache: &mut PeerStore,
        network: &PeerNetwork,
        root: Hash,
    ) -> Result<Vec<Hash>> {
        let mut sources = ContentSources::new(network, Activity::new(Instant::now() + DEADLINE));
        let graph = load_code(root, false, |hash| {
            fetch_into(cache, hash, || sources.fetch(hash)).map(Some)
        })?;
        Ok(graph.into_iter().map(|(hash, _)| hash).collect())
    }
}

pub(super) struct ContentSources<'a> {
    network: &'a PeerNetwork,
    active: Activity,
    local: Option<Vec<Hash>>,
    remote: Option<Vec<Hash>>,
    attempts: usize,
}

impl<'a> ContentSources<'a> {
    pub(super) fn new(network: &'a PeerNetwork, active: Activity) -> Self {
        Self {
            network,
            active,
            local: None,
            remote: None,
            attempts: 0,
        }
    }

    pub(super) fn fetch(&mut self, hash: Hash) -> Result<Vec<u8>> {
        let mut failure = PeerError::Missing(hash);
        self.active.check()?;
        for local in [true, false] {
            let peers = if local {
                self.local
                    .get_or_insert_with(|| self.network.candidates(self.active.deadline, true))
            } else {
                self.remote.get_or_insert_with(|| {
                    let mut peers = self.network.candidates(self.active.deadline, false);
                    if let Some(local) = &self.local {
                        peers.retain(|id| !local.contains(id));
                    }
                    peers
                })
            };
            for &id in peers.iter() {
                self.active.check()?;
                self.attempts += 1;
                if self.attempts > 64 {
                    return Err(PeerError::Limit("content discovery attempts"));
                }
                let mut active = self.active.clone();
                active.deadline = active
                    .deadline
                    .min(Instant::now() + Duration::from_millis(950));
                match Client::for_peer(self.network, id, None).fetch_active(hash, active) {
                    Ok(bytes) => return Ok(bytes),
                    Err(PeerError::Missing(_)) => {}
                    Err(error) => failure = error,
                }
            }
        }
        self.active.check()?;
        Err(failure)
    }
}

fn fetch_into(
    cache: &mut PeerStore,
    hash: Hash,
    fetch: impl FnOnce() -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    if let Some(bytes) = cache.get(hash)? {
        return Ok(bytes);
    }
    let bytes = fetch()?;
    cache.import(hash, &bytes)?;
    Ok(bytes)
}

fn fetch_graph(
    cache: &mut PeerStore,
    root: Hash,
    mut fetch: impl FnMut(Hash) -> Result<Vec<u8>>,
) -> Result<Vec<Hash>> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![root];
    let mut graph = Vec::new();
    let mut remaining: usize = 16 * 1024 * 1024;
    while let Some(hash) = pending.pop() {
        if !seen.insert(hash) {
            continue;
        }
        if seen.len() > 256 {
            return Err(PeerError::Limit("content graph blocks"));
        }
        let bytes = match cache.get(hash)? {
            Some(bytes) => bytes,
            None => fetch(hash)?,
        };
        remaining = remaining
            .checked_sub(bytes.len())
            .ok_or(PeerError::Limit("content graph bytes"))?;
        let (_, links) = content::inspect(hash, &bytes)?;
        pending.extend(links);
        graph.push((hash, bytes));
    }
    cache.import_graph(&graph)?;
    Ok(graph.into_iter().map(|(hash, _)| hash).collect())
}
