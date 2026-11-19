use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use crate::{Error, Hash, NodeId, Placement, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreAccess {
    Read,
    ReadAndPin,
}

/// A host-approved destination and the subset of routes to delegate there.
#[derive(Clone, Debug)]
pub struct Route {
    pub target: Placement,
    pub onward: Vec<Route>,
}

impl Route {
    pub fn new(target: Placement, onward: Vec<Route>) -> Self {
        Self { target, onward }
    }
}

pub(crate) type Routes = BTreeMap<Placement, Arc<RoutesInner>>;

pub(crate) struct RoutesInner(pub(crate) Routes);

pub(crate) fn compile_routes(routes: &[Route], depth: usize) -> Result<Arc<RoutesInner>> {
    if routes.len() > 256 || (!routes.is_empty() && depth >= 16) {
        return Err(Error::Denied("route grant exceeds scope limits"));
    }
    let mut result = BTreeMap::new();
    for route in routes {
        let onward = compile_routes(&route.onward, depth + 1)?;
        if result.insert(route.target, onward).is_some() {
            return Err(Error::Denied("duplicate placement in route grant"));
        }
    }
    Ok(Arc::new(RoutesInner(result)))
}

pub(crate) enum Authority {
    Store {
        roots: BTreeSet<Hash>,
        access: StoreAccess,
    },
    Net(Arc<RoutesInner>),
    Clock,
    Log(Arc<str>),
}

pub(crate) struct GrantInner {
    pub(crate) issuer: Arc<()>,
    pub(crate) node: NodeId,
    pub(crate) authority: Authority,
}

/// An opaque, node-bound handle provisioned by the embedding host.
#[derive(Clone)]
pub struct Grant(pub(crate) Arc<GrantInner>);

impl fmt::Debug for Grant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Grant").finish_non_exhaustive()
    }
}

impl Grant {
    pub(crate) fn new(issuer: &Arc<()>, node: NodeId, authority: Authority) -> Self {
        Self(Arc::new(GrantInner {
            issuer: Arc::clone(issuer),
            node,
            authority,
        }))
    }

    pub(crate) fn check(&self, issuer: &Arc<()>, node: NodeId) -> Result<()> {
        if self.0.node != node || !Arc::ptr_eq(&self.0.issuer, issuer) {
            return Err(Error::Denied("grant belongs to another node or runtime"));
        }
        Ok(())
    }

    pub(crate) fn store(&self, hash: Hash, permission: StoreAccess) -> Result<()> {
        match &self.0.authority {
            Authority::Store { roots, access }
                if *access >= permission && roots.contains(&hash) =>
            {
                Ok(())
            }
            _ => Err(Error::Denied("store operation exceeds the grant's scope")),
        }
    }

    pub(crate) fn route(&self, target: Placement) -> Result<Arc<RoutesInner>> {
        match &self.0.authority {
            Authority::Net(routes) => routes.0.get(&target).cloned(),
            _ => None,
        }
        .ok_or(Error::Denied("placement is outside the network grant"))
    }

    pub(crate) fn clock(&self) -> Result<()> {
        match &self.0.authority {
            Authority::Clock => Ok(()),
            _ => Err(Error::Denied("expected a clock grant")),
        }
    }

    pub(crate) fn log(&self) -> Result<Arc<str>> {
        match &self.0.authority {
            Authority::Log(stream) => Ok(Arc::clone(stream)),
            _ => Err(Error::Denied("expected a log grant")),
        }
    }
}
