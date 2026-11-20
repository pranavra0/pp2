use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::Hash;

use super::{
    super::{PeerError, Result, protocol},
    identity::{ADVERTISEMENT, PeerIdentity, Proof},
};

pub(super) const MAX_PEERS: usize = 64;
pub(super) const MAX_ENDPOINTS: usize = 4;
pub(super) const LEASE_MS: u64 = 8_000;
const CLOCK_SKEW_MS: u64 = 2_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Location {
    pub issued: u64,
    pub lan: Option<SocketAddr>,
    pub direct: Vec<SocketAddr>,
    pub relay: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Record {
    pub location: Location,
    proof: Proof,
}

impl Record {
    pub(super) fn sign(identity: &PeerIdentity, location: Location) -> Result<Self> {
        let proof = identity.sign(ADVERTISEMENT, &protocol::encode(&location)?);
        Ok(Self { location, proof })
    }

    pub(super) fn verify(&self, now: u64) -> Result<Hash> {
        let location = &self.location;
        if location.issued > now.saturating_add(CLOCK_SKEW_MS)
            || location.issued.saturating_add(LEASE_MS) <= now
            || location.direct.len() > MAX_ENDPOINTS
            || !location
                .direct
                .iter()
                .chain(&location.lan)
                .all(valid_endpoint)
        {
            return Err(PeerError::Protocol(
                "invalid or expired discovery lease".into(),
            ));
        }
        self.proof
            .verify(ADVERTISEMENT, &protocol::encode(location)?)
    }
}

pub(super) fn valid_endpoint(address: &SocketAddr) -> bool {
    let ip = address.ip();
    address.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
        && !matches!(address, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0 || address.ip().is_unicast_link_local())
}

struct Entry {
    record: Record,
    local: bool,
    conflict: Option<Record>,
}

#[derive(Default)]
pub(super) struct Directory(BTreeMap<Hash, Entry>);

impl Directory {
    pub(super) fn add(&mut self, record: Record, source: Option<IpAddr>, now: u64) -> Result<()> {
        let id = record.verify(now)?;
        let local =
            source.is_some_and(|ip| record.location.lan.is_some_and(|addr| addr.ip() == ip));
        self.prune(now);
        if let Some(entry) = self.0.get_mut(&id) {
            match record.location.issued.cmp(&entry.record.location.issued) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    if record.location != entry.record.location {
                        entry.conflict = Some(record);
                    }
                    entry.local |= local;
                }
                std::cmp::Ordering::Greater => {
                    *entry = Entry {
                        record,
                        local,
                        conflict: None,
                    };
                }
            }
        } else if self.0.len() < MAX_PEERS {
            self.0.insert(
                id,
                Entry {
                    record,
                    local,
                    conflict: None,
                },
            );
        } else {
            return Err(PeerError::Limit("discovery identities"));
        }
        Ok(())
    }

    pub(super) fn prune(&mut self, now: u64) {
        self.0
            .retain(|_, entry| entry.record.location.issued.saturating_add(LEASE_MS) > now);
    }

    pub(super) fn get(&self, id: Hash) -> Option<(&Record, bool)> {
        let entry = self.0.get(&id)?;
        entry
            .conflict
            .is_none()
            .then_some((&entry.record, entry.local))
    }

    pub(super) fn raw_entries(&self) -> impl Iterator<Item = (Hash, &Record)> {
        self.0.iter().flat_map(|(id, entry)| {
            std::iter::once((*id, &entry.record))
                .chain(entry.conflict.as_ref().map(|record| (*id, record)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_leases_reject_forgery_and_expiry_and_quarantine_conflicts() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("identity.key");
        let id = PeerIdentity::generate(&key).unwrap();
        let identity = PeerIdentity::load(key).unwrap();
        let now = 100_000;
        let original = Location {
            issued: now,
            lan: Some("192.0.2.1:1000".parse().unwrap()),
            direct: vec!["192.0.2.2:1000".parse().unwrap()],
            relay: false,
        };
        let first = Record::sign(&identity, original.clone()).unwrap();
        let mut directory = Directory::default();
        directory.add(first.clone(), None, now).unwrap();
        assert!(!directory.get(id).unwrap().1);
        directory
            .add(first.clone(), Some("192.0.2.1".parse().unwrap()), now)
            .unwrap();
        assert!(directory.get(id).unwrap().1);

        let mut forged = first.clone();
        forged.location.direct[0].set_port(2000);
        assert!(directory.add(forged.clone(), None, now).is_err());
        assert_eq!(directory.get(id).unwrap().0.location, original);
        assert!(directory.add(first.clone(), None, now + LEASE_MS).is_err());

        let conflict = Record::sign(&identity, forged.location.clone()).unwrap();
        directory.add(conflict, None, now).unwrap();
        directory.add(first.clone(), None, now).unwrap();
        assert!(directory.get(id).is_none());
        assert_eq!(directory.raw_entries().count(), 2);
        forged.location.issued += 1;
        let updated = Record::sign(&identity, forged.location.clone()).unwrap();
        directory.add(updated, None, now + 1).unwrap();
        directory.add(first, None, now + 1).unwrap();
        assert_eq!(directory.get(id).unwrap().0.location, forged.location);
        directory.prune(now + 1 + LEASE_MS);
        assert!(directory.get(id).is_none());
    }
}
