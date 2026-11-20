use std::{net::SocketAddr, path::Path};

use pp2::{
    Hash,
    peer::{Binding, Client, PeerIdentity, PeerStore, ReplicaAccess, ResourceMode},
};
use serde_json::json;

use crate::{app_cli::network, peer_cli::access};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "Usage: pp2 peer replica <command>
  share HOME REFERENCE immutable|single-writer|multi-writer
  approve HOME RESOURCE PEER_ID store|read|write [PROGRAM]
  revoke HOME RESOURCE PEER_ID
  follow HOME RESOURCE OWNER_ID[@ADDRESS] LOCAL_REFERENCE
  route HOME RESOURCE PEER_ID ADDRESS
  sync HOME RESOURCE PEER_ID[@ADDRESS] [--once]
  status HOME RESOURCE
  history HOME RESOURCE [AFTER_REVISION_ID]
  retain HOME RESOURCE SNAPSHOTS
  grant HOME LOCAL_REFERENCE reader|writer PROGRAM";

pub(crate) fn run(args: &[&str]) -> Result<()> {
    match args {
        [] | ["-h" | "--help"] => println!("{USAGE}"),
        ["share", home, reference, mode] => {
            let mode = match *mode {
                "immutable" => ResourceMode::Immutable,
                "single-writer" => ResourceMode::SingleWriter,
                "multi-writer" => ResourceMode::MultiWriter,
                _ => return Err(USAGE.into()),
            };
            println!(
                "{}",
                store(home)?.share_replica(&identity(home)?, reference, mode)?
            );
        }
        ["approve", home, resource, peer, level, pin @ ..] if pin.len() <= 1 => {
            let level = match *level {
                "store" => ReplicaAccess::Store,
                "read" => ReplicaAccess::Read,
                "write" => ReplicaAccess::Write,
                _ => return Err(USAGE.into()),
            };
            let program = pin.first().map(|value| value.parse()).transpose()?;
            println!(
                "{}",
                store(home)?.approve_replica(
                    &identity(home)?,
                    resource.parse()?,
                    peer.parse()?,
                    level,
                    program,
                )?
            );
        }
        ["revoke", home, resource, peer] => {
            store(home)?.revoke_replica(&identity(home)?, resource.parse()?, peer.parse()?)?;
        }
        ["follow", home, resource, owner, reference] => {
            let (owner, endpoint) = target(owner)?;
            let resource = resource.parse()?;
            let mut store = store(home)?;
            store.follow_replica(identity(home)?.id(), owner, resource, reference)?;
            if let Some(endpoint) = endpoint {
                store.route_replica(resource, owner, endpoint)?;
            }
        }
        ["route", home, resource, peer, address] => {
            store(home)?.route_replica(resource.parse()?, peer.parse()?, address.parse()?)?;
        }
        ["sync", home, resource, peer] | ["sync", home, resource, peer, "--once"] => {
            let once = args.last() == Some(&"--once");
            let resource = resource.parse()?;
            let (id, address) = target(peer)?;
            let client = Client::for_peer(&network(Path::new(home))?, id, address);
            let mut store = store(home)?;
            let (mut blocks, mut revisions, mut bytes) = (0, 0, 0);
            let pending = loop {
                let pass = client.sync_replica(&mut store, resource)?;
                blocks += pass.blocks;
                revisions += pass.revisions;
                bytes += pass.bytes;
                if once || !pass.pending || pass.blocks == 0 {
                    break pass.pending;
                }
            };
            println!(
                "{}",
                json!({"blocks": blocks, "revisions": revisions, "bytes": bytes, "pending": pending})
            );
        }
        ["status", home, resource] => {
            let status = store(home)?.replica_status(resource.parse()?)?;
            println!(
                "{}",
                json!({
                    "resource": status.resource.to_string(), "owner": status.owner.to_string(),
                    "mode": status.mode, "revision": status.revision,
                    "heads": status.heads.into_iter().map(|id| id.to_string()).collect::<Vec<_>>(),
                    "lease_expires_at_ms": status.lease_expires_at_ms, "revoked": status.revoked,
                })
            );
        }
        ["history", home, resource, after @ ..] if after.len() <= 1 => {
            let after = after.first().map(|value| value.parse()).transpose()?;
            for version in store(home)?.replica_history(resource.parse()?, after, 128)? {
                println!(
                    "{}",
                    json!({
                        "id": version.id.to_string(), "root": version.root.to_string(),
                        "parents": version.parents.into_iter().map(|id| id.to_string()).collect::<Vec<_>>(),
                        "author": version.author.to_string(), "authored_at_ms": version.authored_at_ms,
                        "valid": version.valid,
                        "retained": version.retained,
                    })
                );
            }
        }
        ["retain", home, resource, keep] => {
            let pruned = store(home)?.retain_replica_snapshots(resource.parse()?, keep.parse()?)?;
            println!("{}", json!({ "pruned_snapshots": pruned }));
        }
        ["grant", home, reference, level, program] => {
            let peer = identity(home)?.id();
            let access = access(level)?;
            let program = program.parse()?;
            let grant = store(home)?.issue(reference, peer, access, Some(program))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&Binding {
                    peer,
                    grant,
                    program,
                    access
                })?
            );
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn identity(home: &str) -> Result<PeerIdentity> {
    Ok(PeerIdentity::load(Path::new(home).join("identity.key"))?)
}

fn store(home: &str) -> Result<PeerStore> {
    Ok(PeerStore::open(Path::new(home).join("peer.db"))?)
}

fn target(input: &str) -> Result<(Hash, Option<SocketAddr>)> {
    Ok(match input.split_once('@') {
        Some((peer, address)) => (peer.parse()?, Some(address.parse()?)),
        None => (input.parse()?, None),
    })
}
