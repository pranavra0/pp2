# Operating a peer

## Platform and workspace

The peer and worker require Linux 5.9 or later with seccomp and close_range. Directory grants also require openat2 and a filesystem that reports creation timestamps. The tested build target is x86-64 Linux. Building from source needs Rust/Cargo 1.94.1 and a C build toolchain. Stable-identity workspace initialization invokes the OpenSSL executable. Node.js 24, npm and the locked TypeScript compiler are author tools. SQLite and QuickJS build from the Cargo dependencies.

The ordinary CLI creates a private workspace at `~/.pp2` on first use. Set `PP2_HOME` separately for each test identity. Keep the parent directory accessible only to trusted users. The workspace stores its identity, transport credentials, collections, grants and installations. Stop processes using the workspace before taking a file-level backup of the entire directory. Protect that backup like the identity key. Never run two advertisers with copies of the same identity.

Use `pp2 list` to see installation IDs. With exactly one installation, app commands select it automatically. Otherwise set `PP2_APP` to the desired ID. Installation always creates new private state. Update an existing installation to preserve its state. The administrative lifecycle commands are listed in `pp2 app native --help`. `pp2 app --help` covers fixed graph deployments and subscriptions. `pp2 peer --help` covers inspection of blocks, resources, grants, durable jobs, replication and network services.

## Networking

Start the generic host on a reachable TCP port and leave it running while serving resources. On the same IPv4 LAN, discovery uses multicast group 239.255.73.42 on UDP port 47342. Check the listener, multicast interface, firewall and clocks when a request reports peer-unavailable. On multihomed systems select the local IPv4 address with `lan_interface` in the workspace's `discovery.json`.

Across networks, operators can run a reachable rendezvous service:

```sh
pp2 peer rendezvous 0.0.0.0:7341 --relay
```

Set `discovery.json` on both sides, substituting the reachable service address. Restart the peer after changes.

```json
{"rendezvous":"192.0.2.10:7341","relay":true}
```

Hosts can advertise reachable TCP endpoints with `advertise`. Direct sessions and relayed sessions authenticate the destination identity. A relay can observe metadata and disrupt delivery. Check [discovery limits and identity rotation](architecture.md#peer-identity-and-discovery) when operating outside a LAN.

## Authority and recovery

Keep a record of each grant ID and recipient. On the issuing machine withdraw access with the ID printed by the grant command:

```sh
pp2 revoke "$GRANT_ID"
```

Revocation applies to future authorized operations. Files, paths or cached results already disclosed to the caller cannot be recalled. Connecting a different grant affects the selected installation's binding. Grants previously issued to other holders remain live until revoked. A package update changes what the local installation can invoke. The resource owner manages the lifetime of issued grants separately.

If status reports **awaiting grant**, check that the resource name, program and access in the owner's installation match the client's request. For offline document search, only completed queries are cached. Timeout and unavailable are distinct from permission denial. Ambiguous updates require the same operation ID and expected revision to safely retry. See [commit and retry behavior](architecture.md#evaluation-and-authority).

The process sandbox, bounded execution and identity checks are described in the [architecture reference](architecture.md#isolation-and-limits). There is no published security audit or critical-workload qualification. The documented measurements use controlled workloads. The document workflow has been exercised with two private workspaces on separate Linux network stacks connected by virtual Ethernet. A trial on independently administered physical machines is still pending.
