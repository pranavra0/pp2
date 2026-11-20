# pp2

pp2 runs content-addressed JavaScript on the peers that hold its data. A program can read a local collection, pass capabilities as guest values, and await computations at other peers. Each peer verifies the caller and program before executing code in an isolated process. Peers request verified modules on demand.

## Build and run

The peer daemon uses Linux with seccomp and the `close_range` system call (Linux 5.9 or later). The commands below use Rust 1.94, a C compiler for bundled SQLite and QuickJS, and OpenSSL for development certificates.

~~~sh
cargo build --release --locked --bins --examples
cargo test --locked --all-targets
target/release/pp2 peer --help
~~~

Install the peer CLI with `cargo install --locked --path .`. The application clients are the `document_library` and `inventory` example binaries under `target/release/examples` after building.

## Run a three-peer application

The stock example reads the reorder threshold at the office, evaluates a warehouse program at each location, and combines the totals. The manifest specifies each capability's peer, collection, program, and maximum access. Initialization provisions development credentials and grants. JavaScript packaging and execution use the installed `pp2` binary.

~~~sh
pp2 app init examples/federated-stock/app.json ./stock-deployment
pp2 app run ./stock-deployment '{"sku":"lamp"}'
pp2 app run ./stock-deployment '{"sku":"lamp","viaWest":true}'
~~~

Both invocations return 10 lamps, with 7 at the west warehouse and 3 at the east warehouse. The second invocation explicitly passes the east capability and one descendant call to the west computation. `app run` starts three independent peer processes with separate databases and authenticated loopback connections. The deployment directory persists across invocations.

## Deploy with network discovery

Generate identities and grants for the stock application, then copy each peer directory to its host. Keep each `identity.key` private to the operator of that peer. Copy the `client` directory to the machine invoking the application.

~~~sh
pp2 app init examples/federated-stock/app.json ./stock-deployment --discovery
pp2 app serve PEER_DIRECTORY 0.0.0.0:7340
pp2 app invoke CLIENT_DIRECTORY '{"sku":"lamp","viaWest":true}'
~~~

On a shared LAN, peers announce their current endpoint over IPv4 multicast on UDP port 47342. Open the selected TCP listener port for direct connections. The bind address is a daemon setting. The same deployment can run on one machine with `pp2 app run ./stock-deployment`.

Across networks, run `pp2 peer rendezvous 0.0.0.0:7341 --relay` on a reachable host. Put the service address in `discovery.json` in each peer and client directory. Set `relay` on listening peers to accept incoming connections through the service when a direct path is unavailable.

~~~json
{
  "rendezvous": "192.0.2.10:7341",
  "relay": true
}
~~~

A node can set `advertise` to a list of reachable TCP addresses for direct cross-network connections. The optional `lan_interface` selects a local IPv4 address, and `lan: false` disables multicast. Operators can supply pinned static addresses in a deployment manifest or in a `peer serve-network` graph configuration. A stable route in that configuration has an `id` and an `address`. IDs in JSON use arrays of 32 bytes.

Use `pp2 peer node-init NODE_DIRECTORY` to provision a standalone node, and `pp2 peer identity NODE_DIRECTORY/identity.key` to print its ID. Resource owners use `pp2 peer issue` and `pp2 peer issue-reaction-writer` with a recipient's stable ID. The same ID is accepted by `pp2 app install`, `peer delegate`, and `peer attenuate`. Run existing remote operations through `pp2 peer connect NODE_DIRECTORY PEER_ID OPERATION ...`, omitting their address and TLS credential arguments. Use `PEER_ID@ADDRESS` to also supply a pinned route.

Use `pp2 peer find NODE_DIRECTORY CACHE_DB HASH` to locate explicitly published immutable data or code. `find-program` verifies a program and its declared imports. Add `--publish` to make the verified copies available from the cache's own daemon.

~~~sh
cargo build --locked --bin pp2
python3 scripts/demo-network-discovery.py
~~~

The demo installs a persistent application and runs a delegated stock query across three isolated Linux networks. It moves a peer while a delivery is pending, checks recovery using the same program and grants, and retrieves code from a nearby cache after shutting down the publisher and rendezvous service. It also verifies that a forged lease, mismatched identity, stolen grant, and private-content fetch fail. [Demo script](scripts/demo-network-discovery.py), [identity lifecycle and discovery limits](docs/architecture.md#peer-identity-and-discovery)

For a certificate-pinned deployment, set the participating peers' reachable addresses in the manifest before running `app init` in its default mode. The `admin` directory contains the deployment CA signing key. [Application manifest](examples/federated-stock/app.json)

## Run a computation that survives disconnection

~~~sh
cargo build --release --locked --bin pp2
scripts/demo-autonomous.py
~~~

The demo starts three peer processes with their own certificates, databases, and grant policies. A obtains an attenuated grant from C for B, submits to B, and disconnects while C is offline. When C returns, B reads its local collection and calls C directly. B persists the sum of 13 before A reconnects to retrieve it. [Demo script](scripts/demo-autonomous.py), [guest programs](examples/autonomous)

Use `pp2 peer attenuate` to obtain a grant for a recipient peer. `pp2 peer job-submit` takes a client-generated 64-digit hexadecimal job ID, an absolute expiration in Unix milliseconds, a program hash, an input file, and a graph budget. Supply named bindings from B's local configuration or use `--delegated FILE` with grants addressed to B. The file is a JSON object keyed by guest capability name. Each entry contains `peer` (the issuer ID or certificate fingerprint), `grant`, `program`, and `access` (`Read` or `Write`). JSON fingerprints and hashes are arrays of 32 bytes. In certificate mode, B’s peer directory includes the presenter and each issuer.

Use `job-status` and `job-cancel` with the submitting identity. After an ambiguous submission reply, resubmit the same job ID and arguments. Jobs can live for up to five minutes. The peer keeps each terminal result in its database, and cancellation or expiration can leave any already accepted child work running within its own deadline. [Lifecycle and authority](docs/architecture.md#durable-computations)

For an existing stock deployment, keep the peer databases, certificates, and grants. Add a `directory` object to each peer's `profile.json`, keyed by peer name, with an `address` and SHA-256 certificate `fingerprint` for each participating peer. For `peer serve` configurations, use `peers` entries with `address`, TLS `name`, and `fingerprint`, and reference the fingerprint in each binding's `peer` field. Upgrade all peers that participate in a graph together.

## Run the persistent inventory application

~~~sh
cargo build --release --locked --bin pp2
python3 scripts/demo-persistent-inventory.py
~~~

The warehouse accepts a stock update while the office is offline. The demo kills and restarts the warehouse daemon, then starts the office. The warehouse's installed handler resumes automatically and updates the office's inventory projection. The office skips the projection write when delivering its own subscription. The demo also checks that the office can revoke the warehouse's write grant and that removing the warehouse installation stops local delivery. [Demo script](scripts/demo-persistent-inventory.py) and [guest programs](examples/persistent-inventory).

Package the handler and its imports into the serving peer's database. Use `pp2 peer issue DB REFERENCE HOLDER reader PROGRAM` to grant the handler a watch on one local reference. For an indexed collection, the same grant can also give the handler read access to its entries. For a snapshot reference, issue a separate read grant on an indexed collection for the handler's storage context.

Use `pp2 app install DB HOLDER SUBSCRIPTIONS_JSON` with a JSON object containing `name` and a `subscriptions` object keyed by subscription name. Each subscription specifies `program`, `watch_grant`, `budget`, and `expires_at_ms`. Optional `entry_grant` selects a separate collection and optional `capabilities` lists explicit bindings using the same shape as durable job bindings above. The serving daemon uses its own identity for the installation. Remote resource owners issue their own grants. Use `pp2 peer issue-reaction-writer DB COLLECTION EXECUTOR PROGRAM` at the destination to allow a handler's durable child to update that collection.

The handler receives `{id, reference, revision}`. The ID is a stable hex string and the revision is a decimal string. `pp2 app status DB APPLICATION` shows each cursor, pending revision, missed count, and most recent terminal outcome. Use `pp2 app unsubscribe DB APPLICATION SUBSCRIPTION` to revoke one subscription or `pp2 app remove DB APPLICATION` to stop the installation. Status reports `removing` while already dispatched children may still hold live deadlines. [Delivery and lifecycle semantics](docs/architecture.md#persistent-applications)

## Install and run a native application

`pp2 app native` installs immutable application packages by hash. A package lists its entry program, graph budget, and named capability requests. Installation displays those requests along with terminal access and private state. A request becomes usable after the user supplies an issuer's grant for that name and program. Use `pp2 app native update` to approve a new package while keeping the installation ID and state.

`pp2 app native run HOME APPLICATION` opens the terminal shell or reads commands from standard input. Each line becomes a bounded event in a local worker. The program can call its granted peers, and the shell renders its text result. The laptop runs the shell directly. Resource hosts run an ordinary pp2 peer.

The [native document example](examples/native-documents/README.md) builds an index on a separate machine, searches it interactively, and keeps previous results available while disconnected. It includes a two-machine walkthrough and a comparison with a conventional mTLS service.

## Run Personal Notes on three peers

~~~sh
cargo build --locked --bin pp2
python3 scripts/demo-replicated-notes.py
~~~

The demo installs the same native package in three independent workspaces. Two devices edit while all peer daemons are stopped. After reconnecting, they agree on the same two heads, keep both texts for the conflicted note, and retain the notes added on either branch. An explicit merge combines the branches and a later `resolve` chooses the note text. The third device catches up from another replica while the owner is offline. The demo also checks restart recovery, zero-block sync when current, private content protection, and revocation. [Demo script](scripts/demo-replicated-notes.py), [replication semantics and offline leases](docs/architecture.md#replicated-resources)

### Install across three machines

1. Run `pp2 app native identity ./notes-home` on each machine. Keep each workspace and identity key on its own machine. On the owner machine, package the app and create the resource. Record the package hash, store program hash, resource ID, and owner identity. Supply each other machine's identity to `approve`.

   ~~~sh
   read -r PACKAGE STORE_PROGRAM < <(examples/replicated-notes/package.sh pp2 ./notes-home)
   pp2 peer collection-init ./notes-home/peer.db notes
   RESOURCE=$(pp2 peer replica share ./notes-home notes multi-writer)
   pp2 peer replica approve ./notes-home "$RESOURCE" "$LAPTOP_ID" write "$STORE_PROGRAM"
   pp2 peer replica approve ./notes-home "$RESOURCE" "$THIRD_ID" write "$STORE_PROGRAM"
   pp2 app native host ./notes-home 0.0.0.0:7340
   ~~~

2. On each other machine, use those values and the owner's reachable address. The initial sync establishes the placement lease and creates the local reference.

   ~~~sh
   OWNER_TARGET="$OWNER_ID@$OWNER_ADDRESS"
   pp2 peer replica follow ./notes-home "$RESOURCE" "$OWNER_TARGET" notes
   pp2 peer replica sync ./notes-home "$RESOURCE" "$OWNER_TARGET"
   ~~~

   If a sync reports `"pending":true`, repeat it to finish the remaining blocks. Start `pp2 app native host ./notes-home 0.0.0.0:7340` on the other machines to exchange changes in the background. For route discovery on a LAN, allow discovery traffic and the TCP listener. For direct routes, run `pp2 peer replica route ./notes-home "$RESOURCE" "$PEER_ID" "$PEER_ADDRESS"` for each other peer on each machine, using addresses such as `192.0.2.10:7340`.

3. Install the package and attach the local writer grant on each machine. The owner can use its own reachable address for `OWNER_TARGET`.

   ~~~sh
   APP=$(pp2 app native install ./notes-home "$PACKAGE" "$OWNER_TARGET" --yes)
   pp2 peer replica grant ./notes-home notes writer "$STORE_PROGRAM" > notes-grant.json
   pp2 app native grant ./notes-home "$APP" notes notes-grant.json
   pp2 app native run ./notes-home "$APP" 'set welcome hello'
   pp2 app native run ./notes-home "$APP" 'show welcome'
   ~~~

4. Disconnect two machines and use `set TITLE TEXT` on each. Reconnect their hosts to exchange changes. Use `list` and `show TITLE` to inspect both branches, `merge` to combine them, and `resolve TITLE TEXT` to choose a text. Notes compares whole snapshots and preserves all distinct texts across the branches, including an older text that remains on another branch. Use `pp2 peer replica status ./notes-home "$RESOURCE"` to compare head IDs. After a placement lease expires, reconnect to the owner to renew and fetch any missing history.

Owners can also share resources in `immutable` and `single-writer` modes. Use `store` for a copy that can synchronize, `read` to allow local execution, and `write` to also allow local updates on multi-writer resources. Use `pp2 peer replica --help` for placement, status, history, and revocation commands.

For a single-writer resource, `pp2 peer replica retain HOME RESOURCE 32` keeps up to 32 recent snapshots in that workspace. `pp2 peer gc HOME/peer.db` collects unreferenced payload blocks. History still lists signed revisions and indicates which snapshots retain their payloads. A fresh or stale upgraded peer can synchronize from a compacted source. Use `sync --once` to run one bounded transfer pass. [Retention and compatibility](docs/architecture.md#snapshot-retention)

## Write a guest with effects

The default export of a collection program receives `(pp2, input)`.

- `pp2.storage.revision` is the revision of the invocation's collection snapshot.
- `pp2.call(pp2.resource, operation, input)` reads an explicitly scoped host resource. `pp2.resource` is null when the invocation has no host resource. For a directory, use `list`, `read`, or `readText`. [Host resource interface](docs/architecture.md#host-resources)
- `pp2.storage.get(key)` resolves to `{found: false}` or `{found: true, value}`. Values may be null.
- `pp2.storage.scan({prefix, after, limit})` resolves to `{entries, next}`. Each entry is a key-value pair. Pass `next` as the exclusive `after` cursor for the next page, until it is null. The host orders keys by their UTF-8 bytes and caps each page by rows and encoded size.
- `pp2.evaluate(capability, input, {calls, delegate, timeoutMs, update, consistency})` resolves to `{revision, value}` and includes `view` for replicated resources. Pass a capability from `pp2.capabilities`. Its grant determines which collection and program the target peer authorizes. Set `calls: 0` for a leaf. An optional `delegate` array supplies the only capabilities available to the child. An optional `timeoutMs` shortens that branch's inherited deadline.
- `pp2.evaluateAll([{capability, input, timeoutMs, consistency}])` returns one to four leaf read results in input order. Each leaf consumes one graph call. Synchronous read graphs can run the leaves concurrently. Durable jobs, native invocations, and update graphs run the batch in order.
- On a write invocation, `pp2.storage.put(key, value)` and `pp2.storage.delete(key)` change the local collection. The program returns its ordinary result. The peer commits the changes, revision, and retry receipt together. A remote update requires a writable capability and explicit `update: {revision, operation}`, where `operation` is a 64-character hexadecimal operation ID. Updates are leaves.

Capabilities can be passed to functions, stored in objects, and passed to child invocations through `delegate`. The executing peer keeps the network settings and grant tokens outside the worker. It obtains recipient-bound grants for the requested subset and sends them to the child. Effect failures reject their promises. Workers service effects in submission order.

Collection programs can inspect `pp2.storage.view`. The default `consistency: 'authoritative'` requires an authoritative state. Specify `'replica'` to allow the local view at the peer named in the capability, or pass an immutable revision ID for an exact read. Multi-writer commits use replica consistency. When a replica view reports multiple heads, read those revisions and submit an update with `merge: true` and the current numeric revision. The leaf program writes the merged state through the same collection effects.

Application manifests link TypeScript runtime imports by source specifier and module name in each module's `imports` map. They can seed a collection from newline-delimited JSON pairs like `["stock/lamp/a1",3]`, or use `null` for an empty collection. For existing peers, `pp2 peer collection-init`, `graph-read`, and `graph-update` provide the equivalent lower-level interface. Existing snapshot programs continue to take `(state, input)` and run through `peer read` or `peer update`. [Graph limits and transaction semantics](docs/architecture.md#guest-effects-and-placement)

## Write a program in TypeScript

Install the locked compiler with `npm ci` in the pp2 checkout. Node.js and TypeScript are build tools for the machine packaging the programs. The storage peer executes the emitted ES2022 module using QuickJS.

Save this as `counter.ts`.

~~~ts
type Counter = { total: number };

export default function read(state: Counter): number {
  return state.total;
}
~~~

~~~sh
pp2 peer pack counter.ts counter.ppj
pp2 peer put client.db counter.ppj
npm run typecheck
~~~

`pack` type-checks `.ts` and `.mts` files in strict mode and prints the content hash on success. `npm run typecheck` checks both example apps. For a runtime import such as `import { add } from './math.js'`, TypeScript checks against `math.ts` and pp2 links the import to the packaged dependency's hash.

~~~sh
math_hash=$(pp2 peer pack math.ts math.ppj)
pp2 peer pack counter.ts counter.ppj "./math.js=$math_hash"
~~~

Type-only imports need no runtime link. Publish or cache both blocks if the program uses a runtime dependency.

If rebuilding changes a module hash, update the application profile and issue a grant for the new hash if the current grant is pinned to a version.

## Document library across two machines

1. Create a development CA, storage identity, and client identity. Use the real DNS name in the storage certificate. The client connects to an explicit IP and port and checks that name during TLS.

   ~~~sh
   scripts/dev-certificates.sh certificates storage.example client
   ~~~

   Give each host its own certificate and private key and a copy of ca.pem. Keep the CA signing key and each peer's private key on their respective hosts.

2. On the interface machine, package the TypeScript modules from the checkout after running `npm ci`. Record the returned read and write hashes.

   ~~~sh
   document_library package client.db
   ~~~

3. On the storage machine, initialize the state, issue the two grants for client.pem, and start the peer. The certificate PEM file is public. Set READ_HASH and WRITE_HASH to the package hashes from step 2.

   ~~~sh
   document_library init storage.db documents
   pp2 peer issue storage.db documents client.pem reader "$READ_HASH"
   pp2 peer issue storage.db documents client.pem writer "$WRITE_HASH"
   pp2 peer serve storage.db 0.0.0.0:7340 ca.pem server.pem server.key
   ~~~

4. On the interface machine, save the address, credentials, hashes, and grants in library.json. Set the profile and its containing directory permissions for the local user.

   ~~~json
   {
     "address": "192.0.2.10:7340",
     "name": "storage.example",
     "ca": "ca.pem",
     "certificate": "client.pem",
     "key": "client.key",
     "cache": "client.db",
     "read": {"program": "READ_HASH", "grant": "READER_GRANT"},
     "write": {"program": "WRITE_HASH", "grant": "WRITER_GRANT"}
   }
   ~~~

5. Queue edits and synchronize them when connected. Searches intersect a persisted inverted index on the storage peer. Titles and matching document IDs come back to the interface. The `show` command retrieves one selected document. A previous query can be answered from the local cache during a disconnect and includes its cached revision.

   ~~~sh
   document_library add library.json notes "Meeting notes" notes.txt
   document_library sync library.json
   document_library search library.json "meeting budget"
   document_library show library.json notes
   document_library remove library.json notes
   document_library sync library.json
   ~~~

A host serving a package cache can publish each module using `pp2 peer publish`. Another client can use `pp2 peer fetch-program` to retrieve the verified dependency graph by its root hash. Passing `--publish` lets that cache serve the graph after the original publisher goes offline. An updated package has a new hash. A grant pinned to a version must be replaced or supplemented when the operator authorizes the update.

## Inventory

The inventory application uses the same profile fields and peer operations. Run `inventory package client.db` and `inventory init storage.db stock lamp 4`, then issue grants for the new hashes and reference. Read the current revision before making a reservation. Competing updates against the same revision return a conflict to the caller whose write loses. Repeating the identical command recovers a recent receipt after a lost reply.

~~~sh
inventory status inventory.json
inventory reserve inventory.json 0 order-42 lamp 2
inventory release inventory.json 1 order-42
~~~

## Verification

~~~sh
cargo test --locked --all-targets
cargo build --locked --release --bin pp2 --examples
scripts/validate-peers.py --isolated-networks
scripts/validate-peers.py --samples 40
scripts/benchmark-graph.py --isolated-networks --samples 40
python3 scripts/demo-replicated-notes.py --pp2 target/release/pp2 --isolated-networks \
  --fault-rounds 10 --operations-per-writer 25 --seed 761
~~~

The validation script uses Python 3.9 or later, OpenSSL, and the TypeScript toolchain from `npm ci`. The network namespace runs also use Linux user namespaces, `unshare`, `nsenter`, and `ip`. The snapshot comparison uses Python's SQLite build with FTS5. The graph comparison uses the same stock queries on three pp2 peers and a conventional mTLS service. Add `--trace-dir` with a directory path to collect per-peer timing traces, or repeat `--load-clients` with counts such as 4, 16, and 24 to measure pp2 under load. [Runtime design and measurements](docs/architecture.md#three-peer-graph-measurements)

Use `pp2 eval` for local binary IR evaluation and `pp2 demo placement` for the simulated filter-and-fold workload. The other simulator scenarios are `sandbox`, `locality`, `gossip`, and `gc`.
