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

## Write a guest with effects

The default export of a collection program receives `(pp2, input)`.

- `pp2.storage.get(key)` resolves to `{found: false}` or `{found: true, value}`. Values may be null.
- `pp2.storage.scan({prefix, after, limit})` resolves to `{entries, next}`. Each entry is a key-value pair. Pass `next` as the exclusive `after` cursor for the next page, until it is null. The host orders keys by their UTF-8 bytes and caps each page by rows and encoded size.
- `pp2.evaluate(capability, input, {calls, delegate, timeoutMs, update})` resolves to `{revision, value}`. Pass a capability from `pp2.capabilities`. Its grant determines which collection and program the target peer authorizes. Set `calls: 0` for a leaf. An optional `delegate` array supplies the only capabilities available to the child. An optional `timeoutMs` shortens that branch's inherited deadline.
- On a write invocation, `pp2.storage.put(key, value)` and `pp2.storage.delete(key)` change the local collection. The program returns its ordinary result. The peer commits the changes, revision, and retry receipt together. A remote update requires a writable capability and explicit `update: {revision, operation}`, where `operation` is a 64-character hexadecimal operation ID. Updates are leaves.

Capabilities can be passed to functions, stored in objects, and passed to child invocations through `delegate`. The executing peer keeps the network settings and grant tokens outside the worker. It obtains recipient-bound grants for the requested subset and sends them to the child. Effect failures reject their promises. The API supports normal JavaScript control flow and promise composition. Each worker currently services its submitted effects in order.

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
scripts/validate-peers.py --isolated-networks
scripts/validate-peers.py --samples 40
scripts/benchmark-graph.py --isolated-networks --samples 40
~~~

The validation script uses Python 3.9 or later, OpenSSL, and the TypeScript toolchain from `npm ci`. The network namespace run also uses Linux user namespaces, `unshare`, `nsenter`, and `ip`. The snapshot comparison uses Python's SQLite build with FTS5. The graph comparison uses the same stock queries on three pp2 peers and a conventional mTLS service. [Runtime design and measurements](docs/architecture.md)

Use `pp2 eval` for local binary IR evaluation and `pp2 demo placement` for the simulated filter-and-fold workload. The other simulator scenarios are `sandbox`, `locality`, `gossip`, and `gc`.
