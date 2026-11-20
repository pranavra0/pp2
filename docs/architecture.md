# Runtime design

## Evaluation and authority

Each mutually authenticated TLS 1.3 connection serves one evaluation, control request, or bounded replica transfer. A grant binds a holder and reference to read or write access and can pin one immutable program. Delegation can only narrow access, to depth eight. Revocation deletes descendant grants and their receipts in one transaction.

A graph invocation evaluates a content-addressed module and immutable input under one grant. The same graph engine runs local, authenticated remote, and durable invocations. A compute grant pins a program and carries no storage authority. A resource grant selects a snapshot root, indexed collection, or host resource. Each resource stage runs at its authorized peer and completes before its caller receives a result.

An immutable block read starts at the selected root. A successful read exposes its child addresses to that invocation. A write can add immutable blocks pointing to already visible blocks and select a replacement root. Indexed stages hold one SQLite snapshot and can change rows in an update. The owner rechecks read authority before release. The expected revision guards writes. The root or row changes, revision, event, and retry receipt commit together.

Retry an ambiguous update with the same grant, program, input, expected revision, and operation ID. A matching receipt returns the original result. Changed arguments under an existing ID fail. Receipts survive 1,024 revisions while the grant is live. Older outcomes require reconciliation through application state. The `peer delegate` command issues a new grant on each success. Graph attenuation replays the same live grant for identical requests.

Rust callers can close synchronous work with `Cancellation`. Closing a connection stops the worker and propagates through active child connections. Cancellation can race a commit.

## Peer identity and discovery

Stable IDs are domain-separated SHA-256 hashes of Ed25519 public keys. Peers sign role-specific TLS exporters. Clients verify the destination before revealing their proof or request. Stable mode supports independently issued transport certificates. Certificate mode uses CA validation, TLS names, and certificate fingerprints. [TLS exporters](https://www.rfc-editor.org/rfc/rfc8446#section-7.5)

Changing addresses or TLS certificates preserves the stable ID. For a compromised key, provision a new ID, reissue grants and bindings, and resubmit jobs or reinstall subscriptions. To deny the old ID locally, add it to `revoked` in discovery config and restart. Owners revoke affected grants at their respective peers.

Peers advertise signed leases on IPv4 multicast and optionally through rendezvous. Leases expire after eight seconds with up to two seconds of future clock skew. A LAN route requires a matching packet source. Newer leases supersede older ones. A conflict at the same issuance time suppresses discovered routes until expiry or a newer lease. Pinned routes can still authenticate.

Route order is live LAN, pinned addresses, signed direct addresses, then relay. Rendezvous pairs sockets after a signed challenge and carries end-to-end TLS. It can observe metadata and disrupt service. Ambiguous operations after transmission use receipt or job recovery. Locally available routes work during a rendezvous outage.

The directory holds 64 identities and a lease carries up to four direct addresses plus LAN. Rendezvous permits 32 control requests and 32 relayed sessions concurrently. Each tunnel has 12 seconds and 8 MiB per direction. `peer-unavailable` indicates unavailable authenticated routes. `timeout` indicates an exhausted deadline.

## Guest effects and placement

A compute stage can orchestrate named evaluations. Its entry grant selects the program. Bindings resolve against the caller, entry grant, and program. A resource stage cannot accept outbound bindings. It can return values for an orchestrator to supply as input to the next stage. The terminal stage receives a UI capability and invokes its private state using a separate local stage. Peers can also attach recipient-bound grants. The guest gets opaque invocation-local handles.

To pass a handle to a child via `pp2.evaluate`, the executor asks the issuer to narrow it to the child identity, program, access, budget, and expiry. The destination checks holder, presenter, lineage, and limits. Each call consumes one call plus its descendant allowance, even on failure. A branch can shorten its deadline. Synchronous leaf reads can run in parallel. A leaf at the current peer uses the local execution path. Durable batches journal their children in order.

Limits are 16 child calls, four child levels, 16 bindings, eight seconds per attempt, 128 effects, and four leaf reads per batch. Guest promises enqueue effects in order. Returning with unsettled effects fails. An update is a leaf and commits at the issuing peer. Later graph failures leave committed effects in place.

A workspace administrator can pair an owner binding with a separate, program-pinned local read grant for the same signed resource. Queries that accept a replica or request an exact revision prefer the local copy if its grant, lease, revision, and program are available. Otherwise the query goes to the owner with the resource ID pinned. Authoritative reads, writes, and forwarded grants route to their issuer. The local placement remains independently authorized until its grant is revoked, its lease expires, or the replica learns that its placement was revoked.

## Durable computations

A job is keyed by submitter identity and client-chosen ID at the destination. Acceptance stores the immutable program and input, capabilities, budget, and absolute expiry. An identical submission retrieves status. Changed arguments fail. There are four workers, 32 active jobs per submitter, 64 per peer, and five minutes per job. Restart requeues interrupted attempts.

Before dispatch, the parent records each evaluation effect, its chosen peer, and a stable child ID. A child at the current peer enters the same durable queue directly. Pending children and temporary failures yield the worker. On replay the parent reuses terminal outcomes, or queries the recorded child after a lost acknowledgment. Changing or skipping a recorded effect fails recovery. Reads of the entry's own resource can see newer snapshots on replay. A local write commits data, revision, receipt, and job completion together.

The submitter can query or cancel. A cancellation that commits first prevents local completion. Children can still finish within their deadlines. An expired job or revoked entry grant prevents further local work. Ordinary terminal results remain available to the submitter after grant revocation. Replicated results require current authority and include the resource view. Terminal records share the database quota.

## Persistent applications

The daemon installs subscriptions for its own identity. Each has program-pinned read-only watch and entry grants, named remote grants, a budget, expiry, and a delivery cursor. The entry defaults to the watch grant. A handler with outbound capabilities uses a separate compute entry grant. To read watched data, that handler invokes a resource stage with a pinned read grant. Installation pins the verified handler graph.

Reference creation and revision advances log an event in the same transaction. Receipt replay produces no new event. Events carry a stable ID, reference, and revision. A subscription starts at the current revision and reads the collection snapshot for each attempt. To recover values from a specific revision, store them under an immutable revision key during the original update.

Subscriptions deliver one event at a time in revision order as durable jobs. Temporary failures retry until expiry. A terminal outcome advances the cursor. Reactions require a pinned reaction-writer grant to write. Subscriptions skip reaction events, limiting delivery to one generation per ordinary transition.

Limits are 16 subscriptions per app and 128 active per peer. Deliveries share job capacity and expire after five minutes or at subscription expiry. The log retains up to 4,096 events and 24 hours. A lagging cursor reports gaps and resumes at the next retained event. Enqueued input survives pruning. Each subscription keeps its latest outcome. Remote reaction results survive five minutes past their deadline.

Revoking a watch or entry grant disables affected subscriptions and cancels local deliveries. Removal also cancels local jobs and reports `removing` until recorded child deadlines pass. Resume requires the original identity.

## Host resources

An indexed reference can carry a provider name and private config. Register it with `Server::with_host_provider` and create it through `PeerStore::create_host_resource` or `share_host_resource`. The latter also issues a pinned grant. Guests call read-only provider operations with `pp2.call(pp2.resource, operation, input)`. Reads can repeat on retry.

The clock provider returns epoch milliseconds through `call(resource, 'unixMillis')`. Create a clock reference with `pp2 peer clock-init` and issue a read grant pinned to its consumer.

Authority is rechecked before and after provider reads, at checkpoints, and before result release. Write transactions serialize with grant revocation. The Linux directory provider pins root device, inode, and creation time. Scoped `openat2` lookups stay beneath a verified descriptor without symlinks or mount crossings. File reads require a pinned regular file with one link. Successive calls can see different filesystem versions.

- `list({path, after, limit})` returns up to 64 sorted UTF-8 entries as name/type pairs and a cursor. It examines at most 4,096 entries. An empty path selects the root.
- `read({path, offset, limit})` returns up to 8 KiB as byte integers and a cursor. Null means EOF.
- `readText({path, limit})` returns a whole UTF-8 file up to 16 KiB or fails if it exceeds the limit.

## Native application lifecycle

A `PPA1` package names an entry point, graph budget, and requests. Its hash covers the manifest and its edges retain the referenced module graphs. Publishing makes the package and dependencies available together. Clients fetch by hash from their cache or selected authenticated peers.

Installation creates a stable ID, private collection, and local program-pinned read and write grants. Bindings connect explicit issuer grants to approved requests. An atomic update preserves state and keeps bindings for identical requests. Updates and binding changes renew local grants. Removal revokes local grants and deletes private state and bindings. Issuers control their own grants.

The terminal provides `{type: "line", id, text}` via its `event` operation, up to 4 KiB. The event ID can key an update. The app returns up to 64 lines and 16 KiB. The launcher escapes controls. The reserved `state` binding invokes the entry as a local storage leaf. It can return a value and revision for a subsequent update. A native leaf bound to the local peer also runs directly under its grant.

## Storage and distribution

SQLite uses WAL, synchronous FULL, and a 65,536-page main-file cap. Writers serialize across the database. Successful updates increment the numeric revision even when the hash repeats. Indexed entries support exact keys and ordered prefix scans with exclusive cursors. A replicated collection stores immutable manifests of entry hashes.

Blocks use SHA-256 addresses. References and publication require complete Merkle graphs. Garbage collection traces references, publications, active job inputs and programs, subscription programs, and verified or pending replica history. Unreachable blocks and cache entries are removed together.

Public fetch serves explicitly published hashes. `pp2 peer publish DB HASH --graph` checks every descendant before publishing the graph in one transaction. `peer fetch-graph` and `peer find-graph` verify and cache a complete graph of up to 256 blocks and 16 MiB. Discovery allows up to 64 fetch attempts per graph. A fetched graph is cache data until publication or a reference retains it. An authorized caller can supply code restricted to the declared import graph, and the peer caches it by holder. The receiver verifies hash and format. On a cache miss it can consult discovered sources, LAN first, with up to 64 attempts inside the deadline.

## Replicated resources

A shared reference has a stable resource ID and signed revisions containing state root, parents, and author. Each peer's numeric revision guards local writes and counts changes to its visible heads. Use signed IDs and head sets to compare peers.

| Mode | Reads | Writes |
| --- | --- | --- |
| Immutable | Authoritative, replica, exact revision | Fixed initial state |
| Single writer | Authoritative, replica, exact revision | Owner only |
| Multi-writer | Replica, exact revision | Owner and approved writers, including offline |

Replica reads select the lowest accepted head ID and report all heads. Exact reads select a retained accepted revision. With multiple heads, a writer must explicitly merge at the current local revision. Immutable-block merge stages can read every current head through `blocks.heads` and must call `blocks.setRoot` to select the result. The merge records every current head as a parent. Later arrivals can create new branches. Timestamps never select a winner. Resource views expose the mode, consistency, selected revision, and heads in guest and caller results.

The owner signs placement policies for stable identities. A placement permits storage and can also allow local reads or writes and pin a program. Execution also requires a local holder-bound grant. A store-only placement trusts the host operator with plaintext.

Peers pull private blocks over one authenticated connection per pass, with up to 32 blocks, 36 requests, and a 4 MiB payload threshold. Each request checks current policy, lease, and reachability. Peers verify hashes, signatures, ancestry, and author authority before admission. Pending transfers survive restart and retain their dependencies. Admission commits history, visible state, and a change event together. Imports can coalesce multiple authored changes into one local event. Private resource blocks stay scoped to replication unless independently published.

### Offline authority and revocation

Placement leases last up to 24 hours, start two minutes before issuance, and renew below 12 hours. Current leases let replicas serve and synchronize without the owner. Temporary expiry pauses subscription delivery within the event retention window.

A revision signature authenticates the writer's claimed timestamp. A writer holding the key and an expired lease can sign a record claiming a time within that lease, and an active policy can still admit it. The writer's daemon must enforce both the time and program pin. Trust the daemon, keys, and clocks accordingly.

On revocation the owner signs a policy cutoff. A retired writer's changes survive only if they are ancestors of the owner's accepted heads at that cutoff. Other changes and descendants become invalid but their verified records remain visible in history. An offline acknowledgment establishes local durability subject to that cutoff. A replica that sees its removal stops execution and serving and loses local grants and affected subscriptions. A disconnected replica can continue until it sees the policy or its lease expires. Previously disclosed data can persist.

Limits are 32 active placements, 128 retired placements, 128 heads, and 4,096 keys per replicated collection. Native state and host resources are local. Native apps can bind a separate shared collection.

### Snapshot retention

Use `pp2 peer replica retain HOME RESOURCE SNAPSHOTS` for single-writer history. Compaction drops unretained payloads while preserving ancestry proofs and ordinary receipts. Exact reads of pruned revisions report unavailable. Accidental multiple heads pause pruning.

When a full transfer encounters a pruned payload, a follower can fetch proofs and verify the entire head state before advancing. Progress is durable. A valid lease and authorized source are required. Upgrade followers before compacting upstream. Retention is opt-in after migration. Multi-writer history and signed ancestry continue to consume the workspace quota.

## TypeScript, JavaScript, and binary programs

A graph program exports `(pp2, input)`. The entry may return a promise. The value boundary accepts null, booleans, safe integers, text, lists, and records with bounded size and depth. The direct snapshot interface also supports `(state, input)` and updates returning `{next, value}`.

TypeScript compiles during packaging with strict ES2022. The source packager resolves relative imports and links the acyclic runtime graph by hash. Low-level `peer pack` also accepts already addressed imports. A `PPJ1` module records source and sorted import hashes. Guests get fresh QuickJS contexts without `Date`, `Math.random`, or shared memory. Runtime errors identify emitted module locations by hash.

Binary `AEB1` programs use the Rust interpreter, with a read-only snapshot grant in slot zero. Both runtimes share the transport, process boundary, and snapshot commit path.

## Isolation and limits

The daemon holds credentials, storage, sockets, and grant policy. Workers receive verified code and bounded inputs over pipes. They start with a cleared environment, closed inherited descriptors, seccomp, CPU and address-space limits, and a parent watchdog. QuickJS allows 32 MiB of heap and two seconds of execution outside effect waits. The graph deadline includes waits. Binary programs have fuel and allocation limits.

The peer and worker frame format is `PPN1`, a 32-bit big-endian length, and Postcard. Immutable blocks and portable values have their own formats. Blocks and values are capped at 256 KiB. Code graphs allow 32 modules and 512 KiB. Remote code cache is limited to 16 MiB per holder. A daemon accepts up to 16 inbound connections. Schema migrations are transactional.

## Snapshot application measurements

The 40-query loopback run searched 64 documents (121,648 body bytes). Both implementations returned identical results. Timings include fresh TLS and exclude client startup. Bytes cover application frames.

| Implementation | Median | Request | Response |
| --- | --- | --- | --- |
| pp2 warm | 11.00 ms | 129 B | 393 B |
| HTTPS with SQLite FTS5 | 6.34 ms | 57 B | 441 B |
| pp2 cold, one call | 32 ms | 1,916 B | 108 B |

[Validation script](../scripts/validate-peers.py)

## Three-peer graph measurements

Each warehouse held 20,032 rows and returned a total over 32 matches. Both implementations returned identical results in 40 samples across Linux network namespaces. Bytes cover application frames including the entry call.

| Implementation | Serial median | Parallel median | Parallel bytes |
| --- | --- | --- | --- |
| pp2 | 34.26 ms | 21.77 ms | 565 B |
| Conventional mTLS | 15.36 ms | 11.44 ms | 222 B |

Use `--isolated-networks` to reproduce the topology. Set `PP2_TRACE_GRAPH=1` or pass `--trace-dir` to record peer timing, failures, and memory by invocation and job ID. [Graph benchmark](../scripts/benchmark-graph.py)

## Operational validation

The seeded three-peer Notes run partitioned writers, killed daemons after acknowledgments, and checked both branches against a model before merging. Seed 761 acknowledged 691 writes and merges across ten rounds with 30 operations per writer. A single-writer run verified 41 signed revisions after compaction and transfer restart. [Notes workflow](../scripts/demo-replicated-notes.py)

An initial replica pass transferred 22 private blocks over one TCP connection. The prior wire protocol needed 23 connections for the same blocks. Mixed-version peers can still synchronize through that protocol.

Current evidence comes from controlled runs. Independent physical deployments, sustained WAN load, and critical workloads remain unvalidated. Multi-reference transactions, bounded multi-writer history, interactive guest debugging, remote TypeScript source maps, and portable closure state remain open.
