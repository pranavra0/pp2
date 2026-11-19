# Runtime design

## Evaluation and authority

A peer accepts one operation per mutual TLS 1.3 connection. It validates the client leaf certificate and looks up the capability by both its random ID and the certificate's SHA-256 fingerprint. The peer controls the reference the capability addresses. A grant allows snapshot reads or snapshot reads and atomic updates. It can also restrict execution to one immutable program hash. A grant holder may delegate an equal or narrower grant to a different certificate, with a maximum depth of eight. Revoking a grant removes its descendants and their receipts in the same transaction.

A read runs on a committed snapshot. The peer rechecks authorization before releasing a result. An update uses an expected revision and returns exactly {next, value}. The peer checks the revision and grants inside the committing transaction, then saves the next content block, the reference advance, and a receipt together. Concurrent successful updates to a reference have a total order. Reads see the revision they started with. Storage is single-writer per reference revision, with one authoritative storage peer.

Use the same grant, program, input, expected revision, and operation ID when retrying an ambiguous update. A recent match replays the receipt. Reusing an ID with different arguments while its receipt is retained produces an error. Receipts are retained for 1,024 revisions while the grant remains live. When the revision has advanced past that window, a conflict can establish that the retry did not apply now. The client must reconcile older outcomes through application state. Delegation creates a distinct grant on each success, so a lost delegation reply can leave an unused grant for the administrator to revoke.

A call names a destination explicitly. The client reports elapsed time and application bytes in both directions, including code negotiation. Rust callers can use Cancellation to close an in-flight evaluation. Peer workers stop when their request connection closes or the daemon exits. Cancellation can race a commit, so recovery uses the same update receipt mechanism.

## Storage and distribution

SQLite provides indexed content and reference lookups, durable WAL commits, and concurrent snapshots. The daemon uses synchronous=FULL and a database page quota. Each successful update increments the reference revision even if its content hash stays the same. Reference changes and publication require complete Merkle graphs. Collection traces current references and published roots, then removes unreachable content and associated cache entries in one transaction. Workers take bounded copies of the blocks they use, which can outlive collection of an older revision. [SQLite WAL](https://sqlite.org/wal.html)

An immutable block's SHA-256 address covers its version bytes and contents. Public fetches serve blocks explicitly published by the local administrator. Publish dependencies individually when making a complete program available. An authorized caller can supply missing code over the existing authenticated connection. Supplied modules are cached in the submitting certificate's scope. Only explicitly published code is shared across principals. Client-supplied packages are restricted to the declared import graph, regardless of what the remote peer requests.

Peers find content by hash through a local cache and an ordered list of configured sources. The caller can put LAN sources first. A client verifies each block and can republish it. The CA bootstraps trust. Evaluation and content exchange run directly between peers. Mutable references belong to their authoritative peers, and their current contents have independent immutable addresses.

## TypeScript, JavaScript, and binary programs

A pp2 JavaScript program is an ECMAScript module with a default function taking (state, input). A handler can return a JSON-compatible value or a promise of one. A read returns the value. An update returns an object with next and value fields. State and input are detached values. The wire boundary accepts text, booleans, null, safe integers, arrays, and records. Serialization checks depth, size, and numbers and rejects cycles and unsupported values. ECMAScript property access and toJSON behavior apply during serialization. Code can capture values in ordinary lexical closures within an evaluation. Across evaluations, recreate closures from the same module and explicit data. JavaScript structured cloning rejects callable objects, and V8 startup snapshots are engine initialization artifacts. [HTML structured serialization](https://html.spec.whatwg.org/multipage/structured-data.html), [V8 embedding guide](https://v8.dev/docs/embed)

The packaging command compiles TypeScript on the author's machine with strict ES2022 settings. It type-checks local source dependencies and links runtime imports to explicit hashes. TypeScript errors show source paths and line numbers. The program hash covers the emitted code and import manifest. Types are erased, so code still uses runtime checks when it accepts untrusted input. The TypeScript compiler runs only during packaging. [TypeScript compiler options](https://www.typescriptlang.org/docs/handbook/compiler-options.html)

A `PPJ1` module carries UTF-8 ECMAScript with a sorted list of SHA-256 import hashes. Use `SPECIFIER=HASH` to link a TypeScript import during packaging. A JavaScript module can write `pp2:HASH` directly and declare that hash as a positional pack argument. The loader resolves imports only against the verified manifest. Each worker installs a fresh context. The guest globals omit `Date`, `Math.random`, and shared-memory facilities. The locked QuickJS version supplies the ECMAScript semantics. Runtime exceptions identify emitted module locations by content hash.

V8 is a viable ECMAScript engine for larger workloads. Its standard embedding supports isolated heaps and separate contexts, and its in-process sandbox limits the impact of some engine memory faults. A V8 adoption would still require OS process isolation, controlled module loading, and explicit data and capability boundaries. QuickJS provides module hooks, an interrupt handler, and memory/stack limits, and builds from the locked source dependency without a JIT. These properties fit pp2's current isolated per-request worker. The workload comparison measures the whole pp2 path and does not isolate JavaScript engine cost. [V8 sandbox](https://v8.dev/blog/sandbox), [V8 untrusted-code guidance](https://v8.dev/docs/untrusted-code-mitigations), [QuickJS embedding API](https://www.bellard.org/quickjs/quickjs.html)

Existing AEB1 programs still use the Rust interpreter and their original canonical encoding. A remote binary program sees slot zero as a read-only grant for its snapshot and obtains other portable inputs from its captures. JavaScript and binary IR use the same transport, grant checks, commit path, and process boundary.

## Isolation and limits

The worker receives only verified code, the granted snapshot, and arguments. It starts with a cleared environment, closes inherited descriptors, and installs a Linux seccomp allowlist before reading the request. The filter allows pipe I/O on the designated descriptors and restricts memory mappings. File opens, socket operations, subprocess creation, and executable mappings are outside the allowlist. Resource limits bound address space and CPU. The peer also caps concurrent connections and frame sizes, and a parent watchdog stops expired workers. QuickJS uses a 32 MiB heap limit and a two-second evaluation deadline. Binary IR keeps its fuel and charged allocation budgets. JavaScript reports a heap sample at completion and worker elapsed time. [seccompiler](https://docs.rs/seccompiler/latest/seccompiler/)

The daemon is the trusted host for credentials, the database, and grant policy. It checks the worker result before publishing it to the caller or committing state. A read grant can permit arbitrary programs to observe its entire snapshot. Restrict a grant to an audited program hash when the caller should see only the results that program exposes.

The peer transport and worker envelope use `PPN1`, a 32-bit big-endian length, and a Postcard payload. Changes to message layouts require a new transport version. Immutable `AEB1` and `PPJ1` blocks and `AEV1` portable values retain independent formats. The SQLite database records its pp2 application ID and schema version 1. Blocks and portable values are limited to 256 KiB each. A code graph can contain up to 32 modules and 512 KiB. Remote code caching has a 16 MiB cap per certificate.

## Application measurements

The reproducible comparison in scripts/validate-peers.py uses the same synthetic document queries for both implementations. It measures warm indexed reads over loopback with a fresh mutual TLS connection for each query. The conventional implementation uses an application-specific HTTPS endpoint, certificate policy, and SQLite FTS5 query. The pp2 implementation supplies application-specific indexing and query modules, with TLS, framing, grant validation, and execution handled by the daemon. Wire counts include application framing and exclude TLS records. Timings include network connections and exclude client process startup.

The 40-query run used 64 documents with 121,648 bytes of body text. Both systems returned identical results.

| Implementation | Median latency | Request | Response |
| --- | ---: | ---: | ---: |
| pp2, warm | 10.00 ms | 129 B | 393 B |
| HTTPS with SQLite FTS5 | 6.10 ms | 57 B | 441 B |

The cold pp2 request against an empty library included module negotiation and took 25 ms, with 1,916 B sent and 108 B received. In the warm run, pp2 returned a smaller reply and spent more time per call. Each call starts a new worker and decodes a full reference snapshot. The measurements cover the whole evaluation path and leave those costs unquantified individually.

The conventional search service owns its HTTP request and response schema, its certificate-to-route check, and its SQL query. The pp2 modules own the index and query, while both applications use one server implementation for authentication, versioned writes, and retry receipts. The comparison covers search only. Application complexity and reliability across identical feature sets, WAN latency, and larger libraries require further measurements.

The separate Linux network namespace run exercised peer-sourced application updates, queued edits, cached reads, and restart recovery. It also ran two competing reservations against one available unit and replayed the winning update. The clients and storage peer used separate network stacks on the same host.

## Current scope

- Explicit placement targets a single storage peer per call. Remote-initiated placement and automatic topology discovery remain open.
- The current storage interface evaluates one bounded snapshot and can atomically replace one reference. General indexed operations over large datasets, multiple-reference transactions, and storage replication remain open.
- Live remote debugging, TypeScript source maps for remote errors, and first-class portable JavaScript closure state remain open.
