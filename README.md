# pp2

pp2 runs a content-addressed program on the peer that holds its data. The caller selects the peer and presents a capability for a durable reference. The peer verifies the caller, supplies the reference snapshot to an isolated process, and returns the result. Programs can ship to the peer on demand.

## Build and run

The peer daemon uses Linux with seccomp and the `close_range` system call (Linux 5.9 or later). The commands below use Rust 1.94, a C compiler for bundled SQLite and QuickJS, and OpenSSL for development certificates.

~~~sh
cargo build --release --locked --bins --examples
cargo test --locked --all-targets
target/release/pp2 peer --help
~~~

Install the peer CLI with `cargo install --locked --path .`. The application clients are the `document_library` and `inventory` example binaries under `target/release/examples` after building.

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
~~~

The validation script uses Python 3.9 or later, OpenSSL, and the TypeScript toolchain from `npm ci`. The network namespace run also uses Linux user namespaces, `unshare`, `nsenter`, and `ip`. The comparison uses Python's SQLite build with FTS5. See the [runtime design and measurement notes](docs/architecture.md).

Use `pp2 eval` for local binary IR evaluation and `pp2 demo placement` for the simulated filter-and-fold workload. The other simulator scenarios are `sandbox`, `locality`, `gossip`, and `gc`.
