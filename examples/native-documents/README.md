# Native document search

Install a package by its SHA-256 address, connect a directory grant issued by its owner, and search from a terminal. The document peer reads and indexes the files. Searches return relative paths and an index revision. The laptop saves successful query results in the installation's private collection.

## Install across two machines

Use the Linux pp2 binary on both machines. The directory provider requires `openat2` and a filesystem that reports creation timestamps. The default node settings discover peers on the same LAN. On separate networks, configure the nodes to use the same rendezvous service. [Discovery configuration](../../README.md#deploy-with-network-discovery)

1. On the laptop, get the workspace's persistent peer identity. The command creates the workspace on first use.

   ~~~sh
   pp2 app native identity laptop-node
   ~~~

2. On the document host, package and publish the application and issue a directory grant. Set `LAPTOP_ID` to the identity from step 1. The publisher helper takes the pp2 executable and the publisher workspace. It prints the package and indexer addresses.

   ~~~sh
   read -r PACKAGE INDEXER <<< "$(examples/native-documents/package.sh pp2 documents-node)"
   PUBLISHER_ID=$(pp2 app native identity documents-node)
   pp2 app native share-directory documents-node documents /path/to/documents \
       "$LAPTOP_ID" "$INDEXER" writer > documents.grant.json
   printf '%s\n' "$PACKAGE" "$PUBLISHER_ID"
   pp2 app native host documents-node
   ~~~

   The directory provider supplies read-only file operations. The writer grant lets the pinned indexer update the collection on the document host. Keep the peer running while indexing and searching. The same generic peer can serve other packages and resources.

3. On the laptop, set `PACKAGE` and `PUBLISHER_ID` from step 2 and copy over `documents.grant.json`. Inspect and approve the package when prompted.

   ~~~sh
   APP=$(pp2 app native install laptop-node "$PACKAGE" "$PUBLISHER_ID")
   pp2 app native grant laptop-node "$APP" documents documents.grant.json
   pp2 app native run laptop-node "$APP"
   ~~~

   Enter `index` to build or refresh the index and `search meeting budget` to find files containing both terms. Use `.quit` to exit. The example handles up to 32 UTF-8 Markdown or text files, 16 KiB per file, in up to 20 directories. A completed refresh atomically replaces the index. Cached queries continue to work during disconnection, with their saved revision displayed.

## Update and remove

Publish a new package from the document host with `package.sh pp2 documents-node PATH_TO_NEW_APP_MJS`. On the laptop, approve the new package. The installation ID, cached results, and grant for the unchanged indexer request carry forward. A changed request requires its own grant.

~~~sh
pp2 app native update laptop-node "$APP" "$NEW_PACKAGE" "$PUBLISHER_ID"
pp2 app native status laptop-node "$APP"
pp2 app native remove laptop-node "$APP"
~~~

Removal deletes the laptop installation and its private collection. The remote directory and index belong to the document peer. The owner can revoke the grant with `pp2 peer revoke documents-node/peer.db GRANT_ID`, using the ID printed to stderr by `share-directory`. The laptop can disconnect a binding with `pp2 app native disconnect laptop-node "$APP" documents`.

## Complexity comparison

Both examples rebuild a persistent index on the document host, return matching paths over an authenticated connection, and cache successful searches on the laptop. The Python baseline uses a dedicated mTLS HTTPS service and SQLite. Its service opens the directory with the process's filesystem authority. Package installation, updates, and scoped grants are outside the baseline.

| Nonblank lines | pp2 | Conventional mTLS and SQLite |
| --- | ---: | ---: |
| Application source | 127 | 149 |
| Application source and pp2 packaging helper | 161 | 149 |

The pp2 count includes both JavaScript programs. The baseline count includes its Python client and server. The counts exclude shared runtimes, the conventional certificate provisioning script, and tests. The main difference is which responsibilities are application code. The pp2 programs describe indexing, search, terminal messages, and the offline cache. The baseline also implements HTTPS routes, certificate loading, endpoint configuration, serialization, and independent database setup. Both use two user-facing roles. On the document machine, pp2 runs a generic peer that can serve other applications.

Recount from the repository root.

~~~sh
awk 'NF { n[FILENAME]++ } END { for (f in n) print f, n[f] }' \
    examples/native-documents/*.mjs examples/native-documents/package.sh \
    scripts/native-documents-baseline.py
~~~

Run the three-peer integration fixture with `cargo test --test native -- --nocapture`. It uses distinct laptop, publisher, and directory identities with loopback rendezvous. In one cold refresh, the laptop sent 2,974 bytes of pp2 frames to the document peer, including the missing indexer code, and received 115 bytes of replies. The document peer read 21,000 bytes of source text from its own filesystem. Frame counts exclude TLS overhead.

To run the baseline with a test directory, create development certificates for `localhost` and the `client` role. Run these commands in separate terminals, using the same certificate location.

~~~sh
scripts/dev-certificates.sh baseline-certs localhost client
python3 scripts/native-documents-baseline.py server /path/to/documents index.db baseline-certs 127.0.0.1 7440
python3 scripts/native-documents-baseline.py client localhost 7440 baseline-certs cache.db
~~~
