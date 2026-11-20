# pp2

**Write programs, not servers.**

pp2 lets an application run a function on the computer that owns a resource. The owner grants a specific peer permission to run specific code against that resource. The runtime authenticates the peers, moves verified code where it needs to run, and returns the result.

Consider searching a directory on an office computer from a laptop. With pp2, the application author writes a terminal interface and an indexing function. The office computer reads the documents and maintains the index. A search returns matching paths and the index revision to the laptop. Both machines run the same general-purpose runtime. There is no document service to deploy, search endpoint to design, or database connection to expose.

In the terminal program, searching is a function call through a granted capability:

```js
const result = await evaluate(capabilities.documents, {type: 'search', query}, {
    calls: 0,
    timeoutMs: 2000,
});
```

The resource owner chooses the directory and approves the indexer that runs there. The deadline is explicit because the owner may be offline.

## Try document search

From this checkout on Linux, with Rust 1.94.1, a C toolchain, OpenSSL, Node.js and npm installed, run the following. Cargo's install directory (normally `~/.cargo/bin`) must be on your PATH. The first build compiles SQLite and QuickJS and can take several minutes.

```sh
cargo install --locked --path .
npm ci
pp2 install examples/native-documents
pp2 grant documents examples/native-documents/sample
pp2 run index
pp2 run 'search budget'
```

Review the requested permissions and enter `y` at installation. On a fresh workspace the search prints:

```text
Index revision 1 · 1 match
meeting.md
```

The grant permits the indexer to read files in the selected directory and write its index in pp2 storage. Your source files stay read-only. The same application can search a directory on another peer by connecting a grant issued there.

- [Create a project and run it across two machines](docs/getting-started.md)
- [Write and update an application](docs/applications.md)
- [Operate a peer, manage grants and diagnose failures](docs/operations.md)
- [Runtime architecture and limits](docs/architecture.md)
- [Build, test and prepare a release](CONTRIBUTING.md)

pp2 is experimental systems software. The runtime bounds each invocation, and a disconnected peer can make a call fail. The document app shows the revision of a cached search when the owner is unavailable. Independent production operation and critical workloads have not been validated.
