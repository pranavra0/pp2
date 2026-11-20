# pp2

**Write programs, not servers.**

Evaluate a program at a peer with explicit capabilities. The same runtime launches a local app, runs a query at the owner of private data, and combines results from several peers. Program and data blocks have content addresses. An immutable-root write commits the replacement and a retry receipt together.

## Try document search

On x86-64 Linux, install with Rust 1.94.1, a C toolchain, OpenSSL, Node.js 24, and npm. Put Cargo's bin directory on your PATH.

```sh
cargo install --locked --path .
npm ci
pp2 install examples/native-documents
pp2 grant documents examples/native-documents/sample
pp2 run index
pp2 run 'search budget'
```

Review the install request before approving. Search returns `meeting.md` at index revision 1. The grant lets the indexer read the directory and write its index in pp2 storage.

- [Search across two machines](docs/getting-started.md)
- [Evaluate an ordered map locally and remotely](docs/applications.md#evaluate-over-an-immutable-root)
- [Write and update an app](docs/applications.md)
- [Operate a peer](docs/operations.md)
- [Runtime design and limits](docs/architecture.md)
- [Build, test, and release](CONTRIBUTING.md)
