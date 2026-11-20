# Building and contributing

Use x86-64 Linux, Rust 1.94.1, a C toolchain, OpenSSL, Node.js 24, npm and Python 3. Run from the repository root with the committed Cargo and npm lockfiles.

```sh
npm ci
npm run typecheck
cargo fmt --all --check
cargo test --locked --all-targets
cargo build --release --locked --bin pp2
python3 scripts/check-document-workflow.py target/release/pp2
```

Keep changes focused on observable behavior. For a runtime change, identify the authority, persistence or failure invariant involved and exercise it through its public entry point. Keep the README quickstart and the two-peer guide executable. Use a fresh workspace for first-run checks.

## Preparing a release

Start from a clean revision. Run the checks above, then install the release build and follow the [two-machine guide](docs/getting-started.md). Exercise approval, a changed program request, revocation, an offline query and recovery. Record the commit, toolchain, target, kernel, tested topology and binary checksum with the release. Compare outputs on the supported target before distributing artifacts. Locked dependencies give a repeatable dependency graph. Byte-identical binaries across build hosts have not been established.

The repository currently has no license file. The choice of license, distribution channel and release signing policy remain maintainer decisions.
