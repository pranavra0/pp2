# Build and test

Use the [quickstart toolchain](README.md#run-a-program) and Python 3. Run from the repository root with the committed lockfiles.

```sh
npm ci
npm run typecheck
cargo fmt --all --check
cargo test --locked --all-targets
cargo build --release --locked --bin pp2
python3 scripts/check-document-workflow.py target/release/pp2
```

Exercise runtime invariants through public entry points. Use a fresh workspace for first-run checks.

## Benchmarks

```sh
cargo build --release --locked --bins --examples
python3 scripts/validate-peers.py --samples 40
python3 scripts/benchmark-graph.py --isolated-networks --samples 40
```

Both benchmarks verify result equivalence against the conventional implementation before reporting timings. [Measurements](docs/architecture.md#snapshot-application-measurements)

## Release

Start clean and run the checks above. Follow the [two-machine guide](docs/getting-started.md), including approval, changed requests, revocation, offline search, and recovery. Record the commit, toolchain, target, kernel, topology, and binary checksum. Lockfiles fix dependency versions. Byte-identical builds across hosts remain unverified.

License, distribution, and signing are maintainer decisions.
