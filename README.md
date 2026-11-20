# pp2

**Write programs, not servers.** Send a TypeScript function to the peer that owns the data. That peer verifies the caller and the program, runs the function in QuickJS, and returns its JSON result. Each peer runs the same binary and keeps its own SQLite file.

```ts
import {total} from './total.js';

export default function summarize(state: {readings: number[]}, minimum: number) {
    const readings = state.readings.filter(value => value >= minimum);
    return {count: readings.length, total: total(readings)};
}
```

## Run two peers

From this checkout on x86-64 Linux, with a C toolchain, Rust 1.94.1 or later, OpenSSL, Node.js and npm installed, run the following in Bash. Node and TypeScript are used only when packaging source.

```sh
npm ci
cargo build --locked
demo=$(mktemp -d)
owner() { PP2_HOME="$demo/owner" target/debug/pp2 "$@"; }
caller() { PP2_HOME="$demo/caller" target/debug/pp2 "$@"; }

owner_id=$(owner init)
caller_id=$(caller init)
owner create sensor '{"readings":[2,4,8],"serial":"private"}'
PP2_HOME="$demo/owner" target/debug/pp2 serve 127.0.0.1:47341 &
owner_pid=$!
at="$owner_id@127.0.0.1:47341"

query=$(caller pack examples/portable/summary.ts)
grant=$(owner grant sensor "$caller_id" "$query" read)
options=$(printf '{"input":3,"capabilities":[{"grant":"%s"}],"at":"%s"}' "$grant" "$at")

caller eval "$query" "$options"       # {"count":2,"total":12}
snapshot=$(caller pin "$query" "$options")

append=$(caller pack examples/portable/append.ts)
write=$(owner grant sensor "$caller_id" "$append" write)
update=$(printf '{"input":10,"capabilities":[{"grant":"%s","operation":"reading-1"}],"at":"%s"}' "$write" "$at")
caller eval "$append" "$update"       # 4
caller eval "$append" "$update"       # 4

owner revoke "$write"
owner revoke "$grant"
# Repeating the live evaluation now returns "access denied".
kill "$owner_pid"
wait "$owner_pid" || true
caller eval examples/portable/average.ts "$snapshot"   # 6
```

The owner approves a specific program hash, including its imports. Review the source before issuing a grant. The caller automatically sends the bounded module graph with each evaluation. The owner can start with an empty module store.

## Evaluation contract

`Peer::evaluate(program, options)` and `pp2 eval FILE_OR_HASH [OPTIONS_JSON]` invoke the same evaluator. The default export receives `(state, input)` and may return a promise.

| Option | Meaning |
| --- | --- |
| `input` | JSON argument, default `null`. |
| `capabilities` | An empty list for a local pure computation, or one explicit grant for one resource. The guest receives the authorized state. The runtime keeps the credential. |
| `at` | Defaults to `local`. Use a peer ID, `ID@IP:PORT`, or the snapshot address returned by `pin`. |

For a write, include a caller-chosen `operation` ID alongside the grant and reuse it across retries. A read returns a JSON value. A write returns `{state, value}`. The owner replaces the resource with `state` and returns `value`. Each mutable resource lives at one owner. SQLite serializes writes there and commits the replacement and retry receipt together. A grant binds the authenticated holder, resource, exact program, and access mode. Reusing an operation ID on that grant returns the recorded value, including after a restart. Changing the input with the same ID fails.

`pin` evaluates once and saves the released JSON result in the caller's SQLite file. It returns a SHA-256 snapshot address and a fresh local read capability. Subsequent programs can query that immutable value offline. Revoking the owner grant stops future authorized calls. Already released results remain with their recipients. The caller can revoke its snapshot capability locally.

Each invocation gets a fresh Linux worker with seccomp, process resource limits, a QuickJS interrupt deadline, and a loader restricted to declared content-addressed imports. Guest programs have no filesystem or socket access. Module graphs are limited to 32 modules and 512 KiB. Each resource, input, and result is limited to 256 KiB of JSON.

## Transport and validation

Peers use the existing TCP/TLS 1.3 transport with Ed25519 identities bound to the TLS session. Direct addresses and signed LAN discovery work without a manifest. For rendezvous or relay, run `pp2 rendezvous ADDRESS` and place the optional network settings in `$PP2_HOME/discovery.json`, for example `{"rendezvous":"192.0.2.1:47340","relay":true}`. The default peer directory is `.pp2`.

Run `cargo test --locked --all-targets` after `npm ci`. The end-to-end tests run two peer processes, send an imported TypeScript program in both directions, exercise concurrent retries and revocation, stop the owner, query a pinned result, and exercise a relay-only route.
