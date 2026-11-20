# Write an application

In the [starter project](getting-started.md), `pp2.json` maps source modules, selects an entry point, sets a graph budget, and requests named grants. Each terminal line starts a bounded invocation. The entry point reads it via `call(resource, 'event')` and returns `{lines}`.

```js
const result = await evaluate(capabilities.documents, {type: 'search', query}, {
    calls: 0,
    timeoutMs: 2000,
});
```

The indexer returns matching paths and the collection revision. A refresh uses the expected revision and event ID to commit atomically. The terminal stores successful searches in private installation state. [Terminal](../examples/native-documents/app.mjs) · [Indexer](../examples/native-documents/index.ts)

## Edit and update

Add `log` to the extension check in `index.ts`, then run `pp2 update search` and `pp2 status`. Review the new package before approving. An update keeps the installation ID, state, and bindings for identical requests. A changed request needs a new grant. Review the pinned program because the values it returns determine what the recipient can learn.

For a remote update, run `pp2 publish` on the owner and `pp2 update --from "$RELEASE"` on the client. Issue and connect a fresh grant for a changed request. Revoke the old grant at the owner to withdraw access.

Use the checkout's npm dependencies or run `npm ci` inside a standalone project. Its `npm run typecheck` checks edits. Packaging uses strict ES2022 and links runtime imports through the module's `imports` map. Workers run the compiled modules without Node built-ins.

`pp2 run` starts an interactive session. Enter `help` for app commands or `.quit` to leave.

## Evaluate over an immutable root

A snapshot reference gives a graph program `pp2.blocks`. Use `blocks.root` to find the current root, `blocks.read(hash)` to retrieve its value and child addresses, and `blocks.write(value, children)` to build new immutable nodes during an update. `blocks.setRoot(hash)` stages a replacement, visible to the rest of the invocation through `blocks.root`. Read the current revision through `pp2.snapshot.revision`. The update commits when the program returns successfully. Addresses become readable by walking links from the selected root or by creating blocks in the current update.

The ordered map is a TypeScript AVL tree. A lookup visits one path, a range scan returns a bounded ordered page, and an edit rewrites the affected path and reuses the unaffected subtrees. The map implements storage structure in guest code using the host's block and transaction primitives. [Map library](../examples/ordered-map/map.ts) · [Entry program](../examples/ordered-map/entry.ts)

Run from the pp2 checkout with the [quickstart toolchain](../README.md#try-document-search).

```sh
WORK=$(mktemp -d)
OWNER=$(pp2 peer node-init "$WORK/owner")
DB="$WORK/owner/peer.db"
MAP=$(pp2 peer pack examples/ordered-map/map.ts "$WORK/map.ppj")
ENTRY=$(pp2 peer pack examples/ordered-map/entry.ts "$WORK/entry.ppj" "./map.js=$MAP")
pp2 peer put "$DB" "$WORK/map.ppj"
pp2 peer put "$DB" "$WORK/entry.ppj"

printf 'null\n' > "$WORK/initial.json"
pp2 peer ref-init "$DB" inventory "$WORK/initial.json"
GRANT=$(pp2 peer issue "$DB" inventory "$OWNER" writer "$ENTRY")
BUDGET='{"timeout_ms":3000,"calls":0,"depth":0}'
OPERATION=$(openssl rand -hex 32)

printf '{"type":"put","key":"lamp","value":12}\n' > "$WORK/write.json"
pp2 peer graph-local "$WORK/owner" "$DB" "$GRANT" "$ENTRY" "$WORK/write.json" "$BUDGET" --update 0 "$OPERATION"

printf '{"type":"scan"}\n' > "$WORK/query.json"
pp2 peer graph-local "$WORK/owner" "$DB" "$GRANT" "$ENTRY" "$WORK/query.json" "$BUDGET"
```

The scan returns `[["lamp",12]]` at revision 1. Reuse the same operation ID and arguments to retry the write. To run the scan from a second peer, issue its identity a read grant pinned to `ENTRY`, publish the entry code with `pp2 peer publish "$DB" "$ENTRY" --graph`, and serve the owner with `pp2 peer serve-network`. The second peer calls `pp2 peer connect NODE_DIRECTORY OWNER_ID graph-read - GRANT ENTRY QUERY_FILE BUDGET_JSON`. The owner evaluates the map query and sends back the page.

## Compose stages

A program with outbound bindings uses `peer issue-compute`. For `app init` manifests, omit `collection` on a compute entry or target. A resource stage gets storage or a host resource and returns the values its caller needs. An orchestrator combines those values or passes them as input to another stage. Use `evaluateAll` to dispatch up to four independent leaf reads.

Existing graph applications that combined private reads with outbound evaluation need a compute entry and separate resource grants. A subscription keeps its watch grant and uses `entry_grant` to select the compute stage. A terminal app accesses its private state through `evaluate(capabilities.state, input)`. [Federated stock](../examples/federated-stock/app.json) · [Terminal state](../examples/native-documents/app.mjs)

## Examples

- [Persistent inventory](../examples/persistent-inventory) updates a projection after source changes.
- [Replicated Notes](../examples/replicated-notes) keeps concurrent offline edits until explicit resolution. [Three-peer workflow](../scripts/demo-replicated-notes.py)
