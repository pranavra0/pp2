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

## Examples

- [Federated stock](../examples/federated-stock/app.json) combines reads from several peers.
- [Persistent inventory](../examples/persistent-inventory) updates a projection after source changes.
- [Replicated Notes](../examples/replicated-notes) keeps concurrent offline edits until explicit resolution. [Three-peer workflow](../scripts/demo-replicated-notes.py)
