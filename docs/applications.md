# Write an application

Start with the project generated in [Getting started](getting-started.md). Its `pp2.json` maps module names to source files, selects a terminal entry point, sets the invocation budget, and declares named resource requests. Each request names the program the owner will authorize and the access it needs. A request by itself confers no authority.

The entry point receives a terminal event through `call(resource, 'event')`. It returns an object with a `lines` array. Each line of terminal input starts a new bounded invocation. In the document app the body of a search uses this call:

```js
const result = await evaluate(capabilities.documents, {type: 'search', query}, {
    calls: 0,
    timeoutMs: 2000,
});
```

The indexer receives the query as an ordinary argument. It scans its local index and returns matching paths. The caller gets the returned value and the collection revision. A refresh uses an expected revision and the terminal event's operation ID to commit a replacement index atomically. The terminal saves successful queries in its installation's private collection via the built-in state capability. [Terminal source](../examples/native-documents/app.mjs) · [Indexer source](../examples/native-documents/index.ts)

## Edit and update

For example, add `log` to the extension check in `index.ts` to include UTF-8 log files. From the checkout, rebuild the generated project and inspect the resulting requests:

```sh
pp2 update search
pp2 status
```

Review the new package before approving. An installation ID names a private collection and survives updates. A package address identifies one immutable version. Updating keeps bindings whose name, program, access and description are unchanged. Editing the indexer changes the program hash, so the documents request awaits a new grant. Repeat the local grant and index steps. To distribute an update, publish the new version and use the laptop command below with its new address. For a changed request, issue and connect a fresh grant, and revoke the old grant at the owner when its holders should lose access.

```sh
pp2 update --from "$RELEASE"
```

The editor uses the generated `tsconfig.json` and `directory.d.ts` for the indexer. Packaging checks TypeScript with strict ES2022 settings. The compiler resolves TypeScript from the project's or current directory's Node module tree. Inside a standalone generated project, run `npm ci` to install its locked compiler and `npm run typecheck` to check edits. When developing from the pp2 checkout, you can use its existing npm dependencies. Runtime imports in a TypeScript module can be mapped in its manifest entry with an `imports` object from source specifier to module name. Type-only imports are erased. Workers run the compiled modules without Node built-ins.

Run the app interactively with `pp2 run`. Enter `help` for its commands and `.quit` to leave. A directory grant authorizes the exact indexer code to read the selected directory. Review the program before granting access: its return values determine what the remote caller can learn. Each installation has separate local state. Changing a binding preserves that state, including paths already returned to the app.

## Other application patterns

The [warehouse query](../examples/federated-stock/app.json) shows a fixed graph that reads collections on several peers and combines the results. The [inventory handlers](../examples/persistent-inventory) update a projection after a source change. The [Notes application](../examples/replicated-notes) uses a replicated collection so peers can edit offline and reconcile concurrent versions. Its [three-peer workflow](../scripts/demo-replicated-notes.py) exercises installation, synchronization and explicit conflict resolution. See the architecture reference for [offline authority and revocation](architecture.md#offline-authority-and-revocation).
