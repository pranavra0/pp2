# Document search

Run locally with the [quickstart](../../README.md#try-document-search) or across two peers with the [two-machine guide](../../docs/getting-started.md).

The [terminal](app.mjs) caches successful results. The [indexer](index.ts) reads files and answers queries. The [manifest](pp2.json) declares their binding. The [HTTPS baseline](../../scripts/native-documents-baseline.py) implements similar search and caching with a dedicated client and server.
