# Document search

The [quickstart](../../README.md#try-document-search) runs this project locally. The [two-machine guide](../../docs/getting-started.md) moves its terminal to a laptop and leaves the directory and index on their owner.

The [terminal](app.mjs) handles commands and caches successful results. The [indexer](index.ts) walks directories, tokenizes text, replaces index entries and answers queries. The [manifest](pp2.json) declares the connection between them.

For a conventional implementation of a similar search and cache, see the [Python HTTPS client and server](../../scripts/native-documents-baseline.py). Both programs need an available, authenticated document host for a fresh search. In the Python version the application supplies the endpoints, configures mutual TLS, opens the filesystem directly and manages the index and cache databases. In pp2 the application specifies which code can use the directory, and the shared runtime handles those operations.
