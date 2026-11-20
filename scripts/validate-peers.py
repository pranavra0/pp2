#!/usr/bin/env python3
"""Exercise the CLI applications and compare an indexed search over TLS."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlsplit

from peer_topology import serving

ROOT = Path(__file__).resolve().parents[1]


def command(binary, *args, check=True):
    return subprocess.run(
        [str(binary), *(str(arg) for arg in args)], capture_output=True, text=True,
        check=check, timeout=20, cwd=ROOT,
    )


def output(binary, *args):
    return command(binary, *args).stdout.strip()


@contextmanager
def peer(pp2, db, certificates, address="127.0.0.1:0", prefix=()):
    with serving(
        [*prefix, pp2, "peer", "serve", db, address, certificates / "ca.pem",
         certificates / "server.pem", certificates / "server.key"],
        crash=True, ready_prefix="listening on ",
    ) as ready:
        yield ready.removeprefix("listening on ")


def profile(pp2, certificates, database, reference, modules, cache, address):
    cert = certificates / "client.pem"
    return {
        "address": address,
        "name": "localhost",
        "ca": str(certificates / "ca.pem"),
        "certificate": str(cert),
        "key": str(certificates / "client.key"),
        "cache": str(cache),
        "read": {
            "program": modules["read"],
            "grant": output(pp2, "peer", "issue", database, reference, cert,
                            "reader", modules["read"]),
        },
        "write": {
            "program": modules["write"],
            "grant": output(pp2, "peer", "issue", database, reference, cert,
                            "writer", modules["write"]),
        },
    }


def documents(library, configuration, work):
    body = work / "body.txt"
    rows = []
    for number in range(64):
        identifier = f"doc-{number:03}"
        title = f"Report {number}"
        text = ("meeting notes budget staffing transaction example " * 38).strip()
        if number % 8 == 0:
            text += " quartz ledger"
        body.write_text(text)
        command(library, "add", configuration, identifier, title, body)
        rows.append((identifier, title, text))
    command(library, "sync", configuration)
    return rows


@contextmanager
def storage_network(separate):
    if not separate:
        yield "127.0.0.1:0", ()
        return
    command("ip", "link", "set", "lo", "up")
    with subprocess.Popen(["unshare", "-n", "sh", "-c", "echo ready; exec sleep infinity"],
                          text=True, stdout=subprocess.PIPE) as storage:
        try:
            if storage.stdout.readline().strip() != "ready":
                raise RuntimeError("storage network namespace failed to start")
            prefix = ("nsenter", "--target", str(storage.pid), "--net", "--")
            command("ip", "link", "add", "pp2-client", "type", "veth", "peer", "name", "pp2-storage")
            command("ip", "link", "set", "pp2-storage", "netns", storage.pid)
            command("ip", "address", "add", "10.73.0.1/30", "dev", "pp2-client")
            command("ip", "link", "set", "pp2-client", "up")
            command(*prefix, "ip", "address", "add", "10.73.0.2/30", "dev", "pp2-storage")
            command(*prefix, "ip", "link", "set", "pp2-storage", "up")
            yield "10.73.0.2:0", prefix
        finally:
            storage.terminate()
            storage.wait()


def validate(work, binaries, samples, storage_address, storage_prefix):
    pp2 = binaries / "pp2"
    library = binaries / "examples" / "document_library"
    inventory = binaries / "examples" / "inventory"
    certificates = work / "certs"
    database = work / "storage.db"
    publisher_db, cache = work / "publisher.db", work / "cache.db"
    library_config, stock_config = work / "library.json", work / "inventory.json"
    command(ROOT / "scripts" / "dev-certificates.sh", certificates, "localhost", "client")
    command(library, "init", database, "documents")
    command(inventory, "init", database, "stock", "lamp", 1)
    library_modules = json.loads(output(library, "package", publisher_db))
    stock_modules = json.loads(output(inventory, "package", publisher_db))
    validate_type_error(pp2, work)

    with peer(pp2, publisher_db, certificates) as publisher:
        install = (cache, publisher, "localhost", certificates / "ca.pem",
                   certificates / "client.pem", certificates / "client.key")
        for group in (library_modules, stock_modules):
            for role in ("read", "write"):
                command(pp2, "peer", "fetch-program", *install, group[role], "--publish")
    # The publisher is gone before the storage peer has received a program.
    with peer(pp2, database, certificates, storage_address, storage_prefix) as address:
        library_config.write_text(json.dumps(profile(
            pp2, certificates, database, "documents", library_modules, cache, address)))
        stock_config.write_text(json.dumps(profile(
            pp2, certificates, database, "stock", stock_modules, cache, address)))
        first = json.loads(output(library, "search", library_config, "quartz ledger"))
        assert first["value"] == [] and first["cached"] is False
        stock = json.loads(output(inventory, "status", stock_config))
        assert stock["value"]["available"] == {"lamp": 1}

    # A failed sync preserves the queue. A repeated read can use its cached revision.
    cached = json.loads(output(library, "search", library_config, "quartz ledger"))
    assert cached["cached"] is True and cached["revision"] == 0
    body = work / "offline.txt"
    body.write_text("CafÉ offline note for the document library")
    command(library, "add", library_config, "offline", "Disconnected edit", body)
    assert command(library, "sync", library_config, check=False).returncode != 0

    with peer(pp2, database, certificates, address, storage_prefix):
        command(library, "sync", library_config)
        assert json.loads(output(library, "search", library_config, "café offline"))["value"] == [
            {"id": "offline", "title": "Disconnected edit"}
        ]
        assert json.loads(output(library, "show", library_config, "offline"))["value"]["text"] == body.read_text()
        validate_update(pp2, library, work, certificates, database, cache,
                        library_config, library_modules["index"])
        body.write_text("replacement text")
        command(library, "add", library_config, "offline", "Replaced edit", body)
        command(library, "sync", library_config)
        assert json.loads(output(library, "search", library_config, "café offline"))["value"] == []
        command(library, "remove", library_config, "offline")
        command(library, "sync", library_config)
        assert json.loads(output(library, "show", library_config, "offline"))["value"] is None

        def reserve(identifier):
            return command(inventory, "reserve", stock_config, 0, identifier, "lamp", 1, check=False)

        with ThreadPoolExecutor(max_workers=2) as pool:
            contenders = list(pool.map(reserve, ("a", "b")))
        assert sorted(reply.returncode for reply in contenders) == [0, 1]
        accepted = json.loads(next(reply.stdout for reply in contenders if reply.returncode == 0))
        assert "Conflict(1)" in next(reply.stderr for reply in contenders if reply.returncode != 0)
        identifier = accepted["value"]["id"]
        replay = json.loads(output(inventory, "reserve", stock_config, 0, identifier, "lamp", 1))
        assert replay["value"] == accepted["value"] and replay["worker_ms"] is None
        denied = command(inventory, "reserve", stock_config, 1, "c", "lamp", 1, check=False)
        assert denied.returncode and "insufficient stock" in denied.stderr
        command(inventory, "release", stock_config, 1, identifier)
        assert json.loads(output(inventory, "status", stock_config))["value"]["available"] == {"lamp": 1}
        print("Applications passed: peer-sourced modules and updates, offline edits and reads, restart, indexing, and competing reservations.")
        if samples:
            rows = documents(library, library_config, work)
            compare(work, library, library_config, rows, samples, certificates, first)


def validate_type_error(pp2, work):
    source, packed = work / "bad.ts", work / "bad.ppj"
    source.write_text("export default function read(state: number): number { return 'wrong'; }")
    packed.write_bytes(b"existing output")
    failed = command(pp2, "peer", "pack", source, packed, check=False)
    assert failed.returncode and "TS2322" in failed.stderr
    assert packed.read_bytes() == b"existing output"


def validate_update(pp2, library, work, certificates, database, cache, old_profile, index):
    source, packed = work / "library-v2.ts", work / "library-v2.ppj"
    library_source = ROOT / "examples" / "library"
    (work / "index.ts").write_bytes((library_source / "index.ts").read_bytes())
    read = (library_source / "read.ts").read_text()
    source.write_text(read.replace("title: document.title", "title: document.title.toUpperCase()"))
    failed = command(pp2, "peer", "pack", source, packed, check=False)
    assert failed.returncode and 'link runtime import "./index.js"' in failed.stderr
    program = output(pp2, "peer", "pack", source, packed, f"./index.js={index}")
    command(pp2, "peer", "put", cache, packed, "--publish")
    updated_cache = work / "updated.db"
    client = certificates / "client.pem"
    with peer(pp2, cache, certificates) as source_peer:
        command(pp2, "peer", "fetch-program", updated_cache, source_peer, "localhost",
                certificates / "ca.pem", client, certificates / "client.key", program)
    grant = output(pp2, "peer", "issue", database, "documents", client, "reader", program)
    configuration = json.loads(old_profile.read_text())
    configuration["cache"] = str(updated_cache)
    configuration["read"] = {"program": program, "grant": grant}
    updated_profile = work / "updated.json"
    updated_profile.write_text(json.dumps(configuration))
    result = json.loads(output(library, "search", updated_profile, "café offline"))
    assert result["value"] == [{"id": "offline", "title": "DISCONNECTED EDIT"}]


class SearchHandler(http.server.BaseHTTPRequestHandler):
    """Conventional storage-side search with an application-specific HTTPS endpoint."""

    def do_GET(self):
        if hashlib.sha256(self.connection.getpeercert(binary_form=True)).digest() != self.server.holder:
            return self.send_error(403)
        uri = urlsplit(self.path)
        if uri.path != "/search":
            return self.send_error(404)
        terms = re.findall("[a-z0-9]+", parse_qs(uri.query).get("q", [""])[0].lower())
        with sqlite3.connect(self.server.database) as db:
            rows = db.execute(
                "SELECT id, title FROM documents WHERE documents MATCH ? ORDER BY id LIMIT 50",
                (" AND ".join(terms),),
            ).fetchall() if terms else []
        data = json.dumps([{"id": row[0], "title": row[1]} for row in rows],
                          separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def compare(work, library, configuration, rows, samples, certificates, first):
    conventional_db = work / "conventional.db"
    with sqlite3.connect(conventional_db) as db:
        db.execute("CREATE VIRTUAL TABLE documents USING fts5(id UNINDEXED, title, body)")
        db.executemany("INSERT INTO documents VALUES (?, ?, ?)", rows)

    def context(purpose, identity):
        tls = ssl.create_default_context(purpose, cafile=str(certificates / "ca.pem"))
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(certificates / f"{identity}.pem", certificates / f"{identity}.key")
        return tls

    server_tls = context(ssl.Purpose.CLIENT_AUTH, "server")
    server_tls.verify_mode = ssl.CERT_REQUIRED
    client_tls = context(ssl.Purpose.SERVER_AUTH, "client")
    with http.server.HTTPServer(("127.0.0.1", 0), SearchHandler) as server:
        server.socket = server_tls.wrap_socket(server.socket, server_side=True)
        server.database = conventional_db
        server.holder = hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            (certificates / "client.pem").read_text())).digest()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            pp2_samples, http_samples = [], []
            for _ in range(samples):
                pp2 = json.loads(output(library, "search", configuration, "quartz ledger"))
                query = urlencode({"q": "quartz ledger"})
                request = f"GET /search?{query} HTTP/1.0\r\nHost: localhost\r\n\r\n".encode()
                started = time.perf_counter()
                with socket.create_connection(server.server_address, timeout=5) as tcp:
                    with client_tls.wrap_socket(tcp, server_hostname="localhost") as transport:
                        transport.sendall(request)
                        with transport.makefile("rb") as response:
                            reply = response.read(64 * 1024)
                http_ms = (time.perf_counter() - started) * 1000
                headers, body = reply.split(b"\r\n\r\n", 1)
                assert headers.startswith(b"HTTP/1.0 200 ") and json.loads(body) == pp2["value"]
                pp2_samples.append((pp2["elapsed_ms"], pp2["request_bytes"], pp2["response_bytes"]))
                http_samples.append((http_ms, len(request), len(reply)))
        finally:
            server.shutdown()
            thread.join()
    print(f"Search over loopback: {samples} requests per implementation, {len(rows)} documents, "
          f"{sum(len(row[2].encode()) for row in rows):,} body bytes, identical results.")
    print(f"pp2 cold empty query: {first['elapsed_ms']} ms, {first['request_bytes']} B sent, "
          f"{first['response_bytes']} B received including module negotiation.")
    for name, measurements in (("pp2 warm", pp2_samples), ("HTTPS + SQLite FTS5", http_samples)):
        latency, sent, received = zip(*measurements)
        print(f"{name}: median {statistics.median(latency):.2f} ms, "
              f"{statistics.median(sent):g} B sent, {statistics.median(received):g} B received.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", default=ROOT / "target" / "release", type=Path)
    parser.add_argument("--samples", default=0, type=int,
                        help="also compare this many indexed searches per implementation")
    parser.add_argument("--isolated-networks", action="store_true",
                        help="run the storage peer in a separate Linux network namespace")
    arguments = parser.parse_args()
    if arguments.samples < 0:
        parser.error("--samples must be nonnegative")
    if arguments.isolated_networks and arguments.samples:
        parser.error("run the comparison over loopback without --isolated-networks")
    if arguments.isolated_networks and "PP2_VALIDATION_NETNS" not in os.environ:
        os.environ["PP2_VALIDATION_NETNS"] = "1"
        os.execvp("unshare", ["unshare", "-Urn", "--", sys.executable, __file__, *sys.argv[1:]])
    with tempfile.TemporaryDirectory(prefix="pp2-validation-") as directory:
        with storage_network(arguments.isolated_networks) as (address, prefix):
            validate(Path(directory), arguments.binaries.resolve(), arguments.samples, address, prefix)
