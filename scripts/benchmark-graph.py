#!/usr/bin/env python3
"""Run the three-peer stock application and compare it with SQLite and mTLS/JSON."""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import time

from peer_topology import topology

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("office", "west", "east")


def command(*args, env=None, trace=None):
    result = subprocess.run(args, text=True, capture_output=True, timeout=25, env=env)
    if trace is not None:
        trace.write(result.stderr)
        trace.flush()
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited with status {result.returncode}\n{result.stderr.strip()}")
    return result.stdout.strip()


@contextmanager
def process(*args, env=None, stderr=None):
    with subprocess.Popen(args, text=True, stdout=subprocess.PIPE, env=env, stderr=stderr) as child:
        try:
            ready = child.stdout.readline().strip()
            if not ready:
                raise RuntimeError(f"{args[0]} failed to start ({child.poll()})")
            yield child, ready
        finally:
            child.kill()
            child.wait()


def endpoints(nodes, port):
    if next(iter(nodes.values()))[0] != "127.0.0.1":
        return {role: f"{host}:{port}" for role, (host, _) in nodes.items()}
    with ExitStack() as stack:
        listeners = [stack.enter_context(socket.socket()) for _ in ROLES]
        for sock in listeners:
            sock.bind(("127.0.0.1", 0))
        return {role: f"127.0.0.1:{sock.getsockname()[1]}" for role, sock in zip(ROLES, listeners)}


def prepare(work, rows, addresses):
    example = ROOT / "examples" / "federated-stock"
    manifest = json.loads((example / "app.json").read_text())
    for module in manifest["modules"].values():
        module["source"] = str(example / module["source"])
    for index, role in enumerate(ROLES):
        manifest["peers"][role]["address"] = addresses[role]
        if role == "office":
            entries = [("minimum/lamp", 250)]
        else:
            entries = [(f"stock/lamp/{i:04}", (i + index) % 7 + 1) for i in range(32)]
            entries.extend((f"stock/other-{i:06}/unit", i % 9) for i in range(rows))
        with (work / f"{role}.ndjson").open("w") as output:
            for entry in entries:
                print(json.dumps(entry), file=output)
        with sqlite3.connect(work / f"{role}.sqlite") as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE entries (key BLOB PRIMARY KEY, quantity INTEGER NOT NULL) WITHOUT ROWID")
            db.executemany("INSERT INTO entries VALUES (?,?)",
                           ((key.encode(), value) for key, value in entries))
    path = work / "app.json"
    path.write_text(json.dumps(manifest))
    return path


def lookup(db, role, sku):
    with sqlite3.connect(db) as conn:
        if role == "office":
            return conn.execute("SELECT quantity FROM entries WHERE key=?",
                                (f"minimum/{sku}".encode(),)).fetchone()[0]
        prefix = f"stock/{sku}/".encode()
        return conn.execute("SELECT coalesce(sum(quantity), 0) FROM entries WHERE key>=? AND key<?",
                            (prefix, prefix + b"\xff")).fetchone()[0]


def combine(minimum, quantities):
    total = sum(quantities.values())
    return dict(total=total, belowMinimum=total < minimum, warehouses=quantities)


def address(endpoint):
    host, port = endpoint.rsplit(":", 1)
    return host, int(port)


def tls(directory, server):
    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose, cafile=directory / "ca.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(directory / "peer.pem", directory / "peer.key")
    if server:
        context.num_tickets = 0
    return context


def frame(payload):
    data = json.dumps(payload, separators=(",", ":")).encode()
    return struct.pack("!I", len(data)) + data


def receive(conn):
    with conn.makefile("rb") as stream:
        length = struct.unpack("!I", stream.read(4))[0]
        if length > 65536:
            raise ValueError("baseline frame exceeds its limit")
        data = stream.read(length)
        return json.loads(data), len(data) + 4


def fetch(context, role, endpoint, sku, parallel=False):
    with socket.create_connection(address(endpoint), timeout=3) as tcp:
        tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with context.wrap_socket(tcp, server_hostname=f"pp2-{role}") as conn:
            request = frame({"sku": sku, "parallel": True} if parallel else {"sku": sku})
            conn.sendall(request)
            reply, received = receive(conn)
    return reply, len(request), received


def baseline_peer(role, work, workspace, endpoints):
    outbound = tls(workspace / role, server=False)
    inbound = tls(workspace / role, server=True)
    holder = "client" if role == "office" else "office"
    certificate = (workspace / holder / "peer.pem").read_text()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).digest()
    with socket.create_server(address(endpoints[role])) as listener, ThreadPoolExecutor(2) as workers:
        print(listener.getsockname(), flush=True)
        while True:
            tcp, _ = listener.accept()
            with tcp:
                tcp.settimeout(3)
                tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                with inbound.wrap_socket(tcp, server_side=True) as conn:
                    if hashlib.sha256(conn.getpeercert(binary_form=True)).digest() != fingerprint:
                        continue
                    query, _ = receive(conn)
                    sku = query["sku"]
                    quantity = lookup(work / f"{role}.sqlite", role, sku)
                    if role != "office":
                        conn.sendall(frame(quantity))
                        continue
                    counts = {}
                    sent = received = 0
                    leaves = ("west", "east")
                    if query.get("parallel"):
                        pending = {leaf: workers.submit(fetch, outbound, leaf, endpoints[leaf], sku)
                                   for leaf in leaves}
                        branches = ((leaf, pending[leaf].result()) for leaf in leaves)
                    else:
                        branches = ((leaf, fetch(outbound, leaf, endpoints[leaf], sku)) for leaf in leaves)
                    for leaf, (count, request, response) in branches:
                        counts[leaf] = count
                        sent += request
                        received += response
                    conn.sendall(frame({
                        "value": combine(quantity, counts),
                        "remote_request_bytes": sent, "remote_response_bytes": received,
                    }))


def percentile(samples, fraction):
    return sorted(samples)[max(0, math.ceil(len(samples) * fraction) - 1)]


def measure(work, nodes, binary, rows, samples, trace_dir, load_clients):
    pp2_addresses = endpoints(nodes, 18630)
    baseline_addresses = endpoints(nodes, 18631)
    manifest = prepare(work, rows, pp2_addresses)
    workspace = work / "deployment"
    command(binary, "app", "init", manifest, workspace, "--discovery")
    for role in (*ROLES, "client"):
        (workspace / role / "discovery.json").write_text('{"lan":false}')
    baseline_workspace = work / "baseline-deployment"
    baseline_manifest = json.loads(manifest.read_text())
    for peer in baseline_manifest["peers"].values():
        peer["collections"] = dict.fromkeys(peer["collections"])
    baseline_path = work / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_manifest))
    command(binary, "app", "init", baseline_path, baseline_workspace)
    sizes = {role: (workspace / role / "peer.db").stat().st_size for role in ("west", "east")}
    assert all(size > 256 * 1024 for size in sizes.values())
    expected = combine(lookup(work / "office.sqlite", "office", "lamp"), {
        role: lookup(work / f"{role}.sqlite", role, "lamp") for role in ("west", "east")
    })

    with ExitStack() as stack:
        traced_env = None
        traces = {}
        if trace_dir is not None:
            trace_dir.mkdir(parents=True, exist_ok=True)
            traced_env = {**os.environ, "PP2_TRACE_GRAPH": "1"}
            traces = {role: stack.enter_context((trace_dir / f"{role}.jsonl").open("x"))
                      for role in (*ROLES, "client")}

        def run(via_west=False, serial=False):
            query = json.dumps({"sku": "lamp", "viaWest": via_west, "serial": serial})
            return json.loads(command(binary, "app", "invoke", workspace / "client", query,
                                      env=traced_env, trace=traces.get("client")))

        for role, (_, prefix) in nodes.items():
            stack.enter_context(process(*prefix, binary, "app", "serve", workspace / role,
                                        env=traced_env, stderr=traces.get(role)))
            stack.enter_context(process(*prefix, sys.executable, __file__,
                                        "--baseline-peer", role, work, baseline_workspace,
                                        json.dumps(baseline_addresses)))
        first = run()
        nested = run(via_west=True)
        assert first["value"] == nested["value"] == expected
        assert first["graph"]["remote_calls"] == nested["graph"]["remote_calls"] == 2
        assert first["graph"]["storage_effects"] == nested["graph"]["storage_effects"] == 5
        context = tls(baseline_workspace / "client", server=False)

        native_times = []
        tls_times = {False: [], True: []}
        graphs = {False: [], True: []}
        tls_traffic = {False: [], True: []}
        for sample in range(samples):
            started = time.perf_counter_ns()
            quantities = {
                role: lookup(work / f"{role}.sqlite", role, "lamp") for role in ("west", "east")
            }
            result = combine(lookup(work / "office.sqlite", "office", "lamp"), quantities)
            native_times.append((time.perf_counter_ns() - started) / 1000)
            assert result == expected

            modes = (True, False) if sample % 2 else (False, True)
            for parallel in modes:
                started = time.perf_counter_ns()
                conventional, sent, received = fetch(context, "office", baseline_addresses["office"],
                                                      "lamp", parallel)
                tls_times[parallel].append((time.perf_counter_ns() - started) / 1000)
                assert conventional["value"] == expected
                tls_traffic[parallel].append(sent + received + conventional["remote_request_bytes"]
                                             + conventional["remote_response_bytes"])

                report = run(serial=not parallel)
                assert report["value"] == expected
                assert report["graph"]["remote_calls"] == 2
                assert report["graph"]["storage_effects"] == 5
                graphs[parallel].append(report)

        def load_query(_):
            try:
                report = run()
            except RuntimeError as failure:
                message = str(failure)
                for needle, category in (("no authenticated route", "peer_unavailable"),
                                         ("deadline", "deadline"),
                                         ("timed out", "deadline"),
                                         ("Connection reset", "connection_closed"),
                                         ("failed to fill whole buffer", "connection_closed")):
                    if needle in message:
                        return None, category
                raise
            assert report["value"] == expected
            return report["elapsed_us"], None

        load = []
        for clients in load_clients:
            queries = max(samples, clients * 3)
            started = time.perf_counter()
            with ThreadPoolExecutor(clients) as pool:
                results = list(pool.map(load_query, range(queries)))
            seconds = time.perf_counter() - started
            succeeded = [elapsed for elapsed, _ in results if elapsed is not None]
            failures = Counter(failure for _, failure in results if failure is not None)
            assert run()["value"] == expected
            load.append({
                "clients": clients, "requests": queries, "failures": dict(failures),
                "successful_queries_per_second": round(len(succeeded) / seconds, 1),
                "successful_p95_us": percentile(succeeded, .95) if succeeded else None,
            })

    def timing(values):
        return {"median_us": round(statistics.median(values)), "p95_us": round(percentile(values, .95))}

    def traffic(report):
        return (report["request_bytes"] + report["response_bytes"]
                + report["graph"]["remote_request_bytes"] + report["graph"]["remote_response_bytes"])

    metrics = ("storage_us", "worker_busy_us", "worker_elapsed_us", "worker_startup_us")
    def pp2_timing(reports):
        return {**timing([r["elapsed_us"] for r in reports]),
                "median_application_bytes": statistics.median(map(traffic, reports)),
                **{f"median_{key}": round(statistics.median(r["graph"][key] for r in reports))
                   for key in metrics}}

    summary = {
        "result": expected, "storage_database_bytes": sizes, "samples": samples,
        "sqlite_in_process": timing(native_times),
        "first_pp2_application_bytes": traffic(first), "first_pp2_elapsed_us": first["elapsed_us"],
        "delegated_pp2_elapsed_us": nested["elapsed_us"],
    }
    for parallel, name in ((False, "serial"), (True, "parallel")):
        summary[f"conventional_mtls_{name}"] = {
            **timing(tls_times[parallel]),
            "median_application_bytes": statistics.median(tls_traffic[parallel]),
        }
        summary[f"pp2_{name}"] = pp2_timing(graphs[parallel])
    if load:
        summary["pp2_load_including_cli_startup"] = load
    if trace_dir is not None:
        events = []
        for path in traces.values():
            for line in Path(path.name).read_text().splitlines():
                if line.startswith("{"):
                    events.append(json.loads(line))
        exchanges = [event for event in events if event["event"] == "graph_exchange"]
        executions = [event for event in events if event["event"] == "graph_execution"]
        executed = {event["invocation"] for event in executions}
        assert {event["invocation"] for event in exchanges} == executed
        assert all(event["parent"] is None or event["parent"] in executed for event in exchanges)
        assert all(event["failure"] is None for event in events)
        summary["trace_median_us_per_exchange"] = {
            **{key: round(statistics.median(event["connection"][key] for event in exchanges))
               for key in ("dial_us", "authentication_us")},
            "postcard_us": round(statistics.median(event["postcard_us"] for event in exchanges)),
        }
        summary["trace_median_us_per_execution"] = {
            **{key: round(statistics.median(event["trace"]["worker"][key] for event in executions))
               for key in ("spawn_us", "module_us", "guest_us", "codec_us")},
            **{key: round(statistics.median(event["trace"][key] for event in executions))
               for key in ("storage_open_us", "storage_effect_us", "storage_finish_us")},
        }
    print(json.dumps(summary, indent=2))


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--baseline-peer":
        _, _, role, work, workspace, addresses = sys.argv
        return baseline_peer(role, Path(work), Path(workspace), json.loads(addresses))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated-networks", action="store_true")
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--samples", type=int, default=40)
    parser.add_argument("--rows", type=int, default=20000, help="unmatched rows per warehouse")
    parser.add_argument("--binary", type=Path, default=ROOT / "target" / "release" / "pp2")
    parser.add_argument("--trace-dir", type=Path, help="write per-peer JSON timing traces to a new directory")
    parser.add_argument("--load-clients", type=int, action="append", default=[],
                        help="run a pp2 load check with this many concurrent clients; repeat for more levels")
    args = parser.parse_args()
    if args.samples < 1 or args.rows < 10000:
        parser.error("expected at least one sample and 10000 unmatched rows")
    if any(not 1 <= clients <= 32 for clients in args.load_clients):
        parser.error("--load-clients must be between 1 and 32")
    if args.trace_dir is not None and args.load_clients:
        parser.error("collect traces and measure concurrent client load in separate runs")
    if args.isolated_networks and not args.inside_netns:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, __file__,
                              *sys.argv[1:], "--inside-netns"])
    with tempfile.TemporaryDirectory(prefix="pp2-graph-") as temp, topology(ROLES, args.isolated_networks) as nodes:
        measure(Path(temp), nodes, args.binary.resolve(), args.rows, args.samples, args.trace_dir,
                args.load_clients)


if __name__ == "__main__":
    main()
