#!/usr/bin/env python3
"""Run the three-peer stock application and compare it with SQLite and mTLS/JSON."""
import argparse
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

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("office", "west", "east")


def command(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=25)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited with status {result.returncode}\n{result.stderr.strip()}")
    return result.stdout.strip()


@contextmanager
def process(*args):
    with subprocess.Popen(args, text=True, stdout=subprocess.PIPE) as child:
        try:
            ready = child.stdout.readline().strip()
            if not ready:
                raise RuntimeError(f"{args[0]} failed to start ({child.poll()})")
            yield child, ready
        finally:
            child.kill()
            child.wait()


@contextmanager
def topology(isolated):
    if not isolated:
        yield {role: ("127.0.0.1", ()) for role in ROLES}
        return
    command("ip", "link", "set", "lo", "up")
    with ExitStack() as stack:
        nodes = {"office": ("10.92.0.1", ())}
        for i, role in enumerate(("west", "east")):
            child, _ = stack.enter_context(process("unshare", "-n", "sh", "-c",
                                                   "echo ready; exec sleep infinity"))
            prefix = ("nsenter", "--target", str(child.pid), "--net", "--")
            host, peer = f"10.92.0.{4*i+1}", f"10.92.0.{4*i+2}"
            dev = f"pp2-{role}"
            command("ip", "link", "add", dev, "type", "veth", "peer", "name", "uplink")
            command("ip", "link", "set", "uplink", "netns", str(child.pid))
            command("ip", "address", "add", f"{host}/30", "dev", dev)
            command("ip", "link", "set", dev, "up")
            command(*prefix, "ip", "link", "set", "lo", "up")
            command(*prefix, "ip", "address", "add", f"{peer}/30", "dev", "uplink")
            command(*prefix, "ip", "link", "set", "uplink", "up")
            nodes[role] = (peer, prefix)
        yield nodes


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


def fetch(context, role, endpoint, sku):
    with socket.create_connection(address(endpoint), timeout=3) as tcp:
        tcp.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with context.wrap_socket(tcp, server_hostname=f"pp2-{role}") as conn:
            request = frame({"sku": sku})
            conn.sendall(request)
            reply, received = receive(conn)
    return reply, len(request), received


def baseline_peer(role, work, workspace, endpoints):
    outbound = tls(workspace / role, server=False)
    inbound = tls(workspace / role, server=True)
    holder = "client" if role == "office" else "office"
    certificate = (workspace / holder / "peer.pem").read_text()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).digest()
    with socket.create_server(address(endpoints[role])) as listener:
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
                    for leaf in ("west", "east"):
                        counts[leaf], request, response = fetch(outbound, leaf, endpoints[leaf], sku)
                        sent += request
                        received += response
                    conn.sendall(frame({
                        "value": combine(quantity, counts),
                        "remote_request_bytes": sent, "remote_response_bytes": received,
                    }))


def percentile(samples, fraction):
    return sorted(samples)[max(0, math.ceil(len(samples) * fraction) - 1)]


def measure(work, nodes, binary, rows, samples):
    pp2_addresses = endpoints(nodes, 18630)
    baseline_addresses = endpoints(nodes, 18631)
    manifest = prepare(work, rows, pp2_addresses)
    workspace = work / "deployment"
    command(binary, "app", "init", manifest, workspace)
    sizes = {role: (workspace / role / "peer.db").stat().st_size for role in ("west", "east")}
    assert all(size > 256 * 1024 for size in sizes.values())
    expected = combine(lookup(work / "office.sqlite", "office", "lamp"), {
        role: lookup(work / f"{role}.sqlite", role, "lamp") for role in ("west", "east")
    })

    def run(via_west=False):
        input = json.dumps({"sku": "lamp", "viaWest": via_west})
        return json.loads(command(binary, "app", "invoke", workspace / "client", input))

    with ExitStack() as stack:
        for role, (_, prefix) in nodes.items():
            stack.enter_context(process(*prefix, binary, "app", "serve", workspace / role))
            stack.enter_context(process(*prefix, sys.executable, __file__,
                                        "--baseline-peer", role, work, workspace,
                                        json.dumps(baseline_addresses)))
        cold = run()
        nested = run(via_west=True)
        assert cold["value"] == nested["value"] == expected
        assert cold["graph"]["remote_calls"] == nested["graph"]["remote_calls"] == 2
        assert cold["graph"]["storage_effects"] == nested["graph"]["storage_effects"] == 5
        context = tls(workspace / "client", server=False)

        native_times = []
        tls_times = []
        pp2_times = []
        graphs = []
        tls_traffic = []
        for _ in range(samples):
            started = time.perf_counter_ns()
            quantities = {
                role: lookup(work / f"{role}.sqlite", role, "lamp") for role in ("west", "east")
            }
            result = combine(lookup(work / "office.sqlite", "office", "lamp"), quantities)
            native_times.append((time.perf_counter_ns() - started) / 1000)
            assert result == expected

            started = time.perf_counter_ns()
            conventional, sent, received = fetch(context, "office", baseline_addresses["office"], "lamp")
            tls_times.append((time.perf_counter_ns() - started) / 1000)
            assert conventional["value"] == expected
            tls_traffic.append(sent + received + conventional["remote_request_bytes"]
                               + conventional["remote_response_bytes"])

            report = run()
            assert report["value"] == expected
            pp2_times.append(report["elapsed_us"])
            graphs.append(report)

    def timing(values):
        return {"median_us": round(statistics.median(values)), "p95_us": round(percentile(values, .95))}

    def traffic(report):
        return (report["request_bytes"] + report["response_bytes"]
                + report["graph"]["remote_request_bytes"] + report["graph"]["remote_response_bytes"])

    metrics = ("storage_us", "worker_busy_us", "worker_elapsed_us", "worker_startup_us")
    print(json.dumps({
        "result": expected, "storage_database_bytes": sizes, "samples": samples,
        "sqlite_in_process": timing(native_times),
        "conventional_mtls": {**timing(tls_times), "median_application_bytes": statistics.median(tls_traffic)},
        "pp2": {**timing(pp2_times), "median_application_bytes": statistics.median(map(traffic, graphs)),
                "cold_application_bytes": traffic(cold), "cold_elapsed_us": cold["elapsed_us"],
                "delegated_elapsed_us": nested["elapsed_us"],
                **{f"median_{key}": round(statistics.median(r["graph"][key] for r in graphs))
                   for key in metrics}},
    }, indent=2))


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
    args = parser.parse_args()
    if args.samples < 1 or args.rows < 10000:
        parser.error("expected at least one sample and 10000 unmatched rows")
    if args.isolated_networks and not args.inside_netns:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, __file__,
                              *sys.argv[1:], "--inside-netns"])
    with tempfile.TemporaryDirectory(prefix="pp2-graph-") as temp, topology(args.isolated_networks) as nodes:
        measure(Path(temp), nodes, args.binary.resolve(), args.rows, args.samples)


if __name__ == "__main__":
    main()
