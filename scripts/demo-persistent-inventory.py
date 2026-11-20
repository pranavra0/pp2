#!/usr/bin/env python3

import argparse
import json
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time


from peer_topology import serving


def serve(binary, directory):
    return serving([binary, "app", "serve", directory], crash=True)

def until(read, ready):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = read()
        if ready(value):
            return value
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for inventory delivery, last state: {value}")


def run(binary, workspace, example):
    def command(*args):
        return subprocess.check_output([binary, *args], text=True).strip()

    def json_file(name, value):
        path = workspace / name
        path.write_text(json.dumps(value))
        return path

    def hash_bytes(value):
        return list(bytes.fromhex(value))

    roles = ("warehouse", "office")
    with socket.socket() as warehouse_socket, socket.socket() as office_socket:
        addresses = {}
        for role, listener in zip(roles, (warehouse_socket, office_socket)):
            listener.bind(("127.0.0.1", 0))
            addresses[role] = f"127.0.0.1:{listener.getsockname()[1]}"

    programs = ("set-stock", "publish-stock", "read-movement", "read-office", "write-office")
    leaf = dict(timeout_ms=2000, calls=0, depth=0)
    collections = {"warehouse": "stock", "office": "inventory"}
    manifest = json_file("bootstrap.json", {
        "root": {"peer": "warehouse", "collection": "stock", "module": "set-stock",
                 "capabilities": {}},
        "budget": leaf,
        "modules": {name: {"source": str(example / f"{name}.mjs")} for name in programs},
        "peers": {role: {"address": addresses[role], "collections": {collections[role]: None}}
                  for role in roles},
    })
    deployment = workspace / "peers"
    command("app", "init", manifest, deployment)
    warehouse, office, actor = (deployment / name for name in (*roles, "client"))
    warehouse_db, office_db = (peer / "peer.db" for peer in (warehouse, office))

    hashes = {}
    for name in programs:
        block = workspace / f"{name}.ppj"
        hashes[name] = command("peer", "pack", example / f"{name}.mjs", block)
        if name.endswith("office"):
            command("peer", "put", office_db, block, "--publish")

    def issue(db, reference, recipient, access, name):
        return command("peer", "issue", db, reference, recipient / "peer.pem", access, hashes[name])

    stock_writer = issue(warehouse_db, "stock", actor, "writer", "set-stock")
    watch = issue(warehouse_db, "stock", warehouse, "reader", "publish-stock")
    entry = command("peer", "issue-compute", warehouse_db, warehouse / "peer.pem", hashes["publish-stock"])
    movement = issue(warehouse_db, "stock", warehouse, "reader", "read-movement")
    warehouse_identity = hash_bytes(command("peer", "fingerprint", warehouse / "peer.pem"))
    office_observer = issue(office_db, "inventory", office, "reader", "read-office")
    office_reader = issue(office_db, "inventory", actor, "reader", "read-office")
    warehouse_reader = issue(office_db, "inventory", warehouse, "reader", "read-office")
    warehouse_writer = command(
        "peer", "issue-reaction-writer", office_db, "inventory", warehouse / "peer.pem",
        hashes["write-office"],
    )
    office_identity = hash_bytes(command("peer", "fingerprint", office / "peer.pem"))
    expires = time.time_ns() // 1_000_000 + 300_000

    def install(peer, app, sub, program, grant, budget, capabilities, entry=None):
        spec = json_file(f"{app}.json", {
            "name": app, "subscriptions": {sub: {
                "program": hash_bytes(hashes[program]), "watch_grant": hash_bytes(grant),
                "budget": budget, "capabilities": capabilities, "expires_at_ms": expires,
                "entry_grant": hash_bytes(entry) if entry else None,
            }},
        })
        command("app", "install", peer / "peer.db", peer / "peer.pem", spec)

    install(warehouse, "inventory", "project-stock", "publish-stock", watch,
            dict(timeout_ms=3000, calls=7, depth=1), {
                "movement": {"peer": warehouse_identity, "grant": hash_bytes(movement),
                             "program": hash_bytes(hashes["read-movement"]), "access": "Read"},
                "readOffice": {"peer": office_identity, "grant": hash_bytes(warehouse_reader),
                               "program": hash_bytes(hashes["read-office"]), "access": "Read"},
                "writeOffice": {"peer": office_identity, "grant": hash_bytes(warehouse_writer),
                                "program": hash_bytes(hashes["write-office"]), "access": "Write"},
            }, entry)
    install(office, "office-observer", "observe", "read-office", office_observer, leaf, {})
    command("peer", "unpublish", warehouse_db, hashes["publish-stock"])
    command("peer", "gc", warehouse_db)

    def connection(role):
        return ("-", addresses[role], f"pp2-{role}", actor / "ca.pem",
                actor / "peer.pem", actor / "peer.key")

    def change_stock(quantity, revision, operation):
        event = json_file("stock.json", {"sku": "lamp", "quantity": quantity})
        return json.loads(command(
            "peer", "graph-update", *connection("warehouse"), stock_writer, hashes["set-stock"],
            event, json.dumps(leaf), str(revision), operation,
        ))

    def delivery():
        app = json.loads(command("app", "status", warehouse_db, "inventory"))
        return app["subscriptions"]["project-stock"]

    operation = secrets.token_hex(32)
    with serve(binary, warehouse):
        assert change_stock(8, 0, operation)["revision"] == 1
        assert change_stock(8, 0, operation)["revision"] == 1
        with sqlite3.connect(warehouse_db) as database:
            # Wait until the outbound intent is durable while the office remains offline.
            until(lambda: database.execute("SELECT count(*) FROM job_effects").fetchone()[0], bool)
        print("Warehouse committed stock revision 1 while the office was offline.", flush=True)

    with serve(binary, warehouse), serve(binary, office):
        projected = until(delivery, lambda s: s["last_delivery"] is not None)
        last = projected["last_delivery"]
        assert last["outcome"] == "completed" and last["revision"] == 1, projected
        sku = json_file("sku.json", "lamp")

        def office_stock():
            return json.loads(command(
                "peer", "graph-read", *connection("office"), office_reader, hashes["read-office"],
                sku, json.dumps(leaf),
            ))

        office_result = office_stock()
        assert office_result["revision"] == 1
        assert office_result["value"] == {"quantity": 8, "revision": "1", "event": last["event_id"]}
        observer = until(
            lambda: json.loads(command("app", "status", office_db, "office-observer"))["subscriptions"]["observe"],
            lambda s: s["cursor"] == 1,
        )
        assert observer["last_delivery"] is None
        print(f"After restart the office projected 8 lamps from event {last['event_id']}.")

        command("peer", "revoke", office_db, warehouse_writer)
        change_stock(9, 1, secrets.token_hex(32))
        denied = until(delivery, lambda s: s["cursor"] == 2)["last_delivery"]
        assert denied["outcome"] == "failed" and "denied" in denied["error"], denied
        removal = json.loads(command("app", "remove", warehouse_db, "inventory"))
        assert removal["state"] == "removing" and removal["drain_until_ms"] is not None
        change_stock(10, 2, secrets.token_hex(32))
        assert delivery()["state"] == "revoked" and delivery()["cursor"] == 2
        assert office_stock()["revision"] == 1
        print("The office revoked its writer grant, then warehouse removal stopped new deliveries.")


def main():
    parser = argparse.ArgumentParser(description="Run persistent inventory on two independent peers.")
    parser.add_argument("binary", nargs="?", type=Path, default=Path("target/release/pp2"))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="pp2-inventory-") as workspace:
        run(args.binary.resolve(), Path(workspace), repo / "examples" / "persistent-inventory")


if __name__ == "__main__":
    main()
