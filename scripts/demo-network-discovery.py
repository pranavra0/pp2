#!/usr/bin/env python3
"""Exercise discovery on three isolated, independently addressed Linux networks."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
import time


ROOT = Path(__file__).resolve().parents[1]
ROLES = ("office", "east", "west")
SET_BUDGET = json.dumps({"timeout_ms": 2500, "calls": 0, "depth": 0})


def command(*args):
    return subprocess.check_output(args, text=True, timeout=20).strip()


def json_file(path, value):
    path.write_text(json.dumps(value))
    return path


def hash_array(value):
    return list(bytes.fromhex(value))


def wait_for(read, check, seconds=15):
    until = time.monotonic() + seconds
    while True:
        value = read()
        if check(value):
            return value
        if time.monotonic() >= until:
            raise RuntimeError(f"timed out, last value was {value}")
        time.sleep(0.10)


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


class Networks:
    def __init__(self, stack):
        self.prefix = {}
        for i, role in enumerate(ROLES, 1):
            command("ip", "link", "add", f"br-{role}", "type", "bridge")
            command("ip", "addr", "add", f"10.94.{i}.1/24", "dev", f"br-{role}")
            command("ip", "link", "set", f"br-{role}", "up")
            namespace = subprocess.Popen(
                ["unshare", "-n", "sh", "-c", "echo ready; exec sleep infinity"],
                stdout=subprocess.PIPE, text=True,
            )
            stack.callback(stop, namespace)
            assert namespace.stdout.readline().strip() == "ready"
            prefix = ("nsenter", "--target", str(namespace.pid), "--net", "--")
            self.prefix[role] = prefix
            command("ip", "link", "add", f"veth-{role}", "type", "veth", "peer", "name", "uplink")
            command("ip", "link", "set", "uplink", "netns", str(namespace.pid))
            command("ip", "link", "set", f"veth-{role}", "master", f"br-{role}")
            command("ip", "link", "set", f"veth-{role}", "up")
            command(*prefix, "ip", "link", "set", "lo", "up")
            self.attach(role, f"10.94.{i}.2", f"10.94.{i}.1")
        command("ip", "link", "set", "lo", "up")
        command("ip", "addr", "add", "10.94.0.1/32", "dev", "lo")

    def attach(self, role, address, gateway):
        prefix = self.prefix[role]
        command(*prefix, "ip", "address", "flush", "dev", "uplink")
        command(*prefix, "ip", "address", "add", f"{address}/24", "dev", "uplink")
        command(*prefix, "ip", "link", "set", "uplink", "up")
        command(*prefix, "ip", "route", "replace", "default", "via", gateway)

    def disconnect_west(self):
        command(*self.prefix["west"], "ip", "link", "set", "uplink", "down")

    def move_west(self):
        command("ip", "link", "set", "veth-west", "master", "br-office")
        self.attach("west", "10.94.1.3", "10.94.1.1")


def prepare(binary, work, rendezvous):
    def pp2(*args):
        return command(binary, *args)

    example = ROOT / "examples" / "federated-stock"
    manifest = json.loads((example / "app.json").read_text())
    for details in manifest["modules"].values():
        details["source"] = str(example / details["source"])
    for details in manifest["peers"].values():
        details["collections"] = {name: str(example / source)
                                  for name, source in details["collections"].items()}
    for name, code in {
        "set-minimum": "export default async ({storage}, n) => (await storage.put('minimum/lamp', n), n);",
        "watch-west": """
            export default async ({capabilities, evaluate}) => {
                return (await evaluate(capabilities.west, {sku: 'lamp'}, {calls: 0})).value;
            };
        """,
    }.items():
        source = work / f"{name}.mjs"
        source.write_text(code)
        manifest["modules"][name] = {"source": str(source)}
    manifest_file = json_file(work / "deployment.json", manifest)
    deployment = work / "app"
    pp2("app", "init", manifest_file, deployment, "--discovery")
    node = {role: deployment / role for role in (*ROLES, "client")}
    ids = {role: pp2("peer", "identity", directory / "identity.key")
           for role, directory in node.items()}
    for role, directory in node.items():
        config = {"rendezvous": rendezvous, "relay": role != "client"}
        json_file(directory / "discovery.json", config)

    def pack(name, source, *imports):
        module = work / f"{name}.ppj"
        address = pp2("peer", "pack", source, module, *imports)
        return address, module

    set_program, _ = pack("set-minimum", work / "set-minimum.mjs")
    watch_program, _ = pack("watch-west", work / "watch-west.mjs")
    office_db = node["office"] / "peer.db"
    writer = pp2("peer", "issue", office_db, "settings", ids["client"], "writer", set_program)
    watch = pp2("peer", "issue", office_db, "settings", ids["office"], "reader", watch_program)
    profile = json.loads((node["office"] / "profile.json").read_text())
    route = profile["routes"]["west"]
    install = json_file(work / "subscription.json", {
        "name": "watch-stock", "subscriptions": {"west": {
            "program": hash_array(watch_program), "watch_grant": hash_array(watch),
            "budget": {"timeout_ms": 3000, "calls": 1, "depth": 1},
            "expires_at_ms": time.time_ns() // 1_000_000 + 180_000,
            "capabilities": {"west": {**route, "peer": hash_array(ids["west"])}},
        }},
    })
    pp2("app", "install", office_db, ids["office"], install)

    helper = work / "helper.mjs"
    helper.write_text("export const message = 'content from the original publisher';")
    dependency, dependency_block = pack("helper", helper)
    original = work / "original.mjs"
    original.write_text(f"import {{message}} from 'pp2:{dependency}'; export default () => message;")
    program, block = pack("original", original, dependency)
    pp2("peer", "put", node["east"] / "peer.db", dependency_block, "--publish")
    pp2("peer", "put", node["east"] / "peer.db", block, "--publish")
    content_reader = pp2("peer", "issue", office_db, "settings", ids["client"], "reader", program)
    private = work / "private.mjs"
    private.write_text("export default () => 'unpublished';")
    private_hash, private_block = pack("private", private)
    pp2("peer", "put", node["west"] / "peer.db", private_block)
    intruder = work / "intruder"
    intruder.mkdir()
    pp2("peer", "identity-new", intruder / "identity.key")
    json_file(intruder / "discovery.json", {"rendezvous": rendezvous})
    pinned = work / "pinned"
    pinned.mkdir()
    pp2("peer", "identity-new", pinned / "identity.key")
    json_file(pinned / "discovery.json", {"lan": False})
    return node, ids, writer, set_program, program, dependency, content_reader, private_hash, intruder, pinned


def require_failure(args, expected):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15)
    if result.returncode == 0 or expected not in result.stderr:
        raise RuntimeError(f"expected {expected!r}, got {result.stdout!r} / {result.stderr!r}")


def forged_lease(rendezvous, east, claimed, substitute):
    """Mutate a currently signed location and verify the directory rejects it."""
    address, port = rendezvous.rsplit(":", 1)

    def request(payload):
        with socket.create_connection((address, int(port)), timeout=2) as wire:
            wire.sendall(b"PPR1" + struct.pack(">H", len(payload)) + payload)
            with wire.makefile("rb") as stream:
                header = stream.read(6)
                if not header:
                    return None
                assert header[:4] == b"PPR1"
                return stream.read(struct.unpack(">H", header[4:])[0])

    query = b"\x01\x01" + bytes.fromhex(east)
    response = wait_for(lambda: request(query), lambda reply: reply and reply[:2] == b"\0\x01")
    record = response[2:]
    old, new = socket.inet_aton(claimed), socket.inet_aton(substitute)
    assert old in record
    assert request(b"\0" + record.replace(old, new, 1)) is None
    print("Rendezvous rejected an endpoint change with a forged signature.", flush=True)


def exercise(binary, work, lab, run, launch, rendezvous, forged, wrong_address):
    (node, ids, writer, set_program, program, dependency, content_reader, private_hash,
     intruder, pinned) = prepare(binary, work, rendezvous)

    rv = launch(None, "peer", "rendezvous", rendezvous, "--relay")
    daemons = {role: launch(role, "app", "serve", node[role], "0.0.0.0:7340")
               for role in ROLES}

    def invoke():
        return json.loads(run("office", "app", "invoke", node["client"], '{"sku":"lamp","viaWest":true}'))

    def delivery():
        status = run("office", "app", "status", node["office"] / "peer.db", "watch-stock")
        return json.loads(status)["subscriptions"]["west"]

    def change_minimum(revision, minimum):
        value = json_file(work / "minimum.json", minimum)
        report = run("office", "peer", "connect", node["client"], ids["office"], "graph-update",
                     "-", writer, set_program, value, SET_BUDGET, str(revision), secrets.token_hex(32))
        assert json.loads(report)["revision"] == revision + 1

    def completed(state, revision):
        outcome = state["last_delivery"] or {}
        return outcome.get("revision") == revision and outcome.get("outcome") == "completed"

    run("west", "peer", "find-program", node["west"], node["west"] / "peer.db", program, "--publish")
    assert invoke()["value"]["total"] == 10
    change_minimum(0, 11)
    wait_for(delivery, lambda state: completed(state, 1))
    print("Three independent networks completed a delegated query and an installed application delivery.", flush=True)

    forged(rendezvous, ids["east"])
    with (node["office"] / "profile.json").open() as file:
        route = json.load(file)["routes"]["west"]
    request = json_file(work / "request.json", {"sku": "lamp"})
    lab.fail("office", "no authenticated route",
             "peer", "connect", pinned, f"{ids['west']}@{wrong_address}", "graph-read",
             "-", bytes(route["grant"]).hex(), bytes(route["program"]).hex(), request, SET_BUDGET)
    lab.fail("office", "capability denied",
             "peer", "connect", intruder, ids["west"], "graph-read",
             "-", bytes(route["grant"]).hex(), bytes(route["program"]).hex(), request, SET_BUDGET)
    lab.fail("office", "content is unavailable",
             "peer", "connect", intruder, ids["west"], "fetch",
             work / "private.db", private_hash)
    print("An unexpected peer identity, a stolen grant, and a private-content fetch were all refused.", flush=True)

    lab.disconnect_west()
    change_minimum(1, 12)
    wait_for(delivery, lambda state: state["pending_revision"] == 2)
    lab.fail("office", "no authenticated route",
             "app", "invoke", node["client"], '{"sku":"lamp","viaWest":true}')
    lab.move_west()
    wait_for(delivery, lambda state: completed(state, 2))
    assert invoke()["value"]["total"] == 10
    print("West moved to a new network and address. The installed application resumed its pending delivery.", flush=True)

    lab.stop(daemons["east"])
    lab.stop(rv)
    recovered = run("office", "peer", "find-program", node["client"], work / "nearby.db", program)
    assert recovered.splitlines() == [program, dependency]
    report = run("office", "peer", "connect", node["client"], ids["office"], "graph-read",
                 "-", content_reader, program, request, SET_BUDGET)
    assert json.loads(report)["value"] == "content from the original publisher"
    print("A fresh cache and a cold execution retrieved verified code from nearby West with both services offline.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", type=Path, default=ROOT / "target/debug/pp2")
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.inside_netns:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, __file__,
                            "--inside-netns", "--bin", str(args.bin.resolve())])

    binary = args.bin.resolve()
    with TemporaryDirectory(prefix="pp2-discovery-") as temporary, ExitStack() as stack:
        work = Path(temporary)
        lab = Networks(stack)

        def run(role, *parts):
            return command(*lab.prefix.get(role, ()), binary, *parts)

        def launch(role, *parts):
            process = subprocess.Popen([*lab.prefix.get(role, ()), binary, *parts],
                                       stdout=subprocess.PIPE, text=True)
            stack.callback(stop, process)
            if not process.stdout.readline():
                raise RuntimeError(f"{role} did not start")
            return process

        lab.fail = lambda role, expected, *parts: require_failure(
            (*lab.prefix[role], binary, *parts), expected)
        lab.stop = stop
        exercise(binary, work, lab, run, launch, "10.94.0.1:7341",
                 lambda rendezvous, east: forged_lease(rendezvous, east, "10.94.2.2", "10.94.1.2"),
                 "10.94.1.2:7340")


if __name__ == "__main__":
    main()
