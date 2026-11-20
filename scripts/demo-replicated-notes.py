#!/usr/bin/env python3
"""Run Personal Notes on three pp2 peers, with optional seeded network faults."""

import argparse
import contextlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from peer_topology import partition, topology


ROOT = Path(__file__).resolve().parents[1]
ROLES = ("desktop", "laptop", "travel")


def address():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{sock.getsockname()[1]}"


def until(predicate, timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result := predicate():
            return result
        time.sleep(0.2)
    raise RuntimeError("peers did not converge before the deadline")


class Device:
    def __init__(self, pp2, home, endpoint, prefix):
        self.pp2, self.home, self.endpoint = pp2, home, endpoint
        self.prefix = prefix
        self.identity = self.native("identity", home)
        self.db = home / "peer.db"
        self.app = None
        self.process = None
        (home / "discovery.json").write_text('{"lan":false}')

    @property
    def target(self):
        return f"{self.identity}@{self.endpoint}"

    def call(self, *args, check=True):
        result = subprocess.run(
            [*self.prefix, str(self.pp2), *(str(arg) for arg in args)],
            text=True,
            capture_output=True,
            timeout=30,
        )
        if not check:
            return result
        if result.returncode:
            raise RuntimeError(f"{args}: {result.stderr.strip()}")
        return result.stdout.strip()

    def native(self, *args):
        return self.call("app", "native", *args)

    def replica(self, command, *args, check=True):
        return self.call("peer", "replica", command, self.home, *args, check=check)

    def status(self, resource):
        return json.loads(self.replica("status", resource))

    def connect(self, target, command, *args, check=True):
        return self.call("peer", "connect", self.home, target, command, *args, check=check)

    def start(self):
        self.process = subprocess.Popen(
            [*self.prefix, self.pp2, "app", "native", "host", self.home, self.endpoint],
            stdout=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        if line != f"listening on {self.endpoint}":
            raise RuntimeError(f"{self.home.name} did not start")

    def stop(self, crash=False):
        if self.process:
            if crash:
                self.process.kill()
            else:
                self.process.terminate()
            self.process.wait(timeout=5)
            self.process.stdout.close()
            self.process = None

    def notes(self, command):
        return self.native("run", self.home, self.app, command)


def exercise_faults(devices, resource, rounds, operations, seed):
    rng = random.Random(seed)
    model = {}
    acknowledged = 0
    recoveries = []
    started = time.monotonic()

    def converged(count):
        heads = [device.status(resource)["heads"] for device in devices]
        return len(heads[0]) == count and all(head == heads[0] for head in heads)

    def branch(device, commands):
        expected = dict(model)
        for title, value in commands:
            assert device.notes(f"set {title} {value}") == f"Saved {title}"
            expected[title] = value
        return expected

    for turn in range(rounds):
        observer, left, right = rng.sample(devices, 3)
        writers = (left, right)
        original = observer.status(resource)["heads"]
        assert converged(1)
        commands = []
        for writer in writers:
            items = [(f"fault-{writer.home.name}-{rng.randrange(3)}", f"value-{rng.randrange(1000000)}")
                     for _ in range(operations)]
            items.append(("fault-shared", f"conflict-{turn}-{writer.home.name}"))
            commands.append(items)
            partition(writer.home.name, True)
        try:
            unavailable = left.replica("sync", resource, observer.target, check=False)
            assert unavailable.returncode != 0, unavailable.stdout
            with ThreadPoolExecutor(2) as pool:
                results = [pool.submit(branch, writer, items) for writer, items in zip(writers, commands)]
                branches = [result.result() for result in results]
            acknowledged += sum(map(len, commands))
            assert observer.status(resource)["heads"] == original
            for writer, expected in zip(writers, branches):
                heads = writer.status(resource)["heads"]
                assert len(heads) == 1 and heads != original
                writer.stop(crash=True)
                writer.start()
                assert writer.status(resource)["heads"] == heads
                assert writer.notes("show fault-shared") == expected["fault-shared"]
        finally:
            recovered_at = time.monotonic()
            for writer in writers:
                partition(writer.home.name, False)
        until(lambda: converged(2))
        recoveries.append(round((time.monotonic() - recovered_at) * 1000))
        alternatives = {title: {entry[title] for entry in branches if title in entry}
                        for title in branches[0].keys() | branches[1].keys()}
        for title, texts in sorted(alternatives.items()):
            assert set(observer.notes(f"show {title}").splitlines()) == texts
        assert observer.notes("merge") == "Merged branches. Conflicting note texts are preserved."
        acknowledged += 1
        for title, texts in sorted(alternatives.items()):
            value = rng.choice(sorted(texts))
            if len(texts) > 1:
                assert set(observer.notes(f"show {title}").splitlines()) == texts
                assert observer.notes(f"resolve {title} {value}") == f"Resolved {title}"
                acknowledged += 1
            model[title] = value
        until(lambda: converged(1))
        expected = [f"{title}: {value}" for title, value in sorted(model.items())]
        for device in devices:
            assert device.notes("list").splitlines() == expected
    print(json.dumps({
        "seed": seed, "rounds": rounds, "acknowledged_updates": acknowledged,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "partition_recovery_ms": recoveries,
        "database_bytes": {device.home.name: device.db.stat().st_size for device in devices},
    }, sort_keys=True))


def exercise_compaction(owner, follower):
    follower.stop()
    source = owner.home / "compaction.mjs"
    module = owner.home / "compaction.ppj"
    value = owner.home / "compaction.json"
    source.write_text("export default (state, input) => input === null ? state.seq : {next: input, value: input.seq};")
    owner.call("peer", "pack", source, module)
    program = owner.call("peer", "put", owner.db, module, "--publish")
    value.write_text('{"seq":0}')
    owner.call("peer", "ref-init", owner.db, "journal", value)
    resource = owner.replica("share", "journal", "single-writer")
    owner.replica("approve", resource, follower.identity, "read", program)
    follower.replica("follow", resource, owner.target, "journal")
    old = owner.status(resource)["heads"][0]
    writer = owner.call("peer", "issue", owner.db, "journal", owner.identity, "writer", program)
    commits = 40
    for seq in range(1, commits + 1):
        value.write_text(json.dumps({"seq": seq, "payload": chr(64 + (seq % 26)) * 12000}))
        report = owner.connect(owner.target, "update", owner.db, writer, program, value,
                               seq - 1, f"{seq:064x}")
        assert json.loads(report)["value"] == seq
        if seq == commits - 1:
            pruned = json.loads(owner.replica("retain", resource, 4))
            assert pruned == {"pruned_snapshots": commits - 4}, pruned
    removed = owner.call("peer", "gc", owner.db)

    started = time.monotonic()
    partial = json.loads(follower.replica("sync", resource, owner.target, "--once"))
    assert partial["pending"] and partial["blocks"] == 32 and partial["revisions"] == 0, partial
    assert follower.status(resource)["heads"] == []
    owner.stop(crash=True)
    assert follower.replica("sync", resource, owner.target, "--once", check=False).returncode != 0
    follower.call("peer", "gc", follower.db)
    owner.start()
    resumed = json.loads(follower.replica("sync", resource, owner.target))
    assert not resumed["pending"] and resumed["revisions"] == commits + 1, resumed
    assert 0 < resumed["blocks"] < 32, resumed
    assert follower.status(resource)["heads"] == owner.status(resource)["heads"]
    assert json.loads(follower.replica("sync", resource, owner.target))["blocks"] == 0

    assert follower.call("peer", "put", follower.db, module, "--publish") == program
    follower.start()
    grant = follower.replica("grant", "journal", "reader", program)
    reader = bytes(json.loads(grant)["grant"]).hex()
    value.write_text("null")
    report = follower.connect(follower.target, "replica-read", follower.db, reader, program, value)
    assert json.loads(report)["value"] == commits
    missing = follower.connect(follower.target, "revision-read", follower.db, reader, program, value, old,
                               check=False)
    assert missing.returncode != 0 and "unavailable" in missing.stderr, missing.stderr
    print(json.dumps({
        "compaction_commits": commits, "collected": removed,
        "initial_pass": partial, "resumed": resumed,
        "catch_up_with_restart_ms": round((time.monotonic() - started) * 1000),
    }, sort_keys=True))


def demonstrate(pp2, home, cleanup, nodes, args):
    endpoints = [f"{host}:17340" for host, _ in nodes.values()]
    if not args.isolated_networks:
        addresses = set()
        while len(addresses) < 3:
            addresses.add(address())
        endpoints = sorted(addresses)
    devices = [Device(pp2, home / name, endpoint, nodes[name][1])
               for name, endpoint in zip(ROLES, endpoints)]
    desktop, laptop, travel = devices
    for device in devices:
        cleanup.callback(device.stop)

    package, store_program = subprocess.check_output(
        [ROOT / "examples/replicated-notes/package.sh", pp2, desktop.home],
        text=True,
    ).split()
    desktop.call("peer", "collection-init", desktop.db, "notes")
    resource = desktop.replica("share", "notes", "multi-writer")
    for device in (laptop, travel):
        desktop.replica("approve", resource, device.identity, "write", store_program)
        device.replica("follow", resource, desktop.target, "notes")
    desktop.start()
    for device in devices:
        if device is not desktop:
            device.replica("sync", resource, desktop.target)
        for other in devices:
            if other is not device:
                device.replica("route", resource, other.identity, other.endpoint)
        device.app = device.native("install", device.home, package, desktop.target, "--yes")
        grant = device.home / "notes-grant.json"
        grant.write_text(device.replica("grant", "notes", "writer", store_program))
        device.native("grant", device.home, device.app, "notes", grant)
    if args.fault_rounds:
        for device in (laptop, travel):
            device.start()
        exercise_faults(devices, resource, args.fault_rounds, args.operations_per_writer, args.seed)
        for device in (laptop, travel):
            device.stop()
    assert desktop.notes("set welcome original") == "Saved welcome"
    for device in (laptop, travel):
        device.replica("sync", resource, desktop.target)
        assert device.notes("show welcome") == "original"
    print("Installed Personal Notes on three independent workspaces.")

    # All daemons are stopped. The native app still executes its granted local leaf.
    desktop.stop()
    assert desktop.notes("set welcome desktop edit") == "Saved welcome"
    assert desktop.notes("set groceries apples") == "Saved groceries"
    assert laptop.notes("set welcome laptop edit") == "Saved welcome"
    assert laptop.notes("set travel train") == "Saved travel"
    assert desktop.notes("show welcome") == "desktop edit"
    assert laptop.notes("show welcome") == "laptop edit"
    assert travel.notes("show welcome") == "original"
    print("Desktop and laptop edited independently while all network daemons were stopped.")

    # Two replicas exchange changes using ordinary peer daemons. Travel remains absent.
    desktop.start()
    laptop.start()
    expected = {"desktop edit", "laptop edit"}
    until(lambda: desktop.status(resource)["heads"] == laptop.status(resource)["heads"]
          and len(desktop.status(resource)["heads"]) == 2)
    for device in (desktop, laptop):
        assert set(device.notes("show welcome").splitlines()) == expected
        assert device.notes("show groceries") == "apples"
        assert device.notes("show travel") == "train"
    print("Both peers expose the same two heads and both versions of the conflicting note.")

    assert laptop.notes("merge") == "Merged branches. Conflicting note texts are preserved."
    until(lambda: desktop.status(resource)["heads"] == laptop.status(resource)["heads"]
          and len(desktop.status(resource)["heads"]) == 1)
    assert set(desktop.notes("show welcome").splitlines()) == expected
    assert desktop.notes("set welcome ignored") == "This note has conflicting versions. Use resolve TITLE TEXT."
    assert desktop.notes("resolve welcome agreed text") == "Resolved welcome"
    until(lambda: laptop.notes("show welcome") == "agreed text")
    print("The app merged disjoint notes, retained both conflicting texts, then applied an explicit resolution.")

    # Stale state survives a process restart. Rejoining fetches missing history from a replica.
    desktop.stop()
    laptop.stop()
    for revision in range(1, 15):
        assert laptop.notes(f"set log entry-{revision}") == "Saved log"
    assert travel.notes("show log") == "No such note."
    laptop.start()
    assert laptop.notes("show welcome") == "agreed text"
    assert laptop.notes("show log") == "entry-14"
    catchup = json.loads(travel.replica("sync", resource, laptop.target))
    assert not catchup["pending"] and catchup["blocks"] > 32, catchup
    travel.start()
    assert travel.notes("show welcome") == "agreed text"
    assert travel.notes("show groceries") == "apples"
    assert travel.notes("show travel") == "train"
    assert travel.notes("show log") == "entry-14"
    no_changes = json.loads(travel.replica("sync", resource, laptop.target))
    assert no_changes == {"blocks": 0, "bytes": 0, "pending": False, "revisions": 0}, no_changes
    print(f"The third peer caught up in multiple passes from the laptop while the owner was offline "
          f"({catchup['blocks']} blocks). An unchanged sync transferred zero blocks.")

    head = travel.status(resource)["heads"][0]
    grant = bytes(json.loads((travel.home / "notes-grant.json").read_text())["grant"]).hex()
    request = travel.home / "list.json"
    request.write_text('{"command":"list"}')
    job = uuid.uuid4().hex + uuid.uuid4().hex

    def job_call(command, *args, check=True):
        return travel.call("peer", "connect", travel.home, travel.target, command,
                           *args, check=check)

    job_call("job-submit", travel.db, grant, store_program, request,
             '{"timeout_ms":4000,"calls":0,"depth":0}', job,
             int(time.time() * 1000) + 20000, "--revision", head)

    def completed_job():
        status = json.loads(job_call("job-status", job))
        if status["state"] in ("pending", "running"):
            return None
        assert status["state"] == "completed", status
        return status

    assert until(completed_job)["view"] == {
        "consistency": "revision", "resource": resource, "mode": "multi_writer",
        "revision": head, "heads": [head],
    }

    public_fetch = desktop.call("peer", "connect", desktop.home, travel.target,
                                "fetch", home / "empty-cache.db", head, check=False)
    assert public_fetch.returncode != 0 and "unavailable" in public_fetch.stderr, public_fetch.stderr
    travel.call("peer", "gc", travel.db)
    assert travel.notes("show welcome") == "agreed text"
    print("Public content fetch could not retrieve the revision. Garbage collection retained live history.")

    # The owner conveys a signed revocation. Previously copied contents grant no app authority.
    desktop.start()
    desktop.replica("revoke", resource, travel.identity)
    until(lambda: travel.status(resource)["revoked"])
    denied = travel.call("app", "native", "run", travel.home, travel.app, "show welcome", check=False)
    assert denied.returncode != 0 and "denied" in denied.stderr, denied.stderr
    denied = job_call("job-status", job, check=False)
    assert denied.returncode != 0 and "denied" in denied.stderr, denied.stderr
    print("The revoked peer stopped serving the notes app and its saved job result after observing the owner's policy.")
    for device in devices:
        device.native("remove", device.home, device.app)
        removed = device.call("app", "native", "run", device.home, device.app, "list", check=False)
        assert removed.returncode != 0
    if args.fault_rounds:
        exercise_compaction(desktop, laptop)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pp2", type=Path, default=ROOT / "target/debug/pp2")
    parser.add_argument("--isolated-networks", action="store_true")
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--fault-rounds", type=int, default=0)
    parser.add_argument("--operations-per-writer", type=int, default=20)
    parser.add_argument("--seed", type=int, default=761)
    args = parser.parse_args()
    if args.fault_rounds < 0 or args.operations_per_writer < 1:
        parser.error("expected nonnegative fault rounds and at least one operation per writer")
    if args.fault_rounds and not args.isolated_networks:
        parser.error("fault rounds require --isolated-networks")
    if args.isolated_networks and not args.inside_netns:
        os.execvp("unshare", ["unshare", "-Urn", sys.executable, __file__,
                              *sys.argv[1:], "--inside-netns"])
    with contextlib.ExitStack() as cleanup:
        home = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="pp2-notes-")))
        nodes = cleanup.enter_context(topology(ROLES, args.isolated_networks))
        demonstrate(args.pp2.resolve(), home, cleanup, nodes, args)


if __name__ == "__main__":
    main()
