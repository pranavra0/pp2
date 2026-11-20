#!/usr/bin/env python3
"""Run Personal Notes on three independent pp2 peers using loopback routes."""

import argparse
import contextlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]


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
    def __init__(self, pp2, home, endpoint):
        self.pp2, self.home, self.endpoint = pp2, home, endpoint
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
            [str(self.pp2), *(str(arg) for arg in args)],
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

    def replica(self, command, *args):
        return self.call("peer", "replica", command, self.home, *args)

    def status(self, resource):
        return json.loads(self.replica("status", resource))

    def start(self):
        self.process = subprocess.Popen(
            [self.pp2, "app", "native", "host", self.home, self.endpoint],
            stdout=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        if line != f"listening on {self.endpoint}":
            raise RuntimeError(f"{self.home.name} did not start")

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process.stdout.close()
            self.process = None

    def notes(self, command):
        return self.native("run", self.home, self.app, command)


def demonstrate(pp2, home, cleanup):
    endpoints = set()
    while len(endpoints) < 3:
        endpoints.add(address())
    devices = [Device(pp2, home / name, endpoint)
               for name, endpoint in zip(("desktop", "laptop", "travel"), sorted(endpoints))]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pp2", type=Path, default=ROOT / "target/debug/pp2")
    args = parser.parse_args()
    with contextlib.ExitStack() as cleanup:
        home = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="pp2-notes-")))
        demonstrate(args.pp2.resolve(), home, cleanup)


if __name__ == "__main__":
    main()
