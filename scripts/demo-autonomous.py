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
    return serving([binary, "app", "serve", directory])

def run(binary, workspace, example):
    def command(*args):
        return subprocess.check_output([binary, "peer", *args], text=True).strip()

    roles = ("a", "b", "c")
    sockets = [socket.socket() for _ in roles]
    for listener in sockets:
        listener.bind(("127.0.0.1", 0))
    addresses = {
        role: f"127.0.0.1:{listener.getsockname()[1]}"
        for role, listener in zip(roles, sockets)
    }
    budget = dict(timeout_ms=3000, calls=1, depth=1)
    manifest = {
        "root": {"peer": "b", "module": "local", "capabilities": {}},
        "budget": budget,
        "modules": {
            name: {"source": str(example / f"{name}.mjs")} for name in ("local", "remote")
        },
        "peers": {role: {"address": addresses[role]} for role in roles},
    }
    seed = workspace / "c.ndjson"
    seed.write_text(json.dumps(["stock", 7]) + "\n")
    manifest["peers"]["c"]["collections"] = {"remote": str(seed)}
    manifest_file = workspace / "app.json"
    manifest_file.write_text(json.dumps(manifest))
    deployment = workspace / "deployment"
    subprocess.run([binary, "app", "init", manifest_file, deployment], check=True, stdout=subprocess.DEVNULL)
    for listener in sockets:
        listener.close()

    a, b, c = (deployment / role for role in roles)
    cert_a, cert_b = a / "peer.pem", b / "peer.pem"
    local = command("pack", example / "local.mjs", workspace / "local.ppj")
    remote = command("pack", example / "remote.mjs", workspace / "remote.ppj")
    command("put", c / "peer.db", workspace / "remote.ppj", "--publish")
    grant_b = command("issue-compute", b / "peer.db", cert_a, local)
    grant_c = command("issue", c / "peer.db", "remote", cert_a, "reader", remote)

    def connection(role):
        return addresses[role], f"pp2-{role}", a / "ca.pem", cert_a, a / "peer.key"

    expires = str(time.time_ns() // 1_000_000 + 30_000)
    leaf = json.dumps(dict(timeout_ms=3000, calls=0, depth=0))
    with serve(binary, c):
        grant = command("attenuate", *connection("c"), grant_c, cert_b, "reader", remote, leaf, expires)

    bindings = workspace / "bindings.json"
    bindings.write_text(json.dumps({
        "remote": {
            "peer": list(bytes.fromhex(command("fingerprint", c / "peer.pem"))),
            "grant": list(bytes.fromhex(grant)),
            "program": list(bytes.fromhex(remote)),
            "access": "Read",
        }
    }))
    input_file = workspace / "input.json"
    input_file.write_text(json.dumps({"key": "stock", "local": 6}))
    job = secrets.token_hex(32)
    with serve(binary, b):
        with serve(binary, a):
            accepted = command(
                "job-submit", "-", *connection("b"), grant_b, local, input_file,
                json.dumps(budget), job, expires, "--delegated", bindings,
            )
            print(f"A received {accepted} for {job} and disconnected.", flush=True)

        with serve(binary, c), sqlite3.connect(b / "peer.db") as database:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                # Observe completion on B without opening a second connection from A.
                state = database.execute(
                    "SELECT state FROM jobs WHERE id=?", (bytes.fromhex(job),)
                ).fetchone()
                if state == (2,):
                    result = json.loads(command("job-status", *connection("b"), job))
                    assert result["state"] == "completed" and result["value"] == 13, result
                    print(f"A reconnected and retrieved {json.dumps(result)}")
                    return
                time.sleep(0.1)
            raise RuntimeError("B did not complete the job")


def main():
    parser = argparse.ArgumentParser(description="Run a durable pp2 computation across three peers.")
    parser.add_argument("binary", nargs="?", type=Path, default=Path("target/release/pp2"))
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="pp2-autonomous-") as workspace:
        run(args.binary.resolve(), Path(workspace), repo / "examples" / "autonomous")


if __name__ == "__main__":
    main()
