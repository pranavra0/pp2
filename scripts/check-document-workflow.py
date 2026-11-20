#!/usr/bin/env python3
"""Exercise the public document workflow with independent owner and laptop workspaces."""

import argparse
import json
from contextlib import contextmanager
import os
import shutil
from pathlib import Path
import subprocess
import tempfile

from peer_topology import topology

ROOT = Path(__file__).resolve().parents[1]


class Peer:
    def __init__(self, binary, home, prefix):
        self.command = [*prefix, binary]
        self.env = dict(os.environ, PP2_HOME=str(home))
        self.env.pop("PP2_APP", None)

    def run(self, *args, approve=False, success=True):
        result = subprocess.run(
            [*self.command, *args], cwd=ROOT, env=self.env, capture_output=True,
            text=True, input="y\n" if approve else "", timeout=30,
        )
        if (result.returncode == 0) != success:
            raise AssertionError(f"{args}: exit {result.returncode}\n{result.stderr}")
        return result.stdout.strip() if success else result.stderr

    @contextmanager
    def host(self):
        with subprocess.Popen(
            [*self.command, "host", "0.0.0.0:7340"], env=self.env,
            stdout=subprocess.PIPE, text=True,
        ) as child:
            try:
                assert child.stdout.readline().startswith("listening on ")
                yield
            finally:
                child.terminate()


def check(binary, isolated):
    with tempfile.TemporaryDirectory() as scratch, topology(("owner", "laptop"), isolated) as nodes:
        root = Path(scratch)
        owner, laptop = (Peer(binary, root / role, route) for role, (_, route) in nodes.items())
        if isolated:
            # The fixture has no upstream router. Route link-local multicast onto its Ethernet.
            for _, route in nodes.values():
                subprocess.run([*route, "ip", "route", "add", "224.0.0.0/4", "dev", "uplink"], check=True)
        project = root / "search"
        sample = root / "documents"
        shutil.copytree(ROOT / "examples/native-documents/sample", sample)
        (sample / "build.log").write_text("budget for the next build\n")
        owner.run("new", project)
        declined = owner.run("install", project, success=False)
        assert "approval declined" in declined, declined
        app = owner.run("install", project, approve=True)
        owner.run("grant", "documents", sample)
        assert "Indexed 1 document" in owner.run("run", "index")
        assert owner.run("run", "search budget") == "Index revision 1 · 1 match\nmeeting.md"

        release = owner.run("publish")
        recipient = laptop.run("identity")
        grant = root / "documents.grant"
        grant.write_text(owner.run("grant", "documents", sample, recipient))
        with owner.host():
            client = laptop.run("install", "--from", release, approve=True)
            laptop.run("connect", "documents", grant)
            assert "Indexed 1 document" in laptop.run("run", "index")
            assert "meeting.md" in laptop.run("run", "search budget")
        assert "Offline cache" in laptop.run("run", "search budget")
        assert "no cached result" in laptop.run("run", "search missing")

        entry = project / "app.mjs"
        entry.write_text(entry.read_text().replace("Document search", "Office search"))
        assert owner.run("update", project, approve=True) == app
        with owner.host():
            updated = owner.run("publish")
            assert laptop.run("update", "--from", updated, approve=True) == client
            assert "Office search" in laptop.run("run", "help")
            assert "meeting.md" in laptop.run("run", "search budget")
            owner.run("revoke", bytes(json.loads(grant.read_text())["grant"]).hex())
            assert "capability denied" in laptop.run("run", "search budget")

        indexer = project / "index.ts"
        indexer.write_text(indexer.read_text().replace("md|txt", "md|txt|log"))
        assert owner.run("update", project, approve=True) == app
        assert "awaiting grant" in owner.run("status")
        assert "Connect the documents grant" in owner.run("run", "index")
        owner.run("grant", "documents", sample)
        assert "Indexed 2 documents" in owner.run("run", "index")
        grant.write_text(owner.run("grant", "documents", sample, recipient))
        with owner.host():
            release = owner.run("publish")
            assert laptop.run("update", "--from", release, approve=True) == client
            assert "awaiting grant" in laptop.run("status")
            laptop.run("connect", "documents", grant)
            assert "build.log" in laptop.run("run", "search budget")
        assert app in owner.run("list")
        assert "review" in owner.run().lower()
        assert "--from" in owner.run("install", "--help")
        indexer.write_text(indexer.read_text() + "\nconst broken: number = 'text';\n")
        diagnostic = owner.run("update", project, success=False)
        assert "index.ts" in diagnostic and "TS2322" in diagnostic, diagnostic
        assert app in owner.run("list")
        indexer.write_text(indexer.read_text().split("const broken:")[0])
        second = owner.run("install", project, approve=True)
        assert "PP2_APP" in owner.run("status", success=False)
        owner.env["PP2_APP"] = second
        assert second in owner.run("status")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isolated-networks", action="store_true")
    args = parser.parse_args()
    check(args.binary.resolve(), args.isolated_networks)
    print("Document workflow passed")
