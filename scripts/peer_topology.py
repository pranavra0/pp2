"""Peer processes and isolated Linux network stacks."""

from contextlib import ExitStack, contextmanager
import subprocess


@contextmanager
def serving(command, *, env=None, stderr=None, crash=False, ready_prefix=""):
    with subprocess.Popen(
        command, env=env, stderr=stderr, stdout=subprocess.PIPE, text=True,
    ) as process:
        try:
            ready = process.stdout.readline().strip()
            if not ready or not ready.startswith(ready_prefix):
                raise RuntimeError(f"{command} failed to start")
            yield ready
        finally:
            if crash:
                process.kill()
            else:
                process.terminate()


def ip(*args):
    subprocess.run(("ip", *args), check=True, capture_output=True, timeout=5)


def partition(role, disconnected):
    ip("link", "set", f"v-{role}", "down" if disconnected else "up")


@contextmanager
def topology(roles, isolated):
    if not isolated:
        yield {role: ("127.0.0.1", ()) for role in roles}
        return
    with ExitStack() as stack:
        ip("link", "add", "pp2-bridge", "type", "bridge")
        stack.callback(ip, "link", "del", "pp2-bridge")
        ip("address", "add", "10.92.0.1/24", "dev", "pp2-bridge")
        ip("link", "set", "pp2-bridge", "up")
        nodes = {}
        for index, role in enumerate(roles, start=2):
            child = stack.enter_context(subprocess.Popen(
                ("unshare", "-n", "sh", "-c", "echo ready; exec sleep infinity"),
                text=True, stdout=subprocess.PIPE,
            ))
            stack.callback(child.kill)
            if child.stdout.readline().strip() != "ready":
                raise RuntimeError(f"network namespace for {role} failed to start")
            prefix = ("nsenter", "--target", str(child.pid), "--net", "--")
            host, link = f"10.92.0.{index}", f"v-{role}"
            ip("link", "add", link, "type", "veth", "peer", "name", "uplink")
            ip("link", "set", "uplink", "netns", str(child.pid))
            ip("link", "set", link, "master", "pp2-bridge")
            partition(role, False)
            subprocess.run((*prefix, "ip", "-batch", "-"), check=True, timeout=5, text=True,
                           input=f"link set lo up\naddress add {host}/24 dev uplink\nlink set uplink up\n")
            nodes[role] = (host, prefix)
        yield nodes
