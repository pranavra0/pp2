#!/usr/bin/env python3
"""Conventional document search for the native application comparison."""
import json
import os
import re
import sqlite3
import ssl
import sys
from contextlib import closing
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def words(text):
    return re.findall(r"[a-z0-9]{1,64}", text.lower())


def refresh(root, db):
    documents = []
    for count, (directory, subdirs, files) in enumerate(os.walk(root), 1):
        if count > 20:
            raise ValueError("Directory limit exceeded")
        subdirs[:] = [d for d in subdirs if not (Path(directory) / d).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if path.suffix.lower() not in (".md", ".txt") or path.is_symlink() or not path.is_file():
                continue
            if len(documents) == 32:
                raise ValueError("Document limit exceeded")
            with path.open("rb") as source:
                data = source.read(16385)
            if len(data) > 16384:
                raise ValueError("File limit exceeded")
            relative = path.relative_to(root).as_posix()
            documents.append((relative, json.dumps(sorted(set(words(data.decode()))))))
    with db:
        db.execute("delete from documents")
        db.executemany("insert into documents values (?, ?)", documents)
        db.execute("update revision set number = number + 1")
    return len(documents)


def search(query, db):
    if len(query) > 80:
        raise ValueError("Query limit exceeded")
    terms = set(words(query))
    return [
        name for name, tokens in db.execute("select * from documents order by path")
        if terms and terms.issubset(json.loads(tokens))
    ]


def tls(certs, role):
    server = role == "server"
    context = ssl.create_default_context(
        ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH,
        cafile=str(certs / "ca.pem"),
    )
    context.load_cert_chain(certs / (role + ".pem"), certs / (role + ".key"))
    if server:
        context.verify_mode = ssl.CERT_REQUIRED
    return context


def server(root, db_path, certs, bind, port):
    with closing(sqlite3.connect(db_path)) as db:
        db.executescript("""
            create table if not exists documents(path text primary key, words text);
            create table if not exists revision(number integer);
            insert into revision select 0 where not exists (select 1 from revision);
        """)

        class Handler(BaseHTTPRequestHandler):
            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def run(self, action):
                try:
                    value = action()
                    revision, = db.execute("select number from revision").fetchone()
                    self.reply(200, {"revision": revision, "value": value})
                except (OSError, ValueError) as error:
                    self.reply(400, {"error": str(error)})

            def do_POST(self):
                if self.path != "/index":
                    return self.reply(404, {"error": "Unknown operation"})
                self.run(lambda: refresh(root, db))

            def do_GET(self):
                route = urlsplit(self.path)
                query = parse_qs(route.query).get("q", [""])[0]
                if route.path != "/search":
                    return self.reply(404, {"error": "Unknown operation"})
                self.run(lambda: search(query, db))

        with HTTPServer((bind, int(port)), Handler) as listener:
            listener.socket = tls(certs, "server").wrap_socket(listener.socket, server_side=True)
            print("listening on", listener.server_port, flush=True)
            listener.serve_forever()


def client(host, port, certs, cache_path):
    from urllib.parse import urlencode

    context = tls(certs, "client")
    with closing(sqlite3.connect(cache_path)) as cache:
        cache.execute("create table if not exists cache(query text primary key, result text)")
        for line in sys.stdin:
            line = line.strip()
            if line == ".quit":
                break
            query = line[7:].lower().strip() if line.startswith("search ") else ""
            if line == "index":
                method, path = "POST", "/index"
            elif 1 <= len(query) <= 80:
                method, path = "GET", "/search?" + urlencode({"q": query})
            else:
                print("Document search\nindex\nsearch WORDS\n.quit")
                continue
            try:
                with closing(HTTPSConnection(host, int(port), timeout=2, context=context)) as conn:
                    conn.request(method, path)
                    reply = conn.getresponse()
                    body = json.loads(reply.read(256 * 1024))
                if reply.status != 200:
                    print(body["error"])
                    continue
            except (OSError, TimeoutError) as error:
                if isinstance(error, ssl.SSLError):
                    raise
                if not query:
                    print("Documents are offline.")
                    continue
                row = cache.execute("select result from cache where query = ?", (query,)).fetchone()
                if row is None:
                    print("Documents are offline. This query has no cached result.")
                    continue
                body, status = json.loads(row[0]), "Offline cache"
            else:
                if not query:
                    print(f"Indexed {body['value']} document{'s' if body['value'] != 1 else ''} at revision {body['revision']}")
                    continue
                with cache:
                    cache.execute("replace into cache values (?, ?)", (query, json.dumps(body)))
                status = "Index"
            count = len(body["value"])
            label = "match" if count == 1 else "matches"
            print(f"{status} revision {body['revision']} · {count} {label}")
            print("\n".join(body["value"]))


if __name__ == "__main__":
    mode, *args = sys.argv[1:]
    if mode == "server":
        root, db, certs, bind, port = args
        server(Path(root), db, Path(certs), bind, port)
    elif mode == "client":
        host, port, certs, cache = args
        client(host, port, Path(certs), cache)
    else:
        sys.exit("Use server ROOT DB CERTS BIND PORT or client HOST PORT CERTS CACHE")
