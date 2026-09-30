#!/usr/bin/env python3
"""VulnShop — a small, robust, deliberately-vulnerable local web app for
validating AEGIS end-to-end against a LIVE target you own.

Threaded (survives concurrent scanners, unlike single-threaded demos) with a
real SQLite backend so sqlmap/ghauri can genuinely confirm an injection point.

Deliberate weaknesses (all on 127.0.0.1 only):
  * SQL injection  — GET /search?q=  (string-concatenated SQLite query)
  * SQL injection  — POST /login     (JSON email field concatenated)
  * Data exposure  — /.env, /.git/config reachable (HTTP 200)
  * Directory list — /backup/ returns an "Index of" page
  * Missing HTTP security headers (no CSP/X-Frame-Options/etc.)
Unknown paths return a real 404 so a soft-404 baseline works correctly.
"""
from __future__ import annotations

import html
import json
import os
import sqlite3
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
DBPATH = os.path.join(tempfile.gettempdir(), "aegis_vulnshop.db")

INDEX = """<!doctype html><html><head><title>VulnShop</title></head><body>
<h1>VulnShop</h1><p>Deliberately vulnerable test target.</p>
<ul>
 <li><a href="/search?q=juice">Search products</a></li>
 <li><a href="/api/products">Products API</a></li>
 <li><a href="/backup/">Backups</a></li>
 <li><a href="/admin">Admin</a></li>
 <li><a href="/login">Login</a></li>
</ul></body></html>"""

ENV = ("DB_PASSWORD=sup3rs3cr3t\nAPI_KEY=sk-live-8f3a2b1c9d\n"
       "SECRET_KEY=do-not-commit-this\n")
GITCFG = ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
          "\turl = https://github.com/example/vulnshop.git\n")
BACKUP_LISTING = ("<html><head><title>Index of /backup</title></head><body>"
                  "<h1>Index of /backup</h1><ul>"
                  "<li><a href=\"db.sql.bak\">db.sql.bak</a></li>"
                  "<li><a href=\"secrets.json\">secrets.json</a></li></ul></body></html>")


def init_db() -> None:
    con = sqlite3.connect(DBPATH)
    c = con.cursor()
    c.execute("DROP TABLE IF EXISTS products")
    c.execute("CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    c.executemany("INSERT INTO products(name,price) VALUES(?,?)",
                  [("Apple Juice", 1.99), ("Banana Juice", 2.49),
                   ("Carrot Juice", 2.99), ("Green Smoothie", 3.49),
                   ("Lemonade", 1.49)])
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
    c.executemany("INSERT INTO users(email,password) VALUES(?,?)",
                  [("admin@vuln.local", "s3cr3t-admin"),
                   ("user@vuln.local", "hunter2")])
    con.commit()
    con.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnShop/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        # DELIBERATELY no security headers (CSP / X-Frame-Options / etc.)
        self.end_headers()
        try:
            self.wfile.write(b)
        except BrokenPipeError:
            pass

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path = p.path
        qs = urllib.parse.parse_qs(p.query)
        if path in ("/", "/index.html"):
            return self._send(200, INDEX)
        if path == "/search":
            q = (qs.get("q") or [""])[0]
            con = sqlite3.connect(DBPATH)
            con.row_factory = sqlite3.Row
            sql = "SELECT id, name FROM products WHERE name LIKE '%" + q + "%'"  # INJECTABLE
            try:
                rows = con.execute(sql).fetchall()
                items = "".join(f"<li>{html.escape(r['name'])}</li>" for r in rows)
                return self._send(200, f"<h1>Results</h1><ul>{items}</ul>")
            except sqlite3.Error as e:
                return self._send(200, f"<h1>DB error</h1><pre>{html.escape(str(e))}</pre>")
            finally:
                con.close()
        if path == "/api/products" or path == "/api":
            con = sqlite3.connect(DBPATH)
            con.row_factory = sqlite3.Row
            rows = con.execute("SELECT id,name,price FROM products").fetchall()
            con.close()
            return self._send(200, json.dumps([dict(r) for r in rows]),
                              "application/json")
        if path == "/.env":
            return self._send(200, ENV, "text/plain; charset=utf-8")
        if path == "/.git/config":
            return self._send(200, GITCFG, "text/plain; charset=utf-8")
        if path == "/backup/" or path == "/backup":
            return self._send(200, BACKUP_LISTING)
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /backup/\n",
                              "text/plain; charset=utf-8")
        if path == "/admin":
            return self._send(200, "<h1>Admin</h1><p>Restricted area.</p>")
        if path == "/login":
            return self._send(200, "<h1>Login</h1><form method=post>"
                              "<input name=email><input name=password></form>")
        return self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self):
        p = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if p.path == "/login":
            email = ""
            try:
                email = (json.loads(raw or b"{}") or {}).get("email", "")
            except Exception:
                email = (urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
                         .get("email", [""])[0])
            con = sqlite3.connect(DBPATH)
            con.row_factory = sqlite3.Row
            sql = "SELECT id,email FROM users WHERE email = '" + str(email) + "'"  # INJECTABLE
            try:
                row = con.execute(sql).fetchone()
                ok = row is not None
                return self._send(200, json.dumps({"authenticated": ok}),
                                  "application/json")
            except sqlite3.Error as e:
                return self._send(200, json.dumps({"error": str(e)}),
                                  "application/json")
            finally:
                con.close()
        return self._send(404, "<h1>404 Not Found</h1>")


if __name__ == "__main__":
    init_db()
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    srv.daemon_threads = True
    print(f"VulnShop listening on http://127.0.0.1:{PORT}  (db={DBPATH})", flush=True)
    srv.serve_forever()
