"""Dependency-free HTTP server for the dashboard (stdlib ThreadingHTTPServer).

Security defaults
-----------------
* Optional HTTP basic auth (DASHBOARD_USER / DASHBOARD_PASSWORD).
* Without auth, only requests whose Host header is localhost/127.0.0.1/::1 (or listed
  in DASHBOARD_ALLOWED_HOSTS) are served – this blocks DNS-rebinding attacks.
* State-changing requests need the custom header ``X-Subtrack: 1`` which browsers
  cannot send cross-origin without a CORS preflight (that we never grant) -> no CSRF.
* Strict Content-Security-Policy; the UI never renders scanned data as HTML.
"""
from __future__ import annotations

import base64
import hmac
import json
import mimetypes
import os
import re
import sqlite3
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .. import __version__
from ..db import connect, db_path
from . import api

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 2 * 1024 * 1024
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

ROUTES: list[tuple[str, re.Pattern, str]] = []


def route(method: str, pattern: str):
    def deco(fn):
        ROUTES.append((method, re.compile(f"^{pattern}$"), fn.__name__))
        return fn
    return deco


class Handler(BaseHTTPRequestHandler):
    server_version = f"subtrack/{__version__}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ plumbing
    def log_message(self, fmt, *args):
        if os.environ.get("DASHBOARD_ACCESS_LOG", "1") != "0":
            sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    def _send(self, status: int, body: bytes, content_type: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, data, status: int = 200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode()
        self._send(status, body, "application/json; charset=utf-8", {"Cache-Control": "no-store"})

    def send_error_json(self, status: int, message: str):
        self.send_json({"error": message}, status)

    def _authorized(self) -> bool:
        user = os.environ.get("DASHBOARD_USER", "")
        password = os.environ.get("DASHBOARD_PASSWORD", "")
        if not user and not password:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            given_user, _, given_pw = base64.b64decode(header[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(given_user, user) & hmac.compare_digest(given_pw, password)

    def _host_allowed(self) -> bool:
        if os.environ.get("DASHBOARD_USER") or os.environ.get("DASHBOARD_PASSWORD"):
            return True
        allowed = {h.strip().lower() for h in os.environ.get("DASHBOARD_ALLOWED_HOSTS", "").split(",") if h.strip()}
        if "*" in allowed:
            return True
        host = (self.headers.get("Host") or "").strip().lower()
        host = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return host in LOCAL_HOSTS or host in allowed

    def _dispatch(self):
        url = urlsplit(self.path)
        path = url.path
        if path == "/healthz":
            try:
                conn = connect(timeout=5)
                conn.execute("SELECT 1").fetchone()
                conn.close()
                return self.send_json({"ok": True, "version": __version__})
            except sqlite3.Error as exc:
                return self.send_json({"ok": False, "error": str(exc)}, 503)
        if not self._host_allowed():
            return self._send(
                421, b"Host not allowed. This dashboard has no password, so it only answers on localhost.\n"
                     b"Either set DASHBOARD_USER/DASHBOARD_PASSWORD, or list this hostname in DASHBOARD_ALLOWED_HOSTS.\n",
                "text/plain; charset=utf-8")
        if not self._authorized():
            return self._send(401, b"authentication required\n", "text/plain; charset=utf-8",
                              {"WWW-Authenticate": 'Basic realm="subtrack", charset="UTF-8"'})
        if not path.startswith("/api/"):
            return self._static(path)
        if self.command not in ("GET", "HEAD") and self.headers.get("X-Subtrack") != "1":
            return self.send_error_json(403, "missing X-Subtrack header")
        args = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
        for method, pattern, name in ROUTES:
            if method != ("GET" if self.command == "HEAD" else self.command):
                continue
            match = pattern.match(path)
            if not match:
                continue
            conn = None
            try:
                body = self._json_body() if self.command in ("POST", "PATCH", "PUT") else {}
                conn = connect()
                return getattr(self, name)(conn, args, body, *match.groups())
            except api.ApiError as exc:
                return self.send_error_json(exc.status, exc.message)
            except (ValueError, TypeError) as exc:
                return self.send_error_json(400, f"bad request: {exc}")
            except sqlite3.OperationalError as exc:
                return self.send_error_json(503, f"database busy or unavailable: {exc}")
            except Exception:  # pragma: no cover
                traceback.print_exc()
                return self.send_error_json(500, "internal error (see dashboard logs)")
            finally:
                if conn is not None:
                    conn.close()
        return self.send_error_json(404, "no such endpoint")

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise api.ApiError(413, "request body too large")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            raise api.ApiError(400, "body must be JSON")
        if not isinstance(data, dict):
            raise api.ApiError(400, "body must be a JSON object")
        return data

    def _static(self, path: str):
        if path in ("/", "") or not os.path.splitext(path)[1]:
            path = "/index.html"  # SPA routes
        full = os.path.realpath(os.path.join(STATIC_DIR, path.lstrip("/")))
        if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
            return self._send(404, b"not found\n", "text/plain; charset=utf-8")
        with open(full, "rb") as fh:
            body = fh.read()
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype, {"Cache-Control": "no-cache"})

    do_GET = do_HEAD = do_POST = do_PATCH = do_DELETE = do_PUT = lambda self: self._dispatch()

    # ------------------------------------------------------------------ routes
    @route("GET", r"/api/overview")
    def r_overview(self, conn, args, body):
        self.send_json(api.overview(conn) | {"db": db_path(), "version": __version__})

    @route("GET", r"/api/facets")
    def r_facets(self, conn, args, body):
        self.send_json(api.facets(conn, args))

    @route("GET", r"/api/roots")
    def r_roots(self, conn, args, body):
        self.send_json(api.list_roots(conn))

    @route("PATCH", r"/api/roots/(\d+)")
    def r_root_update(self, conn, args, body, root_id):
        self.send_json(api.update_root(conn, int(root_id), body))

    @route("GET", r"/api/subdomains")
    def r_subdomains(self, conn, args, body):
        self.send_json(api.list_subdomains(conn, args))

    @route("GET", r"/api/subdomains/(\d+)")
    def r_subdomain(self, conn, args, body, sub_id):
        self.send_json(api.get_subdomain(conn, int(sub_id)))

    @route("PATCH", r"/api/subdomains/(\d+)")
    def r_subdomain_update(self, conn, args, body, sub_id):
        self.send_json(api.update_subdomain(conn, int(sub_id), body))

    @route("GET", r"/api/subdomains/(\d+)/history")
    def r_history(self, conn, args, body, sub_id):
        self.send_json(api.subdomain_history(conn, int(sub_id)))

    @route("POST", r"/api/subdomains/(\d+)/tags")
    def r_add_tag(self, conn, args, body, sub_id):
        self.send_json(api.add_tag(conn, int(sub_id), body))

    @route("DELETE", r"/api/subdomains/(\d+)/tags/(\d+)")
    def r_remove_tag(self, conn, args, body, sub_id, tag_id):
        self.send_json(api.remove_tag(conn, int(sub_id), int(tag_id)))

    @route("POST", r"/api/bulk/tags")
    def r_bulk_tags(self, conn, args, body):
        self.send_json(api.bulk_tags(conn, body))

    @route("GET", r"/api/results/(\d+)")
    def r_result(self, conn, args, body, result_id):
        self.send_json(api.get_result(conn, int(result_id)))

    @route("GET", r"/api/tags")
    def r_tags(self, conn, args, body):
        self.send_json(api.list_tags(conn))

    @route("POST", r"/api/tags")
    def r_tag_create(self, conn, args, body):
        self.send_json(api.create_tag(conn, body), 201)

    @route("PATCH", r"/api/tags/(\d+)")
    def r_tag_update(self, conn, args, body, tag_id):
        self.send_json(api.update_tag(conn, int(tag_id), body))

    @route("DELETE", r"/api/tags/(\d+)")
    def r_tag_delete(self, conn, args, body, tag_id):
        self.send_json(api.delete_tag(conn, int(tag_id)))

    @route("GET", r"/api/events")
    def r_events(self, conn, args, body):
        self.send_json(api.list_events(conn, args))

    @route("GET", r"/api/scans")
    def r_scans(self, conn, args, body):
        self.send_json(api.list_scans(conn, args))

    @route("GET", r"/api/scans/(\d+)")
    def r_scan(self, conn, args, body, scan_id):
        self.send_json(api.get_scan(conn, int(scan_id)))

    @route("GET", r"/api/scan-requests")
    def r_requests(self, conn, args, body):
        self.send_json(api.list_scan_requests(conn))

    @route("POST", r"/api/scan-requests")
    def r_request_create(self, conn, args, body):
        self.send_json(api.create_scan_request(conn, body), 201)

    @route("DELETE", r"/api/scan-requests/(\d+)")
    def r_request_cancel(self, conn, args, body, req_id):
        self.send_json(api.cancel_scan_request(conn, int(req_id)))

    @route("GET", r"/api/export")
    def r_export(self, conn, args, body):
        fmt = (args.get("format") or "csv").lower()
        items = list(api.iter_export_rows(conn, args))
        if fmt == "json":
            data, ctype, ext = json.dumps(items, ensure_ascii=False, indent=1).encode(), "application/json", "json"
        elif fmt == "txt":
            data, ctype, ext = ("\n".join(i["host"] for i in items) + "\n").encode(), "text/plain", "txt"
        elif fmt == "urls":
            urls = sorted({u for i in items for u in (i.get("urls") or [])})
            data, ctype, ext = ("\n".join(urls) + "\n").encode(), "text/plain", "txt"
        elif fmt == "csv":
            data, ctype, ext = api.export_csv(items).encode(), "text/csv", "csv"
        else:
            raise api.ApiError(400, "format must be csv, json, txt or urls")
        self._send(200, data, f"{ctype}; charset=utf-8", {
            "Content-Disposition": f'attachment; filename="subtrack-export.{ext}"', "Cache-Control": "no-store"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "8080"))
    conn = connect()  # create / migrate the schema up-front so errors surface immediately
    conn.close()
    httpd = Server((host, port), Handler)
    auth = "basic auth enabled" if os.environ.get("DASHBOARD_USER") else "no auth (localhost only)"
    print(f"subtrack dashboard {__version__} on http://{host}:{port}  db={db_path()}  [{auth}]", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
