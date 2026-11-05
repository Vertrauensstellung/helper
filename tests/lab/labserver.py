#!/usr/bin/env python3
"""
Self-contained test lab: an authoritative DNS server plus HTTP/HTTPS servers
whose behaviour is driven by a JSON state file that is re-read on every request.
Lets the test suite simulate hosts appearing, disappearing and changing between
scans without touching the internet.

state.json layout:
{
  "dns":       {"www.acme.test": {"A": ["127.0.10.1"]}, "x.acme.test": {"CNAME": "y.example"}},
  "wildcards": {"wild.test": {"A": ["127.0.20.1"]}},      # *.wild.test
  "http":      {"www.acme.test": {"status": 200, "title": "Home", "server": "nginx",
                                  "schemes": ["http", "https"], "location": null}}
}
Hosts that are missing from "http" (or have "down": true) get their TCP
connection closed without a response, i.e. httpx sees them as dead.
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import QTYPE, RR, A, AAAA, CNAME, RCODE
from dnslib.server import BaseResolver, DNSLogger, DNSServer

STATE_PATH = None


def load_state():
    try:
        with open(STATE_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {"dns": {}, "wildcards": {}, "http": {}}


class LabResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]
        state = load_state()
        rec = state.get("dns", {}).get(qname)
        if rec is None:
            for wdom, wrec in state.get("wildcards", {}).items():
                if qname.endswith("." + wdom):
                    rec = wrec
                    break
        if rec is None:
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        if "CNAME" in rec:
            reply.add_answer(RR(request.q.qname, QTYPE.CNAME, rdata=CNAME(rec["CNAME"] + "."), ttl=30))
            target = state.get("dns", {}).get(rec["CNAME"].lower(), {})
            if qtype in ("A", "ANY"):
                for ip in target.get("A", []):
                    reply.add_answer(RR(rec["CNAME"] + ".", QTYPE.A, rdata=A(ip), ttl=30))
            return reply
        if qtype in ("A", "ANY"):
            for ip in rec.get("A", []):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ip), ttl=30))
        if qtype in ("AAAA", "ANY"):
            for ip in rec.get("AAAA", []):
                reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ip), ttl=30))
        return reply


class Handler(BaseHTTPRequestHandler):
    scheme = "http"
    _server_name = "lab-httpd"

    def version_string(self):
        return self._server_name

    def log_message(self, *args):
        pass

    def _drop(self):
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _serve(self, head_only=False):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        cfg = load_state().get("http", {}).get(host)
        if not cfg or cfg.get("down") or self.scheme not in cfg.get("schemes", ["http", "https"]):
            return self._drop()
        title = cfg.get("title", host)
        body = cfg.get("body") or f"<html><head><title>{title}</title></head><body><h1>{title}</h1>{cfg.get('extra', '')}</body></html>"
        data = body.encode()
        self._server_name = cfg.get("server", "lab-httpd")
        self.send_response(int(cfg.get("status", 200)))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (cfg.get("headers") or {}).items():
            self.send_header(k, v)
        if cfg.get("location"):
            self.send_header("Location", cfg["location"])
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve(head_only=True)


class HTTPSHandler(Handler):
    scheme = "https"


class TLSServer(ThreadingHTTPServer):
    """Performs the TLS handshake in the per-connection thread, so one slow or
    half-open client cannot block the accept loop."""
    ssl_ctx = None

    def finish_request(self, request, client_address):
        try:
            request = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        self.RequestHandlerClass(request, client_address, self)


def make_cert(directory, sans):
    crt, key = os.path.join(directory, "lab.crt"), os.path.join(directory, "lab.key")
    if not os.path.exists(crt):
        san = ",".join(f"DNS:{name}" for name in sans)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "30", "-subj", "/CN=lab.test", "-addext", f"subjectAltName={san}"],
                       check=True, capture_output=True)
    return crt, key


def main():
    global STATE_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--dns-port", type=int, default=1053)
    ap.add_argument("--http-port", type=int, default=80)
    ap.add_argument("--https-port", type=int, default=443)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--san", default="*.acme.test,acme.test,*.wild.test",
                    help="comma separated subjectAltNames for the self-signed certificate")
    args = ap.parse_args()
    STATE_PATH = args.state

    resolver = LabResolver()
    for tcp in (False, True):
        quiet = DNSLogger(log="-recv,-send,-request,-reply,-truncated,-error,-data", prefix=False)
        DNSServer(resolver, port=args.dns_port, address="127.0.0.1", tcp=tcp, logger=quiet).start_thread()

    httpd = ThreadingHTTPServer((args.bind, args.http_port), Handler)
    httpsd = TLSServer((args.bind, args.https_port), HTTPSHandler)
    crt, key = make_cert(os.path.dirname(os.path.abspath(STATE_PATH)), args.san.split(","))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    httpsd.ssl_ctx = ctx
    threading.Thread(target=httpsd.serve_forever, daemon=True).start()
    print(f"lab up: dns 127.0.0.1:{args.dns_port} http :{args.http_port} https :{args.https_port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
