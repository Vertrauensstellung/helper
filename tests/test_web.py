"""Dashboard API tests: real HTTP server on a random port, seeded through the ingest code path."""
import base64
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tracker import db  # noqa: E402
from tracker.ingest import HttpxRecord, RootResult, ingest  # noqa: E402


def rec(host, title, code=200, **extra):
    data = {"input": host, "url": f"https://{host}", "scheme": "https", "port": "443", "status_code": code,
            "title": title, "webserver": "nginx", "tech": ["Nginx", "PHP"], "a": ["10.0.0.7"], "failed": False}
    data.update(extra)
    return HttpxRecord("main", json.dumps(data), data)


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["TRACKER_DATA"] = cls.tmp.name
        os.environ["DASHBOARD_ACCESS_LOG"] = "0"
        conn = db.connect()
        with db.transaction(conn):
            root_id = db.ensure_root(conn, "ex.com")
        for i, hosts in enumerate([["a.ex.com", "b.ex.com", "login.ex.com"], ["a.ex.com", "login.ex.com"]]):
            with db.transaction(conn):
                sid = conn.execute("INSERT INTO scans(started_at, status) VALUES(?, 'success')", (db.utcnow(),)).lastrowid
            records = [rec(h, "Sign in" if h.startswith("login") else f"page {i}", 401 if h.startswith("login") else 200) for h in hosts]
            ingest(conn, RootResult(root="ex.com", root_id=root_id, scan_id=sid, httpx=records,
                                    sources={h: {"bruteforce"} for h in hosts},
                                    probed={"a.ex.com", "b.ex.com", "login.ex.com"}, probe_ok=True))
        conn.close()
        from tracker.web.server import Handler, Server
        cls.httpd = Server(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()
        for key in ("DASHBOARD_USER", "DASHBOARD_PASSWORD"):
            os.environ.pop(key, None)

    def call(self, path, method="GET", body=None, headers=None, csrf=True):
        hdrs = {"Content-Type": "application/json"} if body is not None else {}
        if csrf and method != "GET":
            hdrs["X-Subtrack"] = "1"
        hdrs.update(headers or {})
        req = urllib.request.Request(self.base + path, method=method, headers=hdrs,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if resp.headers.get_content_type() == "application/json" else raw.decode())
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                return err.code, json.loads(raw)
            except ValueError:
                return err.code, raw.decode()

    def hosts(self, query):
        status, data = self.call("/api/subdomains" + query)
        self.assertEqual(status, 200, data)
        return sorted(i["host"] for i in data["items"])

    def test_overview_and_lists(self):
        status, ov = self.call("/api/overview")
        self.assertEqual((status, ov["total"], ov["active"], ov["offline"]), (200, 3, 2, 1))
        self.assertEqual(self.hosts("?status=offline"), ["b.ex.com"])
        self.assertEqual(self.hosts("?q=title:%22sign%20in%22"), ["login.ex.com"])
        self.assertEqual(self.hosts("?q=code:4xx"), ["login.ex.com"])
        self.assertEqual(self.hosts("?q=-code:4xx%20-status:offline"), ["a.ex.com"])
        self.assertEqual(self.hosts("?tech=PHP&root=ex.com"), ["a.ex.com", "b.ex.com", "login.ex.com"])
        self.assertEqual(self.hosts("?event=changed&event_days=1"), ["a.ex.com"])
        self.assertEqual(self.hosts("?q=100%25"), [], "LIKE wildcards are escaped")
        status, page = self.call("/api/subdomains?per_page=1&page=2&sort=host&order=asc")
        self.assertEqual((page["total"], page["items"][0]["host"]), (3, "b.ex.com"))

    def test_detail_history_and_raw(self):
        _, data = self.call("/api/subdomains?q=host:a.ex.com")
        sub_id = data["items"][0]["id"]
        status, detail = self.call(f"/api/subdomains/{sub_id}")
        self.assertEqual((status, detail["last_result"]["title"]), (200, "page 1"))
        _, hist = self.call(f"/api/subdomains/{sub_id}/history")
        self.assertEqual(len(hist["results"]), 2)
        self.assertEqual([e["type"] for e in hist["events"]], ["changed", "new"])
        status, raw = self.call(f"/api/results/{hist['results'][0]['id']}")
        self.assertEqual(raw["url"], "https://a.ex.com")
        self.assertEqual(self.call("/api/subdomains/9999")[0], 404)

    def test_tags_crud_and_bulk(self):
        _, data = self.call("/api/subdomains?q=host:login")
        sub_id = data["items"][0]["id"]
        status, res = self.call(f"/api/subdomains/{sub_id}/tags", "POST", {"name": "Auth"})
        self.assertEqual(status, 200)
        tag_id = res["tags"][0]["id"]
        self.assertEqual(self.hosts("?tag=auth"), ["login.ex.com"], "tag filter is case-insensitive")
        status, res = self.call("/api/bulk/tags", "POST", {"filter": {"status": "active"}, "add": ["live"]})
        self.assertEqual(res["updated"], 2)
        self.assertEqual(self.hosts("?tag=live,Auth"), ["login.ex.com"])
        self.assertEqual(self.hosts("?untagged=1"), ["b.ex.com"])
        self.assertEqual(self.call(f"/api/tags/{tag_id}", "PATCH", {"name": "authn", "color": "#112233"})[0], 200)
        self.assertEqual(self.call(f"/api/tags/{tag_id}", "PATCH", {"color": "red"})[0], 400)
        self.assertEqual(self.call("/api/tags", "POST", {"name": "live"})[0], 409)
        self.assertEqual(self.call(f"/api/subdomains/{sub_id}/tags/{tag_id}", "DELETE")[0], 200)
        _, tags = self.call("/api/tags")
        live = next(t for t in tags if t["name"] == "live")
        self.assertEqual(live["count"], 2)
        self.assertEqual(self.call(f"/api/tags/{live['id']}", "DELETE")[0], 200)
        self.assertEqual(self.hosts("?tag=live"), [])
        self.assertEqual(self.call("/api/overview")[1]["total"], 3, "deleting tags never deletes assets")

    def test_notes_export_queue(self):
        _, data = self.call("/api/subdomains?q=host:b.ex.com")
        sub_id = data["items"][0]["id"]
        self.assertEqual(self.call(f"/api/subdomains/{sub_id}", "PATCH", {"notes": "=cmd|' /C calc'!A0"})[0], 200)
        status, csv_text = self.call("/api/export?format=csv&sort=host")
        self.assertEqual(status, 200)
        self.assertIn("a.ex.com", csv_text)
        status, hosts = self.call("/api/export?format=txt")
        self.assertEqual(hosts.split(), ["a.ex.com", "b.ex.com", "login.ex.com"])
        status, req = self.call("/api/scan-requests", "POST", {"domains": "new.example, other.example", "params": {"brute": False, "evil": "x"}})
        self.assertEqual((status, req["domains"], json.loads(req["params"])), (201, "new.example,other.example", {"brute": False}))
        self.assertEqual(self.call("/api/scan-requests", "POST", {"domains": "bad domain!"})[0], 400)
        self.assertEqual(self.call("/api/scan-requests", "POST", {"domains": "x.example", "params": {"ports": "80;rm -rf"}})[0], 400)
        self.assertEqual(self.call(f"/api/scan-requests/{req['id']}", "DELETE")[0], 200)
        self.assertEqual(self.call(f"/api/scan-requests/{req['id']}", "DELETE")[0], 409)

    def test_security(self):
        self.assertEqual(self.call("/api/tags", "POST", {"name": "x"}, csrf=False)[0], 403, "CSRF header required")
        self.assertEqual(self.call("/api/overview", headers={"Host": "attacker.example"})[0], 421, "DNS rebinding blocked")
        status, _ = self.call("/")
        self.assertEqual(status, 200)
        self.assertEqual(self.call("/../tracker/db.py")[0], 404)
        os.environ.update(DASHBOARD_USER="u", DASHBOARD_PASSWORD="p")
        try:
            self.assertEqual(self.call("/api/overview")[0], 401)
            good = {"Authorization": "Basic " + base64.b64encode(b"u:p").decode()}
            bad = {"Authorization": "Basic " + base64.b64encode(b"u:x").decode()}
            self.assertEqual(self.call("/api/overview", headers=good)[0], 200)
            self.assertEqual(self.call("/api/overview", headers=bad)[0], 401)
            self.assertEqual(self.call("/healthz")[0], 200, "health check needs no auth")
        finally:
            os.environ.pop("DASHBOARD_USER")
            os.environ.pop("DASHBOARD_PASSWORD")


if __name__ == "__main__":
    unittest.main()
