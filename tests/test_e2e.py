"""End-to-end tests: real dnsx + httpx against the local lab (DNS + HTTP/HTTPS).

subfinder is replaced by tests/fake_subfinder.py because passive sources need
the internet. Skipped automatically when dnsx/httpx are not installed or ports
80/443 cannot be bound (override with LAB_HTTP_PORT / LAB_HTTPS_PORT).

Run inside the scanner image:  make test
"""
import contextlib
import copy
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

DNSX = os.environ.get("DNSX_BIN") or shutil.which("dnsx")
HTTPX = os.environ.get("HTTPX_BIN") or shutil.which("httpx")
HTTP_PORT = int(os.environ.get("LAB_HTTP_PORT", "80"))
HTTPS_PORT = int(os.environ.get("LAB_HTTPS_PORT", "443"))

BASE_STATE = {
    "dns": {
        "acme.test": {"A": ["127.0.10.1"]},
        "www.acme.test": {"A": ["127.0.10.1"]},
        "api.acme.test": {"A": ["127.0.10.2"]},
        "mail.acme.test": {"A": ["127.0.10.4"]},          # resolves, but no web server
        "legacy.acme.test": {"CNAME": "www.acme.test"},
        "secret-sauce.acme.test": {"A": ["127.0.10.5"]},  # only discoverable via the TLS certificate
        "wild.test": {"A": ["127.0.20.1"]},
        "portal.wild.test": {"A": ["127.0.20.2"]},
    },
    "wildcards": {"wild.test": {"A": ["127.0.20.1"]}},
    "http": {
        "acme.test": {"status": 301, "location": "https://www.acme.test/", "title": "Moved"},
        "www.acme.test": {"title": "ACME Home", "server": "nginx/1.25"},
        "api.acme.test": {"status": 401, "title": "API", "server": "envoy", "schemes": ["http"]},
        "legacy.acme.test": {"title": "Legacy"},
        "secret-sauce.acme.test": {"title": "Secret"},
        "portal.wild.test": {"title": "Portal"},
        "wild.test": {"title": "Wild root"},
    },
}
SUBFINDER = {
    "acme.test": [["www.acme.test", ["crtsh", "anubis"]], ["legacy.acme.test", ["crtsh"]],
                  ["shop.acme.test", ["alienvault"]], ["*.acme.test", ["crtsh"]], ["evil.com", ["x"]]],
    "wild.test": [["portal.wild.test", ["crtsh"]]],
}


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def can_bind(port):
    try:
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


@unittest.skipUnless(DNSX and HTTPX, "dnsx/httpx not installed")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (can_bind(HTTP_PORT) and can_bind(HTTPS_PORT)):
            raise unittest.SkipTest(f"cannot bind lab ports {HTTP_PORT}/{HTTPS_PORT}")
        cls.tmp = tempfile.mkdtemp(prefix="subtrack-e2e-")
        cls.state_path = os.path.join(cls.tmp, "state.json")
        cls.write_state(BASE_STATE)
        cls.subfinder_path = os.path.join(cls.tmp, "subfinder.json")
        with open(cls.subfinder_path, "w") as fh:
            json.dump(SUBFINDER, fh)
        cls.dns_port = free_udp_port()
        cls.lab = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "lab", "labserver.py"), "--state", cls.state_path,
             "--dns-port", str(cls.dns_port), "--http-port", str(HTTP_PORT), "--https-port", str(HTTPS_PORT),
             "--san", "*.acme.test,acme.test,secret-sauce.acme.test,outofscope.example"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True)
        line = cls.lab.stdout.readline()
        if "lab up" not in line:
            cls.lab.kill()
            raise RuntimeError(f"lab failed to start: {line}{cls.lab.stdout.read()}")
        # keep draining the lab's output so it can never block on a full pipe
        threading.Thread(target=cls.lab.stdout.read, daemon=True).start()
        cls.data = os.path.join(cls.tmp, "data")
        cls.env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        cls.env.update(TRACKER_DATA=cls.data, SUBFINDER_BIN=os.path.join(HERE, "fake_subfinder.py"),
                       FAKE_SUBFINDER_DATA=cls.subfinder_path, DNSX_BIN=DNSX, HTTPX_BIN=HTTPX,
                       PYTHONPATH=ROOT)

    @classmethod
    def tearDownClass(cls):
        cls.lab.terminate()
        cls.lab.wait(timeout=10)
        cls.lab.stdout.close()
        if not os.environ.get("KEEP_E2E"):
            shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write_state(cls, state):
        tmp = cls.state_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, cls.state_path)

    def scan(self, *args, extra_env=None, expect_rc=0):
        argv = [sys.executable, "-m", "tracker.scan", *args, f"resolvers=127.0.0.1:{self.dns_port}",
                "timeout=3", "retries=1"]
        if (HTTP_PORT, HTTPS_PORT) != (80, 443):
            argv.append(f"ports=http:{HTTP_PORT},https:{HTTPS_PORT}")
        env = dict(self.env, **(extra_env or {}))
        out = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=600,
                             stdin=subprocess.DEVNULL)
        if out.returncode != expect_rc:
            self.fail(f"scan exited {out.returncode}\nSTDOUT:\n{out.stdout}\nSTDERR:\n{out.stderr}")
        return out.stdout

    @contextlib.contextmanager
    def db(self):
        conn = sqlite3.connect(os.path.join(self.data, "tracker.db"))
        conn.row_factory = sqlite3.Row
        try:
            with conn:  # commit on success
                yield conn
        finally:
            conn.close()

    def subs(self, root="acme.test"):
        with self.db() as conn:
            return {r["host"]: dict(r) for r in conn.execute(
                "SELECT s.* FROM subdomains s JOIN roots r ON r.id = s.root_id WHERE r.domain = ?", (root,))}

    def last_events(self):
        with self.db() as conn:
            scan_id = conn.execute("SELECT MAX(id) FROM scans").fetchone()[0]
            return {(r["type"], r["host"]): json.loads(r["details"]) for r in conn.execute(
                "SELECT e.type, s.host, e.details FROM events e JOIN subdomains s ON s.id = e.subdomain_id "
                "WHERE e.scan_id = ?", (scan_id,))}

    def last_scan(self):
        with self.db() as conn:
            scan = dict(conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone())
            roots = [dict(r) for r in conn.execute("SELECT * FROM scan_roots WHERE scan_id = ?", (scan["id"],))]
        return scan, roots

    # The lifecycle steps share state, so they live in one ordered test.
    def test_lifecycle(self):
        # ---- scan 1: initial discovery -------------------------------------
        self.scan("domain=acme.test")
        subs = self.subs()
        self.assertEqual(set(subs), {"acme.test", "www.acme.test", "api.acme.test", "legacy.acme.test",
                                     "secret-sauce.acme.test"},
                         "only httpx-validated hosts are stored (mail has no web server, shop does not resolve)")
        self.assertTrue(all(s["status"] == "active" for s in subs.values()))
        self.assertEqual(subs["api.acme.test"]["scheme"], "http", "https failed -> http fallback")
        self.assertEqual(subs["www.acme.test"]["scheme"], "https")
        self.assertEqual(subs["acme.test"]["location"], "https://www.acme.test/")
        www_sources = set(json.loads(subs["www.acme.test"]["sources"]))
        self.assertTrue({"subfinder:crtsh", "subfinder:anubis", "bruteforce"} <= www_sources, www_sources)
        self.assertEqual(json.loads(subs["secret-sauce.acme.test"]["sources"]), ["tls-san"])
        self.assertEqual(json.loads(subs["legacy.acme.test"]["cname"]), ["www.acme.test"])
        self.assertEqual(subs["www.acme.test"]["tls_subject_cn"], "lab.test")
        with self.db() as conn:
            raw = json.loads(conn.execute(
                "SELECT raw FROM httpx_results h JOIN subdomains s ON s.id = h.subdomain_id "
                "WHERE s.host = 'www.acme.test'").fetchone()[0])
            self.assertEqual(raw["title"], "ACME Home")
            self.assertIn("tls", raw)
            self.assertIn("header", raw, "-irh response headers are part of the stored JSON")
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM dns_results").fetchone()[0], 0)
        self.assertEqual({k[0] for k in self.last_events()}, {"new"})
        scan, roots = self.last_scan()
        self.assertEqual(scan["status"], "success")
        self.assertTrue(os.path.exists(os.path.join(scan["output_dir"], "acme.test", "httpx-main.jsonl")))

        with self.db() as conn:  # a user tag (as set from the dashboard)
            conn.execute("INSERT INTO tags(name, color, created_at) VALUES('keep-me', '#000', 'x')")
            conn.execute("INSERT INTO subdomain_tags SELECT id, 1, 'x' FROM subdomains WHERE host='www.acme.test'")

        # ---- scan 2: changes ------------------------------------------------
        state = copy.deepcopy(BASE_STATE)
        state["http"]["api.acme.test"]["down"] = True                  # web server gone, DNS still there
        del state["dns"]["legacy.acme.test"]                           # DNS removed
        state["http"]["www.acme.test"]["title"] = "ACME Home v2"       # content change
        state["dns"]["beta.acme.test"] = {"A": ["127.0.10.6"]}         # new host (wordlist hit)
        state["http"]["beta.acme.test"] = {"title": "Beta"}
        state["http"]["mail.acme.test"] = {"title": "Webmail"}         # mail now has a web server
        self.write_state(state)
        self.scan("domain=acme.test")
        subs = self.subs()
        self.assertEqual(len(subs), 7, "nothing is ever removed")
        self.assertEqual((subs["api.acme.test"]["status"], subs["api.acme.test"]["offline_reason"]), ("offline", "http"))
        self.assertEqual((subs["legacy.acme.test"]["status"], subs["legacy.acme.test"]["offline_reason"]), ("offline", "dns"))
        ev = self.last_events()
        self.assertEqual(ev[("changed", "www.acme.test")]["changes"]["title"],
                         {"old": "ACME Home", "new": "ACME Home v2"})
        self.assertIn(("new", "beta.acme.test"), ev)
        self.assertIn(("new", "mail.acme.test"), ev)
        self.assertIn(("offline", "api.acme.test"), ev)
        self.assertEqual(json.loads(subs["beta.acme.test"]["sources"]), ["bruteforce"])
        with self.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM subdomain_tags").fetchone()[0], 1)
            phases = {r[0] for r in conn.execute("SELECT DISTINCT phase FROM httpx_results")}
        self.assertTrue(os.path.exists(os.path.join(self.last_scan()[0]["output_dir"], "acme.test",
                                                    "httpx-recheck-targets.txt")), "vanished hosts are rechecked")
        self.assertIn("main", phases)

        # ---- scan 3: api comes back -----------------------------------------
        state["http"]["api.acme.test"]["down"] = False
        self.write_state(state)
        self.scan("domain=acme.test")
        subs = self.subs()
        self.assertEqual(subs["api.acme.test"]["status"], "active")
        self.assertIn(("back_online", "api.acme.test"), self.last_events())
        self.assertEqual(subs["legacy.acme.test"]["status"], "offline")
        self.assertEqual(subs["legacy.acme.test"]["seen_count"], 1)

        # ---- scan 4: scanner-side outage -> guard keeps everything active ---
        outage = copy.deepcopy(state)
        for cfg in outage["http"].values():
            cfg["down"] = True
        self.write_state(outage)
        self.scan("domain=acme.test")
        scan, roots = self.last_scan()
        self.assertEqual(roots[0]["status"], "partial")
        self.assertTrue(json.loads(roots[0]["stats"])["offline_guard_tripped"])
        self.assertEqual(sum(s["status"] == "active" for s in self.subs().values()), 6)

        # ---- scan 5: same, forced -> they really are offline -----------------
        self.scan("domain=acme.test", "force=true")
        self.assertEqual(sum(s["status"] == "active" for s in self.subs().values()), 0)
        self.write_state(state)

    def test_wildcard_domain(self):
        self.scan("domain=wild.test", "san=false")
        subs = self.subs("wild.test")
        self.assertEqual(set(subs), {"wild.test", "portal.wild.test"},
                         "wildcard answers from the brute force must not become assets")
        _, roots = self.last_scan()
        self.assertTrue(json.loads(roots[0]["stats"])["wildcard"])

    def test_subfinder_failure_is_not_fatal(self):
        self.scan("domain=acme.test", extra_env={"FAKE_SUBFINDER_FAIL": "1"})
        scan, roots = self.last_scan()
        self.assertEqual(roots[0]["status"], "partial")
        self.assertIn("subfinder failed", roots[0]["warnings"])

    def test_rescan_all_and_status(self):
        self.scan("domain=acme.test", "passive=false", "brute=false")
        out = self.scan("domain=all", "passive=false", "brute=false")
        self.assertIn("acme.test", out)
        out = self.scan("mode=status")
        self.assertIn("acme.test", out)

    def test_invalid_domain_is_rejected(self):
        self.scan("domain=not a domain", expect_rc=1)

    def test_worker_processes_dashboard_queue(self):
        self.scan("mode=init")
        with self.db() as conn:
            conn.execute("INSERT INTO scan_requests(domains, params, requested_at) "
                         "VALUES('acme.test', '{\"brute\": false, \"passive\": false}', 'now')")
        worker = subprocess.Popen(
            [sys.executable, "-m", "tracker.scan", "mode=worker", "poll_interval=1",
             f"resolvers=127.0.0.1:{self.dns_port}", "timeout=3", "retries=1"],
            cwd=ROOT, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.time() + 180
            status = None
            while time.time() < deadline:
                with self.db() as conn:
                    status, scan_id = conn.execute("SELECT status, scan_id FROM scan_requests ORDER BY id DESC LIMIT 1").fetchone()
                    heartbeat = conn.execute("SELECT value FROM meta WHERE key = 'worker_heartbeat'").fetchone()
                if status in ("done", "failed"):
                    break
                time.sleep(1)
            self.assertEqual(status, "done")
            self.assertIsNotNone(heartbeat)
            with self.db() as conn:
                trigger = conn.execute("SELECT trigger FROM scans WHERE id = ?", (scan_id,)).fetchone()[0]
            self.assertEqual(trigger, "queue:dashboard")
        finally:
            worker.terminate()
            out, _ = worker.communicate(timeout=30)
        self.assertEqual(worker.returncode, 0, out)
        self.assertIn("worker stopped", out)


if __name__ == "__main__":
    unittest.main()
