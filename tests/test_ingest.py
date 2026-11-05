"""Unit tests for the diff/lifecycle logic (no external tools needed)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tracker import db  # noqa: E402
from tracker.hosts import in_scope, normalize_host  # noqa: E402
from tracker.ingest import HttpxRecord, IngestOptions, RootResult, ingest  # noqa: E402
from tracker.scan import parse_args  # noqa: E402


def rec(host, title="t", code=200, scheme="https", port="443", phase="main", **extra):
    data = {"input": host, "url": f"{scheme}://{host}", "scheme": scheme, "port": port, "status_code": code,
            "title": title, "webserver": "nginx", "tech": ["Nginx"], "a": ["10.0.0.1"], "failed": False}
    data.update(extra)
    return HttpxRecord(phase=phase, raw=json.dumps(data), data=data)


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = db.connect(os.path.join(self.tmp.name, "t.db"))
        with db.transaction(self.conn):
            self.root_id = db.ensure_root(self.conn, "ex.com")
        self.scan = 0

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def run_scan(self, alive, probed=None, probe_ok=True, dns=None, force=False):
        self.scan += 1
        with db.transaction(self.conn):
            sid = self.conn.execute("INSERT INTO scans(started_at, status) VALUES(?, 'running')", (db.utcnow(),)).lastrowid
        records = [r if isinstance(r, HttpxRecord) else rec(r) for r in alive]
        hosts = {r.data["input"] for r in records}
        res = RootResult(root="ex.com", root_id=self.root_id, scan_id=sid,
                         sources={h: {"bruteforce"} for h in hosts}, httpx=records,
                         probed=set(probed if probed is not None else hosts), probe_ok=probe_ok)
        if dns is not None:
            res.dns_ok = True
            res.dns_checked = set(res.probed)
            res.dns = {h: {"host": h, "a": ["10.0.0.1"]} for h in dns}
        return ingest(self.conn, res, IngestOptions(force_offline=force)), res

    def sub(self, host):
        return self.conn.execute("SELECT * FROM subdomains WHERE host = ?", (host,)).fetchone()

    def events(self, etype=None):
        q = "SELECT e.type, s.host, e.details FROM events e JOIN subdomains s ON s.id = e.subdomain_id"
        rows = self.conn.execute(q + (" WHERE e.type = ?" if etype else ""), (etype,) if etype else ()).fetchall()
        return [(r[0], r[1], json.loads(r[2])) for r in rows]

    def test_new_then_unchanged(self):
        stats, _ = self.run_scan(["a.ex.com", "b.ex.com"])
        self.assertEqual(stats["new"], 2)
        stats, _ = self.run_scan(["a.ex.com", "b.ex.com"])
        self.assertEqual((stats["new"], stats["unchanged"], stats["changed"]), (0, 2, 0))
        row = self.sub("a.ex.com")
        self.assertEqual(row["seen_count"], 2)
        self.assertEqual(row["status"], "active")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM httpx_results").fetchone()[0], 4)

    def test_raw_json_is_stored_verbatim(self):
        r = rec("a.ex.com", extra_field={"nested": [1, 2]})
        self.run_scan([r])
        raw = self.conn.execute("SELECT raw FROM httpx_results").fetchone()[0]
        self.assertEqual(raw, r.raw)

    def test_changed_event(self):
        self.run_scan(["a.ex.com"])
        stats, _ = self.run_scan([rec("a.ex.com", title="new title", code=403)])
        self.assertEqual(stats["changed"], 1)
        (_, host, details), = self.events("changed")
        self.assertEqual(details["changes"]["title"], {"old": "t", "new": "new title"})
        self.assertEqual(details["changes"]["status_code"], {"old": 200, "new": 403})
        self.assertEqual(self.sub("a.ex.com")["title"], "new title")

    def test_cdn_ip_rotation_is_not_a_change(self):
        self.run_scan([rec("a.ex.com", cdn=True, cdn_name="cloudflare", a=["1.1.1.1"])])
        stats, _ = self.run_scan([rec("a.ex.com", cdn=True, cdn_name="cloudflare", a=["1.0.0.1"])])
        self.assertEqual(stats["changed"], 0)

    def test_offline_and_back_online_never_deleted(self):
        self.run_scan(["a.ex.com", "b.ex.com"])
        stats, _ = self.run_scan(["a.ex.com"], probed=["a.ex.com", "b.ex.com"], dns=["a.ex.com"])
        self.assertEqual(stats["went_offline"], 1)
        b = self.sub("b.ex.com")
        self.assertEqual((b["status"], b["offline_reason"], b["dns_resolves"]), ("offline", "dns", 0))
        last_seen = b["last_seen"]
        stats, _ = self.run_scan(["a.ex.com"], probed=["a.ex.com", "b.ex.com"])
        self.assertEqual(stats["still_offline"], 1)
        self.assertEqual(self.sub("b.ex.com")["last_seen"], last_seen)
        stats, _ = self.run_scan(["a.ex.com", "b.ex.com"])
        self.assertEqual(stats["back_online"], 1)
        self.assertEqual(self.sub("b.ex.com")["status"], "active")
        self.assertEqual([e[0] for e in self.events() if e[1] == "b.ex.com"], ["new", "offline", "back_online"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0], 2)

    def test_failed_probe_never_marks_offline(self):
        self.run_scan(["a.ex.com", "b.ex.com"])
        stats, res = self.run_scan([], probed=["a.ex.com", "b.ex.com"], probe_ok=False)
        self.assertEqual(stats["went_offline"], 0)
        self.assertEqual(self.sub("b.ex.com")["status"], "active")
        self.assertTrue(any("NOT applied" in w for w in res.warnings))

    def test_mass_offline_guard(self):
        hosts = [f"h{i}.ex.com" for i in range(10)]
        self.run_scan(hosts)
        stats, res = self.run_scan(hosts[:1], probed=hosts)
        self.assertTrue(stats["offline_guard_tripped"])
        self.assertEqual(stats["went_offline"], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM subdomains WHERE status='active'").fetchone()[0], 10)
        stats, _ = self.run_scan(hosts[:1], probed=hosts, force=True)
        self.assertEqual(stats["went_offline"], 9)

    def test_failed_records_and_out_of_scope_ignored(self):
        stats, _ = self.run_scan([rec("a.ex.com", failed=True), rec("evil.com"), rec("notex.com")])
        self.assertEqual(stats["new"], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0], 0)

    def test_primary_prefers_https(self):
        self.run_scan([rec("a.ex.com", scheme="http", port="80", title="plain"), rec("a.ex.com", title="tls")])
        row = self.sub("a.ex.com")
        self.assertEqual((row["scheme"], row["title"]), ("https", "tls"))
        self.assertEqual(json.loads(row["urls"]), ["http://a.ex.com", "https://a.ex.com"])
        primary = self.conn.execute("SELECT url FROM httpx_results WHERE id = ?", (row["last_result_id"],)).fetchone()[0]
        self.assertEqual(primary, "https://a.ex.com")

    def test_overlapping_roots(self):
        self.run_scan(["api.dev.ex.com", "www.ex.com"])
        with db.transaction(self.conn):
            dev_id = db.ensure_root(self.conn, "dev.ex.com")
            sid = self.conn.execute("INSERT INTO scans(started_at, status) VALUES(?, 'running')", (db.utcnow(),)).lastrowid
        records = [rec("api.dev.ex.com", title="changed"), rec("new.dev.ex.com")]
        res = RootResult(root="dev.ex.com", root_id=dev_id, scan_id=sid, httpx=records,
                         sources={"api.dev.ex.com": set(), "new.dev.ex.com": {"bruteforce"}},
                         probed={"api.dev.ex.com", "new.dev.ex.com"}, probe_ok=True)
        stats = ingest(self.conn, res)  # must not violate UNIQUE(host)
        self.assertEqual((stats["new"], stats["changed"]), (1, 1))
        self.assertEqual(self.sub("api.dev.ex.com")["root_id"], self.root_id, "keeps the root that found it first")
        self.assertEqual(self.sub("new.dev.ex.com")["root_id"], dev_id)
        self.assertEqual(self.sub("www.ex.com")["status"], "active", "hosts outside dev.ex.com are untouched")
        root_of_event = self.conn.execute(
            "SELECT e.root_id FROM events e JOIN subdomains s ON s.id = e.subdomain_id "
            "WHERE s.host = 'api.dev.ex.com' AND e.type = 'changed'").fetchone()[0]
        self.assertEqual(root_of_event, self.root_id)

    def test_tags_survive_rescans(self):
        self.run_scan(["a.ex.com"])
        with db.transaction(self.conn):
            tag = db.ensure_tag(self.conn, "interesting")
            self.conn.execute("INSERT INTO subdomain_tags VALUES(?, ?, ?)", (self.sub("a.ex.com")["id"], tag, db.utcnow()))
        self.run_scan([], probed=["a.ex.com"])
        self.run_scan(["a.ex.com"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM subdomain_tags").fetchone()[0], 1)


class HostTests(unittest.TestCase):
    def test_normalize(self):
        cases = {
            "WWW.Ex.com.": "www.ex.com", "*.ex.com": "ex.com", "https://a.ex.com:8443/x?y": "a.ex.com",
            "1.2.3.4": None, "": None, "no_dot": None, "a b.com": None, "-bad.ex.com": None,
            "_dmarc.ex.com": "_dmarc.ex.com", "bücher.de": "xn--bcher-kva.de",
        }
        for value, expected in cases.items():
            self.assertEqual(normalize_host(value), expected, value)

    def test_scope(self):
        self.assertTrue(in_scope("a.ex.com", "ex.com"))
        self.assertTrue(in_scope("ex.com", "ex.com"))
        self.assertFalse(in_scope("notex.com", "ex.com"))


class ArgTests(unittest.TestCase):
    def test_key_value(self):
        cfg = parse_args(["domain=ex.com", "brute=false", "threads=5", "--timeout", "3", "--force"], env={})
        self.assertEqual((cfg.domain, cfg.brute, cfg.threads, cfg.timeout, cfg.force), ("ex.com", False, 5, 3, True))

    def test_env_and_bare_domains(self):
        cfg = parse_args([], env={"DOMAIN": "env.com", "SCAN_BRUTE": "no"})
        self.assertEqual((cfg.domain, cfg.brute), ("env.com", False))
        cfg = parse_args(["a.com", "b.com"], env={"DOMAIN": "env.com"})
        self.assertEqual(cfg.domain, "a.com,b.com")

    def test_unknown_option(self):
        with self.assertRaises(SystemExit):
            parse_args(["nope=1"], env={})
        with self.assertRaises(SystemExit):
            parse_args(["brute=maybe"], env={})


if __name__ == "__main__":
    unittest.main()
