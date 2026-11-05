"""Scanner entrypoint.

    python -m tracker.scan domain=example.com
    python -m tracker.scan domain=a.com,b.com brute=false
    python -m tracker.scan domain=all                # re-scan every tracked root
    python -m tracker.scan file=/data/targets.txt
    python -m tracker.scan mode=worker               # process the dashboard's scan queue
    python -m tracker.scan mode=status | mode=backup | mode=init | help

Every option can be given as key=value, --key=value, --key value, or as an
environment variable SCAN_<KEY> (DOMAIN / DOMAINS also work without prefix).
"""
from __future__ import annotations

import fcntl
import os
import signal
import sys
import time
import traceback
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

from . import __version__
from .db import backup as db_backup
from .db import connect, data_dir, ensure_root, hosts_in_scope, jdump, jload, set_meta, transaction, utcnow
from .hosts import normalize_root, parse_domain_list
from .ingest import IngestOptions, ingest
from .pipeline import RootPipeline, tool_version

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_WORDLIST = os.path.join(APP_DIR, "wordlists", "common-subdomains.txt")
PROVIDER_CONFIG_CANDIDATES = (
    "/config/subfinder/provider-config.yaml",
    "/config/provider-config.yaml",
)


def _bool(value) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "y", "on"):
        return True
    if text in ("0", "false", "no", "n", "off", ""):
        return False
    raise ValueError(f"expected true/false, got {value!r}")


@dataclass
class Config:
    mode: str = "scan"                 # scan | worker | status | backup | init
    domain: str = ""                   # comma separated, or "all"
    file: str = ""                     # file with one root domain per line
    passive: bool = True               # run subfinder
    subfinder_all: bool = True         # subfinder -all (every source, slower, better coverage)
    subfinder_sources: str = ""        # subfinder -s ...
    subfinder_max_time: int = 10       # minutes per root
    subfinder_timeout: int = 30        # seconds per source request
    provider_config: str = ""          # subfinder API keys (auto-detected under /config)
    brute: bool = True                 # dnsx brute force with the wordlist
    wordlist: str = DEFAULT_WORDLIST
    san: bool = True                   # probe new in-scope names found in TLS certificates
    recheck: bool = True               # re-probe vanished hosts once more with longer timeouts
    import_file: str = ""              # extra hosts (one per line) to validate, e.g. from other tools
    ports: str = ""                    # httpx -p (empty: httpx default https:443 -> http:80 fallback)
    follow_redirects: bool = False
    threads: int = 50                  # httpx threads
    rate_limit: int = 150              # httpx requests/second
    timeout: int = 10                  # httpx timeout per request (seconds)
    retries: int = 2                   # httpx retries
    httpx_max_time: int = 0            # hard limit per httpx run in seconds (0 = derived from target count)
    dns_threads: int = 100
    dns_rate_limit: int = 0            # dnsx requests/second (0 = unlimited)
    dns_max_time: int = 0
    resolvers: str = ""                # resolvers file for dnsx + httpx
    proxy: str = ""                    # http/socks proxy for httpx + subfinder
    force: bool = False                # bypass the mass-offline guard
    guard_ratio: float = 0.8
    guard_min_active: int = 5
    trigger: str = "cli"
    poll_interval: int = 10            # worker: seconds between queue polls
    schedule_hours: float = 0          # worker: auto re-scan all roots every N hours (0 = off)

    @classmethod
    def keys(cls):
        return {f.name: f for f in fields(cls)}


ALIASES = {"domains": "domain", "d": "domain", "import": "import_file", "hosts_file": "import_file",
           "domains_file": "file", "list": "file", "rl": "rate_limit", "t": "threads"}
# Options the dashboard queue may set (never paths/proxy that could read arbitrary files).
QUEUE_SAFE_KEYS = {"passive", "subfinder_all", "subfinder_max_time", "brute", "san", "recheck", "ports",
                   "follow_redirects", "threads", "rate_limit", "timeout", "retries", "force"}


def parse_args(argv: list[str], env: dict | None = None) -> Config:
    env = os.environ if env is None else env
    known = Config.keys()
    raw: dict[str, str] = {}

    for name in known:
        for var in (f"SCAN_{name.upper()}",) + (("DOMAIN", "DOMAINS") if name == "domain" else ()):
            if env.get(var):
                raw[name] = env[var]
    if env.get("MODE") and "mode" not in raw:
        raw["mode"] = env["MODE"]

    cli_domains: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        i += 1
        if arg in ("-h", "--help", "help"):
            raw["mode"] = "help"
            continue
        if arg.startswith("--"):
            arg = arg[2:]
            if "=" not in arg:
                if i < len(argv) and not argv[i].startswith("--") and "=" not in argv[i]:
                    arg = f"{arg}={argv[i]}"
                    i += 1
                else:
                    arg = f"{arg}=true"
        if "=" not in arg:  # bare word: a mode or a domain
            if arg in ("scan", "worker", "status", "backup", "init"):
                raw["mode"] = arg
            else:
                cli_domains.append(arg)
            continue
        key, value = arg.split("=", 1)
        key = ALIASES.get(key.strip().lower().replace("-", "_"), key.strip().lower().replace("-", "_"))
        if key not in known:
            raise SystemExit(f"unknown option {key!r}. Run with 'help' to see all options.")
        if key == "domain":
            cli_domains.append(value)
        else:
            raw[key] = value
    if cli_domains:  # command line domains replace DOMAIN from the environment
        raw["domain"] = ",".join(cli_domains)
    return build_config(raw)


def build_config(raw: dict) -> Config:
    cfg = Config()
    known = Config.keys()
    for key, value in raw.items():
        f = known[key]
        try:
            if f.type in ("bool", bool):
                value = _bool(value)
            elif f.type in ("int", int):
                value = int(value)
            elif f.type in ("float", float):
                value = float(value)
            else:
                value = str(value).strip()
        except ValueError as exc:
            raise SystemExit(f"invalid value for {key}: {exc}")
        setattr(cfg, key, value)
    if not cfg.provider_config:
        for path in PROVIDER_CONFIG_CANDIDATES:
            if os.path.isfile(path):
                cfg.provider_config = path
                break
    return cfg


def log(msg: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[{stamp}] {msg}"
    print(line, flush=True)
    if _LOG_FH is not None:
        _LOG_FH.write(line + "\n")
        _LOG_FH.flush()


_LOG_FH = None


class Interrupted(Exception):
    pass


def _on_signal(signum, _frame):
    raise Interrupted(f"received signal {signum}")


# --------------------------------------------------------------------------- #
# Scanning                                                                    #
# --------------------------------------------------------------------------- #
def resolve_roots(conn, cfg: Config) -> list[str]:
    tokens = parse_domain_list(cfg.domain) if cfg.domain else []
    if cfg.file:
        try:
            with open(cfg.file) as fh:
                tokens += parse_domain_list(fh.read())
        except OSError as exc:
            raise SystemExit(f"cannot read file={cfg.file}: {exc}")
    roots: list[str] = []
    for token in tokens:
        if token.lower() == "all":
            roots += [r[0] for r in conn.execute("SELECT domain FROM roots ORDER BY domain")]
            continue
        root = normalize_root(token)
        if not root:
            raise SystemExit(f"not a valid domain: {token!r}")
        roots.append(root)
    seen, ordered = set(), []
    for root in roots:
        if root not in seen:
            seen.add(root)
            ordered.append(root)
    return ordered


class RootLock:
    """Advisory per-root lock so two scans never process the same root at once."""

    def __init__(self, root: str):
        lock_dir = os.path.join(data_dir(), "locks")
        os.makedirs(lock_dir, exist_ok=True)
        self.path = os.path.join(lock_dir, f"{root}.lock")
        self.fh = None

    def acquire(self) -> bool:
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            self.fh.close()
            self.fh = None
            return False

    def release(self) -> None:
        if self.fh:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None


def _mark_stale_scans(conn) -> None:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ")
    with transaction(conn):
        conn.execute("UPDATE scans SET status = 'failed', error = 'interrupted (stale)', finished_at = ? "
                     "WHERE status = 'running' AND started_at < ?", (utcnow(), cutoff))
        conn.execute("UPDATE scan_roots SET status = 'failed', error = 'interrupted (stale)', finished_at = ? "
                     "WHERE status = 'running' AND started_at < ?", (utcnow(), cutoff))


def run_scan(cfg: Config, conn=None) -> tuple[int, str]:
    """Scan every requested root. Returns (scan_id, status)."""
    global _LOG_FH
    own_conn = conn is None
    conn = conn or connect()
    roots = resolve_roots(conn, cfg)
    if not roots:
        raise SystemExit("no domains given. Example: domain=example.com  (or domain=all to re-scan everything)")
    _mark_stale_scans(conn)

    params = {k: getattr(cfg, k) for k in Config.keys() if k not in ("mode", "trigger", "poll_interval", "schedule_hours")}
    versions = {name: tool_version(name) for name in ("subfinder", "dnsx", "httpx")}
    with transaction(conn):
        scan_id = conn.execute(
            "INSERT INTO scans(started_at, status, trigger, params, tool_versions) VALUES(?, 'running', ?, ?, ?)",
            (utcnow(), cfg.trigger, jdump(params), jdump(versions)),
        ).lastrowid
        out_dir = os.path.join(data_dir(), "scans", f"{scan_id:05d}")
        conn.execute("UPDATE scans SET output_dir = ? WHERE id = ?", (out_dir, scan_id))
    os.makedirs(out_dir, exist_ok=True)
    _LOG_FH = open(os.path.join(out_dir, "scan.log"), "a")

    log(f"subtrack {__version__} scan #{scan_id}: {len(roots)} root(s): {', '.join(roots[:10])}"
        + (" ..." if len(roots) > 10 else ""))
    log(f"tools: {versions}")
    missing_tools = [n for n, v in versions.items() if v is None]
    if missing_tools:
        log(f"WARNING: could not determine version of {missing_tools} – are they installed?")

    statuses: list[str] = []
    scan_error = None
    interrupted = None
    try:
        for index, root in enumerate(roots, 1):
            log(f"[{index}/{len(roots)}] {root}")
            statuses.append(scan_one_root(conn, cfg, scan_id, root, out_dir))
    except Interrupted as exc:
        interrupted = exc
        scan_error = f"interrupted: {exc}"
        statuses.append("failed")
        log(f"scan interrupted: {exc}")
    except Exception as exc:  # pragma: no cover - last-resort safety net
        scan_error = f"{type(exc).__name__}: {exc}"
        statuses.append("failed")
        log("unexpected error:\n" + traceback.format_exc())
    finally:
        if not statuses:
            final = "failed"
        elif all(s == "skipped" for s in statuses):
            final = "skipped"
        elif all(s in ("success", "skipped") for s in statuses):
            final = "success"
        elif all(s == "failed" for s in statuses):
            final = "failed"
        else:
            final = "partial"
        with transaction(conn):
            conn.execute("UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE id = ?",
                         (final, utcnow(), scan_error, scan_id))
            conn.execute("UPDATE scan_roots SET status = 'failed', finished_at = ?, error = 'interrupted' "
                         "WHERE scan_id = ? AND status = 'running'", (utcnow(), scan_id))
        log(f"scan #{scan_id} finished: {final}. raw output: {out_dir}")
        _LOG_FH.close()
        _LOG_FH = None
        if own_conn:
            conn.close()
    if interrupted is not None:
        raise interrupted  # let the caller (CLI / worker) stop as well
    return scan_id, final


def scan_one_root(conn, cfg: Config, scan_id: int, root: str, out_dir: str) -> str:
    lock = RootLock(root)
    with transaction(conn):
        root_id = ensure_root(conn, root)
        conn.execute("INSERT OR REPLACE INTO scan_roots(scan_id, root_id, status, started_at) VALUES(?, ?, 'running', ?)",
                     (scan_id, root_id, utcnow()))
    if not lock.acquire():
        msg = "another scan is currently processing this root – skipped"
        log(f"  {msg}")
        _finish_root(conn, scan_id, root_id, "skipped", {}, [msg], None)
        return "skipped"
    started = time.monotonic()
    try:
        known = {r["host"]: r["status"] for r in hosts_in_scope(conn, root)}
        workdir = os.path.join(out_dir, root)
        pipe = RootPipeline(cfg, root, root_id, scan_id, workdir, known, log)
        result = pipe.run()
        stats = ingest(conn, result, IngestOptions(force_offline=cfg.force, guard_ratio=cfg.guard_ratio,
                                                   guard_min_active=cfg.guard_min_active))
        stats.update(pipe.stage_stats)
        stats["wildcard"] = result.wildcard
        stats["duration_s"] = round(time.monotonic() - started, 1)
        status = "success" if not result.warnings else "partial"
        if not result.probe_ok and stats["alive"] == 0:
            status = "failed"
        _finish_root(conn, scan_id, root_id, status, stats, result.warnings, None)
        log(f"  => {status}: alive={stats['alive']} new={stats['new']} back_online={stats['back_online']} "
            f"changed={stats['changed']} went_offline={stats['went_offline']} ({stats['duration_s']}s)")
        for warning in result.warnings:
            log(f"  warning: {warning}")
        return status
    except Interrupted:
        _finish_root(conn, scan_id, root_id, "failed", {}, [], "interrupted")
        raise
    except Exception as exc:
        log(f"  root failed: {type(exc).__name__}: {exc}\n{traceback.format_exc()}")
        _finish_root(conn, scan_id, root_id, "failed", {}, [], f"{type(exc).__name__}: {exc}")
        return "failed"
    finally:
        lock.release()


def _finish_root(conn, scan_id, root_id, status, stats, warnings, error) -> None:
    with transaction(conn):
        conn.execute("UPDATE scan_roots SET status = ?, finished_at = ?, stats = ?, warnings = ?, error = ? "
                     "WHERE scan_id = ? AND root_id = ?",
                     (status, utcnow(), jdump(stats), jdump(warnings), error, scan_id, root_id))


# --------------------------------------------------------------------------- #
# Worker (dashboard queue)                                                     #
# --------------------------------------------------------------------------- #
def run_worker(cfg: Config) -> int:
    conn = connect()
    with transaction(conn):
        conn.execute("UPDATE scan_requests SET status = 'failed', error = 'worker restarted', finished_at = ? "
                     "WHERE status = 'running'", (utcnow(),))
    log(f"worker started (poll every {cfg.poll_interval}s"
        + (f", automatic re-scan of all roots every {cfg.schedule_hours}h" if cfg.schedule_hours else "") + ")")
    while True:
        with transaction(conn):
            set_meta(conn, "worker_heartbeat", utcnow())
        if cfg.schedule_hours > 0:
            _maybe_schedule(conn, cfg)
        req = _claim_request(conn)
        if req is None:
            time.sleep(cfg.poll_interval)
            continue
        log(f"queue request #{req['id']}: {req['domains']}")
        job = Config(**{k: getattr(cfg, k) for k in Config.keys()})
        job.mode, job.domain, job.file, job.trigger = "scan", req["domains"], "", f"queue:{req['source']}"
        for key, value in (jload(req["params"], {}) or {}).items():
            if key in QUEUE_SAFE_KEYS:
                setattr(job, key, build_config({key: value}).__dict__[key])
        status, scan_id, error = "failed", None, None
        try:
            scan_id, scan_status = run_scan(job, conn)
            status = "done" if scan_status in ("success", "partial", "skipped") else "failed"
        except SystemExit as exc:
            error = str(exc)
        except Interrupted:
            # stopped mid-scan (docker stop / Ctrl+C): put the request back so it runs again on restart
            with transaction(conn):
                conn.execute("UPDATE scan_requests SET status = 'queued', started_at = NULL WHERE id = ?", (req["id"],))
            raise
        except Exception as exc:  # pragma: no cover
            error = f"{type(exc).__name__}: {exc}"
        with transaction(conn):
            conn.execute("UPDATE scan_requests SET status = ?, finished_at = ?, scan_id = ?, error = ? WHERE id = ?",
                         (status, utcnow(), scan_id, error, req["id"]))


def _claim_request(conn):
    with transaction(conn):
        return conn.execute(
            "UPDATE scan_requests SET status = 'running', started_at = ? "
            "WHERE id = (SELECT id FROM scan_requests WHERE status = 'queued' ORDER BY id LIMIT 1) "
            "RETURNING *", (utcnow(),),
        ).fetchone()


def _maybe_schedule(conn, cfg: Config) -> None:
    with transaction(conn):
        last = conn.execute("SELECT value FROM meta WHERE key = 'last_scheduled_scan'").fetchone()
        due = True
        if last and last[0]:
            last_dt = datetime.strptime(last[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            due = datetime.now(timezone.utc) - last_dt >= timedelta(hours=cfg.schedule_hours)
        pending = conn.execute("SELECT 1 FROM scan_requests WHERE source = 'schedule' AND status IN ('queued','running')").fetchone()
        has_roots = conn.execute("SELECT 1 FROM roots LIMIT 1").fetchone()
        if due and not pending and has_roots:
            conn.execute("INSERT INTO scan_requests(domains, source, requested_at) VALUES('all', 'schedule', ?)", (utcnow(),))
            set_meta(conn, "last_scheduled_scan", utcnow())
            log("scheduled re-scan of all roots queued")


# --------------------------------------------------------------------------- #
# Small utilities                                                              #
# --------------------------------------------------------------------------- #
def print_status() -> None:
    conn = connect()
    try:
        _print_status(conn)
    finally:
        conn.close()


def _print_status(conn) -> None:
    rows = conn.execute(
        "SELECT r.domain, r.last_scan_at, "
        "  SUM(s.status = 'active') AS active, SUM(s.status = 'offline') AS offline, COUNT(s.id) AS total "
        "FROM roots r LEFT JOIN subdomains s ON s.root_id = r.id GROUP BY r.id ORDER BY r.domain"
    ).fetchall()
    if not rows:
        print("no domains tracked yet – run: domain=example.com")
        return
    print(f"{'domain':40} {'total':>7} {'active':>7} {'offline':>8}  last scan")
    for r in rows:
        print(f"{r['domain']:40} {r['total']:>7} {r['active'] or 0:>7} {r['offline'] or 0:>8}  {r['last_scan_at'] or '-'}")
    for r in conn.execute("SELECT id, started_at, finished_at, status FROM scans ORDER BY id DESC LIMIT 5"):
        print(f"scan #{r['id']}: {r['status']:8} {r['started_at']} -> {r['finished_at'] or '…'}")


def usage() -> str:
    lines = [__doc__.strip(), "", "Options (default):"]
    for name, f in Config.keys().items():
        lines.append(f"  {name:20} {getattr(Config, name, f.default)!r}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    cfg = parse_args(sys.argv[1:] if argv is None else argv)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    if cfg.mode == "help":
        print(usage())
        return 0
    if cfg.mode == "init":
        connect().close()
        print(f"database ready: {os.path.join(data_dir(), 'tracker.db')}")
        return 0
    if cfg.mode == "status":
        print_status()
        return 0
    if cfg.mode == "backup":
        dest = os.path.join(data_dir(), "backups", f"tracker-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.db")
        conn = connect()
        try:
            db_backup(conn, dest)
        finally:
            conn.close()
        print(f"backup written: {dest}")
        return 0
    if cfg.mode == "worker":
        try:
            return run_worker(cfg)
        except Interrupted:
            log("worker stopped")
            return 0
    if cfg.mode != "scan":
        raise SystemExit(f"unknown mode {cfg.mode!r}")
    try:
        _, status = run_scan(cfg)
    except Interrupted:
        return 130
    return 0 if status in ("success", "partial", "skipped") else 1


if __name__ == "__main__":
    sys.exit(main())
