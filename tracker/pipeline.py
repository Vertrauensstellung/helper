"""Runs the discovery/validation tools for one root domain.

    subfinder (passive)  ─┐
    dnsx brute force     ─┼─> unique ─> dnsx resolve ─> httpx ─> TLS-SAN round ─> recheck ─> ingest
    known hosts (DB)     ─┤
    root + import file   ─┘

Every tool runs with stdin=/dev/null, in its own process group, with a hard
timeout. Raw tool output is kept under <data>/scans/<scan_id>/<root>/.
"""
from __future__ import annotations

import json
import os
import random
import re
import shutil
import signal
import string
import subprocess
import time
from dataclasses import dataclass

from .hosts import in_scope, normalize_host
from .ingest import HttpxRecord, RootResult

HTTPX_PROBE_FLAGS = [
    "-sc", "-cl", "-ct", "-location", "-title", "-server", "-td", "-method", "-ip", "-cname", "-cdn",
    "-favicon", "-hash", "sha256", "-tls-grab", "-rt", "-lc", "-wc", "-irh", "-ob",
]
COMMON_PD_FLAGS = ["-silent", "-nc", "-duc"]


def tool_bin(name: str) -> str:
    return os.environ.get(f"{name.upper()}_BIN", name)


@dataclass
class ToolResult:
    name: str
    ok: bool
    returncode: int | None
    timed_out: bool
    duration: float
    stderr_tail: str


class ToolRunner:
    def __init__(self, workdir: str, log):
        self.workdir = workdir
        self.log = log
        os.makedirs(workdir, exist_ok=True)

    def run(self, name: str, args: list[str], timeout: float) -> ToolResult:
        stderr_path = os.path.join(self.workdir, f"{name}.stderr.log")
        self.log("  $ " + " ".join(a.replace(self.workdir + os.sep, "") for a in args))
        start = time.monotonic()
        timed_out = False
        with open(stderr_path, "wb") as err:
            try:
                proc = subprocess.Popen(
                    args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                    cwd=self.workdir, start_new_session=True,
                )
            except FileNotFoundError:
                self.log(f"  ! {name}: binary not found: {args[0]}")
                return ToolResult(name, False, None, False, 0.0, f"binary not found: {args[0]}")
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                self.log(f"  ! {name}: timed out after {int(timeout)}s – stopping it, partial output is kept")
            finally:
                if proc.poll() is None:
                    _kill_group(proc)
        duration = time.monotonic() - start
        tail = _tail(stderr_path)
        ok = proc.returncode == 0 and not timed_out
        if not ok and not timed_out:
            self.log(f"  ! {name}: exit code {proc.returncode}: {tail[-500:]}")
        return ToolResult(name, ok, proc.returncode, timed_out, duration, tail)


def _kill_group(proc: subprocess.Popen) -> None:
    for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def _tail(path: str, limit: int = 4000) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - limit))
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return ""


def read_jsonl(path: str):
    """Yield (raw_line, obj) for every complete JSON line; tolerates a truncated last line."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                yield line, json.loads(line)
            except ValueError:
                continue


def write_lines(path: str, items) -> int:
    items = sorted(set(items))
    with open(path, "w") as fh:
        for item in items:
            fh.write(item + "\n")
    return len(items)


def tool_version(name: str) -> str | None:
    try:
        out = subprocess.run([tool_bin(name), "-version"], stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=30, text=True)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or "") + (out.stderr or "")
    match = re.search(r"Current Version:\s*v?([0-9][^\s\x1b]*)", text)
    return f"v{match.group(1)}" if match else None


class RootPipeline:
    def __init__(self, cfg, root: str, root_id: int, scan_id: int, workdir: str, known: dict[str, str], log):
        self.cfg = cfg
        self.root = root
        self.workdir = workdir
        self.known = known  # host -> status for hosts already in the DB
        self.log = log
        self.runner = ToolRunner(workdir, log)
        self.res = RootResult(root=root, root_id=root_id, scan_id=scan_id)
        self.stage_stats: dict = {}

    # ------------------------------------------------------------------ helpers
    def _add(self, host: str | None, source: str | None) -> bool:
        host = normalize_host(host)
        if not host or not in_scope(host, self.root):
            return False
        bucket = self.res.sources.setdefault(host, set())
        if source:
            bucket.add(source)
        return True

    def _path(self, name: str) -> str:
        return os.path.join(self.workdir, name)

    def _resolver_args(self, flag: str) -> list[str]:
        return [flag, self.cfg.resolvers] if self.cfg.resolvers else []

    def _dnsx(self, name: str, hosts_file: str, out: str, extra: list[str] | None = None, retry: int = 2) -> ToolResult:
        args = [
            tool_bin("dnsx"), "-l", hosts_file, "-a", "-aaaa", "-cname", "-json", "-omit-raw", "-o", out,
            *COMMON_PD_FLAGS, "-retry", str(retry), "-t", str(self.cfg.dns_threads),
            *self._resolver_args("-r"),
        ]
        if self.cfg.dns_rate_limit > 0:
            args += ["-rl", str(self.cfg.dns_rate_limit)]
        args += extra or []
        try:
            count = sum(1 for _ in open(hosts_file))
        except OSError:
            count = 0
        timeout = self.cfg.dns_max_time or max(300, count * 0.05 + 300)
        return self.runner.run(name, args, timeout)

    # ------------------------------------------------------------------ stages
    def passive(self) -> None:
        if not self.cfg.passive:
            return
        out = self._path("subfinder.jsonl")
        args = [
            tool_bin("subfinder"), "-d", self.root, "-oJ", "-cs", "-o", out, *COMMON_PD_FLAGS,
            "-timeout", str(self.cfg.subfinder_timeout), "-max-time", str(self.cfg.subfinder_max_time),
        ]
        if self.cfg.subfinder_all:
            args.append("-all")
        if self.cfg.subfinder_sources:
            args += ["-s", self.cfg.subfinder_sources]
        if self.cfg.provider_config:
            args += ["-pc", self.cfg.provider_config]
        if self.cfg.proxy:
            args += ["-proxy", self.cfg.proxy]
        result = self.runner.run("subfinder", args, timeout=self.cfg.subfinder_max_time * 60 + 180)
        found = 0
        for _, rec in read_jsonl(out):
            sources = rec.get("sources") or ([rec["source"]] if rec.get("source") else [])
            tags = [f"subfinder:{s}" for s in sources] or ["subfinder"]
            if self._add(rec.get("host"), None):
                host = normalize_host(rec.get("host"))
                self.res.sources[host].update(tags)
                found += 1
        self.stage_stats["passive"] = found
        if not result.ok:
            self.res.warnings.append(f"subfinder {'timed out' if result.timed_out else 'failed'}; "
                                     f"{found} results were still used")
        self.log(f"  subfinder: {found} in-scope names ({result.duration:.0f}s)")

    def detect_wildcard(self) -> tuple[set[str], set[str]]:
        probes = ["".join(random.choices(string.ascii_lowercase + string.digits, k=14)) for _ in range(5)]
        path = self._path("wildcard-probe.txt")
        write_lines(path, [f"{p}.{self.root}" for p in probes])
        out = self._path("wildcard-probe.jsonl")
        self._dnsx("dnsx-wildcard", path, out, retry=2)
        ips, cnames = set(), set()
        for _, rec in read_jsonl(out):
            ips.update(rec.get("a") or [])
            ips.update(rec.get("aaaa") or [])
            cnames.update(rec.get("cname") or [])
        self.res.wildcard = bool(ips or cnames)
        if self.res.wildcard:
            self.log(f"  wildcard DNS detected for *.{self.root} -> {sorted(ips | cnames)[:6]}")
        return ips, cnames

    def brute(self) -> None:
        if not self.cfg.brute:
            return
        words = load_wordlist(self.cfg.wordlist)
        if not words:
            self.res.warnings.append(f"wordlist {self.cfg.wordlist!r} is empty or unreadable – brute force skipped")
            return
        wild_ips, wild_cnames = self.detect_wildcard()
        cands = self._path("brute-candidates.txt")
        write_lines(cands, [f"{w}.{self.root}" for w in words])
        out = self._path("brute.jsonl")
        extra = ["-auto-wildcard"] if self.res.wildcard else []
        result = self._dnsx("dnsx-brute", cands, out, extra=extra)
        found = filtered = 0
        for _, rec in read_jsonl(out):
            addrs = set(rec.get("a") or []) | set(rec.get("aaaa") or [])
            cnames = set(rec.get("cname") or [])
            if not addrs and not cnames:
                continue
            if self.res.wildcard and ((addrs and addrs <= wild_ips) or (cnames & wild_cnames)):
                filtered += 1
                continue
            if self._add(rec.get("host"), "bruteforce"):
                found += 1
        self.stage_stats.update(brute=found, brute_wildcard_filtered=filtered, wordlist_size=len(words))
        if not result.ok:
            self.res.warnings.append("dnsx brute force did not finish cleanly")
        self.log(f"  dnsx brute force: {found} hits from {len(words)} words"
                 + (f" ({filtered} wildcard answers dropped)" if filtered else ""))

    def extra_inputs(self) -> None:
        self._add(self.root, "input")
        for host in self.known:
            self._add(host, None)
        if self.cfg.import_file:
            added = 0
            try:
                with open(self.cfg.import_file) as fh:
                    for line in fh:
                        if self._add(line.split("#", 1)[0].strip(), "import"):
                            added += 1
            except OSError as exc:
                self.res.warnings.append(f"import file unreadable: {exc}")
            self.stage_stats["imported"] = added

    def resolve(self, hosts: set[str], tag: str) -> bool:
        if not hosts:
            return True
        path = self._path(f"resolve-{tag}.txt")
        write_lines(path, hosts)
        out = self._path(f"dnsx-{tag}.jsonl")
        result = self._dnsx(f"dnsx-{tag}", path, out, retry=3)
        self.res.dns_checked.update(hosts)
        for _, rec in read_jsonl(out):
            host = normalize_host(rec.get("host"))
            if host in hosts and (rec.get("a") or rec.get("aaaa")):
                self.res.dns[host] = rec
        return result.ok

    def httpx(self, hosts: set[str], phase: str, *, timeout: int | None = None, retries: int | None = None,
              threads: int | None = None) -> bool:
        if not hosts:
            return True
        timeout = timeout or self.cfg.timeout
        retries = self.cfg.retries if retries is None else retries
        threads = threads or self.cfg.threads
        path = self._path(f"httpx-{phase}-targets.txt")
        write_lines(path, hosts)
        out = self._path(f"httpx-{phase}.jsonl")
        args = [
            tool_bin("httpx"), "-l", path, "-o", out, "-json", "-no-stdin", *COMMON_PD_FLAGS,
            *HTTPX_PROBE_FLAGS, "-t", str(threads), "-rl", str(self.cfg.rate_limit),
            "-timeout", str(timeout), "-retries", str(retries), *self._resolver_args("-r"),
        ]
        if self.cfg.ports:
            args += ["-p", self.cfg.ports]
        if self.cfg.follow_redirects:
            args.append("-fr")
        if self.cfg.proxy:
            args += ["-proxy", self.cfg.proxy]
        ports = max(1, len(self.cfg.ports.split(","))) if self.cfg.ports else 2
        budget = len(hosts) * ports * timeout * (retries + 1) / max(1, threads)
        result = self.runner.run(f"httpx-{phase}", args, timeout=self.cfg.httpx_max_time or (budget * 3 + 600))
        alive = 0
        for raw, rec in read_jsonl(out):
            self.res.httpx.append(HttpxRecord(phase=phase, raw=raw, data=rec))
            alive += 0 if rec.get("failed") else 1
        self.res.probed.update(hosts)
        self.log(f"  httpx[{phase}]: {alive} responses from {len(hosts)} hosts ({result.duration:.0f}s)")
        if not result.ok:
            self.res.warnings.append(f"httpx[{phase}] {'timed out' if result.timed_out else 'failed'}")
        return result.ok

    def alive_hosts(self) -> set[str]:
        out = set()
        for rec in self.res.httpx:
            if not rec.data.get("failed"):
                host = normalize_host(rec.data.get("input")) or normalize_host(rec.data.get("url"))
                if host:
                    out.add(host)
        return out

    def tls_names(self) -> set[str]:
        names = set()
        for rec in self.res.httpx:
            tls = rec.data.get("tls") or {}
            for name in list(tls.get("subject_an") or []) + [tls.get("subject_cn")]:
                host = normalize_host(name)
                if host and in_scope(host, self.root):
                    names.add(host)
        return names

    # ------------------------------------------------------------------ run
    def run(self) -> RootResult:
        self.passive()
        self.brute()
        self.extra_inputs()

        candidates = set(self.res.sources)
        self.log(f"  {len(candidates)} unique candidates ({len(self.known)} already tracked)")
        dns_ok = self.resolve(candidates, "main")
        self.log(f"  dnsx: {len(self.res.dns)} of {len(candidates)} resolve")

        # Known hosts are always re-probed (that is how we notice them going offline);
        # new names only when they resolve. If dnsx itself failed, probe everything.
        targets = set(self.known) | set(self.res.dns) | {self.root}
        if not dns_ok:
            self.res.warnings.append("dnsx resolve stage did not finish cleanly – probing every candidate")
            targets = candidates
        probe_ok = self.httpx(targets, "main")

        if self.cfg.san:
            new_names = self.tls_names() - set(self.res.sources)
            if new_names:
                for host in new_names:
                    self._add(host, "tls-san")
                self.log(f"  TLS certificates revealed {len(new_names)} new in-scope names")
                dns_ok = self.resolve(new_names, "san") and dns_ok
                san_targets = {h for h in new_names if h in self.res.dns}
                probe_ok = self.httpx(san_targets, "san") and probe_ok
            self.stage_stats["tls_san"] = len(new_names)

        if self.cfg.recheck:
            missing = {h for h, status in self.known.items() if status == "active"} - self.alive_hosts()
            if missing:
                self.log(f"  rechecking {len(missing)} previously active hosts with longer timeouts")
                probe_ok = self.httpx(missing, "recheck", timeout=self.cfg.timeout * 2,
                                      retries=self.cfg.retries + 1, threads=min(self.cfg.threads, 20)) and probe_ok
            self.stage_stats["rechecked"] = len(missing)

        self.res.dns_ok = dns_ok
        self.res.probe_ok = probe_ok
        return self.res


def load_wordlist(path: str) -> list[str]:
    words = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.split("#", 1)[0].strip().lower().strip(".")
                if not word or "*" in word or " " in word:
                    continue
                if normalize_host(f"{word}.example.com"):
                    words.append(word)
    except OSError:
        return []
    return sorted(set(words))


def cleanup_dir(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
