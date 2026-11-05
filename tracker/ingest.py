"""Merge the results of one root-domain scan into the database.

Positive evidence (httpx answered) is always applied. Negative evidence
(a known host did not answer) is only applied when the probe stage finished
cleanly and the mass-offline guard did not trip – so a crashed tool, a timeout
or a broken network on the scanner side can never flip everything "offline".
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .db import hosts_in_scope, jdump, jload, transaction, utcnow
from .hosts import in_scope, normalize_host

# Fields compared between consecutive successful probes to emit "changed" events.
CHANGE_FIELDS = ("url", "status_code", "title", "webserver", "location", "tech", "cname", "ips")
SNAPSHOT_FIELDS = (
    "url", "scheme", "port", "status_code", "title", "webserver", "content_type", "content_length",
    "location", "tech", "ips", "cname", "cdn_name", "body_hash", "favicon",
    "tls_subject_cn", "tls_issuer", "tls_not_after",
)
JSON_FIELDS = {"tech", "ips", "cname", "urls"}


@dataclass
class HttpxRecord:
    phase: str      # main | san | recheck
    raw: str        # the exact JSON line httpx wrote
    data: dict


@dataclass
class RootResult:
    root: str
    root_id: int
    scan_id: int
    sources: dict[str, set[str]] = field(default_factory=dict)   # candidate host -> discovery sources
    dns: dict[str, dict] = field(default_factory=dict)           # resolved host -> dnsx record
    dns_checked: set[str] = field(default_factory=set)           # hosts dnsx was asked about
    dns_ok: bool = False                                         # dnsx stage completed
    httpx: list[HttpxRecord] = field(default_factory=list)
    probed: set[str] = field(default_factory=set)                # hosts sent to httpx
    probe_ok: bool = False                                       # every httpx stage completed
    wildcard: bool | None = None                                 # None = not tested this scan
    warnings: list[str] = field(default_factory=list)


@dataclass
class IngestOptions:
    force_offline: bool = False
    guard_min_active: int = 5      # guard only applies when at least this many hosts were active
    guard_ratio: float = 0.8       # ...and at least this share of them disappeared at once


def host_of_record(rec: dict) -> str | None:
    for key in ("input", "url", "host"):
        host = normalize_host(rec.get(key))
        if host:
            return host
    return None


def _primary_sort_key(rec: dict):
    scheme = rec.get("scheme") or ""
    try:
        port = int(rec.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return (
        scheme != "https",
        port not in (443, 80),
        port,
        rec.get("url") or "",
    )


def _int(value):
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def snapshot(rec: dict) -> dict:
    tls = rec.get("tls") or {}
    issuer = tls.get("issuer_cn")
    if not issuer and tls.get("issuer_org"):
        org = tls["issuer_org"]
        issuer = org[0] if isinstance(org, list) and org else org
    body_hash = (rec.get("hash") or {}).get("body_sha256") if isinstance(rec.get("hash"), dict) else None
    return {
        "url": rec.get("url"),
        "scheme": rec.get("scheme"),
        "port": _int(rec.get("port")),
        "status_code": _int(rec.get("status_code")),
        "title": rec.get("title") or None,
        "webserver": rec.get("webserver") or None,
        "content_type": rec.get("content_type") or None,
        "content_length": _int(rec.get("content_length")),
        "location": rec.get("location") or None,
        "tech": sorted(set(rec.get("tech") or [])),
        "ips": sorted(set((rec.get("a") or []) + (rec.get("aaaa") or []))),
        "cname": sorted(set(rec.get("cname") or [])),
        "cdn_name": (rec.get("cdn_name") or None) if rec.get("cdn") else None,
        "body_hash": body_hash,
        "favicon": rec.get("favicon") or None,
        "tls_subject_cn": tls.get("subject_cn") or None,
        "tls_issuer": issuer or None,
        "tls_not_after": tls.get("not_after") or None,
    }


def row_snapshot(row) -> dict:
    out = {}
    for key in SNAPSHOT_FIELDS:
        value = row[key]
        out[key] = jload(value, []) if key in JSON_FIELDS else value
    return out


def diff(old: dict, new: dict) -> dict:
    changes = {}
    for key in CHANGE_FIELDS:
        if key == "ips" and (old.get("cdn_name") or new.get("cdn_name")):
            continue  # CDN edge IPs rotate constantly; not a meaningful change
        if old.get(key) != new.get(key):
            changes[key] = {"old": old.get(key), "new": new.get(key)}
    return changes


def _dns_lists(rec: dict | None):
    if not rec:
        return [], [], []
    return (sorted(set(rec.get("a") or [])), sorted(set(rec.get("aaaa") or [])), sorted(set(rec.get("cname") or [])))


def ingest(conn, res: RootResult, opts: IngestOptions | None = None) -> dict:
    """Apply one root's scan results. Returns the stats dict stored in scan_roots."""
    opts = opts or IngestOptions()
    now = utcnow()

    # ---- group httpx output by host --------------------------------------
    by_host: dict[str, list[HttpxRecord]] = {}
    for rec in res.httpx:
        if rec.data.get("failed"):
            continue
        host = host_of_record(rec.data)
        if not host or not in_scope(host, res.root):
            continue
        by_host.setdefault(host, []).append(rec)

    stats = {
        "candidates": len(res.sources),
        "resolved": len(res.dns),
        "probed": len(res.probed),
        "alive": len(by_host),
        "new": 0,
        "back_online": 0,
        "changed": 0,
        "went_offline": 0,
        "still_offline": 0,
        "unchanged": 0,
        "offline_guard_tripped": False,
    }

    with transaction(conn):
        existing = {row["host"]: row for row in hosts_in_scope(conn, res.root)}

        # ---- offline guard --------------------------------------------------
        active_before = [h for h, r in existing.items() if r["status"] == "active"]
        missing_active = [h for h in active_before if h not in by_host and h in res.probed]
        allow_negative = res.probe_ok
        if not res.probe_ok:
            res.warnings.append("httpx did not finish cleanly – offline transitions were NOT applied")
        elif (
            not opts.force_offline
            and len(active_before) >= opts.guard_min_active
            and len(missing_active) / len(active_before) >= opts.guard_ratio
        ):
            allow_negative = False
            stats["offline_guard_tripped"] = True
            res.warnings.append(
                f"offline guard: {len(missing_active)}/{len(active_before)} previously active hosts did not answer; "
                "assuming a scanner-side problem and NOT marking them offline (re-run with force=true to override)"
            )

        # ---- alive hosts ----------------------------------------------------
        for host, records in sorted(by_host.items()):
            records.sort(key=lambda r: _primary_sort_key(r.data))
            primary = records[0]
            snap = snapshot(primary.data)
            urls = sorted({r.data.get("url") for r in records if r.data.get("url")})
            sources = set(res.sources.get(host, set()))
            row = existing.get(host)

            if row is None:
                values = dict(snap)
                values.update(
                    root_id=res.root_id, host=host, status="active", first_seen=now, last_seen=now,
                    last_checked=now, status_changed_at=now, first_scan_id=res.scan_id,
                    last_seen_scan_id=res.scan_id, last_checked_scan_id=res.scan_id, seen_count=1,
                    sources=jdump(sorted(sources)), dns_resolves=1,
                    urls=jdump(urls),
                )
                for key in ("tech", "ips", "cname"):
                    values[key] = jdump(values[key])
                cols = ", ".join(values)
                marks = ", ".join("?" for _ in values)
                sub_id = conn.execute(f"INSERT INTO subdomains({cols}) VALUES({marks})", list(values.values())).lastrowid
                _event(conn, res, sub_id, "new", now, {
                    "url": snap["url"], "status_code": snap["status_code"], "title": snap["title"],
                    "sources": sorted(sources),
                })
                stats["new"] += 1
            else:
                sub_id = row["id"]
                old = row_snapshot(row)
                changes = diff(old, snap)
                merged_sources = sorted(set(jload(row["sources"], [])) | sources)
                updates = dict(snap)
                for key in ("tech", "ips", "cname"):
                    updates[key] = jdump(updates[key])
                updates.update(
                    status="active", last_seen=now, last_checked=now, last_seen_scan_id=res.scan_id,
                    last_checked_scan_id=res.scan_id, seen_count=row["seen_count"] + 1,
                    sources=jdump(merged_sources), dns_resolves=1, offline_reason=None, urls=jdump(urls),
                )
                if row["status"] != "active":
                    updates["status_changed_at"] = now
                assignments = ", ".join(f"{k} = ?" for k in updates)
                conn.execute(f"UPDATE subdomains SET {assignments} WHERE id = ?", [*updates.values(), sub_id])
                if row["status"] != "active":
                    _event(conn, res, sub_id, "back_online", now, {
                        "offline_since": row["status_changed_at"], "url": snap["url"],
                        "status_code": snap["status_code"], "changes": changes,
                    })
                    stats["back_online"] += 1
                elif changes:
                    _event(conn, res, sub_id, "changed", now, {"changes": changes})
                    stats["changed"] += 1
                else:
                    stats["unchanged"] += 1

            primary_id = None
            for rec in records:  # records[0] is the primary result
                d = rec.data
                rid = conn.execute(
                    "INSERT INTO httpx_results(scan_id, subdomain_id, observed_at, phase, url, status_code, title, "
                    "webserver, content_length, body_hash, raw) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        res.scan_id, sub_id, now, rec.phase, d.get("url"), _int(d.get("status_code")),
                        d.get("title"), d.get("webserver"), _int(d.get("content_length")),
                        (d.get("hash") or {}).get("body_sha256") if isinstance(d.get("hash"), dict) else None,
                        rec.raw,
                    ),
                ).lastrowid
                primary_id = primary_id or rid
            conn.execute("UPDATE subdomains SET last_result_id = ? WHERE id = ?", (primary_id, sub_id))
            if res.dns_ok and host in res.dns_checked:
                _dns_row(conn, res, sub_id, host, now)

        # ---- known hosts that did not answer ----------------------------
        for host, row in sorted(existing.items()):
            if host in by_host or host not in res.probed:
                continue
            if not allow_negative:
                continue
            resolves = None
            if res.dns_ok and host in res.dns_checked:
                resolves = 1 if host in res.dns else 0
                _dns_row(conn, res, row["id"], host, now)
            reason = "dns" if resolves == 0 else "http"
            if row["status"] == "active":
                conn.execute(
                    "UPDATE subdomains SET status = 'offline', status_changed_at = ?, last_checked = ?, "
                    "last_checked_scan_id = ?, dns_resolves = ?, offline_reason = ? WHERE id = ?",
                    (now, now, res.scan_id, resolves, reason, row["id"]),
                )
                _event(conn, res, row["id"], "offline", now, {
                    "reason": reason, "last_seen": row["last_seen"], "last_url": row["url"],
                    "last_status_code": row["status_code"],
                })
                stats["went_offline"] += 1
            else:
                conn.execute(
                    "UPDATE subdomains SET last_checked = ?, last_checked_scan_id = ?, dns_resolves = ?, "
                    "offline_reason = ? WHERE id = ?",
                    (now, res.scan_id, resolves, reason, row["id"]),
                )
                stats["still_offline"] += 1

        conn.execute(
            "UPDATE roots SET last_scan_id = ?, last_scan_at = ?, wildcard = COALESCE(?, wildcard) WHERE id = ?",
            (res.scan_id, now, None if res.wildcard is None else int(res.wildcard), res.root_id),
        )
    return stats


def _event(conn, res: RootResult, sub_id: int, etype: str, now: str, details: dict) -> None:
    conn.execute(
        "INSERT INTO events(scan_id, root_id, subdomain_id, type, created_at, details) "
        "SELECT ?, root_id, id, ?, ?, ? FROM subdomains WHERE id = ?",
        (res.scan_id, etype, now, jdump(details), sub_id),
    )


def _dns_row(conn, res: RootResult, sub_id: int, host: str, now: str) -> None:
    rec = res.dns.get(host)
    a, aaaa, cname = _dns_lists(rec)
    conn.execute(
        "INSERT INTO dns_results(scan_id, subdomain_id, observed_at, resolves, a, aaaa, cname, raw) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (res.scan_id, sub_id, now, 1 if rec else 0, jdump(a), jdump(aaaa), jdump(cname),
         json.dumps(rec, separators=(",", ":")) if rec else None),
    )
