"""Query/mutation handlers for the dashboard API (pure functions over a sqlite3 connection)."""
from __future__ import annotations

import csv
import io
import re
import shlex
from datetime import datetime, timedelta, timezone

from ..db import ensure_tag, jdump, jload, transaction, utcnow
from ..hosts import normalize_root, parse_domain_list


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


SORTS = {
    "host": "s.host", "first_seen": "s.first_seen", "last_seen": "s.last_seen", "last_checked": "s.last_checked",
    "status_code": "s.status_code", "title": "s.title", "status": "s.status", "webserver": "s.webserver",
    "status_changed_at": "s.status_changed_at", "seen_count": "s.seen_count", "root": "r.domain",
}
TEXT_FIELDS = {
    "host": "s.host", "title": "s.title", "server": "s.webserver", "webserver": "s.webserver", "tech": "s.tech",
    "ip": "s.ips", "cname": "s.cname", "url": "s.urls", "notes": "s.notes", "source": "s.sources",
    "cdn": "s.cdn_name", "location": "s.location", "root": "r.domain", "domain": "r.domain", "tls": "s.tls_subject_cn",
    "issuer": "s.tls_issuer", "favicon": "s.favicon", "hash": "s.body_hash", "type": "s.content_type",
}
FREE_TEXT = ("s.host", "s.title", "s.webserver", "s.tech", "s.ips", "s.urls", "s.cname", "s.notes", "s.cdn_name")


def _days_ago(days) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=float(days))).strftime("%Y-%m-%dT%H:%M:%SZ")


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _code_clause(value: str, params: list) -> str:
    parts = []
    for token in re.split(r"[,\s]+", value.strip()):
        if not token:
            continue
        if re.fullmatch(r"[1-5]xx", token, re.I):
            base = int(token[0]) * 100
            parts.append("s.status_code BETWEEN ? AND ?")
            params += [base, base + 99]
        elif token.isdigit():
            parts.append("s.status_code = ?")
            params.append(int(token))
        else:
            raise ApiError(400, f"invalid status code filter: {token!r}")
    return "(" + " OR ".join(parts) + ")" if parts else "1"


def _tag_exists(name_param: str) -> str:
    return ("EXISTS (SELECT 1 FROM subdomain_tags st JOIN tags t ON t.id = st.tag_id "
            f"WHERE st.subdomain_id = s.id AND t.name = {name_param} COLLATE NOCASE)")


def _parse_query(q: str, where: list, params: list) -> None:
    """Search syntax: free words, field:value, -field:value, "quoted phrases"."""
    try:
        tokens = shlex.split(q)
    except ValueError:
        tokens = q.split()
    for token in tokens:
        negate = token.startswith("-") and len(token) > 1
        if negate:
            token = token[1:]
        clause = None
        field, sep, value = token.partition(":")
        field = field.lower()
        if sep and value and (field in TEXT_FIELDS or field in ("code", "status", "tag", "port", "scheme")):
            if field == "code":
                clause = _code_clause(value, params)
            elif field == "status":
                clause = "s.status = ?"
                params.append(value.lower())
            elif field == "tag":
                clause = _tag_exists("?")
                params.append(value)
            elif field == "port":
                clause = "s.urls LIKE ?"
                params.append(_like(f":{value}"))
                if value in ("80", "443"):
                    clause = "s.port = ?"
                    params[-1] = int(value)
            elif field == "scheme":
                clause = "s.scheme = ?"
                params.append(value.lower())
            else:
                clause = f"{TEXT_FIELDS[field]} LIKE ? ESCAPE '\\'"
                params.append(_like(value))
        else:
            clause = "(" + " OR ".join(f"COALESCE({col}, '') LIKE ? ESCAPE '\\'" for col in FREE_TEXT) + ")"
            params += [_like(token)] * len(FREE_TEXT)
        where.append(f"NOT {clause}" if negate else clause)


# Filter keys that accept several values. The HTTP layer joins repeated query parameters
# with "\n"; root/status/code/tag also accept commas (tech and server values may contain commas).
MULTI_KEYS = {"root", "status", "code", "tech", "server", "tag", "no_tag", "type"}


def multi(args: dict, key: str, commas: bool = True) -> list[str]:
    raw = args.get(key) or ""
    if isinstance(raw, (list, tuple)):
        raw = "\n".join(str(v) for v in raw)
    parts = str(raw).split("\n")
    if commas:
        parts = [p for chunk in parts for p in chunk.split(",")]
    out = []
    for part in (p.strip() for p in parts):
        if part and part not in out:
            out.append(part)
    return out


def _in(column: str, values: list, params: list) -> str:
    params += values
    return f"{column} IN ({','.join('?' * len(values))})"


def _filters(args: dict, skip: str | None = None) -> tuple[str, list]:
    """WHERE clause for the asset list. ``skip`` leaves one filter out (disjunctive facet counts)."""
    where, params = ["1"], []
    get = lambda key: str(args.get(key) or "").strip()  # noqa: E731
    roots = [r.lower() for r in multi(args, "root")] if skip != "root" else []
    if roots:
        where.append(_in("r.domain", roots, params))
    statuses = [v for v in multi(args, "status") if v in ("active", "offline")] if skip != "status" else []
    if statuses:
        where.append(_in("s.status", statuses, params))
    codes = multi(args, "code") if skip != "code" else []
    if codes:
        where.append(_code_clause(",".join(codes), params))
    techs = multi(args, "tech", commas=False) if skip != "tech" else []
    if techs:
        where.append("(" + " OR ".join("s.tech LIKE ? ESCAPE '\\'" for _ in techs) + ")")
        params += [_like(f'"{t}"') for t in techs]
    servers = multi(args, "server", commas=False) if skip != "server" else []
    if servers:
        where.append(_in("s.webserver", servers, params))
    for tag in (multi(args, "tag") if skip != "tag" else []):
        where.append(_tag_exists("?"))
        params.append(tag)
    for tag in multi(args, "no_tag"):
        where.append("NOT " + _tag_exists("?"))
        params.append(tag)
    if get("untagged") in ("1", "true"):
        where.append("NOT EXISTS (SELECT 1 FROM subdomain_tags st WHERE st.subdomain_id = s.id)")
    try:
        if get("new_days") and skip != "new_days":
            where.append("s.first_seen >= ?")
            params.append(_days_ago(get("new_days")))
        if get("changed_days"):
            where.append("s.status_changed_at >= ? AND s.status_changed_at > s.first_seen")
            params.append(_days_ago(get("changed_days")))
        if get("event_days"):
            etype = get("event") or None
            where.append("EXISTS (SELECT 1 FROM events e WHERE e.subdomain_id = s.id AND e.created_at >= ?"
                         + (" AND e.type = ?" if etype else "") + ")")
            params.append(_days_ago(get("event_days")))
            if etype:
                params.append(etype)
    except ValueError:
        raise ApiError(400, "day filters must be numbers")
    if get("ids"):
        try:
            ids = [int(x) for x in get("ids").split(",") if x.strip()]
        except ValueError:
            raise ApiError(400, "ids must be integers")
        where.append(f"s.id IN ({','.join('?' * len(ids)) or 'NULL'})")
        params += ids
    if get("q"):
        _parse_query(get("q"), where, params)
    return " AND ".join(where), params


def _tags_for(conn, ids: list[int]) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {i: [] for i in ids}
    if not ids:
        return out
    for chunk_start in range(0, len(ids), 900):
        chunk = ids[chunk_start:chunk_start + 900]
        rows = conn.execute(
            f"SELECT st.subdomain_id, t.id, t.name, t.color FROM subdomain_tags st JOIN tags t ON t.id = st.tag_id "
            f"WHERE st.subdomain_id IN ({','.join('?' * len(chunk))}) ORDER BY t.name", chunk)
        for r in rows:
            out[r[0]].append({"id": r[1], "name": r[2], "color": r[3]})
    return out


LIST_COLUMNS = (
    "s.id, s.host, r.domain AS root, s.status, s.status_code, s.title, s.webserver, s.tech, s.ips, s.cname, "
    "s.cdn_name, s.url, s.urls, s.scheme, s.port, s.first_seen, s.last_seen, s.last_checked, s.status_changed_at, "
    "s.seen_count, s.sources, s.offline_reason, s.content_length, s.location, s.dns_resolves"
)


def _row_out(row) -> dict:
    d = dict(row)
    for key in ("tech", "ips", "cname", "sources", "urls"):
        if key in d:
            d[key] = jload(d[key], [])
    return d


def list_subdomains(conn, args: dict) -> dict:
    where, params = _filters(args)
    sort = SORTS.get(args.get("sort") or "first_seen", "s.first_seen")
    order = "ASC" if (args.get("order") or "desc").lower() == "asc" else "DESC"
    try:
        page = max(1, int(args.get("page") or 1))
        per_page = min(1000, max(1, int(args.get("per_page") or 50)))
    except ValueError:
        raise ApiError(400, "page/per_page must be integers")
    base = f"FROM subdomains s JOIN roots r ON r.id = s.root_id WHERE {where}"
    total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT {LIST_COLUMNS} {base} ORDER BY {sort} {order} NULLS LAST, s.host ASC LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page]).fetchall()
    items = [_row_out(r) for r in rows]
    tags = _tags_for(conn, [i["id"] for i in items])
    for item in items:
        item["tags"] = tags[item["id"]]
    return {"items": items, "total": total, "page": page, "per_page": per_page}


def iter_export_rows(conn, args: dict):
    where, params = _filters(args)
    sort = SORTS.get(args.get("sort") or "host", "s.host")
    order = "ASC" if (args.get("order") or "asc").lower() == "asc" else "DESC"
    rows = conn.execute(
        f"SELECT {LIST_COLUMNS} FROM subdomains s JOIN roots r ON r.id = s.root_id WHERE {where} "
        f"ORDER BY {sort} {order} NULLS LAST, s.host ASC", params).fetchall()
    items = [_row_out(r) for r in rows]
    tags = _tags_for(conn, [i["id"] for i in items])
    for item in items:
        item["tags"] = [t["name"] for t in tags[item["id"]]]
        yield item


EXPORT_COLUMNS = ("host", "root", "status", "url", "status_code", "title", "webserver", "tech", "ips", "cname",
                  "cdn_name", "first_seen", "last_seen", "last_checked", "seen_count", "tags", "sources", "offline_reason")


def export_csv(items) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPORT_COLUMNS)
    for item in items:
        row = []
        for col in EXPORT_COLUMNS:
            value = item.get(col)
            if isinstance(value, list):
                value = " ".join(str(v) for v in value)
            value = "" if value is None else str(value)
            if value[:1] in ("=", "+", "-", "@", "\t", "\r"):  # spreadsheet formula injection
                value = "'" + value
            row.append(value)
        writer.writerow(row)
    return buf.getvalue()


def get_subdomain(conn, sub_id: int) -> dict:
    row = conn.execute(
        "SELECT s.*, r.domain AS root FROM subdomains s JOIN roots r ON r.id = s.root_id WHERE s.id = ?",
        (sub_id,)).fetchone()
    if not row:
        raise ApiError(404, "subdomain not found")
    d = _row_out(row)
    d["tags"] = _tags_for(conn, [sub_id])[sub_id]
    last = conn.execute("SELECT raw FROM httpx_results WHERE id = ?", (row["last_result_id"],)).fetchone()
    d["last_result"] = jload(last[0], None) if last else None
    dns = conn.execute("SELECT * FROM dns_results WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1", (sub_id,)).fetchone()
    d["dns"] = {"resolves": dns["resolves"], "a": jload(dns["a"], []), "aaaa": jload(dns["aaaa"], []),
                "cname": jload(dns["cname"], []), "observed_at": dns["observed_at"]} if dns else None
    return d


def subdomain_history(conn, sub_id: int) -> dict:
    if not conn.execute("SELECT 1 FROM subdomains WHERE id = ?", (sub_id,)).fetchone():
        raise ApiError(404, "subdomain not found")
    results = [dict(r) for r in conn.execute(
        "SELECT h.id, h.scan_id, h.observed_at, h.phase, h.url, h.status_code, h.title, h.webserver, "
        "h.content_length, h.body_hash FROM httpx_results h WHERE h.subdomain_id = ? ORDER BY h.id DESC LIMIT 1000",
        (sub_id,))]
    events = [dict(r) | {"details": jload(r["details"], {})} for r in conn.execute(
        "SELECT id, scan_id, type, created_at, details FROM events WHERE subdomain_id = ? ORDER BY id DESC", (sub_id,))]
    dns = [dict(r) | {"a": jload(r["a"], []), "aaaa": jload(r["aaaa"], []), "cname": jload(r["cname"], [])}
           for r in conn.execute("SELECT id, scan_id, observed_at, resolves, a, aaaa, cname FROM dns_results "
                                 "WHERE subdomain_id = ? ORDER BY id DESC LIMIT 1000", (sub_id,))]
    # scans in which the host was probed but did not answer
    checks = [dict(r) for r in conn.execute(
        "SELECT sc.id AS scan_id, sc.started_at FROM scans sc "
        "JOIN scan_roots sr ON sr.scan_id = sc.id JOIN subdomains s ON s.root_id = sr.root_id "
        "WHERE s.id = ? AND sc.id >= s.first_scan_id AND sr.status IN ('success','partial') "
        "ORDER BY sc.id DESC LIMIT 1000", (sub_id,))]
    return {"results": results, "events": events, "dns": dns, "scans": checks}


def get_result(conn, result_id: int) -> dict:
    row = conn.execute("SELECT raw FROM httpx_results WHERE id = ?", (result_id,)).fetchone()
    if not row:
        raise ApiError(404, "result not found")
    return jload(row[0], {})


def update_subdomain(conn, sub_id: int, body: dict) -> dict:
    if "notes" not in body:
        raise ApiError(400, "nothing to update")
    with transaction(conn):
        cur = conn.execute("UPDATE subdomains SET notes = ? WHERE id = ?", (str(body["notes"])[:20000], sub_id))
        if not cur.rowcount:
            raise ApiError(404, "subdomain not found")
    return get_subdomain(conn, sub_id)


def _valid_tag_name(name) -> str:
    name = str(name or "").strip()
    if not name or len(name) > 64 or "," in name:
        raise ApiError(400, "tag names must be 1-64 characters and contain no commas")
    return name


def _valid_color(color) -> str | None:
    if color is None:
        return None
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", str(color)):
        raise ApiError(400, "color must look like #rrggbb")
    return str(color)


def add_tag(conn, sub_id: int, body: dict) -> dict:
    name = _valid_tag_name(body.get("name"))
    with transaction(conn):
        if not conn.execute("SELECT 1 FROM subdomains WHERE id = ?", (sub_id,)).fetchone():
            raise ApiError(404, "subdomain not found")
        tag_id = ensure_tag(conn, name, _valid_color(body.get("color")))
        conn.execute("INSERT OR IGNORE INTO subdomain_tags(subdomain_id, tag_id, created_at) VALUES(?,?,?)",
                     (sub_id, tag_id, utcnow()))
    return {"tags": _tags_for(conn, [sub_id])[sub_id]}


def remove_tag(conn, sub_id: int, tag_id: int) -> dict:
    with transaction(conn):
        conn.execute("DELETE FROM subdomain_tags WHERE subdomain_id = ? AND tag_id = ?", (sub_id, tag_id))
    return {"tags": _tags_for(conn, [sub_id])[sub_id]}


def bulk_tags(conn, body: dict) -> dict:
    add = [_valid_tag_name(n) for n in body.get("add") or []]
    remove = [_valid_tag_name(n) for n in body.get("remove") or []]
    if not add and not remove:
        raise ApiError(400, "add or remove at least one tag")
    if body.get("ids"):
        try:
            ids = sorted({int(i) for i in body["ids"]})
        except (TypeError, ValueError):
            raise ApiError(400, "ids must be integers")
    elif isinstance(body.get("filter"), dict):
        flt = {k: "\n".join(map(str, v)) if isinstance(v, list) else str(v) for k, v in body["filter"].items()}
        where, params = _filters(flt)
        ids = [r[0] for r in conn.execute(
            f"SELECT s.id FROM subdomains s JOIN roots r ON r.id = s.root_id WHERE {where}", params)]
    else:
        raise ApiError(400, "give ids or filter")
    now = utcnow()
    with transaction(conn):
        for name in add:
            tag_id = ensure_tag(conn, name)
            conn.executemany("INSERT OR IGNORE INTO subdomain_tags(subdomain_id, tag_id, created_at) VALUES(?,?,?)",
                             [(i, tag_id, now) for i in ids])
        for name in remove:
            row = conn.execute("SELECT id FROM tags WHERE name = ?", (name,)).fetchone()
            if row:
                conn.executemany("DELETE FROM subdomain_tags WHERE subdomain_id = ? AND tag_id = ?",
                                 [(i, row[0]) for i in ids])
    return {"updated": len(ids)}


def list_tags(conn) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT t.id, t.name, t.color, t.created_at, COUNT(st.subdomain_id) AS count FROM tags t "
        "LEFT JOIN subdomain_tags st ON st.tag_id = t.id GROUP BY t.id ORDER BY t.name COLLATE NOCASE")]


def create_tag(conn, body: dict) -> dict:
    name = _valid_tag_name(body.get("name"))
    with transaction(conn):
        if conn.execute("SELECT 1 FROM tags WHERE name = ?", (name,)).fetchone():
            raise ApiError(409, "tag already exists")
        tag_id = ensure_tag(conn, name, _valid_color(body.get("color")))
    return dict(conn.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone())


def update_tag(conn, tag_id: int, body: dict) -> dict:
    with transaction(conn):
        row = conn.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone()
        if not row:
            raise ApiError(404, "tag not found")
        name = _valid_tag_name(body["name"]) if "name" in body else row["name"]
        color = _valid_color(body.get("color")) or row["color"]
        clash = conn.execute("SELECT id FROM tags WHERE name = ? AND id != ?", (name, tag_id)).fetchone()
        if clash:
            raise ApiError(409, "another tag already has that name")
        conn.execute("UPDATE tags SET name = ?, color = ? WHERE id = ?", (name, color, tag_id))
    return dict(conn.execute("SELECT * FROM tags WHERE id = ?", (tag_id,)).fetchone())


def delete_tag(conn, tag_id: int) -> dict:
    with transaction(conn):
        conn.execute("DELETE FROM subdomain_tags WHERE tag_id = ?", (tag_id,))
        cur = conn.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
        if not cur.rowcount:
            raise ApiError(404, "tag not found")
    return {"deleted": tag_id}


def list_roots(conn) -> list[dict]:
    week = _days_ago(7)
    return [dict(r) for r in conn.execute(
        "SELECT r.id, r.domain, r.created_at, r.last_scan_id, r.last_scan_at, r.wildcard, r.notes, "
        "  COUNT(s.id) AS total, COALESCE(SUM(s.status = 'active'), 0) AS active, "
        "  COALESCE(SUM(s.status = 'offline'), 0) AS offline, "
        "  COALESCE(SUM(s.first_seen >= ?), 0) AS new_7d, "
        "  (SELECT sr.status FROM scan_roots sr WHERE sr.scan_id = r.last_scan_id AND sr.root_id = r.id) AS last_scan_status "
        "FROM roots r LEFT JOIN subdomains s ON s.root_id = r.id GROUP BY r.id ORDER BY r.domain", (week,))]


def update_root(conn, root_id: int, body: dict) -> dict:
    with transaction(conn):
        cur = conn.execute("UPDATE roots SET notes = ? WHERE id = ?", (str(body.get("notes", ""))[:20000], root_id))
        if not cur.rowcount:
            raise ApiError(404, "root not found")
    return {"ok": True}


def overview(conn) -> dict:
    one = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731
    week = _days_ago(7)
    last_scan = conn.execute("SELECT id, status, started_at, finished_at FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    heartbeat = conn.execute("SELECT value FROM meta WHERE key = 'worker_heartbeat'").fetchone()
    online = False
    if heartbeat and heartbeat[0]:
        hb = datetime.strptime(heartbeat[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        online = datetime.now(timezone.utc) - hb < timedelta(minutes=3)
    return {
        "roots": one("SELECT COUNT(*) FROM roots"),
        "total": one("SELECT COUNT(*) FROM subdomains"),
        "active": one("SELECT COUNT(*) FROM subdomains WHERE status = 'active'"),
        "offline": one("SELECT COUNT(*) FROM subdomains WHERE status = 'offline'"),
        "new_7d": one("SELECT COUNT(*) FROM subdomains WHERE first_seen >= ?", week),
        "events_7d": {r[0]: r[1] for r in conn.execute(
            "SELECT type, COUNT(*) FROM events WHERE created_at >= ? GROUP BY type", (week,))},
        "scans": one("SELECT COUNT(*) FROM scans"),
        "last_scan": dict(last_scan) if last_scan else None,
        "running_scans": one("SELECT COUNT(*) FROM scans WHERE status = 'running'"),
        "worker": {"online": online, "heartbeat": heartbeat[0] if heartbeat else None},
        "queue": {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM scan_requests WHERE status IN ('queued','running') GROUP BY status")},
    }


def facets(conn, args: dict) -> dict:
    """Counts for every filter facet, restricted to the current filters. Each facet is counted with its
    own filter left out, so several values of one facet can be combined (OR) in the UI."""
    joins = "FROM subdomains s JOIN roots r ON r.id = s.root_id"

    def grouped(skip: str, select: str, group: str, extra: str = "", order: str = "c DESC", limit: int = 300):
        where, params = _filters(args, skip=skip)
        sql = (f"SELECT {select}, COUNT(*) AS c {joins}{extra} WHERE {where} GROUP BY {group} "
               f"ORDER BY {order} LIMIT {int(limit)}")
        return conn.execute(sql, params).fetchall()

    where_all, params_all = _filters(args)
    total = conn.execute(f"SELECT COUNT(*) {joins} WHERE {where_all}", params_all).fetchone()[0]
    status = {r[0]: r[1] for r in grouped("status", "s.status", "s.status")}
    root_counts = [dict(name=r[0], count=r[1]) for r in grouped("root", "r.domain", "r.domain", order="c DESC, r.domain")]
    codes = [dict(code=r[0], count=r[1]) for r in grouped(
        "code", "s.status_code", "s.status_code", order="s.status_code") if r[0] is not None]
    servers = [dict(name=r[0], count=r[1]) for r in grouped(
        "server", "s.webserver", "s.webserver", limit=200) if r[0]]
    tech = [dict(name=r[0], count=r[1]) for r in grouped(
        "tech", "j.value", "j.value", extra=", json_each(s.tech) j")]
    where_t, params_t = _filters(args, skip="tag")
    tag_rows = conn.execute(
        f"SELECT t.id, t.name, t.color, t.created_at, COUNT(st.subdomain_id) AS count FROM tags t "
        f"LEFT JOIN subdomain_tags st ON st.tag_id = t.id AND st.subdomain_id IN "
        f"(SELECT s.id {joins} WHERE {where_t}) GROUP BY t.id ORDER BY count DESC, t.name COLLATE NOCASE",
        params_t).fetchall()
    where_n, params_n = _filters(args, skip="new_days")
    new_counts = {}
    for days in (1, 7, 30, 90):
        new_counts[str(days)] = conn.execute(
            f"SELECT COUNT(*) {joins} WHERE {where_n} AND s.first_seen >= ?", [*params_n, _days_ago(days)]).fetchone()[0]
    return {
        "total": total, "status": status, "root_counts": root_counts, "codes": codes, "servers": servers,
        "tech": tech, "tags": [dict(r) for r in tag_rows], "new": new_counts,
        "roots": [r["domain"] for r in conn.execute("SELECT domain FROM roots ORDER BY domain")],
    }


def insights(conn, args: dict) -> dict:
    """Everything the overview page shows, scoped to an optional set of roots and a time range."""
    roots = [r.lower() for r in multi(args, "root")]
    sub_where, sub_params = "1", []
    ev_where, ev_params = "1", []
    if roots:
        marks = ",".join("?" * len(roots))
        sub_where = f"s.root_id IN (SELECT id FROM roots WHERE domain IN ({marks}))"
        ev_where = f"e.root_id IN (SELECT id FROM roots WHERE domain IN ({marks}))"
        sub_params, ev_params = list(roots), list(roots)
    today = datetime.now(timezone.utc).date()
    days_arg = str(args.get("days") or "30")
    if days_arg == "all":
        first = conn.execute(f"SELECT MIN(created_at) FROM events e WHERE {ev_where}", ev_params).fetchone()[0]
        start = datetime.strptime(first[:10], "%Y-%m-%d").date() if first else today
    else:
        try:
            start = today - timedelta(days=max(1, min(3650, int(days_arg))) - 1)
        except ValueError:
            raise ApiError(400, "days must be a number or 'all'")
    start_ts = start.strftime("%Y-%m-%dT00:00:00Z")

    # ---- daily series reconstructed from the event log ------------------------------------
    base = {r[0]: r[1] for r in conn.execute(
        f"SELECT type, COUNT(*) FROM events e WHERE {ev_where} AND created_at < ? GROUP BY type", [*ev_params, start_ts])}
    per_day: dict[str, dict] = {}
    for d, etype, n in conn.execute(
            f"SELECT substr(created_at, 1, 10), type, COUNT(*) FROM events e WHERE {ev_where} AND created_at >= ? "
            f"GROUP BY 1, 2", [*ev_params, start_ts]):
        per_day.setdefault(d, {})[etype] = n
    total = base.get("new", 0)
    active = total - base.get("offline", 0) + base.get("back_online", 0)
    series = []
    day = start
    while day <= today:
        key = day.isoformat()
        counts = per_day.get(key, {})
        total += counts.get("new", 0)
        active += counts.get("new", 0) - counts.get("offline", 0) + counts.get("back_online", 0)
        series.append({"date": key, "new": counts.get("new", 0), "changed": counts.get("changed", 0),
                       "offline": counts.get("offline", 0), "back_online": counts.get("back_online", 0),
                       "total": total, "active": active})
        day += timedelta(days=1)

    # ---- headline numbers -------------------------------------------------------------------
    one = lambda sql, *p: conn.execute(sql, p).fetchone()[0]  # noqa: E731

    def events_between(etype, start_days, end_days=None):
        if end_days is None:  # current period: open-ended, so events from this very second count too
            return one(f"SELECT COUNT(*) FROM events e WHERE {ev_where} AND type = ? AND created_at >= ?",
                       *ev_params, etype, _days_ago(start_days))
        return one(f"SELECT COUNT(*) FROM events e WHERE {ev_where} AND type = ? AND created_at >= ? AND created_at < ?",
                   *ev_params, etype, _days_ago(start_days), _days_ago(end_days))

    kpis = {
        "total": one(f"SELECT COUNT(*) FROM subdomains s WHERE {sub_where}", *sub_params),
        "active": one(f"SELECT COUNT(*) FROM subdomains s WHERE {sub_where} AND status = 'active'", *sub_params),
        "offline": one(f"SELECT COUNT(*) FROM subdomains s WHERE {sub_where} AND status = 'offline'", *sub_params),
        "roots": len(roots) if roots else one("SELECT COUNT(*) FROM roots"),
    }
    for etype in ("new", "changed", "offline", "back_online"):
        kpis[f"{etype}_7d"] = events_between(etype, 7)
        kpis[f"{etype}_prev_7d"] = events_between(etype, 14, 7)

    # ---- breakdowns of the current (active) surface -----------------------------------------
    act = f"FROM subdomains s WHERE {sub_where} AND s.status = 'active'"

    def top(select, extra="", where_extra="", limit=10):
        return [dict(name=r[0], count=r[1]) for r in conn.execute(
            f"SELECT {select}, COUNT(*) c FROM subdomains s{extra} WHERE {sub_where} AND s.status = 'active' "
            f"{where_extra} GROUP BY 1 ORDER BY c DESC LIMIT {int(limit)}", sub_params)]

    code_classes = {r[0]: r[1] for r in conn.execute(
        f"SELECT CASE WHEN status_code BETWEEN 200 AND 299 THEN '2xx' WHEN status_code BETWEEN 300 AND 399 THEN '3xx' "
        f"WHEN status_code BETWEEN 400 AND 499 THEN '4xx' WHEN status_code >= 500 THEN '5xx' ELSE 'other' END, COUNT(*) "
        f"{act} GROUP BY 1", sub_params)}
    soon = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expiring = [dict(r) for r in conn.execute(
        f"SELECT s.id, s.host, s.tls_not_after, s.tls_issuer {act} AND s.tls_not_after IS NOT NULL "
        f"AND s.tls_not_after <= ? ORDER BY s.tls_not_after LIMIT 10", [*sub_params, soon])]
    takeovers = [dict(r) | {"cname": jload(r["cname"], [])} for r in conn.execute(
        f"SELECT s.id, s.host, s.cname, s.status_changed_at FROM subdomains s WHERE {sub_where} AND s.status = 'offline' "
        f"AND s.offline_reason = 'dns' AND s.cname != '[]' ORDER BY s.status_changed_at DESC LIMIT 10", sub_params)]
    recent = list_events(conn, {"root": "\n".join(roots), "per_page": 8})["items"]
    domains = [r for r in list_roots(conn) if not roots or r["domain"] in roots]
    scans = list_scans(conn, {"per_page": 6})["items"]
    return {
        "range": {"start": start.isoformat(), "end": today.isoformat(), "days": days_arg},
        "series": series,
        "kpis": kpis,
        "code_classes": code_classes,
        "codes": top("s.status_code", where_extra="AND s.status_code IS NOT NULL", limit=8),
        "tech": top("j.value", extra=", json_each(s.tech) j"),
        "servers": top("s.webserver", where_extra="AND s.webserver IS NOT NULL", limit=8),
        "cdn": top("s.cdn_name", where_extra="AND s.cdn_name IS NOT NULL", limit=6),
        "sources": top("j.value", extra=", json_each(s.sources) j"),
        "expiring_tls": expiring,
        "takeover_candidates": takeovers,
        "recent_events": recent,
        "domains": domains,
        "scans": scans,
    }


def list_events(conn, args: dict) -> dict:
    where, params = ["1"], []
    roots = [r.lower() for r in multi(args, "root")]
    if roots:
        where.append(_in("r.domain", roots, params))
    if args.get("scan"):
        where.append("e.scan_id = ?")
        params.append(int(args["scan"]))
    if args.get("days"):
        try:
            where.append("e.created_at >= ?")
            params.append(_days_ago(args["days"]))
        except ValueError:
            raise ApiError(400, "days must be a number")
    if args.get("q"):
        where.append("s.host LIKE ? ESCAPE '\\'")
        params.append(_like(args["q"].strip()))
    joins = "FROM events e JOIN subdomains s ON s.id = e.subdomain_id JOIN roots r ON r.id = e.root_id"
    # counts per type for the same filters (the type filter itself excluded)
    type_counts = {r[0]: r[1] for r in conn.execute(
        f"SELECT e.type, COUNT(*) {joins} WHERE {' AND '.join(where)} GROUP BY e.type", params)}
    types = multi(args, "type")
    if types:
        where.append(_in("e.type", types, params))
    try:
        page = max(1, int(args.get("page") or 1))
        per_page = min(500, max(1, int(args.get("per_page") or 100)))
    except ValueError:
        raise ApiError(400, "page/per_page must be integers")
    base = f"{joins} WHERE {' AND '.join(where)}"
    total = conn.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT e.id, e.scan_id, e.type, e.created_at, e.details, s.id AS subdomain_id, s.host, s.status, "
        f"s.title, s.status_code, r.domain AS root {base} ORDER BY e.id DESC LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page])
    items = [dict(r) | {"details": jload(r["details"], {})} for r in rows]
    return {"items": items, "total": total, "page": page, "per_page": per_page, "type_counts": type_counts}


def list_scans(conn, args: dict) -> dict:
    page = max(1, int(args.get("page") or 1))
    per_page = min(200, max(1, int(args.get("per_page") or 50)))
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    scans = [dict(r) for r in conn.execute(
        "SELECT id, started_at, finished_at, status, trigger, error FROM scans ORDER BY id DESC LIMIT ? OFFSET ?",
        (per_page, (page - 1) * per_page))]
    ids = [s["id"] for s in scans]
    per_scan: dict[int, list] = {i: [] for i in ids}
    if ids:
        for r in conn.execute(
                f"SELECT sr.scan_id, r.domain, sr.status, sr.stats, sr.warnings FROM scan_roots sr "
                f"JOIN roots r ON r.id = sr.root_id WHERE sr.scan_id IN ({','.join('?' * len(ids))}) ORDER BY r.domain", ids):
            per_scan[r[0]].append({"domain": r[1], "status": r[2], "stats": jload(r[3], {}), "warnings": jload(r[4], [])})
    for s in scans:
        s["roots"] = per_scan[s["id"]]
        totals = {}
        for root in s["roots"]:
            for key in ("alive", "new", "went_offline", "back_online", "changed"):
                totals[key] = totals.get(key, 0) + int(root["stats"].get(key) or 0)
        s["totals"] = totals
    return {"items": scans, "total": total, "page": page, "per_page": per_page}


def get_scan(conn, scan_id: int) -> dict:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise ApiError(404, "scan not found")
    scan = dict(row)
    scan["params"] = jload(scan["params"], {})
    scan["tool_versions"] = jload(scan["tool_versions"], {})
    scan["roots"] = [dict(r) | {"stats": jload(r["stats"], {}), "warnings": jload(r["warnings"], [])} for r in conn.execute(
        "SELECT r.domain, sr.status, sr.started_at, sr.finished_at, sr.stats, sr.warnings, sr.error "
        "FROM scan_roots sr JOIN roots r ON r.id = sr.root_id WHERE sr.scan_id = ? ORDER BY r.domain", (scan_id,))]
    return scan


QUEUE_PARAM_TYPES = {"passive": bool, "brute": bool, "san": bool, "recheck": bool, "force": bool,
                     "subfinder_all": bool, "ports": str}


def create_scan_request(conn, body: dict) -> dict:
    raw = str(body.get("domains") or "").strip()
    if not raw:
        raise ApiError(400, "domains is required")
    if raw.lower() == "all":
        domains = ["all"]
    else:
        domains = []
        for token in parse_domain_list(raw):
            root = normalize_root(token)
            if not root:
                raise ApiError(400, f"not a valid domain: {token}")
            domains.append(root)
        if len(domains) > 1000:
            raise ApiError(400, "at most 1000 domains per request")
    params = {}
    for key, value in (body.get("params") or {}).items():
        kind = QUEUE_PARAM_TYPES.get(key)
        if kind is bool:
            params[key] = bool(value)
        elif kind is str:
            value = str(value).strip()
            if value and not re.fullmatch(r"[a-z0-9:,\-]{1,200}", value):
                raise ApiError(400, f"invalid value for {key}")
            if value:
                params[key] = value
    with transaction(conn):
        req_id = conn.execute(
            "INSERT INTO scan_requests(domains, params, source, requested_at) VALUES(?, ?, 'dashboard', ?)",
            (",".join(domains), jdump(params), utcnow())).lastrowid
    return dict(conn.execute("SELECT * FROM scan_requests WHERE id = ?", (req_id,)).fetchone())


def list_scan_requests(conn) -> list[dict]:
    return [dict(r) | {"params": jload(r["params"], {})} for r in conn.execute(
        "SELECT * FROM scan_requests ORDER BY id DESC LIMIT 100")]


def cancel_scan_request(conn, req_id: int) -> dict:
    with transaction(conn):
        cur = conn.execute("UPDATE scan_requests SET status = 'cancelled', finished_at = ? "
                           "WHERE id = ? AND status = 'queued'", (utcnow(), req_id))
        if not cur.rowcount:
            raise ApiError(409, "only queued requests can be cancelled")
    return {"cancelled": req_id}
