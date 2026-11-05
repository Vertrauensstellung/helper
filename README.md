# subtrack

Long-term subdomain tracking: discover → validate → store **forever** → see what changed.

```
            ┌─ subfinder (passive, all sources) ─┐
 domain ──▶ ├─ dnsx brute force (wildcard-safe) ─┼─▶ unique ─▶ dnsx resolve ─▶ httpx ─▶ TLS-SAN round ─▶ recheck ─▶ SQLite
            ├─ every host already in the DB ─────┤                                                        (full httpx JSON)
            └─ root + optional import file ──────┘
```

* **Only hosts that httpx validated are added.** Once added, a host is never deleted. Each host has a
  status (`active` / `offline`), `first_seen`, `last_seen`, `last_checked`, and its full history.
* **Every scan re-probes every known host**, so you see what went offline (and why: DNS gone vs. no
  HTTP answer), what came back, and what changed (status code, title, server, tech, redirect, CNAME, IPs).
* **The full httpx JSON line** (with TLS data and response headers) is stored for every probe of every
  scan. The raw output of every tool is kept on disk as well.
* **A dashboard** for search, filters, tags, bulk tagging, change feed, per-host history and exports.
* **Two containers:** a one-shot `scanner` you call with `domain=example.com`, and a `dashboard`.
  An optional `worker` runs scans queued from the dashboard and can re-scan everything on a schedule.

> Only scan domains you are authorised to test.

---

## Quick start

```bash
git clone <this repo> subtrack && cd subtrack
make build                       # builds both images (Go tools are compiled from source, pinned versions)
make up                          # dashboard on http://127.0.0.1:8080
make scan domain=example.com     # first scan
```

Then just run scans whenever you like. Each run adds new hosts and updates the status of all the known ones:

```bash
make scan domain=example.com
make scan domain=example.com,example.org brute=false
make rescan                      # = domain=all  → every domain already in the DB
make status                      # quick terminal summary
```

No `make`? These are all equivalent:

```bash
./scan domain=example.com
docker compose run --rm scanner domain=example.com
docker run --rm -v "$PWD/data:/data" subtrack-scanner domain=example.com
```

## Scan options

Pass options as `key=value` (also `--key value`, or `SCAN_<KEY>` env vars, or defaults in `scanner.env`).
`./scan help` prints the full list.

| option | default | meaning |
|---|---|---|
| `domain` | – | comma-separated root domains, or `all` for every tracked domain |
| `file` | – | file with one domain per line (path **inside** the container, e.g. `/data/targets.txt`) |
| `passive` | `true` | run subfinder |
| `subfinder_all` | `true` | subfinder `-all` (every source; slower, best coverage) |
| `subfinder_max_time` | `10` | minutes of passive enumeration per domain |
| `brute` | `true` | dnsx brute force with `wordlists/common-subdomains.txt` (108 words) |
| `wordlist` | built-in | your own wordlist, e.g. `/config/words.txt` (`./config` is mounted at `/config`) |
| `san` | `true` | probe new in-scope names found in TLS certificates (one extra round) |
| `recheck` | `true` | re-probe hosts that vanished, with 2× timeout and +1 retry, before calling them offline |
| `import_file` | – | extra hosts to validate (e.g. output of other tools) |
| `ports` | httpx default | httpx `-p`, e.g. `80,443,8080,8443`. Default: https:443 with fallback to http:80 |
| `follow_redirects` | `false` | httpx `-fr` (redirect targets are always recorded) |
| `threads` / `rate_limit` | `50` / `150` | httpx concurrency / requests per second |
| `timeout` / `retries` | `10` / `2` | httpx timeout in seconds per request / retries |
| `dns_threads` / `dns_rate_limit` | `100` / `0` | dnsx concurrency / queries per second (0 = unlimited) |
| `resolvers` | tool defaults | resolver file for dnsx and httpx, e.g. `/config/resolvers.txt` |
| `proxy` | – | proxy for httpx and subfinder (`http://…`, `socks5://…`) |
| `force` | `false` | bypass the mass-offline guard (see below) |

Subfinder API keys: copy `config/subfinder/provider-config.yaml.example` to `provider-config.yaml` and
fill in the keys you have. They are picked up automatically. Keys make a big difference: chaos, github,
virustotal, securitytrails and shodan are worth getting.

### Scheduling

Either cron on the host:

```cron
# every Monday 03:17 – re-scan every tracked domain
17 3 * * 1  cd /opt/subtrack && docker compose run --rm -T scanner domain=all >> data/cron.log 2>&1
```

…or the worker (`SCAN_SCHEDULE_HOURS=168` in `.env` means weekly):

```bash
make worker          # docker compose --profile worker up -d worker
```

The worker also runs scans you queue from the dashboard ("New scan", "Re-scan").

## How tracking works

| situation | what happens |
|---|---|
| host answers for the first time | inserted as `active`, event **new**, `first_seen` set |
| known host answers again | `last_seen`/`seen_count` updated. Event **changed** if status code, title, server, tech, redirect, URL, CNAME or IPs differ (IP changes behind a CDN are ignored) |
| known active host does not answer | rechecked once with longer timeouts. If still silent: `offline` + event **offline** with reason `dns` (no longer resolves) or `http` (resolves, no HTTP answer) |
| offline host answers again | `active` + event **back_online** (with what changed meanwhile) |
| tags / notes | yours. Scans never touch them |

Safety nets that keep the history clean:

* **Never offline on uncertainty.** If httpx crashes or times out, new or alive results are still
  stored, but nothing is marked offline.
* **Mass-offline guard.** If ≥ 80 % of a domain's active hosts (and at least 5) vanish at once, the
  scanner assumes a scanner-side problem (network, resolvers, rate limiting) and does not mark them
  offline. The scan is `partial` with a warning. Re-run with `force=true` if it is real.
* **Wildcard DNS** is detected with random labels. Brute-force answers that only hit the wildcard are
  dropped (own IP/CNAME comparison plus dnsx `-auto-wildcard`).
* **Per-domain lock.** Two scans never process the same domain at the same time. The second one skips it.
* **Clean interruption.** Ctrl+C or `docker stop` kills the tool processes, marks the scan
  `failed (interrupted)`, and changes no host status.
* Every tool runs with a hard timeout and `stdin=/dev/null`. httpx otherwise hangs forever when stdin
  is an open pipe, which happens under cron and CI.

Overlapping roots (`example.com` and `dev.example.com`) are fine. A host belongs to the root that found
it first, and both scans keep it up to date.

## Dashboard

`make up` → <http://127.0.0.1:8080>

* **Assets:** search and filter by domain, status, code, tech, server, tag, first-seen window or
  "had a *changed*/*offline* event in the last 7 days". Sort any column, select rows and bulk add or
  remove tags (or apply to every match). Export CSV, JSON, hosts or URLs.
* **Search syntax:** free text plus `title:"sign in"`, `code:4xx`, `code:200,302`, `tech:wordpress`,
  `server:nginx`, `ip:10.0.`, `cname:cloudfront`, `cdn:cloudflare`, `tag:prod`, `status:offline`,
  `source:bruteforce`, `port:8443`, `tls:corp`, `hash:<sha256>`. Prefix any term with `-` to negate it
  (`-tag:ignore`).
* **Host page:** current snapshot (URLs, TLS, SANs, CDN, favicon hash, DNS), tags, notes, an event
  timeline with diffs, every probe of every scan (including "no response" scans) with its raw httpx
  JSON, and the DNS history.
* **Changes:** the feed of new, changed, offline and back-online events across all domains.
* **Scans:** per-domain funnel (candidates → resolve → alive), stats, warnings, parameters and tool
  versions. Also the queue.
* **Domains / Tags:** manage roots (re-scan) and tags (rename, colour, delete).

**Access:** by default the dashboard is bound to `127.0.0.1` and only answers to `localhost`. On a
server, use an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 server`), or set `DASHBOARD_BIND=0.0.0.0` plus
`DASHBOARD_USER`/`DASHBOARD_PASSWORD` in `.env` (ideally behind a TLS reverse proxy). State-changing
API calls need an `X-Subtrack: 1` header (CSRF protection). Scanned content is always rendered as text,
under a strict CSP.

## Data

Everything is in `./data` (`DATA_DIR` in `.env`):

```
data/
├── tracker.db              SQLite (WAL) – the source of truth
├── scans/00042/scan.log    log of scan #42
├── scans/00042/<domain>/   raw tool output: subfinder.jsonl, brute.jsonl, dnsx-main.jsonl,
│                           httpx-main.jsonl, httpx-san.jsonl, httpx-recheck.jsonl, *.stderr.log
├── backups/                make backup  (consistent online copy, safe while scans run)
└── locks/
```

Main tables: `roots`, `subdomains` (one row per host, current snapshot plus lifecycle), `httpx_results`
(one row per probed URL per scan, `raw` = full httpx JSON), `dns_results`, `events`, `scans` /
`scan_roots` (stats, warnings, tool versions), `tags` / `subdomain_tags`, `scan_requests` (queue).
Query it directly with `sqlite3 data/tracker.db`:

```sql
-- everything that went offline in the last 30 days
SELECT s.host, e.created_at, json_extract(e.details, '$.reason') FROM events e
JOIN subdomains s ON s.id = e.subdomain_id
WHERE e.type = 'offline' AND e.created_at >= date('now', '-30 day');

-- TLS certificates expiring soon, from the stored httpx JSON
SELECT host, tls_not_after FROM subdomains WHERE status = 'active' AND tls_not_after < date('now', '+21 day');

-- full httpx JSON of the latest probe
SELECT raw FROM httpx_results WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'www.example.com') ORDER BY id DESC LIMIT 1;
```

Expect a few KB per alive host per scan: 2,000 hosts scanned weekly for a year is roughly 0.5 GB.

## Tests

```bash
make test
```

This builds the `test` image and runs 27 tests. They cover the change-detection rules, the dashboard
API and its security checks, and an end-to-end lab: a local authoritative DNS server plus HTTP/HTTPS
servers whose hosts appear, change, disappear and come back between scans. The lab tests run the real
**dnsx and httpx** binaries. subfinder is replaced by a stub because passive sources need the internet.

## Troubleshooting

| problem | fix |
|---|---|
| `429 Too Many Requests` pulling base images | set `GO_IMAGE=mirror.gcr.io/library/golang:1.26` and `PY_IMAGE=mirror.gcr.io/library/python:3.13-slim` in `.env` |
| `x509: certificate signed by unknown authority` during build (corporate TLS proxy) | `docker build --secret id=ca,src=/path/proxy-ca.pem --target scanner -t subtrack-scanner .` (same for `dashboard`) |
| dashboard says "Host not allowed" | you are not on `localhost`: set a password, or add the hostname to `DASHBOARD_ALLOWED_HOSTS` |
| scan is `partial` with "offline guard" | the scanner lost connectivity, or the target really went dark. Check `data/scans/<id>/scan.log`, then re-run (or `force=true`) |
| few passive results | add subfinder API keys (`config/subfinder/provider-config.yaml`) |
| unreliable DNS / rate limiting | `resolvers=/config/resolvers.txt` with resolvers you trust, and lower `dns_threads` / `rate_limit` |
| files in `./data` are owned by root | the containers run as root so bind mounts always work. `sudo chown -R $USER data` if needed |
| macOS / Windows Docker Desktop | works. If you see `database is locked` errors on a bind mount, set `DATA_DIR` to a path inside the Docker VM or use a named volume |

Pinned tool versions (Dockerfile build args): subfinder v2.17.0, dnsx v1.3.1, httpx v1.12.0. To bump,
change the `*_VERSION` args and rebuild. The tool versions are recorded with every scan.
