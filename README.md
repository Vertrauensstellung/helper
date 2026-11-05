# subtrack

Long-term subdomain tracking: **discover → validate → store forever → see what changed.**

You call a scanner whenever you like (`make scan domain=example.com`). It finds subdomains with
subfinder and a dnsx brute force, validates them with httpx, and records everything in a SQLite
database that only ever grows. A web dashboard lets you search, filter, tag and export the results,
and shows what appeared, changed, went offline or came back over the months.

> **Only scan domains you are authorised to test.**

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [Architecture](#2-architecture)
3. [Requirements](#3-requirements)
4. [Installation & first scan](#4-installation--first-scan)
5. [Configuration files](#5-configuration-files)
6. [Running scans](#6-running-scans)
7. [All scan options](#7-all-scan-options)
8. [The pipeline in detail](#8-the-pipeline-in-detail)
9. [How tracking works](#9-how-tracking-works)
10. [Safety nets](#10-safety-nets)
11. [The dashboard](#11-the-dashboard)
12. [Accessing the dashboard from another machine](#12-accessing-the-dashboard-from-another-machine)
13. [Worker, queue & scheduling](#13-worker-queue--scheduling)
14. [Dashboard API](#14-dashboard-api)
15. [Data, database & SQL cookbook](#15-data-database--sql-cookbook)
16. [Backups, restore & moving servers](#16-backups-restore--moving-servers)
17. [Recipes](#17-recipes)
18. [Tuning for large scopes](#18-tuning-for-large-scopes)
19. [Tests](#19-tests)
20. [Running without Docker](#20-running-without-docker)
21. [Upgrading](#21-upgrading)
22. [Troubleshooting](#22-troubleshooting)
23. [FAQ & known limitations](#23-faq--known-limitations)
24. [Repository layout](#24-repository-layout)

---

## 1. What it does

* **Discovery:** subfinder (all passive sources), a dnsx brute force (108 common names, wildcard-safe),
  names found in TLS certificates, every host already in the database, and an optional import file
  with hosts from other tools.
* **Validation:** dnsx resolves every candidate, and httpx probes them. **Only hosts that httpx
  confirms are added.**
* **History:** once added, a host is **never deleted**. Each host keeps:
  * a status, `active` or `offline`, and for offline hosts *why* (`dns`: no longer resolves,
    `http`: resolves but nothing answers)
  * `first_seen`, `last_seen` (last time it answered), `last_checked` (last time it was probed)
    and a `seen_count`
  * an event history: **new**, **changed**, **offline**, **back online**
  * the **full httpx JSON** of every probe in every scan (incl. TLS certificate data and response
    headers), plus the DNS answers of every scan
  * where it was discovered (`subfinder:crtsh`, `bruteforce`, `tls-san`, …)
  * your own tags and notes
* **Dashboard:** search with a field syntax, filters, sorting, bulk tagging, exports, a change feed,
  per-host timeline and probe history, scan details, and a scan queue.
* **Docker:** a one-shot `scanner` container (`domain=example.com`), a long-running `dashboard`
  container, and an optional `worker` container for queued and scheduled scans.

## 2. Architecture

```
                      ┌──────────────────────────── scanner container (one-shot) ───────────────────────────┐
                      │                                                                                     │
 make scan            │  subfinder -all ───────┐                                                            │
 domain=example.com ──┼▶ dnsx brute force ─────┼─▶ unique ─▶ dnsx resolve ─▶ httpx ─▶ TLS-SAN ─▶ recheck ─▶ ingest
                      │  known hosts (DB) ─────┤                                    round                   │   │
                      │  root + import file ───┘                                                            │   │
                      └─────────────────────────────────────────────────────────────────────────────────────┘   │
                                                                                                                ▼
                                                       ./data/tracker.db  (SQLite, WAL)   ./data/scans/<id>/…  (raw tool output)
                                                                ▲                ▲
                              ┌──── dashboard container ────────┘                └──────── worker container (optional) ────┐
                              │  stdlib HTTP server + JSON API + UI                 runs scans queued in the dashboard,     │
                              │  http://127.0.0.1:8080                              optional automatic re-scan schedule     │
                              └─────────────────────────────────────────────────────────────────────────────────────────────┘
```

* **One Dockerfile, three targets:** `scanner` (Python + subfinder/dnsx/httpx compiled from source at
  pinned versions, ~330 MB), `dashboard` (Python only, ~176 MB) and `test` (scanner plus the test lab).
* **No Python dependencies at all.** The scanner and dashboard only use the standard library. The
  only third-party code is the three ProjectDiscovery tools.
* **SQLite in WAL mode**, so the dashboard can read while a scan writes. Writes are short transactions,
  one per domain at the end of its scan.
* The containers share nothing but the `./data` folder (and `./config`, read-only, for the scanner).

## 3. Requirements

* Docker with the Compose plugin, version 2.24 or newer (`docker compose version`). The compose
  file uses an optional `env_file`, which older versions can't parse. Any current Docker install is fine.
* Internet access from the scanner (passive sources, DNS, the targets) and, for the build, access to
  Docker Hub (or a mirror) and the Go module proxy.
* `make` is optional. Every target has a plain `docker compose` equivalent.
* Disk: a few hundred MB for images, plus the database (see [storage estimates](#storage-estimates)).

## 4. Installation & first scan

```bash
git clone https://github.com/Vertrauensstellung/helper.git subtrack
cd subtrack

cp .env.example .env                       # optional, defaults are fine on a single machine
make build                                 # builds scanner + dashboard images (first build takes a few minutes)
make up                                    # starts the dashboard -> http://127.0.0.1:8080
make scan domain=example.com               # first scan
```

The first scan creates `./data/tracker.db`. Open the dashboard, and the hosts are there. From now on,
simply scan again whenever you want. Every scan adds new hosts and updates all known ones.

Without `make`:

```bash
docker compose --profile scan build
docker compose up -d dashboard
docker compose run --rm scanner domain=example.com
```

## 5. Configuration files

| file | purpose | in git? |
|---|---|---|
| `.env` | Compose settings: data dir, dashboard bind/port/auth, schedule, base images | no (copy `.env.example`) |
| `scanner.env` | default scan options for every scan (CLI, cron and worker) | no (copy `scanner.env.example`) |
| `config/subfinder/provider-config.yaml` | subfinder API keys | no (copy the `.example`) |
| `config/` | anything you want the scanner to read: wordlists, resolver lists, import files. Mounted read-only at `/config` | your choice |

### `.env`

| variable | default | meaning |
|---|---|---|
| `DATA_DIR` | `./data` | where the database and raw output live (bind mount) |
| `DASHBOARD_BIND` | `127.0.0.1` | host address the dashboard port is published on. `0.0.0.0` = all interfaces |
| `DASHBOARD_PORT` | `8080` | host port of the dashboard |
| `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | empty | enables HTTP basic auth (and disables the host check) |
| `DASHBOARD_ALLOWED_HOSTS` | empty | without a password the dashboard only answers to `localhost`/`127.0.0.1`/`::1`. List extra hostnames/IPs here, comma separated, or `*` |
| `SCAN_SCHEDULE_HOURS` | `0` | worker only: re-scan every tracked domain every N hours (`168` = weekly, `0` = off) |
| `GO_IMAGE` | `golang:1.26` | build base image for the Go tools |
| `PY_IMAGE` | `python:3.13-slim` | runtime base image |

After changing `.env`, re-create the affected container, e.g. `docker compose up -d dashboard`.

### `scanner.env`

Every scan option (see [section 7](#7-all-scan-options)) can be given a default as `SCAN_<OPTION>`:

```ini
SCAN_PORTS=80,443,8080,8443
SCAN_WORDLIST=/config/my-wordlist.txt
SCAN_RESOLVERS=/config/resolvers.txt
SCAN_RATE_LIMIT=100
```

Options on the command line always win over `scanner.env`.

### Subfinder API keys

```bash
cp config/subfinder/provider-config.yaml.example config/subfinder/provider-config.yaml
# edit it, then just scan – the file is detected automatically
```

Without keys, subfinder only uses the free sources. Keys make a big difference. Free or cheap ones
worth getting: **chaos, github, virustotal, securitytrails, shodan, censys, bevigil**. List every
source subfinder knows:

```bash
docker compose run --rm --entrypoint subfinder scanner -ls
```

## 6. Running scans

### Four equivalent ways

```bash
make scan domain=example.com                                     # Makefile
./scan domain=example.com                                        # wrapper script (passes every argument through)
docker compose run --rm scanner domain=example.com               # Compose
docker run --rm -v "$PWD/data:/data" -v "$PWD/config:/config:ro" subtrack-scanner domain=example.com   # plain Docker
```

On Windows PowerShell use the `docker compose run …` form (the `./scan` script needs a POSIX shell).

### Examples

```bash
make scan domain=example.com                         # one domain
make scan domain=example.com,example.org             # several
make scan domain=all                                 # every domain already in the database (= make rescan)
make scan file=/config/targets.txt                   # one domain per line (path inside the container)

make scan domain=example.com brute=false             # skip the brute force
make scan domain=example.com ports=80,443,8080,8443  # probe extra ports
make scan domain=example.com wordlist=/config/big.txt
make scan domain=example.com import_file=/config/amass-hosts.txt
make scan domain=example.com force=true              # bypass the mass-offline guard
make scan domain=all passive=false brute=false san=false   # fast health check of known hosts only

./scan help                                          # every option with its default
make status                                          # summary per domain + last scans
```

With `make`, any [scan option](#7-all-scan-options) given on the command line is passed through
(`make scan domain=x threads=20`). Anything else can go in `ARGS="…"`.

### Argument syntax

* `key=value`, `--key=value`, `--key value`, and `--flag` (= `true`) all work.
* Keys are case-insensitive, `-` and `_` are interchangeable (`--rate-limit 50`).
* Aliases: `domains`/`d` → `domain`, `list`/`domains_file` → `file`, `import`/`hosts_file` →
  `import_file`, `t` → `threads`, `rl` → `rate_limit`.
* Booleans accept `true/false`, `yes/no`, `on/off`, `1/0`.
* Bare words: `scan`, `worker`, `status`, `backup`, `init` select a mode; `help`/`-h`/`--help`
  prints the help; anything else is treated as a domain (`./scan example.com`).
* Domain lists may be separated by commas, spaces or newlines; `#` starts a comment.
* Input is normalised: `https://WWW.Example.com:443/path` becomes `www.example.com`. Unicode
  domains are converted to punycode. IP addresses are rejected.
* Unknown options or invalid values stop the scan immediately with an error (nothing is written).

### Precedence

command line → environment (`SCAN_<KEY>`, plus `DOMAIN`/`DOMAINS`/`MODE` without prefix) →
`scanner.env` (which is just environment) → built-in default. Domains given on the command line
replace `DOMAIN` from the environment.

### Modes

| mode | what it does |
|---|---|
| `scan` (default) | runs a scan |
| `worker` | processes the dashboard queue forever, see [section 13](#13-worker-queue--scheduling) |
| `status` | prints domains with total/active/offline counts and the last 5 scans |
| `backup` | writes a consistent copy of the database to `data/backups/tracker-YYYYmmdd-HHMMSS.db` |
| `init` | only creates/migrates the database |
| `help` | prints all options with defaults |

### Exit codes

| code | meaning |
|---|---|
| `0` | scan `success`, `partial` (finished with warnings) or `skipped` (domain locked by another scan) |
| `1` | scan `failed`, or invalid arguments |
| `130` | interrupted (Ctrl+C / `docker stop`) |

### What a scan prints

```
[01:18:09] subtrack 1.0.0 scan #1: 2 root(s): acme.test, wild.test
[01:18:09] tools: {'subfinder': 'v2.17.0', 'dnsx': 'v1.3.1', 'httpx': 'v1.12.0'}
[01:18:09] [1/2] acme.test
[01:18:10]   subfinder: 0 in-scope names (0s)
[01:18:10]   dnsx brute force: 4 hits from 108 words
[01:18:10]   5 unique candidates (0 already tracked)
[01:18:10]   dnsx: 5 of 5 resolve
[01:18:17]   httpx[main]: 4 responses from 5 hosts (7s)
[01:18:17]   TLS certificates revealed 1 new in-scope names
[01:18:18]   httpx[san]: 1 responses from 1 hosts (1s)
[01:18:18]   => success: alive=5 new=5 back_online=0 changed=0 went_offline=0 (8.1s)
[01:18:18] [2/2] wild.test
[01:18:18]   wildcard DNS detected for *.wild.test -> ['127.0.20.1']
[01:18:18]   dnsx brute force: 1 hits from 108 words
...
[01:18:19] scan #1 finished: success. raw output: /data/scans/00001
```

Every tool command line is logged as well (lines starting with `$`). The same log is written to
`data/scans/<id>/scan.log`.

## 7. All scan options

| option | default | meaning |
|---|---|---|
| `mode` | `scan` | `scan`, `worker`, `status`, `backup`, `init`, `help` |
| `domain` | – | comma-separated root domains, or `all` |
| `file` | – | file with root domains, one per line (path inside the container) |
| **passive** | | |
| `passive` | `true` | run subfinder |
| `subfinder_all` | `true` | subfinder `-all`: every source (slower, best coverage) |
| `subfinder_sources` | – | only these sources, e.g. `crtsh,github` (subfinder `-s`) |
| `subfinder_max_time` | `10` | minutes of enumeration per domain (subfinder `-max-time`) |
| `subfinder_timeout` | `30` | seconds per source request (subfinder `-timeout`) |
| `provider_config` | auto | API key file. Auto-detected at `/config/subfinder/provider-config.yaml` or `/config/provider-config.yaml` |
| **brute force** | | |
| `brute` | `true` | dnsx brute force |
| `wordlist` | `/app/wordlists/common-subdomains.txt` | 108 words. Use your own via `/config/...` |
| **validation** | | |
| `san` | `true` | probe new in-scope names found in TLS certificates (one extra round) |
| `recheck` | `true` | re-probe vanished hosts with 2× timeout, +1 retry, ≤20 threads |
| `import_file` | – | extra hosts to validate, one per line (`#` comments allowed, out-of-scope lines ignored) |
| `ports` | – | httpx `-p`, e.g. `80,443,8080,8443` or `http:8080,https:8443`. Empty = httpx default: HTTPS on 443, falling back to HTTP on 80 |
| `follow_redirects` | `false` | httpx `-fr`. Redirect targets are recorded either way (`location`) |
| `threads` | `50` | httpx threads |
| `rate_limit` | `150` | httpx requests per second |
| `timeout` | `10` | httpx timeout per request, seconds |
| `retries` | `2` | httpx retries |
| `httpx_max_time` | `0` | hard limit per httpx run in seconds. `0` = derived from the target count (see [8.8](#88-timeouts)) |
| `dns_threads` | `100` | dnsx threads |
| `dns_rate_limit` | `0` | dnsx queries per second, `0` = unlimited |
| `dns_max_time` | `0` | hard limit per dnsx run in seconds, `0` = derived |
| `resolvers` | – | resolver list for dnsx and httpx: a file (`/config/resolvers.txt`) or comma list (`1.1.1.1,9.9.9.9`) |
| `proxy` | – | proxy for httpx and subfinder, e.g. `http://10.0.0.1:8080`, `socks5://127.0.0.1:9050` |
| **tracking** | | |
| `force` | `false` | bypass the mass-offline guard |
| `guard_ratio` | `0.8` | guard trips when this share of active hosts vanishes at once… |
| `guard_min_active` | `5` | …and the domain had at least this many active hosts |
| **worker** | | |
| `poll_interval` | `10` | seconds between queue polls |
| `schedule_hours` | `0` | automatic re-scan of all domains every N hours, `0` = off |
| `trigger` | `cli` | label stored with the scan (`cli`, `queue:dashboard`, `queue:schedule`, or your own, e.g. `cron`) |

Expert overrides (environment only): `TRACKER_DATA` (data dir, default `/data`), `TRACKER_DB`
(database path), `SUBFINDER_BIN` / `DNSX_BIN` / `HTTPX_BIN` (tool binaries).

## 8. The pipeline in detail

Per root domain, in this order. Each domain is processed completely before the next one starts.

### 8.1 Passive enumeration (subfinder)

```
subfinder -d <root> -oJ -cs -o subfinder.jsonl -silent -nc -duc -timeout 30 -max-time 10 -all [-pc keys] [-s …] [-proxy …]
```

`-cs` records **every** source that reported a name, stored as `subfinder:<source>`. Results are
normalised (lowercase, `*.` and trailing dots stripped) and anything outside the root is dropped.
If subfinder fails or times out, the results it produced so far are still used and the scan is
marked `partial`.

### 8.2 Wildcard detection

Five random 14-character labels (`k3j9…<root>`) are resolved. If any of them resolves, the domain
has wildcard DNS. The answer IPs/CNAMEs are remembered, and the domain is flagged `wildcard` in the
database and dashboard.

### 8.3 Brute force (dnsx)

```
dnsx -l brute-candidates.txt -a -aaaa -cname -json -omit-raw -o brute.jsonl -silent -nc -duc -retry 2 -t 100 [-auto-wildcard] [-r resolvers]
```

`<word>.<root>` for every word of the wordlist. Words may contain dots (`dev.api`), and `#` comments,
blank lines, `*` and invalid labels are ignored. On wildcard domains a hit is only kept if its
addresses are **not** a subset of the wildcard answers and its CNAME is not a wildcard CNAME. dnsx
`-auto-wildcard` is applied on top. Hits are recorded with the source `bruteforce`.

The built-in list (`wordlists/common-subdomains.txt`, 108 words) is deliberately small, which keeps
it to a few seconds per domain. For deeper brute forcing put a bigger list into `./config/` and use
`wordlist=/config/<file>`.

### 8.4 Merge

Candidates = subfinder ∪ brute force ∪ **every host already tracked under this root** ∪ the root
itself (`input`) ∪ `import_file` (`import`). Everything is de-duplicated and scope-checked.

### 8.5 Resolve (dnsx)

All candidates are resolved (`-a -aaaa -cname`, 3 retries). A candidate counts as resolving when
it has an A or AAAA record. The DNS answers of tracked hosts are stored for every scan.

### 8.6 Probe (httpx)

```
httpx -l targets.txt -o httpx-main.jsonl -json -no-stdin -silent -nc -duc
      -sc -cl -ct -location -title -server -td -method -ip -cname -cdn -favicon -hash sha256
      -tls-grab -rt -lc -wc -irh -ob -t 50 -rl 150 -timeout 10 -retries 2 [-p …] [-fr] [-r …] [-proxy …]
```

Targets = **all known hosts** (whether they resolved or not, so a flaky resolver can't make them
look dead) + new candidates that resolved + the root. If the dnsx stage failed, every candidate is
probed. The JSON includes status code, title, server, technologies (wappalyzer), IPs, CNAMEs,
CDN/WAF, favicon mmh3, body and header SHA-256, TLS certificate (subject, SANs, issuer, validity,
fingerprints), response headers, response time, word and line counts. The response body itself is
not stored.

### 8.7 TLS-SAN round and recheck

* **TLS-SAN round** (`san=true`): every subject CN / SAN of the certificates seen so far that is in
  scope and not yet a candidate is resolved and probed (source `tls-san`). This regularly finds
  hosts no passive source knows. It runs once and does not recurse.
* **Recheck** (`recheck=true`): every host that was `active` before this scan and did not answer is
  probed again with twice the timeout, one more retry and at most 20 threads (phase `recheck`).

### 8.8 Timeouts

Every tool runs in its own process group with `stdin=/dev/null` and a hard limit. When the limit is
reached it gets SIGTERM, then SIGKILL after 10 s, and whatever it wrote is still used.

| tool | hard limit |
|---|---|
| subfinder | `subfinder_max_time × 60 + 180` seconds |
| dnsx | `dns_max_time`, else `max(300, candidates × 0.05 + 300)` seconds |
| httpx | `httpx_max_time`, else `3 × hosts × ports × timeout × (retries+1) / threads + 600` seconds (ports = 2 without `ports=`) |

### 8.9 Ingest

The results of all phases are merged into the database in **one transaction per domain** (see the
next section). Then the scan moves on to the next domain.

### 8.10 Raw output on disk

```
data/scans/00042/scan.log
data/scans/00042/<root>/subfinder.jsonl          subfinder.stderr.log
                        wildcard-probe.txt/.jsonl dnsx-wildcard.stderr.log
                        brute-candidates.txt      brute.jsonl          dnsx-brute.stderr.log
                        resolve-main.txt          dnsx-main.jsonl      dnsx-main.stderr.log
                        httpx-main-targets.txt    httpx-main.jsonl     httpx-main.stderr.log
                        resolve-san.txt / dnsx-san.jsonl / httpx-san-*.{txt,jsonl}            (if any)
                        httpx-recheck-targets.txt / httpx-recheck.jsonl                       (if any)
```

These files are not needed by the dashboard. Everything important is in the database, so you can
delete old scan folders to save space.

## 9. How tracking works

### Lifecycle

| situation | what happens |
|---|---|
| a host answers for the first time | inserted as `active`; `first_seen` = `last_seen` = now; event **new** |
| a known host answers again | `last_seen`, `last_checked`, `seen_count`, sources and the snapshot are updated. Event **changed** if a tracked field differs |
| a known `active` host does not answer (after the recheck) | `offline`, `status_changed_at` = now, `offline_reason` = `dns` or `http`; event **offline** |
| an `offline` host still does not answer | only `last_checked` and the DNS state are updated (no new event) |
| an `offline` host answers again | `active`; event **back_online** with the offline duration and what changed meanwhile |
| you tag / annotate a host | stored separately; scans never touch tags or notes |

A host that resolves in DNS but never answers HTTP(S) is **not** added. That's intentional: only
hosts that httpx validated enter the database. Once a host is in, it stays forever.

### Fields that trigger a "changed" event

`url` (scheme/port of the primary URL), `status_code`, `title`, `webserver`, `location` (redirect
target), `tech`, `cname`, `ips`. IP changes are ignored when the host is behind a CDN (edge IPs
rotate constantly). Body hash, content length, TLS certificate and favicon are stored and searchable,
but don't create events, because they change too often (CSRF tokens, timestamps, certificate
renewals).

### Primary URL

A host can answer on several URLs (e.g. with `ports=` set). Every URL is stored. The host's snapshot
(title, code, …) comes from the **primary** one: HTTPS before HTTP, then ports 443/80 before
others, then the lowest port. All alive URLs are listed in `urls`.

### Discovery sources

| source | meaning |
|---|---|
| `subfinder:<name>` | reported by that passive source (`subfinder:crtsh`, `subfinder:virustotal`, …) |
| `bruteforce` | found by the dnsx brute force |
| `tls-san` | found in a TLS certificate of another host |
| `import` | from `import_file` |
| `input` | the root domain itself |

Sources accumulate over time: if subfinder reports a host in a later scan, its source is added.

### Event details

Each event stores a JSON `details` object:

| type | details |
|---|---|
| `new` | `url`, `status_code`, `title`, `sources` |
| `changed` | `changes: {field: {old, new}}` |
| `offline` | `reason` (`dns`/`http`), `last_seen`, `last_url`, `last_status_code` |
| `back_online` | `offline_since`, `url`, `status_code`, `changes` |

### Scan and domain statuses

| status | meaning |
|---|---|
| `running` | in progress (scans stuck in `running` for over 48 h are marked `failed (stale)` by the next scan) |
| `success` | everything ran cleanly |
| `partial` | finished, but with warnings (a tool failed or timed out, or the offline guard tripped). Positive results were stored |
| `failed` | the domain could not be processed (or the scan was interrupted) |
| `skipped` | another scan was processing the domain at that moment |

### Overlapping roots

Tracking `example.com` **and** `dev.example.com` works. A host belongs to the root that found it
first, and a scan of either root re-probes and updates every tracked host inside its scope.

## 10. Safety nets

The goal: the history must stay trustworthy even when things go wrong.

* **Positive evidence always counts, negative evidence only when it's certain.** If httpx crashes
  or times out, new, changed and back-online results are stored, but nothing is marked offline.
* **Mass-offline guard.** If at least `guard_ratio` (80 %) of a domain's active hosts vanish at
  once, and it had at least `guard_min_active` (5), the scanner assumes a scanner-side problem
  (network down, broken resolver, rate limited, IP blocked) and marks nothing offline. The scan
  becomes `partial` with a clear warning. If it's real, re-run with `force=true`.
* **Recheck before offline.** A host is only called offline after a second, slower probe.
* **Known hosts are always probed by httpx**, even when dnsx said they don't resolve. A flaky resolver
  can't kill them.
* **Wildcard-safe brute force** (section 8.3).
* **Per-domain lock** (`data/locks/<root>.lock`, works across containers). Two scans never process
  the same domain at the same time. The second skips it (`skipped`, exit code 0).
* **Clean interruption.** Ctrl+C or `docker stop`: the running tool's process group is killed, the
  scan is marked `failed (interrupted)`, and no host status changes. A worker puts the interrupted
  request back into the queue.
* **No hangs.** Every tool runs with a hard timeout and `stdin=/dev/null`. httpx otherwise blocks
  forever reading stdin when it is an open pipe, which happens under cron and CI.
* **Strict input validation.** Unknown options, bad values and invalid domains abort before
  anything is written.
* **Out-of-scope results are dropped**, whatever a tool returns.
* **Schema migrations are automatic** and versioned (`PRAGMA user_version`).

## 11. The dashboard

Start it with `make up` (or `docker compose up -d dashboard`) and open <http://127.0.0.1:8080>. It
runs all the time and needs no restart when scans run. Times are shown in your browser's local time.
Hover any time to see it in UTC.

### Navigation & shortcuts

* **Sidebar:** Overview, Assets, Changes, Scans, Domains, Tags (with counts), the worker status
  (`Worker online` / `Worker offline` / `Scanning…`, plus the queue size), a light/dark toggle
  (follows the OS by default, remembered per browser) and the shortcut list. On a phone the
  sidebar slides in from the ☰ button.
* **Command palette (`Ctrl K` / `⌘K`, or the search field in the top bar):** jump to any host
  (searches as you type), page, domain or tag, or run an action (New scan, Re-scan all, dark mode).
* **Keyboard:** `/` search assets · `j`/`k` next/previous row (or next/previous host while the detail
  panel is open) · `↵` open · `x` select · `Esc` close · `g o`/`g a`/`g c`/`g s`/`g d`/`g t` go to a page ·
  `?` all shortcuts.
* **New scan** (top right): queue a scan for the worker (see [section 13](#13-worker-queue--scheduling)).

### Overview

One screen for the whole attack surface, scoped by a **domain** selector and a **time range**
(30 days, 90 days, 1 year, all time). Everything is clickable and drills into the filtered asset list.

* **KPI tiles:** tracked hosts, active (with availability %), offline (with how many came back
  this week), and new / changed / went offline in the last 7 days, each with a 30-day sparkline
  and the change against the previous 7 days.
* **Attack surface:** active vs. all-time tracked hosts over time (rebuilt from the event log),
  with a crosshair tooltip. Arrow keys work when the chart has focus.
* **Response mix:** share of 2xx/3xx/4xx/5xx among active hosts, availability, share behind a
  CDN/WAF, and the top status codes.
* **Changes:** new / changed / went offline / back online per day (per week or month for longer
  ranges) as stacked columns, with a hover tooltip and totals in the legend. Next to it, the latest changes.
* **Technologies, web servers, discovered by:** ranked bars. Click one to see those hosts.
* **Domains:** availability meter, new hosts this week and last scan per domain.
* **Watchlist:** TLS certificates expiring within 30 days (or already expired), and **possible
  takeovers**: offline hosts whose DNS vanished but that had a CNAME.
* **Recent scans** with their results.

Chart colours come from a palette validated for colour-vision deficiencies in light and dark mode.
Status (active/offline) is never shown by colour alone: there is always a label next to it.

### Assets – search & filters

* **Big search box with suggestions.** As you type it offers:
  * matching **filters**: `ngi` → *Tech: Nginx (17 hosts)*, *Server: nginx (25 hosts)*
  * **fields**: `ti` → `title:`
  * after `tech:`, `server:`, `tag:`, `domain:`, `status:` or `code:`, the **values** that exist in
    your data, with counts
  * **hosts** to jump straight to
  * your **recent searches** when the box is empty

  `↑↓` to move, `↵` to apply, `Tab` to complete, `Esc` to close. Picking a filter turns it into a
  chip, and anything else stays free text with the field syntax below. Results update as you type.
* **Quick views:** All assets, Active, New this week, Went offline · 7d, Changed · 7d, Server errors,
  Auth walls 401/403, Untagged. Plus your own views: **Save view** stores the current filters (in
  this browser) as an extra pill.
* **Active filters** are shown as chips (remove one with ×, or *Clear all*).
* **Facet sidebar** with live counts for status, domain, response (classes and exact codes),
  technology, web server (both with a filter box), tags and first-seen window. Within a facet the
  values are combined with OR (e.g. `nginx` *or* `Apache`). Across facets they're combined with AND.
  Tags are the exception: several tags means the host must have all of them. Each facet's counts
  ignore its own selection, so you always see what selecting another value would give. On a phone
  the facets open from a *Filters* button.
* **Results table:** host with title · server underneath (↗ opens the site), status, code,
  technologies (click to filter), IP/CDN (on screens wider than 1600 px), seen (last seen, and
  first seen underneath), tags. Sort by column header or the sort menu (newest, recently seen,
  recent status change, A→Z, status code, most scans), and toggle compact rows. 25 to 1000 rows per page.
* **Bulk tagging:** tick rows (or `x`), then use the toolbar at the bottom: *Add tag* / *Remove tag*,
  or *Tag all N matches* for every host matching the current filters.
* **Export** the current result as CSV, JSON, a host list or a URL list.
* Clicking a row opens the **detail panel** on the right. The list stays where it is, and `j`/`k`
  step through the results.
* The whole filter state is in the URL, so you can bookmark it or send it to someone.

### Search syntax

| query | finds |
|---|---|
| `login` | free text in host, title, server, tech, IPs, URLs, CNAME, CDN and notes |
| `title:"sign in"` | quoted phrases |
| `host:dev` | host contains `dev` |
| `code:200` · `code:4xx` · `code:301,302` | status codes and classes |
| `tech:wordpress` | technology (wappalyzer) |
| `server:nginx` | web server header |
| `ip:10.0.` | IP contains |
| `cname:cloudfront` | CNAME contains |
| `cdn:cloudflare` | CDN / WAF name |
| `tag:prod` | has tag (case-insensitive) |
| `status:offline` | `active` / `offline` |
| `source:bruteforce` · `source:crtsh` | discovered by |
| `port:8443` | an alive URL uses this port |
| `scheme:http` | primary URL scheme |
| `url:/admin` · `location:login` | URL / redirect target contains |
| `tls:corp` · `issuer:"let's encrypt"` | TLS certificate subject CN / issuer |
| `hash:<sha256>` · `favicon:<mmh3>` | body hash / favicon hash (find identical pages) |
| `type:json` | content type |
| `domain:example.com` (or `root:`) · `notes:todo` | root domain / your notes |
| `-tag:ignore` · `-code:404` | a leading `-` negates any term |

Terms are combined with AND: `code:2xx tech:php -tag:reviewed`.

### Host detail (panel or full page)

Opens as a side panel from any list (⤢ opens it as its own page, `#/host/<id>`). Header: host,
status, code, title, root, ‹ › for the previous/next result, copy, open in a new tab.

* **Overview:**
  * an offline callout (since when, and DNS vs. HTTP)
  * an **availability strip** with one cell per scan of its domain (answered / no response)
  * tags with autocomplete and quick tags (`interesting`, `in-scope`, `out-of-scope`, `ignore`,
    `reported`), and notes
  * fact cards for:
    * **Response:** URLs, code, title, server, redirect, content, technologies
    * **Network:** IPs, CNAME, CDN/WAF, last DNS answer
    * **TLS:** subject, issuer, expiry with days left, SANs, version
    * **Fingerprints & history:** favicon and body hash (click to find hosts serving the same
      thing), discovery sources, first/last seen, last checked
* **Timeline:** every event with old → new diffs.
* **Probes:** one row per probe per scan plus "no response in this scan" rows. **JSON** opens the full
  httpx JSON of that probe.
* **DNS:** the DNS answer of every scan.
* **Raw JSON:** the latest httpx output, with copy.

### Changes

Every event grouped by day (Today, Yesterday, …). Filter by type (with counts per type), domain,
period (24 h, 7 / 30 / 90 days, a year, all time) and host. Changed events show their diffs inline.
Click a row to open the host. *Load more* pages back in time.

### Scans

* **Queue:** requests from the dashboard with status, options and the resulting scan. Queued
  requests can be cancelled. A banner tells you when requests are waiting but no worker runs.
* **History:** status, scan number and trigger, start, duration, domains, results (alive, +new,
  −offline, ↑back, ~changed) and a warning badge.
* **Scan detail:** per domain:
  * the **validation funnel** (candidates → resolve → probed → alive)
  * discovery numbers (subfinder, brute force, TLS SANs, wildcard answers dropped)
  * changes, duration and warnings
  * links to that domain's assets and changes
  * plus the parameters and tool versions used

### Domains & Tags

* **Domains:** a card per root domain with hosts, active, new this week, availability meter, last
  scan, *Changes* and *Re-scan*. Plus *Re-scan all* and *Add domain*.
* **Tags:** create (with colour), rename and recolour inline, delete (the assets stay, only the tag
  goes). The count links to the tagged assets. Tag names are 1–64 characters, without commas, and
  case-insensitive (`Prod` = `prod`).

`active`/`offline` is not a tag: the status is tracked automatically and shown as a labelled dot.

### Security model

* Without `DASHBOARD_USER`/`DASHBOARD_PASSWORD`, the dashboard only answers requests addressed to
  `localhost`/`127.0.0.1`/`::1` or a name in `DASHBOARD_ALLOWED_HOSTS` (otherwise HTTP 421). This
  blocks DNS-rebinding attacks from websites you visit.
* With a user/password, HTTP basic auth protects everything except `/healthz`.
* Every state-changing request needs the header `X-Subtrack: 1`. Browsers can't send it cross-origin
  without a preflight that the dashboard never allows, which blocks CSRF.
* Scanned data (titles, headers, hostnames) is attacker-controlled and is **always rendered as text**,
  never as HTML. A strict Content-Security-Policy, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `nosniff` are set. Links to targets open with
  `noopener noreferrer`, and only `http(s)` links are made clickable.
* CSV exports escape cells starting with `= + - @` (spreadsheet formula injection).

## 12. Accessing the dashboard from another machine

The dashboard speaks **plain HTTP**. Open `http://…`, not `https://…`. If you type `https://`, or the
browser upgrades it on its own, the connection fails with an SSL/protocol error.

### Option A – SSH tunnel (most secure, nothing to configure)

```bash
ssh -L 8080:127.0.0.1:8080 user@your-server
# then open http://127.0.0.1:8080 on your own machine
```

### Option B – directly on your LAN

`.env` on the server:

```ini
DASHBOARD_BIND=0.0.0.0
DASHBOARD_ALLOWED_HOSTS=192.168.178.187        # exactly what you type in the browser, without http:// and port
# or better, a password instead of the host list:
# DASHBOARD_USER=me
# DASHBOARD_PASSWORD=a-long-random-password
```

```bash
docker compose up -d dashboard                 # re-create with the new settings
docker compose ps dashboard                    # must show 0.0.0.0:8080->8080/tcp
curl http://192.168.178.187:8080/healthz       # on the server: {"ok": true, ...}
```

Then open `http://192.168.178.187:8080/`.

* **Edge** may upgrade `http://` to `https://` automatically. Turn off *Automatic HTTPS* under
  `edge://settings/privacy` (or use a private window).
* If `curl` works on the server but not from your PC, a firewall blocks the port, e.g.
  `sudo ufw allow 8080/tcp`.
* `DASHBOARD_ALLOWED_HOSTS` takes several names (`192.168.178.187,nas.local`) or `*`.

### Option C – HTTPS via a reverse proxy

Keep `DASHBOARD_BIND=127.0.0.1`, set a user and password, and put a TLS proxy in front. Caddy, for
example (Caddyfile):

```
subtrack.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

With a password set, the host check is skipped, so the proxy's hostname needs no extra settings.

## 13. Worker, queue & scheduling

### Scans from the dashboard

"New scan", "Re-scan" and "Re-scan all" put a request into the queue (`scan_requests` table). A
**worker** container executes them one after another:

```bash
make worker                    # = docker compose --profile worker up -d worker
make worker-stop
docker compose logs -f worker
```

* The worker uses the defaults from `scanner.env` plus the options chosen in the dialog (passive,
  brute force, TLS SANs, force, ports). For safety the dashboard can only set harmless options:
  never file paths, resolvers or proxies.
* Request statuses: `queued` → `running` → `done` / `failed`, or `cancelled`.
* The worker writes a heartbeat. The dashboard shows it as online when the heartbeat is less than
  3 minutes old (during a long scan the pill shows `scanning…` instead).
* `docker stop` during a scan stops the scan cleanly and puts the request back into the queue. After
  a hard crash, requests left in `running` are marked `failed (worker restarted)`.
* Queued scans just wait while no worker is running. Nothing is lost.

### Automatic re-scans

**With the worker:** set `SCAN_SCHEDULE_HOURS=168` in `.env` (weekly) and start the worker. Every
N hours it queues a re-scan of all domains (trigger `queue:schedule`). It never queues a second one
while one is still pending.

**With cron** on the host (no worker needed):

```cron
# every Monday at 03:17 – re-scan every tracked domain
17 3 * * 1  cd /opt/subtrack && docker compose run --rm -T scanner domain=all trigger=cron >> data/cron.log 2>&1

# every day at 06:43 – quick health check of known hosts only (no discovery)
43 6 * * *  cd /opt/subtrack && docker compose run --rm -T scanner domain=all passive=false brute=false san=false trigger=cron-health >> data/cron.log 2>&1

# first of the month – database backup
5 4 1 * *   cd /opt/subtrack && docker compose run --rm -T scanner mode=backup >> data/cron.log 2>&1
```

`-T` disables the TTY, which cron doesn't have. The per-domain lock makes overlapping runs safe.

**With a systemd timer**, the same: `ExecStart=/usr/bin/docker compose -f /opt/subtrack/docker-compose.yml run --rm -T scanner domain=all`.

## 14. Dashboard API

Everything the UI does goes through a JSON API, so you can script it. Base URL
`http://127.0.0.1:8080`. Send `X-Subtrack: 1` with every POST/PATCH/DELETE, and basic auth if
configured.

| method | path | purpose |
|---|---|---|
| GET | `/healthz` | `{"ok": true}`. No auth (used by the Docker health check) |
| GET | `/api/overview` | counts, events of the last 7 days, last scan, worker and queue state |
| GET | `/api/insights?root=&days=30\|90\|365\|all` | everything on the Overview: daily series, KPIs with previous-period values, breakdowns, watchlists, domains, recent scans |
| GET | `/api/facets` | facet counts for the current filters (takes the asset filter parameters; each facet ignores its own filter) |
| GET | `/api/roots` | root domains with counts |
| PATCH | `/api/roots/{id}` | `{"notes": "…"}` |
| GET | `/api/subdomains` | asset list, filter parameters below |
| GET | `/api/subdomains/{id}` | one asset incl. tags, last raw httpx JSON and last DNS answer |
| PATCH | `/api/subdomains/{id}` | `{"notes": "…"}` (max 20,000 chars) |
| GET | `/api/subdomains/{id}/history` | probe results, events, DNS history, scans of its root |
| POST | `/api/subdomains/{id}/tags` | `{"name": "prod", "color": "#2563eb"}` (tag is created if needed) |
| DELETE | `/api/subdomains/{id}/tags/{tag_id}` | remove a tag from an asset |
| POST | `/api/bulk/tags` | `{"ids": [1,2]}` or `{"filter": {…}}`, plus `"add": [...]` and/or `"remove": [...]` |
| GET | `/api/results/{id}` | the raw httpx JSON of one probe |
| GET / POST | `/api/tags` | list (with counts) / create `{"name", "color"}` |
| PATCH / DELETE | `/api/tags/{id}` | rename/recolour / delete |
| GET | `/api/events` | `type`, `root` (both repeatable), `scan`, `days`, `q` (host contains), `page`, `per_page` (≤500). Also returns `type_counts` |
| GET | `/api/scans` · `/api/scans/{id}` | scan list (`page`, `per_page` ≤200) / details with per-domain stats and warnings |
| GET / POST | `/api/scan-requests` | queue list / enqueue `{"domains": "a.com,b.com" or "all", "params": {…}}` (≤1000 domains) |
| DELETE | `/api/scan-requests/{id}` | cancel a queued request |
| GET | `/api/export?format=csv\|json\|txt\|urls` | export, takes the same filters as `/api/subdomains` |

**Filter parameters** for `/api/subdomains`, `/api/export` and bulk `filter`:

| parameter | meaning |
|---|---|
| `q` | search syntax (section 11) |
| `root` | root domain. Repeat for several (`root=a.com&root=b.com`, OR) |
| `status` | `active` / `offline` (repeatable) |
| `code` | `200`, `4xx`, `301,302` (repeatable, OR) |
| `tech` / `server` | exact technology / web server (repeatable, OR) |
| `tag` / `no_tag` | comma list: must have all / none of these tags |
| `untagged` | `1` = no tags at all |
| `new_days` | first seen within N days |
| `changed_days` | went offline or came back within N days |
| `event` + `event_days` | had an event of this type within N days |
| `ids` | comma list of asset ids |
| `sort` | `host`, `first_seen`, `last_seen`, `last_checked`, `status_code`, `title`, `status`, `webserver`, `status_changed_at`, `seen_count`, `root` |
| `order` | `asc` / `desc` |
| `page`, `per_page` | pagination (`per_page` ≤ 1000) |

Examples:

```bash
# all active hosts of a domain, as a plain list (e.g. to feed into other tools)
curl -s 'http://127.0.0.1:8080/api/export?format=txt&status=active&root=example.com'

# alive URLs that are new this week
curl -s 'http://127.0.0.1:8080/api/export?format=urls&new_days=7'

# everything that changed in the last day, as JSON
curl -s 'http://127.0.0.1:8080/api/events?type=changed,offline,back_online&days=1'

# queue a scan from a script (a worker must be running)
curl -s -X POST -H 'X-Subtrack: 1' -H 'Content-Type: application/json' \
     -d '{"domains": "example.com", "params": {"brute": false}}' http://127.0.0.1:8080/api/scan-requests

# tag every 401/403 host as "auth"
curl -s -X POST -H 'X-Subtrack: 1' -H 'Content-Type: application/json' \
     -d '{"filter": {"code": "401,403"}, "add": ["auth"]}' http://127.0.0.1:8080/api/bulk/tags
```

## 15. Data, database & SQL cookbook

### Layout

```
data/
├── tracker.db (+ -wal, -shm)   SQLite database – the source of truth
├── scans/00042/                raw tool output and log of scan #42 (section 8.10)
├── backups/                    make backup
└── locks/                      per-domain lock files
```

### Tables

| table | one row per | key columns |
|---|---|---|
| `roots` | root domain | `domain`, `created_at`, `last_scan_id`, `last_scan_at`, `wildcard`, `notes` |
| `subdomains` | host (never deleted) | `host`, `root_id`, `status`, `offline_reason`, `first_seen`, `last_seen`, `last_checked`, `status_changed_at`, `seen_count`, `sources`, `dns_resolves`, snapshot: `url`, `urls`, `scheme`, `port`, `status_code`, `title`, `webserver`, `content_type`, `content_length`, `location`, `tech`, `ips`, `cname`, `cdn_name`, `body_hash`, `favicon`, `tls_subject_cn`, `tls_issuer`, `tls_not_after`, `last_result_id`, `notes` |
| `httpx_results` | probed URL per scan | `scan_id`, `subdomain_id`, `observed_at`, `phase` (`main`/`san`/`recheck`), `url`, `status_code`, `title`, `webserver`, `content_length`, `body_hash`, **`raw`** (the full httpx JSON line, verbatim) |
| `dns_results` | tracked host per scan | `scan_id`, `subdomain_id`, `resolves`, `a`, `aaaa`, `cname`, `raw` (dnsx JSON) |
| `events` | lifecycle event | `scan_id`, `root_id`, `subdomain_id`, `type`, `created_at`, `details` (JSON) |
| `scans` | scan run | `started_at`, `finished_at`, `status`, `trigger`, `params`, `tool_versions`, `output_dir`, `error` |
| `scan_roots` | domain per scan | `status`, `stats` (JSON: candidates, resolved, probed, alive, new, changed, went_offline, back_online, still_offline, unchanged, passive, brute, tls_san, rechecked, wildcard, duration_s, …), `warnings` |
| `tags`, `subdomain_tags` | tag / assignment | `name` (unique, case-insensitive), `color` |
| `scan_requests` | dashboard queue entry | `domains`, `params`, `source`, `status`, `scan_id`, `error` |
| `meta` | setting | `schema_version`, `worker_heartbeat`, `last_scheduled_scan` |

JSON list columns (`tech`, `ips`, `cname`, `sources`, `urls`) can be queried with SQLite's JSON
functions (`json_each`, `json_extract`). All timestamps are UTC, ISO 8601 (`2026-11-05T01:18:09Z`).

### Querying

On the host with `sqlite3 data/tracker.db` (`apt install sqlite3`), or without installing anything:

```bash
docker compose run --rm --entrypoint python scanner -c \
  "import sqlite3; c = sqlite3.connect('/data/tracker.db'); print(c.execute('SELECT COUNT(*) FROM subdomains').fetchone())"
```

Reading is always safe, even during a scan.

### SQL cookbook

```sql
-- hosts that went offline in the last 30 days, and why
SELECT s.host, e.created_at, json_extract(e.details, '$.reason') AS reason
FROM events e JOIN subdomains s ON s.id = e.subdomain_id
WHERE e.type = 'offline' AND e.created_at >= strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-30 days')
ORDER BY e.created_at DESC;

-- new hosts per month
SELECT substr(first_seen, 1, 7) AS month, COUNT(*) FROM subdomains GROUP BY month ORDER BY month;

-- every title a host ever had
SELECT DISTINCT title, MIN(observed_at) AS first, MAX(observed_at) AS last
FROM httpx_results WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'www.example.com')
GROUP BY title ORDER BY first;

-- the full httpx JSON of the latest probe of a host
SELECT raw FROM httpx_results
WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'www.example.com') ORDER BY id DESC LIMIT 1;

-- anything inside the stored JSON, e.g. the TLS version of every active host
SELECT s.host, json_extract(h.raw, '$.tls.tls_version')
FROM subdomains s JOIN httpx_results h ON h.id = s.last_result_id WHERE s.status = 'active';

-- TLS certificates expiring in the next 21 days
SELECT host, tls_not_after FROM subdomains
WHERE status = 'active' AND tls_not_after < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+21 days')
ORDER BY tls_not_after;

-- possible subdomain takeovers: CNAME exists but the host no longer resolves
SELECT host, cname, status_changed_at FROM subdomains
WHERE status = 'offline' AND offline_reason = 'dns' AND cname != '[]';

-- most common technologies
SELECT j.value AS tech, COUNT(*) FROM subdomains, json_each(subdomains.tech) j
WHERE status = 'active' GROUP BY tech ORDER BY 2 DESC LIMIT 20;

-- which passive source finds the most validated hosts
SELECT j.value AS source, COUNT(*) FROM subdomains, json_each(subdomains.sources) j
GROUP BY source ORDER BY 2 DESC;

-- hosts serving an identical page (same body hash), e.g. a wildcard catch-all
SELECT body_hash, COUNT(*), group_concat(host, ' ') FROM subdomains
WHERE body_hash IS NOT NULL GROUP BY body_hash HAVING COUNT(*) > 3 ORDER BY 2 DESC;

-- uptime: in how many of its root's scans did each host answer?
SELECT s.host, s.seen_count,
       (SELECT COUNT(*) FROM scan_roots sr WHERE sr.root_id = s.root_id AND sr.scan_id >= s.first_scan_id
          AND sr.status IN ('success', 'partial')) AS scans_since_first_seen
FROM subdomains s ORDER BY s.host;

-- hosts with a given tag
SELECT s.host FROM subdomains s JOIN subdomain_tags st ON st.subdomain_id = s.id
JOIN tags t ON t.id = st.tag_id WHERE t.name = 'interesting';
```

### Removing a host anyway

By design nothing is ever deleted. If you really need to remove one, stop the worker and make a
backup first, then run (in this order, because of the foreign keys):

```sql
DELETE FROM httpx_results WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'junk.example.com');
DELETE FROM dns_results   WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'junk.example.com');
DELETE FROM events        WHERE subdomain_id = (SELECT id FROM subdomains WHERE host = 'junk.example.com');
DELETE FROM subdomains    WHERE host = 'junk.example.com';   -- tags are removed automatically
```

If it is still out there, the next scan will find and add it again. Usually a tag like `ignore` plus
`-tag:ignore` in your searches is the better choice.

### Storage estimates

Each probe stores the full httpx JSON: about 1.5 KB for a minimal site, typically 3–5 KB for a real
one (headers, TLS details), plus about 0.3 KB of DNS data. As a rule of thumb, **2,000 hosts scanned
weekly for a year ≈ 0.5 GB**. The raw files under `data/scans/` take about as much again and can be
deleted at any time.

## 16. Backups, restore & moving servers

```bash
make backup                                          # -> data/backups/tracker-20261105-011915.db
```

The backup uses SQLite's online backup API, so it's consistent even while the dashboard or a scan is
running. **Copying `tracker.db` with `cp` while it's in use is not safe** (the WAL file holds recent
writes). Use `make backup`, or stop everything first.

**Restore:**

```bash
docker compose --profile worker down                 # stop dashboard + worker; make sure no scan runs
cp data/backups/tracker-20261105-011915.db data/tracker.db
rm -f data/tracker.db-wal data/tracker.db-shm
make up
```

**Move to another server:** stop everything, copy the whole `data/` folder (and `config/`, `.env`,
`scanner.env`) to the new machine, `make build && make up`. Or copy only a backup file as
`data/tracker.db`. The raw scan folders are optional.

## 17. Recipes

| goal | command |
|---|---|
| add a new domain | `make scan domain=newcorp.com` (or *Domains → Add domain* with a worker) |
| re-scan everything | `make rescan` |
| fast "what's still up?" check (no discovery) | `make scan domain=all passive=false brute=false san=false` |
| deep scan with a big wordlist | `make scan domain=x.com wordlist=/config/big.txt dns_rate_limit=500` |
| scan non-standard web ports | `make scan domain=x.com ports=80,443,8000,8080,8443,8888,9443` |
| validate hosts from another tool (amass, crt.sh dumps, …) | put them in `config/hosts.txt`, then `make scan domain=x.com import_file=/config/hosts.txt` |
| use trusted resolvers | `config/resolvers.txt` (one IP per line), `SCAN_RESOLVERS=/config/resolvers.txt` in `scanner.env` |
| scan through a proxy / VPN gateway | `make scan domain=x.com proxy=socks5://10.8.0.1:1080` |
| it really went dark, mark everything offline | `make scan domain=x.com force=true` |
| list of everything new this week | dashboard tile *New · 7d*, or `curl …/api/export?format=txt&new_days=7` |
| hide noise | tag it `ignore` (bulk), then search `-tag:ignore` |
| find all login pages | search `title:login` or `title:"sign in"`, bulk-tag `login` |
| find dangling CNAMEs | SQL cookbook → "possible subdomain takeovers" |
| shell inside the scanner image | `make shell`, then run `subfinder`, `dnsx`, `httpx` by hand |

## 18. Tuning for large scopes

* **Passive time:** `subfinder_max_time` (minutes per domain) is the biggest lever for big
  organisations. `subfinder_all=false` uses only subfinder's default sources (faster).
* **Probe speed:** `threads` and `rate_limit` (httpx). Lower them if the target or your network
  struggles. Raise them on a strong VPS. Every extra port in `ports=` multiplies the probe count.
* **DNS:** `dns_threads` and `dns_rate_limit`. Public resolvers rate-limit aggressive brute
  forcing. Use your own resolver list for large wordlists.
* **Timeouts:** `timeout`/`retries` decide how quickly a slow host is given up. The recheck already
  doubles them for hosts that vanished.
* **Splitting work:** run cheap health checks often (`passive=false brute=false san=false`) and
  full discovery less often (weekly/monthly).
* **Being polite:** the default 150 requests/second is fine for most programmes. Check the rules of
  your bug bounty programme and lower `rate_limit` if required.

## 19. Tests

```bash
make test         # builds the `test` image and runs the suite inside it
```

31 tests:

* **Unit (`tests/test_ingest.py`):** new/unchanged/changed detection, CDN IP rotation is ignored,
  offline with reason `dns`/`http`, still-offline, back-online, nothing deleted, a failed probe
  never marks offline, the mass-offline guard and `force`, out-of-scope and failed records ignored,
  primary URL choice, raw JSON stored verbatim, tags survive re-scans, overlapping roots, hostname
  normalisation, argument parsing.
* **Dashboard (`tests/test_web.py`):** a real server on a random port. Covers search syntax,
  filters, pagination, LIKE escaping, detail/history/raw JSON, tag CRUD and bulk tagging, notes,
  exports, queue validation, the CSRF header, DNS-rebinding protection, basic auth and path
  traversal.
* **End-to-end (`tests/test_e2e.py`):** a lab with its own authoritative DNS server plus HTTP/HTTPS
  servers (`tests/lab/labserver.py`), driven by a JSON state file. Between five scans hosts appear,
  change titles, lose their web server, lose DNS, come back, and finally simulate a total outage
  (the guard must hold) and a forced one. It also covers wildcard domains, TLS-SAN discovery, HTTPS →
  HTTP fallback, subfinder failure, `domain=all`, `mode=status`, invalid input and the worker
  processing a dashboard request. The e2e tests use the **real dnsx and httpx** binaries. subfinder
  is replaced by `tests/fake_subfinder.py` because passive sources need the internet.

Run them without Docker: `pip install dnslib==0.9.26`, put `dnsx` and `httpx` on the `PATH` (or set
`DNSX_BIN`/`HTTPX_BIN`), then `python3 -m unittest discover -s tests -t .`. The e2e tests need ports
80/443 (run as root) or `LAB_HTTP_PORT=8080 LAB_HTTPS_PORT=8443`. Without the tools they're skipped.
`KEEP_E2E=1` keeps the lab's temporary data for inspection.

## 20. Running without Docker

Requirements: Python ≥ 3.10 with SQLite ≥ 3.35 (any current Linux/macOS), and subfinder, dnsx and
httpx on the `PATH`:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0
go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0

export TRACKER_DATA=$PWD/data
python3 -m tracker.scan domain=example.com
DASHBOARD_PORT=8080 python3 -m tracker.web          # dashboard on http://127.0.0.1:8080
```

Make sure the `httpx` on the `PATH` is ProjectDiscovery's, not the Python package of the same name.
Without Docker, the API key file is not auto-detected: pass `provider_config=~/.config/subfinder/provider-config.yaml`
(or rely on subfinder's own default location).

## 21. Upgrading

* **subtrack itself:** `git pull && make build && make up`. Database migrations run automatically on
  first start. Make a backup before upgrading.
* **The tools:** change `SUBFINDER_VERSION`, `DNSX_VERSION`, `HTTPX_VERSION` at the top of the
  `Dockerfile` and run `make build`. Or a one-off:
  `docker build --build-arg HTTPX_VERSION=v1.x.y --target scanner -t subtrack-scanner .`.
  Every scan records the tool versions it used (scan detail → *Parameters & tool versions*). Old raw
  JSON stays untouched, even if a newer httpx changes its output format.
* **Base images:** `GO_IMAGE`/`PY_IMAGE` in `.env`.

## 22. Troubleshooting

| symptom | cause / fix |
|---|---|
| browser: `ERR_SSL_PROTOCOL_ERROR` / connection reset | you opened `https://`. The dashboard is plain `http://` (section 12). Edge: disable *Automatic HTTPS* |
| dashboard: "Host not allowed" (421) | not opened via `localhost`: add the name/IP to `DASHBOARD_ALLOWED_HOSTS` or set a password, then `docker compose up -d dashboard` |
| dashboard not reachable from another PC | `DASHBOARD_BIND=0.0.0.0` missing (check `docker compose ps`), or a firewall blocks the port |
| `429 Too Many Requests` when building | Docker Hub rate limit: set `GO_IMAGE=mirror.gcr.io/library/golang:1.26` and `PY_IMAGE=mirror.gcr.io/library/python:3.13-slim` in `.env` |
| `x509: certificate signed by unknown authority` during the build | a TLS-intercepting (corporate) proxy: `docker build --secret id=ca,src=/path/proxy-ca.pem --target scanner -t subtrack-scanner .` (same for `--target dashboard -t subtrack-dashboard`) |
| scan is `partial`: "offline guard" | most known hosts didn't answer. Check `data/scans/<id>/scan.log` and your connectivity/resolvers, re-run. If it's real: `force=true` |
| scan is `partial`: "subfinder failed / timed out" | the passive results so far were used. Raise `subfinder_max_time`, check API keys |
| scan `skipped` | another scan is processing that domain right now (lock in `data/locks/`) |
| very few passive results | add subfinder API keys (section 5) |
| unstable DNS results, many timeouts | resolvers are rate limiting you: `resolvers=/config/resolvers.txt`, lower `dns_threads` / `rate_limit` |
| queued dashboard scans never start | no worker: `make worker` (the pill in the top bar shows the state) |
| `database is locked` | normally impossible on Linux (WAL + retries). On Docker Desktop bind mounts (macOS/Windows), set `DATA_DIR` to a path inside the Docker VM or use a named volume |
| files in `./data` are owned by root | the containers run as root so bind mounts always work: `sudo chown -R $USER data` |
| `unknown option 'xyz'` | typo in an option, see `./scan help` |
| a scan seems stuck | each tool has a hard limit (section 8.8). Follow `data/scans/<id>/scan.log` and the `*.stderr.log` files |

## 23. FAQ & known limitations

**Why SQLite and not Postgres?** One file, no server to run, trivial backups, and it comfortably
handles hundreds of thousands of hosts and millions of probe rows. The dashboard reads while scans
write (WAL). Postgres would only be worth it with many concurrent writers.

**Why aren't DNS-only hosts (no web server) stored?** You asked for httpx-validated hosts only.
They show up in the raw `dnsx-main.jsonl` of each scan, and if they start serving HTTP later, the
next scan adds them automatically.

**Wildcard domains:** brute-force noise is filtered, but passive names on a wildcard domain all
resolve and are answered by the catch-all page, so they are added. Find them with `hash:<body hash>`
(or the "identical page" SQL query), bulk-tag them `wildcard`, and exclude them with `-tag:wildcard`.
Also, on wildcard domains a host never goes offline for DNS reasons, because the wildcard always answers.

**HTTP ↔ HTTPS flapping:** with the default ports, httpx tries HTTPS and falls back to HTTP. A host
whose HTTPS times out occasionally shows a `url` change in that scan. That is real information, but
it can be noise. `ports=80,443` probes both every time.

**Is the response body stored?** No, only its SHA-256, word and line counts. Headers, TLS details and
everything else httpx reports are stored.

**IPv6?** AAAA records are resolved and stored, and httpx connects over whatever the system supports.

**Non-web services (SSH, mail, …)?** Out of scope. This tracks web-facing hosts.

**Can I import my old results?** Yes: put the hosts in a file and scan with `import_file=`. They are
validated like everything else.

**Can several scanners run at once?** Yes, for different domains. The same domain is protected by
its lock. SQLite serialises the short write transactions.

**Does the dashboard have HTTPS?** No. Use an SSH tunnel or a reverse proxy (section 12).

**Testing caveat:** the test-suite runs the real dnsx and httpx against the local lab, but stubs
subfinder (passive sources need the internet). The real subfinder runs in the Docker image and its
output format is handled as documented by subfinder (`-oJ -cs`).

## 24. Repository layout

```
.
├── Dockerfile                  targets: scanner (default), dashboard, test
├── docker-compose.yml          dashboard, scanner (profile scan), worker (profile worker)
├── Makefile                    build/up/down/logs/scan/rescan/status/backup/worker/shell/test
├── scan                        wrapper: docker compose run --rm -T scanner "$@"
├── .env.example                compose settings
├── scanner.env.example         default scan options (SCAN_*)
├── config/
│   └── subfinder/provider-config.yaml.example
├── wordlists/
│   └── common-subdomains.txt   built-in brute-force list (108 words)
├── tracker/                    the Python package (stdlib only)
│   ├── scan.py                 CLI: argument parsing, modes, scan orchestration, locks, worker
│   ├── pipeline.py             runs subfinder/dnsx/httpx with timeouts, collects results
│   ├── ingest.py               merges results into the DB: lifecycle, change detection, guard
│   ├── db.py                   schema, migrations, connections, backup
│   ├── hosts.py                hostname normalisation and scope checks
│   └── web/
│       ├── server.py           HTTP server, routing, auth, security headers
│       ├── api.py              queries and mutations behind the API
│       └── static/             index.html, app.js, app.css, favicon.svg (no external assets)
└── tests/
    ├── test_ingest.py · test_web.py · test_e2e.py
    ├── fake_subfinder.py
    └── lab/labserver.py        DNS + HTTP/HTTPS test lab
```
