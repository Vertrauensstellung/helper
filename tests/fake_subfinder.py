#!/usr/bin/env python3
"""Stand-in for subfinder in tests (passive sources need the internet).

Reads FAKE_SUBFINDER_DATA (JSON: {"root": [["host", ["source", ...]], ...]}) and
writes subfinder-compatible `-oJ -cs` JSON lines to the -o file.
"""
import json
import os
import sys

args = sys.argv[1:]
if "-version" in args:
    print("[INF] Current Version: v2.17.0-fake", file=sys.stderr)
    sys.exit(0)
domain = args[args.index("-d") + 1]
out = args[args.index("-o") + 1]
data = {}
path = os.environ.get("FAKE_SUBFINDER_DATA")
if path and os.path.exists(path):
    with open(path) as fh:
        data = json.load(fh)
if os.environ.get("FAKE_SUBFINDER_FAIL"):
    print("[FTL] simulated failure", file=sys.stderr)
    sys.exit(1)
with open(out, "w") as fh:
    for host, sources in data.get(domain, []):
        fh.write(json.dumps({"host": host, "input": domain, "sources": sources}) + "\n")
