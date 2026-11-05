# syntax=docker/dockerfile:1
#
# One Dockerfile, three targets:
#   scanner   (default) – python + subfinder/dnsx/httpx, entrypoint = the scan CLI
#   dashboard           – python only, serves the web UI/API
#   test                – scanner + test lab, runs the test-suite
#
# Base images are build args so you can point them at a mirror, e.g.
#   --build-arg GO_IMAGE=mirror.gcr.io/library/golang:1.26
# Behind a TLS-intercepting (corporate) proxy pass its CA certificate:
#   docker build --secret id=ca,src=/path/to/proxy-ca.pem ...
ARG GO_IMAGE=golang:1.26
ARG PY_IMAGE=python:3.13-slim

# --------------------------------------------------------------------------- #
FROM ${GO_IMAGE} AS tools
ARG SUBFINDER_VERSION=v2.17.0
ARG DNSX_VERSION=v1.3.1
ARG HTTPX_VERSION=v1.12.0
ENV CGO_ENABLED=0 GOBIN=/out GOTOOLCHAIN=auto GOFLAGS=-trimpath
RUN --mount=type=secret,id=ca,required=false <<'SH'
set -eu
if [ -s /run/secrets/ca ]; then
  cat /etc/ssl/certs/ca-certificates.crt /run/secrets/ca > /tmp/ca.pem
  export SSL_CERT_FILE=/tmp/ca.pem
fi
go install -ldflags="-s -w" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}"
go install -ldflags="-s -w" "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}"
go install -ldflags="-s -w" "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"
rm -f /tmp/ca.pem
SH
RUN /out/subfinder -version && /out/dnsx -version && /out/httpx -version

# --------------------------------------------------------------------------- #
FROM ${PY_IMAGE} AS base
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TRACKER_DATA=/data
WORKDIR /app
COPY tracker/ /app/tracker/
VOLUME ["/data"]

# --------------------------------------------------------------------------- #
FROM base AS dashboard
ENV DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('DASHBOARD_PORT', '8080'), timeout=4)"]
CMD ["python", "-m", "tracker.web"]

# --------------------------------------------------------------------------- #
FROM base AS test
COPY --from=tools /out/ /usr/local/bin/
COPY wordlists/ /app/wordlists/
RUN --mount=type=secret,id=ca,required=false <<'SH'
set -eu
if [ -s /run/secrets/ca ]; then
  cat "$(python -c 'import ssl; print(ssl.get_default_verify_paths().openssl_cafile)')" /run/secrets/ca > /tmp/ca.pem
  export PIP_CERT=/tmp/ca.pem
fi
pip install --no-cache-dir --root-user-action=ignore dnslib==0.9.26
rm -f /tmp/ca.pem
SH
COPY tests/ /app/tests/
ENTRYPOINT ["python", "-m", "unittest", "discover", "-v", "-s", "/app/tests", "-t", "/app"]

# --------------------------------------------------------------------------- #
FROM base AS scanner
COPY --from=tools /out/ /usr/local/bin/
COPY wordlists/ /app/wordlists/
ENTRYPOINT ["python", "-m", "tracker.scan"]
CMD ["help"]
