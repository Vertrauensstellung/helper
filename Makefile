# subtrack – convenience targets around docker compose.
#
#   make build
#   make up                                   # dashboard -> http://127.0.0.1:8080
#   make scan domain=example.com              # scan one or more (comma separated) root domains
#   make scan domain=example.com brute=false ports=80,443,8080,8443
#   make scan file=/data/targets.txt          # one domain per line (path inside the container)
#   make rescan                               # re-scan every tracked domain
#   make status | make backup | make test | make logs | make down

COMPOSE ?= docker compose
RUN     := $(COMPOSE) run --rm -T scanner

# Any of these given on the make command line is passed through to the scanner as key=value.
SCAN_OPTS := passive subfinder_all subfinder_sources subfinder_max_time brute wordlist san recheck import_file \
             ports follow_redirects threads rate_limit timeout retries httpx_max_time dns_threads dns_rate_limit \
             resolvers proxy force guard_ratio guard_min_active
PASS    := $(foreach v,$(SCAN_OPTS),$(if $(filter command line,$(origin $(v))),$(v)=$($(v))))

.PHONY: help build up down logs scan rescan status backup worker worker-stop test shell

help:
	@sed -n '2,12p' Makefile | sed 's/^# \{0,1\}//'

build:
	$(COMPOSE) --profile scan --profile worker build

up:
	$(COMPOSE) up -d dashboard
	@echo "dashboard: http://$${DASHBOARD_BIND:-127.0.0.1}:$${DASHBOARD_PORT:-8080}"

down:
	$(COMPOSE) --profile worker down

logs:
	$(COMPOSE) --profile worker logs -f --tail=200

scan:
	@if [ -z "$(domain)$(file)" ]; then echo "usage: make scan domain=example.com   (or domain=a.com,b.com | domain=all | file=/data/targets.txt)"; exit 2; fi
	$(RUN) $(if $(domain),domain=$(domain)) $(if $(file),file=$(file)) $(PASS) $(ARGS)

rescan:
	$(RUN) domain=all $(PASS) $(ARGS)

status:
	$(RUN) mode=status

backup:
	$(RUN) mode=backup

worker:
	$(COMPOSE) --profile worker up -d worker

worker-stop:
	$(COMPOSE) --profile worker stop worker

shell:
	$(COMPOSE) run --rm --entrypoint bash scanner

test:
	docker build --target test -t subtrack-test $(BUILD_ARGS) .
	docker run --rm subtrack-test
