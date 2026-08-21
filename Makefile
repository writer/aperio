# Aperio local development.
#
# `make` (or `make help`) lists every target. The common loop is:
#
#   make setup     # one-time: .env, deps, database, migrations, seed data
#   make dev       # run the Go API and the Next.js console together
#
# DATABASE_URL and APERIO_NATS_URL in .env are the single source of truth for
# local infrastructure: docker-compose publishes Postgres/NATS on the host
# ports embedded in those URLs, so changing a port is a one-line .env edit.

SHELL := /bin/bash
.DEFAULT_GOAL := help

ENV_FILE ?= .env
WEB_PORT ?= 3000
API_ADDR ?= :4100
PRISMA_SCHEMA := packages/db/prisma/schema.prisma
DEV_CONFIG := scripts/dev-config.mjs
BUF_VERSION := v1.59.0
COMPOSE := docker compose -p aperio
GO_SRC_DIRS := cmd internal
GO_WORKER_ARGS ?=

BOLD := \033[1m
DIM := \033[2m
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
CYAN := \033[36m
RESET := \033[0m

# Quote-safe .env loader for recipe shells. Explicit environment variables win
# over values from ENV_FILE so alternate-port test runs can override .env.
LOAD_ENV := eval "$$(node scripts/load-env-shell.mjs "$(ENV_FILE)")";

##@ Help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\n$(BOLD)Aperio local development$(RESET)\n\nUsage: make $(CYAN)<target>$(RESET)\n"} /^[a-zA-Z0-9_.-]+:.*##/ { printf "  $(CYAN)%-18s$(RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BOLD)%s$(RESET)\n", substr($$0, 5) }' $(MAKEFILE_LIST)
	@printf "\n"

##@ Setup

.PHONY: setup
setup: env install db-generate db-up migrate seed ## One-command bootstrap for a fresh checkout
	@printf '$(GREEN)Setup complete.$(RESET) Start the stack with: $(BOLD)make dev$(RESET)\n'

.PHONY: env
env: ## Create .env from .env.example if it does not exist
	@if [ -f $(ENV_FILE) ]; then \
		printf '$(DIM)%s already exists; leaving it untouched.$(RESET)\n' "$(ENV_FILE)"; \
	else \
		cp .env.example $(ENV_FILE); \
		printf '$(GREEN)Created %s from .env.example.$(RESET) Fill in real secrets before sharing.\n' "$(ENV_FILE)"; \
	fi

.PHONY: install
install: ## Install Node dependencies (npm ci)
	@npm ci

.PHONY: doctor
doctor: ## Check the local toolchain and infra ports
	@printf '$(BOLD)Toolchain$(RESET)\n'
	@for tool in go node npm docker; do \
		if command -v $$tool >/dev/null 2>&1; then \
			case $$tool in \
				go) ver="$$(go version 2>&1)";; \
				*) ver="$$($$tool --version 2>&1 | head -1)";; \
			esac; \
			printf '  $(GREEN)ok$(RESET)   %-6s %s\n' "$$tool" "$$ver"; \
		else \
			printf '  $(RED)miss$(RESET) %-6s not found on PATH\n' "$$tool"; \
		fi; \
	done
	@printf '$(BOLD)Configuration$(RESET)\n'
	@if [ -f $(ENV_FILE) ]; then \
		$(LOAD_ENV) printf '  $(GREEN)ok$(RESET)   %s present\n' "$(ENV_FILE)"; \
		$(LOAD_ENV) printf '  $(DIM)Postgres host port: %s | NATS port: %s$(RESET)\n' "$$(node $(DEV_CONFIG) db-port)" "$$(node $(DEV_CONFIG) nats-port)"; \
	else \
		printf '  $(YELLOW)warn$(RESET) %s missing; run: make env\n' "$(ENV_FILE)"; \
	fi

##@ Run

.PHONY: dev
dev: require-env ## Run the API and web console together (Ctrl-C stops both)
	@$(MAKE) --no-print-directory db-up migrate
	@$(LOAD_ENV) printf '$(GREEN)API$(RESET) on %s   $(GREEN)Web$(RESET) on http://localhost:%s   (Ctrl-C to stop)\n' "$${APERIO_CONNECT_ADDR:-$(API_ADDR)}" "$(WEB_PORT)"
	@$(MAKE) --no-print-directory -j2 _run-api _run-web

.PHONY: api
api: require-env ## Run only the Go/ConnectRPC API (brings up + migrates the DB)
	@$(MAKE) --no-print-directory db-up migrate
	@$(MAKE) --no-print-directory _run-api

.PHONY: web
web: require-env ## Run only the Next.js console
	@$(MAKE) --no-print-directory _run-web

.PHONY: _run-api
_run-api: require-env
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/aperio

.PHONY: _run-web
_run-web: require-env
	@$(LOAD_ENV) npx next dev apps/web -p $(WEB_PORT)

.PHONY: worker-ingestion
worker-ingestion: require-env ## Run the Go ingestion worker
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/ingestion-worker $(GO_WORKER_ARGS)

.PHONY: worker-ingestion-go
worker-ingestion-go: worker-ingestion ## Alias for the Go ingestion worker

.PHONY: worker-siem
worker-siem: require-env ## Run the Go SIEM dispatcher worker
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/siem-dispatcher $(GO_WORKER_ARGS)

.PHONY: worker-siem-go
worker-siem-go: worker-siem ## Alias for the Go SIEM dispatcher worker

.PHONY: worker-google
worker-google: require-env ## Run the Go Google Workspace audit-log poller
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/google-workspace-poller $(GO_WORKER_ARGS)

.PHONY: worker-google-go
worker-google-go: worker-google ## Alias for the Go Google Workspace poller

.PHONY: worker-google-bigquery
worker-google-bigquery: require-env ## Run the Go Google Workspace BigQuery sync
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/google-workspace-bigquery-sync $(GO_WORKER_ARGS)

.PHONY: worker-google-bigquery-go
worker-google-bigquery-go: worker-google-bigquery ## Alias for the Go Google Workspace BigQuery sync

.PHONY: worker-google-directory
worker-google-directory: require-env ## Run the Go Google Workspace directory sync
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/google-workspace-directory-sync $(GO_WORKER_ARGS)

.PHONY: worker-google-directory-go
worker-google-directory-go: worker-google-directory ## Alias for the Go Google Workspace directory sync

.PHONY: worker-google-oauth
worker-google-oauth: require-env ## Run the Go Google Workspace OAuth grant sync
	@$(MAKE) --no-print-directory db-up
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/google-workspace-oauth-sync $(GO_WORKER_ARGS)

.PHONY: worker-google-oauth-go
worker-google-oauth-go: worker-google-oauth ## Alias for the Go Google Workspace OAuth sync

.PHONY: smoke-workers-go
smoke-workers-go: require-env ## Run bounded Go worker smokes
	@$(MAKE) --no-print-directory db-up migrate
	@$(LOAD_ENV) npm run worker:ingestion -- -once -limit 1
	@$(LOAD_ENV) npm run worker:siem -- -once -limit 1
	@$(LOAD_ENV) npm run smoke:siem:adapters

.PHONY: smoke-e2e
smoke-e2e: require-env ## Run the local Go API + TypeScript FE E2E smoke harness
	@$(LOAD_ENV) ENV_FILE="$(ENV_FILE)" npm run smoke:e2e

.PHONY: mcp
mcp: require-env ## Run the Go stdio MCP broker
	@$(LOAD_ENV) DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go run ./cmd/mcp-broker

##@ Database & infra

.PHONY: up
up: db-up nats-up ## Start all local infrastructure (Postgres + NATS)

.PHONY: down
down: ## Stop local infrastructure (data is kept)
	@$(COMPOSE) stop

.PHONY: ps
ps: ## Show local infrastructure status
	@$(COMPOSE) ps

.PHONY: logs
logs: ## Tail local infrastructure logs
	@$(COMPOSE) logs -f --tail=100

.PHONY: db-up
db-up: require-env ## Start Postgres on the port from DATABASE_URL
	@$(LOAD_ENV) set -e; export APERIO_POSTGRES_PORT=$$(node $(DEV_CONFIG) db-port); \
		printf '$(CYAN)Starting Postgres on host port %s ...$(RESET)\n' "$$APERIO_POSTGRES_PORT"; \
		$(COMPOSE) up -d --wait postgres; \
		node $(DEV_CONFIG) wait postgres "$$DATABASE_URL" 60000

.PHONY: nats-up
nats-up: require-env ## Start NATS on the port from APERIO_NATS_URL
	@$(LOAD_ENV) set -e; export APERIO_NATS_PORT=$$(node $(DEV_CONFIG) nats-port); \
		export APERIO_NATS_MONITOR_PORT=$$(node $(DEV_CONFIG) nats-monitor-port); \
		printf '$(CYAN)Starting NATS on host port %s ...$(RESET)\n' "$$APERIO_NATS_PORT"; \
		$(COMPOSE) up -d --wait nats; \
		node $(DEV_CONFIG) wait nats "$$APERIO_NATS_URL" 60000

.PHONY: migrate
migrate: require-env ## Apply pending Prisma migrations
	@$(LOAD_ENV) npx prisma migrate deploy --schema $(PRISMA_SCHEMA)

.PHONY: migrate-new
migrate-new: require-env ## Create and apply a new migration (name=...)
	@$(LOAD_ENV) npx prisma migrate dev --schema $(PRISMA_SCHEMA) $(if $(name),--name $(name),)

.PHONY: seed
seed: require-env ## Seed the demo organization and example data
	@$(LOAD_ENV) npx tsx scripts/seed.ts

.PHONY: psql
psql: ## Open a psql shell in the Postgres container
	@$(COMPOSE) exec postgres psql -U aperio -d aperio

.PHONY: db-reset
db-reset: require-env ## Drop and recreate the local DB schema, then migrate (DESTROYS DATA)
	@$(MAKE) --no-print-directory db-up
	@printf '$(YELLOW)Dropping the public schema in the local database ...$(RESET)\n'
	@$(COMPOSE) exec -T postgres psql -U aperio -d aperio -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
	@$(MAKE) --no-print-directory migrate
	@printf '$(GREEN)Database reset.$(RESET) Run: make seed\n'

.PHONY: db-generate
db-generate: ## Generate the Prisma client
	@npm run db:generate

.PHONY: db-validate
db-validate: ## Validate the Prisma schema
	@npm run db:validate

##@ Contracts (protobuf)

.PHONY: generate
generate: ## Regenerate Go + TypeScript protobuf clients (needs network)
	@go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) generate --template buf.gen.go.yaml --exclude-path proto/cerebro
	@go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION) generate --template buf.gen.ts.yaml

.PHONY: generate-check
generate-check: generate ## Verify the generated clients are up to date
	@git diff --exit-code -- gen packages/connect/src/gen && \
		test -z "$$(git status --porcelain -- gen packages/connect/src/gen)" && \
		printf '$(GREEN)Generated clients are current.$(RESET)\n'

.PHONY: proto-lint
proto-lint: ## Lint protobuf contracts (buf lint)
	@npm run proto:lint

##@ Quality

.PHONY: fmt
fmt: ## Format Go sources
	@gofmt -l -w $(GO_SRC_DIRS)

.PHONY: fmt-check
fmt-check: ## Fail if Go sources are not gofmt-clean
	@unformatted="$$(gofmt -l $(GO_SRC_DIRS))"; \
		if [ -n "$$unformatted" ]; then \
			printf '$(RED)gofmt needed:$(RESET)\n%s\n' "$$unformatted"; exit 1; \
		fi

.PHONY: vet
vet: ## Run go vet
	@go vet ./...

.PHONY: lint
lint: fmt-check vet proto-lint ## Run Go + protobuf linters

.PHONY: typecheck
typecheck: ## TypeScript type checking
	@npm run typecheck

.PHONY: guardrails-migration
guardrails-migration: ## Run migration ownership and runtime guardrails
	@npm run guardrails:migration

.PHONY: test
test: test-go test-api ## Run Go and API tests

.PHONY: test-go
test-go: ## Run Go unit tests
	@go test ./...

.PHONY: test-go-db
test-go-db: require-env ## Run Go tests including DB-backed routes (needs Postgres)
	@$(MAKE) --no-print-directory db-up migrate
	@$(LOAD_ENV) APERIO_TEST_DATABASE_URL="$$(node $(DEV_CONFIG) go-database-url)" go test -p 1 ./...

.PHONY: test-api
test-api: require-env ## Run the TypeScript/node test suite
	@$(LOAD_ENV) npm run test:api

.PHONY: leak-check
leak-check: ## Scan the tree for committed secrets
	@npm run leak:check

.PHONY: audit
audit: ## Audit production dependencies
	@npm run audit:prod

.PHONY: verify
verify: db-generate typecheck guardrails-migration generate-check lint test-go test-go-db test-api db-validate build-web smoke-workers-go smoke-e2e audit leak-check ## Run the full pre-PR preflight

##@ Build

.PHONY: build
build: build-go build-web ## Build the API binary and the web console

.PHONY: build-go
build-go: ## Build the Go API binary into bin/aperio
	@mkdir -p bin && go build -o bin/aperio ./cmd/aperio
	@printf '$(GREEN)Built bin/aperio$(RESET)\n'

.PHONY: build-web
build-web: ## Production build of the Next.js console
	@npm run build:web

##@ Cleanup

.PHONY: clean
clean: ## Remove build artifacts and local caches
	@rm -rf bin .next apps/web/.next
	@printf 'Removed build artifacts.\n'

.PHONY: nuke
nuke: ## Stop infra, delete its volumes, and clean build artifacts (DESTROYS DATA)
	@$(COMPOSE) down -v --remove-orphans
	@$(MAKE) --no-print-directory clean

.PHONY: require-env
require-env:
	@if [ ! -f $(ENV_FILE) ]; then \
		printf '$(RED)Missing %s.$(RESET) Create it with: $(BOLD)make env$(RESET) (or run make setup)\n' "$(ENV_FILE)" >&2; \
		exit 1; \
	fi
