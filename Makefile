SHELL := /bin/sh
VERSION ?= 2.0.4
COMMIT  := $(shell git rev-parse --short=12 HEAD 2>/dev/null)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X github.com/alexwoo-awso/apb/internal/version.Version=$(VERSION) \
  -X github.com/alexwoo-awso/apb/internal/version.Commit=$(COMMIT) \
  -X github.com/alexwoo-awso/apb/internal/version.Date=$(DATE)

.PHONY: help build test lint run image up down logs smoke sample worldmap clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

build: ## Build both binaries into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/ ./cmd/...

test: ## Run every test
	go test ./...

lint: ## Vet and check formatting
	go vet ./...
	@out=$$(gofmt -l cmd internal web tools test); \
	 if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

run: ## Run the server locally against ./data over plain HTTP
	APB_DATA_DIR=./data APB_ADDR=:8080 APB_DEV=true APB_LOG_FORMAT=text \
	APB_BASE_URL=http://localhost:8080 go run ./cmd/apbd

image: ## Build the container image
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
	  --build-arg DATE=$(DATE) -t apb:$(VERSION) .

up: ## Start the compose stack
	docker compose up -d --build

down: ## Stop the compose stack
	docker compose down

logs: ## Follow the service log
	docker compose logs -f apb

smoke: ## Walk a running server end to end: APB_SMOKE_URL and APB_SMOKE_CODE
	python3 scripts/smoke.py "$${APB_SMOKE_URL:-http://127.0.0.1:8080}" "$$APB_SMOKE_CODE"

sample: ## Write sample RouterOS bundles to bin/sample for review
	@mkdir -p bin/sample
	APB_RSC_DUMP=$$(pwd)/bin/sample go test ./internal/rsc -run TestDumpBundle
	@ls bin/sample

worldmap: ## Regenerate web/static/world.svg from upstream geometry
	go run ./tools/worldmap -out web/static/world.svg

clean: ## Remove build output
	rm -rf bin
