.PHONY: help build run test vet tidy infra-up infra-down clean

ACTIVE_ENV ?= dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Build the server binary
	go build -o bin/auth-server ./cmd

run: ## Run the server (ACTIVE_ENV defaults to dev)
	ACTIVE_ENV=$(ACTIVE_ENV) go run ./cmd

test: ## Run all tests
	go test ./...

vet: ## Run go vet
	go vet ./...

tidy: ## Tidy modules
	go mod tidy

infra-up: ## Start local Postgres + Redis
	docker compose up -d

infra-down: ## Stop local infrastructure
	docker compose down

clean: ## Remove build artifacts
	rm -rf bin
