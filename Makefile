.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

.PHONY: test
test: ## Run the tests.
	go test -race ./...

.PHONY: lint
lint: ## Run golangci-lint.
	./tools/golangci-lint.sh run --timeout 2m30s

.PHONY: lint-fix
lint-fix: ## Run golangci-lint with --fix.
	./tools/golangci-lint.sh run --fix

.PHONY: fmt
fmt: ## Format the code.
	gofmt -w .

.PHONY: verify
verify: fmt lint test ## Format, lint and test.
