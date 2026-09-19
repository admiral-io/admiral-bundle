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

.PHONY: fetch
fetch: ## Fetch master and tags from origin.
	@git fetch --quiet --tags origin master

.PHONY: check-master
check-master: fetch ## Ensure HEAD is master and matches origin/master.
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "Releases are cut from master, not $$(git rev-parse --abbrev-ref HEAD)." >&2; \
		exit 1; \
	fi
	@if [ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/master)" ]; then \
		echo "Local master does not match origin/master. Pull (or push) before tagging." >&2; \
		exit 1; \
	fi

.PHONY: version
version: fetch ## Show the current and next version.
	@echo "Current: $$(./tools/svu.sh current)"
	@echo "Next:    $$(./tools/svu.sh next)"

.PHONY: release
release: check-master ## Tag and push the next version (auto-detected from commits).
	@VERSION=$$(./tools/svu.sh next) && \
	echo "Current version: $$(./tools/svu.sh current)" && \
	echo "Next version:    $$VERSION" && \
	echo "" && \
	read -p "Proceed? [y/N] " confirm && [ "$$confirm" = "y" ] && \
	$(MAKE) --no-print-directory tag VERSION=$$VERSION

.PHONY: release-patch
release-patch: check-master ## Tag and push a patch release.
	@$(MAKE) --no-print-directory tag VERSION=$$(./tools/svu.sh patch)

.PHONY: release-minor
release-minor: check-master ## Tag and push a minor release.
	@$(MAKE) --no-print-directory tag VERSION=$$(./tools/svu.sh minor)

.PHONY: release-major
release-major: check-master ## Tag and push a major release.
	@$(MAKE) --no-print-directory tag VERSION=$$(./tools/svu.sh major)

.PHONY: tag
tag: check-master ## Tag and push an explicit version. Usage: make tag VERSION=v1.2.3
	@if [ -z "$(VERSION)" ]; then \
		echo "VERSION is required. Usage: make tag VERSION=v1.2.3" >&2; \
		exit 1; \
	fi
	@if ! echo "$(VERSION)" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "VERSION must be vX.Y.Z, got $(VERSION)." >&2; \
		exit 1; \
	fi
	@if [ -n "$$(git status --porcelain --untracked-files=no)" ]; then \
		echo "Working tree is dirty. Commit or stash before tagging." >&2; \
		exit 1; \
	fi
	@if git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null; then \
		echo "Tag $(VERSION) already exists." >&2; \
		exit 1; \
	fi
	$(MAKE) --no-print-directory verify
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
