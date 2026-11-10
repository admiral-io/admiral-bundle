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

# tag_release tags and pushes the version `svu $(1)` names, after a prompt.
define tag_release
	@VERSION=$$(./tools/svu.sh $(1)) && \
	echo "Current version: $$(./tools/svu.sh current)" && \
	echo "Next version:    $$VERSION" && \
	echo "" && \
	read -p "Proceed? [y/N] " confirm && [ "$$confirm" = "y" ] && \
	git tag -a $$VERSION -m "Release $$VERSION" && \
	git push origin $$VERSION
endef

.PHONY: release-check
release-check: ## Refuse to tag anything but a clean master that matches origin.
	@branch=$$(git rev-parse --abbrev-ref HEAD); \
	if [ "$$branch" != master ]; then echo "error: release from master, not $$branch" >&2; exit 1; fi
	@if [ -n "$$(git status --porcelain --untracked-files=no)" ]; then \
		echo "error: commit or stash your changes first; a tag names the commit, not the tree" >&2; exit 1; fi
	@git fetch --quiet --tags origin master
	@if [ "$$(git rev-parse HEAD)" != "$$(git rev-parse origin/master)" ]; then \
		echo "error: HEAD is not origin/master; pull or push first" >&2; exit 1; fi
	@$(MAKE) --no-print-directory verify

.PHONY: release
release: release-check ## Tag and push the next version (auto-detected from commits).
	$(call tag_release,next)

.PHONY: release-patch
release-patch: release-check ## Tag and push a patch release.
	$(call tag_release,patch)

.PHONY: release-minor
release-minor: release-check ## Tag and push a minor release.
	$(call tag_release,minor)

.PHONY: release-major
release-major: release-check ## Tag and push a major release.
	$(call tag_release,major)

.PHONY: version
version: ## Show current and next version.
	@echo "Current: $$(./tools/svu.sh current)"
	@echo "Next:    $$(./tools/svu.sh next)"
