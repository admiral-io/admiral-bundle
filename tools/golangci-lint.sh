#!/usr/bin/env bash
set -euo pipefail

# golangci-lint wrapper script
# Ensures consistent lint behavior across development and CI environments.
#
# Checks the VERSION, not merely the presence, of the binary. Checking presence
# alone means a different version already on PATH silently wins -- which is how
# CI can fail a lint that passed locally, on a rule the older binary does not
# have. Keep GOLANGCI_LINT_VERSION in lockstep with .github/workflows/lint.yaml.
#
# It also checks the Go release the binary was BUILT with against the local
# toolchain. A golangci-lint built with an older Go panics with "file requires
# newer Go version" when the toolchain moves on, even when its own version is
# right, so that case reinstalls too.

GOLANGCI_LINT_VERSION="v2.12.2"

want="${GOLANGCI_LINT_VERSION#v}"
want_go="$(go env GOVERSION | sed -n 's/^go\([0-9]*\.[0-9]*\).*/\1/p')"
have=""
have_go=""
if command -v golangci-lint &> /dev/null; then
    have="$(golangci-lint --version 2>/dev/null | sed -n 's/.*version \([0-9][^ ]*\).*/\1/p')"
    have_go="$(golangci-lint --version 2>/dev/null | sed -n 's/.*built with go\([0-9]*\.[0-9]*\).*/\1/p')"
fi

if [[ "${have}" != "${want}" || "${have_go}" != "${want_go}" ]]; then
    echo "Installing golangci-lint ${GOLANGCI_LINT_VERSION} with go${want_go} (found: ${have:-none}, built with go${have_go:-?})..." >&2
    GOBIN="$(go env GOPATH)/bin" go install \
        "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}"
    exec "$(go env GOPATH)/bin/golangci-lint" "$@"
fi

golangci-lint "$@"
