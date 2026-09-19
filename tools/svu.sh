#!/usr/bin/env bash
set -euo pipefail

# svu wrapper script
# Ensures consistent semantic versioning behavior across development and CI environments

SVU_VERSION="v3.2.3"

# Check if svu is installed and matches the expected version
NEEDS_INSTALL=false
if ! command -v svu &>/dev/null; then
    NEEDS_INSTALL=true
elif ! svu --version 2>&1 | grep -q "${SVU_VERSION#v}"; then
    echo "svu version mismatch, upgrading to ${SVU_VERSION}..."
    NEEDS_INSTALL=true
fi

if [ "$NEEDS_INSTALL" = true ]; then
    echo "Installing svu ${SVU_VERSION}..."
    go install github.com/caarlos0/svu/v3@${SVU_VERSION}
fi

# Run svu with the provided arguments
exec svu "$@"