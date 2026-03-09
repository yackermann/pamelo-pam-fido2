#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <oem-folder> [--skip-build]" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OEM_FOLDER="$1"
shift || true

cd "${REPO_ROOT}"

if [[ ! -d "${OEM_FOLDER}" ]]; then
  echo "OEM folder not found: ${OEM_FOLDER}" >&2
  exit 1
fi

GOCACHE="${GOCACHE:-${REPO_ROOT}/.cache/go-build}" \
  go run ./cmd/dpkgmake -oem-folder "${OEM_FOLDER}" "$@"
