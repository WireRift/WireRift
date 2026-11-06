#!/bin/bash
# test-coverage.sh — Runs tests with coverage and enforces minimum threshold

set -euo pipefail

MIN_COVERAGE=${MIN_COVERAGE:-90}

echo "Running tests with coverage..."
PACKAGES=(./cmd/... ./internal/...)
go test -coverprofile=coverage.out -covermode=atomic -timeout 120s "${PACKAGES[@]}"

COVERAGE=$(go tool cover -func=coverage.out | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
echo "Total coverage: ${COVERAGE}%"

if awk -v coverage="$COVERAGE" -v minimum="$MIN_COVERAGE" 'BEGIN { exit !(coverage < minimum) }'; then
    echo "ERROR: Coverage ${COVERAGE}% is below minimum ${MIN_COVERAGE}%"
    exit 1
fi

echo "OK: Coverage ${COVERAGE}% meets minimum ${MIN_COVERAGE}%"
exit 0
