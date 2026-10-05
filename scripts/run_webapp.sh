#!/usr/bin/env bash
# Launch the ThreatInt web dashboard.
#
# Usage: scripts/run_webapp.sh [PORT] [--live]
#   PORT    port to bind (default 12000)
#   --live  hit real feeds instead of the offline fixtures
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${1:-12000}"
shift || true

exec .venv/bin/python -m threatint.webapp.app \
    --host 0.0.0.0 \
    --port "$PORT" \
    "$@"
