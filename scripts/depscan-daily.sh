#!/usr/bin/env bash
# Daily depscan run. Point cron, systemd or launchd at this file.
#
#   ./depscan-daily.sh /path/to/your/projects [/path/to/reports]
#
# Exits 0 when nothing at or above the configured severity was found, and 1
# when something was. cron mails you the output of a job that exits non-zero,
# so that alone is a working notification channel.

set -euo pipefail

ROOT="${1:-$HOME/projects}"
OUT="${2:-$HOME/depscan-reports}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${DEPSCAN_PYTHON:-python3}"

mkdir -p "$OUT"
cd "$HERE"

# `|| status=$?` is required: under `set -e` a non-zero exit would otherwise
# abort the script before the status could be inspected, and findings are
# reported precisely by a non-zero exit.
status=0
"$PYTHON" -m depscan scan \
    --root "$ROOT" \
    --out-dir "$OUT" \
    --fail-on high \
    --no-color \
    --quiet || status=$?

if [ "$status" -ne 0 ]; then
    echo
    echo "Full report: $OUT/scan-latest.md"
    echo "Open in a browser: $OUT/scan-latest.html"
fi
exit "$status"
