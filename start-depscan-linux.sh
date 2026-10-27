#!/usr/bin/env bash
# Run this to open depscan in your browser:  ./start-depscan-linux.sh
cd "$(dirname "$0")" || exit 1

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3.11 or newer is required but was not found."
    echo "On Debian/Ubuntu:  sudo apt install python3"
    exit 1
fi

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' || {
    echo "Python 3.11 or newer is required. Found: $(python3 --version)"
    exit 1
}

echo "Starting depscan. Press Control-C to stop."
exec python3 -m depscan gui
