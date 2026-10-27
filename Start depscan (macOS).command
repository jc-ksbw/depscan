#!/usr/bin/env bash
# Double-click this file to open depscan in your browser.
# macOS may refuse the first time: right-click the file and choose Open,
# then confirm. That only has to be done once.
cd "$(dirname "$0")" || exit 1

if command -v python3 >/dev/null 2>&1; then
    PY=python3
elif command -v python >/dev/null 2>&1; then
    PY=python
else
    echo "Python 3.11 or newer is required but was not found."
    echo "Install it from https://www.python.org/downloads/ and run this again."
    read -r -p "Press Return to close."
    exit 1
fi

"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' || {
    echo "Python 3.11 or newer is required. Found: $("$PY" --version)"
    read -r -p "Press Return to close."
    exit 1
}

echo "Starting depscan. Keep this window open while you use it."
echo "Close this window, or press Control-C, to stop."
echo
"$PY" -m depscan gui
read -r -p "depscan has stopped. Press Return to close."
