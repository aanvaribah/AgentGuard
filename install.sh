#!/bin/bash
set -euo pipefail

pyname=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        pyname="$candidate"
        break
    fi
done

if [[ -z "$pyname" ]]; then
    echo "No python3 binary found on PATH." >&2
    exit 1
fi

if ! "$pyname" -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    echo "AgentGuard needs Python 3.11 or newer ($pyname is $("$pyname" -V 2>&1))." >&2
    exit 1
fi

if ! command -v ollama >/dev/null 2>&1; then
    echo "Ollama is required but not installed. Install it with Ollama's official installer:" >&2
    echo "  https://ollama.com/download" >&2
    echo "then start it and rerun this script." >&2
    exit 1
fi

"$pyname" -m venv venv
venv/bin/python -m pip install -r requirements.txt

# Pulls the pinned models and checks their digests.
venv/bin/python -m agent_guard.analyst.models

BANNER=$(cat << 'BANNER_END'

    _                    _    ____                     _
   / \   __ _  ___ _ __ | |_ / ___|_   _  __ _ _ __ __| |
  / _ \ / _` |/ _ \ '_ \| __| |  _| | | |/ _` | '__/ _` |
 / ___ \ (_| |  __/ | | | |_| |_| | |_| | (_| | | | (_| |
/_/   \_\__, |\___|_| |_|\__|\____|\__,_|\__,_|_|  \__,_|
        |___/
BANNER_END
)

printf "%s\n\n" "$BANNER"
venv/bin/python main.py -h
printf "\n\033[0;31mRemember to source venv/bin/activate!\n\033[0m"
