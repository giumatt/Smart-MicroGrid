#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

cleanup() {
    echo "Cleanup: removing folder in simulation/..."
    find "$SCRIPT_DIR/simulation" -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
    echo "Cleanup completed."
}

trap cleanup SIGINT SIGTERM

"$SCRIPT_DIR/.venv/bin/python" swarm_simulator.py "$@"