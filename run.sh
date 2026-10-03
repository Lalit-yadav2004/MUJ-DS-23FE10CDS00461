#!/usr/bin/env bash
# ==============================================================================
# CodePulse AI - Turnkey Execution Script
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# 1. Check Python
PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    echo "[!] Error: Python 3 is required but was not found."
    exit 1
fi

# 2. Setup Virtual Environment if missing
if [ ! -d ".venv" ]; then
    echo "[*] Initializing virtual environment in .venv..."
    $PYTHON_BIN -m venv .venv
    source .venv/bin/activate
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
else
    source .venv/bin/activate
fi

# 3. Handle Commands
CMD=${1:-"web"}

case "$CMD" in
    web)
        PORT=${2:-8000}
        echo "[*] Launching CodePulse AI Web Dashboard at http://127.0.0.1:$PORT..."
        python main.py web --port "$PORT"
        ;;
    scan)
        TARGET=${2:-"evals/test_corpus/cwe_89_sqli.py"}
        echo "[*] Running CodePulse Multi-Agent Scan on $TARGET..."
        python main.py scan "$TARGET" --mock
        ;;
    bench)
        echo "[*] Executing Automated Benchmark Suite..."
        python main.py bench --mock
        ;;
    test)
        echo "[*] Running Test Suite..."
        pytest
        ;;
    *)
        python main.py "$@"
        ;;
esac
