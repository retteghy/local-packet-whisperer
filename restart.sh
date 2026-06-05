#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

LOG_FILE="${LPW_LOG:-$HOME/lpw.log}"

# prerequisites
[ -x .venv/bin/streamlit ] || { echo "✗ .venv/bin/streamlit not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }
[ -f bin/lpw_main.py ]     || { echo "✗ bin/lpw_main.py not found"; exit 1; }

# free the port
fuser -k 8501/tcp 2>/dev/null || true
sleep 1

# launch streamlit fully detached: setsid gives it its own session so it
# survives this shell closing; output goes to the log file, not the terminal.
setsid .venv/bin/streamlit run bin/lpw_main.py > "$LOG_FILE" 2>&1 < /dev/null &
PID=$!
disown "$PID" 2>/dev/null || true

# wait up to ~10s for port 8501 to be bound, then return to the prompt
for _ in $(seq 1 20); do
    if ! kill -0 "$PID" 2>/dev/null; then
        echo "✗ Streamlit exited before binding to port 8501. Last log lines:"
        tail -n 15 "$LOG_FILE" 2>/dev/null
        exit 1
    fi
    if ss -tlnp 2>/dev/null | grep -q ":8501"; then
        echo "✓ Streamlit running detached on port 8501 (PID $PID)"
        echo "  logs : $LOG_FILE"
        echo "  stop : fuser -k 8501/tcp"
        exit 0
    fi
    sleep 0.5
done

echo "✗ Streamlit started (PID $PID) but did not bind to port 8501 within 10s. Last log lines:"
tail -n 15 "$LOG_FILE" 2>/dev/null
kill "$PID" 2>/dev/null || true
exit 1
