#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# prerequisites
[ -x .venv/bin/streamlit ] || { echo "✗ .venv/bin/streamlit not found. Run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }
[ -f bin/lpw_main.py ]     || { echo "✗ bin/lpw_main.py not found"; exit 1; }

# free the port
fuser -k 8501/tcp 2>/dev/null || true
sleep 1

# launch streamlit in background so we can verify it actually came up
.venv/bin/streamlit run bin/lpw_main.py &
PID=$!
trap 'kill -INT $PID 2>/dev/null; wait $PID 2>/dev/null; exit' INT TERM

# wait up to ~10s for port 8501 to be bound by our PID
for _ in $(seq 1 20); do
    if ! kill -0 $PID 2>/dev/null; then
        echo "✗ Streamlit exited before binding to port 8501"
        exit 1
    fi
    if ss -tlnp 2>/dev/null | grep -q ":8501"; then
        echo "✓ Streamlit running on port 8501 (PID $PID)"
        wait $PID
        exit $?
    fi
    sleep 0.5
done

echo "✗ Streamlit started (PID $PID) but did not bind to port 8501 within 10s"
kill $PID 2>/dev/null
exit 1
