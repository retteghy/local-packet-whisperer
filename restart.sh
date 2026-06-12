#!/usr/bin/env bash
# Restart LPW. On the deployment host (ihkki) LPW runs as a systemd *system*
# service (lpw.service), so a restart is just a service restart — this no longer
# launches Streamlit by hand. See the unit at /etc/systemd/system/lpw.service.
set -e

SERVICE="${LPW_SERVICE:-lpw}"

# systemctl restart on a system service needs root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi

if ! systemctl list-unit-files "${SERVICE}.service" >/dev/null 2>&1 \
   || ! systemctl cat "${SERVICE}" >/dev/null 2>&1; then
    echo "✗ systemd service '${SERVICE}' not found."
    echo "  This script restarts the lpw systemd service; set LPW_SERVICE if it's named differently."
    exit 1
fi

echo "↻ Restarting ${SERVICE}.service ..."
$SUDO systemctl restart "${SERVICE}"

# wait up to ~10s for port 8501 to be bound again
for _ in $(seq 1 20); do
    if ss -tlnp 2>/dev/null | grep -q ":8501"; then
        PID=$(systemctl show -p MainPID --value "${SERVICE}" 2>/dev/null)
        echo "✓ ${SERVICE}.service running on port 8501 (MainPID ${PID})"
        echo "  status : systemctl status ${SERVICE}"
        echo "  logs   : journalctl -u ${SERVICE} -f"
        exit 0
    fi
    sleep 0.5
done

echo "✗ ${SERVICE}.service restarted but port 8501 is not bound after 10s. Recent logs:"
$SUDO journalctl -u "${SERVICE}" -n 15 --no-pager 2>/dev/null || true
exit 1
