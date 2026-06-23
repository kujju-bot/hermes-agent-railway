#!/usr/bin/env bash
set -e

# Create 512MB swap as a safety net — if a process briefly spikes past the
# RAM limit it slows down instead of getting OOM-killed.
if [ ! -f /swapfile ]; then
  fallocate -l 512M /swapfile && chmod 600 /swapfile \
    && mkswap /swapfile && swapon /swapfile 2>/dev/null \
    && echo "Swap enabled (512MB)" \
    || echo "Swap setup skipped (not supported)"
fi

AUTO_UPDATE="${AUTO_UPDATE:-true}"

if [ "$AUTO_UPDATE" = "true" ]; then
  echo "Checking for Hermes updates..."
  cd /opt/hermes-agent
  if git pull --recurse-submodules 2>&1 | grep -v 'Already up to date'; then
    echo "Updating dependencies..."
    VIRTUAL_ENV=/opt/hermes-agent/venv uv pip install -e ".[all]" --quiet
    echo "Update complete."
  else
    echo "Already up to date."
  fi
fi

# ---------------------------------------------------------------------------
# Supervised restart loop for a background service.
# Usage:  supervise <label> <command...>
# Restarts the command on crash with exponential backoff (max 30s).
# ---------------------------------------------------------------------------
supervise() {
  local label="$1"; shift
  local delay=1
  while true; do
    echo "[supervisor] Starting $label ..."
    "$@" &
    local pid=$!
    wait "$pid" || true
    echo "[supervisor] $label (pid $pid) exited, restarting in ${delay}s ..."
    sleep "$delay"
    delay=$(( delay * 2 ))
    if [ "$delay" -gt 30 ]; then delay=30; fi
  done
}

if [ "$LITE_MODE" = "true" ]; then
  echo "Starting in LITE_MODE (no web UI)..."

  supervise "hermes-dashboard" hermes dashboard --host 127.0.0.1 --port 9119 --no-open &
  exec python /auth_proxy.py
else
  supervise "hermes-dashboard" hermes dashboard --host 127.0.0.1 --port 9119 --no-open &

  cd /opt/hermes-agent && HERMES_WEBUI_PORT=8787 supervise "hermes-webui" venv/bin/python /opt/hermes-webui/server.py &

  exec python /auth_proxy.py
fi
