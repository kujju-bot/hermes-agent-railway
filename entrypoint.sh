#!/usr/bin/env bash
set -e

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

if [ "$LITE_MODE" = "true" ]; then
  echo "Starting in LITE_MODE (no web UI)..."

  hermes dashboard --host 127.0.0.1 --port 9119 --no-open &
  exec python /auth_proxy.py
else
  hermes dashboard --host 127.0.0.1 --port 9119 --no-open &

  cd /opt/hermes-agent && HERMES_WEBUI_PORT=8787 venv/bin/python /opt/hermes-webui/server.py &

  exec python /auth_proxy.py
fi
