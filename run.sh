#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
pip install -r requirements.txt

WALLETD_PID=""
cleanup() {
  if [ -n "$WALLETD_PID" ]; then
    kill "$WALLETD_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

MODE="${MA_SIGNER_MODE:-SOFTWARE}"
TRANSPORT="${MA_SIGNER_TRANSPORT:-}"

MODE_UP="$(echo "$MODE" | tr '[:lower:]' '[:upper:]')"
TRANSPORT_UP="$(echo "$TRANSPORT" | tr '[:lower:]' '[:upper:]')"

if [ "$MODE_UP" = "FIRMWARE" ]; then
  # Default transport for firmware in v0.6 is SERIAL (PTY), unless user forces SOCKET.
  if [ -z "$TRANSPORT" ]; then
    export MA_SIGNER_TRANSPORT="SERIAL"
    TRANSPORT_UP="SERIAL"
  fi

  if [ "$TRANSPORT_UP" = "SOCKET" ]; then
    echo "[run.sh] Starting walletd TCP on ${MA_WALLETD_HOST:-127.0.0.1}:${MA_WALLETD_PORT:-7788}..."
    export MA_WALLETD_MODE="TCP"
    python -u daemon/walletd.py &
    WALLETD_PID=$!
    sleep 0.2
  else
    # SERIAL (PTY) mode
    mkdir -p runtime
    export MA_WALLETD_MODE="SERIAL"
    export MA_TTY_PATH="${MA_TTY_PATH:-runtime/ttyMA0}"
    export MA_SERIAL_PORT="${MA_SERIAL_PORT:-runtime/ttyMA0}"
    echo "[run.sh] Starting walletd SERIAL (PTY) on ${MA_TTY_PATH}..."
    python -u daemon/walletd.py &
    WALLETD_PID=$!
    # allow daemon to create PTY & symlink
    sleep 0.25
    echo "[run.sh] SERIAL port ready at: ${MA_SERIAL_PORT}"
  fi
fi

python app.py
