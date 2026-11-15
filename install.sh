#!/usr/bin/env bash
# =============================================================================
#  MySSH-MCP installer  —  Ubuntu / Debian VPS  (run as root)
#
#  Builds the Rust binary, installs it to /usr/local/bin/myssh-mcp, generates the
#  API key (/home/MCP_MySSH_APIKey.txt), writes /etc/myssh-mcp/config.toml and
#  enables the systemd service `myssh-mcp` (runs as root, starts on boot) and
#  always adds `ufw allow <port>/tcp` (default port 4040), whether ufw is active
#  or not. Re-running it upgrades in place and keeps the existing API key.
# =============================================================================
set -euo pipefail

PORT=""
BIND=""
PUBLIC_HOST=""
NEW_KEY=0
TMP_SWAP=""

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

  --port N             listen port (default 4040; opened with `ufw allow N/tcp`)
  --bind ADDR          listen address (default 0.0.0.0; use 127.0.0.1 behind a
                       reverse proxy or when you only connect through SSH)
  --public-host HOST   public IP / hostname written into the connection guide
                       (auto-detected when omitted)
  --new-key            generate a new API key (default: keep the existing one)
  -h, --help           show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --port)          PORT="${2:?--port needs a value}"; shift 2 ;;
    --bind)          BIND="${2:?--bind needs a value}"; shift 2 ;;
    --public-host)   PUBLIC_HOST="${2:?--public-host needs a value}"; shift 2 ;;
    --new-key)       NEW_KEY=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo ./install.sh"
  exit 1
fi
if [ "$(uname -s)" != "Linux" ]; then
  echo "MySSH-MCP supports Linux only."
  exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required (systemctl not found)."
  exit 1
fi

if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
fi
case "${ID:-} ${ID_LIKE:-}" in
  *ubuntu*|*debian*) ;;
  *) echo "WARNING: MySSH-MCP is tested on Ubuntu/Debian (detected: ${PRETTY_NAME:-unknown}). Continuing." ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cleanup() {
  if [ -n "$TMP_SWAP" ]; then
    swapoff "$TMP_SWAP" 2>/dev/null || true
    rm -f "$TMP_SWAP"
  fi
}
trap cleanup EXIT

add_tmp_swap() {
  TMP_SWAP=/myssh-mcp-build.swap
  if { fallocate -l 2G "$TMP_SWAP" 2>/dev/null || dd if=/dev/zero of="$TMP_SWAP" bs=1M count=2048 status=none; } \
     && chmod 600 "$TMP_SWAP" && mkswap "$TMP_SWAP" >/dev/null && swapon "$TMP_SWAP"; then
    echo "    temporary 2 GB swap enabled for the build (removed afterwards)"
  else
    rm -f "$TMP_SWAP"
    TMP_SWAP=""
    echo "    could not add temporary swap — continuing anyway"
  fi
}

echo "==> [1/5] Installing build dependencies"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq build-essential pkg-config curl ca-certificates >/dev/null
else
  echo "    apt-get not found — make sure gcc, make, pkg-config and curl are installed."
fi

echo "==> [2/5] Checking the Rust toolchain"
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
  echo "    Rust not found — installing it with rustup (minimal profile)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
cargo --version

echo "==> [3/5] Building MySSH-MCP (release) — a few minutes on a small VPS"
MEM_KB=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
SWAP_KB=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
if [ "${MEM_KB:-0}" -lt 1800000 ] && [ "${SWAP_KB:-0}" -lt 1000000 ]; then
  echo "    low memory detected ($((MEM_KB / 1024)) MiB RAM)"
  add_tmp_swap
fi
cargo build --release

echo "==> [4/5] Installing the binary to /usr/local/bin/myssh-mcp"
install -m 0755 target/release/myssh-mcp /usr/local/bin/myssh-mcp

echo "==> [5/5] Running setup (API key, config, ufw rule, systemd service, log rotation)"
SETUP_ARGS=()
if [ -n "$PORT" ]; then SETUP_ARGS+=(--port "$PORT"); fi
if [ -n "$BIND" ]; then SETUP_ARGS+=(--bind "$BIND"); fi
if [ -n "$PUBLIC_HOST" ]; then SETUP_ARGS+=(--public-host "$PUBLIC_HOST"); fi
if [ "$NEW_KEY" = 1 ]; then SETUP_ARGS+=(--new-key); fi
/usr/local/bin/myssh-mcp setup ${SETUP_ARGS[@]+"${SETUP_ARGS[@]}"}

echo
echo "Done. Server address (IP:port), API key and copy-paste connection instructions:"
echo "    sudo cat /home/MCP_MySSH_APIKey.txt"
echo "Live audit log:"
echo "    sudo tail -f /server_log/claude_log.txt"
