#!/usr/bin/env bash
# MySSH-MCP uninstaller (run as root).
#   sudo ./uninstall.sh           remove service + binary, keep config, key, logs, backups
#   sudo ./uninstall.sh --purge   also remove config, API key file and file backups
# The audit log (/server_log) is always kept — delete it yourself if you really want to.
set -euo pipefail

PURGE=0
if [ "${1:-}" = "--purge" ]; then
  PURGE=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root:  sudo ./uninstall.sh"
  exit 1
fi

systemctl disable --now myssh-mcp 2>/dev/null || true
rm -f /etc/systemd/system/myssh-mcp.service /etc/logrotate.d/myssh-mcp /usr/local/bin/myssh-mcp
systemctl daemon-reload

if [ "$PURGE" = 1 ]; then
  rm -rf /etc/myssh-mcp /home/MCP_MySSH_APIKey.txt /var/backups/myssh-mcp
  echo "MySSH-MCP removed (config, API key and backups deleted)."
else
  echo "MySSH-MCP service and binary removed."
  echo "Kept: /etc/myssh-mcp, /home/MCP_MySSH_APIKey.txt, /var/backups/myssh-mcp (use --purge to delete)."
fi
echo "Audit log kept in /server_log."
