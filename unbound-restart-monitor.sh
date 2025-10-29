#!/bin/bash
# Monitoramento de reinício do Unbound
# Salva data/hora de cada restart em /var/log/unbound-restarts.log
LOG_FILE="/var/log/unbound-restarts.log"
systemctl status unbound | grep 'Active:' | grep -q running || exit 0
LAST_START=$(journalctl -u unbound | grep 'Started unbound.service' | tail -1 | awk '{print $1, $2, $3, $4, $5}')
if [ -n "$LAST_START" ]; then
    echo "[RESTART] $LAST_START" >> "$LOG_FILE"
fi