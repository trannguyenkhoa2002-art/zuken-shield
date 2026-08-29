#!/usr/bin/env bash
# Read-only health summary. Changes nothing.
set -uo pipefail

echo "=== Services ==="
systemctl is-active shield-agent shield-privileged 2>/dev/null || true
systemctl show shield-agent -p NRestarts -p Result -p MemoryCurrent -p MemoryMax 2>/dev/null || true

echo
echo "=== Watchdog restarts (last 24h) ==="
journalctl -u shield-agent --since "24 hours ago" --no-pager 2>/dev/null \
    | grep -cE "Watchdog timeout|Failed with result" || echo 0

echo
echo "=== Recent maintenance passes ==="
journalctl -u shield-agent --no-pager 2>/dev/null \
    | grep "Database maintenance" | tail -3 || echo "(none logged yet)"

echo
echo "=== Kernel probe coverage ==="
journalctl -u shield-agent --no-pager 2>/dev/null \
    | grep -iE "probe|bpftrace" | tail -5 || echo "(none logged yet)"

echo
echo "=== Database integrity ==="
if [ -r /var/lib/shield/shield.db ]; then
    sqlite3 "file:/var/lib/shield/shield.db?mode=ro" "PRAGMA quick_check(1);" 2>/dev/null \
        || echo "(sqlite3 not installed, or database not readable by this user)"
else
    echo "(database not readable by this user — try with sudo)"
fi

echo
echo "Reminder: no alerts is not the same as nothing happened. Confirm the"
echo "collectors above are reporting before concluding detection is broken."
