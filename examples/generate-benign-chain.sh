#!/usr/bin/env bash
# Generate the exec -> file write -> outbound connection pattern, benignly.
#
# Only run this on a machine you own. It writes three small files under
# /dev/shm and optionally makes ONE outbound TCP connection to a host and port
# you supply. It installs nothing and changes no system configuration.
set -euo pipefail

TARGET_HOST="${1:-}"
TARGET_PORT="${2:-}"
WORKDIR="/dev/shm"
PREFIX="shield-lab-artifact"

cleanup() { rm -f "${WORKDIR}/${PREFIX}"-*.txt; }
trap cleanup EXIT

echo "==> Writing three files under ${WORKDIR}"
for i in 1 2 3; do
    printf 'shield lab artifact %s, created %s\n' "$i" "$(date -Is)" \
        > "${WORKDIR}/${PREFIX}-${i}.txt"
    sleep 0.2
done

if [ -n "$TARGET_HOST" ] && [ -n "$TARGET_PORT" ]; then
    echo "==> One outbound connection to ${TARGET_HOST}:${TARGET_PORT}"
    echo "    (only do this to a host you own)"
    curl -s --max-time 3 "http://${TARGET_HOST}:${TARGET_PORT}/" >/dev/null || true
else
    echo "==> No target given; skipping the connection step."
    echo "    Usage: $0 <host-you-own> <port>"
fi

echo
echo "==> Done. In Shield, expect within a minute or so:"
echo "    - process_exec, file_write x3, and socket_connect (if a target was given)"
echo "    - alert BEHAVIOR_EXEC_WRITE_CONNECT (needs bpftrace for full visibility)"
echo "    - scenario SUSPICIOUS_EXECUTION_CHAIN on the incident report"
echo
echo "    The family is MALWARE_EXECUTION: that names the pattern class, not a"
echo "    verdict. The report's epistemic state is where certainty is stated."
