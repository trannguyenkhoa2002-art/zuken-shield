#!/bin/bash
# Root-only destructive-isolated integration checks. Nothing runs unless the
# caller explicitly sets SHIELD_RUN_ROOT_TESTS=1.
set -euo pipefail

if [[ "${SHIELD_RUN_ROOT_TESTS:-}" != "1" ]]; then
    echo "Refusing: set SHIELD_RUN_ROOT_TESTS=1 inside a disposable VM." >&2
    exit 2
fi
if [[ "$(id -u)" != "0" ]]; then
    echo "Run as root inside a disposable VM." >&2
    exit 2
fi

ns="shield-test-$$"
cleanup() {
    ip netns delete "$ns" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$ns"
ip -n "$ns" link set lo up

# Exercise only Shield's private nftables table inside the namespace.
ip netns exec "$ns" nft -f - <<'EOF'
table inet shield {
  set blocked_ips { type ipv4_addr; flags timeout; }
  chain input { type filter hook input priority filter; policy accept; ip saddr @blocked_ips drop; }
}
EOF
ip netns exec "$ns" nft add element inet shield blocked_ips '{ 192.0.2.10 timeout 10s }'
ip netns exec "$ns" nft list set inet shield blocked_ips | grep -q '192.0.2.10'
ip netns exec "$ns" nft delete element inet shield blocked_ips '{ 192.0.2.10 }'

echo "PASS: isolated nftables response lifecycle"
