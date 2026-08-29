#!/bin/bash
# Sinh khoá cho các cơ chế fail-open của Shield: chữ ký rule pack / config
# manifest / plugin (Ed25519, khớp `openssl pkeyutl -verify -rawin` trong
# shield/security/supply_chain.py) và khoá HMAC cho audit ledger.
#
#   ./scripts/generate-signing-keys.sh              # ra /etc/shield (cần sudo)
#   ./scripts/generate-signing-keys.sh /tmp/keys    # ra thư mục khác
#
# Khoá riêng KHÔNG được để lại trên máy chạy agent: sinh xong thì chuyển
# *-private.pem sang máy ký (offline/CI) và xoá khỏi endpoint. Máy chạy agent
# chỉ cần *-public.pem + file .sig.
set -euo pipefail

OUT_DIR="${1:-/etc/shield}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v openssl >/dev/null || { echo "Cần openssl." >&2; exit 1; }
install -d -m 750 "$OUT_DIR"

for name in rule-signing config-signing plugin-signing; do
    if [ -f "$OUT_DIR/$name-private.pem" ]; then
        echo "==> Bỏ qua $name: $OUT_DIR/$name-private.pem đã tồn tại (không ghi đè)"
        continue
    fi
    echo "==> Sinh cặp khoá Ed25519: $name"
    openssl genpkey -algorithm ed25519 -out "$OUT_DIR/$name-private.pem"
    chmod 600 "$OUT_DIR/$name-private.pem"
    openssl pkey -in "$OUT_DIR/$name-private.pem" -pubout -out "$OUT_DIR/$name-public.pem"
    chmod 644 "$OUT_DIR/$name-public.pem"
done

if [ -f "$OUT_DIR/audit-hmac.key" ]; then
    echo "==> Bỏ qua audit HMAC: $OUT_DIR/audit-hmac.key đã tồn tại"
else
    echo "==> Sinh khoá HMAC cho audit ledger"
    openssl rand -hex 32 > "$OUT_DIR/audit-hmac.key"
    chmod 600 "$OUT_DIR/audit-hmac.key"
fi

# Từ 1.1 rule được tách theo lĩnh vực (default/ssh/endpoint/syslog/probe).
# Phải ký TẤT CẢ: agent từ chối khởi động nếu có một pack chưa ký — một pack
# không ký lọt vào là đủ để vô hiệu hoá cả cơ chế ký.
RULE_DIR="$ROOT_DIR/shield/rules"
if [ -d "$RULE_DIR" ]; then
    echo "==> Ký toàn bộ rule pack trong $RULE_DIR"
    for RULE_PACK in "$RULE_DIR"/*.json; do
        [ -f "$RULE_PACK" ] || continue
        openssl pkeyutl -sign -inkey "$OUT_DIR/rule-signing-private.pem" \
            -rawin -in "$RULE_PACK" -out "$RULE_PACK.sig"
        openssl pkeyutl -verify -pubin -inkey "$OUT_DIR/rule-signing-public.pem" \
            -sigfile "$RULE_PACK.sig" -rawin -in "$RULE_PACK" >/dev/null
        echo "    $(basename "$RULE_PACK") -> $(basename "$RULE_PACK").sig"
    done
    echo "    LƯU Ý: sửa bất kỳ rule pack nào cũng phải chạy lại script này,"
    echo "    nếu không agent sẽ từ chối khởi động."
fi

cat <<CONF

==> Khai vào /etc/systemd/system/shield-agent.service rồi
    \`systemctl daemon-reload && systemctl restart shield-agent\`:

Environment=SHIELD_RULE_PUBLIC_KEY=$OUT_DIR/rule-signing-public.pem
Environment=SHIELD_PLUGIN_PUBLIC_KEY=$OUT_DIR/plugin-signing-public.pem
Environment=SHIELD_AUDIT_HMAC_KEY=$(cat "$OUT_DIR/audit-hmac.key")

    Config/update manifest cần thêm chính file manifest + chữ ký của nó:
Environment=SHIELD_CONFIG_MANIFEST=$OUT_DIR/update-manifest.json
Environment=SHIELD_CONFIG_PUBLIC_KEY=$OUT_DIR/config-signing-public.pem
Environment=SHIELD_CONFIG_SIGNATURE=$OUT_DIR/update-manifest.json.sig

    Khoá HMAC ở trên là secret — production nên nạp qua systemd credentials
    (LoadCredential=) thay vì để plaintext trong unit file.
CONF
