#!/usr/bin/env bash
# Đóng gói shield-probe — agent nhỏ cài lên MÁY KHÁC trong mạng.
#
# Tách hẳn khỏi gói shield-monitor là điểm mấu chốt: máy chỉ cần gửi log
# không nên phải cài PyQt6 + scapy + reportlab.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT_DIR/packaging"
PKG_NAME="shield-probe"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$PKG_DIR/probe-pyproject.toml" | head -1)"
ARCH="all"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

install -d "$STAGE/DEBIAN" \
           "$STAGE/opt/shield-probe" \
           "$STAGE/usr/bin" \
           "$STAGE/lib/systemd/system" \
           "$STAGE/etc/shield-probe" \
           "$STAGE/usr/share/doc/$PKG_NAME"

# Chỉ package `probe` + pyproject của nó. Không đụng tới `shield`.
cp -r "$ROOT_DIR/probe" "$STAGE/opt/shield-probe/probe"
find "$STAGE/opt/shield-probe" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
install -m 644 "$PKG_DIR/probe-pyproject.toml" "$STAGE/opt/shield-probe/pyproject.toml"

install -m 755 "$PKG_DIR/assets/shield-probe" "$STAGE/usr/bin/shield-probe"
install -m 644 "$ROOT_DIR/systemd/shield-probe.service" "$STAGE/lib/systemd/system/shield-probe.service"
install -m 644 "$PKG_DIR/probe-config.example.json" "$STAGE/etc/shield-probe/config.example.json"
install -m 644 "$ROOT_DIR/docs/PROBE.md" "$STAGE/usr/share/doc/$PKG_NAME/README.md"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Depends: python3 (>= 3.10), python3-venv, systemd
Recommends: openssl
Maintainer: Zuken <shield@localhost>
Description: Shield Probe — read-only log forwarder
 Đọc journald và file log của máy này rồi gửi về Shield chính qua mTLS.
 Chỉ đọc: không nftables, không kill process, không quarantine.
 Không phụ thuộc PyQt6/scapy — cài được lên máy chỉ cần gửi log.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e
VENV=/opt/shield-probe/.venv
python3 -m venv --clear "$VENV"
"$VENV/bin/pip" install --no-index --no-deps --no-build-isolation /opt/shield-probe --quiet

install -d -m 700 /etc/shield-probe /var/lib/shield-probe

if [ ! -f /etc/shield-probe/config.json ]; then
    cat <<'MSG'

==> shield-probe đã cài, nhưng CHƯA cấu hình.

    Trên máy chạy Shield:
      sudo /usr/share/shield/scripts/generate-probe-ca.sh issue <tên-máy-này>
      sudo shield-admin probe-enroll --name <tên-máy-này> --fingerprint <fp>

    Trên máy này:
      1. Chép probe.crt, probe.key, server-ca.crt vào /etc/shield-probe/
      2. cp /etc/shield-probe/config.example.json /etc/shield-probe/config.json
      3. Sửa server_host và probe_id trong config.json
      4. sudo shield-probe test
      5. sudo systemctl enable --now shield-probe

MSG
else
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
        systemctl daemon-reload
        systemctl restart shield-probe.service || true
    fi
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/bash
set -e
case "$1" in
    remove|purge)
        if command -v systemctl >/dev/null; then
            systemctl disable --now shield-probe.service 2>/dev/null || true
            systemctl daemon-reload || true
        fi
        ;;
esac
if [ "$1" = "purge" ]; then
    rm -rf /opt/shield-probe/.venv /var/lib/shield-probe
    echo "Giữ lại /etc/shield-probe (chứa chứng chỉ) — tự xoá nếu muốn."
fi
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postrm"

install -d "$ROOT_DIR/dist"
OUTPUT="$ROOT_DIR/dist/${PKG_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT" >/dev/null
echo "==> $OUTPUT"
