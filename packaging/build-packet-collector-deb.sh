#!/usr/bin/env bash
# Đóng gói helper bắt gói — TÁCH RIÊNG khỏi shield-monitor.
#
# Lý do tách nằm ở giấy phép: helper dùng scapy (GPL-2.0), lõi Shield nhắm
# Apache-2.0. Hai gói riêng, hai tiến trình riêng, hai file phụ thuộc riêng.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
PKG_NAME="shield-packet-collector"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT_DIR/packaging/packet-collector/pyproject.toml")"
ARCH="all"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> Build ${PKG_NAME} ${VERSION}"
install -d "$STAGE/DEBIAN" "$STAGE/opt/${PKG_NAME}" "$STAGE/lib/systemd/system"
install -d "$STAGE/usr/share/doc/${PKG_NAME}"

rsync -a --exclude '__pycache__' --exclude '*.pyc' \
    "$ROOT_DIR/packet_helper" "$STAGE/opt/${PKG_NAME}/"
install -m 644 "$ROOT_DIR/packaging/packet-collector/pyproject.toml" \
    "$STAGE/opt/${PKG_NAME}/pyproject.toml"
install -m 644 "$ROOT_DIR/systemd/shield-packet-collector.service" \
    "$STAGE/lib/systemd/system/shield-packet-collector.service"

# Ghi chú giấy phép đi CÙNG gói, không nằm rải rác ở kho nguồn.
cat > "$STAGE/usr/share/doc/${PKG_NAME}/README" <<'DOC'
Shield packet collector — optional component.

This package depends on scapy, which is distributed under the GPL-2.0. The
Zuken Shield core is a separate package targeting the Apache-2.0 licence and
does not import scapy. The two run as distinct programs in distinct processes,
exchanging structured observations over a local Unix socket.

That separation is architectural. It makes the licence boundary explicit and
testable; it is not a legal conclusion, and none is offered here.

Shield works without this package, with reduced network visibility.
DOC

sed "s/VERSION_PLACEHOLDER/${VERSION}/" "$ROOT_DIR/packaging/packet-collector/control" \
    > "$STAGE/DEBIAN/control"

cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
VENV=/opt/shield-packet-collector/.venv
python3 -m venv --system-site-packages --clear "$VENV"
"$VENV/bin/pip" install --no-index --no-deps --no-build-isolation \
    /opt/shield-packet-collector >/dev/null
systemctl daemon-reload || true
echo "==> shield-packet-collector đã cài."
echo "    Bật:  sudo systemctl enable --now shield-packet-collector"
echo "    Đây là thành phần TUỲ CHỌN; Shield chạy được khi không có nó."
POST
chmod 755 "$STAGE/DEBIAN/postinst"

find "$STAGE" -type d -exec chmod 755 {} +
find "$STAGE/opt" -type f -exec chmod 644 {} +
chmod 755 "$STAGE/DEBIAN/postinst"

install -d "$OUT_DIR"
dpkg-deb --build --root-owner-group "$STAGE" \
    "$OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
echo "==> Xong: $OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
