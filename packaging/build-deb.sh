#!/bin/bash
# Đóng gói Shield thành 1 file .deb cài được bằng `sudo apt install ./<file>.deb`
# (hoặc `sudo dpkg -i` + `sudo apt --fix-broken install` nếu thiếu dep).
#
# File .deb dùng các Python package do Ubuntu quản lý; postinst chỉ dựng wheel
# của chính Shield bằng `--no-index`, không truy cập PyPI. Các dependency lớn
# như PyQt6/scapy được APT giải quyết trước khi postinst chạy.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT_DIR/packaging"
OUT_DIR="$ROOT_DIR/dist"
STAGE="$(mktemp -d)"
chmod 755 "$STAGE"  # mktemp -d mặc định 0700 — tránh dpkg-deb/lintian phàn nàn quyền thư mục gốc gói
trap 'rm -rf "$STAGE"' EXIT

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT_DIR/pyproject.toml")"
if [ -z "$VERSION" ]; then
    echo "Không đọc được version từ pyproject.toml" >&2
    exit 1
fi
ARCH="$(dpkg --print-architecture)"
PKG_NAME="shield-monitor"
DEB_FILE="$OUT_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "==> Build ${PKG_NAME} ${VERSION} (${ARCH})"

# --- cây file gói ---
install -d "$STAGE/DEBIAN"
install -d "$STAGE/opt/shield"
install -d "$STAGE/lib/systemd/system"
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/share/applications"
install -d "$STAGE/usr/share/icons/hicolor/scalable/apps"
install -d "$STAGE/usr/share/doc/${PKG_NAME}"
install -d "$STAGE/usr/share/shield/audit"
install -d "$STAGE/usr/share/shield/scripts"

# Mã nguồn — loại cache/venv/egg-info, không cần trong .deb.
rsync -a \
    --exclude '__pycache__' --exclude '*.pyc' \
    --exclude '.venv' --exclude '*.egg-info' --exclude '.git' \
    --exclude 'dist' --exclude 'packaging' --exclude 'tests' \
    `# Corpora eval chỉ có test dùng, mà test không nằm trong gói — nên đây là` \
    `# 388 KB fixture không ai đọc trên máy người dùng.` \
    --exclude 'evals' \
    "$ROOT_DIR/shield" "$ROOT_DIR/pyproject.toml" "$ROOT_DIR/README.md" \
    "$ROOT_DIR/docs" \
    "$ROOT_DIR/systemd" "$ROOT_DIR/scripts" \
    "$STAGE/opt/shield/"

# setuptools đọc các đường dẫn trong [tool.setuptools.data-files] khi postinst
# dựng wheel offline. Giữ các nguồn đó trong /opt/shield, kể cả khi cùng file
# đã được .deb cài vào vị trí hệ thống bên dưới.
install -d "$STAGE/opt/shield/packaging"
install -m 644 "$ROOT_DIR/packaging/99-shield.rules" "$STAGE/opt/shield/packaging/99-shield.rules"

# rsync kế thừa quyền từ máy build (umask có thể là 077 trên CI/sandbox) —
# ép về world-readable chuẩn .deb, không thì README/docs/*.md postinst hướng
# dẫn user đọc lại chỉ root mở được (postinst chạy pip install cũng vẫn OK
# vì chạy bằng root, nhưng đọc tài liệu sau khi cài thì user thường cần mở
# được).
find "$STAGE/opt/shield" -type d -exec chmod 755 {} +
find "$STAGE/opt/shield" -type f -exec chmod 644 {} +

install -m 644 "$ROOT_DIR/systemd/shield-agent.service" "$STAGE/lib/systemd/system/shield-agent.service"
install -m 644 "$ROOT_DIR/systemd/shield-privileged.service" "$STAGE/lib/systemd/system/shield-privileged.service"
install -m 644 "$ROOT_DIR/systemd/shield-guardian.service" "$STAGE/lib/systemd/system/shield-guardian.service"
install -m 644 "$ROOT_DIR/systemd/shield-guardian.timer" "$STAGE/lib/systemd/system/shield-guardian.timer"
install -m 644 "$ROOT_DIR/packaging/99-shield.rules" "$STAGE/usr/share/shield/audit/99-shield.rules"
# Liệt kê bằng glob thay vì tên từng file: thêm script mới mà quên sửa dòng
# này thì nó vẫn vào /opt/shield/scripts (copy cả cây) nhưng thiếu ở
# /usr/share/shield/scripts — lệch giữa 2 nơi, khó thấy.
for script in "$ROOT_DIR"/scripts/*.sh; do
    install -m 755 "$script" "$STAGE/usr/share/shield/scripts/$(basename "$script")"
done
install -m 755 "$PKG_DIR/assets/shield-launcher" "$STAGE/usr/bin/shield"
install -m 755 "$PKG_DIR/assets/shield-assess" "$STAGE/usr/bin/shield-assess"
install -m 755 "$PKG_DIR/assets/shield-admin" "$STAGE/usr/bin/shield-admin"
install -m 755 "$PKG_DIR/assets/shield-benchmark" "$STAGE/usr/bin/shield-benchmark"
install -m 755 "$PKG_DIR/assets/shield-guardian" "$STAGE/usr/bin/shield-guardian"
install -m 644 "$PKG_DIR/assets/shield.desktop" "$STAGE/usr/share/applications/shield.desktop"
install -m 644 "$PKG_DIR/assets/shield.svg" "$STAGE/usr/share/icons/hicolor/scalable/apps/shield-monitor.svg"
install -m 644 "$ROOT_DIR/README.md" "$STAGE/usr/share/doc/${PKG_NAME}/README.md"
for doc in "$ROOT_DIR"/docs/*.md; do
    install -m 644 "$doc" "$STAGE/usr/share/doc/${PKG_NAME}/$(basename "$doc")"
done

sed "s/VERSION_PLACEHOLDER/${VERSION}/; s/Architecture: amd64/Architecture: ${ARCH}/" \
    "$PKG_DIR/debian/control" > "$STAGE/DEBIAN/control"
install -m 755 "$PKG_DIR/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 755 "$PKG_DIR/debian/preinst" "$STAGE/DEBIAN/preinst"
install -m 755 "$PKG_DIR/debian/postrm" "$STAGE/DEBIAN/postrm"

# Kích thước cài đặt (Installed-Size, KB) — không bắt buộc nhưng lintian
# sạch hơn nếu có.
SIZE_KB="$(du -sk "$STAGE" --exclude=DEBIAN | cut -f1)"
sed -i "/^Description:/i Installed-Size: ${SIZE_KB}" "$STAGE/DEBIAN/control"

mkdir -p "$OUT_DIR"
fakeroot dpkg-deb --build --root-owner-group "$STAGE" "$DEB_FILE"

echo "==> Xong: $DEB_FILE"
if command -v lintian >/dev/null; then
    echo "==> lintian:"
    lintian "$DEB_FILE" || true
fi
echo
echo "Cài:    sudo apt install ./$(basename "$DEB_FILE")"
echo "Gỡ:     sudo apt remove shield-monitor      (giữ dữ liệu /var/lib/shield)"
echo "Gỡ hết: sudo apt purge shield-monitor"
