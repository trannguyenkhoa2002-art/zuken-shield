#!/usr/bin/env bash
# Tạo CA riêng cho Shield Probe + chứng chỉ server, rồi phát chứng chỉ cho
# từng probe (KE-HOACH-SHIELD-1.1.md mục A1).
#
# Vì sao CA riêng chứ không dùng Let's Encrypt: probe nói chuyện với Shield
# trong mạng nội bộ, bằng IP hoặc tên máy nội bộ — không có CA công cộng nào
# ký cho những tên đó, và cũng không nên có. CA riêng nghĩa là danh sách máy
# được phép gửi log do BẠN quyết định, không phải do bên thứ ba.
#
#   ./generate-probe-ca.sh init <ip-hoặc-hostname-của-shield>
#   ./generate-probe-ca.sh issue <tên-probe>
set -euo pipefail

CA_DIR="${SHIELD_PROBE_CA_DIR:-/etc/shield/probe-ca}"
DAYS_CA=3650
DAYS_LEAF=825   # trần thực tế của nhiều thư viện TLS

usage() {
    cat <<'EOF'
Cách dùng:
  generate-probe-ca.sh init <shield-host>   Tạo CA + chứng chỉ server
  generate-probe-ca.sh issue <probe-name>   Phát chứng chỉ cho một probe

Biến môi trường:
  SHIELD_PROBE_CA_DIR   Thư mục CA (mặc định /etc/shield/probe-ca)
EOF
}

require_openssl() {
    command -v openssl >/dev/null || { echo "Cần openssl." >&2; exit 1; }
}

cmd_init() {
    local host="$1"
    [ -n "$host" ] || { echo "Thiếu địa chỉ Shield." >&2; exit 1; }
    mkdir -p "$CA_DIR"
    chmod 700 "$CA_DIR"

    if [ -f "$CA_DIR/ca.crt" ]; then
        echo "CA đã tồn tại tại $CA_DIR — không tạo đè." >&2
        echo "Muốn tạo lại thì tự xoá thư mục đó trước (MỌI probe sẽ phải ghi danh lại)." >&2
        exit 1
    fi

    echo "==> Tạo CA nội bộ"
    openssl req -x509 -newkey ed25519 -days "$DAYS_CA" -nodes \
        -keyout "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" \
        -subj "/CN=Zuken Shield Probe CA"

    echo "==> Tạo chứng chỉ server cho $host"
    local san="DNS:$host"
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        san="IP:$host"
    fi
    openssl req -newkey ed25519 -nodes \
        -keyout "$CA_DIR/server.key" -out "$CA_DIR/server.csr" \
        -subj "/CN=$host"
    openssl x509 -req -in "$CA_DIR/server.csr" -days "$DAYS_LEAF" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$CA_DIR/server.crt" \
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$san")
    rm -f "$CA_DIR/server.csr"
    chmod 600 "$CA_DIR"/*.key

    cat <<EOF

==> CA đã sẵn sàng: $CA_DIR

Thêm vào systemd/shield-agent.service (hoặc file override):

  Environment=SHIELD_LOG_INGEST_LISTEN=0.0.0.0:9443
  Environment=SHIELD_LOG_INGEST_CERT=$CA_DIR/server.crt
  Environment=SHIELD_LOG_INGEST_KEY=$CA_DIR/server.key
  Environment=SHIELD_LOG_INGEST_CLIENT_CA=$CA_DIR/ca.crt

Rồi phát chứng chỉ cho từng máy:  $0 issue <tên-probe>
EOF
}

cmd_issue() {
    local name="$1"
    [ -n "$name" ] || { echo "Thiếu tên probe." >&2; exit 1; }
    [ -f "$CA_DIR/ca.crt" ] || { echo "Chưa có CA — chạy '$0 init <host>' trước." >&2; exit 1; }

    local out="$CA_DIR/probes/$name"
    mkdir -p "$out"
    chmod 700 "$out"

    openssl req -newkey ed25519 -nodes \
        -keyout "$out/probe.key" -out "$out/probe.csr" \
        -subj "/CN=shield-probe-$name"
    openssl x509 -req -in "$out/probe.csr" -days "$DAYS_LEAF" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$out/probe.crt" \
        -extfile <(printf "extendedKeyUsage=clientAuth\n")
    rm -f "$out/probe.csr"
    cp "$CA_DIR/ca.crt" "$out/server-ca.crt"
    chmod 600 "$out/probe.key"

    # Fingerprint = SHA256 của DER, đúng cách security/fleet.py tính danh tính.
    local fingerprint
    fingerprint=$(openssl x509 -in "$out/probe.crt" -outform DER | openssl dgst -sha256 -hex | awk '{print $NF}')

    cat <<EOF

==> Chứng chỉ probe "$name" đã tạo: $out
    Fingerprint: $fingerprint

Bước 1 — ghi danh trên máy Shield:
  sudo shield-admin probe enroll --name "$name" --fingerprint $fingerprint

Bước 2 — chép 3 file sang máy cần giám sát:
  scp $out/probe.crt $out/probe.key $out/server-ca.crt <máy-kia>:/etc/shield-probe/

Bước 3 — trên máy đó, tạo /etc/shield-probe/config.json rồi:
  sudo shield-probe test && sudo systemctl enable --now shield-probe

LƯU Ý: probe.key là bí mật. Chép xong thì đừng để bản sao nằm lại nơi khác.
EOF
}

require_openssl
case "${1:-}" in
    init)  shift; cmd_init "${1:-}" ;;
    issue) shift; cmd_issue "${1:-}" ;;
    *)     usage; exit 1 ;;
esac
