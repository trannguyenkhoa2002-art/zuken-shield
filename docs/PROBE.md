# Shield Probe — thu thập log từ các máy khác trong mạng

Shield Probe là một agent nhỏ cài lên **máy khác** trong mạng để máy đó gửi
log về Shield chính. Probe **chỉ đọc**: không chặn IP, không dừng tiến trình,
không cách ly file. Một probe bị chiếm quyền cũng không trở thành công cụ tấn
công ngược vào mạng của bạn.

Probe chỉ phụ thuộc thư viện chuẩn Python — không PySide6, không scapy. Gói cài
đặt nhỏ và không kéo theo giao diện đồ hoạ.

---

## 1. Kiến trúc

```
Máy A (có probe)  ─┐
Máy B (có probe)  ─┼─ mTLS TLS 1.3 ─→  Shield  ─→ detector ─→ alert
Router / camera   ─┘  syslog thô          │
                                          └─→ forensic ledger (chỉ nhận probe)
```

Hai đường vào, **hai mức tin cậy khác nhau**:

| Đường vào | Xác thực | `trust` | Vào ledger? | Trần severity |
|---|---|---|---|---|
| Shield Probe | Certificate mTLS | `authenticated` | Có | `critical` |
| Syslog thô | Không có | `unauthenticated` | **Không** | `warning` |

Syslog không có cơ chế xác thực nào: bất kỳ ai trong mạng cũng gửi được một
gói UDP khai mình là router. Vì vậy log syslog không bao giờ được vào sổ bằng
chứng, không bao giờ tự lên mức `critical`, và không bao giờ được dùng để
huấn luyện baseline hành vi.

---

## 2. Cài đặt

### 2.1. Trên máy chạy Shield — tạo CA một lần

```bash
sudo /usr/share/shield/scripts/generate-probe-ca.sh init 192.168.1.10
```

Thay `192.168.1.10` bằng IP (hoặc hostname) mà các probe sẽ kết nối tới.

Lệnh này in ra 4 dòng `Environment=`. Thêm chúng vào Shield:

```bash
sudo systemctl edit shield-agent
```

```ini
[Service]
Environment=SHIELD_LOG_INGEST_LISTEN=0.0.0.0:9443
Environment=SHIELD_LOG_INGEST_CERT=/etc/shield/probe-ca/server.crt
Environment=SHIELD_LOG_INGEST_KEY=/etc/shield/probe-ca/server.key
Environment=SHIELD_LOG_INGEST_CLIENT_CA=/etc/shield/probe-ca/ca.crt
```

```bash
sudo systemctl restart shield-agent
```

### 2.2. Phát chứng chỉ cho từng máy

```bash
sudo /usr/share/shield/scripts/generate-probe-ca.sh issue may-ban-lam-viec
```

Lệnh in ra một **fingerprint**. Ghi danh nó:

```bash
sudo shield-admin probe-enroll --name may-ban-lam-viec --fingerprint <fingerprint>
```

Kết quả trả về `endpoint_id` — cần cho bước sau.

> Có certificate hợp lệ **chưa đủ** để gửi log. Fingerprint còn phải được ghi
> danh. Bỏ bước này thì probe bị từ chối ngay ở tầng ứng dụng.

### 2.3. Trên máy cần giám sát

```bash
sudo apt install ./shield-probe_1.1.0a1_all.deb
```

Chép 3 file từ máy Shield sang:

```bash
scp /etc/shield/probe-ca/probes/may-ban-lam-viec/probe.crt \
    /etc/shield/probe-ca/probes/may-ban-lam-viec/probe.key \
    /etc/shield/probe-ca/probes/may-ban-lam-viec/server-ca.crt \
    may-ban-lam-viec:/etc/shield-probe/
```

Tạo cấu hình:

```bash
sudo cp /etc/shield-probe/config.example.json /etc/shield-probe/config.json
sudo nano /etc/shield-probe/config.json
```

Sửa `server_host` và `probe_id` (chính là `endpoint_id` ở bước 2.2).

Thử trước khi bật:

```bash
sudo shield-probe test
```

Nếu hiện `OK — kết nối mTLS tới Shield thành công` thì bật:

```bash
sudo systemctl enable --now shield-probe
```

---

## 3. Cấu hình

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `server_host` / `server_port` | — / 9443 | Địa chỉ Shield |
| `probe_id` | — | `endpoint_id` từ `probe-enroll` |
| `spool_max_bytes` | 256 MB | Trần buffer khi mất mạng |
| `rate_per_s` | 200 | Trần dòng/giây probe gửi đi |
| `batch_lines` / `batch_bytes` | 500 / 256 KB | Kích thước mỗi lần gửi |
| `journal_identifiers` | sshd, sudo, su, kernel, systemd-logind, cron | Lọc journald |
| `log_files` | `[]` | File log theo dõi thêm, ví dụ `/var/log/auth.log` |
| `include_audit` | `true` | Đọc thêm Linux Audit qua journald |

### Về `include_audit`

Audit cho tín hiệu tốt hơn journald nhiều: nó thấy `execve` thật với đường dẫn
đầy đủ, thay vì một dòng chữ do chương trình tự viết ra. Nhưng chỉ có nếu máy
đó đã bật `auditd`; không bật thì lượt đọc trả về rỗng và không tốn gì.

Probe **lọc ngay tại nguồn**, chỉ gửi 3 nhóm: `execve`, sự kiện đăng nhập
(`USER_AUTH`/`USER_LOGIN`/`USER_ACCT`), và thay đổi cấu hình (`CONFIG_CHANGE`,
`ANOM_ABEND`, `AVC`). Các bản ghi `PATH`/`CWD`/`PROCTITLE` bị bỏ — một máy bận
sinh hàng nghìn dòng loại đó mỗi giây, gửi hết về chỉ làm nghẹt Shield mà không
thêm thông tin gì.

Audit dùng con trỏ riêng (`audit.cursor`), tách khỏi con trỏ journald. Dùng
chung một con trỏ sẽ khiến hai luồng nuốt mất bản ghi của nhau — và kiểu mất
log đó im lặng tuyệt đối.

### Mất mạng thì sao?

Probe ghi vào spool trên đĩa. Có mạng lại thì gửi bù, theo đúng thứ tự.

Nếu spool đầy, probe bỏ **dòng cũ nhất** và ghi thêm một bản ghi
`probe_spool_overflow` để Shield biết có một khoảng trống trong log. Im lặng
mất log là điều tệ nhất một hệ thống bằng chứng có thể làm — thà biết mình mù
còn hơn tưởng mình thấy hết.

Probe chỉ xoá dòng khỏi spool **sau khi** Shield xác nhận đã nhận. Mạng đứt
giữa chừng thì dòng đó được gửi lại. Thà trùng còn hơn mất.

---

## 4. Syslog từ router, camera, switch

Thiết bị không cài được probe thì đẩy syslog. Đây là đường vào hạng hai.

```bash
sudo systemctl edit shield-agent
```

```ini
[Service]
Environment=SHIELD_SYSLOG_BIND=0.0.0.0
Environment=SHIELD_SYSLOG_PORT=5514
Environment=SHIELD_SYSLOG_ALLOWED_SOURCES=192.168.1.1,192.168.1.20
```

**Allowlist rỗng nghĩa là không nhận gì.** Không có chế độ "nhận tất cả" — đó
là lựa chọn có chủ ý, không phải thiếu sót.

Mặc định probe chỉ nghe `127.0.0.1`; phải sửa `SHIELD_SYSLOG_BIND` mới mở ra
mạng. Nếu quên đặt allowlist trước khi mở, Shield vẫn từ chối mọi thứ.

---

## 5. Theo dõi và khắc phục

```bash
# Trên máy Shield
shield-admin probe-list          # probe nào còn gửi, trễ bao nhiêu
shield-admin probe-revoke <id>   # thu hồi quyền gửi log

# Trên máy có probe
shield-probe status              # còn tồn bao nhiêu dòng chưa gửi
journalctl -u shield-probe -f
```

Trong app: tab **Trung tâm bảo mật** có bảng probe (tên, IP, lần gửi cuối,
độ trễ, số dòng bị bỏ).

| Triệu chứng | Nguyên nhân thường gặp |
|---|---|
| `probe is not enrolled` | Chưa chạy `shield-admin probe-enroll` |
| `certificate verify failed` | `server_ca` sai file, hoặc `server_host` khác CN/SAN trong chứng chỉ |
| `pending_lines` tăng mãi | Shield không nghe cổng 9443, hoặc firewall chặn |
| Probe im lặng, không lỗi | `journal_identifiers` không khớp gì trên máy đó |
| `rate limited` trong probe-list | Máy đó phun log quá `rate_per_s` — tăng trần hoặc lọc bớt |

---

## 6. Gỡ bỏ

```bash
sudo apt remove shield-probe        # giữ lại chứng chỉ trong /etc/shield-probe
sudo apt purge shield-probe         # xoá venv và spool
```

Trên máy Shield, nhớ thu hồi:

```bash
shield-admin probe-revoke <endpoint_id>
```

Thu hồi xoá hẳn fingerprint khỏi danh sách, nên chứng chỉ cũ không còn đường
vào — kể cả khi ai đó vẫn giữ bản sao khoá riêng.
