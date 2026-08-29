# Zuken Shield — Hướng dẫn sử dụng và vận hành

**Created by Zuken** · Phiên bản `3.0.0a2` · [English version](USER_GUIDE.md)

Đây là tài liệu đầy đủ: Shield làm gì, cài và chạy ra sao, xử lý một cảnh báo thế
nào, vận hành production ra sao, và kiểm thử gì trước khi phát hành. Nếu chỉ muốn
chạy được ngay, nhảy tới [§3 Cài đặt](#3-cài-đặt).

---

## 1. Shield dùng để làm gì

Shield bảo vệ một máy Linux và mạng nội bộ quanh nó. Nó thu thập tín hiệu từ máy,
từ LAN và từ log hệ thống; phát hiện hành vi đáng chú ý; lưu bằng chứng ngay trên
máy; rồi hỗ trợ điều tra, báo cáo và phản ứng có kiểm soát.

Nó phát hiện và giám sát:

- thiết bị lạ trong LAN, MAC gateway đổi, xung đột ARP/NDP, DHCP giả, quét cổng;
- đăng nhập SSH thất bại, `sudo` thất bại, USB mới cắm, card mạng ở chế độ promiscuous;
- tiến trình, dịch vụ systemd, cổng đang lắng nghe, thay đổi file quan trọng;
- DNS resolver, mục trong `/etc/hosts`, cổng mở và banner dịch vụ.

Và nó hỗ trợ phần việc **sau khi** phát hiện: gom cảnh báo thành incident, chấm
điểm rủi ro tất định, ánh xạ MITRE ATT&CK, hồ sơ điều tra (case), báo cáo TXT/PDF,
tóm tắt offline, và các hành động phản ứng (chặn IP/MAC, dừng tiến trình, cách ly
file) — đều có kiểm tra đầu vào và đường hoàn tác.

**Shield không phải** là antivirus đầy đủ, không phải SIEM/EDR doanh nghiệp, cũng
không phải công cụ quét lỗ hổng. Điểm rủi ro dùng để **ưu tiên việc cần xem
trước**. Nó không chứng minh máy an toàn, cũng không chứng minh máy đã bị xâm nhập.

**Chỉ quét hệ thống và mạng bạn sở hữu hoặc được cấp phép kiểm thử.**

---

## 2. Kiến trúc và quyền

| Thành phần | Chạy bằng | Nhiệm vụ |
|---|---|---|
| `shield-agent` | root | Thu thập, phát hiện, chấm điểm, policy, lưu trữ, IPC server |
| `shield-privileged` | root | Bề mặt RPC tối thiểu cho firewall và dừng tiến trình |
| `shield` (UI) | user thường | Giao diện PySide6, nói chuyện qua Unix socket cục bộ |

Agent cần root để bắt gói tin, đọc một số log và thực thi phản ứng hệ thống.
**Không chạy UI bằng `sudo`.** Lúc cài, user desktop được thêm vào group `shield`
để truy cập được `/run/shield/shield.sock`.

Pipeline tách bạch: mô tả sự thật → phán đoán → hành động.

```text
collector ──> Event ──> detector ──> Alert ──> scorer ──> policy ──> store / IPC
                                                            │
                                                    response adapter
```

Collector chỉ mô tả sự thật, không phân loại. Detector sinh alert kèm bằng chứng
và playbook. Scorer chấm 0–100 kèm độ tin cậy. PolicyEngine là **nơi duy nhất** có
thể quyết định phản ứng tự động, và mặc định `audit_only=True` — mọi kết quả đều
chỉ là `alert`, kể cả khi điểm 100. Mọi quyết định được ghi vào `audit_log`.

Muốn có ngăn chặn tự động phải đủ **cả ba**: quản trị viên tắt audit-only, điểm
đạt ngưỡng cấu hình, và đúng rule đó nằm trong allowlist.

---

## 3. Cài đặt

### Cài gói có sẵn

```bash
cd ~/Desktop/"zuken shield"
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
```

APT có thể cần Internet để lấy dependency hệ thống còn thiếu. Riêng mã Python của
Shield được cài offline vào `/opt/shield/.venv`, không đụng PyPI.

### Tự build gói

```bash
./packaging/build-deb.sh
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
```

Build lại mà không đổi version thì phải thêm `--reinstall`:

```bash
sudo apt install --reinstall ./dist/shield-monitor_3.0.0a2_amd64.deb
```

### Kiểm tra sau khi cài

```bash
dpkg-query -W -f='${Status} ${Version}\n' shield-monitor
systemctl status shield-agent shield-privileged --no-pager
journalctl -u shield-agent -n 50 --no-pager
```

Kết quả đúng là `install ok installed 3.0.0a2`, cả 2 service `active`, và log
khởi động liệt kê collector, đường dẫn DB và socket IPC. Bản thân trình cài cũng
tự chạy health check và thoát với mã lỗi kèm log nếu service không lên.

---

## 4. Lần chạy đầu

Mở **Shield** trong menu ứng dụng, hoặc chạy `shield`.

Nếu service đang dừng, launcher sẽ bật hộp thoại xác thực của desktop để khởi động
chúng. Nó cũng có thể chạy UI với group `shield` vừa được cấp, nhưng **đăng xuất
rồi đăng nhập lại** vẫn là cách chắc chắn nhất để phiên nhận group mới.

Trình tự nên làm:

1. Xác nhận header hiển thị **Agent online**.
2. **Management → Settings**: chọn ngôn ngữ và giao diện.
3. Chỉ chấp nhận baseline gateway khi đang ở mạng tin cậy, và sau khi bạn nhận ra
   đúng IP/MAC của router nhà mình.
4. **Monitoring → Devices**: quét nhanh, chỉ đánh dấu tin cậy những thiết bị bạn
   nhận ra.
5. Làm việc chính ở **Operations → Overview / Incidents**.

---

## 4b. Công tắc tắt / tạm dừng giám sát

Trên thanh tiêu đề, cạnh chỉ báo kết nối, luôn có một cụm điều khiển:

```
[● Đang giám sát]   [Tạm dừng ▾]   [Tắt Shield]
```

Không cần chạy `systemctl` nữa.

### Khi nào dùng

Shield chạy `arp-scan` mỗi 60 giây và `nmap -sn` mỗi 15 phút. Ở mạng nhà thì
vô hại. Ở **mạng trường học, cơ quan, khách sạn hay quán cà phê**, hệ thống
NAC/IDS của họ đánh dấu đó là quét mạng trái phép — và điều đó có thể vi phạm
quy định sử dụng mạng.

Trước khi nối vào một mạng như vậy, bấm **Tạm dừng → Chỉ dừng quét chủ động**.

### Ba mức

| Mức | Dừng cái gì | Còn lại gì |
|---|---|---|
| **Chỉ dừng quét chủ động** | arp-scan, nmap, self-audit, poll router, né tránh | Vẫn phát hiện được tấn công qua sniff và log máy |
| **Dừng toàn bộ giám sát** | thêm cả sniff, ghi lưu lượng, tarpit, nhận log | Không còn gì |
| **Tắt Shield** | agent thoát hẳn | Không tự chạy lại cho tới khi bạn bật |

Khuyến nghị dùng mức đầu tiên. Nó cắt đúng phần gây rắc rối mà vẫn giữ khả
năng phát hiện — dừng cả phần thụ động là tự làm mình mù.

### Thời hạn

Chọn 15 phút / 1 giờ / 8 giờ / đến khi tự bật lại. Bản có thời hạn **tự bật
lại** — để bạn không tắt lúc vào trường rồi quên, và máy ở nhà cũng không
được bảo vệ.

Mọi lần tạm dừng và tắt đều ghi vào audit log. Đây là điều kiện để Guardian
phân biệt "người dùng chủ động tắt" với "kẻ tấn công vừa giết Shield".

## 5. Bản đồ giao diện

| Khu vực | Trang | Mục đích |
|---|---|---|
| **Operations** | Overview | Tình trạng chung, số thiết bị/cảnh báo, các chặn đang hiệu lực |
| | Incidents | Các phát hiện liên quan gom theo đối tượng trong 24 giờ |
| | Alerts | Bằng chứng, playbook và phản ứng cho từng cảnh báo |
| **Monitoring** | Devices | Dò LAN, trạng thái tin cậy, theo dõi, lối tắt tự kiểm tra |
| | Traffic | Lưu lượng theo thiết bị, giao thức, backend router |
| | System Log | Sự kiện hệ thống đã lọc |
| | DNS Control | Resolver, baseline, `/etc/hosts`, kiểm tra chiếm quyền DNS |
| | WiFi Passwords | Mật khẩu NetworkManager đã lưu sẵn trên chính máy này |
| **Investigation** | Security Center | Sức khoẻ collector, MITRE, timeline, case, baseline, suppression, fleet |
| | Response | Hàng đợi phản ứng: Shield định làm gì, đã làm gì, đã gỡ gì |
| | Assessment | Kiểm thử pipeline phát hiện bằng sự kiện mô phỏng an toàn |
| | Self-Audit | `nmap -sV`, phân loại cổng, so sánh snapshot |
| | Reports | Tổng hợp theo kỳ, xuất TXT/PDF |
| **Management** | Settings | Ngôn ngữ, giao diện, lịch quét, dải được cấp phép, chặn, né tránh, tarpit, xuất log |
| | Help | Hướng dẫn ngắn ngay trong ứng dụng |

Xám là thông tin, vàng cần xem lại, đỏ cần điều tra ngay. **Severity và risk là hai
thứ khác nhau**: severity là phân loại của rule, còn risk kết hợp nó với bằng chứng
thực tế thu được.

---

## 6. Quy trình xử lý một cảnh báo

1. Mở **Incidents**, tìm đối tượng có nhiều tín hiệu liên quan cùng lúc.
2. Mở **Alerts**: đọc rule, thời điểm, đối tượng, điểm rủi ro và bằng chứng.
3. **Nghĩ tới nguyên nhân hợp lệ trước** — đổi Wi-Fi, cài phần mềm, cắm USB, bật
   VPN hay Docker đều sinh tín hiệu.
4. Chỉ chạy playbook sau khi đã xác minh đúng IP, MAC, PID hoặc file.
5. Với phản ứng trên máy, đọc kỹ preview rồi mới xác nhận.
6. Tạo case trong **Security Center**, ghi chú, chuyển trạng thái `open` →
   `investigating` → `resolved` hoặc `false_positive`.
7. Với false positive lặp lại, thêm suppression có thời hạn kèm lý do.

Vài ranh giới an toàn nên biết:

- Chặn firewall tự hết hạn sau 24 giờ.
- Dừng tiến trình kiểm tra **cả PID lẫn start ticks**, nên không bắn nhầm PID đã
  được cấp lại cho tiến trình khác.
- Cách ly file verify SHA-256, chạy được qua nhiều filesystem, tạo rollback ID, và
  từ chối ghi đè nếu vị trí cũ đã có file mới.
- Phản ứng đi theo preview → xác nhận → token dùng một lần, gắn với đúng client đã
  yêu cầu.

---

## 7. Thiết bị, quét mạng và Self-Audit

**Quét nhanh** dùng `arp-scan`, hợp cho kiểm tra thường xuyên. **Quét sâu** dùng
`nmap -sn`: đầy đủ hơn nhưng mất vài phút.

Mỗi thiết bị quan sát được có một định danh nội bộ `DEVICE-…` — IP **không** được
coi là danh tính vì DHCP đổi liên tục. Trang Devices hiển thị loại thiết bị dự
đoán, độ tin cậy, rủi ro, IP/MAC hiện tại, lịch sử quan sát và mục **vì sao Shield
nghĩ vậy**. Khi tín hiệu chưa đủ, Shield giữ nguyên **Unknown** thay vì đoán bừa.

Bạn có thể đổi tên thiết bị, thêm nhãn chủ sở hữu, vị trí, mục đích và mức quan
trọng. Shield không suy luận danh tính con người. Nhiều MAC chỉ được gộp khi bạn
xác nhận, và **Split MAC** gỡ liên kết sai.

**Dải được cấp phép**: trong Settings, thêm CIDR kèm lý do/căn cứ cấp phép. Shield
chỉ quét dải đã lưu, giới hạn kích thước dải, và kiểm tra lại mục tiêu một lần nữa
bên trong agent trước khi quét.

**Self-Audit** chạy `nmap -sV` để lấy banner dịch vụ. Nó không khai thác, không dò
mật khẩu. Kết quả chia Nguy hiểm/Cần xem/Bình thường. Danh sách CVE chỉ là gợi ý
offline nhỏ, **không** phải quét lỗ hổng theo phiên bản. Mỗi lần quét thành công
thành một snapshot, để lần sau báo được cổng nào vừa mở thêm hoặc vừa đóng.

---

## 8. DNS, lưu lượng và Wi-Fi

**DNS Control** đọc resolver thật qua `resolvectl` (dự phòng `/etc/resolv.conf`),
theo dõi lưu lượng UDP/53 tới resolver lạ, và liệt kê mục đáng chú ý trong
`/etc/hosts`. Sau khi đổi mạng hợp lệ, hãy xem lại và cập nhật baseline. Bài kiểm
tra chiếm quyền DNS cần `dig` (`sudo apt install dnsutils`). DoT/DoH không được
giải mã, và việc các resolver công cộng trả lời khác nhau thường chỉ là CDN, tự nó
không chứng minh có tấn công.

**Traffic**: chọn **Watch** để đếm lưu lượng của một thiết bị; cài `tshark` thì có
thêm phân loại giao thức (`sudo apt install tshark`). Một máy trong mạng switch
không thể thấy hết lưu lượng của máy khác — muốn số liệu toàn mạng thì cấu hình
backend SSH tới router hoặc script tuỳ chỉnh in ra JSON dạng:

```json
[{"ip":"192.168.1.23","mac":"aa:bb:cc:dd:ee:ff","rx_bytes":10485760,"tx_bytes":2097152}]
```

**WiFi Passwords** chỉ đọc lại các mạng NetworkManager **đã lưu sẵn trên máy này**.
Mật khẩu luôn bị che tới khi bạn chủ động hiện, và kết quả chỉ gửi cho đúng client
UI đã yêu cầu. Shield không bắt handshake, không dò mật khẩu mạng khác.

---

## 9. Security Center và Assessment

Trong **Security Center**: xem Collector Health trước khi tin vào tính đầy đủ của
dữ liệu; tìm kiếm theo PID, hash, IP, user, hostname hay đường dẫn để dựng timeline
và đồ thị tiến trình; hiểu độ phủ MITRE là *kỹ thuật đã quan sát được*, không phải
phần trăm an toàn; quản lý case, baseline hành vi, suppression và fleet; và luôn
phân biệt dữ liệu **Observed** với dữ liệu **Synthetic** của Assessment.

Kernel telemetry báo rõ backend đang dùng là eBPF, auditd hay procfs. Khi có BTF và
`bpftrace`, agent chạy một chương trình trace exec **cố định** — không có đoạn probe
nào đến từ IPC hay cấu hình. Thiếu eBPF thì hiển thị ra, không giấu.

Baseline bất thường cục bộ học hành vi tiến trình, listener, dịch vụ và DNS trong
một khoảng thời gian giới hạn, sau đó đề xuất phát hiện có giải thích cho hành vi
mới. Sự kiện mô phỏng không bao giờ được dùng để huấn luyện. Reset phải chủ động,
có xác nhận và được ghi lại. Không có gì được tải lên đâu cả.

**Assessment** phát sự kiện mô phỏng trong bộ nhớ để kiểm chứng chuỗi
Sự kiện → Phát hiện → Rủi ro → Bằng chứng. Nó không khai thác, không chặn, không
sửa hệ thống. Chạy không cần giao diện:

```bash
shield-assess run --output ./shield-assessment-output
```

Kết quả gồm `assessment.json`, `junit.xml`, `results.sarif`, `coverage.json` và
`evidence.zip`. Thêm `--hmac-key-file` cho `run` và `verify` để có bằng chứng được
xác thực. Profile tự viết phải khai `schema_version: 1` và
`authorized_local_only: true`; sự kiện bị giới hạn theo allowlist và mỗi bài test
có watchdog tối đa 60 giây.

Bộ này chứng minh **pipeline đấu nối đúng**. Nó **không** chứng minh collector
kernel/audit/mạng quan sát được hoạt động thật — phần đó cần các gate VM ở §13.

---

## 10. Báo cáo, dữ liệu và sao lưu

**Reports** tổng hợp theo hôm nay, 7 ngày hoặc 30 ngày. TXT hợp để xem nhanh hoặc
đưa vào script; PDF hợp để lưu hồ sơ, có tóm tắt, timeline và bằng chứng.
**Phân tích cục bộ** chạy offline, không gửi log ra Internet, và không có quyền
phản ứng.

| Dữ liệu | Đường dẫn |
|---|---|
| Database | `/var/lib/shield/shield.db` |
| Bản sao lưu | `/var/lib/shield/backups/` |
| PCAP | `/var/lib/shield/pcaps/` |
| Snapshot | `/var/lib/shield/snapshots/` |
| File cách ly | `/var/lib/shield/quarantine/` |
| Mã đã cài | `/opt/shield/` |
| Log dịch vụ | systemd journal |

**Management → Settings → Sao lưu và phục hồi** bật/tắt sao lưu tự động hằng ngày
(mặc định bật); **Backup ngay** tạo bản sao nhất quán tức thì. Riêng bản sao lưu
trước mỗi lần nâng cấp gói **luôn** được tạo bất kể công tắc trên — đó là ranh giới
an toàn, không phải tuỳ chọn.

**Lưu giữ dữ liệu**: bảo trì chạy mỗi 6 giờ. Sự kiện thô quá 30 ngày, cảnh báo quá
365 ngày và cache threat intel hết hạn sẽ bị xoá. Sổ forensic **không bao giờ** bị
tự động cắt — hãy lưu trữ và checkpoint theo chính sách của bạn trước khi xoá tay.

Sổ forensic có hash-chain. Nó chỉ chống được việc tính lại toàn chuỗi khi bạn cấu
hình khoá HMAC riêng. Bằng chứng nằm trên chính máy đó **không** bất biến trước kẻ
tấn công đã có quyền root.

---

## 11. Những công cụ cần cẩn thận

**Ghim ARP gateway** — chỉ dùng khi chắc chắn baseline gateway đúng. Nó tạo một
neighbor tĩnh; đổi router hoặc đổi mạng có thể mất kết nối cho tới khi gỡ hoặc làm
mới mục đó.

**Né tránh khẩn cấp** — đổi MAC và xin IP mới theo chu kỳ. Mỗi lần đổi là rớt hết
kết nối đang có, và Wi-Fi có quản lý có thể từ chối máy. Nó **câu giờ**, không đuổi
được kẻ tấn công. Nó không bao giờ tự bật.

**Tarpit phòng thủ** — mở cổng mồi và giữ chân các kết nối do **đối phương tự khởi
tạo**. Nó không bao giờ gửi flood ra ngoài. Có giới hạn để tự bảo vệ máy: tối đa
100 kết nối bị giữ, 10 kết nối cho mỗi IP nguồn (để một kẻ tấn công không chiếm
sạch slot), và 30 phút cho mỗi kết nối. Cổng mồi mặc định bind `0.0.0.0` để bẫy
được kẻ quét từ bất kỳ interface nào; nếu máy có IP public thì agent sẽ cảnh báo, và
bạn đặt `SHIELD_TARPIT_BIND` về đúng IP LAN để giới hạn lại.

---

## 12. Vận hành và làm cứng

### Checklist production

1. Sinh khoá bằng `sudo ./scripts/generate-signing-keys.sh`, rồi nạp
   `SHIELD_AUDIT_HMAC_KEY` và `SHIELD_RULE_PUBLIC_KEY` qua systemd credential hoặc
   secret manager. Đừng commit chúng.
2. Giữ `/var/lib/shield` thuộc `root:shield`; file DB và quarantine không được để
   mọi user đọc.
3. Rà lại danh sách đường dẫn FIM trước khi triển khai. Giám sát đúng các file cấu
   hình nhạy cảm, không quét cả cây home hay cây dữ liệu.
4. Giữ policy ở chế độ audit-only cho tới khi đã kiểm thử preview và rollback trên
   đúng distro đích.
5. Coi plugin là mã tin cậy. Quyền có phiên bản và Python cô lập giảm sai sót,
   nhưng **không phải** sandbox mức hệ điều hành.
6. Chạy `shield-benchmark --iterations 10` sau khi cài và sau khi thêm đường dẫn
   FIM lớn. Lệnh thoát khác 0 khi vượt ngưỡng tài nguyên.
7. Sau mỗi lần nâng cấp, kiểm tra `systemctl status shield-agent`, lỗi trong
   journal và ô toàn vẹn forensic.
8. Muốn có telemetry exec và file được bảo vệ theo sự kiện, xem lại rồi cài
   `/usr/share/shield/audit/99-shield.rules` vào `/etc/audit/rules.d/`. Collector
   `/proc` vẫn là phương án dự phòng khi không có auditd.

### Ranh giới tin cậy: group `shield`

Bất cứ thứ gì nối được tới socket agent (`/run/shield/shield.sock`, quyền `0660`
`root:shield`) đều gửi được **mọi** lệnh trong allowlist, gồm cả `response_execute`
— tức chặn IP và dừng tiến trình **bằng quyền root** thông qua helper. Trên socket
đó **không có** kiểm tra vai trò theo từng lệnh.

**Thêm một user vào group `shield` là cấp cho họ quyền phản ứng tương đương root.**
Trình cài tự thêm user đang cài vào group; trên máy nhiều người dùng, hãy rà lại
danh sách thành viên.

Muốn siết thêm, đặt `SHIELD_IPC_ALLOWED_UIDS` thành danh sách UID ngăn cách bằng
dấu phẩy trong `shield-agent.service`. Khi đó peer ngoài danh sách bị từ chối ngay
lúc kết nối dù có trong group; root luôn được phép để agent không tự khoá chính
mình. Bỏ trống thì giữ nguyên hành vi cũ theo group.

Helper root chặt hơn: chỉ chấp nhận root hoặc đúng UID agent đã cấu hình, từ vựng
là allowlist cố định, không chạy shell, không phân tích lệnh tự do. UI không bao
giờ nói chuyện trực tiếp với nó.

Đường dẫn socket cũng được kiểm lúc khởi động: agent từ chối phục vụ từ thư mục
không thuộc về nó hoặc ai cũng ghi được mà không có sticky bit, và **không** còn
rơi về `/tmp`. Chạy ngoài systemd thì phải đặt `SHIELD_SOCK` hoặc `XDG_RUNTIME_DIR`.

### Bật chữ ký và HMAC

Ký rule pack, verify config manifest, ký plugin và HMAC cho sổ forensic đều là
**tuỳ chọn**. Không cấu hình gì thì agent chạy fail-open và ghi cảnh báo lúc khởi
động, nói rõ đang thiếu cái nào.

```bash
sudo ./scripts/generate-signing-keys.sh          # ghi ra /etc/shield
```

Script sinh cặp khoá Ed25519 (đúng loại mà Shield verify bằng
`openssl pkeyutl -verify -rawin`), một khoá HMAC 256-bit, ký sẵn rule pack đi kèm,
rồi in ra các dòng `Environment=` để dán vào unit file. Sau đó chuyển các file
`*-private.pem` sang máy ký offline — trên endpoint chỉ cần khoá công khai và file
`.sig`.

Sửa `shield/rules/default.json` thì **phải ký lại**: một khi đã đặt
`SHIELD_RULE_PUBLIC_KEY`, rule pack chưa ký hoặc ký cũ sẽ chặn agent khởi động. Đó
là fail-closed có chủ đích.

### Hiệu năng

Bus sự kiện và bus cảnh báo đều có trần (8192 và 2048 bản ghi); bên sản xuất bị
backpressure chứ không để RAM phình vô hạn. Collector không được dùng hàng đợi vô
hạn, không poll dày hơn mức có lý do, và không gọi mạng đồng bộ trên event loop.
Hash được tính tăng dần, tra cứu threat intel có cache, và khi quá tải thì telemetry
ưu tiên thấp bị bỏ trước cảnh báo bảo mật.

---

## 12b. Mới trong 1.1

### Guardian — canh chừng Shield từ bên ngoài

`shield-guardian.timer` chạy mỗi 60 giây như một tiến trình **riêng**, kiểm tra:

- `shield-agent` có còn chạy không — nếu bị dừng mà không có lệnh tắt hợp lệ
  nào được ghi nhận, phát alert `critical`
- agent có đang khởi động lại liên tục không (`Restart=` che được crash-loop)
- file cài đặt có bị thay đổi không
- database còn đó và mở được không
- sổ bằng chứng có bị cắt ngắn không — nó chỉ được phép dài ra

Trước 1.1, `tamper_monitor_loop` chạy *bên trong* agent, nên `systemctl stop
shield-agent` xoá luôn cả cơ chế tự bảo vệ. Guardian bịt đúng lỗ đó.

```bash
journalctl -u shield-guardian -f     # xem nó nói gì
shield-guardian --json               # chạy một lần, in kết quả
```

Agent cũng ping `WATCHDOG=1` cho systemd (`WatchdogSec=90`), nên agent **treo**
— chứ không chết — cũng bị phát hiện và khởi động lại.

### Thu thập log từ máy khác

Xem `PROBE.md` trong cùng thư mục tài liệu. Tóm tắt:

- **Shield Probe** — agent nhỏ (15 KB, chỉ stdlib) cài lên máy Linux khác,
  gửi log về qua mTLS. Chỉ đọc, không bao giờ nhận lệnh.
- **Syslog** — cho router/camera/switch không cài được gì. Không xác thực
  được, nên log loại này **không vào sổ bằng chứng**, **không lên mức
  critical**, và **không dạy baseline**.

### Điểm rủi ro đầy đủ 5 yếu tố

```
Risk = Severity × Confidence × Asset Value × Repetition × Threat Context
```

Đặt độ quan trọng thiết bị ở tab Thiết bị (`Critical` / `Important` /
`Normal` / `Low priority`) — nó tham gia trực tiếp vào điểm. Mọi yếu tố đã tác
động đều liệt kê trong `risk_reasons` của alert.

### Sự việc (Incident)

Tab Sự cố có thêm bảng trên cùng: các sự việc do correlation ghép lại, mỗi
cái có mức rủi ro, kỹ thuật MITRE, và một hành động khuyến nghị cụ thể.
Correlation rule nằm ở `shield/rules/correlation.json` — thêm chuỗi tấn công
mới không phải sửa mã nguồn.

### Database hỏng tự phục hồi

Agent gặp database hỏng sẽ dời nó sang `shield.db.corrupt.<timestamp>` (**giữ
lại làm bằng chứng, không bao giờ xoá**), cứu phần đọc được sang database
mới, rồi chạy tiếp — thay vì crash-loop và để máy mất giám sát hoàn toàn.

### Cách ly có dead-man switch

Cách ly endpoint nói rõ dịch vụ nào sẽ đứt (SSH/DNS/Web/chia sẻ file/
email) và **tự gỡ** nếu agent ngừng gia hạn. Không có công tắc này thì lệnh
cách ly bị từ chối thẳng — cách ly một máy rồi mất khả năng gỡ là hỏng nặng
hơn thứ đang phòng chống.

Từ 2.0, nó cách ly thật. Shield ghi một bộ luật nftables vào `table inet
shield_isolation` riêng, rồi **đọc lại ruleset từ kernel** và kiểm tra: cả hai
hook có mặc định `drop` không, loopback còn được đi không, địa chỉ quản trị của
bạn còn được chấp nhận không. Chỉ khi tất cả đều đúng, lệnh mới báo thành công.
Nếu kiểm chứng thất bại, Shield xoá table đó đi và nói thẳng là **chưa** cách ly
được.

Trước 2.0, lệnh này arm đồng hồ tự gỡ rồi báo "đã cách ly" mà không áp một luật
firewall nào. Người vận hành nhìn thấy chữ "đã cách ly" trong khi máy vẫn nối
mạng bình thường — và vì tin là đã cô lập được, họ ngừng tìm cách khác.

Hai điều nên biết trước khi bấm nút:

- **Các kết nối đang mở bị cắt.** Cách ly cố ý không chừa `ct state
  established`: cho các kết nối đang mở chạy tiếp nghĩa là phiên điều khiển của
  kẻ tấn công sống sót — đúng thứ cần cắt. Phiên quản trị của bạn sống được vì
  địa chỉ quản trị được cho phép tường minh theo địa chỉ.
- **Không đụng gì tới phần firewall còn lại.** Cách ly nằm trong table riêng,
  nên gỡ cách ly không thể xoá nhầm một luật chặn IP đang có hiệu lực.

## 12c. Mới trong 2.0

Bản 2.0 xoay quanh một ý duy nhất: **Shield không bao giờ được nói một điều nó
chưa kiểm chứng.** Phần lớn những gì dưới đây tồn tại vì một bản trước đã nói
một điều nó chưa kiểm, và không ai phát hiện ra.

### Cách ly thật sự cách ly

Cách ly endpoint giờ ghi một bộ luật nftables thật vào `table inet
shield_isolation` riêng, rồi **đọc lại ruleset từ kernel** và kiểm: cả hai hook
có mặc định `drop` không, loopback còn đi được không, địa chỉ quản trị của bạn
còn được chấp nhận không. Chỉ khi tất cả đều đúng nó mới báo thành công, và chỉ
khi đó đồng hồ tự gỡ mới được kích hoạt.

Trước 2.0, nó kích hoạt đồng hồ rồi báo "đã cách ly" mà không áp một luật
firewall nào. Bạn nhìn thấy chữ "đã cách ly" trong khi máy vẫn nối mạng bình
thường — và vì tin là đã cô lập được, bạn ngừng tìm cách khác.

Hai điều nên biết trước khi bấm nút:

- **Các kết nối đang mở bị cắt.** Cách ly cố ý không chừa `ct state
  established`: cho các kết nối đang mở chạy tiếp nghĩa là phiên điều khiển của
  kẻ tấn công sống sót — đúng thứ cần cắt. Phiên quản trị của bạn sống được vì
  địa chỉ quản trị được cho phép tường minh theo địa chỉ.
- **Không đụng gì tới phần firewall còn lại.** Cách ly nằm trong table riêng,
  nên gỡ cách ly không thể xoá nhầm một luật chặn IP đang có hiệu lực.

### Hàng đợi phản ứng

Trang **Response** mới hiện mọi hành động Shield định làm, đã làm, hoặc đã gỡ.
Ba khối tách rời có chủ ý:

| Khối | Là gì |
|---|---|
| Bảng | Chuyện đang xảy ra |
| Lịch sử trạng thái | Mọi bước chuyển, ai gây ra, lúc nào |
| Bằng chứng hậu kiểm | Thứ Shield **đọc lại được từ hệ thống** sau đó |

Khối thứ ba mới là khối quan trọng. Hai khối đầu chỉ nói Shield *nghĩ* gì. Một
hành động ở trạng thái `Đã áp, chưa kiểm chứng` cho tới khi có thứ gì đó thật sự
đọc lại trạng thái hệ thống — và **chưa kiểm chứng không có nghĩa là đã thành
công**, chỉ có nghĩa là chưa ai đọc lại.

Mọi hành động đều có thời hạn và tự gỡ. Nếu việc gỡ thất bại, bạn nhận một cảnh
báo mức nguy cấp ngay lập tức, vì gỡ thất bại để lại một luật firewall không ai
sẽ gỡ nữa.

Bốn hành động đã có, mỗi cái đủ hợp đồng — xem trước, kiểm tiền điều kiện, áp,
kiểm chứng, gỡ:

| Hành động | Mức | Làm gì |
|---|---|---|
| `snapshot_state` | 1 | Ghi lại ARP, socket và toàn bộ ruleset firewall vào một file. Chạy nó *trước* mọi thứ khác — chặn xong thì hết dấu vết. |
| `rate_limit_ip` | 2 | Làm chậm một địa chỉ xuống 50 gói/giây thay vì cắt hẳn. Nếu Shield đoán sai thì người dùng thật ở đó vẫn làm việc được — chậm, chứ không đứt. |
| `block_ip` | 2 | Chặn mọi lưu lượng đi và đến một địa chỉ, có thời hạn. |
| `isolate_endpoint` | 3 | Cắt tất cả trừ địa chỉ quản trị. **Luôn cần người duyệt** — một máy tự cách ly mình vì một detector chưa hiệu chuẩn là một sự cố tự gây ra. |

`stop_process` cố ý chưa có adapter: nó không đảo ngược được, và 2.0 không tự
động hoá thứ gì nó không gỡ lại được.

**Dừng mọi hành động phản ứng** là một ô tích ngay trên trang đó. Nó chặn mọi
lần áp hành động mới, và cố ý **không** chặn việc gỡ hay việc phục hồi sau
crash — một công tắc an toàn mà cũng chặn đường ra sẽ đóng băng mọi luật
firewall đang áp, và người bấm nó để dừng thiệt hại lại là người gây ra thiệt
hại lớn hơn. Việc đã duyệt vẫn nằm chờ và chạy lại khi bạn tắt công tắc.

### Telemetry nhân: được ĐO, không được khai

Trước đây Shield khai eBPF cho nó năng lực về tiến trình, file và socket, chỉ vì
`/sys/kernel/btf/vmlinux` tồn tại. Thực tế collector chỉ phát `process_exec`,
nên chuỗi hành vi `exec → ghi file → mở kết nối` là **code chết** trên mọi máy
thật — nó chưa từng kêu một lần nào, và không thể kêu.

Giờ từng probe được **gắn thật vào kernel lúc khởi động**, và chỉ loại nào gắn
được mới tính là có. Security Center hiện một dòng sức khoẻ cho mỗi loại event,
cộng một dòng `behavior_chain` riêng nói thẳng chuỗi có chạy được không, hoặc
thiếu mắt xích nào.

Hai quyết định bạn có thể nhận ra khi nhìn dữ liệu:

- `file_write` theo dõi `openat` có cờ ghi, không theo dõi syscall `write`.
  `write` bắn mỗi dòng log — hàng chục nghìn sự kiện mỗi giây trên một máy nhàn
  rỗi, nhấn chìm cả đường event để đổi lấy tín hiệu gần bằng không.
- Chuỗi hành vi chỉ kêu khi file được ghi rơi vào chỗ dropper hay đặt payload
  (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`, `/root`). Không có điều kiện đó
  thì mỗi lượt `apt upgrade` là một cảnh báo mức nguy cấp.

### Evidence graph và điều tra

Mỗi event giờ mang một `event_id` duy nhất, cả thời điểm xảy ra lẫn thời điểm
Shield nhận được, cùng nguồn gốc và mức tin cậy. Từ đó Shield dựng **evidence
graph** trên 12 loại thực thể — tiến trình, file, địa chỉ, người dùng, phiên
đăng nhập, thiết bị, dịch vụ và một số loại khác — nối với nhau bằng 11 quan hệ
như `ran_on`, `spawned`, `wrote`, `connected_to`, `logged_into`.

Quy tắc khiến graph đáng tin: **một cạnh không tồn tại được nếu thiếu ít nhất
một tham chiếu bằng chứng**, và ghi một cạnh mà bằng chứng của nó không tồn tại
sẽ bị từ chối. Khi hạn lưu trữ xoá một event, mọi cạnh dựa vào nó cũng biến mất
— một khẳng định bạn không kiểm lại được nữa thì không được tiếp tục trông
giống một khẳng định kiểm lại được.

Cạnh giữ mức tin cậy của **bằng chứng sinh ra nó**, không bao giờ thừa hưởng
mức tin cậy của thực thể ở hai đầu. Một dòng syslog giả mạo nhắc tới một máy bạn
đã quan sát cục bộ vẫn chỉ là một dòng syslog giả mạo.

### Phân tích bằng AI, và cái công tắc tắt nó đi

Trang **Incidents** có thêm khối phân tích. Trên bản cài mặc định, nó chạy một
bộ phân tích cục bộ tất định: chỉ đếm và ghép quan hệ, không suy luận về ý đồ.
Không có model ngôn ngữ nào trừ khi người quản trị tự cấu hình.

Những điều khối đó **không bao giờ** làm:

- Viết chữ **"đã xác nhận"**. Xác nhận là việc của bạn, sau khi đọc bằng chứng.
  Phân tích chỉ được nói `chưa xác nhận`, `có căn cứ`, `bị mâu thuẫn` hoặc
  `thiếu bằng chứng`.
- Đưa ra một xác suất. Nhãn tin cậy là `thấp`, `trung bình` hoặc `cao` — không
  bao giờ là một con số trông như xác suất đúng đã hiệu chuẩn.
- Giấu lỗi của chính nó. Nếu phân tích trích dẫn một bằng chứng không tồn tại,
  bạn vẫn nhìn thấy nó đã khẳng định gì, kèm một dòng đỏ nói rằng tham chiếu đó
  là bịa. Xoá đi sẽ giấu mất tín hiệu hữu ích nhất: một bộ phân tích liên tục
  bịa bằng chứng là một bộ phân tích cần bị tắt.

**Tắt toàn bộ phân tích AI** là một ô tích ngay trên trang đó. Nó chặn mọi lời
gọi công cụ của lớp phân tích và không thay đổi gì ở phát hiện, chấm điểm hay
phản ứng — nếu tắt AI cũng làm ngừng phát hiện thì sẽ không ai dám dùng công
tắc. Trạng thái được nhớ qua lần khởi động lại.

### Độ chính xác của detector được ĐO, không phải đoán

Trước đây cảnh báo hiện một con số `confidence` đọc như "90% khả năng đúng".
Thực ra nó có nghĩa "cảnh báo này có 5 mẩu bằng chứng". Hai câu hỏi khác nhau, và
2.0 tách chúng ra:

- **Sức mạnh bằng chứng** — bằng chứng phong phú và độc lập tới đâu. Tính ngay
  từ chính cảnh báo.
- **Độ chính xác detector** — detector này, ở phiên bản này, đã đúng bao nhiêu
  phần trăm trong thực tế. Nó chỉ tồn tại khi **có người** dán nhãn kết quả, và
  vẫn là *chưa biết* cho tới khi đủ 20 nhãn. Chưa biết thì hiện là chưa biết,
  không điền 0.5 vào đó.

Hệ quả trực tiếp: **detector chưa hiệu chuẩn không bao giờ được tự động hành
động.** Cho một detector mà chưa ai đo độ chính xác tự đi chặn IP là đánh cược
bằng hệ thống của người khác.

### Xuất log ra thư mục bạn chọn

**Cài đặt → Xuất log ra thư mục của bạn** ghi thêm một bản log vào chỗ bạn chỉ
định, để bạn tự lưu trữ, gửi cho người khác xem, hay nạp vào công cụ phân tích
riêng. Bản chính vẫn nằm trong database của Shield.

Bạn tự chọn mức tối đa Shield được dùng. Sau đó trang này nói cho bạn thứ thật
sự quan trọng:

> Đang dùng 350.0 MB / 1.0 GB (34.2%) — 22 file
> Nhịp hiện tại khoảng 80.0 MB/ngày, nên hạn mức này giữ được khoảng 12.8 ngày.
> Ổ đĩa còn trống 1.7 TB.

"10 GB" không nói cho bạn điều gì; "khoảng 12 ngày" thì nói rất nhiều. Cố ý
không có lựa chọn *không giới hạn* — một hạn mức vô hạn nghĩa là Shield tự cho
phép mình lấp đầy ổ đĩa của bạn.

Hai quy tắc an toàn nên biết:

- Shield chỉ đếm và chỉ xoá những file **do chính nó tạo** (`shield-log-*.jsonl`).
  Bạn trỏ vào thư mục Tài liệu của mình thì nó không đụng tới bất cứ thứ gì khác
  trong đó.
- Thư mục phải đã tồn tại, không được là thư mục hệ thống, và không thành phần
  nào trên đường dẫn được là liên kết tượng trưng. Shield chạy dưới quyền root;
  đi theo một symlink do người khác đặt sẵn chính là cách một bộ xuất log trở
  thành đường ghi đè `/etc/shadow`.

### Threat intelligence có thể thu hồi được

Threat intelligence là dữ liệu **do người khác viết** mà Shield dùng để ra quyết
định về máy của bạn. Điều đó khiến nó là một bề mặt tấn công: một bản ghi bị đầu
độc nói gateway của bạn là máy chủ điều khiển sẽ khiến Shield đề xuất chặn đúng
thứ đang giữ cho máy online.

Mỗi tài liệu intel Shield giữ nay ghi rõ nó đến từ đâu, hash nội dung, chữ ký có
xác minh được không, tải về lúc nào, nhập vào lúc nào, và thuộc bậc tin cậy nào.
Chỉ tài liệu có **chữ ký đã xác minh** mới vào bậc tin cậy. Nhập nội dung chưa ký
vẫn làm được nhưng phải yêu cầu tường minh, và nó vào bậc không tin cậy — nơi nó
vẫn hiện ra cho bạn xem nhưng không quyết định được kết luận nào.

Tài liệu có chữ ký **sai** thì mọi bậc đều từ chối. Đó là chuyện khác hẳn với
không có chữ ký: nó nghĩa là ai đó đã sửa nội dung sau khi ký.

Nếu một nguồn hoá ra bị đầu độc, hãy **thu hồi nó**. Thu hồi có hiệu lực ngay ở
lần tra tiếp theo, không cần khởi động lại. Nó không xoá tài liệu, vì sau một sự
cố, câu bạn cần trả lời là "kết luận hôm qua dựa trên cái gì, và cái đó giờ ra
sao?"

Nguồn ngoài **chỉ đối chứng**. Dù bao nhiêu nguồn đã ký cùng nói một điều, một
khẳng định mà mọi bằng chứng đều là nguồn ngoài không bao giờ được đạt trạng thái
"có căn cứ". Nguồn ngoài mô tả thế giới nói chung; nó không quan sát máy của bạn.

### Trần dung lượng database giờ mới thật sự giới hạn

`SHIELD_DATABASE_MAX_MB` trước đây đo theo kích thước file. SQLite không làm
file nhỏ lại khi xoá dòng, nên cái trần đó không bao giờ thấy việc xoá của chính
nó có tác dụng: nó có thể xoá tới hai triệu event và kết thúc vẫn báo là đang
trên trần. Giờ nó đo phần dung lượng đang thật sự dùng, và bản cài mới còn tự
trả đĩa về hệ điều hành.

Nếu bạn giữ mức lưu trữ 30 ngày, lưu ý evidence graph tốn thêm khoảng 600 byte
cho mỗi event mà nó hiểu, cộng vào phần event thô. Nâng trần lên nếu bạn muốn
giữ đủ 30 ngày.

---

## 12d. Mới trong 3.0. Giải thích bằng AI cục bộ, và vì sao nó tắt sẵn

Shield 3.0 có thể thêm một đoạn giải thích ngắn vào báo cáo sự cố. Nó tắt cho
tới khi bạn bật, nó chạy ngay trên máy này, và báo cáo không phụ thuộc vào nó.

### Báo cáo luôn đến trước

Mở một sự cố là dựng một báo cáo tất định từ những gì Shield đo được: loại sự
cố, mức nghiêm trọng, khung thời gian, tài sản bị ảnh hưởng, hoạt động quan sát
được, sự kiện đã xác nhận, bằng chứng đã kiểm, phát hiện hỗ trợ, bước tiếp theo
nên làm, và giới hạn. Báo cáo đó mới là thứ có thẩm quyền. Nó đầy đủ một mình,
hiện ra trong khoảng một mili giây, và mọi giá trị trong đó đến từ cơ sở dữ
liệu chứ không từ model.

Đoạn giải thích của AI, khi có, nằm ở một khối riêng bên dưới, có nhãn, và
trông rõ ràng là phụ. Không dòng nào trong báo cáo do model viết, và không câu
nào của model được trình bày như một phép đo.

### Hai công tắc, và cả hai phải bật

Quản trị viên cấu hình provider trong unit file. Sau đó ai đó tích ô **Giải
thích bằng AI** ở trang Sự cố. Một cái thôi là chưa đủ. Cấu hình provider là
việc cài đặt; tích ô là chấp nhận rằng máy này sẽ chạy một model. Nếu một hành
động làm cả hai việc thì model bắt đầu chạy ngay lúc cài xong, và chưa từng có
ai đồng ý.

Mặc định là tắt. Tắt lại sau này thì báo cáo vẫn đầy đủ đúng như cũ.

### Model là do bạn cung cấp

Shield không bao giờ tự tải model. Trong mã AI không có HTTP client, cũng không
có mirror nào để lấy về. Bạn tự cài một file GGUF, thuộc sở hữu root và cho
phép mọi người đọc, đặt dưới `/opt/shield/models`. Bản đã kiểm là
Qwen2.5-1.5B-Instruct Q4_K_M. Runtime `llama-cpp-python` là phụ thuộc tuỳ chọn,
Shield không cần nó để khởi động.

Cài runtime vào ĐÚNG môi trường của agent:

```bash
sudo /opt/shield/.venv/bin/pip install llama-cpp-python
```

Đường dẫn đó là quan trọng. Worker chạy model ở chế độ cô lập (`python -I`) để
mã native không đáng tin không nhặt được bất cứ thứ gì đang nằm trong
site-packages của người dùng hay của hệ thống — và điều đó cũng có nghĩa là một
runtime cài ở chỗ khác thì nó không nhìn thấy. Thiếu runtime thì bảng giải
thích báo provider không dùng được, còn báo cáo không bị ảnh hưởng.

**Cài lại runtime sau MỖI lần nâng cấp Shield.** Gói dựng lại virtualenv từ đầu
ở mỗi lần cài, và đó là chủ ý: cài đặt diễn ra offline và lặp lại được, không
mang theo gì từ lần trước. File GGUF nằm ngoài virtualenv nên còn nguyên;
`llama-cpp-python` thì không. Cho tới khi bạn cài lại, Shield vẫn chạy bình
thường và phần trả lời AI báo là provider không dùng được.

Không có model và không có runtime thì Shield vẫn chạy bình thường và báo cáo
sự cố hoạt động đúng như tài liệu mô tả. Chỉ là đoạn giải thích không xuất hiện.

### Nó chạy nền, trong cgroup riêng

Suy luận mất khoảng 15 đến 25 giây trên CPU đã kiểm, nên nó không bao giờ diễn
ra trong lúc bạn chờ. Mở một sự cố là nhận báo cáo ngay lập tức và xếp phần
giải thích vào hàng; bảng thông tin nói rằng nó đang được chuẩn bị, và đoạn văn
hiện ra khi xong.

Model chạy trong một tiến trình riêng, trong một systemd scope tạm nằm CẠNH
agent chứ không nằm trong agent, giới hạn 2560 MB với swap tắt, 300% CPU và 96
tác vụ, và bị gỡ mạng. Nếu không dựng được scope đó, hoặc không gỡ được mạng,
thì không model nào chạy cả và bạn nhận báo cáo tất định. Không có đường lui
nào chạy mà không cách ly.

### Chỉ những kịch bản đã qua kiểm

Tám trong bốn mươi lăm kịch bản của Shield được phép có giải thích: họ tấn công
xác thực, và chuỗi thực thi đáng ngờ. Phần còn lại chỉ có báo cáo tất định, kể
cả mọi thứ Shield không phân loại được. Kịch bản giành quyền đó bằng đo đạc,
từng họ một, và một họ đạt 94,7% so với ngưỡng 95% đã bị để lại thay vì làm
tròn lên.

Quyền đó do agent quyết định. Giao diện không thể nới nó ra.

### Những gì nó sẽ không làm

Không có khung chat, không có ô nhập lệnh, và không có cách nào hỏi model một
câu. Model không bao giờ được cấp công cụ, kết nối cơ sở dữ liệu, hay
capability token, và nó không kích hoạt được hành động phản ứng nào. Nó nhận
những sự kiện Shield đã kiểm và viết văn xuôi về chúng; toàn bộ giao diện chỉ
có vậy.

Mọi câu đều được kiểm trước khi lưu. Câu nào bịa ra một cổng, một địa chỉ, một
mã tiến trình, một con số đếm, một mốc thời gian, hay một tham chiếu bằng chứng
đều bị bỏ, và câu nào khẳng định chắc chắn hơn mức Shield biết cũng vậy. Việc
bỏ diễn ra theo từng câu, nên một đoạn sai một phần sẽ mất đúng phần sai và giữ
phần còn lại, còn một đoạn mất hết thì đơn giản là không xuất hiện.

### Những giới hạn nên biết

Bộ lọc đối chiếu điều được nói với giá trị đo được. Nó không xét giọng điệu hay
ý định, nên một đoạn giải thích có thể chứa câu mang dáng dấp mệnh lệnh, kiểu
"hãy chạy isolate_host ngay". Không có gì thực thi câu đó: Shield không có
đường nào đi từ văn bản sinh ra tới một hành động, và câu đó chỉ nằm trong khối
giải thích đã dán nhãn. Hãy coi nó là lời bình, không phải chỉ thị, và hành
động theo báo cáo.

Mỗi bộ bằng chứng chỉ được giải thích nhiều nhất hai lần. Hỏng cả hai lần thì
bảng thông tin nói vậy và dừng lại. Đổi bằng chứng, đổi ngôn ngữ, hay đổi model
là một câu hỏi mới và một lượt thử mới.

Đoạn giải thích không được giữ dưới dạng output thô của model. Chỉ những câu đã
qua kiểm mới được lưu, và chúng bị bỏ khi bằng chứng mà chúng mô tả thay đổi.

---

## 13. Kiểm thử và các gate phát hành

Unit test không cần quyền đặc biệt, chạy an toàn trên máy làm việc:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest tests/ -q
```

Test cần quyền cao từ chối chạy trừ khi bật tường minh. **Đừng bao giờ** chạy
chúng trên máy đang mang lưu lượng production.

```bash
# vòng đời nftables bên trong network namespace riêng
sudo SHIELD_RUN_ROOT_TESTS=1 ./scripts/security-integration.sh

# smoke test trên gói đã cài thật
sudo SHIELD_RUN_VM_TESTS=1 ./scripts/vm-smoke.sh
```

Smoke test kiểm: trạng thái service, các cờ hardening của systemd, log khởi động,
ngưỡng của `shield-benchmark`, verify sổ forensic trên **database thật**, và khởi
động UI ở chế độ headless.

Kết quả release lab được chấm bằng:

```bash
shield-admin release-gate ./advanced-lab-results.json
```

Lệnh thoát mã 5 khi thiếu hoặc trượt một kịch bản bắt buộc, và bản thân nó không
chạy test quyền cao — một bài kiểm tra phát hành không được phép tự ý thay đổi máy.

### Còn bắt buộc trước 1.0 Stable

1. Soak test 24 giờ, 72 giờ, 7 ngày rồi 30 ngày trên gói thật, có lưu bằng chứng.
2. Chạy toàn bộ kịch bản root/response thật trong network namespace hoặc VM dùng
   một lần, lưu kết quả rollback, trên cả image Ubuntu, Debian và Kali.
3. Review độc lập về ranh giới quyền: socket, allowlist helper, TOCTOU, symlink,
   script đóng gói và độ tin cậy plugin.
4. Kiểm thử restore database và rollback gói trên từng bản Ubuntu được hỗ trợ.
5. Bổ sung YARA production và baseline time-series đầy đủ theo từng thiết bị (giờ
   hoạt động, băng thông, peer, đích đến).
6. Bổ sung collector DHCP, mDNS và SSDP/UPnP chuyên dụng cho việc nhận dạng thiết bị.
7. Mở rộng việc gom incident thành bản ghi lưu bền có trạng thái, tài sản bị ảnh
   hưởng và timeline bằng chứng.

Cho tới khi các gate đó đạt, tên đúng của sản phẩm là **Zuken Shield 1.0 RC**.

---

## 14. Khắc phục sự cố

**UI báo mất kết nối agent**

```bash
groups "$USER"
systemctl status shield-agent --no-pager
ls -l /run/shield/shield.sock
journalctl -u shield-agent -e --no-pager
```

Nếu phiên hiện tại chưa có group `shield`, đăng xuất rồi đăng nhập lại.

**Báo `No module named shield`** — virtualenv riêng cài chưa xong:

```bash
sudo apt install --reinstall ./dist/shield-monitor_3.0.0a2_amd64.deb
/opt/shield/.venv/bin/python -c 'import shield; print(shield.__version__)'
```

**Cài dở dang hoặc thiếu dependency**

```bash
sudo apt install ./dist/shield-monitor_3.0.0a2_amd64.deb
sudo dpkg --configure -a
```

**Một chức năng quét không chạy** — xem journal để tìm lỗi thiếu `arp-scan`,
`nmap`, `tcpdump`, `nftables` hoặc lỗi quyền. Cài `tshark` để phân loại giao thức,
`dnsutils` cho bài kiểm tra DNS, `fonts-dejavu-core` nếu PDF thiếu chữ tiếng Việt.
Trang Wi-Fi trống khi NetworkManager chưa lưu mạng nào.

---

## 15. Gỡ cài đặt

```bash
sudo apt remove shield-monitor     # giữ /var/lib/shield
sudo apt purge shield-monitor      # cũng vẫn giữ dữ liệu điều tra
```

Chỉ xoá tay `/var/lib/shield` sau khi chắc chắn không còn cần lịch sử, PCAP,
snapshot hay file đã cách ly trong đó.

---

## 16. Ranh giới an toàn

- Chỉ quét hệ thống và mạng bạn sở hữu hoặc được cấp phép kiểm thử.
- Đừng coi gợi ý CVE, điểm rủi ro hay độ phủ MITRE là bằng chứng có lỗ hổng.
- Xác minh bằng chứng trước khi chặn, dừng tiến trình, cách ly file hay ghim ARP.
- Đừng bật phản ứng tự động trước khi đã thử preview và rollback trong VM.
- Plugin là mã tin cậy; chỉ bật plugin đã rà soát và có verify chữ ký.
- Shield không thay thế sao lưu, cập nhật bảo mật, tường lửa được quản lý đúng
  cách, MFA, hay một quy trình ứng phó sự cố.
