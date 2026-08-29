"""Explainable local baseline detector; no model download or cloud upload.

Shield học "cái gì là bình thường ở ĐÂY" rồi báo khi thấy lệch. Ba chiều
(KE-HOACH-SHIELD-1.1.md mục B7):

1. **Hành vi máy** — tiến trình, cổng lắng nghe, service, DNS server.
2. **Thiết bị trong mạng** — máy nào thường có mặt vào khung giờ nào. Một
   thiết bị lạ lúc 3 giờ sáng khác hẳn cùng thiết bị đó lúc 2 giờ chiều.
3. **Giờ đăng nhập** — user nào thường đăng nhập giờ nào. SSH lúc 03:20
   trong khi baseline là 08:00–18:00 là tín hiệu đáng chú ý.

Toàn bộ đều là đếm tần suất, không có mô hình học máy: mỗi cảnh báo phải giải
thích được bằng một câu, và phải tái lập được từ dữ liệu trong SQLite.
"""

from __future__ import annotations

import logging
import time

from shield.common.models import Alert, Event, now
from shield.security.trust import may_train_baseline

logger = logging.getLogger("shield.anomaly")

# Hành vi máy — dải 6 tiếng là đủ: một tiến trình chạy 9h hay 11h sáng đều là
# "buổi sáng ngày làm việc", không đáng tách riêng.
OBSERVED_KINDS = {"process_exec", "process_started", "listener_opened", "service_changed", "dns_servers_changed"}

# PHIÊN BẢN ĐỊNH DẠNG KHOÁ, theo TỪNG loại event.
#
# `behavior_key()` dựng khoá từ các trường của event. Thêm một trường vào
# telemetry là đổi khoá, và mọi thứ đã học trở thành "chưa từng thấy". Tăng số
# ở đây khi điều đó xảy ra: agent sẽ xoá baseline của ĐÚNG loại đó và học lại
# trong im lặng, thay vì coi cả máy là bất thường.
#
# Đặt theo từng loại, không phải một số chung: đổi cách dựng khoá của
# `process_started` không có lý do gì bắt `host_seen` học lại.
#
# Lịch sử:
#   process_started 1 -> 2  (Phase 2/A2) ảnh chụp procfs thêm `uid`, nên khoá
#       đi từ `process_started|system|<dải>|<exe>` thành
#       `process_started|<uid>|<dải>|<exe>`. Đo trên máy thật: 640 khoá đã học
#       thành vô dụng, ~200 cảnh báo/giờ lúc đầu.
BEHAVIOR_KEY_FORMATS: dict[str, int] = {
    "process_exec": 1,       # eBPF/auditd LUÔN có uid — định dạng không đổi
    "process_started": 2,
    "listener_opened": 1,
    "service_changed": 1,
    "dns_servers_changed": 1,
    "host_seen": 1,
    "ssh_auth_success": 1,
    "login_success": 1,
}

# Thiết bị: cũng dải 6 tiếng — đêm / sáng / chiều / tối.
DEVICE_KINDS = {"host_seen"}

# Đăng nhập: dải 2 tiếng, mịn hơn. Ranh giới giữa "tan làm" và "nửa đêm" là
# thứ đáng phân biệt, còn dải 6 tiếng thì gộp 18h với 23h làm một.
LOGIN_KINDS = {"ssh_auth_success", "login_success"}
LOGIN_BAND_HOURS = 2


def _band(ts: float, hours: int) -> int:
    return time.localtime(ts).tm_hour // hours


# Mỗi loại được quan sát phải có một hàm dựng giá trị khoá TƯỜNG MINH.
#
# Trước đây chỗ này là một chuỗi `if/elif` kết thúc bằng `else` bắt tất cả,
# vốn viết cho `dns_servers_changed`. Hậu quả: thêm một loại vào
# `OBSERVED_KINDS` mà quên thêm nhánh thì MỌI event của loại đó gộp thành một
# khoá duy nhất với giá trị RỖNG — `'socket_connect|1000|1|'` — và không có
# lỗi nào được nêu. Một detector im lặng trông y hệt một máy sạch.
#
# Dạng bảng tra làm điều kiện đó kiểm được: `OBSERVED_KINDS` phải là tập con
# của các khoá ở đây, và có bất biến khẳng định điều đó.
KEY_VALUE_BUILDERS = {
    "process_exec": lambda d: d.get("exe") or d.get("comm"),
    "process_started": lambda d: d.get("exe") or d.get("comm"),
    "listener_opened": lambda d: f"{d.get('protocol', 'tcp')}:{d.get('port', '?')}",
    "service_changed": lambda d: d.get("unit") or d.get("name"),
    "dns_servers_changed": lambda d: ",".join(sorted(map(str, d.get("servers", [])))),
}

_da_canh_bao: set[str] = set()


def behavior_key(event: Event) -> str | None:
    """Khoá hành vi, hoặc None nếu loại này chưa có hàm dựng tường minh.

    None nghĩa là KHÔNG học và KHÔNG cảnh báo — fail closed. Học bằng một khoá
    bịa ra còn tệ hơn không học: nó dạy baseline rằng mọi thứ đều giống nhau,
    rồi im lặng mãi mãi.
    """
    builder = KEY_VALUE_BUILDERS.get(event.kind)
    if builder is None:
        if event.kind not in _da_canh_bao:
            _da_canh_bao.add(event.kind)
            logger.warning(
                "loại %r nằm trong danh sách quan sát nhưng không có hàm dựng "
                "khoá hành vi — bỏ qua, không học", event.kind)
        return None
    value = builder(event.data)
    user = event.data.get("uid", event.data.get("user", "system"))
    return f"{event.kind}|{user}|{_band(event.ts, 6)}|{value}"


def device_key(event: Event) -> str:
    """Thiết bị nhận diện bằng MAC, không bằng IP: IP đổi theo DHCP, và một
    baseline theo IP sẽ báo động mỗi lần router cấp lại địa chỉ."""
    identity = event.data.get("mac") or event.data.get("ip") or "unknown"
    return f"device_seen|{str(identity).lower()}|{_band(event.ts, 6)}"


def login_key(event: Event) -> str:
    user = event.data.get("user", "unknown")
    host = event.data.get("probe_host") or event.data.get("host") or "local"
    return f"login_time|{host}|{user}|{_band(event.ts, LOGIN_BAND_HOURS)}"


class LocalBaselineDetector:
    def __init__(self, store, learning_days: int = 7, minimum_observations: int = 3) -> None:
        self.store = store
        self.learning_days = max(1, min(30, learning_days))
        self.minimum_observations = max(1, minimum_observations)
        # Số cảnh báo đã BỊ NÉN vì loại đó đang học lại. Nén mà không đếm là
        # nén trong im lặng, và một detector im lặng trông y hệt một máy sạch.
        self.suppressed_by_relearn: dict[str, int] = {}

    def handle_event(self, event: Event) -> list[Alert]:
        # may_train_baseline loại cả event synthetic (từ Assessment) lẫn log
        # không xác thực — nguồn giả mạo được thì không được dạy baseline
        # rằng hành vi tấn công là "bình thường". Xem security/trust.py.
        if not may_train_baseline(event):
            return []

        if event.kind in OBSERVED_KINDS:
            key = behavior_key(event)
            if key is None:
                return []
            return self._check(
                event, key, "ANOMALY_NEW_BEHAVIOR",
                "New behavior outside local baseline",
                f"First-seen {event.kind} for this user/time band",
            )
        if event.kind in DEVICE_KINDS:
            return self._check(
                event, device_key(event), "ANOMALY_DEVICE_AT_UNUSUAL_TIME",
                "A device appeared at a time it never appears",
                "This device has not been seen in this part of the day before",
            )
        if event.kind in LOGIN_KINDS:
            return self._check(
                event, login_key(event), "ANOMALY_LOGIN_AT_UNUSUAL_TIME",
                "A login happened at an unusual hour for this account",
                f"{event.data.get('user', 'unknown')} has not logged in during this time band before",
            )
        return []

    def _relearning(self, kind: str, at: float) -> bool:
        getter = getattr(self.store, "_relearn_until_for", None)
        return bool(getter and getter(kind) > at)

    def _check(self, event: Event, key: str, rule_id: str, title: str, detail: str) -> list[Alert]:
        previous, learning = self.store.observe_behavior(key, event.kind, self.learning_days)
        if learning or previous >= self.minimum_observations:
            # Phân biệt "đang học lần đầu" với "đang học lại sau khi đổi định
            # dạng khoá": cái sau là hệ quả của một thay đổi do chính chúng ta
            # gây ra, và phải nhìn thấy được ở tab Sức khoẻ.
            if learning and previous == 0 and self._relearning(event.kind, event.ts):
                self.suppressed_by_relearn[event.kind] = \
                    self.suppressed_by_relearn.get(event.kind, 0) + 1
            return []
        return [Alert(
            now(), rule_id, "warning", title, detail, key,
            evidence={
                "behavior_key": key, "previous_observations": previous,
                "explanation": "locally learned first-seen behavior",
                "local_hour": time.localtime(event.ts).tm_hour,
                **event.data,
            },
            playbook=["snapshot_state"],
        )]
