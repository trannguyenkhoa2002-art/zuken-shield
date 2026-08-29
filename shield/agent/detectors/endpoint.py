"""Conservative endpoint behavior and file-integrity detections."""

from __future__ import annotations

from shield.common.models import Alert, Event, now

# Cổng mà một máy trạm không nên mở ra ngoài. Danh sách này đã tồn tại viết
# cứng trong nhánh `listener_opened`; nay nó có tên và được DÙNG CHUNG cho cả
# hai nhánh, để "cổng nào là nguy hiểm" không có hai câu trả lời.
SENSITIVE_LISTENER_PORTS = frozenset({23, 445, 3389, 5900})

# Cửa sổ chống trùng cho cảnh báo lúc khởi động: 24 giờ.
#
# `listener_observed` phát lại ở MỖI lần agent khởi động. Với cửa sổ mặc định
# 300 giây, mỗi lần khởi động lại sinh một hàng alert mới cho đúng một sự việc
# không đổi — và một cảnh báo lặp lại mỗi lần khởi động là cách nhanh nhất dạy
# người dùng bỏ qua nó. Cơ chế chống trùng chính danh tra thẳng bảng `alerts`
# nên nó sống qua restart; ở đây chỉ cần nói ra nhịp đúng.
BOOTSTRAP_ALERT_COOLDOWN_S = 86400.0


class EndpointDetector:
    def handle_event(self, ev: Event) -> list[Alert]:
        if ev.kind in {"process_started", "process_exec"}:
            exe = str(ev.data.get("exe", ""))
            if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                return [Alert(
                    now(), "ENDPOINT_SUSPICIOUS_EXEC_PATH", "warning",
                    "Tiến trình chạy từ vị trí tạm thời đáng chú ý",
                    f"PID {ev.data.get('pid')} chạy {exe}", exe or str(ev.data.get("pid")),
                    evidence=dict(ev.data), playbook=["snapshot_state"],
                )]
        if ev.source == "fim" and ev.kind in {"file_modified", "file_deleted"}:
            after = ev.data.get("after", {}) if ev.kind == "file_modified" else ev.data
            path = str(after.get("path", ev.data.get("path", "configured path")))
            return [Alert(
                now(), "FILE_INTEGRITY_CHANGED", "warning",
                "File integrity baseline changed", f"{ev.kind}: {path}", path,
                evidence={"change": ev.kind, "path": path, **ev.data}, playbook=["snapshot_state"],
            )]
        if ev.kind == "security_file_changed":
            path = str(ev.data.get("path") or ev.data.get("key", "protected configuration"))
            return [Alert(
                now(), "ENDPOINT_SECURITY_CONFIG_CHANGED", "critical",
                "Security-sensitive configuration changed",
                f"{path} changed by PID {ev.data.get('pid')} ({ev.data.get('exe', 'unknown')})",
                path, evidence=dict(ev.data), playbook=["snapshot_state"],
            )]
        if ev.kind == "usb_added":
            subject = f"{ev.data.get('vendor_id', '?')}:{ev.data.get('product_id', '?')}"
            return [Alert(
                now(), "ENDPOINT_USB_ADDED", "info", "USB device connected",
                ev.data.get("product") or subject, subject, evidence=dict(ev.data),
            )]
        if ev.kind == "listener_opened" and \
                int(ev.data.get("port", 0)) in SENSITIVE_LISTENER_PORTS:
            port = int(ev.data["port"])
            return [Alert(
                now(), "ENDPOINT_SENSITIVE_LISTENER_OPENED", "warning",
                "Sensitive network service started listening",
                f"{ev.data.get('protocol', 'tcp')} {ev.data.get('ip', '*')}:{port}",
                str(port), evidence=dict(ev.data), playbook=["snapshot_state"],
            )]
        if ev.kind == "listener_observed" and \
                int(ev.data.get("port", 0)) in SENSITIVE_LISTENER_PORTS:
            # NGỮ NGHĨA KHÁC HẲN nhánh trên, nên rule_id khác và câu chữ khác.
            #
            # Shield không biết cổng này mở từ bao giờ, nên không được nói "vừa
            # mở", "mới xuất hiện", "kẻ tấn công mở", hay "persistence". Nó chỉ
            # được nói đúng thứ nó thấy: cổng đang mở lúc bắt đầu giám sát.
            #
            # Mức `info` chứ không `warning`: thấp hơn đúng một bậc trong
            # taxonomy có sẵn (info | warning | critical). Rủi ro là thật —
            # một cổng SMB mở sẵn vẫn là cổng SMB mở — nhưng nó KHÔNG phải một
            # thay đổi vừa xảy ra, và trộn hai thứ đó làm một sẽ khiến cảnh báo
            # "vừa mở" mất trọng lượng.
            port = int(ev.data["port"])
            protocol = str(ev.data.get("protocol", "tcp"))
            owners = ev.data.get("owners") or ()
            # MỘT cảnh báo cho mỗi dịch vụ, kể cả khi nhiều tiến trình cùng giữ
            # socket. Danh sách chủ sở hữu vào evidence, đã sắp, không bốc một
            # cái làm đại diện.
            return [Alert(
                now(), "RISKY_LISTENER_PRESENT_AT_STARTUP", "info",
                "Risky listener already present when monitoring started",
                f"{protocol} {ev.data.get('ip', '*')}:{port} was already listening "
                "when Shield started. The opening time is unknown.",
                f"{protocol}:{port}",
                evidence={**ev.data,
                          # Đã SẮP: bằng chứng phải giống nhau giữa hai lần
                          # quan sát cùng một thứ, kể cả khi thứ tự đầu vào đổi.
                          "owner_identities": sorted(
                              f"{o.get('pid')}:{o.get('start_ticks')}" for o in owners)},
                playbook=["snapshot_state"],
                dedupe_window_s=BOOTSTRAP_ALERT_COOLDOWN_S,
            )]
        return []
