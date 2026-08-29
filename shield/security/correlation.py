"""Gộp nhiều alert rời rạc thành MỘT sự việc (incident).

Trước 1.1, alert tương quan cũng chỉ là "thêm một alert nữa": người dùng nhìn
thấy 30 dòng thay vì một sự việc có đầu có cuối. Từ 1.1, mỗi lần correlation
khớp sẽ mở (hoặc cập nhật) một `incident` — có id, mức rủi ro, kỹ thuật MITRE,
và một hành động khuyến nghị cụ thể.

Rule correlation nạp từ `shield/rules/correlation.json` thay vì viết cứng
trong agent, để thêm một chuỗi tấn công mới không phải sửa mã nguồn.
"""

from __future__ import annotations

import json
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path

from shield.common.models import Alert, now

# Trần cho min_count. Lịch sử mỗi subject bị giới hạn, nên một ngưỡng cao hơn
# sức chứa sẽ KHÔNG BAO GIỜ khớp — một luật phát hiện im lặng vĩnh viễn là kiểu
# hỏng tệ nhất, vì nó trông y hệt như "không có gì xảy ra".
MAX_MIN_COUNT = 1000
# Số subject theo dõi đồng thời. Subject của syslog là IP nguồn, mà IP nguồn của
# một gói UDP thì giả mạo được: không chặn trần ở đây thì chỉ cần bơm log với IP
# ngẫu nhiên là agent phình bộ nhớ tới chết.
MAX_SUBJECTS = 2048


@dataclass(frozen=True)
class CorrelationRule:
    id: str
    required_rules: frozenset[str]
    window_s: float
    severity: str = "critical"
    title: str = "Correlated suspicious activity"
    mitre_techniques: tuple[str, ...] = ()
    recommended_action: str = ""
    # min_count > 0: gom theo SỐ LƯỢNG thay vì theo tổ hợp rule khác nhau.
    # Một loại log lặp lại đủ nhiều tự nó là một vấn đề — 50 lần đăng nhập
    # sai từ một máy không phải "50 cảnh báo nhỏ", nó là một cuộc dò mật khẩu.
    #
    # Đặt CUỐI danh sách trường là có chủ ý: chèn vào giữa sẽ làm mọi lời gọi
    # dựng bằng tham số vị trí đọc lệch trường mà không báo lỗi.
    min_count: int = 0

    @classmethod
    def from_dict(cls, raw: dict) -> "CorrelationRule":
        required = raw.get("required_rules")
        min_count = int(raw.get("min_count", 0) or 0)
        if not isinstance(required, list) or not required:
            raise ValueError(f"correlation rule {raw.get('id')!r} cần ít nhất 1 rule thành phần")
        if min_count:
            if not 2 <= min_count <= MAX_MIN_COUNT:
                raise ValueError(f"min_count phải nằm trong khoảng 2..{MAX_MIN_COUNT}")
        elif len(required) < 2:
            # Không có min_count thì luật chỉ có nghĩa khi ghép từ 2 rule trở lên;
            # một rule đơn lẻ không có ngưỡng sẽ khớp mọi alert và làm nhiễu.
            raise ValueError(f"correlation rule {raw.get('id')!r} cần ít nhất 2 rule thành phần")
        window = float(raw.get("window_s", 600))
        if not 1 <= window <= 86400:
            raise ValueError("window_s phải nằm trong khoảng 1 giây tới 24 giờ")
        if raw.get("severity", "critical") not in {"info", "warning", "critical"}:
            raise ValueError("severity không hợp lệ")
        return cls(
            id=str(raw["id"]),
            required_rules=frozenset(str(item) for item in required),
            window_s=window,
            min_count=min_count,
            severity=raw.get("severity", "critical"),
            title=str(raw.get("title", "Correlated suspicious activity")),
            mitre_techniques=tuple(str(t) for t in raw.get("mitre_techniques", ())),
            recommended_action=str(raw.get("recommended_action", "")),
        )

    @staticmethod
    def load_all(path: Path, public_key: Path | None = None) -> list["CorrelationRule"]:
        """Nạp correlation pack, kiểm chữ ký khi có khoá công khai.

        Event pack đã bắt buộc ký; nếu correlation pack không ký thì kẻ sửa
        được file này sẽ tắt được toàn bộ việc gộp alert thành sự việc, mà
        alert lẻ vẫn chạy nên nhìn bên ngoài mọi thứ đều bình thường.
        """
        path = Path(path)
        if public_key:
            from shield.security.supply_chain import verify_detached_signature

            signature = path.with_suffix(path.suffix + ".sig")
            if not signature.exists():
                raise ValueError(f"correlation pack chưa được ký: {path.name}")
            ok, message = verify_detached_signature(path, signature, public_key)
            if not ok:
                raise ValueError(f"correlation signature verification failed: {message}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1 or not isinstance(raw.get("rules"), list):
            raise ValueError("unsupported correlation rule schema")
        if raw.get("pack_type") != "correlation":
            raise ValueError("file này không phải correlation pack")
        rules = [CorrelationRule.from_dict(item) for item in raw["rules"] if item.get("enabled", True)]
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate correlation rule id")
        return rules


class CorrelationEngine:
    def __init__(
        self,
        rules: list[CorrelationRule],
        max_per_subject: int = 100,
        max_subjects: int = MAX_SUBJECTS,
    ) -> None:
        self.rules = tuple(rules)
        # Sức chứa lịch sử phải phủ được ngưỡng lớn nhất mà luật yêu cầu, nếu
        # không luật đó không bao giờ khớp mà cũng không báo lỗi.
        needed = max((rule.min_count for rule in self.rules), default=0)
        self.max_per_subject = max(2, max_per_subject, needed)
        self.max_subjects = max(1, max_subjects)
        self._history: OrderedDict[str, deque] = OrderedDict()
        self._last_emitted: OrderedDict[tuple[str, str], float] = OrderedDict()
        self.evicted_subjects = 0

    def _history_for(self, subject: str) -> deque:
        """Lịch sử theo subject, giữ LRU trong giới hạn cố định."""
        history = self._history.get(subject)
        if history is None:
            history = deque(maxlen=self.max_per_subject)
            self._history[subject] = history
            while len(self._history) > self.max_subjects:
                self._history.popitem(last=False)
                self.evicted_subjects += 1
        else:
            self._history.move_to_end(subject)
        return history

    def _throttled(self, key: tuple[str, str], ts: float, window_s: float) -> bool:
        previous = self._last_emitted.get(key)
        if previous is not None and ts - previous < window_s:
            self._last_emitted.move_to_end(key)
            return True
        self._last_emitted[key] = ts
        self._last_emitted.move_to_end(key)
        while len(self._last_emitted) > self.max_subjects:
            self._last_emitted.popitem(last=False)
        return False

    def handle_alert(self, alert: Alert) -> list[Alert]:
        return [item.alert for item in self.correlate(alert)]

    def correlate(self, alert: Alert) -> list["Correlation"]:
        """Trả về cả Alert lẫn ngữ cảnh để mở incident.

        `handle_alert` giữ nguyên chữ ký cũ cho đường ống detector hiện có;
        alert consumer dùng `correlate` để lấy thêm MITRE và hành động khuyến
        nghị mà không phải bới lại evidence.
        """
        history = self._history_for(alert.subject)
        # Mang theo `alert.alert_id` (= alerts.id) chứ không tra ngược sau. Gộp
        # trùng làm `alerts.ts` dịch tới, nên tra theo (rule_id, ts) sẽ trượt.
        history.append((alert.ts, alert.rule_id, alert.severity, alert.detail,
                        int(alert.alert_id or 0),
                        str(alert.evidence.get("event_id", ""))))
        output: list[Correlation] = []
        for rule in self.rules:
            cutoff = alert.ts - rule.window_s
            recent = [item for item in history if item[0] >= cutoff]
            matching = [item for item in recent if item[1] in rule.required_rules]
            if rule.min_count:
                # Luật ngưỡng: đủ số lần trong cửa sổ thì thành một sự việc.
                if len(matching) < rule.min_count:
                    continue
            elif not rule.required_rules.issubset({item[1] for item in matching}):
                continue
            key = (rule.id, alert.subject)
            if self._throttled(key, alert.ts, rule.window_s):
                continue
            contributing = [
                {"rule_id": rule_id, "ts": ts, "severity": severity,
                 "detail": detail, "alert_id": alert_id, "event_id": event_id}
                for ts, rule_id, severity, detail, alert_id, event_id in matching
            ]
            # LÝ DO GỘP: chỉ đầu vào của luật và số đo được. Không câu chữ.
            # Cùng một `matching` cho ra đúng cùng một dict, nên hai lần chạy
            # trên cùng dữ liệu so sánh được bằng dấu bằng.
            reason = {
                "reason_kind": "threshold_count" if rule.min_count else "rule_combination",
                "rule_id": rule.id,
                "subject": alert.subject,
                "window_s": rule.window_s,
                "required_rules": sorted(rule.required_rules),
                "observed_rules": sorted({item["rule_id"] for item in contributing}),
                "min_count": rule.min_count,
                "observed_count": len(contributing),
                "first_contributing_ts": min(item["ts"] for item in contributing),
                "last_contributing_ts": max(item["ts"] for item in contributing),
            }
            correlated = Alert(
                now(), rule.id, rule.severity, rule.title,
                (f"{len(contributing)} events matching "
                 f"{', '.join(sorted(rule.required_rules))} for {alert.subject}"
                 if rule.min_count else
                 f"Rules {', '.join(sorted(rule.required_rules))} matched for {alert.subject}"),
                alert.subject,
                evidence={
                    "rules": sorted(rule.required_rules), "window_s": rule.window_s,
                    "min_count": rule.min_count, "observed_count": len(contributing),
                    "mitre_techniques": list(rule.mitre_techniques),
                    "recommended_action": rule.recommended_action,
                    "contributing_alerts": len(contributing),
                },
                playbook=["snapshot_state"],
            )
            output.append(Correlation(correlated, rule, contributing, reason))
        return output


@dataclass(frozen=True)
class Correlation:
    alert: Alert
    rule: CorrelationRule
    contributing: list = field(default_factory=list)
    # Lý do gộp dạng có cấu trúc. Đặt CUỐI và có mặc định để lời gọi cũ dựng
    # bằng tham số vị trí không đọc lệch trường.
    reason: dict = field(default_factory=dict)
