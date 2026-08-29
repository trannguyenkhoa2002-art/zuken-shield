"""Versioned declarative event rules with no dynamic code execution."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from shield.common.models import Alert, Event, now

ALLOWED_SEVERITIES = {"info", "warning", "critical"}
ALLOWED_OPERATORS = {
    "eq", "ne", "in", "not_in", "prefix", "suffix", "contains", "regex", "gte", "lte", "exists",
}

# Chống ReDoS. Một pattern ác ý — hoặc chỉ là vụng về — treo được cả detector,
# và detector treo nghĩa là Shield mù trong khi vẫn hiện "đang chạy".
#
# Cắt độ dài đầu vào KHÔNG đủ: `(a+)+b` gặp 2000 ký tự "a" vẫn chạy tới hết
# tuổi thọ vũ trụ, vì backtracking tăng theo hàm mũ chứ không theo độ dài.
# Nên phải chặn ngay từ hình dạng pattern lúc nạp.
MAX_REGEX_PATTERN_CHARS = 200
MAX_REGEX_INPUT_CHARS = 2000

# Lượng từ lồng trong lượng từ: (a+)+, (a*)*, (a+){2,}, (?:x+)+ ... Đây là
# hình dạng gây bùng nổ backtracking. Heuristic bảo thủ: thà từ chối oan một
# pattern hợp lệ (viết lại được) còn hơn để lọt một pattern treo detector.
_NESTED_QUANTIFIER = re.compile(r"\((?:\?[:=!])?[^()]*[+*}][^()]*\)\s*[+*{]")


def rejects_catastrophic_backtracking(pattern: str) -> str:
    """Trả về lý do từ chối, hoặc chuỗi rỗng nếu pattern chấp nhận được."""
    if len(pattern) > MAX_REGEX_PATTERN_CHARS:
        return f"regex pattern must be under {MAX_REGEX_PATTERN_CHARS} characters"
    if _NESTED_QUANTIFIER.search(pattern):
        return (
            "regex has a quantifier applied to a group that already contains one "
            "(for example (a+)+), which can hang the detector — rewrite it without nesting"
        )
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"invalid regex: {exc}"
    return ""


@dataclass(frozen=True)
class EventRule:
    id: str
    version: int
    source: str | None
    kind: str
    field: str
    operator: str
    value: object
    severity: str
    title: str
    detail: str
    subject_field: str
    playbook: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict) -> "EventRule":
        required = {"id", "version", "kind", "match", "severity", "title", "detail", "subject_field"}
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"rule missing fields: {sorted(missing)}")
        match = raw["match"]
        if not isinstance(match, dict) or set(match) != {"field", "operator", "value"}:
            raise ValueError("match must contain exactly field/operator/value")
        if match["operator"] not in ALLOWED_OPERATORS:
            raise ValueError(f"unsupported operator: {match['operator']}")
        if match["operator"] == "regex":
            if not isinstance(match["value"], str):
                raise ValueError("regex pattern must be a string")
            reason = rejects_catastrophic_backtracking(match["value"])
            if reason:
                raise ValueError(f"rule {raw['id']}: {reason}")
        if match["operator"] in {"gte", "lte"} and not isinstance(match["value"], (int, float)):
            raise ValueError("gte/lte require a numeric value")
        if raw["severity"] not in ALLOWED_SEVERITIES or int(raw["version"]) < 1:
            raise ValueError("invalid severity or version")
        return cls(
            id=str(raw["id"]), version=int(raw["version"]), source=raw.get("source"),
            kind=str(raw["kind"]), field=str(match["field"]), operator=match["operator"],
            value=match["value"], severity=raw["severity"], title=str(raw["title"]),
            detail=str(raw["detail"]), subject_field=str(raw["subject_field"]),
            playbook=tuple(raw.get("playbook", ())),
        )

    def matches(self, event: Event) -> bool:
        if event.kind != self.kind or (self.source and event.source != self.source):
            return False
        actual = event.data.get(self.field)

        if self.operator == "exists":
            return (actual is not None) == bool(self.value)
        if self.operator == "eq":
            return actual == self.value
        if self.operator == "ne":
            return actual != self.value
        if self.operator == "in":
            return actual in self.value if isinstance(self.value, list) else False
        if self.operator == "not_in":
            return actual not in self.value if isinstance(self.value, list) else False
        if self.operator in {"gte", "lte"}:
            # bool là con của int trong Python, và float(True) == 1.0 — nên
            # phải loại thẳng, không được để nó rơi vào nhánh ép kiểu bên
            # dưới. Nếu không, `enabled: true` so được với ngưỡng số và cho
            # ra một kết quả hoàn toàn vô nghĩa.
            if isinstance(actual, bool):
                return False
            if not isinstance(actual, (int, float)):
                try:
                    actual = float(actual)
                except (TypeError, ValueError):
                    return False
            return actual >= self.value if self.operator == "gte" else actual <= self.value

        if not isinstance(actual, str) or not isinstance(self.value, str):
            return False
        if self.operator == "regex":
            return re.search(self.value, actual[:MAX_REGEX_INPUT_CHARS]) is not None
        return {
            "prefix": actual.startswith,
            "suffix": actual.endswith,
            "contains": lambda value: value in actual,
        }[self.operator](self.value)


class RuleDetector:
    def __init__(self, rules: list[EventRule]) -> None:
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate rule id")
        self.rules = tuple(rules)

    @classmethod
    def from_file(cls, path: Path, public_key: Path | None = None, signature: Path | None = None) -> "RuleDetector":
        if public_key is not None:
            from shield.security.supply_chain import verify_detached_signature
            if signature is None:
                raise ValueError("signed rules require a detached signature")
            ok, message = verify_detached_signature(path, signature, public_key)
            if not ok:
                raise ValueError(f"rule signature verification failed: {message}")
        return cls(cls.load_rules(path, public_key, signature))

    @staticmethod
    def load_rules(path: Path, public_key: Path | None = None, signature: Path | None = None) -> list[EventRule]:
        if public_key is not None:
            from shield.security.supply_chain import verify_detached_signature
            if signature is None:
                raise ValueError("signed rules require a detached signature")
            ok, message = verify_detached_signature(path, signature, public_key)
            if not ok:
                raise ValueError(f"rule signature verification failed: {message}")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != 1 or not isinstance(raw.get("rules"), list):
            raise ValueError("unsupported rule file schema")
        return [EventRule.from_dict(item) for item in raw["rules"] if item.get("enabled", True)]

    @classmethod
    def from_directory(cls, directory: Path, public_key: Path | None = None) -> "RuleDetector":
        """Nạp mọi rule pack trong một thư mục (mục B4 kế hoạch 1.1).

        Tách theo lĩnh vực (ssh/endpoint/syslog/probe) để sửa một mảng không
        phải đụng vào cả file. Khi bật ký, MỌI pack đều phải có chữ ký hợp lệ
        — một pack không ký lọt vào là đủ để vô hiệu hoá cả cơ chế ký.
        """
        rules: list[EventRule] = []
        for path in sorted(Path(directory).glob("*.json")):
            # Thư mục rules chứa nhiều LOẠI pack (event rule, correlation
            # rule). Phân biệt bằng `pack_type` khai trong file, không bằng
            # tên file: tên file là thứ dễ đổi và dễ đặt sai nhất.
            header = json.loads(path.read_text(encoding="utf-8"))
            if header.get("pack_type", "event") != "event":
                continue
            signature = path.with_suffix(path.suffix + ".sig") if public_key else None
            if public_key and not signature.exists():
                raise ValueError(f"rule pack chưa được ký: {path.name}")
            rules.extend(cls.load_rules(path, public_key, signature))
        return cls(rules)

    def handle_event(self, event: Event) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if not rule.matches(event):
                continue
            subject = str(event.data.get(rule.subject_field, "unknown"))
            # Rule pack là dữ liệu, có thể sai. Một placeholder thiếu không
            # được phép làm đứt cả đường ống detector.
            try:
                detail = rule.detail.format(**event.data)
            except (KeyError, IndexError, ValueError):
                detail = rule.detail
            alerts.append(Alert(
                now(), rule.id, rule.severity, rule.title, detail,
                subject, evidence={**event.data, "rule_version": rule.version},
                playbook=list(rule.playbook),
            ))
        return alerts
