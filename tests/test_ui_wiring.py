"""Kiểm tra "đấu dây" của UI bằng phân tích tĩnh — chạy được không cần Qt.

Máy CI (và sandbox dev) không có libEGL nên không import được PySide6; nhưng
đúng những lỗi hay gặp nhất ở tầng UI lại kiểm được bằng đọc mã nguồn:

1. i18n: mọi khoá `t("...")` phải tồn tại trong STRINGS, và mọi rule_id
   detector phát ra phải có bản dịch title/detail — nếu thiếu, lịch sử cảnh
   báo sẽ hiện tiếng Việt thô kể cả khi UI đang để English.
2. Đường đi lệnh/broadcast giữa UI và agent phải khớp 2 chiều.
3. `bind()` chạy hàm NGAY lúc đăng ký, nên không được bind một hàm vẽ bảng
   trước khi bảng đó được tạo — lỗi này làm app crash ngay khi mở, và đã
   thực sự xảy ra một lần khi thêm bind cho bảng router.
"""

from __future__ import annotations

import re
import ast
import json
from pathlib import Path

import pytest

from shield.agent.tarpit import DEFAULT_TARPIT_PORTS
from shield.ui.i18n import STRINGS

ROOT = Path(__file__).resolve().parent.parent
UI_SRC = (ROOT / "shield" / "ui" / "__main__.py").read_text()
AGENT_SRC = (ROOT / "shield" / "agent" / "__main__.py").read_text()
DETECTOR_DIR = ROOT / "shield" / "agent" / "detectors"


# --- 1. i18n ---


def test_ui_default_tarpit_ports_matches_agent():
    """UI giữ 1 bản sao hằng số này (tránh import cả module agent.tarpit vào
    tiến trình UI) — phải tay đổi cả 2 chỗ nếu đổi danh sách mặc định."""
    m = re.search(r"DEFAULT_TARPIT_PORTS = \[([\d,\s]+)\]", UI_SRC)
    assert m, "không tìm thấy DEFAULT_TARPIT_PORTS trong UI"
    ui_ports = [int(x) for x in m.group(1).split(",") if x.strip()]
    assert ui_ports == list(DEFAULT_TARPIT_PORTS)


def test_every_translation_key_used_by_ui_exists():
    keys = set(re.findall(r'(?<![\w.])t\("([a-zA-Z0-9_.]+)"', UI_SRC))
    assert keys, "không tìm thấy lời gọi t() nào — regex hỏng?"
    missing = sorted(k for k in keys if k not in STRINGS)
    assert missing == [], f"khoá i18n dùng trong UI nhưng chưa khai báo: {missing}"


def test_every_string_has_both_languages():
    bad = [k for k, v in STRINGS.items() if not (isinstance(v, tuple) and len(v) == 2)]
    assert bad == [], f"khoá thiếu cặp (vi, en): {bad}"
    empty = [k for k, (vi, en) in STRINGS.items() if not vi.strip() or not en.strip()]
    assert empty == [], f"khoá có bản dịch rỗng: {empty}"


def test_navigation_is_grouped_and_help_covers_advanced_workflows():
    for key in ("section.operations", "section.monitoring", "section.investigation", "section.management"):
        assert key in STRINGS
        assert key in UI_SRC
    assert "self._sections" in UI_SRC
    assert "QTabWidget.TabPosition.North" in UI_SRC
    for key in ("help.navigation_title", "help.advanced_title", "help.assessment_title"):
        assert key in STRINGS
        assert key in UI_SRC


def _detector_rule_ids() -> set[str]:
    rules: set[str] = set()
    for path in DETECTOR_DIR.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if name != "Alert":
                continue
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                rules.add(node.args[1].value)
            for keyword in node.keywords:
                if keyword.arg == "rule_id" and isinstance(keyword.value, ast.Constant):
                    rules.add(keyword.value.value)
    # Mọi rule pack trong thư mục, không chỉ default.json — từ 1.1 rule được
    # tách theo lĩnh vực (ssh/endpoint/syslog/probe), và một pack quên dịch
    # sẽ hiện tiếng Anh thô giữa giao diện tiếng Việt.
    for rule_file in sorted((ROOT / "shield" / "rules").glob("*.json")):
        rules |= {item["id"] for item in json.loads(rule_file.read_text())["rules"]
                  if item.get("enabled", True)}
    # Correlation rule chuyển từ mã nguồn sang shield/rules/correlation.json
    # (mục B5) — vẫn phải có bản dịch như mọi rule khác.
    correlation_file = ROOT / "shield" / "rules" / "correlation.json"
    rules |= {item["id"] for item in json.loads(correlation_file.read_text())["rules"]
              if item.get("enabled", True)}
    return rules


def test_every_alert_rule_is_translatable():
    """Nếu thiếu, alert_text() rơi về title/detail thô (luôn tiếng Việt) —
    đúng triệu chứng "để English mà lịch sử vẫn tiếng Việt"."""
    rules = _detector_rule_ids()
    assert rules, "không đọc được rule_id nào từ detector"
    missing = sorted(
        r for r in rules
        if f"alert.{r}.title" not in STRINGS or f"alert.{r}.detail" not in STRINGS
    )
    assert missing == [], f"rule chưa có bản dịch title/detail: {missing}"


def test_alert_templates_have_matching_placeholders_in_both_languages():
    """{ip}, {mac}... phải giống nhau ở 2 ngôn ngữ, nếu không đổi sang English
    sẽ ném KeyError và alert rơi về chuỗi thô.

    Kiểm MỌI khoá, không riêng `alert.*`: bản trước chỉ soi tiền tố đó, nên một
    khoá như `live.feed_dropped` lệch placeholder sẽ lọt qua và chỉ nổ đúng lúc
    người dùng đổi ngôn ngữ.
    """
    bad = []
    for key, (vi, en) in STRINGS.items():
        if set(re.findall(r"\{(\w+)\}", vi)) != set(re.findall(r"\{(\w+)\}", en)):
            bad.append((key, vi, en))
    assert bad == [], f"placeholder lệch giữa 2 ngôn ngữ: {bad}"


VIETNAMESE_ONLY_CHARACTERS = set(
    "ăâđêôơư"
    "àáảãạằắẳẵặầấẩẫậ"
    "èéẻẽẹềếểễệ"
    "ìíỉĩị"
    "òóỏõọồốổỗộờớởỡợ"
    "ùúủũụừứửữự"
    "ỳýỷỹỵ"
)


def test_english_strings_contain_no_vietnamese():
    """Ô tiếng Anh không được chứa chữ Việt.

    Lỗi thường gặp nhất khi thêm khoá mới là dán cùng một câu tiếng Việt vào cả
    hai ô. Không có test này thì người dùng chọn English vẫn thấy tiếng Việt, và
    không ai nhận ra cho tới khi có người báo.
    """
    bad = [key for key, (_vi, en) in STRINGS.items()
           if any(character in VIETNAMESE_ONLY_CHARACTERS for character in en.lower())]
    assert bad == [], f"bản tiếng Anh còn chữ Việt: {bad}"


def test_message_box_titles_are_not_hardcoded_in_one_language():
    tree = ast.parse(UI_SRC)
    hardcoded = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in {"information", "warning", "question", "critical"} or len(node.args) < 2:
            continue
        title = node.args[1]
        if isinstance(title, ast.Constant) and isinstance(title.value, str):
            hardcoded.append(title.value)
    assert hardcoded == [], f"QMessageBox title chưa qua i18n: {hardcoded}"


# --- 2. UI <-> agent ---


def test_every_command_ui_sends_has_an_agent_handler():
    sent = set(re.findall(r'"cmd":\s*"([a-z_]+)"', UI_SRC))
    handled = set(re.findall(r'cmd == "([a-z_]+)"', AGENT_SRC))
    # `cmd in {"a", "b"}` cũng là cách xử lý hợp lệ và agent có dùng. Bỏ sót
    # dạng này biến một guard hữu ích thành một cảnh báo giả, và cảnh báo giả
    # lặp lại vài lần là cách nhanh nhất để người ta tắt guard.
    for group in re.findall(r'cmd in \{([^}]*)\}', AGENT_SRC):
        handled.update(re.findall(r'"([a-z_]+)"', group))
    assert sent, "không tìm thấy lệnh nào UI gửi"
    missing = sorted(sent - handled)
    assert missing == [], f"UI gửi lệnh agent không xử lý: {missing}"


def test_every_broadcast_agent_sends_is_handled_by_ui():
    sent = set(re.findall(r'broadcast\(\s*\n?\s*"([a-z_]+)"', AGENT_SRC))
    handled = set(re.findall(r'msg_type == "([a-z_]+)"', UI_SRC))
    assert sent, "không tìm thấy broadcast nào"
    missing = sorted(sent - handled)
    assert missing == [], f"agent broadcast mà UI bỏ qua: {missing}"


def test_every_send_to_agent_uses_is_handled_by_ui():
    """Đối xứng với test broadcast ở trên, cho nhánh trả lời 1 client. Trước
    đây chỉ broadcast được kiểm, nên đổi một lệnh từ broadcast sang send_to là
    tự động rơi ra khỏi lưới kiểm tra wiring."""
    sent = set(re.findall(r'send_to\(\s*\n?\s*client_id,\s*\n?\s*"([a-z_]+)"', AGENT_SRC))
    handled = set(re.findall(r'msg_type == "([a-z_]+)"', UI_SRC))
    for block in re.findall(r'msg_type in \{([^}]+)\}', UI_SRC):
        handled |= set(re.findall(r'"([a-z_]+)"', block))
    assert sent, "không tìm thấy send_to nào"
    missing = sorted(sent - handled)
    assert missing == [], f"agent send_to mà UI bỏ qua: {missing}"


def test_wifi_passwords_are_never_broadcast():
    """PSK plaintext chỉ được trả cho đúng client đã yêu cầu. broadcast sẽ đẩy
    mật khẩu tới mọi UI đang mở socket mà audit log không ghi được ai đã nhận."""
    assert 'broadcast(\n            "wifi_passwords_result"' not in AGENT_SRC
    assert 'broadcast("wifi_passwords_result"' not in AGENT_SRC
    assert re.search(r'send_to\(\s*\n?\s*client_id,\s*\n?\s*"wifi_passwords_result"', AGENT_SRC)


def test_playbook_actions_are_all_runnable():
    """Mọi action_id detector gợi ý phải có nhãn i18n và có nhánh xử lý trong
    _run_playbook_action — nếu không, nút bấm ra thông báo 'không hỗ trợ'."""
    actions: set[str] = set()
    for path in DETECTOR_DIR.glob("*.py"):
        for block in re.findall(r"playbook=\[([^\]]+)\]", path.read_text()):
            actions |= set(re.findall(r'"([a-z_]+)"', block))
    assert actions, "không đọc được playbook nào"

    no_label = sorted(a for a in actions if f"action.{a}" not in STRINGS)
    assert no_label == [], f"action thiếu nhãn i18n: {no_label}"

    handler = UI_SRC[UI_SRC.index("def _run_playbook_action") :]
    handler = handler[: handler.index("\n    def ", 1)]
    no_branch = sorted(a for a in actions if f'"{a}"' not in handler)
    assert no_branch == [], f"action không có nhánh xử lý trong UI: {no_branch}"


# --- 3. bind() không được chạy trước khi widget tồn tại ---


def _tab_bodies() -> dict[str, str]:
    bodies = {}
    matches = list(re.finditer(r"^class (\w+)\(", UI_SRC, re.MULTILINE))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(UI_SRC)
        bodies[m.group(1)] = UI_SRC[m.start() : end]
    return bodies


@pytest.mark.parametrize("cls", sorted(_tab_bodies()))
def test_bound_render_methods_come_after_their_widgets(cls: str):
    """`self.bind(self._render_x)` gọi _render_x ngay lập tức — nếu đặt trước
    dòng tạo bảng mà _render_x đụng tới, app crash lúc khởi động."""
    body = _tab_bodies()[cls]
    for m in re.finditer(r"self\.bind\(self\.(\w+)\)", body):
        method_name, bind_pos = m.group(1), m.start()
        decl = re.search(rf"\n    def {method_name}\(self.*?(?=\n    def |\Z)", body, re.DOTALL)
        if decl is None:
            continue
        for attr in set(re.findall(r"self\.(\w+)\b", decl.group(0))):
            if attr == method_name or attr.startswith("_render"):
                continue
            assign = re.search(rf"self\.{attr}\s*(?::[^=\n]+)?=", body)
            if assign is None:
                continue  # thuộc tính của lớp cha / gán ở nơi khác
            assert assign.start() < bind_pos, (
                f"{cls}: bind({method_name}) ở vị trí {bind_pos} chạy trước khi "
                f"self.{attr} được gán ({assign.start()}) — app sẽ crash lúc mở tab"
            )


def test_every_broadcast_handler_reads_the_payload_not_the_envelope():
    """Agent luôn gói tin thành {"type": ..., "data": {...}}.

    Handler đọc thẳng `msg.get("cái_gì")` sẽ luôn nhận None — không lỗi, không
    cảnh báo, chỉ đơn giản là không bao giờ hiện gì. Sáu tính năng đã từng hỏng
    đúng kiểu này cùng lúc (incidents, isolation, live_stats, agent_problems,
    monitoring_state, watch_status) và mọi test đều xanh, vì test cũ chỉ kiểm
    handler CÓ TỒN TẠI, không kiểm nó đọc đúng chỗ.
    """
    source = UI_SRC
    tree = ast.parse(source)
    lines = source.splitlines()

    dispatch = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "on_message":
            dispatch = node
            break
    assert dispatch is not None, "không tìm thấy on_message"

    body = "\n".join(lines[dispatch.lineno - 1:dispatch.end_lineno])
    # Chỉ `type` được phép đọc ở tầng ngoài; mọi khoá khác phải nằm trong data.
    offenders = sorted({
        name for name in re.findall(r'msg\.get\(\s*["\'](\w+)["\']', body)
        if name not in {"type", "data"}
    })
    assert offenders == [], (
        f"handler đọc sai tầng, phải qua msg[\"data\"]: {offenders}"
    )
    assert 'msg["data"]' in body or 'msg.get("data")' in body


# --- thanh tiêu đề không được nuốt dòng ghi công ---


def test_the_brand_label_can_shrink_without_hard_clipping():
    """`QLabel` thường cắt cứng khi hết chỗ.

    Đo trên giao diện thật ở cửa sổ 1000 px, thanh tiêu đề hiện:

        ZUKEN SHIELD  ver 2.1 Alpha  •  Create

    Cụt giữa chữ, không dấu `…`, không cách nào đọc lại phần mất. Người dùng
    không phân biệt được "hết chỗ" với "phần mềm hỏng".

    Ba điều kiện dưới đây là ba thứ làm nên bản sửa, và thiếu bất kỳ cái nào
    thì lỗi quay lại:

    - `minimumSizeHint` nhỏ hơn `sizeHint`, để bố cục CÓ THỂ co nhãn lại;
    - rút gọn ở GIỮA, để hai đầu — tên sản phẩm và dòng ghi công — còn lại;
    - `Preferred` chứ không `Ignored`: `Ignored` bỏ luôn `sizeHint` nên nhãn
      co về mức tối thiểu ngay cả khi màn hình thừa chỗ.
    """
    tree = ast.parse(UI_SRC)
    cls = next((node for node in ast.walk(tree)
                if isinstance(node, ast.ClassDef) and node.name == "ElidedLabel"), None)
    assert cls is not None, "không còn ElidedLabel — nhãn thương hiệu lại cắt cứng"
    methods = {node.name for node in cls.body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    assert {"minimumSizeHint", "sizeHint", "resizeEvent", "setText"} <= methods, methods
    body = ast.dump(cls)
    assert "ElideMiddle" in body, "rút gọn ở cuối sẽ nuốt đúng dòng ghi công"
    assert "Ignored" not in body, "Ignored làm nhãn co lại kể cả khi thừa chỗ"
    assert "setToolTip" in body, "nguyên văn phải còn đọc lại được"


def test_the_header_brand_uses_the_eliding_label():
    assert 'brand = ElidedLabel(' in UI_SRC, \
        "nhãn thương hiệu quay lại QLabel thường"
    assert "Created by {__creator__}" in UI_SRC
