"""Entrypoint UI — chạy: python -m shield.ui

UI được nhóm thành 4 khu vực Vận hành/Giám sát/Điều tra/Quản trị với tab con
nằm ngang. Màu sắc dùng chung từ `shield.ui.theme`,
chuỗi hiển thị song ngữ VI/EN từ `shield.ui.i18n` — không tab nào tự chế màu
hay chuỗi riêng.

Alert title/detail được ánh xạ qua rule ID tại tầng hiển thị; evidence thô vẫn
được giữ nguyên để không làm sai lệch dữ liệu điều tra. Mọi chuỗi UI tĩnh dùng
bảng VI/EN chung và được regression-test cho cả hai ngôn ngữ.
"""

from __future__ import annotations

import collections
import json
import os
import re
import sys
import sqlite3
import time
from xml.sax.saxutils import escape
from pathlib import Path

from PySide6.QtCore import QProcess, QRect, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QScrollArea,
    QStatusBar,
    QStyledItemDelegate,
    QTableWidget,
    QTextBrowser,
    QTableWidgetItem,
    QTabWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from shield.agent.store import Store
from shield.assessment.exporters import coverage as assessment_coverage
from shield.security.investigations import build_process_graph
from shield.security.diagnostics import export_diagnostic_bundle
from shield import __creator__, __display_version__, __version__
from shield.ui import theme
from shield.ui.client import SocketClient
from shield.ui.evidence_view import (
    event_subject,
    event_summary,
    evidence_detail_rows,
)
from shield.ui.incident_view import correlation_reason_rows
from shield.ai import chat_router
from shield.ui import chat_view, report_view

# Nhịp hỏi lại và TRẦN số lần. Suy luận mất ~15–25 giây, nên vài giây một lần
# là đủ; 40 lần (~2 phút) là quá đủ cho một việc đáng lẽ xong sau 25 giây, và
# một vòng hỏi không có trần là một vòng chạy mãi sau khi người dùng đã bỏ đi.
REPORT_POLL_MS = 3000
REPORT_POLL_MAX = 40
from shield.ui.i18n import STRINGS, alert_text, current_lang, error_message, set_lang, t

_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_MAC_PATTERN = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

def action_label(action_id: str) -> str:
    """Nhãn hiển thị cho 1 action_id trong playbook — dịch qua i18n
    (`action.<id>`), rơi về chính action_id nếu chưa có bản dịch (xem
    t() trong shield/ui/i18n.py)."""
    return t(f"action.{action_id}")

ONLINE_WINDOW_S = 300.0  # thiết bị coi là "online" nếu last_seen trong 5 phút gần nhất

# Cổng mồi mặc định cho tarpit — trùng với shield.agent.tarpit.DEFAULT_TARPIT_PORTS.
# Giữ 1 hằng số riêng ở đây (thay vì import module agent.tarpit vào tiến
# trình UI) để UI không kéo theo phụ thuộc asyncio server của agent chỉ để
# lấy 1 danh sách số — agent luôn là nguồn sự thật cho giá trị đang áp dụng
# thật (đọc lại qua broadcast tarpit_status), đây chỉ là giá trị gợi ý ban
# đầu điền sẵn vào ô nhập.
DEFAULT_TARPIT_PORTS = [2222, 4444, 8081, 31337]

DAY_KEYS = ["day.mon", "day.tue", "day.wed", "day.thu", "day.fri", "day.sat", "day.sun"]


def fmt_ts(ts: float) -> str:
    return time.strftime("%H:%M:%S %d/%m", time.localtime(ts))


def _scrollable(widget: QWidget) -> QScrollArea:
    """Bọc 1 tab trong QScrollArea — vài tab (Lưu lượng, Cài đặt) đã chồng
    nhiều mục (đồ thị + bảng giao thức + cấu hình router + bảng router,
    hoặc bảng chặn + lịch quét + dải mạng cấp phép) nên có thể cao hơn màn
    hình. Bọc chung ở đây (thay vì sửa từng tab) để tab nào cũng cuộn được
    nếu sau này lại phình ra thêm, không phải nhớ sửa lại."""
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    for table in widget.findChildren(QTableWidget):
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(34)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    scroll.setWidget(widget)
    return scroll


TAB_MARGIN = 20
TAB_SPACING = 14


def tab_layout(widget: QWidget) -> QVBoxLayout:
    """QVBoxLayout gốc cho 1 tab, với lề/khoảng cách thống nhất.

    Trước đây mỗi tab tự gọi `QVBoxLayout(self)` và ăn giá trị mặc định của
    Qt (lề ~9px, spacing ~6px) — quá chật với các tab dày bảng số liệu, chữ
    dính sát viền và các khối dính nhau. Gom về 1 chỗ để sửa 1 lần là mọi
    tab đổi theo, không phải nhớ chỉnh từng file.
    """
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(TAB_MARGIN, TAB_MARGIN, TAB_MARGIN, TAB_MARGIN)
    layout.setSpacing(TAB_SPACING)
    return layout


def row_layout() -> QHBoxLayout:
    """QHBoxLayout cho 1 hàng nút/ô nhập, khoảng cách rộng hơn mặc định Qt
    (6px) — các nút dính sát nhau vừa xấu vừa dễ bấm nhầm."""
    layout = QHBoxLayout()
    layout.setSpacing(10)
    return layout


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class I18nMixin:
    """Mọi tab kế thừa để đăng ký widget cần dịch lại khi đổi ngôn ngữ.

    `bind(refresh_fn)` chạy `refresh_fn` ngay (để set text lần đầu) và lưu
    lại để `retranslate()` gọi lại mỗi khi người dùng đổi ngôn ngữ ở Cài đặt
    — tránh phải rebuild lại toàn bộ widget mỗi lần đổi.
    """

    def _init_i18n(self) -> None:
        self._i18n_refreshers: list = []

    def bind(self, refresh_fn) -> None:
        refresh_fn()
        self._i18n_refreshers.append(refresh_fn)

    def retranslate(self) -> None:
        for fn in self._i18n_refreshers:
            fn()


def make_tile(accent: str | None = None) -> tuple[QFrame, QLabel, QLabel]:
    """1 ô số liệu (Tổng quan/Tự kiểm tra/Báo cáo) — label mờ phía trên, số
    lớn phía dưới. `accent` tô màu số theo severity/status nếu có. Text của
    label do caller `bind()` riêng (i18n) — hàm này chỉ dựng khung."""
    frame = QFrame()
    frame.setObjectName("tile")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(14, 12, 14, 12)
    label = QLabel()
    label.setObjectName("tileLabel")
    value = QLabel()
    value.setObjectName("tileValue")
    if accent:
        value.setStyleSheet(f"color: {accent};")
    layout.addWidget(label)
    layout.addWidget(value)
    return frame, label, value


class SeverityStripeDelegate(QStyledItemDelegate):
    """Vẽ 1 sọc màu 3px bên trái cột đầu tiên theo severity — tương đương
    `border-left` trong mockup HTML. Chỉ cột 0 (Thời gian) mới vẽ sọc."""

    def __init__(self, color_col: int = 0, parent=None) -> None:
        super().__init__(parent)
        self.color_col = color_col

    def paint(self, painter: QPainter, option, index) -> None:
        super().paint(painter, option, index)
        if index.column() != self.color_col:
            return
        alert = index.data(Qt.ItemDataRole.UserRole)
        if not alert:
            return
        color = theme.SEVERITY_COLOR.get(alert.get("severity"))
        if not color or alert.get("severity") == "info":
            return
        painter.save()
        painter.fillRect(QRect(option.rect.left(), option.rect.top(), 3, option.rect.height()), QColor(color))
        painter.restore()


def _translated(key, params, fallback: str | None) -> str:
    """Dịch từ khoá nếu có, ngược lại dùng câu sẵn.

    Producer tất định của Shield sinh ra KHOÁ nên dịch được sang mọi ngôn ngữ.
    Một model ngôn ngữ thì không: nó sinh câu, và câu đó ở đúng một ngôn ngữ.
    Phương án cuối là hiện nguyên câu — thà một câu sai ngôn ngữ còn hơn một ô
    trống, nhưng khác biệt đó phải nhìn thấy được chứ không bị che đi.
    """
    if key and str(key) in STRINGS:
        try:
            return t(str(key), **(params or {}))
        except (KeyError, IndexError, ValueError):
            # Thiếu một tham số chỉ ở một ngôn ngữ là lỗi chỉ người dùng ngôn
            # ngữ đó gặp. Rơi về câu sẵn thay vì đổ cả bảng.
            return str(fallback or key)
    return str(fallback or "")


class IncidentsTab(QWidget, I18nMixin):
    """Incident-centric view: group related alerts by subject."""

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.client = socket_client
        # Gán TRƯỚC mọi self.bind: bind chạy hàm dịch ngay lập tức.
        self._investigation: dict | None = None
        layout = tab_layout(self)
        title = QLabel()
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: title.setText(t("nav.incidents")))
        layout.addWidget(title)
        subtitle = QLabel()
        subtitle.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: subtitle.setText(t("incidents.sub")))
        layout.addWidget(subtitle)
        # Bảng trên: incident THẬT do correlation engine ghép (mục B5) — một
        # sự việc có id, mức rủi ro, kỹ thuật MITRE và hành động khuyến nghị.
        # Bảng dưới: alert gom theo đối tượng, giữ nguyên như trước, cho những
        # gì chưa đủ điều kiện thành incident.
        correlated_title = QLabel()
        correlated_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: correlated_title.setText(t("incidents.correlated_title")))
        layout.addWidget(correlated_title)
        self.incident_table = QTableWidget(0, 6)
        self.bind(lambda: self.incident_table.setHorizontalHeaderLabels([
            t("incidents.col_title"), t("incidents.col_subject"), t("incidents.col_risk"),
            t("incidents.col_state"), t("incidents.col_mitre"), t("incidents.col_action"),
        ]))
        self.incident_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.incident_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.incident_table)

        incident_action_row = row_layout()
        self.incident_state_combo = QComboBox()
        for state in ("open", "investigating", "contained", "resolved", "false_positive"):
            self.incident_state_combo.addItem(t(f"incidents.state.{state}"), state)
        self.bind(self._retranslate_incident_states)
        incident_action_row.addWidget(self.incident_state_combo)
        incident_state_btn = QPushButton()
        self.bind(lambda: incident_state_btn.setText(t("incidents.set_state")))
        incident_state_btn.clicked.connect(self._set_incident_state)
        incident_action_row.addWidget(incident_state_btn)
        incident_action_row.addStretch(1)
        layout.addLayout(incident_action_row)

        # --- Vì sao đây là một sự việc (Phase 1 v10) ---
        # Mở rộng tab đã có, KHÔNG dựng màn hình incident thứ hai: nó đọc cùng
        # `self.store` như bảng phía trên, không có đường dữ liệu riêng.
        reasons_title = QLabel()
        reasons_title.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 10px;")
        self.bind(lambda: reasons_title.setText(t("incidents.reasons_title")))
        layout.addWidget(reasons_title)
        self.reason_table = QTableWidget(0, 2)
        self.reason_table.horizontalHeader().setVisible(False)
        self.reason_table.verticalHeader().setVisible(False)
        self.reason_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        self.reason_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.reason_table.setMaximumHeight(220)
        layout.addWidget(self.reason_table)
        self.incident_table.itemSelectionChanged.connect(self._render_reasons)
        self.bind(self._render_reasons)

        # --- Phân tích điều tra (kế hoạch 2.0 mục 2.5) ---
        # Bố cục ở đây là một quyết định về sự trung thực, không phải về thẩm mỹ.
        # Bốn thứ dưới đây có mức đáng tin KHÁC HẲN nhau và phải nhìn thấy khác
        # nhau: sự kiện quan sát được, phát hiện của detector, giả thuyết của
        # phân tích, và bằng chứng ủng hộ/mâu thuẫn. Trộn chúng vào một khối
        # văn xuôi là cách nhanh nhất để một suy đoán được đọc như một sự thật.
        ai_title = QLabel()
        ai_title.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 10px;")
        self.bind(lambda: ai_title.setText(t("ai.title")))
        layout.addWidget(ai_title)

        ai_row = row_layout()
        self.ai_run_btn = QPushButton()
        self.bind(lambda: self.ai_run_btn.setText(t("ai.run")))
        self.ai_run_btn.clicked.connect(self._run_investigation)
        ai_row.addWidget(self.ai_run_btn)
        self.ai_provider_label = QLabel()
        self.ai_provider_label.setObjectName("pageDescription")
        ai_row.addWidget(self.ai_provider_label, 1)
        layout.addLayout(ai_row)

        kill_row = row_layout()
        self.ai_kill_switch = QCheckBox()
        self.bind(lambda: self.ai_kill_switch.setText(t("ai.kill_switch")))
        self.ai_kill_switch.toggled.connect(self._toggle_ai_kill_switch)
        kill_row.addWidget(self.ai_kill_switch)
        self.ai_kill_state = QLabel()
        kill_row.addWidget(self.ai_kill_state)
        kill_row.addStretch(1)
        layout.addLayout(kill_row)
        self.ai_kill_hint = QLabel()
        self.ai_kill_hint.setWordWrap(True)
        self.ai_kill_hint.setObjectName("pageDescription")
        self.bind(lambda: self.ai_kill_hint.setText(t("ai.kill_switch_hint")))
        layout.addWidget(self.ai_kill_hint)

        self.ai_caveat = QLabel()
        self.ai_caveat.setWordWrap(True)
        self.ai_caveat.setObjectName("pageDescription")
        self.bind(lambda: self.ai_caveat.setText(t("ai.never_confirmed")))
        layout.addWidget(self.ai_caveat)

        # Bật/tắt CÓ CHỦ Ý phần giải thích. Một boolean, không hơn: không chọn
        # model, không sửa đường dẫn, không ô nhập prompt.
        opt_row = row_layout()
        self.ai_opt_in = QCheckBox()
        self.bind(lambda: self.ai_opt_in.setText(t("report.ai.opt_in")))
        self.ai_opt_in.toggled.connect(self._toggle_ai_explanation)
        opt_row.addWidget(self.ai_opt_in)
        self.ai_opt_state = QLabel()
        opt_row.addWidget(self.ai_opt_state)
        opt_row.addStretch(1)
        layout.addLayout(opt_row)
        self.ai_opt_hint = QLabel()
        self.ai_opt_hint.setWordWrap(True)
        self.ai_opt_hint.setObjectName("pageDescription")
        self.bind(lambda: self.ai_opt_hint.setText(t("report.ai.opt_in_hint")))
        layout.addWidget(self.ai_opt_hint)

        self.ai_view = QTextBrowser()
        self.ai_view.setOpenExternalLinks(False)
        self.ai_view.setMinimumHeight(180)
        self.bind(self._render_investigation)
        layout.addWidget(self.ai_view)

        # --- Báo cáo sự cố (Phase 3D) ---
        #
        # Khối RIÊNG bên dưới phần phân tích. Dữ liệu Shield đo được và văn xuôi
        # model đi ra hai danh sách khác nhau từ `report_view`, và ở đây chúng
        # được vẽ thành hai khối có nhãn khác nhau — giao diện không có cách nào
        # nối chúng lại.
        report_title = QLabel()
        report_title.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 10px;")
        self.bind(lambda: report_title.setText(t("report.title")))
        layout.addWidget(report_title)
        self.report_state = QLabel()
        self.report_state.setObjectName("pageDescription")
        self.report_state.setWordWrap(True)
        layout.addWidget(self.report_state)
        self.report_view = QTextBrowser()
        self.report_view.setOpenExternalLinks(False)
        self.report_view.setMinimumHeight(220)
        self.report_view.anchorClicked.connect(self._open_report_evidence)
        self.bind(self._render_report)
        layout.addWidget(self.report_view)

        # --- Hỏi đáp gắn vào sự cố này (Incident Chat v0) ---
        #
        # NẰM DƯỚI báo cáo có chủ ý: báo cáo tất định là thứ có thẩm quyền và
        # nó đọc xong trước. Khối này không có ô lệnh, không chọn model, không
        # chỉnh nhiệt độ, không nút hành động — chỉ một câu hỏi và một câu trả
        # lời đã qua đúng bộ kiểm mà báo cáo dùng.
        chat_title = QLabel()
        chat_title.setObjectName("sectionTitle")
        self.bind(lambda: chat_title.setText(t("chat.title")))
        layout.addWidget(chat_title)
        self.chat_caveat = QLabel()
        self.chat_caveat.setObjectName("pageDescription")
        self.chat_caveat.setWordWrap(True)
        self.bind(lambda: self.chat_caveat.setText(t("chat.subordinate")))
        layout.addWidget(self.chat_caveat)
        self.chat_view = QTextBrowser()
        self.chat_view.setOpenExternalLinks(False)
        self.chat_view.setMinimumHeight(160)
        self.chat_view.anchorClicked.connect(self._open_report_evidence)
        layout.addWidget(self.chat_view)
        self.chat_state = QLabel()
        self.chat_state.setObjectName("pageDescription")
        self.chat_state.setWordWrap(True)
        layout.addWidget(self.chat_state)
        # Nút bấm nhanh = CHÍNH bộ ý định đóng. Người dùng thấy ngay chat trả
        # lời được những gì, thay vì gặp một ô trống gợi ý rằng nó trả lời được
        # mọi thứ — bản mở đã đo được là nó không.
        quick_row = QHBoxLayout()
        self._chat_quick = []
        for code in chat_router.quick_intents():
            button = QPushButton()
            button.setProperty("intentCode", code)
            self.bind(lambda b=button, c=code: b.setText(t(f"chat.intent.{c}")))
            button.clicked.connect(lambda _checked=False, c=code: self._ask_intent(c))
            quick_row.addWidget(button)
            self._chat_quick.append(button)
        quick_row.addStretch(1)
        layout.addLayout(quick_row)
        self.chat_limited = QLabel()
        self.chat_limited.setObjectName("pageDescription")
        self.bind(lambda: self.chat_limited.setText(t("chat.limited_notice")))
        layout.addWidget(self.chat_limited)

        chat_row = QHBoxLayout()
        self.chat_input = QLineEdit()
        self.chat_input.setMaxLength(500)
        self.bind(lambda: self.chat_input.setPlaceholderText(t("chat.placeholder")))
        self.chat_input.returnPressed.connect(self._send_chat)
        chat_row.addWidget(self.chat_input, 1)
        self.chat_ask = QPushButton()
        self.bind(lambda: self.chat_ask.setText(t("chat.ask")))
        self.chat_ask.clicked.connect(self._send_chat)
        chat_row.addWidget(self.chat_ask)
        layout.addLayout(chat_row)
        self._chat = {}
        self._chat_polls = 0
        self._chat_timer = QTimer(self)
        self._chat_timer.setInterval(REPORT_POLL_MS)
        self._chat_timer.timeout.connect(self._poll_chat)
        self.bind(self._render_chat)

        # Hỏi lại khi còn `pending`. Có TRẦN, và dừng hẳn khi có câu trả lời
        # cuối cùng — hỏi mãi một câu đã xong là đốt CPU của chính máy đang
        # được bảo vệ.
        self._report_polls = 0
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(REPORT_POLL_MS)
        self._poll_timer.timeout.connect(self._poll_report)

        grouped_title = QLabel()
        grouped_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: grouped_title.setText(t("incidents.grouped_title")))
        layout.addWidget(grouped_title)
        self.table = QTableWidget(0, 5)
        self.bind(lambda: self.table.setHorizontalHeaderLabels([
            t("incidents.col_subject"), t("incidents.col_risk"), t("incidents.col_count"),
            t("incidents.col_rules"), t("incidents.col_last"),
        ]))
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._details)
        layout.addWidget(self.table)
        self.bind(self.refresh)

    # --- phân tích điều tra ---

    def _selected_incident_id(self) -> str:
        row = self.incident_table.currentRow()
        if row < 0:
            return ""
        item = self.incident_table.item(row, 0)
        return str(item.data(Qt.ItemDataRole.UserRole) or "") if item else ""

    def _toggle_ai_explanation(self, enabled: bool) -> None:
        self.client.send_command({"cmd": "set_ai_explanation", "enabled": bool(enabled)})

    def on_ai_explanation_state(self, data: dict) -> None:
        enabled = bool(data.get("enabled"))
        self.ai_opt_in.blockSignals(True)
        self.ai_opt_in.setChecked(enabled)
        self.ai_opt_in.blockSignals(False)
        configured = str(data.get("provider_configured", "disabled"))
        if configured == "disabled":
            # Quản trị viên chưa cấu hình model nào. Nói thẳng, thay vì để một
            # công tắc bật được mà không làm gì.
            self.ai_opt_in.setEnabled(False)
            self.ai_opt_state.setText(t("report.ai.provider_missing"))
            return
        self.ai_opt_in.setEnabled(True)
        self.ai_opt_state.setText(t("report.ai.opt_in_on") if enabled
                                  else t("report.ai.opt_in_off"))

    def _poll_report(self) -> None:
        """Hỏi lại đúng lệnh đã có. KHÔNG kênh mới, KHÔNG suy luận mới."""
        incident_id = str((self._investigation or {}).get("incident_id", ""))
        state = (self._investigation or {}).get("ai_enrichment") or {}
        if (not incident_id or not report_view.should_poll(state)
                or self._report_polls >= REPORT_POLL_MAX
                or not self.isVisible()):
            self._poll_timer.stop()
            return
        self._report_polls += 1
        self.client.send_command({"cmd": "investigate_incident",
                                  "incident_id": incident_id})

    def _open_report_evidence(self, url) -> None:
        """Mở màn hình Expert Evidence ĐÃ CÓ. Không dựng cái thứ hai."""
        ref = url.toString() if hasattr(url, "toString") else str(url)
        if ref.startswith("evidence:"):
            self.window().open_evidence(ref.removeprefix("evidence:"))

    def _ask_intent(self, code: str) -> None:
        """Bấm nút = gửi CÂU HỎI CHUẨN của ý định đó.

        Gửi câu hỏi chứ không gửi thẳng mã ý định: đường đi của một câu bấm nút
        và một câu gõ tay phải giống hệt nhau, nên bộ ánh xạ tất định được kiểm
        ở cả hai lối vào chứ không chỉ ở lối gõ tay.
        """
        self.chat_input.setText(t(f"chat.question.{code}"))
        self._send_chat()

    def _send_chat(self) -> None:
        """Gửi câu hỏi. KHÔNG chờ model — câu trả lời tới sau qua thăm dò."""
        question = self.chat_input.text().strip()
        incident_id = str((self._investigation or {}).get("incident_id", ""))
        if not question or not incident_id:
            return
        self.chat_input.clear()
        self.client.send_command({"cmd": "chat_send", "incident_id": incident_id,
                                  "question": question,
                                  "locale": current_lang()})

    def _poll_chat(self) -> None:
        self._chat_polls += 1
        incident_id = str((self._investigation or {}).get("incident_id", ""))
        if self._chat_polls > REPORT_POLL_MAX or not incident_id:
            self._chat_timer.stop()
            return
        self.client.send_command({"cmd": "chat_history", "incident_id": incident_id,
                                  "locale": current_lang()})

    def on_chat_state(self, data: dict) -> None:
        current = str((self._investigation or {}).get("incident_id", ""))
        if current and str(data.get("incident_id", "")) != current:
            # Câu trả lời của một sự cố KHÁC. Bỏ qua, không vẽ đè.
            return
        # Phản hồi TỪ CHỐI ("một câu đang được xử lý") không kèm `messages`.
        # Gán đè cả state khi đó sẽ xoá trắng hội thoại đang hiển thị — người
        # dùng gõ thêm một câu và thấy lịch sử biến mất.
        if "messages" in data:
            self._chat = dict(data)
        else:
            merged = dict(self._chat or {})
            merged.update(data)
            self._chat = merged
        self._render_chat()
        if chat_view.should_poll(self._chat):
            if not self._chat_timer.isActive():
                self._chat_polls = 0
                self._chat_timer.start()
        else:
            self._chat_timer.stop()

    def _render_chat(self) -> None:
        """Vẽ hội thoại. Câu hỏi của người, câu trả lời của model, có nhãn."""
        if not hasattr(self, "chat_view"):
            return
        state = self._chat or {}
        self.chat_state.setText(chat_view.status_line(state, t))
        enabled = chat_view.can_ask(state)
        self.chat_input.setEnabled(enabled)
        self.chat_ask.setEnabled(enabled)
        for button in getattr(self, "_chat_quick", []):
            button.setEnabled(enabled)
        muted = theme.SEVERITY_COLOR.get("info", "#888")
        blocks = []
        for turn in chat_view.turns(state):
            blocks.append(f"<p><b>{escape(t('chat.you'))}:</b> "
                          f"{escape(turn['question'])}</p>")
            if turn["status"] == "pending":
                blocks.append(f"<p style='color:{muted}'><i>"
                              f"{escape(t('chat.state.pending'))}</i></p>")
                continue
            if not turn["answer"]:
                blocks.append(f"<p style='color:{muted}'><i>"
                              f"{escape(t('chat.state.failed'))}</i></p>")
                continue
            blocks.append(f"<p style='color:{muted}'><b>{escape(t('chat.ai'))}:</b> "
                          f"<i>{escape(turn['answer'])}</i></p>")
            if turn["limitations"]:
                blocks.append(f"<p style='color:{muted}'><i>"
                              f"{escape(t('chat.limitations'))}: "
                              f"{escape(turn['limitations'])}</i></p>")
            if turn["refs"]:
                links = " ".join(
                    f"<a href='evidence:{escape(ref)}'>{escape(ref[:12])}</a>"
                    for ref in turn["refs"])
                blocks.append(f"<p style='color:{muted}'>"
                              f"{escape(t('chat.evidence'))}: {links}</p>")
        self.chat_view.setHtml("".join(blocks))

    def _render_report(self) -> None:
        """Vẽ báo cáo: khối TẤT ĐỊNH trước, khối AI sau và phụ."""
        if not hasattr(self, "report_view"):
            return
        data = self._investigation or {}
        report = data.get("incident_report") or {}
        state = data.get("ai_enrichment") or {}
        self.report_state.setText(report_view.status_line(state, t) if state else "")

        if not report:
            self.report_view.setPlainText(t("report.empty"))
            return

        rows = report_view.deterministic_rows(report, t, self._format_ts)
        blocks = [f"<h4>{escape(t('report.deterministic_title'))}</h4>"]
        current = ""
        for label_key, value, section in rows:
            if section != current:
                current = section
                blocks.append(
                    f"<p style='margin-top:8px'><b>"
                    f"{escape(t(f'report.section.{section}'))}</b></p>")
            label = t(label_key) if label_key in STRINGS else label_key
            if label_key == "report.evidence_ref" and value:
                blocks.append(f"<p>{escape(label)}: "
                              f"<a href='evidence:{escape(value)}'>{escape(value)}</a></p>")
            else:
                blocks.append(f"<p>{escape(label)}"
                              + (f": {escape(value)}" if value else "") + "</p>")

        ai = report_view.ai_rows(report, state, t)
        if ai:
            # Nhãn nói rõ đây là văn do model viết, và nói rõ báo cáo phía trên
            # đã đầy đủ mà không cần nó. Khối này KHÔNG được trông giống dữ liệu.
            muted = theme.SEVERITY_COLOR.get("info", "#888")
            blocks.append(f"<hr><h4>{escape(t('report.ai.title'))}</h4>")
            blocks.append(f"<p style='color:{muted}'><i>"
                          f"{escape(t('report.ai.subordinate'))}</i></p>")
            for label_key, text in ai:
                blocks.append(f"<p style='color:{muted}'><b>{escape(t(label_key))}</b>: "
                              f"<i>{escape(text)}</i></p>")
        self.report_view.setHtml("".join(blocks))

    def _format_ts(self, value) -> str:
        try:
            number = float(value or 0)
        except (TypeError, ValueError):
            return "—"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(number)) if number else "—"

    def _toggle_ai_kill_switch(self, enabled: bool) -> None:
        self.client.send_command({"cmd": "set_ai_kill_switch", "enabled": bool(enabled)})

    def on_ai_kill_switch(self, data: dict) -> None:
        killed = bool(data.get("enabled"))
        self.ai_kill_switch.blockSignals(True)
        self.ai_kill_switch.setChecked(killed)
        self.ai_kill_switch.blockSignals(False)
        self.ai_kill_state.setText(t("ai.kill_switch_on") if killed
                                   else t("ai.kill_switch_off"))
        self.ai_kill_state.setStyleSheet(
            f"color: {theme.SEVERITY_COLOR['warning']};" if killed else "")

    def _run_investigation(self) -> None:
        self._report_polls = 0
        incident_id = self._selected_incident_id()
        if not incident_id:
            self._investigation = {"errors": [t("ai.select_first")]}
            self._render_investigation()
            return
        self.client.send_command({"cmd": "investigate_incident", "incident_id": incident_id})

    def on_investigation(self, data: dict) -> None:
        previous = str((self._investigation or {}).get("incident_id", ""))
        self._investigation = data
        if str(data.get("incident_id", "")) != previous:
            self._report_polls = 0
            self._chat_polls = 0
            self._chat = {}
            self._chat_timer.stop()
            if data.get("incident_id"):
                self.client.send_command({"cmd": "chat_open",
                                          "incident_id": str(data["incident_id"]),
                                          "locale": current_lang()})
        self._render_investigation()
        self._render_report()
        state = data.get("ai_enrichment") or {}
        if report_view.should_poll(state) and self._report_polls < REPORT_POLL_MAX:
            self._poll_timer.start()
        else:
            self._poll_timer.stop()

    def _render_investigation(self) -> None:
        """Vẽ kết quả, phân tách theo mức đáng tin.

        Lỗi được hiển thị RÕ chứ không im lặng: gate Phase 2 đòi "invalid
        JSON/schema fail closed và UI hiển thị lỗi rõ ràng". Một ô trống khi
        phân tích hỏng khiến người dùng tưởng không có gì đáng chú ý.
        """
        if not hasattr(self, "ai_view"):
            return
        data = self._investigation
        if not data:
            self.ai_view.setPlainText(t("ai.no_result"))
            self.ai_provider_label.setText("")
            return

        blocks: list[str] = []
        errors = data.get("errors") or []
        if errors:
            colour = theme.SEVERITY_COLOR["critical"]
            for reason in errors:
                blocks.append(
                    f'<p style="color:{colour}"><b>'
                    + escape(t("ai.error", reason=str(reason))) + "</b></p>")

        provider = str(data.get("provider") or "")
        if provider == "disabled":
            blocks.append(f"<p><i>{escape(t('ai.disabled'))}</i></p>")
        if provider:
            when = time.strftime("%H:%M:%S", time.localtime(data.get("analysed_ts") or time.time()))
            self.ai_provider_label.setText(t("ai.provider", provider=provider,
                                             model=data.get("model", "?"), when=when))

        summary = _translated(data.get("summary_key"), data.get("summary_params"),
                              data.get("summary"))
        if summary:
            blocks.append(f"<p>{escape(summary)}</p>")

        hypotheses = data.get("hypotheses") or []
        blocks.append(f"<h4>{escape(t('ai.section_hypotheses'))}</h4>")
        if not hypotheses:
            blocks.append(f"<p><i>{escape(t('ai.no_hypotheses'))}</i></p>")
        for item in hypotheses:
            status = str(item.get("status", "unconfirmed"))
            label = t(f"ai.status_{status}") if f"ai.status_{status}" in STRINGS else status
            statement = _translated(item.get("statement_key"), item.get("statement_params"),
                                    item.get("statement"))
            blocks.append(
                f"<p><b>{escape(str(item.get('id', '')))}</b> "
                f"[{escape(label)}] {escape(statement)}</p>")
            if item.get("downgrade_reason"):
                blocks.append(
                    f'<p style="color:{theme.SEVERITY_COLOR["warning"]}">&nbsp;&nbsp;'
                    + escape(t("ai.downgraded", reason=str(item["downgrade_reason"])))
                    + "</p>")
            refs = item.get("evidence_refs") or []
            if refs:
                blocks.append(f"<p>&nbsp;&nbsp;{escape(t('ai.section_supporting'))}: "
                              + escape(", ".join(str(r) for r in refs[:8])) + "</p>")
            missing_keys = item.get("missing_evidence_keys") or []
            missing = [_translated(key, {}, "") for key in missing_keys] \
                if missing_keys else list(item.get("missing_evidence") or [])
            against = list(item.get("contradicting_evidence_refs") or []) + missing
            if against:
                blocks.append(f"<p>&nbsp;&nbsp;{escape(t('ai.section_against'))}: "
                              + escape("; ".join(str(a) for a in against[:8])) + "</p>")

        query_keys = data.get("query_keys") or []
        queries = [_translated(key, {}, "") for key in query_keys] \
            if query_keys else (data.get("recommended_queries") or [])
        if queries:
            blocks.append(f"<h4>{escape(t('ai.section_next'))}</h4><ul>"
                          + "".join(f"<li>{escape(str(q))}</li>" for q in queries[:10])
                          + "</ul>")
        actions = data.get("recommended_actions") or []
        if actions:
            blocks.append(f"<h4>{escape(t('ai.section_actions'))}</h4><ul>"
                          + "".join(f"<li>{escape(str(a))}</li>" for a in actions[:10])
                          + "</ul>")

        validation = data.get("validation") or {}
        if validation.get("checked"):
            blocks.append("<p><i>" + escape(t(
                "ai.validator", checked=validation.get("checked", 0),
                downgraded=validation.get("downgraded", 0))) + "</i></p>")
            if validation.get("unknown_refs"):
                blocks.append('<p style="color:' + theme.SEVERITY_COLOR["critical"] + '">'
                              + escape(t("ai.validator_unknown",
                                         count=len(validation["unknown_refs"]))) + "</p>")
            if validation.get("out_of_scope_refs"):
                blocks.append('<p style="color:' + theme.SEVERITY_COLOR["warning"] + '">'
                              + escape(t("ai.validator_scope",
                                         count=len(validation["out_of_scope_refs"]))) + "</p>")

        limitation_keys = data.get("limitation_keys") or []
        limitations = [_translated(key, {}, "") for key in limitation_keys] \
            if limitation_keys else (data.get("limitations") or [])
        if limitations:
            blocks.append("<ul>" + "".join(
                f"<li><i>{escape(str(item))}</i></li>" for item in limitations[:8]) + "</ul>")

        self.ai_view.setHtml("".join(blocks))

    def _retranslate_incident_states(self) -> None:
        for index in range(self.incident_state_combo.count()):
            value = self.incident_state_combo.itemData(index)
            self.incident_state_combo.setItemText(index, t(f"incidents.state.{value}"))

    def _set_incident_state(self) -> None:
        row = self.incident_table.currentRow()
        if row < 0:
            QMessageBox.information(self, t("nav.incidents"), t("incidents.pick_one"))
            return
        item = self.incident_table.item(row, 0)
        incident_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not incident_id:
            return
        self.client.send_command({
            "cmd": "incident_set_state", "incident_id": incident_id,
            "state": self.incident_state_combo.currentData(),
        })

    def on_incidents(self, incidents: list) -> None:
        """Agent đẩy incident mới. Không tự đọc DB ở đây: agent là nơi duy
        nhất biết incident vừa mở, và đọc lại DB sẽ trễ một nhịp."""
        self._render_incidents(incidents)

    def _render_incidents(self, incidents: list | None = None) -> None:
        if incidents is None:
            incidents = self.store.list_incidents(limit=100)
        self.incident_table.setRowCount(0)
        for item in incidents:
            row = self.incident_table.rowCount()
            self.incident_table.insertRow(row)
            score = int(item.get("risk_score", 0))
            values = [
                item.get("title", ""),
                item.get("subject", ""),
                f"{score}/100",
                item.get("state", "open"),
                ", ".join(item.get("mitre_techniques", [])) or "—",
                item.get("recommended_action", "") or "—",
            ]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item.get("incident_id"))
                if col == 2:
                    band = "critical" if score >= 80 else "warning" if score >= 50 else "info"
                    cell.setForeground(QColor(theme.SEVERITY_COLOR[band]))
                self.incident_table.setItem(row, col, cell)

    def _render_reasons(self) -> None:
        """Đọc lý do gộp của sự việc đang chọn. Chỉ hiển thị dữ liệu có cấu
        trúc; không có ô nào ở đây nhận văn xuôi."""
        incident_id = self._selected_incident_id()
        if not incident_id:
            rows = [("incidents.reason.none", "")]
        else:
            rows = correlation_reason_rows(
                self.store.incident_correlation_reasons(incident_id),
                self.store.incident_alert_ids(incident_id),
                t, fmt_ts)
        self.reason_table.setRowCount(0)
        for label_key, value in rows:
            row = self.reason_table.rowCount()
            self.reason_table.insertRow(row)
            label = QTableWidgetItem(t(label_key))
            label.setForeground(QColor(theme.TEXT_DIM))
            self.reason_table.setItem(row, 0, label)
            self.reason_table.setItem(row, 1, QTableWidgetItem(str(value)))

    def refresh(self) -> None:
        self._render_incidents()
        self._render_reasons()
        cutoff = time.time() - 86400
        grouped: dict[str, list[dict]] = collections.defaultdict(list)
        for alert in self.store.recent_alerts(limit=2000):
            if alert["ts"] >= cutoff:
                grouped[alert["subject"]].append(alert)
        incidents = sorted(grouped.items(), key=lambda item: max(a["risk_score"] for a in item[1]), reverse=True)
        self.table.setRowCount(0)
        for subject, alerts in incidents:
            row = self.table.rowCount()
            self.table.insertRow(row)
            peak = max(int(a.get("risk_score", 0)) for a in alerts)
            latest = max(a["ts"] for a in alerts)
            rules = sorted({a["rule_id"] for a in alerts})
            values = [subject, f"{peak}/100", str(sum(int(a.get("count", 1)) for a in alerts)), ", ".join(rules), fmt_ts(latest)]
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, alerts)
                if col == 1:
                    band = "critical" if peak >= 80 else "warning" if peak >= 50 else "info"
                    item.setForeground(QColor(theme.SEVERITY_COLOR[band]))
                self.table.setItem(row, col, item)

    def _details(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        alerts = item.data(Qt.ItemDataRole.UserRole) if item else []
        timeline = []
        for alert in sorted(alerts, key=lambda a: a["ts"], reverse=True)[:50]:
            timeline.append(f"{fmt_ts(alert['ts'])}  [{alert.get('risk_score', 0)}/100]  {alert_text(alert)[0]}")
        QMessageBox.information(self, t("nav.incidents"), "\n".join(timeline))


class AlertsTab(QWidget, I18nMixin):
    """Tab Cảnh báo — bảng lọc theo mức/thời gian (mục 4). Sọc màu bên trái
    theo severity (mockup UI/UX) qua `SeverityStripeDelegate`, thay vì chỉ tô
    nền cả dòng cho critical như bản trước — giữ được cả 3 mức đều nhận ra
    được ở cột đầu, không riêng critical.

    Nút "Pin ARP gateway" luôn hiện sẵn. Double-click 1 dòng mở dialog
    playbook (mục 3) dựa vào `alert.playbook`.
    """

    def __init__(self, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.socket_client = socket_client
        self._pending_response: tuple[str, dict] | None = None
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.alerts")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.sub_label.setText(t("alerts.sub")))
        layout.addWidget(self.sub_label)

        actions_row = row_layout()
        self.pin_btn = QPushButton()
        self.bind(lambda: self.pin_btn.setText(t("alerts.pin_gateway")))
        self.pin_btn.clicked.connect(self._on_pin_gateway_clicked)
        actions_row.addWidget(self.pin_btn)
        actions_row.addStretch()
        layout.addLayout(actions_row)

        self.table = QTableWidget(0, 6)
        self.bind(
            lambda: self.table.setHorizontalHeaderLabels(
                [t("alerts.col_time"), t("alerts.col_severity"), t("alerts.col_title"),
                 t("alerts.col_risk"), t("alerts.col_detail"), t("alerts.col_subject")]
            )
        )
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setItemDelegate(SeverityStripeDelegate(color_col=0, parent=self.table))
        self.table.cellDoubleClicked.connect(self._on_row_double_clicked)
        layout.addWidget(self.table)

    def _on_pin_gateway_clicked(self) -> None:
        reply = QMessageBox.question(
            self, t("alerts.confirm_title"), t("alerts.pin_confirm"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "pin_gateway_arp"})

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        item = self.table.item(row, 0)
        alert = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not alert or not alert.get("playbook"):
            QMessageBox.information(self, t("playbook.title"), t("alerts.no_playbook"))
            return
        self._show_playbook_dialog(alert)

    def _show_playbook_dialog(self, alert: dict) -> None:
        subject = alert.get("subject", "")
        title, detail = alert_text(alert)
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        layout = QVBoxLayout(dialog)
        subject_label = QLabel(f"{t('alerts.col_subject')}: {subject}\n\n{detail}")
        subject_label.setWordWrap(True)
        subject_label.setMinimumWidth(420)
        layout.addWidget(subject_label)
        for action_id in alert["playbook"]:
            btn = QPushButton(action_label(action_id))
            btn.clicked.connect(
                lambda _c, a=action_id, s=subject, d=dialog: self._run_playbook_action(a, s, d)
            )
            layout.addWidget(btn)
        evidence = alert.get("evidence") or {}
        if evidence.get("pid") and evidence.get("start_ticks"):
            btn = QPushButton(t("response.preview_stop"))
            btn.clicked.connect(lambda: self._preview_response("stop_process", {"pid": evidence["pid"], "start_ticks": evidence["start_ticks"]}))
            layout.addWidget(btn)
            tree_btn = QPushButton(t("response.preview_stop_tree"))
            tree_btn.clicked.connect(lambda: self._preview_response("stop_process_tree", {"pid": evidence["pid"], "start_ticks": evidence["start_ticks"]}))
            layout.addWidget(tree_btn)
        candidate_path = evidence.get("path") or evidence.get("exe")
        if candidate_path:
            btn = QPushButton(t("response.preview_quarantine"))
            btn.clicked.connect(lambda: self._preview_response("quarantine_file", {"path": candidate_path}))
            layout.addWidget(btn)
        dialog.exec()

    def _preview_response(self, action: str, params: dict) -> None:
        self._pending_response = (action, params)
        self.socket_client.send_command({"cmd": "response_preview", "action": action, "params": params})

    def on_response_result(self, data: dict) -> None:
        if data.get("phase") == "preview" and data.get("ok") and data.get("token") and self._pending_response:
            action, params = self._pending_response
            reply = QMessageBox.question(
                self, t("respqueue.title"), t("response.confirm", message=data.get("message", "")),
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.socket_client.send_command({
                    "cmd": "response_execute", "token": data["token"], "action": action, "params": params,
                })
            self._pending_response = None
        elif data.get("phase") == "execute":
            QMessageBox.information(self, t("respqueue.title"), data.get("message", ""))

    def _run_playbook_action(self, action_id: str, subject: str, dialog: QDialog) -> None:
        is_ip = bool(_IP_PATTERN.match(subject))
        is_mac = bool(_MAC_PATTERN.match(subject))
        cmd: dict | None = None

        if action_id == "block_ip" and is_ip:
            cmd = {"cmd": "block_ip", "ip": subject}
        elif action_id == "block_mac" and is_mac:
            cmd = {"cmd": "block_mac", "mac": subject}
        elif action_id == "start_capture" and is_ip:
            cmd = {"cmd": "watch_device", "ip": subject}
        elif action_id == "trust_device" and is_mac:
            cmd = {"cmd": "trust_device", "mac": subject}
        elif action_id == "snapshot_state":
            cmd = {"cmd": "snapshot_state"}
        elif action_id == "pin_gateway_arp":
            cmd = {"cmd": "pin_gateway_arp"}

        if cmd is None:
            QMessageBox.warning(
                self, t("alerts.confirm_title"),
                f"{action_label(action_id)} / {subject!r}",
            )
            return

        reply = QMessageBox.question(
            self, t("alerts.confirm_title"),
            f"{action_label(action_id)} — {subject}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command(cmd)
            dialog.close()

    def load_from_store(self, store: Store) -> None:
        for row in reversed(store.recent_alerts(limit=200)):
            self.prepend_alert(row)

    def prepend_alert(self, alert: dict) -> None:
        self.table.insertRow(0)
        severity = alert["severity"]
        title, detail = alert_text(alert)
        values = [
            fmt_ts(alert["ts"]),
            t(f"severity.{severity}") if severity in ("info", "warning", "critical") else severity,
            title,
            f"{int(alert.get('risk_score', 0))}/100",
            detail,
            alert["subject"],
        ]
        sev_color = QColor(theme.SEVERITY_COLOR.get(severity, theme.TEXT_DIM))

        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, alert)
            if col == 1:
                item.setForeground(sev_color)
                font = item.font()
                font.setBold(True)
                item.setFont(font)
            if col == 3:
                score = int(alert.get("risk_score", 0))
                band = "critical" if score >= 80 else "warning" if score >= 50 else "info"
                item.setForeground(QColor(theme.SEVERITY_COLOR[band]))
            self.table.setItem(0, col, item)

    def retranslate(self) -> None:  # override: cột title/detail phải dịch lại theo alert_text()
        super().retranslate()
        for row in range(self.table.rowCount()):
            item0 = self.table.item(row, 0)
            alert = item0.data(Qt.ItemDataRole.UserRole) if item0 else None
            if alert is None:
                continue
            title, detail = alert_text(alert)
            self.table.item(row, 2).setText(title)
            self.table.item(row, 4).setText(detail)


class DevicesTab(QWidget, I18nMixin):
    """Explainable profiles for devices actually observed by Shield."""

    audit_requested = Signal(str)

    COLUMN_KEYS = [
        "devices.col_online", "devices.col_status", "devices.col_name", "devices.col_type",
        "devices.col_confidence", "devices.col_ip", "devices.col_mac", "devices.col_vendor",
        "devices.col_risk", "devices.col_last_seen",
    ]

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        self._watching: set[str] = set()
        self._devices: list[dict] = []
        self._selected_id: str | None = None
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.devices")))
        layout.addWidget(self.title_label)

        scan_row = row_layout()
        self.quick_scan_btn = QPushButton()
        self.bind(lambda: self.quick_scan_btn.setText(t("devices.scan_quick")))
        self.bind(lambda: self.quick_scan_btn.setToolTip(t("devices.scan_quick_tip")))
        self.quick_scan_btn.clicked.connect(
            lambda: self.socket_client.send_command({"cmd": "discover_now"})
        )
        self.deep_scan_btn = QPushButton()
        self.bind(lambda: self.deep_scan_btn.setText(t("devices.scan_deep")))
        self.bind(lambda: self.deep_scan_btn.setToolTip(t("devices.scan_deep_tip")))
        self.deep_scan_btn.clicked.connect(
            lambda: self.socket_client.send_command({"cmd": "discover_deep"})
        )
        self.scan_status_label = QLabel()
        self.scan_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        scan_row.addWidget(self.quick_scan_btn)
        scan_row.addWidget(self.deep_scan_btn)
        scan_row.addWidget(self.scan_status_label)
        scan_row.addStretch()
        layout.addLayout(scan_row)

        self.table = QTableWidget(0, len(self.COLUMN_KEYS))
        self.bind(lambda: self.table.setHorizontalHeaderLabels([t(k) for k in self.COLUMN_KEYS]))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setMinimumSectionSize(96)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(250)
        layout.addWidget(self.table)

        self.profile_title = QLabel()
        self.profile_title.setStyleSheet("font-size: 16px; font-weight: 700;")
        self.bind(lambda: self.profile_title.setText(t("devices.profile_title")))
        layout.addWidget(self.profile_title)

        identity_row = row_layout()
        self.identity_label = QLabel(t("devices.select_device"))
        self.identity_label.setWordWrap(True)
        identity_row.addWidget(self.identity_label, 2)
        self.trust_btn = QPushButton()
        self.trust_btn.clicked.connect(self._toggle_trust)
        self.audit_btn = QPushButton()
        self.bind(lambda: self.audit_btn.setText(t("devices.audit_btn")))
        self.audit_btn.clicked.connect(self._audit_selected)
        self.watch_btn = QPushButton()
        self.watch_btn.clicked.connect(self._toggle_watch)
        identity_row.addWidget(self.trust_btn)
        identity_row.addWidget(self.audit_btn)
        identity_row.addWidget(self.watch_btn)
        layout.addLayout(identity_row)

        metadata_row = row_layout()
        self.name_edit = QLineEdit(); self.owner_edit = QLineEdit()
        self.location_edit = QLineEdit(); self.purpose_edit = QLineEdit()
        self.criticality_combo = QComboBox()
        for value in ("Critical", "Important", "Normal", "Low priority"):
            self.criticality_combo.addItem(value, value)
        self.bind(self._translate_criticality)
        for widget, key in (
            (self.name_edit, "devices.name"), (self.owner_edit, "devices.owner"),
            (self.location_edit, "devices.location"), (self.purpose_edit, "devices.purpose"),
        ):
            self.bind(lambda w=widget, k=key: w.setPlaceholderText(t(k)))
            metadata_row.addWidget(widget)
        metadata_row.addWidget(self.criticality_combo)
        self.save_btn = QPushButton()
        self.bind(lambda: self.save_btn.setText(t("devices.save_profile")))
        self.save_btn.clicked.connect(self._save_metadata)
        metadata_row.addWidget(self.save_btn)
        layout.addLayout(metadata_row)

        self.why_label = QLabel()
        self.why_label.setStyleSheet("font-weight: 700;")
        self.bind(lambda: self.why_label.setText(t("devices.why")))
        layout.addWidget(self.why_label)
        self.evidence_table = QTableWidget(0, 3)
        self.bind(lambda: self.evidence_table.setHorizontalHeaderLabels([
            t("devices.evidence_signal"), t("devices.evidence_value"), t("devices.evidence_reason")
        ]))
        self.evidence_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.evidence_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.evidence_table.setMaximumHeight(170)
        layout.addWidget(self.evidence_table)
        self.profile_disclaimer = QLabel()
        self.profile_disclaimer.setWordWrap(True)
        self.profile_disclaimer.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.profile_disclaimer.setText(t("devices.profile_disclaimer")))
        layout.addWidget(self.profile_disclaimer)

        identity_actions = row_layout()
        self.merge_combo = QComboBox(); self.split_combo = QComboBox()
        self.merge_btn = QPushButton(); self.split_btn = QPushButton()
        self.bind(lambda: self.merge_btn.setText(t("devices.merge")))
        self.bind(lambda: self.split_btn.setText(t("devices.split")))
        self.merge_btn.clicked.connect(self._merge_selected)
        self.split_btn.clicked.connect(self._split_selected)
        identity_actions.addWidget(self.merge_combo, 2); identity_actions.addWidget(self.merge_btn)
        identity_actions.addWidget(self.split_combo, 2); identity_actions.addWidget(self.split_btn)
        layout.addLayout(identity_actions)
        self.bind(self.refresh)  # đăng ký để retranslate() rebuild bảng khi đổi ngôn ngữ

    def on_scan_status(self, data: dict) -> None:
        kind, state = data.get("kind"), data.get("state")
        if state == "running":
            key = {
                "deep": "devices.scanning_deep",
                "range": "devices.scanning_range",
            }.get(kind, "devices.scanning_quick")
            self.scan_status_label.setText(t(key))
        else:
            self.scan_status_label.setText("")
            self.refresh()

    def refresh(self) -> None:
        selected_id = self._selected_id
        self._devices = self.store.list_device_identities()
        # Online lên trước: thứ đang hoạt động ngay lúc này mới là thứ cần nhìn,
        # còn thiết bị tắt từ tuần trước thì để dưới.
        cutoff = time.time() - ONLINE_WINDOW_S
        self._devices.sort(key=lambda item: (float(item["last_seen"]) < cutoff,
                                             -float(item["last_seen"])))
        self.table.setRowCount(0)
        for dev in self._devices:
            self._add_row(dev)
        if selected_id:
            for row, dev in enumerate(self._devices):
                if dev["device_id"] == selected_id:
                    self.table.selectRow(row)
                    break
        if self.table.rowCount() and not self.table.selectedItems():
            self.table.selectRow(0)
        if not self._devices:
            self._selected_id = None
            self._show_profile(None)

    def _add_row(self, dev: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        status = t("devices.status_trusted") if dev["trusted"] else t("devices.status_new")
        # Online/offline là câu hỏi đầu tiên người ta hỏi về một thiết bị, và
        # trước đây cột "Trạng thái" chỉ nói tin-cậy/mới nên không trả lời được.
        # Nói bằng CHỮ chứ không chỉ bằng màu: người mù màu, ảnh chụp màn hình
        # đen trắng, và bản in đều mất sạch thông tin nếu chỉ có màu.
        is_online = time.time() - float(dev["last_seen"]) <= ONLINE_WINDOW_S
        online_text = t("devices.online") if is_online else t("devices.offline")
        values = [
            online_text,
            status,
            dev["display_name"],
            t(f"devices.type.{dev['device_type']}"),
            f"{round(float(dev['confidence']) * 100)}%",
            dev["current_ip"] or "",
            dev["current_mac"],
            dev["vendor"] or "—",
            f"{dev['risk_score']}/100",
            fmt_ts(dev["last_seen"]),
        ]
        for col, val in enumerate(values):
            item = QTableWidgetItem(str(val))
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, dev["device_id"])
                item.setForeground(QColor(
                    theme.STATUS_COLOR["ok"] if is_online else theme.TEXT_DIM))
            if col == 1:
                item.setForeground(QColor(
                    theme.STATUS_COLOR["ok"] if dev["trusted"] else theme.TEXT_DIM))
            self.table.setItem(row, col, item)
        self.table.setRowHeight(row, 40)

    def _selected(self) -> dict | None:
        return next((item for item in self._devices if item["device_id"] == self._selected_id), None)

    def _translate_criticality(self) -> None:
        for index in range(self.criticality_combo.count()):
            value = self.criticality_combo.itemData(index)
            self.criticality_combo.setItemText(index, t(f"devices.criticality.{value}"))

    def _on_selection_changed(self) -> None:
        items = self.table.selectedItems()
        if not items:
            return
        self._selected_id = self.table.item(items[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        self._show_profile(self._selected())

    def _show_profile(self, dev: dict | None) -> None:
        enabled = dev is not None
        for widget in (self.name_edit, self.owner_edit, self.location_edit, self.purpose_edit,
                       self.criticality_combo, self.save_btn, self.trust_btn, self.audit_btn,
                       self.watch_btn, self.merge_combo, self.merge_btn, self.split_combo, self.split_btn):
            widget.setEnabled(enabled)
        self.evidence_table.setRowCount(0)
        self.merge_combo.clear(); self.split_combo.clear()
        if not dev:
            self.identity_label.setText(t("devices.select_device"))
            return
        summary = t(
            "devices.identity_summary", id=dev["device_id"], type=t(f"devices.type.{dev['device_type']}"),
            confidence=round(float(dev["confidence"]) * 100), ip=dev["current_ip"] or "—",
            mac=dev["current_mac"] or "—", first=fmt_ts(dev["first_seen"]), last=fmt_ts(dev["last_seen"]),
        )
        # Hồ sơ đầy đủ: bảng trả lời "máy này là gì", phần dưới trả lời những
        # câu hỏi người điều tra hỏi tiếp — nó đã dùng IP nào, mở cổng gì, dính
        # cảnh báo nào. Trước đây phải tự ghép từ ba tab khác nhau mới ra.
        try:
            dossier = self.store.device_dossier(dev["device_id"], ONLINE_WINDOW_S)
        except Exception:  # noqa: BLE001 - hồ sơ hỏng không được làm chết tab
            dossier = None
        if dossier:
            minutes = int(dossier["seen_ago_s"] // 60)
            lines = [
                t("devices.dossier_online") if dossier["online"]
                else t("devices.dossier_offline", minutes=minutes),
                t("devices.dossier_addresses",
                  ips=", ".join(dossier["ip_addresses"]) or "—",
                  macs=len(dossier["macs"]), count=dossier["observation_count"]),
            ]
            if dossier["open_ports"]:
                ports = ", ".join(
                    str(item.get("port", item)) if isinstance(item, dict) else str(item)
                    for item in dossier["open_ports"][:12]
                )
                lines.append(t("devices.dossier_ports", ports=ports))
            if dossier["alert_count"]:
                newest = dossier["alerts"][0]
                lines.append(t("devices.dossier_alerts",
                               count=dossier["alert_count"],
                               severity=t(f"severity.{dossier['worst_severity']}")
                               if dossier["worst_severity"] else "—",
                               latest=fmt_ts(newest["ts"]), rule=newest["rule_id"]))
            else:
                lines.append(t("devices.dossier_no_alerts"))
            summary = summary + "\n" + "\n".join(lines)
        self.identity_label.setText(summary)
        self.name_edit.setText(dev["display_name"]); self.owner_edit.setText(dev["owner_label"])
        self.location_edit.setText(dev["location"]); self.purpose_edit.setText(dev["purpose"])
        index = self.criticality_combo.findData(dev["criticality"])
        self.criticality_combo.setCurrentIndex(max(0, index))
        self.trust_btn.setText(t("devices.untrust_btn") if dev["trusted"] else t("devices.trust_btn"))
        watching = bool(dev["current_ip"] and dev["current_ip"] in self._watching)
        self.watch_btn.setText(t("devices.unwatch_btn") if watching else t("devices.watch_btn"))
        for evidence in dev["profile_evidence"]:
            row = self.evidence_table.rowCount(); self.evidence_table.insertRow(row)
            signal = str(evidence.get("signal", ""))
            reason_key = f"devices.evidence.{signal}"
            for col, value in enumerate((t(reason_key), evidence.get("value", ""), t(reason_key + ".reason"))):
                self.evidence_table.setItem(row, col, QTableWidgetItem(str(value)))
        if not dev["profile_evidence"]:
            self.evidence_table.insertRow(0)
            self.evidence_table.setItem(0, 2, QTableWidgetItem(t("devices.no_evidence")))
        for candidate in self._devices:
            if candidate["device_id"] != dev["device_id"]:
                self.merge_combo.addItem(f"{candidate['display_name']} ({candidate['device_id']})", candidate["device_id"])
        for mac in dev["macs"]:
            self.split_combo.addItem(mac, mac)
        self.merge_btn.setEnabled(self.merge_combo.count() > 0)
        self.split_btn.setEnabled(len(dev["macs"]) > 1)

    def _save_metadata(self) -> None:
        dev = self._selected()
        if not dev:
            return
        self.socket_client.send_command({
            "cmd": "update_device_metadata", "device_id": dev["device_id"],
            "display_name": self.name_edit.text(), "owner_label": self.owner_edit.text(),
            "location": self.location_edit.text(), "purpose": self.purpose_edit.text(),
            "criticality": self.criticality_combo.currentData(),
        })

    def _toggle_trust(self) -> None:
        dev = self._selected()
        if dev and dev["current_mac"]:
            self.socket_client.send_command({"cmd": "untrust_device" if dev["trusted"] else "trust_device", "mac": dev["current_mac"]})

    def _audit_selected(self) -> None:
        dev = self._selected()
        if dev and dev["current_ip"]:
            self.audit_requested.emit(dev["current_ip"])

    def _toggle_watch(self) -> None:
        dev = self._selected()
        if not dev or not dev["current_ip"]:
            return
        ip, mac = dev["current_ip"], dev["current_mac"]
        if ip in self._watching:
            self.socket_client.send_command({"cmd": "unwatch_device", "ip": ip})
            self._watching.discard(ip)
        else:
            self.socket_client.send_command({"cmd": "watch_device", "ip": ip, "mac": mac})
            self._watching.add(ip)
        self._show_profile(dev)

    def _merge_selected(self) -> None:
        dev = self._selected(); secondary = self.merge_combo.currentData()
        if not dev or not secondary:
            return
        if QMessageBox.question(self, t("devices.merge"), t("devices.merge_confirm")) == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "merge_devices", "primary_id": dev["device_id"], "secondary_id": secondary})

    def _split_selected(self) -> None:
        dev = self._selected(); mac = self.split_combo.currentData()
        if not dev or not mac:
            return
        if QMessageBox.question(self, t("devices.split"), t("devices.split_confirm", mac=mac)) == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "split_device", "device_id": dev["device_id"], "mac": mac})


class TrafficTab(QWidget, I18nMixin):
    """Tab Lưu lượng — đồ thị realtime bytes/giây cho host đang theo dõi
    (mục 2.5 kế hoạch, Shield tự sniff), CỘNG thêm bảng lưu lượng TOÀN mạng
    đọc từ router (không phải Shield tự bắt gói — trên mạng switch máy này
    vốn không thấy được traffic của thiết bị khác, xem router_backends.py).
    """

    MAX_POINTS = 60

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        layout = tab_layout(self)
        self.label = QLabel()
        self.label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.label.setText(t("traffic.placeholder")))
        layout.addWidget(self.label)

        self._data: collections.deque = collections.deque(maxlen=self.MAX_POINTS)
        self._current_ip: str | None = None
        self._curve = None

        try:
            # GHIM binding TRƯỚC khi import.
            #
            # `pyqtgraph` tự dò binding Qt và thử theo thứ tự của riêng nó. Trên
            # một máy còn PyQt6 (GPL-3.0) nằm lại, nó sẽ nạp PyQt6 vào cùng tiến
            # trình này — kéo lại đúng phụ thuộc mà cả đợt chuyển sang PySide6
            # vừa gỡ ra, và kéo lại một cách im lặng.
            os.environ.setdefault("PYQTGRAPH_QT_LIB", "PySide6")
            import pyqtgraph as pg

            self.plot_widget = pg.PlotWidget()
            self.plot_widget.setBackground(theme.BG)
            self.bind(lambda: self.plot_widget.setLabel("left", t("traffic.axis_bps"), color=theme.TEXT_DIM))
            self.bind(lambda: self.plot_widget.setLabel("bottom", t("traffic.axis_seconds"), color=theme.TEXT_DIM))
            self.plot_widget.showGrid(x=True, y=True, alpha=0.15)
            self._curve = self.plot_widget.plot(pen=pg.mkPen(color=theme.ACCENT, width=2))
            layout.addWidget(self.plot_widget)
        except ImportError:
            no_pg_label = QLabel()
            self.bind(lambda lbl=no_pg_label: lbl.setText(t("traffic.no_pyqtgraph")))
            layout.addWidget(no_pg_label)

        self._last_traffic: dict | None = None
        self.bind(self._refresh_label)

        # --- Thống kê giao thức (tshark — engine Wireshark) cho host đang
        # theo dõi. Cộng dồn từ lúc bắt đầu theo dõi host đó, reset khi đổi
        # sang theo dõi host khác — không phải rolling window như đồ thị
        # bytes/giây ở trên, vì mục đích là "host này đang nói giao thức
        # gì", không phải tốc độ tức thời. ---
        self.protocols_title = QLabel()
        self.protocols_title.setStyleSheet("font-weight: 700; margin-top: 12px;")
        self.bind(lambda: self.protocols_title.setText(t("traffic.protocols_title")))
        layout.addWidget(self.protocols_title)

        self.protocols_table = QTableWidget(0, 2)
        self.bind(
            lambda: self.protocols_table.setHorizontalHeaderLabels(
                [t("traffic.col_protocol"), t("traffic.col_packets")]
            )
        )
        self.protocols_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.protocols_table.setMinimumHeight(170)
        self.protocols_table.setMaximumHeight(260)
        layout.addWidget(self.protocols_table)
        self._protocol_ip: str | None = None
        self._protocol_counts: dict[str, int] = {}
        self.bind(self._render_protocols)

        # --- Lưu lượng toàn mạng từ router ---
        self.router_title = QLabel()
        self.router_title.setStyleSheet("font-weight: 700; margin-top: 12px;")
        self.bind(lambda: self.router_title.setText(t("router.title")))
        layout.addWidget(self.router_title)

        self.router_desc = QLabel()
        self.router_desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.router_desc.setWordWrap(True)
        self.bind(lambda: self.router_desc.setText(t("router.desc")))
        layout.addWidget(self.router_desc)

        self.router_backend_combo = QComboBox()
        self.bind(self._fill_backend_combo)
        self.router_backend_combo.currentIndexChanged.connect(self._on_backend_type_changed)

        self.router_host_edit = QLineEdit()
        self.bind(lambda: self.router_host_edit.setPlaceholderText(t("router.host_placeholder")))
        self.router_autodetect_btn = QPushButton()
        self.bind(lambda: self.router_autodetect_btn.setText(t("router.auto_detect")))
        self.router_autodetect_btn.clicked.connect(
            lambda: self.socket_client.send_command({"cmd": "detect_gateway_ip_now"})
        )
        self.router_user_edit = QLineEdit()
        self.bind(lambda: self.router_user_edit.setPlaceholderText(t("router.user_placeholder")))
        self.router_key_edit = QLineEdit()
        self.bind(lambda: self.router_key_edit.setPlaceholderText(t("router.key_placeholder")))
        self.router_script_edit = QLineEdit()
        self.bind(lambda: self.router_script_edit.setPlaceholderText(t("router.script_placeholder")))

        cfg_row1 = row_layout()
        cfg_row1.addWidget(self.router_backend_combo)
        cfg_row1.addWidget(self.router_host_edit)
        cfg_row1.addWidget(self.router_autodetect_btn)
        cfg_row1.addWidget(self.router_user_edit)
        layout.addLayout(cfg_row1)
        cfg_row2 = row_layout()
        cfg_row2.addWidget(self.router_key_edit)
        cfg_row2.addWidget(self.router_script_edit)
        layout.addLayout(cfg_row2)

        btn_row = row_layout()
        self.router_save_btn = QPushButton()
        self.bind(lambda: self.router_save_btn.setText(t("router.save")))
        self.router_save_btn.clicked.connect(self._on_save_backend)
        self.router_poll_btn = QPushButton()
        self.bind(lambda: self.router_poll_btn.setText(t("router.poll_now")))
        self.router_poll_btn.clicked.connect(
            lambda: self.socket_client.send_command({"cmd": "poll_router_traffic_now"})
        )
        btn_row.addWidget(self.router_save_btn)
        btn_row.addWidget(self.router_poll_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.router_table = QTableWidget(0, 5)
        self.bind(
            lambda: self.router_table.setHorizontalHeaderLabels(
                [t("router.col_ip"), t("router.col_mac"), t("router.col_rx"),
                 t("router.col_tx"), t("router.col_updated")]
            )
        )
        self.router_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.router_table.verticalHeader().setVisible(False)
        self.router_table.setMinimumHeight(200)
        layout.addWidget(self.router_table)
        self._on_backend_type_changed()

        # bind() gọi hàm NGAY, nên dòng này phải nằm sau khi router_table đã
        # tồn tại. Cần bind (không chỉ gọi 1 lần) vì bảng có dòng placeholder
        # dịch được, phải vẽ lại khi đổi ngôn ngữ.
        self.bind(self._render_router_table)

    _BACKEND_TYPES = ["disabled", "ssh_conntrack", "custom_script"]

    def _fill_backend_combo(self) -> None:
        current = self.router_backend_combo.currentData()
        self.router_backend_combo.blockSignals(True)
        self.router_backend_combo.clear()
        self.router_backend_combo.addItem(t("router.backend_disabled"), "disabled")
        self.router_backend_combo.addItem(t("router.backend_ssh"), "ssh_conntrack")
        self.router_backend_combo.addItem(t("router.backend_script"), "custom_script")
        if current:
            idx = self.router_backend_combo.findData(current)
            if idx >= 0:
                self.router_backend_combo.setCurrentIndex(idx)
        self.router_backend_combo.blockSignals(False)

    def _on_backend_type_changed(self, _index: int = 0) -> None:
        kind = self.router_backend_combo.currentData() or "disabled"
        is_ssh = kind == "ssh_conntrack"
        is_script = kind == "custom_script"
        self.router_host_edit.setVisible(is_ssh)
        self.router_autodetect_btn.setVisible(is_ssh)
        self.router_user_edit.setVisible(is_ssh)
        self.router_key_edit.setVisible(is_ssh)
        self.router_script_edit.setVisible(is_script)

    def _on_save_backend(self) -> None:
        kind = self.router_backend_combo.currentData() or "disabled"
        cmd = {"cmd": "set_router_backend", "backend_type": kind}
        if kind == "ssh_conntrack":
            cmd.update(
                host=self.router_host_edit.text().strip(),
                user=self.router_user_edit.text().strip() or "root",
                key_path=self.router_key_edit.text().strip(),
            )
        elif kind == "custom_script":
            cmd.update(path=self.router_script_edit.text().strip())
        self.socket_client.send_command(cmd)

    def on_gateway_ip_detected(self, data: dict) -> None:
        gw_ip = data.get("gw_ip")
        if gw_ip:
            self.router_host_edit.setText(gw_ip)
        else:
            QMessageBox.warning(self, t("router.title"), t("router.auto_detect_failed"))

    def on_router_backend_error(self, data: dict) -> None:
        QMessageBox.warning(self, t("router.title"), error_message(data))

    def on_router_traffic(self, data: dict) -> None:
        # Ghi vào DB đã xảy ra ở agent trước khi broadcast — UI chỉ cần đọc
        # lại self.store để hiện bảng, nhất quán với mọi bảng khác trong app.
        self._render_router_table()

    def _render_router_table(self) -> None:
        rows = self.store.list_router_traffic()
        self.router_table.setRowCount(0)
        if not rows:
            self.router_table.insertRow(0)
            item = QTableWidgetItem(t("router.no_data"))
            self.router_table.setItem(0, 0, item)
            self.router_table.setSpan(0, 0, 1, 5)
            return
        for r in rows:
            row = self.router_table.rowCount()
            self.router_table.insertRow(row)
            self.router_table.setItem(row, 0, QTableWidgetItem(r["ip"]))
            self.router_table.setItem(row, 1, QTableWidgetItem(r.get("mac") or ""))
            self.router_table.setItem(row, 2, QTableWidgetItem(fmt_bytes(r["rx_bytes"])))
            self.router_table.setItem(row, 3, QTableWidgetItem(fmt_bytes(r["tx_bytes"])))
            self.router_table.setItem(row, 4, QTableWidgetItem(fmt_ts(r["updated_ts"])))

    def on_traffic_protocols(self, data: dict) -> None:
        ip = data.get("ip")
        if ip != self._protocol_ip:
            self._protocol_ip = ip
            self._protocol_counts = {}
        for proto, n in (data.get("counts") or {}).items():
            self._protocol_counts[proto] = self._protocol_counts.get(proto, 0) + n
        self._render_protocols()

    def _render_protocols(self) -> None:
        self.protocols_table.setRowCount(0)
        if not self._protocol_counts:
            self.protocols_table.insertRow(0)
            self.protocols_table.setItem(0, 0, QTableWidgetItem(t("traffic.protocols_none")))
            self.protocols_table.setSpan(0, 0, 1, 2)
            return
        for proto, count in sorted(self._protocol_counts.items(), key=lambda kv: -kv[1]):
            row = self.protocols_table.rowCount()
            self.protocols_table.insertRow(row)
            self.protocols_table.setItem(row, 0, QTableWidgetItem(proto.upper()))
            self.protocols_table.setItem(row, 1, QTableWidgetItem(str(count)))

    def _refresh_label(self) -> None:
        if self._last_traffic is None:
            self.label.setText(t("traffic.placeholder"))
        else:
            self.label.setText(t("traffic.watching_fmt", ip=self._last_traffic["ip"], bps=self._last_traffic["bps"]))

    def on_traffic(self, data: dict) -> None:
        ip = data.get("ip")
        bps = data.get("bytes_per_s", 0)
        if ip != self._current_ip:
            self._current_ip = ip
            self._data.clear()
        self._data.append(bps)
        self._last_traffic = {"ip": ip, "bps": bps}
        self._refresh_label()
        if self._curve is not None:
            self._curve.setData(list(self._data))


class LogTab(QWidget, I18nMixin):
    """Tab Log máy — luồng sự kiện từ journal đã lọc.

    Trước đây bảng này KHÔNG có trần: `prepend_event` chèn một dòng cho mỗi
    event journal và không bao giờ xoá dòng nào. Một giao diện mở cả ngày sẽ
    tích luỹ vô hạn — đúng thứ mà mọi hàng đợi khác trong Shield đều có trần
    để tránh.

    Hai con số phải TÁCH BIỆT và không được gộp:

    - `evicted`: dòng bị người xem bỏ vì đầy bảng hoặc vì đang tạm dừng. Đây là
      giới hạn của MÀN HÌNH, dữ liệu vẫn nằm nguyên trong database.
    - telemetry drop (`event_bus.dropped`, trần tốc độ collector): dữ liệu
      KHÔNG BAO GIỜ tồn tại. Đó là mất mát thật.

    Gộp hai cái đó lại là nói với người vận hành rằng Shield đang mất log trong
    khi nó chỉ đang cuộn màn hình.
    """

    MAX_ROWS = 500

    def __init__(self) -> None:
        super().__init__()
        self._init_i18n()
        layout = tab_layout(self)
        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.log")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.sub_label.setText(t("log.sub")))
        layout.addWidget(self.sub_label)

        self.table = QTableWidget(0, 3)
        self.bind(
            lambda: self.table.setHorizontalHeaderLabels(
                [t("log.col_time"), t("log.col_kind"), t("log.col_detail")]
            )
        )
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.paused = False
        self.evicted = 0
        status_row = row_layout()
        self.pause_btn = QPushButton()
        self.pause_btn.setCheckable(True)
        self.pause_btn.toggled.connect(self._toggle_pause)
        self.bind(lambda: self.pause_btn.setText(
            t("log.resume") if self.paused else t("log.pause")))
        status_row.addWidget(self.pause_btn)
        self.status_label = QLabel()
        self.status_label.setObjectName("pageDescription")
        self.bind(self._refresh_status)
        status_row.addWidget(self.status_label, 1)
        layout.addLayout(status_row)

    def _toggle_pause(self, paused: bool) -> None:
        self.paused = bool(paused)
        self.pause_btn.setText(t("log.resume") if self.paused else t("log.pause"))
        self._refresh_status()

    def _refresh_status(self) -> None:
        self.status_label.setText(t("log.viewer_status").format(
            rows=self.table.rowCount(), cap=self.MAX_ROWS, evicted=self.evicted))

    def load_from_store(self, store: Store) -> None:
        for ev in reversed(store.recent_events(source="journal", limit=200)):
            self.prepend_event(ev)

    def prepend_event(self, ev: dict) -> None:
        # Tạm dừng thì BỎ, không xếp hàng. Một hàng đợi "để phát lại khi tiếp
        # tục" là một hàng đợi không giới hạn mang tên khác — và người xem tạm
        # dừng để ĐỌC, không phải để tua lại.
        if self.paused:
            self.evicted += 1
            self._refresh_status()
            return
        self.table.insertRow(0)
        kind_key = f"log.kind.{ev['kind']}"
        kind_vi = t(kind_key) if kind_key in STRINGS else ev["kind"]
        detail = ev["data"].get("message") or str(ev["data"])
        for col, val in enumerate([fmt_ts(ev["ts"]), kind_vi, detail]):
            item = QTableWidgetItem(str(val))
            if col == 1:
                item.setData(Qt.ItemDataRole.UserRole, ev["kind"])
            self.table.setItem(0, col, item)
        # Trần cứng. Dòng CŨ nhất bị bỏ: khi theo dõi trực tiếp, cái vừa xảy ra
        # mới là cái người ta cần.
        while self.table.rowCount() > self.MAX_ROWS:
            self.table.removeRow(self.table.rowCount() - 1)
            self.evicted += 1
        self._refresh_status()

    def retranslate(self) -> None:  # override: nội dung bảng phải dịch lại theo cột 1
        super().retranslate()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 1)
            if item is None:
                continue
            kind = item.data(Qt.ItemDataRole.UserRole)
            kind_key = f"log.kind.{kind}"
            # Cùng guard như prepend_event(): kind lạ (rule mới, log khác) thì
            # hiện chính tên kind, không hiện chuỗi khoá "log.kind.xxx".
            item.setText(t(kind_key) if kind_key in STRINGS else str(kind))


class EvidenceTab(QWidget, I18nMixin):
    """Đường kiểm chứng độc lập cho chuyên gia.

    Câu hỏi mà tab này tồn tại để trả lời là: *"Tôi không tin kết luận của
    Shield. Cho tôi xem bằng chứng."*

    Ba ràng buộc quyết định toàn bộ thiết kế:

    1. **Không có AI ở bất kỳ bước nào.** Không gọi model, không tóm tắt, không
       lọc bằng suy đoán. Bật `SHIELD_AI_KILL_SWITCH` không đổi gì ở đây — có
       test chứng minh.
    2. **Không có đường đọc thứ hai.** Tab này không mở database và không viết
       một câu SQL nào; nó gửi hai lệnh IPC, và agent trả lời qua
       `EvidenceQueries` — nơi đã có trần cứng, ngân sách thời gian, che bí mật
       bằng bộ luật chung, và nhật ký truy vấn.
    3. **Có trần ở mọi chỗ.** Cửa sổ thời gian bắt buộc, trang có trần, bảng
       trực tiếp có trần dòng. Số dòng bị cuộn khỏi khung được đếm RIÊNG với
       telemetry bị mất — gộp hai cái đó lại là nói rằng Shield đang mất log
       trong khi nó chỉ đang cuộn màn hình.
    """

    MAX_ROWS = 500
    WINDOWS = (("evidence.window.1h", 3600), ("evidence.window.6h", 6 * 3600),
               ("evidence.window.24h", 86400), ("evidence.window.7d", 7 * 86400))

    def __init__(self, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.client = socket_client
        self.live = True
        self.evicted = 0
        self._cursor = ""
        self._rows: list[dict] = []

        layout = tab_layout(self)
        title = QLabel()
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: title.setText(t("nav.evidence")))
        layout.addWidget(title)
        subtitle = QLabel()
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: subtitle.setText(t("evidence.sub")))
        layout.addWidget(subtitle)

        mode_row = row_layout()
        self.live_btn = QPushButton()
        self.live_btn.setCheckable(True)
        self.live_btn.setChecked(True)
        self.live_btn.toggled.connect(self._toggle_live)
        self.bind(lambda: self.live_btn.setText(t("evidence.mode_live")))
        mode_row.addWidget(self.live_btn)
        self.window_combo = QComboBox()
        for key, seconds in self.WINDOWS:
            self.window_combo.addItem(t(key), seconds)
        self.bind(self._retranslate_windows)
        mode_row.addWidget(self.window_combo)
        for name, key in (("kind", "evidence.filter.kind"), ("source", "evidence.filter.source"),
                          ("origin", "evidence.filter.origin"), ("pid", "evidence.filter.pid"),
                          ("ip", "evidence.filter.ip"), ("port", "evidence.filter.port")):
            box = QLineEdit()
            box.setMaximumWidth(120)
            setattr(self, f"_f_{name}", box)
            self.bind(lambda b=box, k=key: b.setPlaceholderText(t(k)))
            mode_row.addWidget(box)
        layout.addLayout(mode_row)

        id_row = row_layout()
        for name, key in (("incident_id", "evidence.filter.incident"),
                          ("alert_id", "evidence.filter.alert"),
                          ("event_id", "evidence.filter.event")):
            box = QLineEdit()
            setattr(self, f"_f_{name}", box)
            self.bind(lambda b=box, k=key: b.setPlaceholderText(t(k)))
            id_row.addWidget(box)
        self.search_btn = QPushButton()
        self.search_btn.clicked.connect(self.search)
        self.bind(lambda: self.search_btn.setText(t("evidence.search")))
        id_row.addWidget(self.search_btn)
        self.more_btn = QPushButton()
        self.more_btn.clicked.connect(lambda: self.search(more=True))
        self.more_btn.setEnabled(False)
        self.bind(lambda: self.more_btn.setText(t("evidence.more")))
        id_row.addWidget(self.more_btn)
        layout.addLayout(id_row)

        self.table = QTableWidget(0, 5)
        self.bind(lambda: self.table.setHorizontalHeaderLabels([
            t("evidence.col_time"), t("evidence.col_kind"), t("evidence.col_source"),
            t("evidence.col_subject"), t("evidence.col_summary")]))
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._open_selected)
        layout.addWidget(self.table, 2)

        self.status_label = QLabel()
        self.status_label.setObjectName("pageDescription")
        self.bind(self._refresh_status)
        layout.addWidget(self.status_label)

        detail_title = QLabel()
        detail_title.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 8px;")
        self.bind(lambda: detail_title.setText(t("evidence.detail_title")))
        layout.addWidget(detail_title)
        self.detail = QTableWidget(0, 2)
        self.detail.horizontalHeader().setVisible(False)
        self.detail.verticalHeader().setVisible(False)
        self.detail.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.detail.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.detail, 1)
        self.bind(self._render_detail_placeholder)

    # --- trực tiếp ---

    def _retranslate_windows(self) -> None:
        for index, (key, _seconds) in enumerate(self.WINDOWS):
            self.window_combo.setItemText(index, t(key))

    def _toggle_live(self, live: bool) -> None:
        self.live = bool(live)
        self._refresh_status()

    def on_event(self, event: dict) -> None:
        """Một event mới từ agent. Bỏ khi đang tắt chế độ trực tiếp — KHÔNG
        xếp hàng: một hàng đợi "để phát lại" là hàng đợi không giới hạn mang
        tên khác."""
        if not self.live:
            self.evicted += 1
            self._refresh_status()
            return
        self._insert(event, at_top=True)
        while self.table.rowCount() > self.MAX_ROWS:
            self.table.removeRow(self.table.rowCount() - 1)
            self._rows.pop()
            self.evicted += 1
        self._refresh_status()

    def _insert(self, event: dict, *, at_top: bool) -> None:
        row = 0 if at_top else self.table.rowCount()
        self.table.insertRow(row)
        self._rows.insert(row, event)
        values = [fmt_ts(event.get("ts", 0)), event.get("kind", ""), event.get("source", ""),
                  event_subject(event), event_summary(event)]
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if col == 0:
                item.setData(Qt.ItemDataRole.UserRole, event.get("event_id", ""))
            self.table.setItem(row, col, item)

    def _refresh_status(self) -> None:
        self.status_label.setText(t("evidence.viewer_status").format(
            rows=self.table.rowCount(), cap=self.MAX_ROWS, evicted=self.evicted))

    # --- tìm kiếm ---

    def search(self, *, more: bool = False) -> None:
        self.live_btn.setChecked(False)
        window = int(self.window_combo.currentData() or 3600)
        now_ts = time.time()
        filters = {}
        for name in ("pid", "ip", "port"):
            value = getattr(self, f"_f_{name}").text().strip()
            if value:
                filters[name] = int(value) if name in ("pid", "port") and value.isdigit() else value
        alert_text = self._f_alert_id.text().strip()
        self.client.send_command({
            "cmd": "expert_search_events",
            "start_time": now_ts - window, "end_time": now_ts,
            "kind": self._f_kind.text().strip(), "source": self._f_source.text().strip(),
            "origin": self._f_origin.text().strip(),
            "event_id": self._f_event_id.text().strip(),
            "incident_id": self._f_incident_id.text().strip(),
            "alert_id": int(alert_text) if alert_text.isdigit() else None,
            "filters": filters, "limit": 100,
            "cursor": self._cursor if more else "",
        })
        if not more:
            self.table.setRowCount(0)
            self._rows.clear()

    def on_search_result(self, payload: dict) -> None:
        for event in payload.get("events", []):
            self._insert(event, at_top=False)
        self._cursor = str(payload.get("next_cursor", ""))
        self.more_btn.setEnabled(bool(self._cursor))
        self.status_label.setText(t("evidence.result_count").format(
            count=self.table.rowCount(),
            window=f"{int(payload.get('window_s', 0)) // 3600}h"))

    # --- chi tiết ---

    def _render_detail_placeholder(self) -> None:
        if self.detail.rowCount() == 0:
            self._render_detail([("evidence.pick_one", "", "identity")])

    def _open_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._rows):
            return
        event_id = self._rows[row].get("event_id", "")
        if event_id:
            self.client.send_command({"cmd": "expert_get_event", "event_id": event_id})
        else:
            self._render_detail(evidence_detail_rows(self._rows[row], t, fmt_ts))

    def open_event(self, event_id: str) -> None:
        """Cửa vào cho màn hình khác. Dùng lại ĐÚNG đường đã có, không dựng
        màn hình bằng chứng thứ hai."""
        event_id = str(event_id or "").strip()
        if event_id:
            self.client.send_command({"cmd": "expert_get_event", "event_id": event_id})

    def on_event_detail(self, payload: dict) -> None:
        self._render_detail(evidence_detail_rows(payload.get("event"), t, fmt_ts))

    def _render_detail(self, rows) -> None:
        self.detail.setRowCount(0)
        current_group = ""
        for label_key, value, group in rows:
            if group != current_group:
                current_group = group
                index = self.detail.rowCount()
                self.detail.insertRow(index)
                header = QTableWidgetItem(t(f"evidence.group.{group}"))
                header.setForeground(QColor(theme.SEVERITY_COLOR["warning"]))
                self.detail.setItem(index, 0, header)
                self.detail.setItem(index, 1, QTableWidgetItem(""))
            index = self.detail.rowCount()
            self.detail.insertRow(index)
            # Nhãn CỐ ĐỊNH đi qua bộ dịch; tên trường của dữ liệu thì KHÔNG —
            # dịch một tên trường bằng chứng là sửa bằng chứng.
            label = t(label_key) if label_key in STRINGS else label_key
            item = QTableWidgetItem(label)
            item.setForeground(QColor(theme.TEXT_DIM))
            self.detail.setItem(index, 0, item)
            self.detail.setItem(index, 1, QTableWidgetItem(str(value)))


class ResponseTab(QWidget, I18nMixin):
    """Hàng đợi phản ứng: việc đang chờ, lịch sử trạng thái, bằng chứng hậu kiểm.

    Tab này tồn tại vì gate Phase 4 đòi "UI hiển thị toàn bộ transition và
    evidence hậu kiểm". Nhưng lý do sâu hơn: một hành động phản ứng là thứ duy
    nhất Shield làm mà ĐỔI trạng thái máy của người khác. Nếu người vận hành
    không xem lại được từng bước — ai duyệt, áp lúc nào, kiểm chứng ra sao, gỡ
    hay chưa — thì họ không có cách nào biết Shield đã làm gì với máy của họ.

    Ba khối, có chủ ý tách rời: BẢNG là hiện tại, LỊCH SỬ là quá khứ, BẰNG CHỨNG
    là thứ máy đọc lại được từ hệ thống thật. Khối thứ ba mới là khối quan
    trọng — hai khối đầu chỉ nói Shield NGHĨ gì.
    """

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.client = socket_client
        self._jobs: list[dict] = []
        self._selected: str = ""
        layout = tab_layout(self)

        title = QLabel()
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: title.setText(t("respqueue.title")))
        layout.addWidget(title)
        subtitle = QLabel()
        subtitle.setWordWrap(True)
        subtitle.setObjectName("pageDescription")
        self.bind(lambda: subtitle.setText(t("response.sub")))
        layout.addWidget(subtitle)

        kill_row = row_layout()
        self.response_kill_switch = QCheckBox()
        self.bind(lambda: self.response_kill_switch.setText(t("response.kill_switch")))
        self.response_kill_switch.toggled.connect(self._toggle_response_kill_switch)
        kill_row.addWidget(self.response_kill_switch)
        self.response_kill_state = QLabel()
        kill_row.addWidget(self.response_kill_state)
        kill_row.addStretch(1)
        layout.addLayout(kill_row)
        self.response_kill_hint = QLabel()
        self.response_kill_hint.setWordWrap(True)
        self.response_kill_hint.setObjectName("pageDescription")
        self.bind(lambda: self.response_kill_hint.setText(t("response.kill_switch_hint")))
        layout.addWidget(self.response_kill_hint)

        self.table = QTableWidget(0, 5)
        self.bind(lambda: self.table.setHorizontalHeaderLabels([
            t("response.col_action"), t("response.col_target"), t("response.col_state"),
            t("response.col_ttl"), t("response.col_updated"),
        ]))
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_selection)
        layout.addWidget(self.table)

        actions = row_layout()
        self.approve_btn = QPushButton()
        self.bind(lambda: self.approve_btn.setText(t("response.approve")))
        self.approve_btn.clicked.connect(self._approve)
        actions.addWidget(self.approve_btn)
        self.deny_btn = QPushButton()
        self.bind(lambda: self.deny_btn.setText(t("response.deny")))
        self.deny_btn.clicked.connect(self._deny)
        actions.addWidget(self.deny_btn)
        self.rollback_btn = QPushButton()
        self.bind(lambda: self.rollback_btn.setText(t("response.rollback")))
        self.rollback_btn.clicked.connect(self._rollback)
        actions.addWidget(self.rollback_btn)
        self.refresh_btn = QPushButton()
        self.bind(lambda: self.refresh_btn.setText(t("response.refresh")))
        self.refresh_btn.clicked.connect(self.refresh)
        actions.addWidget(self.refresh_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        history_title = QLabel()
        history_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: history_title.setText(t("response.history_title")))
        layout.addWidget(history_title)
        self.history_view = QTextBrowser()
        self.history_view.setMinimumHeight(120)
        layout.addWidget(self.history_view)

        verification_title = QLabel()
        verification_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: verification_title.setText(t("response.verification_title")))
        layout.addWidget(verification_title)
        self.verification_view = QTextBrowser()
        self.verification_view.setMinimumHeight(120)
        layout.addWidget(self.verification_view)
        # Bind SAU khi cả hai ô đã tồn tại: `bind` chạy hàm dịch ngay lập tức,
        # và `_render_detail` chạm vào cả history_view lẫn verification_view.
        # Đặt trước thì app đổ ngay lúc mở tab.
        self.bind(self._render_detail)

    # --- dữ liệu ---

    def refresh(self) -> None:
        self.client.send_command({"cmd": "response_jobs_now"})
        self.client.send_command({"cmd": "response_kill_switch_now"})

    def _toggle_response_kill_switch(self, enabled: bool) -> None:
        self.client.send_command({"cmd": "set_response_kill_switch",
                                  "enabled": bool(enabled)})

    def on_kill_switch(self, data: dict) -> None:
        stopped = bool(data.get("enabled"))
        self.response_kill_switch.blockSignals(True)
        self.response_kill_switch.setChecked(stopped)
        self.response_kill_switch.blockSignals(False)
        self.response_kill_state.setText(t("response.kill_switch_on") if stopped
                                         else t("response.kill_switch_off"))
        self.response_kill_state.setStyleSheet(
            f"color: {theme.SEVERITY_COLOR['warning']};" if stopped else "")

    def on_jobs(self, data: dict) -> None:
        self._jobs = list(data.get("jobs") or [])
        self.table.setRowCount(len(self._jobs))
        for row, job in enumerate(self._jobs):
            state = str(job.get("state", ""))
            cells = [
                str(job.get("action", "")),
                json.dumps(job.get("target") or {}, ensure_ascii=False),
                _state_label(state),
                f"{int(job.get('ttl_s', 0))}s" if job.get("ttl_s") else "—",
                time.strftime("%H:%M:%S", time.localtime(job.get("updated_ts") or 0)),
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, job.get("job_id"))
                if column == 2:
                    item.setForeground(QColor(_state_colour(state)))
                self.table.setItem(row, column, item)
        if self._selected:
            self._render_detail()

    def on_job_detail(self, data: dict) -> None:
        self._detail = data
        self._render_detail()

    # --- thao tác ---

    def _selected_job(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._jobs):
            return None
        return self._jobs[row]

    def _on_selection(self) -> None:
        job = self._selected_job()
        self._selected = str(job.get("job_id")) if job else ""
        if self._selected:
            self.client.send_command({"cmd": "response_job_detail", "job_id": self._selected})

    def _approve(self) -> None:
        job = self._selected_job()
        if job is None:
            self.history_view.setPlainText(t("response.select_first"))
            return
        answer = QMessageBox.question(
            self, t("response.approve"),
            t("response.confirm_approve", action=job.get("action", ""),
              target=json.dumps(job.get("target") or {}, ensure_ascii=False),
              ttl=int(job.get("ttl_s", 0))),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.client.send_command({"cmd": "response_approve", "job_id": job["job_id"]})

    def _deny(self) -> None:
        job = self._selected_job()
        if job is None:
            self.history_view.setPlainText(t("response.select_first"))
            return
        self.client.send_command({"cmd": "response_deny", "job_id": job["job_id"]})

    def _rollback(self) -> None:
        job = self._selected_job()
        if job is None:
            self.history_view.setPlainText(t("response.select_first"))
            return
        answer = QMessageBox.question(
            self, t("response.rollback"),
            t("response.confirm_rollback", action=job.get("action", ""),
              target=json.dumps(job.get("target") or {}, ensure_ascii=False)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.client.send_command({"cmd": "response_rollback", "job_id": job["job_id"]})

    # --- vẽ ---

    def _render_detail(self) -> None:
        if not hasattr(self, "history_view"):
            return
        detail = getattr(self, "_detail", None)
        if not detail or not detail.get("transitions"):
            self.history_view.setPlainText(t("response.history_empty"))
            self.verification_view.setPlainText(t("response.verification_empty"))
            return

        rows = []
        for item in detail["transitions"]:
            when = time.strftime("%H:%M:%S", time.localtime(item.get("ts") or 0))
            arrow = f"{_state_label(item.get('from_state', '')) or '—'} → " \
                    f"{_state_label(item.get('to_state', ''))}"
            actor = escape(str(item.get("actor") or ""))
            note = escape(str(item.get("detail") or ""))
            rows.append(f"<tr><td>{when}</td><td>{escape(arrow)}</td>"
                        f"<td>{actor}</td><td>{note}</td></tr>")
        self.history_view.setHtml("<table cellpadding='4'>" + "".join(rows) + "</table>")

        checks = detail.get("verifications") or []
        if not checks:
            self.verification_view.setPlainText(t("response.verification_empty"))
            return
        blocks = []
        for item in checks:
            when = time.strftime("%H:%M:%S", time.localtime(item.get("ts") or 0))
            verified = bool(item.get("verified"))
            colour = theme.ACCENT if verified else theme.SEVERITY_COLOR["critical"]
            label = t("response.verified_yes") if verified else t("response.verified_no")
            blocks.append(f'<p><b>{when}</b> <span style="color:{colour}">'
                          f"{escape(label)}</span></p>")
            observed = item.get("observed") or {}
            if observed:
                blocks.append("<p>" + escape(t(
                    "response.observed",
                    observed=json.dumps(observed, ensure_ascii=False)[:400])) + "</p>")
            reason = _translated(item.get("reason_key"), item.get("reason_params"),
                                 item.get("reason"))
            if reason:
                blocks.append(f"<p>{escape(reason)}</p>")
        self.verification_view.setHtml("".join(blocks))


def _state_label(state: str) -> str:
    key = f"response.state.{state}"
    return t(key) if key in STRINGS else str(state)


def _state_colour(state: str) -> str:
    if state in {"ROLLBACK_FAILED", "VERIFY_FAILED", "APPLY_FAILED"}:
        return theme.SEVERITY_COLOR["critical"]
    if state in {"APPLYING", "APPLIED", "VERIFYING", "ROLLING_BACK", "PROPOSED"}:
        return theme.SEVERITY_COLOR["warning"]
    return theme.ACCENT


class SettingsTab(QWidget, I18nMixin):
    """Tab Cài đặt — danh sách đang chặn + Gỡ chặn, Lịch quét sâu (công cụ
    chủ động), ngôn ngữ hiển thị. Ngưỡng detector/Telegram vẫn qua env/CLI
    (xem README) — chưa có form nhập, để dành đợt sau.
    """

    language_changed = Signal(str)
    appearance_changed = Signal(str)

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        # Gán TRƯỚC bất kỳ self.bind nào: bind chạy hàm dịch ngay lập tức, và
        # một hàm dịch đọc thuộc tính chưa tồn tại sẽ đổ ngay lúc dựng giao diện.
        self._export_directory = ""
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.settings")))
        layout.addWidget(self.title_label)

        # --- Ngôn ngữ ---
        lang_row = row_layout()
        self.lang_label = QLabel()
        self.bind(lambda: self.lang_label.setText(t("settings.language")))
        self.lang_combo = QComboBox()
        self.lang_combo.addItem("English", "en")
        self.lang_combo.addItem("Tiếng Việt", "vi")
        self.lang_combo.setCurrentIndex(0 if current_lang() == "en" else 1)
        self.lang_combo.currentIndexChanged.connect(
            lambda _i: self.language_changed.emit(self.lang_combo.currentData())
        )
        lang_row.addWidget(self.lang_label)
        lang_row.addWidget(self.lang_combo)
        self.appearance_label = QLabel()
        self.bind(lambda: self.appearance_label.setText(t("settings.appearance")))
        self.appearance_combo = QComboBox()
        for mode in ("dark", "light", "contrast"):
            self.appearance_combo.addItem(t(f"settings.appearance_{mode}"), mode)
        self.bind(self._retranslate_appearance)
        self.appearance_combo.currentIndexChanged.connect(
            lambda _i: self.appearance_changed.emit(self.appearance_combo.currentData())
        )
        lang_row.addWidget(self.appearance_label)
        lang_row.addWidget(self.appearance_combo)
        lang_row.addStretch()
        layout.addLayout(lang_row)

        # --- Backup định kỳ (backup trước migration luôn bắt buộc) ---
        backup_title = QLabel()
        backup_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: backup_title.setText(t("settings.backup_title")))
        layout.addWidget(backup_title)
        backup_row = row_layout()
        self.backup_enable = QCheckBox()
        self.bind(lambda: self.backup_enable.setText(t("settings.backup_enable")))
        self.backup_enable.setChecked(self.store.get_baseline("automatic_backup_enabled") != "0")
        self.backup_enable.toggled.connect(self._on_backup_policy_changed)
        backup_row.addWidget(self.backup_enable)
        self.backup_now_btn = QPushButton()
        self.bind(lambda: self.backup_now_btn.setText(t("settings.backup_now")))
        self.backup_now_btn.clicked.connect(lambda: self.socket_client.send_command({"cmd": "backup_now"}))
        backup_row.addWidget(self.backup_now_btn)
        backup_row.addStretch()
        layout.addLayout(backup_row)
        self.backup_status_label = QLabel()
        self.backup_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        last_backup = float(self.store.get_baseline("database_last_backup") or 0)
        self.backup_status_label.setText(
            t("settings.backup_last", time=fmt_ts(last_backup))
            if last_backup else t("settings.backup_never")
        )
        layout.addWidget(self.backup_status_label)

        # --- Làm mới phiên quét ---
        # Danh sách thiết bị chỉ tích thêm, không bao giờ tự bớt: máy này có 101
        # thiết bị trong khi 9 cái online. Phần còn lại là mạng cũ, khách vãng
        # lai và MAC ngẫu nhiên của điện thoại người qua đường — và một danh
        # sách như vậy tự làm mình vô dụng, vì không ai soi 101 dòng tìm cái lạ.
        rescan_title = QLabel()
        rescan_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: rescan_title.setText(t("settings.rescan_title")))
        layout.addWidget(rescan_title)
        self.rescan_hint = QLabel()
        self.rescan_hint.setWordWrap(True)
        self.rescan_hint.setObjectName("pageDescription")
        self.bind(lambda: self.rescan_hint.setText(t("settings.rescan_hint")))
        layout.addWidget(self.rescan_hint)
        rescan_row = row_layout()
        self.rescan_scope = QComboBox()
        self.bind(self._translate_rescan_scope)
        rescan_row.addWidget(self.rescan_scope)
        self.rescan_btn = QPushButton()
        self.bind(lambda: self.rescan_btn.setText(t("settings.rescan_btn")))
        self.rescan_btn.clicked.connect(self._confirm_rescan)
        rescan_row.addWidget(self.rescan_btn)
        rescan_row.addStretch()
        layout.addLayout(rescan_row)

        # --- Xuất log ra thư mục người dùng chọn ---
        # Hai câu hỏi người dùng thật sự có khi bật thứ này: "ghi vào đâu" và
        # "nó ăn mất bao nhiêu đĩa của tôi". Phần dưới trả lời cả hai bằng số
        # THẬT của máy này, không phải bằng một dòng mô tả chung chung.
        export_title = QLabel()
        export_title.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: export_title.setText(t("settings.export_title")))
        layout.addWidget(export_title)
        self.export_hint = QLabel()
        self.export_hint.setWordWrap(True)
        self.export_hint.setObjectName("pageDescription")
        self.bind(lambda: self.export_hint.setText(t("settings.export_hint")))
        layout.addWidget(self.export_hint)

        export_row = row_layout()
        self.export_enable = QCheckBox()
        self.bind(lambda: self.export_enable.setText(t("settings.export_enable")))
        export_row.addWidget(self.export_enable)
        self.export_path_label = QLabel()
        self.export_path_label.setWordWrap(True)
        self.bind(self._refresh_export_path_label)
        export_row.addWidget(self.export_path_label, 1)
        self.export_browse_btn = QPushButton()
        self.bind(lambda: self.export_browse_btn.setText(t("settings.export_browse")))
        self.export_browse_btn.clicked.connect(self._choose_export_folder)
        export_row.addWidget(self.export_browse_btn)
        self.export_open_btn = QPushButton()
        self.bind(lambda: self.export_open_btn.setText(t("settings.export_open")))
        self.export_open_btn.clicked.connect(self._open_export_folder)
        self.export_open_btn.setEnabled(False)
        export_row.addWidget(self.export_open_btn)
        layout.addLayout(export_row)

        quota_row = row_layout()
        self.export_quota_label = QLabel()
        self.bind(lambda: self.export_quota_label.setText(t("settings.export_quota")))
        quota_row.addWidget(self.export_quota_label)
        self.export_quota = QComboBox()
        for megabytes in (256, 512, 1024, 5 * 1024, 10 * 1024, 20 * 1024, 50 * 1024):
            self.export_quota.addItem(fmt_bytes(megabytes * 1024 ** 2), megabytes)
        self.export_quota.setCurrentIndex(2)
        quota_row.addWidget(self.export_quota)
        self.export_events_check = QCheckBox()
        self.export_events_check.setChecked(True)
        self.bind(lambda: self.export_events_check.setText(t("settings.export_events")))
        quota_row.addWidget(self.export_events_check)
        self.export_alerts_check = QCheckBox()
        self.export_alerts_check.setChecked(True)
        self.bind(lambda: self.export_alerts_check.setText(t("settings.export_alerts")))
        quota_row.addWidget(self.export_alerts_check)
        self.export_apply_btn = QPushButton()
        self.bind(lambda: self.export_apply_btn.setText(t("settings.export_apply")))
        self.export_apply_btn.clicked.connect(self._apply_export_settings)
        quota_row.addWidget(self.export_apply_btn)
        quota_row.addStretch()
        layout.addLayout(quota_row)

        self.export_status_label = QLabel()
        self.export_status_label.setWordWrap(True)
        self.bind(lambda: self.export_status_label.setText(t("settings.export_status_off")))
        layout.addWidget(self.export_status_label)
        self.export_note_label = QLabel()
        self.export_note_label.setWordWrap(True)
        self.export_note_label.setObjectName("pageDescription")
        self.bind(lambda: self.export_note_label.setText(
            t("settings.export_full_note") + " " + t("settings.export_unlimited_warning")))
        layout.addWidget(self.export_note_label)

        # --- Đang chặn ---
        self.blocking_label = QLabel()
        self.bind(lambda: self.blocking_label.setText(t("settings.blocking")))
        layout.addWidget(self.blocking_label)

        self.table = QTableWidget(0, 4)
        self.bind(
            lambda: self.table.setHorizontalHeaderLabels(
                [t("settings.col_type"), t("settings.col_value"), t("settings.col_expires"), ""]
            )
        )
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        # --- Lịch quét sâu ---
        self.schedule_label = QLabel()
        self.schedule_label.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: self.schedule_label.setText(t("settings.schedule")))
        layout.addWidget(self.schedule_label)
        self.schedule_desc = QLabel()
        self.schedule_desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.schedule_desc.setWordWrap(True)
        self.bind(lambda: self.schedule_desc.setText(t("settings.schedule_desc")))
        layout.addWidget(self.schedule_desc)

        self.schedule_enable = QCheckBox()
        self.bind(lambda: self.schedule_enable.setText(t("settings.schedule_enable")))
        layout.addWidget(self.schedule_enable)

        days_row = row_layout()
        self.day_checks: list[QCheckBox] = []
        for key in DAY_KEYS:
            cb = QCheckBox()
            self.bind(lambda cb=cb, k=key: cb.setText(t(k)))
            self.day_checks.append(cb)
            days_row.addWidget(cb)
        layout.addLayout(days_row)

        time_row = row_layout()
        self.time_label = QLabel()
        self.bind(lambda: self.time_label.setText(t("settings.schedule_time")))
        self.time_edit = QLineEdit("03:00")
        self.time_edit.setFixedWidth(70)
        self.schedule_save_btn = QPushButton()
        self.bind(lambda: self.schedule_save_btn.setText(t("common.save")))
        self.schedule_save_btn.clicked.connect(self._on_save_schedule)
        time_row.addWidget(self.time_label)
        time_row.addWidget(self.time_edit)
        time_row.addWidget(self.schedule_save_btn)
        time_row.addStretch()
        layout.addLayout(time_row)

        # --- Dải mạng được cấp phép (quét ngoài mạng nhà) ---
        self.range_label = QLabel()
        self.range_label.setStyleSheet("font-weight: 700; margin-top: 8px;")
        self.bind(lambda: self.range_label.setText(t("settings.authorized_ranges")))
        layout.addWidget(self.range_label)

        self.range_desc = QLabel()
        self.range_desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.range_desc.setWordWrap(True)
        self.bind(lambda: self.range_desc.setText(t("settings.authorized_ranges_desc")))
        layout.addWidget(self.range_desc)

        self.range_cidr_edit = QLineEdit()
        self.bind(lambda: self.range_cidr_edit.setPlaceholderText(t("settings.range_cidr_placeholder")))
        self.range_note_edit = QLineEdit()
        self.bind(lambda: self.range_note_edit.setPlaceholderText(t("settings.range_note_placeholder")))
        add_row = row_layout()
        add_row.addWidget(self.range_cidr_edit)
        add_row.addWidget(self.range_note_edit)
        layout.addLayout(add_row)

        confirm_row = row_layout()
        self.range_confirm_check = QCheckBox()
        self.bind(lambda: self.range_confirm_check.setText(t("settings.range_confirm")))
        self.range_add_btn = QPushButton()
        self.bind(lambda: self.range_add_btn.setText(t("settings.range_add")))
        self.range_add_btn.setEnabled(False)
        self.range_confirm_check.toggled.connect(self.range_add_btn.setEnabled)
        self.range_add_btn.clicked.connect(self._on_add_range)
        confirm_row.addWidget(self.range_confirm_check)
        confirm_row.addWidget(self.range_add_btn)
        confirm_row.addStretch()
        layout.addLayout(confirm_row)

        self.range_table = QTableWidget(0, 4)
        self.bind(
            lambda: self.range_table.setHorizontalHeaderLabels(
                [t("settings.range_col_cidr"), t("settings.range_col_note"), "", ""]
            )
        )
        self.range_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.range_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.range_table)

        # --- Né tránh khẩn cấp — đổi MAC + IP liên tục, chỉ bật tay ---
        self._evasion_enabled = False
        self.evasion_title = QLabel()
        self.evasion_title.setStyleSheet(
            f"font-weight: 700; margin-top: 8px; color: {theme.SEVERITY_COLOR['warning']};"
        )
        self.bind(lambda: self.evasion_title.setText(t("settings.evasion_title")))
        layout.addWidget(self.evasion_title)

        self.evasion_desc = QLabel()
        self.evasion_desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.evasion_desc.setWordWrap(True)
        self.bind(lambda: self.evasion_desc.setText(t("settings.evasion_desc")))
        layout.addWidget(self.evasion_desc)

        evasion_row = row_layout()
        self.evasion_interval_label = QLabel()
        self.bind(lambda: self.evasion_interval_label.setText(t("settings.evasion_interval")))
        self.evasion_interval_combo = QComboBox()
        for secs in (20, 30, 60, 120, 300, 600):
            self.evasion_interval_combo.addItem(f"{secs}s", secs)
        self.evasion_interval_combo.setCurrentIndex(2)  # 60s mặc định
        self.evasion_toggle_btn = QPushButton()
        self.bind(self._retranslate_evasion_toggle)
        self.evasion_toggle_btn.clicked.connect(self._on_evasion_toggle)
        evasion_row.addWidget(self.evasion_interval_label)
        evasion_row.addWidget(self.evasion_interval_combo)
        evasion_row.addWidget(self.evasion_toggle_btn)
        evasion_row.addStretch()
        layout.addLayout(evasion_row)

        self.evasion_status_label = QLabel()
        self.evasion_status_label.setWordWrap(True)
        self.evasion_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.evasion_status_label.setText(t("settings.evasion_status_off")))
        layout.addWidget(self.evasion_status_label)

        # --- Tarpit phòng thủ — honeypot thụ động trên cổng mồi, chỉ bật tay ---
        self._tarpit_enabled = False
        self.tarpit_title = QLabel()
        self.tarpit_title.setStyleSheet(
            f"font-weight: 700; margin-top: 8px; color: {theme.SEVERITY_COLOR['warning']};"
        )
        self.bind(lambda: self.tarpit_title.setText(t("settings.tarpit_title")))
        layout.addWidget(self.tarpit_title)

        self.tarpit_desc = QLabel()
        self.tarpit_desc.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.tarpit_desc.setWordWrap(True)
        self.bind(lambda: self.tarpit_desc.setText(t("settings.tarpit_desc")))
        layout.addWidget(self.tarpit_desc)

        tarpit_row = row_layout()
        self.tarpit_ports_label = QLabel()
        self.bind(lambda: self.tarpit_ports_label.setText(t("settings.tarpit_ports")))
        self.tarpit_ports_edit = QLineEdit()
        self.tarpit_ports_edit.setText(",".join(str(p) for p in DEFAULT_TARPIT_PORTS))
        self.tarpit_ports_edit.setMinimumWidth(180)
        self.tarpit_toggle_btn = QPushButton()
        self.bind(self._retranslate_tarpit_toggle)
        self.tarpit_toggle_btn.clicked.connect(self._on_tarpit_toggle)
        tarpit_row.addWidget(self.tarpit_ports_label)
        tarpit_row.addWidget(self.tarpit_ports_edit)
        tarpit_row.addWidget(self.tarpit_toggle_btn)
        tarpit_row.addStretch()
        layout.addLayout(tarpit_row)

        self.tarpit_status_label = QLabel()
        self.tarpit_status_label.setWordWrap(True)
        self.tarpit_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.tarpit_status_label.setText(t("settings.tarpit_status_off")))
        layout.addWidget(self.tarpit_status_label)

        self.tarpit_table = QTableWidget(0, 3)
        self.bind(
            lambda: self.tarpit_table.setHorizontalHeaderLabels(
                [t("settings.tarpit_col_ip"), t("settings.tarpit_col_port"), t("settings.tarpit_col_since")]
            )
        )
        self.tarpit_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tarpit_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tarpit_table.setMaximumHeight(160)
        layout.addWidget(self.tarpit_table)

        layout.addStretch()
        self.bind(self.refresh)  # đăng ký để retranslate() rebuild bảng khi đổi ngôn ngữ

    def _retranslate_appearance(self) -> None:
        for index in range(self.appearance_combo.count()):
            mode = self.appearance_combo.itemData(index)
            self.appearance_combo.setItemText(index, t(f"settings.appearance_{mode}"))

    def _on_save_schedule(self) -> None:
        days = [i for i, cb in enumerate(self.day_checks) if cb.isChecked()]
        run_time = self.time_edit.text().strip()
        if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", run_time):
            QMessageBox.warning(self, t("nav.settings"), "HH:MM")
            return
        self.socket_client.send_command(
            {"cmd": "set_scan_schedule", "enabled": self.schedule_enable.isChecked(), "days": days, "time": run_time}
        )

    def _translate_rescan_scope(self) -> None:
        current = self.rescan_scope.currentData()
        self.rescan_scope.clear()
        for days, key in ((7, "settings.rescan_7d"), (30, "settings.rescan_30d"),
                          (None, "settings.rescan_all")):
            self.rescan_scope.addItem(t(key), days)
        index = self.rescan_scope.findData(current)
        self.rescan_scope.setCurrentIndex(max(0, index))

    def _confirm_rescan(self) -> None:
        days = self.rescan_scope.currentData()
        # Hỏi lại, và nói RÕ cái gì mất cái gì còn. "Bạn có chắc không?" mà
        # không nói hậu quả thì người dùng chỉ học cách bấm Yes theo phản xạ.
        answer = QMessageBox.question(
            self, t("settings.rescan_confirm_title"),
            t("settings.rescan_confirm_all") if days is None
            else t("settings.rescan_confirm_days", days=days),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.socket_client.send_command({
            "cmd": "reset_scan_session",
            "older_than_days": "all" if days is None else days,
        })

    # --- xuất log ---

    def _refresh_export_path_label(self) -> None:
        self.export_path_label.setText(self._export_directory or t("settings.export_none"))

    def _choose_export_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(
            self, t("settings.export_browse"),
            self._export_directory or str(Path.home()),
            QFileDialog.Option.ShowDirsOnly,
        )
        if not chosen:
            return
        self._export_directory = chosen
        self._refresh_export_path_label()
        self.export_enable.setChecked(True)

    def _open_export_folder(self) -> None:
        if not self._export_directory:
            return
        # startDetached: mở trình quản lý file KHÔNG được giữ tiến trình con
        # gắn với Shield — đóng Shield mà cửa sổ file vẫn còn là hành vi đúng.
        QProcess.startDetached("xdg-open", [self._export_directory])

    def _apply_export_settings(self) -> None:
        self.socket_client.send_command({
            "cmd": "set_log_export",
            "enabled": bool(self.export_enable.isChecked()),
            "directory": self._export_directory,
            "max_mb": int(self.export_quota.currentData() or 1024),
            "include_events": bool(self.export_events_check.isChecked()),
            "include_alerts": bool(self.export_alerts_check.isChecked()),
        })

    def on_log_export_status(self, data: dict) -> None:
        """Hiển thị trạng thái thật do agent trả về.

        Giao diện KHÔNG tự đoán trạng thái từ việc người dùng vừa bấm gì: agent
        có thể từ chối thư mục vì lý do chỉ nó biết (quyền, symlink, ổ đầy), và
        một giao diện tự nhận là "đã bật" trong khi agent đang tắt là dạng nói
        dối tệ nhất — người dùng tin là có log và không đi tìm nữa.
        """
        self._export_directory = str(data.get("directory") or "")
        self._refresh_export_path_label()
        self.export_enable.blockSignals(True)
        self.export_enable.setChecked(bool(data.get("enabled")))
        self.export_enable.blockSignals(False)
        self.export_open_btn.setEnabled(bool(self._export_directory))
        quota_mb = int(data.get("max_bytes", 0)) // 1024 ** 2
        index = self.export_quota.findData(quota_mb)
        if index >= 0:
            self.export_quota.setCurrentIndex(index)
        self.export_events_check.setChecked(bool(data.get("include_events", True)))
        self.export_alerts_check.setChecked(bool(data.get("include_alerts", True)))

        code = str(data.get("last_error_code") or "")
        error = str(data.get("last_error") or "")
        if error and not data.get("active"):
            # Dịch từ MÃ. Chuỗi `last_error` của agent luôn là tiếng Việt và
            # chỉ dùng làm phương án cuối cho một mã chưa có bản dịch — hiện
            # thẳng nó ra ở giao diện tiếng Anh là lỗi đã xảy ra một lần.
            key = f"settings.export_err_{code}" if code else ""
            reason = t(key) if key in STRINGS else error or t("settings.export_err_unknown")
            detail = str(data.get("last_error_detail") or "")
            if detail:
                reason = f"{reason} ({detail})"
            self.export_status_label.setText(t("settings.export_error", reason=reason))
            self.export_status_label.setStyleSheet(f"color: {theme.SEVERITY_COLOR['critical']};")
            return
        self.export_status_label.setStyleSheet("")
        if not data.get("active"):
            self.export_status_label.setText(t("settings.export_status_off"))
            return
        lines = [t(
            "settings.export_status_used",
            used=fmt_bytes(int(data.get("used_bytes", 0))),
            quota=fmt_bytes(int(data.get("max_bytes", 0))),
            percent=data.get("used_percent", 0),
            files=int(data.get("file_count", 0)),
        )]
        days = data.get("days_retained_estimate")
        if days:
            lines.append(t("settings.export_status_rate",
                           per_day=fmt_bytes(int(data.get("bytes_per_day_estimate", 0))),
                           days=days))
        else:
            lines.append(t("settings.export_status_rate_unknown"))
        lines.append(t("settings.export_status_free",
                       free=fmt_bytes(int(data.get("disk_free_bytes", 0)))))
        dropped = int(data.get("dropped_lines", 0))
        if dropped:
            lines.append(t("settings.export_status_dropped", count=dropped))
        self.export_status_label.setText(" ".join(lines))

    def _on_backup_policy_changed(self, enabled: bool) -> None:
        self.socket_client.send_command({"cmd": "set_backup_policy", "enabled": bool(enabled)})

    def on_backup_status(self, data: dict) -> None:
        enabled = bool(data.get("enabled", True))
        self.backup_enable.blockSignals(True)
        self.backup_enable.setChecked(enabled)
        self.backup_enable.blockSignals(False)
        if data.get("ok") is False:
            self.backup_status_label.setText(t("settings.backup_failed", error=data.get("error", "")))
            return
        if data.get("path"):
            self.backup_status_label.setText(t("settings.backup_done", path=data["path"]))
        elif data.get("last_backup"):
            self.backup_status_label.setText(t("settings.backup_last", time=fmt_ts(data["last_backup"])))
        else:
            self.backup_status_label.setText(t("settings.backup_never"))

    def refresh(self) -> None:
        self.table.setRowCount(0)
        for b in self.store.list_active_blocks():
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem("IP" if b["kind"] == "ip" else "MAC"))
            self.table.setItem(row, 1, QTableWidgetItem(b["value"]))
            self.table.setItem(row, 2, QTableWidgetItem(fmt_ts(b["expires_ts"])))
            btn = QPushButton(t("settings.unblock"))
            kind, value = b["kind"], b["value"]
            btn.clicked.connect(lambda _c, k=kind, v=value: self._on_unblock_clicked(k, v))
            self.table.setCellWidget(row, 3, btn)
        self._render_ranges()

    def _on_unblock_clicked(self, kind: str, value: str) -> None:
        cmd_name = "unblock_ip" if kind == "ip" else "unblock_mac"
        key = "ip" if kind == "ip" else "mac"
        self.socket_client.send_command({"cmd": cmd_name, key: value})
        self.refresh()

    def _on_add_range(self) -> None:
        cidr = self.range_cidr_edit.text().strip()
        note = self.range_note_edit.text().strip()
        if not cidr or not note:
            return
        self.socket_client.send_command({"cmd": "add_authorized_range", "cidr": cidr, "note": note})
        self.range_cidr_edit.clear()
        self.range_note_edit.clear()
        self.range_confirm_check.setChecked(False)

    def on_authorized_range_error(self, data: dict) -> None:
        QMessageBox.warning(self, t("settings.authorized_ranges"), error_message(data))

    def on_authorized_ranges_updated(self, data: dict) -> None:
        # data["ranges"] tới từ agent, nhưng UI đọc lại chính SQLite của mình
        # (đã ghi ngay trước khi agent broadcast) để nhất quán với cách bảng
        # "Đang chặn" ở trên đọc self.store.list_active_blocks().
        self._render_ranges()

    def _render_ranges(self) -> None:
        self.range_table.setRowCount(0)
        for r in self.store.list_authorized_ranges():
            row = self.range_table.rowCount()
            self.range_table.insertRow(row)
            self.range_table.setItem(row, 0, QTableWidgetItem(r["cidr"]))
            self.range_table.setItem(row, 1, QTableWidgetItem(r["note"]))
            scan_btn = QPushButton(t("settings.range_scan"))
            scan_btn.clicked.connect(lambda _c, cidr=r["cidr"]: self._on_scan_range(cidr))
            self.range_table.setCellWidget(row, 2, scan_btn)
            remove_btn = QPushButton(t("settings.range_remove"))
            remove_btn.clicked.connect(lambda _c, cidr=r["cidr"]: self._on_remove_range(cidr))
            self.range_table.setCellWidget(row, 3, remove_btn)

    def _on_remove_range(self, cidr: str) -> None:
        self.socket_client.send_command({"cmd": "remove_authorized_range", "cidr": cidr})

    def _on_scan_range(self, cidr: str) -> None:
        reply = QMessageBox.question(
            self,
            t("settings.range_scan_confirm_title"),
            t("settings.range_scan_confirm_body", cidr=cidr),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "scan_authorized_range", "cidr": cidr})

    def _retranslate_evasion_toggle(self) -> None:
        self.evasion_toggle_btn.setText(
            t("settings.evasion_turn_off") if self._evasion_enabled else t("settings.evasion_turn_on")
        )

    def _on_evasion_toggle(self) -> None:
        if self._evasion_enabled:
            # Tắt: không cần hỏi lại — chiều an toàn, càng tắt sớm càng tốt.
            self.socket_client.send_command({"cmd": "set_evasion", "enabled": False})
            return

        reply = QMessageBox.warning(
            self,
            t("settings.evasion_confirm_title"),
            t("settings.evasion_confirm_body"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            interval = self.evasion_interval_combo.currentData()
            self.socket_client.send_command(
                {"cmd": "set_evasion", "enabled": True, "interval_s": interval}
            )

    def on_evasion_status(self, data: dict) -> None:
        self._evasion_enabled = bool(data.get("enabled"))
        self._retranslate_evasion_toggle()
        if not self._evasion_enabled:
            self.evasion_status_label.setText(t("settings.evasion_status_off"))
            self.evasion_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
            return
        if data.get("ok") is False:
            self.evasion_status_label.setText(
                t("settings.evasion_status_error", error=error_message(data))
            )
            self.evasion_status_label.setStyleSheet(f"color: {theme.SEVERITY_COLOR['critical']};")
            return
        mac = data.get("mac") or "?"
        ip = data.get("ip") or "?"
        self.evasion_status_label.setText(
            t("settings.evasion_status_on", mac=mac, ip=ip, ts=fmt_ts(data.get("ts", time.time())))
        )
        self.evasion_status_label.setStyleSheet(
            f"color: {theme.SEVERITY_COLOR['warning']}; font-weight: 600;"
        )

    def on_evasion_error(self, data: dict) -> None:
        QMessageBox.warning(self, t("settings.evasion_title"), error_message(data))

    def _retranslate_tarpit_toggle(self) -> None:
        self.tarpit_toggle_btn.setText(
            t("settings.tarpit_turn_off") if self._tarpit_enabled else t("settings.tarpit_turn_on")
        )

    def _on_tarpit_toggle(self) -> None:
        if self._tarpit_enabled:
            self.socket_client.send_command({"cmd": "set_tarpit", "enabled": False})
            return

        reply = QMessageBox.question(
            self,
            t("settings.tarpit_confirm_title"),
            t("settings.tarpit_confirm_body"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        ports = self.tarpit_ports_edit.text().strip()
        self.socket_client.send_command({"cmd": "set_tarpit", "enabled": True, "ports": ports})

    def on_tarpit_status(self, data: dict) -> None:
        self._tarpit_enabled = bool(data.get("enabled"))
        self._retranslate_tarpit_toggle()
        ports = data.get("ports") or []
        conns = data.get("connections") or []

        if not self._tarpit_enabled:
            self.tarpit_status_label.setText(t("settings.tarpit_status_off"))
            self.tarpit_status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        else:
            self.tarpit_status_label.setText(
                t("settings.tarpit_status_on", ports=", ".join(str(p) for p in ports), count=len(conns))
            )
            self.tarpit_status_label.setStyleSheet(
                f"color: {theme.SEVERITY_COLOR['warning']}; font-weight: 600;"
            )

        self.tarpit_table.setRowCount(0)
        for c in conns:
            row = self.tarpit_table.rowCount()
            self.tarpit_table.insertRow(row)
            self.tarpit_table.setItem(row, 0, QTableWidgetItem(c.get("ip", "")))
            self.tarpit_table.setItem(row, 1, QTableWidgetItem(str(c.get("port", ""))))
            self.tarpit_table.setItem(row, 2, QTableWidgetItem(fmt_ts(c.get("since", time.time()))))

    def on_tarpit_connection(self, data: dict) -> None:
        # alert đã được agent phát qua kênh "alert" riêng (Alerts tab lo hiện
        # thị chi tiết) — ở đây chỉ cần dùng sự kiện này để làm mới ngay bảng
        # kết nối đang giữ, không phải đợi tới chu kỳ poll tiếp theo.
        self.socket_client.send_command({"cmd": "tarpit_status_now"})

    def on_tarpit_error(self, data: dict) -> None:
        QMessageBox.warning(self, t("settings.tarpit_title"), error_message(data))


class OverviewTab(QWidget, I18nMixin):
    """Tab Tổng quan — đèn trạng thái lớn, 4 ô số liệu, 5 alert gần nhất.
    Đèn trạng thái suy ra từ 5 alert gần nhất, không toàn lịch sử."""

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        self._ledger_checked_at = 0.0
        self._ledger_status: tuple[bool, int | None, str] = (True, None, "")
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.overview")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.sub_label.setText(t("overview.sub")))
        layout.addWidget(self.sub_label)

        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setMinimumHeight(80)
        layout.addWidget(self.status_label)

        tile_row = row_layout()
        self.tile_devices, self.lbl_devices, self.val_devices = make_tile()
        self.bind(lambda: self.lbl_devices.setText(t("overview.devices_online")))
        self.tile_alerts, self.lbl_alerts, self.val_alerts = make_tile(theme.SEVERITY_COLOR["critical"])
        self.bind(lambda: self.lbl_alerts.setText(t("overview.alerts_24h")))
        self.tile_blocks, self.lbl_blocks, self.val_blocks = make_tile(theme.SEVERITY_COLOR["warning"])
        self.bind(lambda: self.lbl_blocks.setText(t("overview.active_blocks")))
        self.tile_watch, self.lbl_watch, self.val_watch = make_tile(theme.STATUS_COLOR["ok"])
        self.bind(lambda: self.lbl_watch.setText(t("overview.watching")))
        for tile in (self.tile_devices, self.tile_alerts, self.tile_blocks, self.tile_watch):
            tile_row.addWidget(tile)
        layout.addLayout(tile_row)

        # Ô "8 / 101" nói có 8 máy đang online nhưng không có cách nào biết 8
        # cái đó là ai. Một con số không tra ngược được thì không dùng để làm
        # gì; bảng ngay dưới đây liệt kê đúng những máy đang được tính.
        self.online_label = QLabel()
        self.online_label.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 12px;")
        self.bind(lambda: self.online_label.setText(t("overview.online_title")))
        layout.addWidget(self.online_label)
        self.online_table = QTableWidget(0, 5)
        self.bind(lambda: self.online_table.setHorizontalHeaderLabels([
            t("devices.col_online"), t("devices.col_name"), t("devices.col_ip"),
            t("devices.col_mac"), t("devices.col_last_seen"),
        ]))
        self.online_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.online_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.online_table.setMinimumHeight(160)
        self.online_table.setMaximumHeight(260)
        layout.addWidget(self.online_table)
        self.online_note = QLabel()
        self.online_note.setObjectName("pageDescription")
        self.online_note.setWordWrap(True)
        layout.addWidget(self.online_note)

        # --- Số liệu SỐNG (đẩy từ agent mỗi giây) -------------------------
        # Bốn ô trên kia chỉ vẽ lại khi có alert; mạng bình thường cả ngày mới
        # có vài cái nên màn hình đứng yên hàng giờ, dù agent vẫn xử lý vài
        # event mỗi giây. Phần dưới đây là hoạt động thật, theo thời gian thực.
        self.live_label = QLabel()
        self.live_label.setStyleSheet("font-size: 15px; font-weight: 700; margin-top: 12px;")
        self.bind(lambda: self.live_label.setText(t("live.title")))
        layout.addWidget(self.live_label)

        live_row = row_layout()
        self.tile_rate, self.lbl_rate, self.val_rate = make_tile(theme.STATUS_COLOR["ok"])
        self.bind(lambda: self.lbl_rate.setText(t("live.events_per_s")))
        self.tile_total, self.lbl_total, self.val_total = make_tile()
        self.bind(lambda: self.lbl_total.setText(t("live.events_session")))
        self.tile_sources, self.lbl_sources, self.val_sources = make_tile()
        self.bind(lambda: self.lbl_sources.setText(t("live.active_sources")))
        self.tile_uptime, self.lbl_uptime, self.val_uptime = make_tile()
        self.bind(lambda: self.lbl_uptime.setText(t("live.uptime")))
        for tile in (self.tile_rate, self.tile_total, self.tile_sources, self.tile_uptime):
            live_row.addWidget(tile)
        layout.addLayout(live_row)

        self._stale = False
        self._live_series: collections.deque = collections.deque(maxlen=60)
        self._live_curve = None
        try:
            import pyqtgraph as pg

            self.live_plot = pg.PlotWidget()
            self.live_plot.setBackground(theme.BG)
            self.live_plot.setMaximumHeight(140)
            self.live_plot.showGrid(x=True, y=True, alpha=0.15)
            self.bind(lambda: self.live_plot.setLabel("left", t("live.axis_events"), color=theme.TEXT_DIM))
            self.bind(lambda: self.live_plot.setLabel("bottom", t("live.axis_seconds"), color=theme.TEXT_DIM))
            self._live_curve = self.live_plot.plot(pen=pg.mkPen(color=theme.ACCENT, width=2))
            layout.addWidget(self.live_plot)
        except ImportError:
            fallback = QLabel()
            self.bind(lambda lbl=fallback: lbl.setText(t("traffic.no_pyqtgraph")))
            layout.addWidget(fallback)

        live_tables = row_layout()
        source_column = QVBoxLayout()
        self.sources_title = QLabel()
        self.bind(lambda: self.sources_title.setText(t("live.sources_title")))
        source_column.addWidget(self.sources_title)
        self.sources_table = QTableWidget(0, 3)
        self.bind(lambda: self.sources_table.setHorizontalHeaderLabels(
            [t("live.col_source"), t("live.col_per_minute"), t("live.col_last")]))
        self.sources_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.sources_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.sources_table.setMinimumHeight(150)
        source_column.addWidget(self.sources_table)
        live_tables.addLayout(source_column, 1)

        feed_column = QVBoxLayout()
        self.feed_title = QLabel()
        self.bind(lambda: self.feed_title.setText(t("live.feed_title")))
        feed_column.addWidget(self.feed_title)
        self.feed_table = QTableWidget(0, 3)
        self.bind(lambda: self.feed_table.setHorizontalHeaderLabels(
            [t("alerts.col_time"), t("live.col_source"), t("live.col_kind")]))
        self.feed_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.feed_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.feed_table.setMinimumHeight(150)
        feed_column.addWidget(self.feed_table)
        self.feed_note = QLabel()
        self.feed_note.setObjectName("pageDescription")
        feed_column.addWidget(self.feed_note)
        live_tables.addLayout(feed_column, 1)
        layout.addLayout(live_tables)

        self.recent_label = QLabel()
        self.bind(lambda: self.recent_label.setText(t("overview.recent_alerts")))
        layout.addWidget(self.recent_label)
        self.recent_table = QTableWidget(0, 3)
        self.bind(
            lambda: self.recent_table.setHorizontalHeaderLabels(
                [t("alerts.col_time"), t("alerts.col_severity"), t("alerts.col_title")]
            )
        )
        self.recent_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.recent_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.recent_table.setMinimumHeight(180)
        self.recent_table.setMaximumHeight(280)
        layout.addWidget(self.recent_table)
        layout.addStretch()

        self.bind(self.refresh)

    def mark_stale(self, stale: bool) -> None:
        """Agent tắt: nói thẳng là số đã ngừng cập nhật.

        Giữ nguyên "20,6 sự kiện/giây" trên màn hình sau khi agent chết là nói
        dối bằng cách im lặng — người nhìn không có cách nào biết con số đó đã
        đứng từ mười phút trước.
        """
        self._stale = stale
        if stale:
            for value in (self.val_rate, self.val_total, self.val_sources, self.val_uptime):
                value.setText("—")
                value.setStyleSheet(f"color: {theme.TEXT_DIM};")
            if self._live_curve is not None:
                self._live_curve.setData([], [])
            self.sources_table.setRowCount(0)
            self.feed_note.setText(t("live.stopped"))
            self.live_label.setText(t("live.title_stopped"))
        else:
            self.live_label.setText(t("live.title"))
            self.feed_note.setText("")

    def on_live_stats(self, data: dict) -> None:
        """Số liệu sống từ agent, mỗi giây một lượt.

        Không nội suy, không làm mượt: mọi con số ở đây là số đếm thật. Một
        bảng điều khiển bịa số tệ hơn một bảng đứng yên, vì nó khiến người ta
        tin vào cái không có.
        """
        self._stale = False
        self.live_label.setText(t("live.title"))
        paused = bool(data.get("paused"))
        rate = float(data.get("events_per_s", 0.0))
        self.val_rate.setText(t("live.paused_value") if paused else f"{rate:.1f}")
        self.val_rate.setStyleSheet(
            f"color: {theme.TEXT_DIM if paused else theme.STATUS_COLOR['ok']};"
        )
        self.val_total.setText(f"{int(data.get('events_total', 0)):,}")

        sources = data.get("sources") or []
        active = sum(1 for row in sources if row.get("per_minute", 0) > 0)
        self.val_sources.setText(f"{active} / {len(sources)}")

        uptime = int(data.get("uptime_s", 0))
        hours, remainder = divmod(uptime, 3600)
        self.val_uptime.setText(f"{hours}h {remainder // 60}m")

        series = data.get("series") or []
        if self._live_curve is not None and series:
            self._live_curve.setData(list(range(-len(series) + 1, 1)), series)

        self.sources_table.setRowCount(0)
        for row in sorted(sources, key=lambda item: -item.get("per_minute", 0)):
            index = self.sources_table.rowCount()
            self.sources_table.insertRow(index)
            self.sources_table.setItem(index, 0, QTableWidgetItem(str(row.get("source", ""))))
            per_minute = int(row.get("per_minute", 0))
            count_item = QTableWidgetItem(str(per_minute))
            # Collector còn sống mà không sinh event nào trông y hệt một mạng
            # yên tĩnh — tô màu để phân biệt được bằng mắt.
            if per_minute == 0:
                count_item.setForeground(QColor(theme.SEVERITY_COLOR["warning"]))
            self.sources_table.setItem(index, 1, count_item)
            last_ts = float(row.get("last_ts", 0.0))
            self.sources_table.setItem(
                index, 2, QTableWidgetItem(fmt_ts(last_ts) if last_ts else "—"))

        for entry in data.get("feed") or []:
            self.feed_table.insertRow(0)
            self.feed_table.setItem(0, 0, QTableWidgetItem(fmt_ts(entry.get("ts", 0))))
            self.feed_table.setItem(0, 1, QTableWidgetItem(str(entry.get("source", ""))))
            kind = str(entry.get("kind", ""))
            origin = str(entry.get("origin", "local"))
            # Log từ máy khác phải nhìn ra ngay là từ máy khác.
            label = kind if origin == "local" else f"{kind}  ←  {origin}"
            self.feed_table.setItem(0, 2, QTableWidgetItem(label))
        while self.feed_table.rowCount() > 100:
            self.feed_table.removeRow(self.feed_table.rowCount() - 1)

        dropped = int(data.get("feed_dropped", 0))
        # Nói thẳng số dòng không kịp hiện. Cắt bớt trong im lặng là nói dối.
        self.feed_note.setText(t("live.feed_dropped", count=dropped) if dropped else "")

    def refresh(self) -> None:
        alerts = self.store.recent_alerts(limit=5)
        if any(a["severity"] == "critical" for a in alerts):
            status = "alert"
        elif any(a["severity"] == "warning" for a in alerts):
            status = "watching"
        else:
            status = "ok"

        color = theme.STATUS_COLOR[status]
        self.status_label.setText(f"●  {t(f'status.{status}')}")
        self.status_label.setStyleSheet(
            f"font-size: 24px; font-weight: 700; color: {color}; "
            f"background: {theme.BG_ALT}; border-radius: 8px; padding: 20px;"
        )

        now_ts = time.time()
        devices = self.store.list_devices()
        online = sum(1 for d in devices if now_ts - d["last_seen"] <= ONLINE_WINDOW_S)
        alerts_24h = self.store.recent_alerts(limit=500)
        alerts_24h_count = sum(1 for a in alerts_24h if now_ts - a["ts"] <= 86400)
        blocks = self.store.list_active_blocks()

        # Chữ "online" nằm ngay cạnh con số: "8 / 101" một mình không nói được
        # 8 là cái gì trong 101.
        self.val_devices.setText(
            t("overview.devices_value", online=online, total=len(devices)))

        online_devices = sorted(
            (device for device in devices if now_ts - device["last_seen"] <= ONLINE_WINDOW_S),
            key=lambda device: -device["last_seen"],
        )
        self.online_table.setRowCount(0)
        for device in online_devices:
            row = self.online_table.rowCount()
            self.online_table.insertRow(row)
            online_item = QTableWidgetItem(t("devices.online"))
            online_item.setForeground(QColor(theme.STATUS_COLOR["ok"]))
            self.online_table.setItem(row, 0, online_item)
            name = device.get("hostname") or device.get("vendor") or t("devices.unknown_name")
            self.online_table.setItem(row, 1, QTableWidgetItem(str(name)))
            self.online_table.setItem(row, 2, QTableWidgetItem(str(device.get("ip") or "—")))
            self.online_table.setItem(row, 3, QTableWidgetItem(str(device.get("mac") or "—")))
            self.online_table.setItem(row, 4, QTableWidgetItem(fmt_ts(device["last_seen"])))
        # Số trong ô và số dòng trong bảng phải luôn khớp — nếu lệch thì một
        # trong hai đang nói dối, và người dùng cần biết ngay chứ không phải
        # tự đếm tay để phát hiện.
        self.online_note.setText(
            t("overview.online_note", minutes=int(ONLINE_WINDOW_S // 60))
            if online_devices else t("overview.online_none")
        )
        self.val_alerts.setText(str(alerts_24h_count))
        self.val_blocks.setText(str(len(blocks)))
        if now_ts - self._ledger_checked_at >= 60:
            self._ledger_status = self.store.verify_forensic_ledger()
            self._ledger_checked_at = now_ts
        ledger_ok, bad_record, _message = self._ledger_status
        self.val_watch.setText(
            t("overview.ledger_ok") if ledger_ok else t("overview.ledger_bad", record=bad_record)
        )
        self.val_watch.setStyleSheet(
            f"color: {theme.STATUS_COLOR['ok'] if ledger_ok else theme.SEVERITY_COLOR['critical']};"
        )

        self.recent_table.setRowCount(0)
        for a in alerts:
            row = self.recent_table.rowCount()
            self.recent_table.insertRow(row)
            self.recent_table.setItem(row, 0, QTableWidgetItem(fmt_ts(a["ts"])))
            sev_item = QTableWidgetItem(t(f"severity.{a['severity']}"))
            sev_item.setForeground(QColor(theme.SEVERITY_COLOR.get(a["severity"], theme.TEXT_DIM)))
            self.recent_table.setItem(row, 1, sev_item)
            title, _detail = alert_text(a)
            self.recent_table.setItem(row, 2, QTableWidgetItem(title))


class SelfAuditTab(QWidget, I18nMixin):
    """Tab Tự kiểm tra — công cụ chủ động: quét cổng mở trên chính máy +
    thiết bị tin cậy, chỉ liệt kê + phân loại rủi ro, không khai thác (mục 7
    kế hoạch). Dữ liệu tới từ broadcast `self_audit_result` (agent chạy
    `nmap -sV`, xem `shield/agent/actions.py::self_port_scan`).
    """

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        self._results: dict[str, dict] = {}  # host -> {"ports": [...], "ts": ...}
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.audit")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.sub_label.setWordWrap(True)
        self.bind(lambda: self.sub_label.setText(t("audit.sub")))
        layout.addWidget(self.sub_label)

        self.diff_label = QLabel()
        self.diff_label.setWordWrap(True)
        self.diff_label.setStyleSheet(
            f"color: {theme.SEVERITY_COLOR['warning']}; font-weight: 600;"
        )
        self.diff_label.hide()
        layout.addWidget(self.diff_label)

        btn_row = row_layout()
        self.rescan_all_btn = QPushButton()
        self.bind(lambda: self.rescan_all_btn.setText(t("audit.rescan_all")))
        self.rescan_all_btn.clicked.connect(self._rescan_all)
        btn_row.addWidget(self.rescan_all_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.table = QTableWidget(0, 6)
        self.bind(
            lambda: self.table.setHorizontalHeaderLabels(
                [t("audit.col_host"), t("audit.col_port"), t("audit.col_service"),
                 t("audit.col_risk"), t("audit.col_suggestion"), t("audit.col_cve")]
            )
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(260)
        layout.addWidget(self.table)

        self.bind(self._render)

    def request_scan(self, host: str) -> None:
        """Gọi từ tab Thiết bị (nút "Kiểm tra") hoặc trực tiếp trong tab này."""
        self.socket_client.send_command({"cmd": "self_port_scan", "host": host})

    def _rescan_all(self) -> None:
        self.request_scan("127.0.0.1")
        for dev in self.store.list_devices():
            if dev["trusted"] and dev["ip"]:
                self.request_scan(dev["ip"])

    def on_self_audit_result(self, data: dict) -> None:
        host = data.get("host", "")
        if not data.get("ok"):
            return
        self._results[host] = {"ports": data.get("ports", []), "ts": data.get("ts", time.time())}
        self._show_diff_notice(host, data.get("diff"))
        self._render()

    def _show_diff_notice(self, host: str, diff: dict | None) -> None:
        if not diff or (not diff.get("added") and not diff.get("removed")):
            return
        added = ", ".join(f"{p['port']}/{p['proto']}" for p in diff.get("added", [])) or "-"
        removed = ", ".join(f"{p['port']}/{p['proto']}" for p in diff.get("removed", [])) or "-"
        self.diff_label.setText(t("audit.diff_changed", host=host, added=added, removed=removed))
        self.diff_label.show()

    RISK_SUGGESTION_KEY = {
        "danger": "audit.risk_danger",
        "caution": "audit.risk_caution",
        "safe": "audit.risk_safe",
    }

    def _render(self) -> None:
        self.table.setRowCount(0)
        if not self._results:
            self.table.insertRow(0)
            item = QTableWidgetItem(t("audit.no_hosts"))
            self.table.setItem(0, 0, item)
            self.table.setSpan(0, 0, 1, 6)
            return
        for host, result in self._results.items():
            for p in result["ports"]:
                row = self.table.rowCount()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(host))
                self.table.setItem(row, 1, QTableWidgetItem(f"{p['port']}/{p['proto']}"))
                service = p.get("service", "")
                version = p.get("version", "")
                self.table.setItem(row, 2, QTableWidgetItem(f"{service} {version}".strip()))
                risk = p.get("risk", "safe")
                risk_item = QTableWidgetItem(t(self.RISK_SUGGESTION_KEY.get(risk, "audit.risk_safe")))
                risk_item.setForeground(QColor(theme.RISK_COLOR.get(risk, theme.TEXT_DIM)))
                font = risk_item.font()
                font.setBold(True)
                risk_item.setFont(font)
                self.table.setItem(row, 3, risk_item)
                self.table.setItem(row, 4, QTableWidgetItem(p.get("advice", "")))
                hints = p.get("cve_hints") or []
                hint_text = " | ".join(
                    f"{h['cve']}: {h['note']}" if h.get("cve", "-") != "-" else h["note"]
                    for h in hints
                )
                self.table.setItem(row, 5, QTableWidgetItem(hint_text))
        self.table.resizeRowsToContents()


class ReportsTab(QWidget, I18nMixin):
    """Tab Báo cáo — nhìn tổng thể theo ngày/tuần thay vì phản ứng từng
    alert riêng lẻ (công cụ chủ động). Tính hoàn toàn từ dữ liệu đã có trong
    Store (đọc, không gọi lệnh agent nào) — export .txt chỉ là UI ghi file
    cục bộ bằng dữ liệu đã tải, không phải hành động hệ thống.
    """

    PERIODS = {"today": 1, "7d": 7, "30d": 30}

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store = store
        self.socket_client = socket_client
        self._period = "7d"
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("nav.reports")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.sub_label.setText(t("reports.sub")))
        layout.addWidget(self.sub_label)

        toolbar = row_layout()
        self.period_group = QButtonGroup(self)
        self.period_buttons: dict[str, QPushButton] = {}
        for pid, key in [("today", "reports.period_today"), ("7d", "reports.period_7d"), ("30d", "reports.period_30d")]:
            btn = QPushButton()
            btn.setCheckable(True)
            self.bind(lambda btn=btn, k=key: btn.setText(t(k)))
            btn.clicked.connect(lambda _c, p=pid: self._set_period(p))
            self.period_group.addButton(btn)
            self.period_buttons[pid] = btn
            toolbar.addWidget(btn)
        self.period_buttons["7d"].setChecked(True)
        toolbar.addStretch()
        self.analyze_btn = QPushButton()
        self.bind(lambda: self.analyze_btn.setText(t("reports.analyze")))
        self.analyze_btn.clicked.connect(
            lambda: self.socket_client.send_command(
                {"cmd": "analyze_alerts", "limit": 500, "lang": current_lang()}
            )
        )
        toolbar.addWidget(self.analyze_btn)
        self.export_btn = QPushButton()
        self.bind(lambda: self.export_btn.setText(t("reports.export")))
        self.export_btn.clicked.connect(self._export)
        toolbar.addWidget(self.export_btn)
        self.export_pdf_btn = QPushButton()
        self.bind(lambda: self.export_pdf_btn.setText(t("reports.export_pdf")))
        self.export_pdf_btn.clicked.connect(self._export_pdf)
        toolbar.addWidget(self.export_pdf_btn)
        layout.addLayout(toolbar)

        tile_row = row_layout()
        self.tile_new, self.lbl_new, self.val_new = make_tile()
        self.bind(lambda: self.lbl_new.setText(t("reports.new_devices")))
        self.tile_crit, self.lbl_crit, self.val_crit = make_tile(theme.SEVERITY_COLOR["critical"])
        self.bind(lambda: self.lbl_crit.setText(t("reports.critical_alerts")))
        self.tile_std, self.lbl_std, self.val_std = make_tile(theme.SEVERITY_COLOR["warning"])
        self.bind(lambda: self.lbl_std.setText(t("reports.standard_alerts")))
        self.tile_actions, self.lbl_actions, self.val_actions = make_tile(theme.STATUS_COLOR["ok"])
        self.bind(lambda: self.lbl_actions.setText(t("reports.actions_taken")))
        for tile in (self.tile_new, self.tile_crit, self.tile_std, self.tile_actions):
            tile_row.addWidget(tile)
        layout.addLayout(tile_row)

        self.by_day_label = QLabel()
        self.bind(lambda: self.by_day_label.setText(t("reports.alerts_by_day")))
        layout.addWidget(self.by_day_label)
        self.by_day_table = QTableWidget(0, 4)
        self.bind(
            lambda: self.by_day_table.setHorizontalHeaderLabels(
                ["", t("severity.info"), t("severity.warning"), t("severity.critical")]
            )
        )
        self.by_day_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.by_day_table.setMinimumHeight(200)
        self.by_day_table.setMaximumHeight(300)
        layout.addWidget(self.by_day_table)

        self.digest_label = QLabel()
        self.bind(lambda: self.digest_label.setText(t("reports.digest")))
        layout.addWidget(self.digest_label)
        self.digest_list_label = QLabel()
        self.digest_list_label.setWordWrap(True)
        self.digest_list_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        layout.addWidget(self.digest_list_label)
        layout.addStretch()

        self.bind(self.refresh)

    def _set_period(self, pid: str) -> None:
        self._period = pid
        self.refresh()

    def _cutoff_ts(self) -> float:
        return time.time() - self.PERIODS[self._period] * 86400

    def refresh(self) -> None:
        cutoff = self._cutoff_ts()
        alerts = [a for a in self.store.recent_alerts(limit=2000) if a["ts"] >= cutoff]
        devices = self.store.list_devices()
        new_devices = sum(1 for d in devices if d["first_seen"] >= cutoff)
        critical = [a for a in alerts if a["severity"] == "critical"]
        warning = [a for a in alerts if a["severity"] == "warning"]

        self.val_new.setText(str(new_devices))
        self.val_crit.setText(str(len(critical)))
        self.val_std.setText(str(len(warning)))
        self.val_actions.setText(str(len(self.store.recent_audit_logs(since_ts=cutoff))))

        # Khoá sort là ngày đầy đủ (có năm) để không bị lẫn thứ tự khi khoảng
        # thời gian báo cáo vắt qua giao thừa năm; nhãn hiển thị vẫn "dd/mm"
        # cho gọn (xem DeprecationWarning cũ của time.strptime("%d/%m") không
        # có năm — đã bỏ, không còn parse lại chuỗi đã format).
        by_day: dict[str, dict[str, int]] = {}
        day_labels: dict[str, str] = {}
        for a in alerts:
            local = time.localtime(a["ts"])
            sort_key = time.strftime("%Y-%m-%d", local)
            day_labels[sort_key] = time.strftime("%d/%m", local)
            by_day.setdefault(sort_key, {"info": 0, "warning": 0, "critical": 0})
            by_day[sort_key][a["severity"]] = by_day[sort_key].get(a["severity"], 0) + 1

        self.by_day_table.setRowCount(0)
        for sort_key in sorted(by_day):
            row = self.by_day_table.rowCount()
            self.by_day_table.insertRow(row)
            counts = by_day[sort_key]
            self.by_day_table.setItem(row, 0, QTableWidgetItem(day_labels[sort_key]))
            for col, sev in enumerate(["info", "warning", "critical"], start=1):
                item = QTableWidgetItem(str(counts.get(sev, 0)))
                if counts.get(sev, 0) > 0:
                    item.setForeground(QColor(theme.SEVERITY_COLOR[sev]))
                self.by_day_table.setItem(row, col, item)

        if not alerts:
            self.digest_list_label.setText(t("reports.no_alerts"))
        else:
            top = sorted(alerts, key=lambda a: a["ts"], reverse=True)[:5]
            # alert_text() chứ không phải a["title"] thô: agent luôn ghi tiếng
            # Việt vào DB, nên đọc thẳng cột title sẽ ra tiếng Việt kể cả khi
            # UI đang để English (lịch sử phải theo ngôn ngữ đang chọn).
            lines = [f"• {fmt_ts(a['ts'])} — {alert_text(a)[0]} ({a['subject']})" for a in top]
            self.digest_list_label.setText("\n".join(lines))

    def _export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, t("reports.export"), str(Path.home() / "shield-report.txt"), "Text (*.txt)"
        )
        if not path:
            return
        cutoff = self._cutoff_ts()
        alerts = [a for a in self.store.recent_alerts(limit=2000) if a["ts"] >= cutoff]
        ledger_ok, bad_record, ledger_message = self.store.verify_forensic_ledger()
        avg_risk = (sum(int(a.get("risk_score", 0)) for a in alerts) / len(alerts)) if alerts else 0
        lines = [
            f"Shield — {t('reports.digest')} ({self._period})", "=" * 40,
            f"Forensic ledger: {'VERIFIED' if ledger_ok else f'INVALID at #{bad_record}'} ({ledger_message})",
            f"Average risk score: {avg_risk:.1f}/100", "",
        ]
        for a in sorted(alerts, key=lambda a: a["ts"]):
            title, _detail = alert_text(a)
            sev = t(f"severity.{a['severity']}")
            lines.append(
                f"{fmt_ts(a['ts'])} [{sev}] [risk={int(a.get('risk_score', 0))}/100] "
                f"{title} — {a['subject']}"
            )
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        QMessageBox.information(self, t("reports.export"), t("reports.export_done", path=path))

    @staticmethod
    def _pdf_fonts() -> tuple[str, str]:
        """Đăng ký font TrueType hỗ trợ dấu tiếng Việt cho reportlab —
        Helvetica mặc định (Base14) không có glyph tiếng Việt, chữ có dấu sẽ
        vỡ khi xuất PDF. DejaVu Sans có sẵn theo mặc định trên Ubuntu/Debian
        (gói fonts-dejavu-core). Rơi về Helvetica nếu không tìm thấy — báo cáo
        vẫn xuất được, chỉ mất dấu tiếng Việt thay vì crash."""
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        regular_candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        ]
        bold_candidates = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        ]
        regular = next((p for p in regular_candidates if Path(p).exists()), None)
        if not regular:
            return "Helvetica", "Helvetica-Bold"
        if "Shield-VN" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("Shield-VN", regular))
            bold = next((p for p in bold_candidates if Path(p).exists()), regular)
            pdfmetrics.registerFont(TTFont("Shield-VN-Bold", bold))
        return "Shield-VN", "Shield-VN-Bold"

    def _export_pdf(self) -> None:
        """Xuất PDF chuẩn hơn cho kiểm thử sâu hệ thống — có bằng chứng
        (timestamp, subject, mức độ, chi tiết) từng alert thay vì chỉ số
        thống kê, phù hợp nộp báo cáo (đề xuất #5 trong đợt rà soát)."""
        path, _ = QFileDialog.getSaveFileName(
            self, t("reports.export_pdf"), str(Path.home() / "shield-report.pdf"), "PDF (*.pdf)"
        )
        if not path:
            return

        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        font_regular, font_bold = self._pdf_fonts()
        styles = getSampleStyleSheet()
        for name in ("Normal", "BodyText"):
            styles[name].fontName = font_regular
        styles["Title"].fontName = font_bold
        styles["Heading2"].fontName = font_bold

        cutoff = self._cutoff_ts()
        alerts = sorted(
            (a for a in self.store.recent_alerts(limit=2000) if a["ts"] >= cutoff),
            key=lambda a: a["ts"],
        )
        devices = self.store.list_devices()
        new_devices = sum(1 for d in devices if d["first_seen"] >= cutoff)
        critical = [a for a in alerts if a["severity"] == "critical"]
        warning = [a for a in alerts if a["severity"] == "warning"]

        story: list = [
            Paragraph(t("reports.pdf_report_title"), styles["Title"]),
            Paragraph(
                t("reports.pdf_generated_at", ts=fmt_ts(time.time()), period=t(f"reports.period_{self._period}")),
                styles["Normal"],
            ),
            Spacer(1, 14),
            Paragraph(t("reports.pdf_summary"), styles["Heading2"]),
        ]

        summary_data = [
            [t("reports.new_devices"), t("reports.critical_alerts"), t("reports.standard_alerts")],
            [str(new_devices), str(len(critical)), str(len(warning))],
        ]
        summary_table = Table(summary_data, hAlign="LEFT")
        summary_table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (-1, -1), font_regular),
                    ("FONTNAME", (0, 0), (-1, 0), font_bold),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("TEXTCOLOR", (2, 1), (2, 1), colors.HexColor("#c62828") if critical else colors.black),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 18))

        story.append(Paragraph(t("reports.pdf_evidence"), styles["Heading2"]))
        if not alerts:
            story.append(Paragraph(t("reports.no_alerts"), styles["Normal"]))
        else:
            rows = [[t("reports.pdf_col_ts"), t("reports.pdf_col_severity"), t("reports.pdf_col_title"),
                     t("reports.pdf_col_subject")]]
            for a in alerts:
                rows.append(
                    [fmt_ts(a["ts"]), t(f"severity.{a['severity']}"), alert_text(a)[0], a["subject"]]
                )
            table = Table(rows, colWidths=[85, 60, 200, 130], repeatRows=1)
            style_cmds = [
                ("FONTNAME", (0, 0), (-1, -1), font_regular),
                ("FONTNAME", (0, 0), (-1, 0), font_bold),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
            for i, a in enumerate(alerts, start=1):
                if a["severity"] == "critical":
                    style_cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor("#c62828")))
                elif a["severity"] == "warning":
                    style_cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor("#e65100")))
            table.setStyle(TableStyle(style_cmds))
            story.append(table)

        story.append(PageBreak())
        story.append(Paragraph(t("reports.pdf_detail"), styles["Heading2"]))
        if not alerts:
            story.append(Paragraph(t("reports.no_alerts"), styles["Normal"]))
        for a in alerts:
            raw_title, raw_detail = alert_text(a)
            sev_label = escape(t(f"severity.{a['severity']}"))
            title = escape(str(raw_title))
            subject = escape(str(a.get("subject", "")))
            story.append(
                Paragraph(
                    f"<b>{fmt_ts(a['ts'])} — [{sev_label}] {title}</b>",
                    styles["Normal"],
                )
            )
            story.append(Paragraph(f"{t('reports.pdf_col_subject')}: {subject}", styles["Normal"]))
            if raw_detail:
                story.append(Paragraph(escape(str(raw_detail)), styles["Normal"]))
            story.append(Spacer(1, 8))

        SimpleDocTemplate(path, pagesize=A4, title="Shield Report").build(story)
        QMessageBox.information(self, t("reports.export_pdf"), t("reports.export_done", path=path))


class DnsTab(QWidget, I18nMixin):
    """Tab Tự kiểm soát DNS — DNS server máy đang thật sự dùng, so với
    baseline; các dòng /etc/hosts bất thường; và test chống hijack (so kết
    quả phân giải giữa resolver của máy và resolver công khai).

    Toàn bộ chỉ đọc cấu hình + gửi truy vấn DNS thông thường — không sửa gì
    trên máy, không tấn công gì (mục 7 kế hoạch). Nút "Đặt baseline" là hành
    động ghi duy nhất, và chỉ ghi vào DB của Shield.
    """

    def __init__(self, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.socket_client = socket_client
        self._status: dict = {}
        self._hijack: list[dict] = []
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("dns.title")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.sub_label.setWordWrap(True)
        self.bind(lambda: self.sub_label.setText(t("dns.sub")))
        layout.addWidget(self.sub_label)

        btn_row = row_layout()
        btn_row.setSpacing(10)
        self.refresh_btn = QPushButton()
        self.bind(lambda: self.refresh_btn.setText(t("dns.refresh")))
        self.refresh_btn.clicked.connect(
            lambda: self.socket_client.send_command({"cmd": "dns_status_now"})
        )
        btn_row.addWidget(self.refresh_btn)
        self.hijack_btn = QPushButton()
        self.bind(lambda: self.hijack_btn.setText(t("dns.run_hijack_check")))
        self.hijack_btn.clicked.connect(self._run_hijack_check)
        btn_row.addWidget(self.hijack_btn)
        self.baseline_btn = QPushButton()
        self.bind(lambda: self.baseline_btn.setText(t("dns.set_baseline")))
        self.baseline_btn.clicked.connect(self._set_baseline)
        btn_row.addWidget(self.baseline_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        # --- Resolver hiện tại vs baseline ---
        self.resolver_header = QLabel()
        self.resolver_header.setStyleSheet("font-weight: 700;")
        self.bind(lambda: self.resolver_header.setText(t("dns.resolvers_header")))
        layout.addWidget(self.resolver_header)
        self.resolver_label = QLabel()
        self.resolver_label.setWordWrap(True)
        layout.addWidget(self.resolver_label)
        self.baseline_label = QLabel()
        self.baseline_label.setWordWrap(True)
        self.baseline_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        layout.addWidget(self.baseline_label)

        # --- /etc/hosts ---
        self.hosts_header = QLabel()
        self.hosts_header.setStyleSheet("font-weight: 700;")
        self.bind(lambda: self.hosts_header.setText(t("dns.hosts_header")))
        layout.addWidget(self.hosts_header)
        self.hosts_table = QTableWidget(0, 2)
        self.bind(
            lambda: self.hosts_table.setHorizontalHeaderLabels(
                [t("dns.col_ip"), t("dns.col_names")]
            )
        )
        self.hosts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.hosts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hosts_table.setMinimumHeight(140)
        layout.addWidget(self.hosts_table)

        # --- Test hijack ---
        self.hijack_header = QLabel()
        self.hijack_header.setStyleSheet("font-weight: 700;")
        self.bind(lambda: self.hijack_header.setText(t("dns.hijack_header")))
        layout.addWidget(self.hijack_header)
        self.hijack_note = QLabel()
        self.hijack_note.setWordWrap(True)
        self.hijack_note.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.hijack_note.setText(t("dns.hijack_note")))
        layout.addWidget(self.hijack_note)
        self.hijack_table = QTableWidget(0, 4)
        self.bind(
            lambda: self.hijack_table.setHorizontalHeaderLabels(
                [t("dns.col_domain"), t("dns.col_local"), t("dns.col_public"), t("dns.col_verdict")]
            )
        )
        self.hijack_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.hijack_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.hijack_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hijack_table.setMinimumHeight(140)
        layout.addWidget(self.hijack_table)
        layout.addStretch()

        self.bind(self._render)

    def _run_hijack_check(self) -> None:
        self.hijack_btn.setEnabled(False)
        self.hijack_btn.setText(t("dns.checking"))
        self.socket_client.send_command({"cmd": "dns_hijack_check"})

    def _set_baseline(self) -> None:
        reply = QMessageBox.question(
            self,
            t("dns.set_baseline"),
            t("dns.set_baseline_confirm"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "set_dns_baseline"})

    def on_dns_status(self, data: dict) -> None:
        self._status = data
        self._render()

    def on_dns_hijack_result(self, data: dict) -> None:
        self.hijack_btn.setEnabled(True)
        self.hijack_btn.setText(t("dns.run_hijack_check"))
        if not data.get("ok"):
            QMessageBox.warning(self, t("dns.hijack_header"), error_message(data))
            return
        self._hijack = data.get("results", [])
        self._render()

    VERDICT_KEY = {
        "ok": "dns.verdict_ok",
        "suspect": "dns.verdict_suspect",
        "unknown": "dns.verdict_unknown",
    }
    VERDICT_COLOR_KEY = {"ok": "safe", "suspect": "danger", "unknown": "caution"}

    def _render(self) -> None:
        servers = self._status.get("servers") or []
        baseline = self._status.get("baseline") or []
        source = self._status.get("source", "")

        if not servers:
            self.resolver_label.setText(t("dns.no_resolvers"))
            self.resolver_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        else:
            self.resolver_label.setText(t("dns.current", servers=", ".join(servers), source=source))
            changed = baseline and sorted(servers) != sorted(baseline)
            color = theme.SEVERITY_COLOR["critical"] if changed else theme.STATUS_COLOR["ok"]
            self.resolver_label.setStyleSheet(f"color: {color}; font-weight: 600;")

        self.baseline_label.setText(
            t("dns.baseline", servers=", ".join(baseline)) if baseline else t("dns.no_baseline")
        )

        overrides = self._status.get("hosts_overrides") or []
        self.hosts_table.setRowCount(0)
        if not overrides:
            self.hosts_table.insertRow(0)
            self.hosts_table.setItem(0, 0, QTableWidgetItem(t("dns.hosts_clean")))
            self.hosts_table.setSpan(0, 0, 1, 2)
        else:
            for entry in overrides:
                row = self.hosts_table.rowCount()
                self.hosts_table.insertRow(row)
                self.hosts_table.setItem(row, 0, QTableWidgetItem(entry.get("ip", "")))
                self.hosts_table.setItem(
                    row, 1, QTableWidgetItem(", ".join(entry.get("names", [])))
                )

        self.hijack_table.setRowCount(0)
        if not self._hijack:
            self.hijack_table.insertRow(0)
            self.hijack_table.setItem(0, 0, QTableWidgetItem(t("dns.hijack_not_run")))
            self.hijack_table.setSpan(0, 0, 1, 4)
            return
        for r in self._hijack:
            row = self.hijack_table.rowCount()
            self.hijack_table.insertRow(row)
            self.hijack_table.setItem(row, 0, QTableWidgetItem(r.get("domain", "")))
            self.hijack_table.setItem(row, 1, QTableWidgetItem(", ".join(r.get("local", []))))
            self.hijack_table.setItem(row, 2, QTableWidgetItem(", ".join(r.get("public", []))))
            verdict = r.get("verdict", "unknown")
            item = QTableWidgetItem(t(self.VERDICT_KEY.get(verdict, "dns.verdict_unknown")))
            item.setForeground(
                QColor(theme.RISK_COLOR.get(self.VERDICT_COLOR_KEY.get(verdict, "caution")))
            )
            font = item.font()
            font.setBold(True)
            item.setFont(font)
            self.hijack_table.setItem(row, 3, item)


class WifiPasswordsTab(QWidget, I18nMixin):
    """Tab xem mật khẩu WiFi đã lưu trên CHÍNH máy này (qua NetworkManager).

    Chỉ đọc lại secret NetworkManager đã lưu sẵn cho các mạng máy này từng
    kết nối — KHÔNG dò/bẻ mật khẩu mạng khác, đúng ranh giới "chỉ xem thông
    tin của chính mình" (mục 7 kế hoạch). Mật khẩu ẩn mặc định (giống bảng
    mật khẩu trên trình duyệt), có nút hiện/ẩn để tránh lộ khi có người nhìn
    qua vai (shoulder surfing).
    """

    def __init__(self, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.socket_client = socket_client
        self._networks: list[dict] = []
        self._revealed = False
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("wifi.title")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.sub_label.setWordWrap(True)
        self.bind(lambda: self.sub_label.setText(t("wifi.sub")))
        layout.addWidget(self.sub_label)

        btn_row = row_layout()
        self.refresh_btn = QPushButton()
        self.bind(lambda: self.refresh_btn.setText(t("wifi.refresh")))
        self.refresh_btn.clicked.connect(self._refresh)
        btn_row.addWidget(self.refresh_btn)
        self.reveal_btn = QPushButton()
        self.bind(self._retranslate_reveal_btn)
        self.reveal_btn.clicked.connect(self._toggle_reveal)
        btn_row.addWidget(self.reveal_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.table = QTableWidget(0, 2)
        self.bind(
            lambda: self.table.setHorizontalHeaderLabels([t("wifi.col_ssid"), t("wifi.col_password")])
        )
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        self.bind(self._render)

    def _retranslate_reveal_btn(self) -> None:
        self.reveal_btn.setText(t("wifi.hide") if self._revealed else t("wifi.reveal"))

    def _refresh(self) -> None:
        self.socket_client.send_command({"cmd": "list_wifi_passwords"})

    def _toggle_reveal(self) -> None:
        self._revealed = not self._revealed
        self._retranslate_reveal_btn()
        self._render()

    def on_wifi_passwords_result(self, data: dict) -> None:
        if not data.get("ok"):
            return
        self._networks = data.get("networks", [])
        self._render()

    def _render(self) -> None:
        self.table.setRowCount(0)
        if not self._networks:
            self.table.insertRow(0)
            self.table.setItem(0, 0, QTableWidgetItem(t("wifi.no_networks")))
            self.table.setSpan(0, 0, 1, 2)
            return
        for net in self._networks:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(net.get("ssid", "")))
            password = net.get("password", "")
            shown = password if self._revealed else "•" * max(len(password), 8)
            self.table.setItem(row, 1, QTableWidgetItem(shown if password else t("wifi.no_password")))


class AdvancedSecurityTab(QWidget, I18nMixin):
    """Operational view for advanced defensive capabilities."""

    def __init__(self, socket_client: SocketClient, store: Store) -> None:
        super().__init__()
        self._init_i18n()
        self.socket_client = socket_client
        self.store = store
        self._status: dict = {}
        self._records: list[dict] = []
        layout = tab_layout(self)

        title = QLabel()
        title.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: title.setText(t("advanced.title")))
        layout.addWidget(title)
        sub = QLabel()
        sub.setWordWrap(True)
        sub.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: sub.setText(t("advanced.sub")))
        layout.addWidget(sub)

        tiles = row_layout()
        self._tiles = {}
        for key in ("telemetry", "mitre", "cases", "endpoints", "health"):
            frame, label, value = make_tile(theme.ACCENT)
            self.bind(lambda label=label, key=key: label.setText(t(f"advanced.{key}")))
            value.setText("—")
            self._tiles[key] = value
            tiles.addWidget(frame)
        layout.addLayout(tiles)

        search_title = QLabel()
        search_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: search_title.setText(t("advanced.search_title")))
        layout.addWidget(search_title)
        search_row = row_layout()
        self.search_input = QLineEdit()
        self.bind(lambda: self.search_input.setPlaceholderText(t("advanced.search_placeholder")))
        self.search_input.returnPressed.connect(self._search)
        search_row.addWidget(self.search_input)
        search_btn = QPushButton()
        self.bind(lambda: search_btn.setText(t("advanced.search")))
        search_btn.clicked.connect(self._search)
        search_row.addWidget(search_btn)
        layout.addLayout(search_row)
        self.graph_label = QLabel()
        self.graph_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        layout.addWidget(self.graph_label)
        self.search_table = QTableWidget(0, 5)
        self.bind(lambda: self.search_table.setHorizontalHeaderLabels([
            t("advanced.col_time"), t("advanced.col_type"), t("advanced.col_source"),
            t("advanced.col_subject"), t("advanced.col_provenance"),
        ]))
        self.search_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.search_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.search_table)

        health_title = QLabel()
        health_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: health_title.setText(t("advanced.health_title")))
        layout.addWidget(health_title)
        self.health_table = QTableWidget(0, 8)
        self.bind(lambda: self.health_table.setHorizontalHeaderLabels([
            t("advanced.col_component"), t("advanced.col_backend"),
            t("advanced.col_health"), t("advanced.col_heartbeat"),
            t("advanced.col_event"), t("advanced.col_restarts"),
            t("advanced.col_dropped"), t("advanced.col_detail"),
        ]))
        self.health_table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.health_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.health_table)

        probe_title = QLabel()
        probe_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: probe_title.setText(t("probe.table_title")))
        layout.addWidget(probe_title)
        self.probe_hint = QLabel()
        self.probe_hint.setWordWrap(True)
        self.probe_hint.setObjectName("pageDescription")
        self.bind(lambda: self.probe_hint.setText(t("probe.hint")))
        layout.addWidget(self.probe_hint)
        self.probe_table = QTableWidget(0, 6)
        self.bind(lambda: self.probe_table.setHorizontalHeaderLabels([
            t("probe.col_name"), t("probe.col_address"), t("probe.col_last_seen"),
            t("probe.col_lag"), t("probe.col_lines"), t("probe.col_dropped"),
        ]))
        self.probe_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.probe_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.probe_table)

        system_health_title = QLabel()
        system_health_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: system_health_title.setText(t("advanced.system_health_title")))
        layout.addWidget(system_health_title)
        self.system_health_table = QTableWidget(0, 4)
        self.bind(lambda: self.system_health_table.setHorizontalHeaderLabels([
            t("advanced.col_metric"), t("advanced.col_value"),
            t("advanced.col_health"), t("advanced.col_detail"),
        ]))
        self.system_health_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.system_health_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.system_health_table)
        diagnostics_row = row_layout()
        diagnostics_button = QPushButton()
        self.bind(lambda: diagnostics_button.setText(t("advanced.export_diagnostics")))
        diagnostics_button.clicked.connect(self._export_diagnostics)
        diagnostics_row.addWidget(diagnostics_button)
        diagnostics_row.addStretch()
        layout.addLayout(diagnostics_row)

        baseline_title = QLabel()
        baseline_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: baseline_title.setText(t("advanced.baseline_title")))
        layout.addWidget(baseline_title)
        baseline_row = row_layout()
        self.baseline_label = QLabel()
        baseline_row.addWidget(self.baseline_label)
        reset_btn = QPushButton()
        self.bind(lambda: reset_btn.setText(t("advanced.reset_baseline")))
        reset_btn.clicked.connect(self._reset_baseline)
        baseline_row.addWidget(reset_btn)
        baseline_row.addStretch()
        layout.addLayout(baseline_row)

        suppression_title = QLabel()
        suppression_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: suppression_title.setText(t("advanced.suppression_title")))
        layout.addWidget(suppression_title)
        suppression_row = row_layout()
        self.suppression_rule = QLineEdit()
        self.bind(lambda: self.suppression_rule.setPlaceholderText(t("advanced.suppression_rule")))
        self.suppression_subject = QLineEdit("*")
        self.bind(lambda: self.suppression_subject.setPlaceholderText(t("advanced.suppression_subject")))
        self.suppression_hours = QLineEdit("24")
        self.suppression_hours.setFixedWidth(70)
        self.bind(lambda: self.suppression_hours.setPlaceholderText(t("advanced.suppression_hours")))
        self.suppression_reason = QLineEdit()
        self.bind(lambda: self.suppression_reason.setPlaceholderText(t("advanced.suppression_reason")))
        suppression_btn = QPushButton()
        self.bind(lambda: suppression_btn.setText(t("advanced.suppression_add")))
        suppression_btn.clicked.connect(self._add_suppression)
        for widget in (self.suppression_rule, self.suppression_subject, self.suppression_hours,
                       self.suppression_reason, suppression_btn):
            suppression_row.addWidget(widget)
        layout.addLayout(suppression_row)
        self.suppression_label = QLabel()
        self.suppression_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        layout.addWidget(self.suppression_label)

        case_title = QLabel()
        case_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: case_title.setText(t("advanced.case_title")))
        layout.addWidget(case_title)
        case_row = row_layout()
        self.case_title_input = QLineEdit()
        self.bind(lambda: self.case_title_input.setPlaceholderText(t("advanced.case_name")))
        case_row.addWidget(self.case_title_input)
        self.case_subject_input = QLineEdit()
        self.bind(lambda: self.case_subject_input.setPlaceholderText(t("advanced.case_subject")))
        case_row.addWidget(self.case_subject_input)
        case_btn = QPushButton()
        self.bind(lambda: case_btn.setText(t("advanced.case_create")))
        case_btn.clicked.connect(self._create_case)
        case_row.addWidget(case_btn)
        layout.addLayout(case_row)
        self.case_table = QTableWidget(0, 4)
        self.bind(lambda: self.case_table.setHorizontalHeaderLabels([
            t("advanced.col_case"), t("advanced.case_subject"),
            t("advanced.col_state"), t("advanced.col_updated"),
        ]))
        self.case_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.case_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.case_table)
        case_action_row = row_layout()
        self.case_state_combo = QComboBox()
        for state in ("open", "investigating", "resolved", "false_positive"):
            self.case_state_combo.addItem(t(f"advanced.state.{state}"), state)
        self.bind(self._retranslate_case_states)
        case_action_row.addWidget(self.case_state_combo)
        self.case_note_input = QLineEdit()
        self.bind(lambda: self.case_note_input.setPlaceholderText(t("advanced.case_note")))
        case_action_row.addWidget(self.case_note_input)
        case_update_btn = QPushButton()
        self.bind(lambda: case_update_btn.setText(t("advanced.case_update")))
        case_update_btn.clicked.connect(self._update_case)
        case_action_row.addWidget(case_update_btn)
        layout.addLayout(case_action_row)

        fleet_title = QLabel()
        fleet_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: fleet_title.setText(t("advanced.fleet_title")))
        layout.addWidget(fleet_title)
        self.fleet_table = QTableWidget(0, 3)
        self.bind(lambda: self.fleet_table.setHorizontalHeaderLabels([
            t("advanced.col_endpoint"), t("advanced.col_role"), t("advanced.col_fingerprint"),
        ]))
        self.fleet_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.fleet_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.fleet_table)

        lab_title = QLabel()
        lab_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        self.bind(lambda: lab_title.setText(t("advanced.lab_title")))
        layout.addWidget(lab_title)
        lab_note = QLabel()
        lab_note.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: lab_note.setText(t("advanced.lab_note")))
        layout.addWidget(lab_note)
        self.lab_table = QTableWidget(0, 3)
        self.bind(lambda: self.lab_table.setHorizontalHeaderLabels([
            t("advanced.col_scenario"), t("advanced.col_isolation"), t("advanced.col_validates"),
        ]))
        self.lab_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.lab_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.lab_table)
        self.bind(self._render)

    def _search(self) -> None:
        query = self.search_input.text().strip()
        if query:
            self.socket_client.send_command({"cmd": "security_search", "query": query})

    def _export_diagnostics(self) -> None:
        path, _selected_filter = QFileDialog.getSaveFileName(
            self, t("advanced.export_diagnostics"), "zuken-shield-diagnostics.zip", "ZIP (*.zip)"
        )
        if not path:
            return
        if not path.lower().endswith(".zip"):
            path += ".zip"
        try:
            export_diagnostic_bundle(self.store, Path(path))
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self, t("advanced.export_diagnostics"),
                t("advanced.export_diagnostics_failed", error=str(exc)),
            )
            return
        QMessageBox.information(
            self, t("advanced.export_diagnostics"),
            t("advanced.export_diagnostics_done", path=path),
        )

    def _retranslate_case_states(self) -> None:
        for index in range(self.case_state_combo.count()):
            self.case_state_combo.setItemText(index, t(f"advanced.state.{self.case_state_combo.itemData(index)}"))

    def _create_case(self) -> None:
        title, subject = self.case_title_input.text().strip(), self.case_subject_input.text().strip()
        if title and subject:
            self.socket_client.send_command({"cmd": "case_create", "title": title, "subject": subject})
            self.case_title_input.clear()
            self.case_subject_input.clear()

    def _reset_baseline(self) -> None:
        if QMessageBox.question(self, t("advanced.baseline_title"), t("advanced.reset_confirm"),
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self.socket_client.send_command({"cmd": "baseline_reset", "confirm": True})

    def _add_suppression(self) -> None:
        try:
            hours = float(self.suppression_hours.text())
        except ValueError:
            hours = 24
        if self.suppression_rule.text().strip():
            self.socket_client.send_command({
                "cmd": "suppression_add", "rule_pattern": self.suppression_rule.text().strip(),
                "subject_pattern": self.suppression_subject.text().strip() or "*", "hours": hours,
                "reason": self.suppression_reason.text().strip() or "analyst exception",
            })

    def _update_case(self) -> None:
        row = self.case_table.currentRow()
        item = self.case_table.item(row, 0) if row >= 0 else None
        case_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not case_id:
            return
        self.socket_client.send_command({"cmd": "case_state", "case_id": case_id,
                                         "state": self.case_state_combo.currentData()})
        note = self.case_note_input.text().strip()
        if note:
            self.socket_client.send_command({"cmd": "case_note", "case_id": case_id, "note": note})
            self.case_note_input.clear()

    def on_status(self, data: dict) -> None:
        self._status.update(data)
        self._render()

    def on_search(self, data: dict) -> None:
        self._records = data.get("records", [])
        self._render_search()

    def _render_search(self) -> None:
        self.search_table.setRowCount(0)
        events = [item for item in self._records if item.get("record_type") == "event"]
        graph = build_process_graph(events)
        self.graph_label.setText(t("advanced.process_graph", nodes=len(graph["nodes"]), edges=len(graph["edges"])))
        if not self._records:
            self.search_table.insertRow(0)
            self.search_table.setItem(0, 0, QTableWidgetItem(t("advanced.no_results")))
            self.search_table.setSpan(0, 0, 1, 5)
            return
        for record in self._records:
            row = self.search_table.rowCount()
            self.search_table.insertRow(row)
            data = record.get("data") or record.get("evidence") or {}
            synthetic = bool(data.get("synthetic") or data.get("assessment_id"))
            values = (fmt_ts(record.get("ts", 0)), record.get("record_type", ""),
                      record.get("source") or record.get("rule_id", ""),
                      record.get("subject") or data.get("exe") or data.get("path") or str(data.get("pid", "")),
                      t("advanced.synthetic" if synthetic else "advanced.actual"))
            for col, value in enumerate(values):
                self.search_table.setItem(row, col, QTableWidgetItem(str(value)))

    def _render(self) -> None:
        health = self._status.get("collector_health", [])
        kernel = next((item for item in health if item.get("component") == "kernel_telemetry"), {})
        self._tiles["telemetry"].setText(kernel.get("backend", "—"))
        mitre = self._status.get("mitre", {})
        self._tiles["mitre"].setText(f"{mitre.get('coverage_percent', 0):.1f}%")
        cases = self._status.get("cases", [])
        self._tiles["cases"].setText(str(sum(item.get("state") in {"open", "investigating"} for item in cases)))
        endpoints = self._status.get("endpoints", [])
        self._tiles["endpoints"].setText(str(len(endpoints)))
        # Điểm tổng thay cho việc đếm số thành phần hỏng: "3 ⚠" không nói
        # được 3 cái đó nặng hay nhẹ. Đây là sức khoẻ của SHIELD, không phải
        # mức an toàn của mạng — xem security/health.overall_health().
        overall = self._status.get("overall_health") or {}
        if overall:
            self._tiles["health"].setText(f"{overall.get('score', 0)}%")
            worst = overall.get("penalties") or []
            self._tiles["health"].setToolTip(
                t("advanced.health_score_tooltip",
                  detail=", ".join(f"{p['name']} ({p['state']})" for p in worst[:4]))
                if worst else t("advanced.healthy")
            )
        else:
            unhealthy = sum(item.get("state") in {"degraded", "failed"} for item in health)
            unhealthy += sum(item.get("state") in {"degraded", "failed"} for item in self._status.get("system_health", []))
            self._tiles["health"].setText(t("advanced.healthy") if not unhealthy else f"{unhealthy} ⚠")

        self.health_table.setRowCount(0)
        for item in health:
            row = self.health_table.rowCount(); self.health_table.insertRow(row)
            values = (item.get("component", ""), item.get("backend", ""),
                      item.get("state", t("advanced.healthy" if item.get("healthy") else "advanced.unhealthy")),
                      fmt_ts(item.get("last_heartbeat", 0)) if item.get("last_heartbeat") else "—",
                      fmt_ts(item.get("last_event", 0)) if item.get("last_event") else "—",
                      item.get("restart_count", 0), item.get("dropped_events", 0),
                      item.get("error_message") or item.get("detail", ""))
            for col, value in enumerate(values): self.health_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.system_health_table.setRowCount(0)
        for item in self._status.get("system_health", []):
            row = self.system_health_table.rowCount(); self.system_health_table.insertRow(row)
            value = item.get("value", 0)
            unit = item.get("unit", "")
            if unit == "bytes":
                shown = fmt_bytes(value)
            elif unit == "unix_ts":
                shown = fmt_ts(value)
            elif unit == "%":
                shown = f"{value:.1f}%"
            elif unit == "seconds":
                shown = f"{value / 3600:.1f} h"
            else:
                shown = f"{value:.1f} {unit}".strip()
            values = (item.get("metric", ""), shown, item.get("state", ""), item.get("detail", ""))
            for col, cell_value in enumerate(values):
                self.system_health_table.setItem(row, col, QTableWidgetItem(str(cell_value)))
        # Probe và syslog (kế hoạch 1.1 phần A). Trạng thái "chưa bật" cũng
        # phải nói rõ: một bảng trống nhìn giống hệt một bảng có probe chết.
        probes = self._status.get("probes", [])
        self.probe_table.setRowCount(0)
        for item in probes:
            row = self.probe_table.rowCount(); self.probe_table.insertRow(row)
            lag = item.get("lag_s")
            values = (
                item.get("display_name") or item.get("probe_id", ""),
                item.get("remote_addr", "—"),
                fmt_ts(item.get("last_seen", 0)) if item.get("last_seen") else "—",
                f"{lag:.0f}s" if isinstance(lag, (int, float)) else "—",
                item.get("lines_total", 0),
                item.get("lines_dropped", 0),
            )
            for col, value in enumerate(values):
                self.probe_table.setItem(row, col, QTableWidgetItem(str(value)))
        syslog = self._status.get("syslog", {})
        if probes or syslog.get("listening"):
            self.probe_hint.setText(t(
                "probe.summary",
                probes=len(probes),
                syslog=t("probe.syslog_on") if syslog.get("listening") else t("probe.syslog_off"),
                accepted=syslog.get("accepted", 0),
                rejected=syslog.get("rejected_source", 0) + syslog.get("rejected_rate", 0),
            ))
        else:
            self.probe_hint.setText(t("probe.hint"))

        baseline = self._status.get("baseline", {})
        self.baseline_label.setText(t("advanced.baseline_summary", behaviors=baseline.get("behaviors", 0), observations=baseline.get("observations", 0)))
        self.suppression_label.setText(t("advanced.suppression_count", count=len(self._status.get("suppressions", []))))
        self.case_table.setRowCount(0)
        for item in cases:
            row = self.case_table.rowCount(); self.case_table.insertRow(row)
            values = (item.get("title", ""), item.get("subject", ""), item.get("state", ""), fmt_ts(item.get("updated_ts", 0)))
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, item.get("case_id"))
                self.case_table.setItem(row, col, cell)
        self.fleet_table.setRowCount(0)
        for item in endpoints:
            row = self.fleet_table.rowCount(); self.fleet_table.insertRow(row)
            values = (item.get("display_name", ""), item.get("role", ""), item.get("certificate_fingerprint", ""))
            for col, value in enumerate(values): self.fleet_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.lab_table.setRowCount(0)
        for item in self._status.get("lab", []):
            row = self.lab_table.rowCount(); self.lab_table.insertRow(row)
            values = (item.get("id", ""), item.get("isolation", ""), ", ".join(item.get("validates", [])))
            for col, value in enumerate(values): self.lab_table.setItem(row, col, QTableWidgetItem(str(value)))
        self._render_search()


class AssessmentTab(QWidget, I18nMixin):
    """Safe pipeline validation and historical coverage in one screen."""

    def __init__(self, store: Store, socket_client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.store, self.socket_client = store, socket_client
        self._result: dict = {}
        self._coverage: dict = {}
        layout = tab_layout(self)

        self.title_label = QLabel()
        self.title_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.bind(lambda: self.title_label.setText(t("assessment.title")))
        layout.addWidget(self.title_label)
        self.sub_label = QLabel()
        self.sub_label.setWordWrap(True)
        self.sub_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        self.bind(lambda: self.sub_label.setText(t("assessment.sub")))
        layout.addWidget(self.sub_label)

        controls = row_layout()
        self.run_btn = QPushButton()
        self.bind(lambda: self.run_btn.setText(t("assessment.run")))
        self.run_btn.clicked.connect(self._run)
        controls.addWidget(self.run_btn)
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"color: {theme.TEXT_DIM};")
        controls.addWidget(self.status_label)
        controls.addStretch()
        layout.addLayout(controls)

        tiles = row_layout()
        self._tile_values = {}
        for key, color in (
            ("passed", theme.STATUS_COLOR["ok"]),
            ("failed", theme.SEVERITY_COLOR["critical"]),
            ("inconclusive", theme.SEVERITY_COLOR["warning"]),
            ("coverage", theme.ACCENT),
        ):
            frame, label, value = make_tile(color)
            self.bind(lambda label=label, key=key: label.setText(t(f"assessment.{key}")))
            value.setText("0%" if key == "coverage" else "0")
            self._tile_values[key] = value
            tiles.addWidget(frame)
        layout.addLayout(tiles)

        self.table = QTableWidget(0, 4)
        self.bind(lambda: self.table.setHorizontalHeaderLabels([
            t("assessment.col_test"), t("assessment.col_status"),
            t("assessment.col_latency"), t("assessment.col_assertions"),
        ]))
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        history = self.store.recent_assessments(limit=1)
        if history:
            self._result = history[0]
        self.bind(self._render)

    def _run(self) -> None:
        if self.socket_client.send_command({"cmd": "assessment_run_default"}):
            self.run_btn.setEnabled(False)
            self.status_label.setText(t("assessment.running"))

    def on_status(self, data: dict) -> None:
        status = data.get("status")
        if status == "running":
            self.run_btn.setEnabled(False)
            self.status_label.setText(t("assessment.running"))
        elif status == "done":
            self.run_btn.setEnabled(True)
            self._result = data.get("result", {})
            self._coverage = data.get("coverage", {})
            self.status_label.setText(t("assessment.done", time=fmt_ts(time.time())))
            self._render()
        elif status == "error":
            self.run_btn.setEnabled(True)
            self.status_label.setText(t("assessment.error", error=data.get("error", "")))

    def on_history(self, data: dict) -> None:
        sessions = data.get("sessions") or []
        if sessions and not self._result:
            self._result = sessions[0]
            self._render()

    def _render(self) -> None:
        results = self._result.get("results", [])
        if results and not self._coverage:
            self._coverage = assessment_coverage(self._result)
        for status in ("passed", "failed", "inconclusive"):
            self._tile_values[status].setText(str(sum(item.get("status") == status for item in results)))
        self._tile_values["coverage"].setText(f"{self._coverage.get('rule_coverage_percent', 0):.1f}%")
        self.table.setRowCount(0)
        if not results:
            self.table.insertRow(0)
            self.table.setItem(0, 0, QTableWidgetItem(t("assessment.no_results")))
            self.table.setSpan(0, 0, 1, 4)
            if not self.status_label.text():
                self.status_label.setText(t("assessment.ready"))
            return
        for result in results:
            row = self.table.rowCount()
            self.table.insertRow(row)
            status = result.get("status", "inconclusive")
            assertions = result.get("assertions", [])
            passed = sum(bool(item.get("passed")) for item in assertions)
            latency = result.get("latency_ms")
            values = (
                result.get("test_id", ""), t(f"assessment.status.{status}"),
                t("assessment.latency_fmt", value=latency) if latency is not None else "—",
                t("assessment.assertions_fmt", passed=passed, total=len(assertions)),
            )
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))


class HelpTab(QWidget, I18nMixin):
    """Bilingual in-app guide; no network or external browser required."""

    SECTIONS = (
        ("help.welcome_title", "help.welcome_body"),
        ("help.navigation_title", "help.navigation_body"),
        ("help.incident_title", "help.incident_body"),
        ("help.advanced_title", "help.advanced_body"),
        ("help.assessment_title", "help.assessment_body"),
        ("help.response_title", "help.response_body"),
        ("help.ai_title", "help.ai_body"),
        ("help.tools_title", "help.tools_body"),
        ("help.troubleshoot_title", "help.troubleshoot_body"),
        ("help.safety_title", "help.safety_body"),
    )

    def __init__(self) -> None:
        super().__init__()
        self._init_i18n()
        layout = tab_layout(self)

        header = QLabel()
        header.setStyleSheet("font-size: 20px; font-weight: 700;")
        self.bind(lambda: header.setText(f"{t('nav.help')} — Shield {__version__}"))
        layout.addWidget(header)

        for title_key, body_key in self.SECTIONS:
            frame = QFrame()
            frame.setObjectName("tile")
            section = QVBoxLayout(frame)
            section.setContentsMargins(16, 14, 16, 14)
            title = QLabel()
            title.setStyleSheet("font-size: 15px; font-weight: 700;")
            body = QLabel()
            body.setWordWrap(True)
            body.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            body.setStyleSheet(f"color: {theme.TEXT_DIM}; line-height: 1.4;")
            self.bind(lambda label=title, key=title_key: label.setText(t(key)))
            self.bind(lambda label=body, key=body_key: label.setText(t(key)))
            section.addWidget(title)
            section.addWidget(body)
            layout.addWidget(frame)
        layout.addStretch()


class MonitoringControl(QWidget, I18nMixin):
    """Công tắc tắt/tạm dừng giám sát, nằm trên thanh tiêu đề nên thấy được từ
    MỌI tab.

    Vì sao đặt ở header chứ không nhét vào Cài đặt: lúc cần tắt gấp — đang ở
    mạng trường học, mạng cơ quan, mạng khách sạn — người dùng không có thời
    gian đi tìm. Nút phải ở ngay trước mắt.

    Ba mức tương ứng `shield/agent/switch.py`:
      - active_scan: arp-scan/nmap/self-audit/router poll/né tránh — thứ khiến
        IT của trường đánh dấu máy này đang quét mạng.
      - capture: tcpdump theo host + tarpit (mở cổng lắng nghe).
      - passive: sniff và đọc log — không phát ra gói nào.
    """

    def __init__(self, client: SocketClient) -> None:
        super().__init__()
        self._init_i18n()
        self.client = client
        self._state: dict = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Gán TRƯỚC mọi self.bind(): bind() gọi hàm render ngay lập tức, nên
        # thuộc tính nào hàm đó đọc cũng phải tồn tại từ trước.
        self._agent_online = True
        self.state_badge = QLabel()
        self.state_badge.setObjectName("monitoringBadge")
        layout.addWidget(self.state_badge)

        self.pause_button = QToolButton()
        self.pause_button.setObjectName("monitoringPause")
        self.pause_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.pause_menu = QMenu(self.pause_button)
        self.pause_button.setMenu(self.pause_menu)
        layout.addWidget(self.pause_button)

        self.shutdown_button = QPushButton()
        self.shutdown_button.setObjectName("monitoringShutdown")
        self.shutdown_button.clicked.connect(self._confirm_shutdown)
        layout.addWidget(self.shutdown_button)

        # Nút bật lại. Không có nó thì "Tắt Shield" là một ngõ cụt: agent chết
        # nên không còn socket, mà mọi lệnh của app đều đi qua socket đó — bấm
        # tắt xong là hết đường bật lại từ trong ứng dụng.
        #
        # Bật lại cần quyền root nên đi qua pkexec: polkit sẽ hỏi mật khẩu. Đó
        # là điều đúng — dừng giám sát thì người đang ngồi trước máy quyết định
        # được, nhưng bật lại là thao tác hệ thống và hiếm khi làm.
        self.start_button = QPushButton()
        self.start_button.setObjectName("monitoringStart")
        self.start_button.clicked.connect(self._start_agent)
        self.start_button.hide()
        layout.addWidget(self.start_button)

        self.bind(self._rebuild_menu)
        self.bind(self._render_state)

    def set_agent_online(self, online: bool) -> None:
        """Agent chết thì chỉ còn một hành động có nghĩa: bật lại."""
        self._agent_online = online
        self.pause_button.setVisible(online)
        self.shutdown_button.setVisible(online)
        self.start_button.setVisible(not online)
        self._render_state()

    def _start_agent(self) -> None:

        started = QProcess.startDetached(
            "pkexec", ["systemctl", "start", "shield-agent.service"])
        if not started:
            QMessageBox.warning(
                self, t("common.error"), t("switch.start_failed"))

    # --- menu -------------------------------------------------------------
    def _rebuild_menu(self) -> None:
        self.start_button.setText(t("switch.start_btn"))
        self.start_button.setToolTip(t("switch.start_hint"))
        self.pause_button.setText(t("switch.pause_button"))
        self.pause_button.setToolTip(t("switch.pause_tooltip"))
        self.shutdown_button.setText(t("switch.shutdown_button"))
        self.shutdown_button.setToolTip(t("switch.shutdown_tooltip"))
        self.pause_menu.clear()
        for scope, label_key in (("active_scan", "switch.scope_active"), ("all", "switch.scope_all")):
            submenu = self.pause_menu.addMenu(t(label_key))
            for seconds, duration_key in (
                (900, "switch.for_15m"), (3600, "switch.for_1h"),
                (28800, "switch.for_8h"), (None, "switch.until_resumed"),
            ):
                action = submenu.addAction(t(duration_key))
                action.triggered.connect(
                    lambda _checked=False, s=scope, d=seconds: self._pause(s, d)
                )
        self.pause_menu.addSeparator()
        resume = self.pause_menu.addAction(t("switch.resume_all"))
        resume.triggered.connect(lambda _checked=False: self._resume())

    # --- gửi lệnh ---------------------------------------------------------
    def _pause(self, scope: str, duration_s: int | None) -> None:
        command = {"cmd": "pause_monitoring", "scope": scope, "reason": t("switch.reason_manual")}
        if duration_s is not None:
            command["duration_s"] = duration_s
        self.client.send_command(command)

    def _resume(self) -> None:
        self.client.send_command({"cmd": "resume_monitoring", "scope": "all"})

    def _confirm_shutdown(self) -> None:
        answer = QMessageBox.question(
            self, t("switch.shutdown_confirm_title"), t("switch.shutdown_confirm_body"),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.client.send_command({"cmd": "shutdown_agent", "reason": t("switch.reason_manual")})

    # --- trạng thái -------------------------------------------------------
    def apply_state(self, state: dict) -> None:
        self._state = state or {}
        self._render_state()

    def _render_state(self) -> None:
        if not self._agent_online:
            # Agent đã tắt: đừng hiện "đang chạy" chỉ vì trạng thái cuối cùng
            # nhận được nói vậy. Đó là dữ liệu chết trình bày như đang sống.
            self.state_badge.setText(t("switch.state_agent_off"))
            self.state_badge.setProperty("paused", True)
            self.state_badge.setToolTip(t("switch.state_agent_off_hint"))
            self.state_badge.style().unpolish(self.state_badge)
            self.state_badge.style().polish(self.state_badge)
            return
        paused = set(self._state.get("paused", []))
        if not paused:
            self.state_badge.setText(t("switch.state_running"))
            self.state_badge.setProperty("paused", False)
        elif paused >= {"active_scan", "capture", "passive"}:
            self.state_badge.setText(t("switch.state_all_paused"))
            self.state_badge.setProperty("paused", True)
        else:
            self.state_badge.setText(t("switch.state_partial", scopes=", ".join(sorted(paused))))
            self.state_badge.setProperty("paused", True)
        resume_ts = [v for v in (self._state.get("resume_ts") or {}).values() if v]
        if paused and resume_ts:
            remaining = max(0, int(min(resume_ts) - time.time()))
            self.state_badge.setToolTip(t("switch.resumes_in", minutes=max(1, remaining // 60)))
        else:
            self.state_badge.setToolTip(t("switch.pause_tooltip"))
        self.state_badge.style().unpolish(self.state_badge)
        self.state_badge.style().polish(self.state_badge)


def _open_store_for_ui(attempts: int = 5, delay_s: float = 1.0) -> Store:
    """Mở database ở chế độ không đổi schema, thử lại khi agent đang bận.

    Agent giữ khoá ghi trong lúc migrate hoặc sao lưu. Đó là trạng thái tạm và
    bình thường — nhưng nếu giao diện sập vì nó, người dùng thấy một traceback
    ngay lúc vừa nâng cấp xong, và điều đó trông y hệt một bản cài hỏng.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return Store(allow_migration=False)
        except sqlite3.OperationalError as exc:
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise SystemExit(
        f"Không mở được database Shield: {last}\n"
        "Agent có thể đang nâng cấp database. Đợi một phút rồi mở lại."
    )


class ElidedLabel(QLabel):
    """Nhãn tự rút gọn Ở GIỮA khi hết chỗ, và giữ nguyên văn trong tooltip.

    `QLabel` thường cắt cứng phần thừa: ở cửa sổ 1000 px thanh tiêu đề hiện
    "ZUKEN SHIELD  ver 2.1 Alpha  •  Create" — cụt giữa chữ, không dấu `…`, và
    không có cách nào đọc lại phần bị mất. Người dùng không phân biệt được
    "chỗ này hết chỗ" với "phần mềm hỏng".

    Rút gọn ở GIỮA chứ không ở cuối là có chủ ý: hai đầu chuỗi là hai thứ phải
    còn lại — tên sản phẩm và dòng ghi công tác giả. Cắt từ cuối sẽ nuốt đúng
    phần ghi công.
    """

    def __init__(self, text: str = "") -> None:
        super().__init__(text)
        self._full = text
        self.setToolTip(text)
        # `Preferred`, KHÔNG phải `Ignored`: `Ignored` bỏ luôn `sizeHint()` nên
        # nhãn co về mức tối thiểu ở MỌI bề rộng — kể cả khi màn hình thừa chỗ.
        # Thứ cần là "dùng đủ chỗ khi có, nhường khi thiếu", và đó là
        # `Preferred` cộng một `minimumSizeHint` nhỏ.
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)

    def setText(self, text: str) -> None:  # noqa: N802 — API của Qt
        self._full = text
        self.setToolTip(text)
        self._render()

    def resizeEvent(self, event) -> None:  # noqa: N802 — API của Qt
        super().resizeEvent(event)
        self._render()

    def _render(self) -> None:
        metrics = self.fontMetrics()
        available = max(0, self.width() - 2)
        elided = metrics.elidedText(self._full, Qt.TextElideMode.ElideMiddle, available)
        QLabel.setText(self, elided)

    def sizeHint(self):  # noqa: N802 — API của Qt
        """Chỗ nhãn MUỐN: đủ cho toàn bộ chuỗi."""
        hint = super().sizeHint()
        hint.setWidth(self.fontMetrics().horizontalAdvance(self._full) + 4)
        return hint

    def minimumSizeHint(self):  # noqa: N802 — API của Qt
        """Chỗ nhãn CHẤP NHẬN được. `QLabel` mặc định trả về đúng `sizeHint`
        cho chữ không xuống dòng, nên bố cục không có cách nào co nó lại một
        cách tử tế — nó chỉ bị cắt cứng."""
        hint = super().minimumSizeHint()
        hint.setWidth(min(hint.width(), 140))
        return hint


def _locate_widget(container, target):
    """(chỉ số nhóm, chỉ số trang) của một widget trong cây tab, hoặc None."""
    for outer in range(container.count()):
        section = container.widget(outer)
        if not hasattr(section, "count"):
            continue
        for inner in range(section.count()):
            page = section.widget(inner)
            if page is target or target in page.findChildren(type(target)):
                return outer, inner
    return None


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.resize(1360, 840)
        self.setMinimumSize(1040, 680)

        # Giao diện mở kết nối SQLite riêng và KHÔNG BAO GIỜ đổi schema.
        #
        # Dòng này từng ghi chú "chỉ đọc theo kiến trúc" trong khi vẫn gọi
        # `Store()` với quyền migrate mặc định. Khi lên 2.0, agent migrate
        # database 204 MB lúc khởi động, người dùng mở app đúng lúc đó, và app
        # sập ngay ở dòng này với `database is locked`. Chú thích nói một đằng,
        # mã làm một nẻo — và mã mới là thứ chạy.
        self.store = _open_store_for_ui()
        self.client = SocketClient()

        self.tabs = QTabWidget()
        self.tabs.setObjectName("primaryNav")
        self.tabs.tabBar().setObjectName("primaryNavBar")
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)

        self.overview_tab = OverviewTab(self.store, self.client)
        self.incidents_tab = IncidentsTab(self.store, self.client)
        self.devices_tab = DevicesTab(self.store, self.client)
        self.alerts_tab = AlertsTab(self.client)
        self.alerts_tab.load_from_store(self.store)
        self.traffic_tab = TrafficTab(self.store, self.client)
        self.audit_tab = SelfAuditTab(self.store, self.client)
        self.advanced_tab = AdvancedSecurityTab(self.client, self.store)
        self.assessment_tab = AssessmentTab(self.store, self.client)
        self.log_tab = LogTab()
        self.log_tab.load_from_store(self.store)
        self.evidence_tab = EvidenceTab(self.client)
        self.reports_tab = ReportsTab(self.store, self.client)
        self.dns_tab = DnsTab(self.client)
        self.wifi_tab = WifiPasswordsTab(self.client)
        self.response_tab = ResponseTab(self.store, self.client)
        self.settings_tab = SettingsTab(self.store, self.client)
        self.help_tab = HelpTab()

        self._tab_order = [
            (self.overview_tab, "nav.overview"),
            (self.incidents_tab, "nav.incidents"),
            (self.alerts_tab, "nav.alerts"),
            (self.devices_tab, "nav.devices"),
            (self.traffic_tab, "nav.traffic"),
            (self.log_tab, "nav.log"),
            (self.evidence_tab, "nav.evidence"),
            (self.dns_tab, "nav.dns"),
            (self.wifi_tab, "nav.wifi"),
            (self.advanced_tab, "nav.security_center"),
            (self.assessment_tab, "nav.assessment"),
            (self.audit_tab, "nav.audit"),
            (self.reports_tab, "nav.reports"),
            (self.settings_tab, "nav.settings"),
            (self.help_tab, "nav.help"),
        ]

        self._sections = [
            ("section.operations", "header.operations_desc", [
                (self.overview_tab, "nav.overview"),
                (self.incidents_tab, "nav.incidents"),
                (self.alerts_tab, "nav.alerts"),
            ]),
            ("section.monitoring", "header.monitoring_desc", [
                (self.devices_tab, "nav.devices"),
                (self.traffic_tab, "nav.traffic"),
                (self.log_tab, "nav.log"),
                (self.dns_tab, "nav.dns"),
                (self.wifi_tab, "nav.wifi"),
            ]),
            ("section.investigation", "header.investigation_desc", [
                (self.evidence_tab, "nav.evidence"),
                (self.advanced_tab, "nav.security_center"),
                (self.response_tab, "nav.response"),
                (self.assessment_tab, "nav.assessment"),
                (self.audit_tab, "nav.audit"),
                (self.reports_tab, "nav.reports"),
            ]),
            ("section.management", "header.management_desc", [
                (self.settings_tab, "nav.settings"),
                (self.help_tab, "nav.help"),
            ]),
        ]
        self._section_tabs: list[QTabWidget] = []
        for _section_key, _description_key, pages in self._sections:
            section_tabs = QTabWidget()
            section_tabs.setObjectName("sectionTabs")
            section_tabs.tabBar().setObjectName("sectionNavBar")
            section_tabs.setTabPosition(QTabWidget.TabPosition.North)
            for widget, _page_key in pages:
                section_tabs.addTab(_scrollable(widget), "")
            section_tabs.currentChanged.connect(self._update_page_header)
            self._section_tabs.append(section_tabs)
            self.tabs.addTab(section_tabs, "")
        self.tabs.currentChanged.connect(self._update_page_header)
        self._evidence_location = _locate_widget(self.tabs, self.evidence_tab)

        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)
        central_layout.setSpacing(0)
        header = QFrame()
        header.setObjectName("appHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 14, 22, 14)
        brand = ElidedLabel(f"ZUKEN SHIELD  ver {__display_version__}  •  Created by {__creator__}")
        brand.setObjectName("appBrand")
        header_layout.addWidget(brand)
        header_layout.addSpacing(22)
        page_column = QVBoxLayout()
        page_column.setSpacing(2)
        self.breadcrumb_label = QLabel()
        self.breadcrumb_label.setObjectName("breadcrumb")
        self.page_title_label = QLabel()
        self.page_title_label.setObjectName("pageTitle")
        self.page_description_label = QLabel()
        self.page_description_label.setObjectName("pageDescription")
        self.page_description_label.setWordWrap(True)
        page_column.addWidget(self.breadcrumb_label)
        page_column.addWidget(self.page_title_label)
        page_column.addWidget(self.page_description_label)
        header_layout.addLayout(page_column, 1)
        self.monitoring_control = MonitoringControl(self.client)
        header_layout.addWidget(self.monitoring_control, alignment=Qt.AlignmentFlag.AlignTop)
        self.connection_badge = QLabel()
        self.connection_badge.setObjectName("connectionBadge")
        header_layout.addWidget(self.connection_badge, alignment=Qt.AlignmentFlag.AlignTop)
        central_layout.addWidget(header)
        # Dải vấn đề: Shield tự nói nó đang hỏng chỗ nào. Đặt trên tab chứ không
        # nằm trong một tab nào, vì thứ này không được phép phải đi tìm mới thấy.
        self.problem_banner = QLabel()
        self.problem_banner.setObjectName("problemBanner")
        self.problem_banner.setWordWrap(True)
        self.problem_banner.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.problem_banner.hide()
        central_layout.addWidget(self.problem_banner)
        central_layout.addWidget(self.tabs, 1)
        self._retranslate_tab_bar()

        self.devices_tab.audit_requested.connect(self._on_audit_requested)
        self.settings_tab.language_changed.connect(self._on_language_changed)
        self.settings_tab.appearance_changed.connect(self._on_appearance_changed)

        self.setCentralWidget(central)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(t("status.connecting"))
        self.setWindowTitle(t("app.title"))

        self._baseline_prompted = False
        self._connected = False
        self._health_status: dict = {}
        self.connection_badge.setText(t("header.agent_offline"))
        self.connection_badge.setProperty("online", False)

        self.client.message_received.connect(self.on_message)
        self.client.connection_status.connect(self.on_connection_status)
        self.client.start()

    def _retranslate_tab_bar(self) -> None:
        for section_index, (section_key, _description_key, pages) in enumerate(self._sections):
            self.tabs.setTabText(section_index, t(section_key))
            section_tabs = self._section_tabs[section_index]
            for page_index, (_widget, page_key) in enumerate(pages):
                section_tabs.setTabText(page_index, t(page_key))
        self._update_page_header()

    def open_evidence(self, event_id: str) -> None:
        """Từ báo cáo sự cố -> màn hình Expert Evidence ĐÃ CÓ.

        Không dựng màn hình bằng chứng thứ hai: `EvidenceTab` đã biết cách hiện
        một sự kiện, gồm cả câu trả lời khi Shield không giữ payload gốc.
        """
        location = getattr(self, "_evidence_location", None)
        if location is not None:
            outer, inner = location
            self.tabs.setCurrentIndex(outer)
            section = self.tabs.widget(outer)
            if hasattr(section, "setCurrentIndex"):
                section.setCurrentIndex(inner)
        self.evidence_tab.open_event(event_id)

    def _update_page_header(self, _index: int = 0) -> None:
        section_index = max(0, self.tabs.currentIndex())
        if section_index >= len(self._sections):
            return
        section_key, description_key, pages = self._sections[section_index]
        page_index = max(0, self._section_tabs[section_index].currentIndex())
        page_key = pages[min(page_index, len(pages) - 1)][1]
        self.breadcrumb_label.setText(t("header.location", section=t(section_key), page=t(page_key)))
        self.page_title_label.setText(t(page_key))
        self.page_description_label.setText(t(description_key))

    def _show_agent_problems(self, problems: list) -> None:
        """Hiện vấn đề của chính Shield. Nội dung giữ nguyên tiếng Anh.

        Đây là cùng câu chữ được gửi ra notify-send và Telegram — người đọc
        thông báo trên điện thoại rồi mở app phải thấy đúng một câu, không phải
        hai bản dịch khác nhau của cùng một sự việc.
        """
        if not problems:
            self.problem_banner.hide()
            return
        worst = "critical" if any(p.get("severity") == "critical" for p in problems) else "warning"
        lines = [f"• {p.get('title', '')} — {p.get('remedy', '')}" for p in problems[:5]]
        if len(problems) > 5:
            lines.append(f"… and {len(problems) - 5} more")
        self.problem_banner.setProperty("severity", worst)
        self.problem_banner.setText(
            t("problems.banner", count=len(problems)) + "\n" + "\n".join(lines)
        )
        self.problem_banner.style().unpolish(self.problem_banner)
        self.problem_banner.style().polish(self.problem_banner)
        self.problem_banner.show()

    def _on_language_changed(self, lang: str) -> None:
        set_lang(lang)
        self.setWindowTitle(t("app.title"))
        self._retranslate_tab_bar()
        for widget, _key in self._tab_order:
            widget.retranslate()
        self.monitoring_control.retranslate()
        self.connection_badge.setText(t("header.agent_online" if self._connected else "header.agent_offline"))
        self.status.showMessage(t("status.connected") if self._connected else t("status.disconnected"))

    def _on_appearance_changed(self, mode: str) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(theme.STYLES.get(mode, theme.QSS))

    def _on_audit_requested(self, ip: str) -> None:
        for section_index, (_section_key, _description_key, pages) in enumerate(self._sections):
            widgets = [widget for widget, _key in pages]
            if self.audit_tab in widgets:
                self.tabs.setCurrentIndex(section_index)
                self._section_tabs[section_index].setCurrentIndex(widgets.index(self.audit_tab))
                break
        self.audit_tab.request_scan(ip)

    def on_connection_status(self, connected: bool) -> None:
        self._connected = connected
        self.connection_badge.setText(t("header.agent_online" if connected else "header.agent_offline"))
        self.connection_badge.setProperty("online", connected)
        self.monitoring_control.set_agent_online(connected)
        # Mất agent nghĩa là mọi con số trên màn hình đã ngừng cập nhật. Để
        # chúng đứng nguyên trông y hệt đang chạy — đó mới là chỗ nguy hiểm.
        self.overview_tab.mark_stale(not connected)
        self.connection_badge.style().unpolish(self.connection_badge)
        self.connection_badge.style().polish(self.connection_badge)
        self.status.showMessage(t("status.connected") if connected else t("status.disconnected"))
        if connected:
            # Kéo hiện trạng DNS ngay khi nối được agent — nếu chờ chu kỳ
            # 5 phút của dns_monitor_loop thì tab DNS trống trơn lúc mới mở.
            self.client.send_command({"cmd": "dns_status_now"})
            # Tương tự cho né tránh — quan trọng hơn cả DNS: nếu agent restart
            # lúc tính năng đang bật (baseline vẫn "1"), UI phải hiện đúng
            # trạng thái ngay, không để người dùng tưởng đã tắt.
            self.client.send_command({"cmd": "evasion_status_now"})
            self.client.send_command({"cmd": "tarpit_status_now"})
            self.client.send_command({"cmd": "health_status_now"})
            self.client.send_command({"cmd": "assessment_history_now"})
            self.client.send_command({"cmd": "advanced_status_now"})
            self.client.send_command({"cmd": "backup_status_now"})
            # Cấu hình xuất log nằm ở agent, không ở UI: người dùng có thể đã
            # bật nó từ một phiên khác, hoặc từ máy khác qua cùng agent. Hỏi
            # lại thay vì hiện mặc định "tắt" — hiện sai nghĩa là họ tưởng
            # chưa bật rồi bật lại lần nữa lên một thư mục khác.
            self.client.send_command({"cmd": "get_log_export_status"})
            self.client.send_command({"cmd": "response_jobs_now"})
            self.client.send_command({"cmd": "ai_kill_switch_now"})
            self.client.send_command({"cmd": "response_kill_switch_now"})
            # Trạng thái công tắc phải đúng ngay lần vẽ đầu: nếu agent đang
            # tạm dừng mà header hiện "Đang giám sát" thì người dùng tưởng
            # mình vẫn được bảo vệ.
            self.client.send_command({"cmd": "monitoring_status_now"})

    def on_message(self, msg: dict) -> None:
        msg_type = msg.get("type")
        if msg_type == "alert":
            alert = msg["data"]
            self.alerts_tab.prepend_alert(alert)
            self.overview_tab.refresh()
            self.incidents_tab.refresh()
            self.reports_tab.refresh()
            if alert.get("rule_id") in ("DEVICE_NEW", "DEVICE_MAC_RANDOMIZED"):
                self.devices_tab.refresh()
        elif msg_type == "baseline_needed":
            self._handle_baseline_needed(msg["data"])
        elif msg_type == "traffic_bytes":
            self.traffic_tab.on_traffic(msg["data"])
        elif msg_type == "traffic_protocols":
            self.traffic_tab.on_traffic_protocols(msg["data"])
        elif msg_type == "log_event":
            self.log_tab.prepend_event(msg["data"])
        elif msg_type == "evidence_event":
            self.evidence_tab.on_event(msg["data"])
        elif msg_type == "expert_search_events_result":
            self.evidence_tab.on_search_result(msg["data"])
        elif msg_type == "expert_get_event_result":
            self.evidence_tab.on_event_detail(msg["data"])
        elif msg_type == "blocks_updated":
            self.settings_tab.refresh()
            self.overview_tab.refresh()
        elif msg_type == "scan_status":
            self.devices_tab.on_scan_status(msg["data"])
        elif msg_type == "devices_updated":
            self.devices_tab.refresh()
        elif msg_type == "self_audit_result":
            self.audit_tab.on_self_audit_result(msg["data"])
        elif msg_type == "assessment_status":
            self.assessment_tab.on_status(msg["data"])
        elif msg_type == "assessment_history":
            self.assessment_tab.on_history(msg["data"])
        elif msg_type == "advanced_status":
            self.advanced_tab.on_status(msg["data"])
        elif msg_type == "backup_status":
            self.settings_tab.on_backup_status(msg["data"])
        elif msg_type == "security_search_result":
            self.advanced_tab.on_search(msg["data"])
        elif msg_type in {"case_updated", "fleet_updated", "suppression_updated"}:
            self.client.send_command({"cmd": "advanced_status_now"})
        elif msg_type == "authorized_ranges_updated":
            self.settings_tab.on_authorized_ranges_updated(msg["data"])
        elif msg_type == "authorized_range_error":
            self.settings_tab.on_authorized_range_error(msg["data"])
        elif msg_type == "router_traffic_updated":
            self.traffic_tab.on_router_traffic(msg["data"])
        elif msg_type == "router_backend_error":
            self.traffic_tab.on_router_backend_error(msg["data"])
        elif msg_type == "gateway_ip_detected":
            self.traffic_tab.on_gateway_ip_detected(msg["data"])
        elif msg_type == "wifi_passwords_result":
            self.wifi_tab.on_wifi_passwords_result(msg["data"])
        elif msg_type == "dns_status":
            self.dns_tab.on_dns_status(msg["data"])
        elif msg_type == "dns_hijack_result":
            self.dns_tab.on_dns_hijack_result(msg["data"])
        elif msg_type == "dns_error":
            QMessageBox.warning(self, t("nav.dns"), error_message(msg["data"]))
        elif msg_type == "evasion_status":
            self.settings_tab.on_evasion_status(msg["data"])
        elif msg_type == "evasion_error":
            self.settings_tab.on_evasion_error(msg["data"])
        elif msg_type == "tarpit_status":
            self.settings_tab.on_tarpit_status(msg["data"])
        elif msg_type == "tarpit_connection":
            self.settings_tab.on_tarpit_connection(msg["data"])
        elif msg_type == "tarpit_error":
            self.settings_tab.on_tarpit_error(msg["data"])
        elif msg_type == "response_result":
            data = msg["data"]
            self.alerts_tab.on_response_result(data)
            summary = f"{data.get('action', '')}: {data.get('message', '')}"
            if data.get("ok"):
                self.status.showMessage(summary, 10000)
            else:
                QMessageBox.warning(self, t("respqueue.title"), summary)
        elif msg_type == "analysis_result":
            data = msg["data"]
            details = "\n".join(f"• {item}" for item in data.get("observations", []))
            QMessageBox.information(
                self, t("reports.analysis_title"),
                f"{data.get('summary', '')}\n\n{details}".strip(),
            )
        elif msg_type == "health_status":
            self._health_status = msg["data"]
            components = self._health_status.get("components", {})
            active = sum(bool(value) for value in components.values())
            self.status.showMessage(t("status.connected_health", active=active, total=len(components)))
        elif msg_type == "runtime_health":
            self.advanced_tab.on_status(msg["data"])
        elif msg_type == "incidents_updated":
            incidents = (msg.get("data") or {}).get("incidents", [])
            self.incidents_tab.on_incidents(incidents)
            self.status.showMessage(t("incidents.updated", count=len(incidents)))

        elif msg_type == "isolation_state":
            data = msg.get("data") or {}
            self.status.showMessage(
                t("isolation.renewed", target=data.get("target", ""))
                if data.get("renewed") else t("isolation.not_armed", target=data.get("target", ""))
            )

        elif msg_type == "scan_session_reset":
            data = msg.get("data") or {}
            self.devices_tab.refresh()
            self.overview_tab.refresh()
            self.status.showMessage(t("settings.rescan_done",
                                      count=data.get("devices_removed", 0)))

        elif msg_type == "live_stats":
            self.overview_tab.on_live_stats(msg.get("data") or {})

        elif msg_type == "log_export_status":
            self.settings_tab.on_log_export_status(msg.get("data") or {})

        elif msg_type == "investigation_result":
            self.incidents_tab.on_investigation(msg.get("data") or {})

        elif msg_type == "ai_kill_switch":
            self.incidents_tab.on_ai_kill_switch(msg.get("data") or {})

        elif msg_type == "ai_explanation_state":
            self.incidents_tab.on_ai_explanation_state(msg.get("data") or {})

        elif msg_type == "chat_state":
            self.incidents_tab.on_chat_state(msg.get("data") or {})

        elif msg_type == "response_jobs":
            self.response_tab.on_jobs(msg.get("data") or {})

        elif msg_type == "response_job_detail":
            self.response_tab.on_job_detail(msg.get("data") or {})

        elif msg_type == "response_kill_switch":
            self.response_tab.on_kill_switch(msg.get("data") or {})

        elif msg_type == "agent_problems":
            self._show_agent_problems((msg.get("data") or {}).get("problems") or [])

        elif msg_type == "monitoring_state":
            data = msg.get("data") or {}
            self.monitoring_control.apply_state(data)
            paused = data.get("paused") or []
            self.status.showMessage(
                t("switch.status_paused", scopes=", ".join(paused)) if paused
                else t("switch.status_running")
            )

        elif msg_type == "agent_shutting_down":
            self.status.showMessage(t("switch.status_shutting_down"))
            QMessageBox.information(self, t("switch.shutdown_done_title"),
                                    t("switch.shutdown_done_body"))

        elif msg_type == "watch_status":
            if (msg.get("data") or {}).get("paused"):
                self.status.showMessage(t("switch.status_capture_paused"))

        elif msg_type == "command_error":
            QMessageBox.warning(self, t("common.error"), str(msg.get("data", {}).get("error", "Unknown error")))

    def _handle_baseline_needed(self, data: dict) -> None:
        if self._baseline_prompted:
            return
        self._baseline_prompted = True

        gw_ip, gw_mac = data.get("gw_ip"), data.get("gw_mac")
        reply = QMessageBox.question(
            self, t("baseline.dialog_title"),
            t("baseline.dialog_body", gw_mac=gw_mac, gw_ip=gw_ip),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.client.send_command({"cmd": "set_gateway_baseline", "gw_ip": gw_ip, "gw_mac": gw_mac})
            self.status.showMessage(t("baseline.confirmed", gw_ip=gw_ip, gw_mac=gw_mac))
        else:
            self.status.showMessage(t("baseline.declined"))

    def closeEvent(self, event) -> None:
        # Ngắt kết nối trước khi dừng thread: nếu không, một message đã được
        # worker thread emit() ngay trước khi thoát run() vẫn còn nằm trong
        # hàng đợi sự kiện Qt và sẽ được xử lý SAU khi store đã đóng, gây
        # "Cannot operate on a closed database" (xem shield/ui/client.py).
        self.client.message_received.disconnect(self.on_message)
        self.client.stop()
        self.store.close()
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(theme.QSS)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
