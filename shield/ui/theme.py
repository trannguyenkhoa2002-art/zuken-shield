"""Bảng màu & QSS dùng chung toàn UI.

Nguyên tắc từ KE-HOACH-SHIELD.md mục 4: "chỉ 3 mức màu cảnh báo (xám / vàng /
đỏ). Nếu mọi thứ đều đỏ thì không còn gì là đỏ." Áp dụng nghiêm: SEVERITY_COLOR
là nơi DUY NHẤT định nghĩa 3 màu này — mọi tab dùng lại từ đây, không tự chế
màu riêng, để "đỏ" luôn có nghĩa là critical ở bất cứ đâu trong app.

Giao diện tối trung tính: chữ chính gần trắng để đọc lâu không mỏi, xanh lá
chỉ dành cho trạng thái bình thường và điểm nhấn. Vàng/đỏ vì thế vẫn nổi bật
mà màn hình không bị phủ một màu như giao diện terminal cũ.

Khoảng cách (padding/margin/spacing) cố tình rộng tay: app hiển thị bảng dày
đặc số liệu, chật quá thì đọc rất mệt khi phải nhìn lâu.
"""

from __future__ import annotations

# --- Màu nền tảng (chỉ dùng để dựng khung UI, không mang nghĩa cảnh báo) ---
BG = "#0b0f14"
BG_ALT = "#111820"
BG_ELEVATED = "#18212b"
BORDER = "#2a3948"
TEXT = "#e7edf3"
TEXT_DIM = "#98a8b8"
ACCENT = "#4ade80"

# Font mono cho toàn app — danh sách fallback để chạy được cả khi máy không
# có font ưa thích (Ubuntu/Kali đều có DejaVu Sans Mono sẵn).
FONT_STACK = 'Inter, "Noto Sans", "DejaVu Sans", sans-serif'

# --- 3 màu cảnh báo — nguồn sự thật duy nhất, dùng lại ở mọi tab ---
SEVERITY_COLOR = {"info": TEXT_DIM, "warning": "#ffc043", "critical": "#ff5f56"}
SEVERITY_BG = {"info": "transparent", "warning": "#2a2110", "critical": "#2b1414"}
SEVERITY_VI = {"info": "Thông tin", "warning": "Cảnh báo", "critical": "Nguy cấp"}

# --- Đèn trạng thái tổng quan (mục 4: "đèn trạng thái lớn") ---
STATUS_COLOR = {"ok": ACCENT, "watching": SEVERITY_COLOR["warning"], "alert": SEVERITY_COLOR["critical"]}
STATUS_VI = {"ok": "Bình thường", "watching": "Đang theo dõi", "alert": "Có cảnh báo"}

# --- Mức rủi ro cổng mở (tab Tự kiểm tra) — dùng lại đúng 3 màu cảnh báo,
# không chế màu riêng: nguy hiểm=đỏ, nên xem lại=vàng, bình thường=xanh. ---
RISK_COLOR = {"danger": SEVERITY_COLOR["critical"], "caution": SEVERITY_COLOR["warning"], "safe": STATUS_COLOR["ok"]}
RISK_BG = {"danger": SEVERITY_BG["critical"], "caution": SEVERITY_BG["warning"], "safe": "transparent"}

QSS = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT};
    font-family: {FONT_STACK};
    font-size: 13px;
}}
QMainWindow {{ background-color: {BG}; }}

QTabWidget::pane {{
    border: 1px solid {BORDER};
    background: {BG};
    top: -1px;
    padding: 4px;
}}
QTabBar::tab {{
    background: {BG_ALT};
    color: {TEXT_DIM};
    padding: 13px 20px;
    border: none;
    border-left: 3px solid transparent;
    min-width: 128px;
    text-align: left;
}}
QTabBar::tab:selected {{
    background: {BG_ELEVATED};
    color: {ACCENT};
    border-left: 3px solid {ACCENT};
    font-weight: 700;
}}
QTabBar::tab:hover:!selected {{ color: {TEXT}; background: {BG_ELEVATED}; }}

QTableWidget {{
    background: {BG};
    alternate-background-color: {BG_ALT};
    gridline-color: {BORDER};
    border: 1px solid {BORDER};
    selection-background-color: {BORDER};
    selection-color: {ACCENT};
}}
QTableWidget::item {{ padding: 7px 9px; }}
QHeaderView::section {{
    background: {BG_ALT};
    color: {TEXT_DIM};
    padding: 10px 9px;
    border: none;
    border-bottom: 1px solid {BORDER};
    font-weight: 700;
    text-transform: uppercase;
}}
QTableCornerButton::section {{ background: {BG_ALT}; border: none; }}

QPushButton {{
    background: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 3px;
    padding: 8px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background: #20303d; border-color: {ACCENT}; color: {ACCENT}; }}
QPushButton:pressed {{ background: {ACCENT}; color: {BG}; }}
QPushButton:disabled {{ color: #667788; border-color: #202d39; }}

QStatusBar {{
    background: {BG_ALT};
    color: {TEXT_DIM};
    border-top: 1px solid {BORDER};
    padding: 3px 8px;
}}
QLabel {{ color: {TEXT}; }}

QDialog {{ background: {BG}; }}
QMessageBox {{ background: {BG}; }}
QMessageBox QLabel {{ color: {TEXT}; }}

QScrollBar:vertical {{ background: {BG}; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 24px; }}
QScrollBar::handle:vertical:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: {BG}; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 5px; min-width: 24px; }}
QScrollBar::handle:horizontal:hover {{ background: {ACCENT}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
QScrollArea {{ border: none; }}

/* --- Tile số liệu (Tổng quan/Tự kiểm tra/Báo cáo) --- */
QFrame#tile {{
    background: {BG_ALT};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 6px;
}}
QLabel#tileLabel {{
    color: {TEXT_DIM};
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}}
QLabel#tileValue {{ font-size: 24px; font-weight: 700; color: {ACCENT}; }}

/* --- Badge mức rủi ro (tab Tự kiểm tra) — dynamic property "risk" set qua
setProperty(), không hard-code màu trong widget code (1 nguồn duy nhất). --- */
QLabel[risk="danger"] {{ color: {RISK_COLOR["danger"]}; font-weight: 700; }}
QLabel[risk="caution"] {{ color: {RISK_COLOR["caution"]}; font-weight: 700; }}
QLabel[risk="safe"] {{ color: {RISK_COLOR["safe"]}; font-weight: 700; }}

QComboBox {{
    background: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 3px;
    padding: 6px 10px;
    min-height: 20px;
}}
QComboBox:hover {{ border-color: {ACCENT}; }}
QComboBox QAbstractItemView {{
    background: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    selection-background-color: {BORDER};
    selection-color: {ACCENT};
}}

QLineEdit {{
    background: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {BORDER};
    border-radius: 3px;
    padding: 7px 10px;
    selection-background-color: {BORDER};
    selection-color: {ACCENT};
}}
QLineEdit:focus {{ border-color: {ACCENT}; }}
QLineEdit::placeholder {{ color: #667788; }}

QCheckBox {{ color: {TEXT}; spacing: 8px; padding: 3px 0; }}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border: 1px solid {BORDER};
    border-radius: 3px;
    background: {BG_ELEVATED};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QToolTip {{
    background: {BG_ELEVATED};
    color: {TEXT};
    border: 1px solid {ACCENT};
    padding: 5px 8px;
}}

QFrame#appHeader {{
    background: {BG_ALT};
    border-bottom: 1px solid {BORDER};
}}
QLabel#appBrand {{
    color: {ACCENT};
    font-size: 17px;
    font-weight: 800;
    letter-spacing: 1px;
}}
QLabel#breadcrumb {{ color: {TEXT_DIM}; font-size: 11px; font-weight: 600; }}
QLabel#pageTitle {{ color: {TEXT}; font-size: 20px; font-weight: 800; }}
QLabel#pageDescription {{ color: {TEXT_DIM}; font-size: 12px; }}
QLabel#connectionBadge {{
    color: {SEVERITY_COLOR['critical']};
    background: {SEVERITY_BG['critical']};
    border: 1px solid {SEVERITY_COLOR['critical']};
    border-radius: 10px;
    padding: 5px 10px;
    font-weight: 700;
}}
QLabel#connectionBadge[online="true"] {{
    color: {ACCENT};
    background: {BG_ELEVATED};
    border-color: {ACCENT};
}}

/* Công tắc giám sát trên header. Trạng thái "đang chạy" cố ý trung tính, còn
   "đã tạm dừng" tô màu cảnh báo: một Shield đang tắt mà nhìn như đang chạy là
   kiểu hiểu nhầm nguy hiểm nhất mà UI này có thể gây ra. */
QLabel#monitoringBadge {{
    color: {ACCENT};
    background: {BG_ELEVATED};
    border: 1px solid {ACCENT};
    border-radius: 10px;
    padding: 5px 10px;
    font-weight: 700;
}}
QLabel#monitoringBadge[paused="true"] {{
    color: {SEVERITY_COLOR['warning']};
    background: {SEVERITY_BG['warning']};
    border-color: {SEVERITY_COLOR['warning']};
}}
QToolButton#monitoringPause {{
    color: {TEXT};
    background: {BG_ELEVATED};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 6px 12px;
    font-weight: 700;
}}
QToolButton#monitoringPause:hover {{ border-color: {ACCENT}; }}
QPushButton#monitoringShutdown {{
    color: {SEVERITY_COLOR['critical']};
    background: {SEVERITY_BG['critical']};
    border: 1px solid {SEVERITY_COLOR['critical']};
    border-radius: 10px;
    padding: 6px 12px;
    font-weight: 700;
}}
QPushButton#monitoringShutdown:hover {{ background: {SEVERITY_COLOR['critical']}; color: {BG}; }}

QTabWidget#primaryNav::pane {{ border: none; padding: 0; }}
QTabBar#primaryNavBar::tab {{
    min-width: 170px;
    padding: 12px 22px;
    border-left: none;
    border-bottom: 4px solid transparent;
}}
QTabBar#primaryNavBar::tab:selected {{
    border-left: none;
    border-bottom: 4px solid {ACCENT};
}}
QTabBar#sectionNavBar::tab {{
    min-width: 110px;
    padding: 11px 18px;
    border-left: none;
    border-bottom: 3px solid transparent;
}}
QTabBar#sectionNavBar::tab:selected {{
    border-left: none;
    border-bottom: 3px solid {ACCENT};
}}
QTabWidget#sectionTabs::pane {{
    border: none;
    border-top: 1px solid {BORDER};
    padding: 0;
}}
"""


def _recolor(source: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        source = source.replace(old, new)
    return source


LIGHT_QSS = _recolor(QSS, {
    BG: "#f5f7fa", BG_ALT: "#ffffff", BG_ELEVATED: "#e9eef3",
    BORDER: "#b8c4cf", TEXT: "#17212b", TEXT_DIM: "#506274",
    "#20303d": "#dce7ef", "#667788": "#718191",
    SEVERITY_BG["warning"]: "#fff4cc", SEVERITY_BG["critical"]: "#ffe5e5",
})

HIGH_CONTRAST_QSS = _recolor(QSS, {
    BG: "#000000", BG_ALT: "#000000", BG_ELEVATED: "#101010",
    BORDER: "#ffffff", TEXT: "#ffffff", TEXT_DIM: "#ffffff", ACCENT: "#00ff66",
    "#20303d": "#202020", "#667788": "#dddddd",
}) + "\nQWidget { font-size: 15px; } QPushButton:focus, QLineEdit:focus, QComboBox:focus { border: 3px solid #ffff00; }"

STYLES = {"dark": QSS, "light": LIGHT_QSS, "contrast": HIGH_CONTRAST_QSS}
