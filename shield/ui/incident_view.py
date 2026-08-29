"""Dựng nội dung bảng "vì sao đây là một sự việc" cho tab Sự việc.

Tách khỏi `shield/ui/__main__.py` vì hai lý do:

1. Máy CI không có libEGL nên không import được PySide6. Logic ở đây là chỗ dễ
   sai nhất của tính năng này (thứ tự dòng, khoá dịch, trạng thái "không có
   dữ liệu") mà lại kiểm được hoàn toàn không cần Qt.
2. Nó phải giữ được một bất biến: bảng này chỉ hiển thị DỮ LIỆU CÓ CẤU TRÚC.
   Ở một module riêng thì "module này có nhận văn xuôi ở đâu không" là câu
   hỏi đọc hết được bằng mắt.
"""

from __future__ import annotations


# Dựng nội dung bảng "vì sao đây là một sự việc" — THUẦN, không chạm Qt.
#
# Tách ra khỏi widget vì đây là chỗ dễ sai nhất và cũng là chỗ khó test nhất
# nếu để lẫn trong Qt: thứ tự dòng, khoá dịch, và trạng thái "không có dữ liệu".
# Ở dạng hàm thuần thì cả ba kiểm được mà không cần dựng QApplication.
#
# Trả về danh sách (khoá_nhãn, giá_trị_đã_hiển_thị). Giá trị là số, danh sách
# rule và mốc thời gian — KHÔNG có trường văn xuôi nào, và ở giai đoạn này
# không có gì do model sinh ra.
def correlation_reason_rows(reasons: list[dict], alert_ids: list[int],
                            translate, format_ts) -> list[tuple[str, str]]:
    if not reasons:
        # Không suy diễn. Sự việc trước v10 không có dữ liệu này, và nói rằng
        # nó "không tồn tại" là câu trả lời đúng duy nhất.
        return [("incidents.reason.legacy", "")]
    rows: list[tuple[str, str]] = []
    for reason in reasons:
        kind = str(reason.get("reason_kind", ""))
        rows.extend([
            ("incidents.reason.kind",
             translate(f"incidents.reason.kind.{kind}") if kind else "—"),
            ("incidents.reason.rule", str(reason.get("rule_id", "")) or "—"),
            ("incidents.reason.window",
             translate("incidents.reason.seconds").format(
                 value=_trim_number(reason.get("window_s", 0)))),
            ("incidents.reason.required",
             ", ".join(str(r) for r in reason.get("required_rules", [])) or "—"),
            ("incidents.reason.observed",
             ", ".join(str(r) for r in reason.get("observed_rules", [])) or "—"),
            ("incidents.reason.counts",
             f"{int(reason.get('min_count', 0))} / {int(reason.get('observed_count', 0))}"),
            ("incidents.reason.first", format_ts(reason.get("first_contributing_ts", 0))),
            ("incidents.reason.last", format_ts(reason.get("last_contributing_ts", 0))),
        ])
    rows.append((
        "incidents.reason.alerts",
        ", ".join(str(i) for i in alert_ids) if alert_ids
        else translate("incidents.reason.no_alert_ids"),
    ))
    return rows


def _trim_number(value) -> str:
    """600.0 -> "600". Một cửa sổ thời gian hiện ra là "600.0 giây" trông như
    một phép đo có phần thập phân, mà nó là một tham số cấu hình."""
    number = float(value or 0)
    return str(int(number)) if number == int(number) else str(number)
