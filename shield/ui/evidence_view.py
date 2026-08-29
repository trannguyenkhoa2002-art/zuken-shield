"""Dựng nội dung cho tab Expert Evidence — THUẦN, không chạm Qt.

Cùng lý do như `incident_view.py`: máy CI không import được PySide6, mà những
chỗ dễ sai nhất của một màn hình bằng chứng lại kiểm được hoàn toàn không cần
Qt — thứ tự trường, khoá dịch, và câu trả lời khi dữ liệu KHÔNG tồn tại.

Nguyên tắc của file này:

- Không có trường nào do model sinh ra. Không có trường nào được dịch nếu nó
  là dữ liệu (đường dẫn, IP, hash, ID, tên tiến trình).
- Nếu Shield không giữ payload gốc thì nói thẳng ra. KHÔNG dựng lại một "raw"
  giả từ các trường đã chuẩn hoá — một bản dựng lại trông y hệt bản gốc là
  cách chắc chắn nhất để một suy đoán được đọc như bằng chứng.
"""

from __future__ import annotations

# Thứ tự các nhóm trong màn hình chi tiết. Cố định, vì bốn nhóm này có mức
# đáng tin KHÁC HẲN nhau và phải nhìn thấy khác nhau: định danh là sự thật của
# hệ thống lưu trữ, nguồn gốc là thứ quyết định tin được bao nhiêu, dữ liệu đã
# chuẩn hoá là quan sát, còn liên kết là suy ra tất định.
IDENTITY_FIELDS = ("event_id", "ts", "kind")
PROVENANCE_FIELDS = ("source", "origin", "trust", "collector_version",
                     "content_hash", "signature_status", "ts_ingested")


def evidence_detail_rows(event: dict | None, translate, format_ts) -> list[tuple[str, str, str]]:
    """(khoá_nhãn, giá_trị, nhóm). Nhóm để giao diện vẽ tiêu đề phân cách."""
    if not event:
        return [("evidence.not_found", "", "identity")]

    rows: list[tuple[str, str, str]] = []
    for field in IDENTITY_FIELDS:
        value = event.get(field, "")
        if field == "ts":
            value = format_ts(value) if value else ""
        rows.append((f"evidence.field.{field}", str(value or "—"), "identity"))

    for field in PROVENANCE_FIELDS:
        value = event.get(field, "")
        if field == "ts_ingested":
            value = format_ts(value) if value else ""
        rows.append((f"evidence.field.{field}", str(value or "—"), "provenance"))

    # Dữ liệu đã chuẩn hoá: thứ tự khoá CỐ ĐỊNH (đã sắp), để hai lần mở cùng
    # một event cho ra cùng một màn hình.
    for key in sorted(event.get("data") or {}):
        rows.append((key, _flatten(event["data"][key]), "normalized"))

    rows.append(("evidence.alert_ids",
                 ", ".join(str(i) for i in event.get("alert_ids") or ()) or "—", "links"))
    rows.append(("evidence.incident_ids",
                 ", ".join(str(i) for i in event.get("incident_ids") or ()) or "—", "links"))
    graph = event.get("evidence") or {}
    rows.append(("evidence.graph_ref", str(graph.get("evidence_ref") or "—"), "links"))

    # Câu trả lời khi thứ được hỏi KHÔNG tồn tại. Đây là dòng quan trọng nhất
    # của màn hình này.
    rows.append(("evidence.raw_not_retained"
                 if not event.get("raw_retained") else "evidence.raw_available",
                 "", "raw"))
    return rows


def _flatten(value) -> str:
    """Giá trị bất kỳ -> một dòng. KHÔNG cắt bí mật ra: dữ liệu tới đây đã đi
    qua bộ luật che chung ở `EvidenceQueries`."""
    if isinstance(value, (list, tuple)):
        return ", ".join(_flatten(item) for item in value)
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}={_flatten(v)}" for k, v in sorted(value.items())) + "}"
    return str(value)


def event_summary(event: dict) -> str:
    """Một dòng tóm tắt cho bảng kết quả. Ghép từ DỮ LIỆU, không diễn giải.

    Cố ý không có câu văn nào: một bản tóm tắt do máy viết ra sẽ được đọc như
    một kết luận, và màn hình này tồn tại để người ta KHÔNG phải tin kết luận
    nào cả.
    """
    data = event.get("data") or {}
    parts = []
    for key in ("exe", "path", "comm", "remote_ip", "ip", "mac", "user",
                "src_ip", "dst_port", "port", "unit", "message"):
        value = data.get(key)
        if value not in (None, "", []):
            parts.append(f"{key}={_flatten(value)}")
        if len(parts) >= 3:
            break
    return " · ".join(parts) if parts else "—"


def event_subject(event: dict) -> str:
    """Đối tượng của event — cùng khái niệm `subject` mà alert đang dùng."""
    data = event.get("data") or {}
    for key in ("subject", "ip", "remote_ip", "src_ip", "mac", "host", "exe", "path", "unit"):
        value = data.get(key)
        if value not in (None, "", []):
            return _flatten(value)
    return event.get("origin", "") or "—"
