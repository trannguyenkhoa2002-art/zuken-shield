"""Dựng báo cáo sự cố từ dữ liệu CHUẨN TẮC của Shield (Phase 3D, bước C).

Đây là chỗ khuôn báo cáo gặp sản phẩm. Bất biến của cả file: **mọi trường đếm
được hoặc định danh được đến từ `store`, không từ model.** Model — nếu có bật —
chỉ đóng góp ba ô văn xuôi đã qua `OutputValidator`, và ba ô đó bỏ đi được.

Vì thế báo cáo là một TÍNH NĂNG SẢN PHẨM, không phải một tính năng AI: tắt AI
hoàn toàn thì nó vẫn ra đầy đủ.

Ưu tiên định danh cho mức incident, theo đúng ngữ nghĩa đã có chứ không phát
minh heuristic mới:

1. `incidents.correlation_id` — chính là `rule_id` của quy tắc tương quan đã
   sinh ra incident, nên nó tra CÙNG một registry.
2. Nếu correlation_id chưa có ánh xạ: gộp tất định từ các alert đóng góp —
   chọn theo (mức nghiêm trọng giảm dần, rule_id tăng dần). Hai khoá đó không
   phụ thuộc thứ tự duyệt, nên xáo thứ tự alert không đổi kết quả.
3. `UNKNOWN`.

Phát hiện phụ KHÔNG được đổi kịch bản chính. Chúng xuất hiện ở
`supporting_detections`, sắp xếp tất định.
"""

from __future__ import annotations

from shield.report.scenarios import UNKNOWN, for_rule
from shield.report.template import AiSlots, render

# Thứ tự mức nghiêm trọng. Để lộ ra đây vì nó quyết định kịch bản CHÍNH khi
# phải gộp, và một thứ tự chôn trong hàm là một thứ tự không ai kiểm được.
_SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1, "": 0}


def primary_scenario(incident: dict, alerts) -> tuple[str, str]:
    """-> (scenario_code, nguồn). Tất định, KHÔNG phụ thuộc thứ tự alert."""
    correlation_id = str(incident.get("correlation_id", "") or "")
    canonical = for_rule(correlation_id) if correlation_id else None
    if canonical is not None:
        return canonical.scenario_code, "correlation"

    # Gộp tất định. Sắp bằng khoá tổng, không "alert cuối cùng thắng": thứ tự
    # duyệt là chi tiết cài đặt, và để nó quyết định kịch bản nghĩa là cùng một
    # incident có thể ra hai báo cáo khác nhau.
    candidates = [
        (-_SEVERITY_RANK.get(str(a.get("severity", "")), 0), str(a.get("rule_id", "")))
        for a in alerts or ()
        if for_rule(str(a.get("rule_id", ""))) is not None
    ]
    if candidates:
        _rank, rule_id = min(candidates)
        return for_rule(rule_id).scenario_code, "aggregated"
    return UNKNOWN, "unknown"


def supporting_detections(alerts) -> list[dict]:
    """Phát hiện phụ, sắp TẤT ĐỊNH. Không đổi kịch bản chính."""
    rows = []
    for alert in alerts or ():
        rule_id = str(alert.get("rule_id", ""))
        scenario = for_rule(rule_id)
        rows.append({
            "rule_id": rule_id,
            "scenario_code": scenario.scenario_code if scenario else UNKNOWN,
            "severity": str(alert.get("severity", "")),
            "ts": float(alert.get("ts", 0.0) or 0.0),
        })
    # Khử trùng lặp theo (rule_id, ts): cùng một alert có thể tới hai lần qua
    # hai đường, và đếm nó hai lần là bịa ra một mẫu.
    unique = {(r["rule_id"], r["ts"]): r for r in rows}
    return sorted(unique.values(), key=lambda r: (r["rule_id"], r["ts"]))


def build(store, incident_id: str, *, result=None, locale: str = "vi") -> dict:
    """Báo cáo sự cố tất định. `result` (nếu có) chỉ cấp văn xuôi cho ba ô AI.

    KHÔNG BAO GIỜ ném: một báo cáo hỏng không được làm hỏng lượt điều tra.
    """
    incident = store.incident(incident_id) or {}
    alerts = store.incident_alerts(incident_id) if incident else []
    # `incident_refs()` trả về khoá `ref_id`, KHÔNG phải `ref`. Bản đầu đọc
    # nhầm tên và `.get()` trả rỗng — mọi báo cáo hiện `validated_evidence: 0`
    # và gắn thêm giới hạn `thin_evidence`, trong khi bằng chứng đã được liên
    # kết đầy đủ. Fixture tổng hợp không bắt được vì chúng chưa từng link ref;
    # lỗi chỉ lộ ra khi phát lại alert THẬT của production.
    refs = [str(item["ref_id"]) for item in
            (store.incident_refs(incident_id, "evidence") or [])
            if item.get("ref_id")]

    code, source = primary_scenario(incident, alerts)
    # `alert`-shape chuẩn tắc cho renderer. Mọi giá trị lấy từ hàng incident —
    # đây là chỗ "quyền sở hữu trường" được thi hành, không phải một lời hứa.
    canonical_alert = {
        "rule_id": str(incident.get("correlation_id", "") or ""),
        "severity": str(incident.get("severity", "info")),
        "risk_score": int(incident.get("risk_score", 0) or 0),
        "evidence_strength": float(incident.get("confidence", 0.0) or 0.0),
        "subject": str(incident.get("subject", "")),
        "title": str(incident.get("title", "")),
        "detail": "",
        "ts": float(incident.get("first_seen", 0.0) or 0.0),
        "first_seen": float(incident.get("first_seen", 0.0) or 0.0),
        "last_seen": float(incident.get("last_seen", 0.0) or 0.0),
        "playbook": [incident["recommended_action"]] if incident.get("recommended_action")
                    else ["snapshot_state"],
        "evidence": _evidence(incident, alerts,
                              scenario_facts(store, incident_id, code)),
    }
    report = render(canonical_alert, scenario_code=code, source=source,
                    evidence_refs=refs,
                    slots=AiSlots.from_result(result), locale=locale)
    report["incident_type"]["incident_id"] = str(incident_id)
    report["supporting_detections"] = supporting_detections(alerts)
    report["deterministic_sections"] = list(report["deterministic_sections"]) + \
        ["supporting_detections"]
    return report


def _evidence(incident: dict, alerts, scenario_facts: dict | None = None) -> dict:
    """Dữ kiện chuẩn tắc mức incident, CỘNG dữ kiện của kịch bản chính.

    Hai lớp, và thiếu lớp thứ hai là một lỗi thật đã quan sát được:

    - Lớp incident (`rules`, `observed_count`, …) mô tả sự việc đã ghép.
    - Lớp KỊCH BẢN (`process_identity`, `sequence`, …) mô tả thứ kịch bản ấy
      nói về, và nó nằm trong evidence của alert đóng góp, không nằm ở incident.

    Trước khi có lớp thứ hai, một incident gộp từ `BEHAVIOR_EXEC_WRITE_CONNECT`
    ra kịch bản `SUSPICIOUS_EXECUTION_CHAIN` với `confirmed_facts` RỖNG và
    "thiếu dữ kiện bắt buộc: process_identity, sequence" — trong khi alert bên
    dưới có đủ cả hai. Báo cáo mỏng đi vì đọc sai chỗ, không phải vì thiếu dữ
    liệu.
    """
    facts = {
        "rules": sorted({str(a.get("rule_id", "")) for a in alerts or () if a.get("rule_id")}),
        "observed_count": len(alerts or ()),
        "contributing_alerts": int(incident.get("alert_count", 0) or 0),
        "mitre_techniques": list(incident.get("mitre_techniques") or []),
        "recommended_action": str(incident.get("recommended_action", "") or ""),
    }
    # Dữ kiện của kịch bản KHÔNG ghi đè lớp incident: hai lớp mô tả hai thứ, và
    # để lớp dưới đè lên lớp trên là để một alert lẻ nói thay cho cả sự việc.
    for key, value in (scenario_facts or {}).items():
        facts.setdefault(str(key), value)
    return facts


def scenario_facts(store, incident_id: str, scenario_code: str) -> dict:
    """Dữ kiện của kịch bản chính, lấy từ alert đã sinh ra nó.

    Chỉ lấy những khoá kịch bản KHAI BÁO — không đổ cả evidence của alert vào
    báo cáo. Một trường không có trong `required`/`optional` là một trường
    không ai định nghĩa nghĩa cho, và đổ nó vào đây là mời người đọc suy diễn.

    Chọn tất định: alert khớp kịch bản, sắp theo (ts, rule_id), lấy cái đầu.
    """
    from shield.report.scenarios import BY_CODE

    scenario = BY_CODE.get(str(scenario_code))
    if scenario is None:
        return {}
    wanted = set(scenario.required_fact_keys) | set(scenario.optional_fact_keys)
    if not wanted:
        return {}
    try:
        rows = store.conn.execute(
            "SELECT a.ts, a.rule_id, a.evidence FROM alerts a "
            "JOIN incident_alerts ia ON ia.rule_id = a.rule_id AND ia.alert_ts = a.ts "
            "WHERE ia.incident_id = ? ORDER BY a.ts, a.rule_id",
            (str(incident_id),)).fetchall()
    except Exception:  # noqa: BLE001 — báo cáo không được hỏng vì một lượt đọc
        return {}
    import json as _json

    for _ts, rule_id, blob in rows:
        if str(rule_id) not in scenario.rule_ids:
            continue
        try:
            evidence = _json.loads(blob or "{}")
        except (ValueError, TypeError):
            continue
        picked = {k: evidence[k] for k in sorted(wanted)
                  if k in evidence and evidence[k] not in (None, "")}
        if picked:
            return picked
    return {}
