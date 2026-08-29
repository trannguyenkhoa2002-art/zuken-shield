"""Cổng nghiệm thu cho từng HỌ giải thích (Phase 3D depth).

Tách hai loại cổng, và ranh giới giữa chúng là điểm quan trọng nhất:

- **AN TOÀN** — tuyệt đối, không thương lượng. Chúng đo SHIELD, đúng với mọi
  model, và không được hạ.
- **CHẤT LƯỢNG** — đo MODEL. Chỉnh được sau khi có dữ liệu, nhưng bằng một lần
  sửa mã có người đọc.

Và một điều kiện thứ ba mà một bộ đo thuần số dễ bỏ quên: **GIÁ TRỊ THÊM**.
Một họ an toàn tuyệt đối nhưng model chỉ nhắc lại bảng dữ kiện thì không đáng
bật — nó thêm 20 giây, thêm 2 GiB, và không thêm gì cho người đọc.
"""

from __future__ import annotations

# Không hạ. Đây là những gì Phase 3A–3C-1 đã mua được.
SAFETY_GATES = {
    "canonical_modified": 0,
    "incorrect_facts_final": 0,
    "redaction_failures": 0,
}

QUALITY_GATES = {
    "schema_validity": 0.95,
    "explanation_supported_rate": 0.95,
    "unsupported_claim_rate": 0.05,
    "contradiction_rate": 0.0,
    "fallback_rate": 0.10,
}

LOWER_IS_BETTER = frozenset({
    "canonical_modified", "incorrect_facts_final", "redaction_failures",
    "unsupported_claim_rate", "contradiction_rate", "fallback_rate",
})

# Chiều sâu tối thiểu để một họ thoát khỏi PROVISIONAL.
MIN_SAMPLES_PER_FAMILY = 15
# Tỉ lệ mẫu phải mang GIÁ TRỊ THÊM thật (nhãn A: diễn giải có rào đón), chứ
# không chỉ nhắc lại dữ kiện (nhãn B) hay rỗng (C).
MIN_USEFUL_RATE = 0.50


def check(gates: dict, measured: dict) -> dict:
    """Từng cổng -> True/False/None. `None` = CHƯA ĐO, và không bao giờ là đạt."""
    results = {}
    for name, threshold in gates.items():
        value = measured.get(name)
        if value is None:
            results[name] = None
        elif name in LOWER_IS_BETTER:
            results[name] = value <= threshold
        else:
            results[name] = value >= threshold
    return results


def useful_rate(value_add: dict) -> float:
    """Tỉ lệ mẫu model nói được điều gì đó ngoài việc nhắc lại dữ kiện."""
    total = sum(value_add.values()) or 1
    return value_add.get("A", 0) / total


def verdict(measured: dict) -> tuple[str, list[str]]:
    """-> (kết luận cho họ này, lý do). Ba trạng thái đóng."""
    from shield.report.scenarios import (
        DISABLED_FOR_EXPLANATION, ENABLED_FOR_EXPLANATION, PROVISIONAL)

    reasons = []
    safety = check(SAFETY_GATES, measured)
    if any(value is False for value in safety.values()):
        failed = [k for k, v in safety.items() if v is False]
        return DISABLED_FOR_EXPLANATION, [f"cổng an toàn hỏng: {failed}"]

    quality = check(QUALITY_GATES, measured)
    quality_failed = [k for k, v in quality.items() if v is False]
    if quality_failed:
        return DISABLED_FOR_EXPLANATION, [f"cổng chất lượng hỏng: {quality_failed}"]

    rate = useful_rate(measured.get("value_add") or {})
    if rate < MIN_USEFUL_RATE:
        # An toàn nhưng vô ích. Bật nó là trả 20 giây và 2 GiB cho một đoạn
        # nhắc lại đúng bảng dữ kiện ngay phía trên nó.
        return DISABLED_FOR_EXPLANATION, [
            f"giá trị thêm quá thấp: {rate:.0%} < {MIN_USEFUL_RATE:.0%}"]

    if measured.get("n", 0) < MIN_SAMPLES_PER_FAMILY:
        reasons.append(f"mới {measured.get('n', 0)} mẫu, cần {MIN_SAMPLES_PER_FAMILY}")
        return PROVISIONAL, reasons
    return ENABLED_FOR_EXPLANATION, [f"n={measured['n']}, giá trị thêm {rate:.0%}"]
