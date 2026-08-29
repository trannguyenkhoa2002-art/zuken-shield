"""Hiệu chuẩn detector — độ chính xác ĐO ĐƯỢC, không phải phỏng đoán (mục 3.1).

Đây là chỗ tách hai thứ đã bị gộp làm một từ 1.1:

- `evidence_strength`: bằng chứng phong phú và độc lập tới đâu. Tính được ngay
  từ chính alert — nhiều dấu hiệu, lặp lại nhiều lần, có nguồn ngoài đối chứng.
- `detector_confidence`: detector này, ở PHIÊN BẢN này, đã đúng bao nhiêu phần
  trăm trong quá khứ. Chỉ biết được khi có người dán nhãn đúng/sai.

Bản 1.1 gọi cái thứ nhất là `confidence` và hiển thị nó như thể là cái thứ hai.
Người đọc thấy "confidence 0.90" và hiểu là "90% khả năng đúng" — trong khi nó
chỉ có nghĩa "alert này có 5 mẩu bằng chứng". Mục 3.4 cấm đúng chuyện đó:
"Confidence heuristic không được hiển thị như xác suất trước khi calibration."

**Chưa có dữ liệu thì trả về `None`, không phải một số mặc định.** Một detector
chưa hiệu chuẩn có độ chính xác KHÔNG BIẾT, và điền 0.5 hay 0.9 vào đó là bịa
ra một con số rồi để người khác quyết định dựa trên nó.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

CALIBRATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS detector_calibration (
    rule_id TEXT NOT NULL,
    detector_version TEXT NOT NULL DEFAULT '',
    true_positives INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    -- Nhãn "chưa rõ": người dán nhãn nhìn mà không kết luận được. Đếm riêng,
    -- vì gộp nó vào false_positives sẽ phạt oan detector, còn bỏ đi thì mất
    -- dấu vết rằng có những alert không ai hiểu.
    undetermined INTEGER NOT NULL DEFAULT 0,
    updated_ts REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(rule_id, detector_version)
);
"""

CALIBRATION_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_calibration_updated ON detector_calibration(updated_ts);
"""

# Số mẫu tối thiểu trước khi dám gọi một tỉ lệ là "độ chính xác". Ba mẫu đúng
# liên tiếp cho ra 100% — một con số vừa đúng về số học vừa vô nghĩa về thống kê.
MIN_SAMPLES = 20


@dataclass(frozen=True)
class CalibrationRecord:
    rule_id: str
    detector_version: str = ""
    true_positives: int = 0
    false_positives: int = 0
    undetermined: int = 0
    updated_ts: float = 0.0

    @property
    def labelled(self) -> int:
        return self.true_positives + self.false_positives

    @property
    def precision(self) -> float | None:
        """Tỉ lệ đúng, hoặc None nếu chưa đủ mẫu để nói gì."""
        if self.labelled < MIN_SAMPLES:
            return None
        return self.true_positives / self.labelled

    def interval(self, z: float = 1.96) -> tuple[float, float] | None:
        """Khoảng tin cậy Wilson 95%.

        Một điểm số đơn lẻ giấu mất việc nó dựa trên bao nhiêu mẫu: 19/20 và
        950/1000 đều ra 95%, nhưng cái đầu có thể là 75% trong thực tế. Khoảng
        tin cậy nói ra điều đó, và người vận hành cần biết trước khi cho phép
        một detector tự động hoá hành động.
        """
        n = self.labelled
        if n < MIN_SAMPLES:
            return None
        p = self.true_positives / n
        denominator = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denominator
        margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
        return (max(0.0, centre - margin), min(1.0, centre + margin))

    def to_dict(self) -> dict:
        interval = self.interval()
        return {
            "rule_id": self.rule_id, "detector_version": self.detector_version,
            "true_positives": self.true_positives, "false_positives": self.false_positives,
            "undetermined": self.undetermined, "labelled": self.labelled,
            "precision": self.precision,
            "interval_low": interval[0] if interval else None,
            "interval_high": interval[1] if interval else None,
            "calibrated": self.precision is not None,
            "min_samples": MIN_SAMPLES,
            "updated_ts": self.updated_ts,
        }


class DetectorCalibration:
    """Đọc/ghi bảng hiệu chuẩn. Không có gì tự động dán nhãn ở đây."""

    def __init__(self, conn) -> None:
        self.conn = conn

    def record_label(self, rule_id: str, verdict: str, *,
                     detector_version: str = "", at: float | None = None) -> None:
        """Ghi một nhãn do NGƯỜI đặt: true_positive | false_positive | undetermined.

        Không có đường nào cho detector tự dán nhãn cho chính nó, và cũng không
        có đường nào cho AI. Một hệ thống tự chấm điểm mình luôn được điểm cao.
        """
        column = {
            "true_positive": "true_positives",
            "false_positive": "false_positives",
            "undetermined": "undetermined",
        }.get(str(verdict))
        if column is None:
            raise ValueError(f"nhãn không hợp lệ: {verdict!r}")
        if not rule_id:
            raise ValueError("thiếu rule_id")
        self.conn.execute(
            f"INSERT INTO detector_calibration(rule_id,detector_version,{column},updated_ts) "
            "VALUES(?,?,1,?) "
            f"ON CONFLICT(rule_id,detector_version) DO UPDATE SET {column}={column}+1, "
            "updated_ts=excluded.updated_ts",
            (str(rule_id), str(detector_version), float(at or time.time())),
        )

    def get(self, rule_id: str, detector_version: str = "") -> CalibrationRecord:
        row = self.conn.execute(
            "SELECT rule_id,detector_version,true_positives,false_positives,undetermined,"
            "updated_ts FROM detector_calibration WHERE rule_id=? AND detector_version=?",
            (str(rule_id), str(detector_version)),
        ).fetchone()
        if row is None:
            return CalibrationRecord(rule_id=str(rule_id), detector_version=str(detector_version))
        return CalibrationRecord(*row)

    def precision_for(self, rule_id: str, detector_version: str = "") -> float | None:
        return self.get(rule_id, detector_version).precision

    def list_all(self, limit: int = 500) -> list[dict]:
        rows = self.conn.execute(
            "SELECT rule_id,detector_version,true_positives,false_positives,undetermined,"
            "updated_ts FROM detector_calibration ORDER BY updated_ts DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
        return [CalibrationRecord(*row).to_dict() for row in rows]
