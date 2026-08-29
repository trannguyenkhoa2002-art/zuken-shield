"""Bộ đo chất lượng phát hiện (KE-HOACH-SHIELD-2.0.md mục 3.2).

Không có gì ở đây chạy trên máy thật hay chạm mạng: corpus là dữ liệu tĩnh có
phiên bản, và runner chỉ bơm event vào detector rồi đếm.
"""

from shield.evals.metrics import ConfusionMatrix, DetectorMetrics, MetricsReport

__all__ = ["ConfusionMatrix", "DetectorMetrics", "MetricsReport"]
