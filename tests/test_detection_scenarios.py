"""20 kịch bản xác thực phát hiện, chạy qua đường ống thật của agent.

Mỗi kịch bản dựng chuỗi Event mà collector thật phát ra cho một hành vi tấn
công, chạy qua run_event_consumer + run_alert_consumer, và đối chiếu alert /
incident / vùng xám thu được với kỳ vọng. Xem shield/assessment/detection_scenarios.
"""

from __future__ import annotations

import pytest

from shield.assessment.detection_scenarios import SCENARIOS, run_scenario


def test_there_are_twenty_scenarios():
    assert len(SCENARIOS) == 20
    assert len({s.id for s in SCENARIOS}) == 20


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.id)
def test_scenario_is_detected(scenario, tmp_path):
    result = run_scenario(scenario, tmp_path / f"{scenario.id}.db")
    assert result["passed"], (
        f"{scenario.id}: missing={result['missing_alerts']} "
        f"incident_ok={result['incident_ok']} gray_ok={result['gray_zone_ok']} "
        f"detected={list(result['detected_alerts'])}")


def test_every_expectation_is_backed_by_an_outcome():
    """Không kịch bản nào 'pass' bằng cách không kỳ vọng gì."""
    for scenario in SCENARIOS:
        assert scenario.expect_alerts or scenario.expect_gray_zone or scenario.expect_incident, scenario.id


def test_detections_carry_risk_and_evidence_confidence(tmp_path):
    """Alert phát hiện được phải mang cả hai điểm — Risk và Evidence Confidence."""
    result = run_scenario(next(s for s in SCENARIOS if s.id == "ssh-bruteforce"), tmp_path / "s.db")
    scored = result["detected_alerts"]["LOCAL_SSH_BRUTEFORCE"]
    assert scored["risk"] > 0
    assert scored["evidence_confidence"] >= 0


def test_a_multi_step_attack_becomes_one_incident(tmp_path):
    result = run_scenario(next(s for s in SCENARIOS if s.id == "recon-then-ssh"), tmp_path / "s.db")
    assert "CORRELATED_RECON_AND_SSH_ATTACK" in result["incidents"]
    assert {"SCAN_PORTSCAN", "LOCAL_SSH_BRUTEFORCE"} <= set(result["detected_alerts"])


def test_below_threshold_activity_is_not_silent(tmp_path):
    """Hoạt động dưới ngưỡng phát hiện phải vào vùng xám, không biến mất."""
    for scenario_id in ("ssh-near-miss", "port-scan-near-miss"):
        result = run_scenario(next(s for s in SCENARIOS if s.id == scenario_id), tmp_path / f"{scenario_id}.db")
        assert "below_threshold" in result["gray_zone_kinds"]
        assert not result["detected_alerts"], "near-miss không được thành alert"
