"""Mô hình bằng chứng cho DNS_RESOLVER_CHANGED và MITM_ROGUE_DHCP.

Hai tín hiệu này ủng hộ lẫn nhau: rogue DHCP thường đi kèm đổi resolver. Mỗi
alert đứng một mình chỉ đạt mức vừa phải; thấy cả hai gần nhau thì cao hơn,
và danh sách còn thiếu nói đúng thứ chưa thấy.
"""

from __future__ import annotations

import time

from shield.agent.store import Store
from shield.common.models import Alert
from shield.security.scoring import RiskContext, RiskScorer


def _dns(ts):
    return Alert(ts, "DNS_RESOLVER_CHANGED", "critical", "t", "d", "203.0.113.53",
                 evidence={"baseline": "192.168.1.1", "current": "203.0.113.53"})


def _dhcp(ts):
    return Alert(ts, "MITM_ROGUE_DHCP", "critical", "t", "d", "192.168.1.66",
                 evidence={"known_dhcp": "192.168.1.1", "rogue_dhcp": "192.168.1.66"})


def test_a_resolver_change_alone_lists_the_corroboration_it_lacks():
    confidence = RiskScorer().assess(_dns(time.time()), RiskContext()).evidence_confidence
    assert confidence.basis == "model:DNS_RESOLVER_CHANGED"
    assert confidence.score == 35
    assert confidence.missing == ("repeated_observation", "rogue_dhcp_nearby", "gateway_tampering_nearby")


def test_rogue_dhcp_and_resolver_change_corroborate_each_other(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    store.insert_alert(_dhcp(now - 60))
    store.upsert_device("aa:bb:cc:00:00:66", "192.168.1.66")
    dns_facts = store.evidence_facts(_dns(now))
    assert dns_facts == {"rogue_dhcp_nearby"}
    assert RiskScorer().assess(_dns(now), RiskContext(), dns_facts).evidence_confidence.score == 60
    store.insert_alert(_dns(now))
    dhcp_facts = store.evidence_facts(_dhcp(now))
    assert dhcp_facts == {"dns_changed_nearby", "rogue_server_on_lan"}
    confidence = RiskScorer().assess(_dhcp(now), RiskContext(), dhcp_facts).evidence_confidence
    assert confidence.score == 80 and confidence.missing == ("repeated_observation",)


def test_far_apart_signals_do_not_corroborate(tmp_path):
    store = Store(tmp_path / "s.db")
    now = time.time()
    store.insert_alert(_dhcp(now - 3 * 3600))
    assert store.evidence_facts(_dns(now)) == set()
