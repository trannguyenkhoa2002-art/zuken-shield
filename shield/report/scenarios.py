"""Registry kịch bản CHÍNH DANH — dựng từ coverage THẬT (mục 1–2 của 3D).

Luật một: **chỉ thêm một scenario code khi Shield đã phát hiện được nó.** Một
registry liệt kê `DATA_EXFILTRATION` trong khi không detector nào tìm ra
exfiltration là một lời hứa với người dùng mà sản phẩm không giữ — và nó sẽ
được đọc như một cam kết bảo vệ.

Vì thế bốn họ trong đề xuất ban đầu KHÔNG có mặt ở đây, và điều đó có chủ ý:

- `PERSISTENCE` — không có detector cron/systemd-unit/autostart nào.
- `DATA_EXFILTRATION` — không detector nào đo khối lượng dữ liệu đi ra.
- `RESOURCE_ABUSE` — không detector nào đo CPU/GPU bất thường.
- `LATERAL_MOVEMENT` — chỉ có một quy tắc tương quan chạm tới rìa khái niệm;
  một họ dựng trên một quy tắc là một họ chưa tồn tại.

Chúng nằm trong `UNSUPPORTED_FAMILIES` để lần sau ai thêm detector thì biết chỗ
nối vào, và để báo cáo coverage nói thật thay vì nói tròn.

Luật hai: **không nhân bản taxonomy detector.** Registry này KHÔNG định nghĩa
lại `rule_id` hay MITRE; nó chỉ ÁNH XẠ `rule_id` đã có sang một khuôn báo cáo.
Một `rule_id` không có ánh xạ rơi vào `UNKNOWN`, và đó là một kết quả hợp lệ.
"""

from __future__ import annotations

import dataclasses

# Họ kịch bản CÓ hỗ trợ. Mỗi họ ở đây có ít nhất hai detector/rule thật.
FAMILIES = (
    "MALWARE_EXECUTION",
    "AUTHENTICATION_ATTACK",
    "PRIVILEGE_ESCALATION",
    "RECONNAISSANCE",
    "SUSPICIOUS_NETWORK",
    "FILE_CONFIG_TAMPERING",
    "DEFENSE_EVASION",
    "RISKY_SERVICE_EXPOSURE",
    "DEVICE_INVENTORY",
    "SHIELD_SELF_INTEGRITY",
)

# Họ CỐ Ý chưa hỗ trợ, kèm lý do. Đây là tài liệu coverage đọc được bằng máy —
# một bài test đối chiếu nó với registry, nên nó không thể lạc hậu trong im lặng.
UNSUPPORTED_FAMILIES = {
    "PERSISTENCE": "chưa có detector cron/systemd-unit/autostart",
    "DATA_EXFILTRATION": "chưa có detector đo khối lượng dữ liệu đi ra",
    "RESOURCE_ABUSE": "chưa có detector CPU/GPU bất thường",
    "LATERAL_MOVEMENT": "chỉ một quy tắc tương quan chạm tới rìa khái niệm",
}

# Mã kịch bản khi không có ánh xạ. KHÔNG phải một lỗi.
UNKNOWN = "UNKNOWN"

# Họ được phép kèm văn xuôi AI. Danh sách này là CẤU HÌNH CHÍNH DANH, không
# phải một suy đoán ở tầng giao diện: nếu nó sống trong UI thì một đường vào
# khác sẽ bỏ qua nó, và "chỉ bật cho ba họ" trở thành một câu trong tài liệu.
#
# Ba họ này đến từ đo đạc trên model thật: chúng có một câu chuyện tự nhiên để
# kể, và văn xuôi ở đó thêm được diễn giải. Những họ khác thì không — đặc biệt
# `SHIELD_SELF_INTEGRITY`, nơi model liên tục viết "đã xác nhận" cho những việc
# chưa hề được xác nhận.
EXPLANATION_ELIGIBLE_FAMILIES = frozenset({
    "AUTHENTICATION_ATTACK",
    "RECONNAISSANCE",
    "MALWARE_EXECUTION",
})

# Mức đủ tin cậy của TỪNG họ. Ba trạng thái, đóng:
#
#   ENABLED_FOR_EXPLANATION  - đủ mẫu, qua mọi cổng, có giá trị thêm rõ ràng
#   PROVISIONAL              - trông ổn nhưng chưa đủ chiều sâu/độ phủ
#   DISABLED_FOR_EXPLANATION - chất lượng hoặc giá trị thêm không đạt
#
# `EXPLANATION_ELIGIBLE_FAMILIES` nói họ nào ĐƯỢC PHÉP có văn xuôi; bảng này
# nói ta đã ĐO ĐƯỢC tới đâu. Hai câu hỏi khác nhau, và trộn chúng lại sẽ khiến
# "được phép" bị đọc thành "đã chứng minh".
#
# Ghi ELIGIBILITY, không phải triển khai: provider vẫn `disabled` toàn cục, và
# không dòng nào ở đây bật model lên.
ENABLED_FOR_EXPLANATION = "ENABLED_FOR_EXPLANATION"
ENABLED_WITH_SCENARIO_GATING = "ENABLED_WITH_SCENARIO_GATING"
PROVISIONAL = "PROVISIONAL"
DISABLED_FOR_EXPLANATION = "DISABLED_FOR_EXPLANATION"

# Đo trên 67 mẫu, Qwen2.5-1.5B, chế độ chỉ-giải-thích (xem
# `shield/evals/datasets/explanation-depth-corpus.json`):
#
#   AUTHENTICATION_ATTACK  n=25, 7 kịch bản, mọi cổng đạt, 100% mẫu có diễn giải
#   MALWARE_EXECUTION      n=23, 16 mẫu PHÁT LẠI alert thật, mọi cổng đạt, 91%
#   RECONNAISSANCE         n=19, schema_validity 94,7% < cổng 95% -> KHÔNG bật
#
# `RECONNAISSANCE` trượt vì ĐÚNG MỘT mẫu trong 19 (một ca đối kháng sinh dài
# chạm trần token). Ghi DISABLED chứ không làm tròn lên: một cổng nới ra cho
# vừa số đo là một cổng không còn là cổng. Đo lại với nhiều mẫu hơn sẽ nói
# được nó thật sự ở đâu.
EXPLANATION_MATURITY: dict[str, str] = {
    "AUTHENTICATION_ATTACK": ENABLED_FOR_EXPLANATION,
    # Tổng của họ đạt, nhưng hai mã bên trong KHÔNG giống nhau — nên họ này bật
    # THEO TỪNG MÃ, không bật cả gói. Xem `EXPLANATION_SCENARIO_OVERRIDE`.
    "MALWARE_EXECUTION": ENABLED_WITH_SCENARIO_GATING,
    "RECONNAISSANCE": DISABLED_FOR_EXPLANATION,
}

# Quyết định theo TỪNG MÃ, ghi trong CHÍNH registry này — không mở một bảng
# thứ hai cho cùng một khái niệm.
#
# Chỉ dùng khi một mã lệch khỏi mức của họ nó. Số đo:
#
#   SUSPICIOUS_EXECUTION_CHAIN      n=15, schema 100,0%  -> bật
#   EXECUTION_FROM_SUSPICIOUS_PATH  n= 8, schema  87,5%  -> KHÔNG bật
#
# Tổng của `MALWARE_EXECUTION` đạt 95,7% chỉ vì mã tốt đông hơn mã yếu. Bật cả
# họ vì con số tổng nghĩa là để mã yếu đi nhờ — và người đọc báo cáo của mã yếu
# không biết mình đang đọc phần chưa đạt.
EXPLANATION_SCENARIO_OVERRIDE: dict[str, str] = {
    "SUSPICIOUS_EXECUTION_CHAIN": ENABLED_FOR_EXPLANATION,
    "EXECUTION_FROM_SUSPICIOUS_PATH": DISABLED_FOR_EXPLANATION,
}

# Mã có quá ít mẫu để nói chắc, GIỮ LẠI để quan sát chứ không để chặn. Họ
# `AUTHENTICATION_ATTACK` bật ở mức HỌ; những mã này vẫn được giải thích, nhưng
# người vận hành phải đọc được rằng bằng chứng đằng sau chúng còn mỏng.
LOW_SAMPLE_CONFIDENCE = frozenset({
    "LOGIN_AT_UNUSUAL_TIME", "NETWORK_DEVICE_AUTH_FAILURE",
    "REPEATED_AUTH_FAILURES", "SERVICE_ACCOUNT_LOGIN", "SSH_ROOT_LOGIN",
})


def explanation_maturity(scenario_code: str) -> str:
    """Mức đủ tin cậy của kịch bản này. Họ ngoài allowlist -> DISABLED.

    Thứ tự tra: mã trước, họ sau. Một mã đã có quyết định riêng thì quyết định
    đó thắng — kể cả khi họ của nó đã bật.
    """
    code = str(scenario_code)
    scenario = BY_CODE.get(code)
    if scenario is None or scenario.family not in EXPLANATION_ELIGIBLE_FAMILIES:
        return DISABLED_FOR_EXPLANATION
    if code in EXPLANATION_SCENARIO_OVERRIDE:
        return EXPLANATION_SCENARIO_OVERRIDE[code]
    family = EXPLANATION_MATURITY.get(scenario.family, PROVISIONAL)
    if family == ENABLED_WITH_SCENARIO_GATING:
        # Họ bật theo từng mã, mà mã này chưa có quyết định riêng -> chưa đủ
        # căn cứ. Im lặng cho qua sẽ biến "bật theo mã" thành "bật cả họ".
        return PROVISIONAL
    return family


def explanation_enabled(scenario_code: str) -> bool:
    """Kịch bản này ĐƯỢC PHÉP kèm văn xuôi model chưa. Chỉ `ENABLED` mới tính.

    `PROVISIONAL` KHÔNG tính: nó nghĩa là "trông ổn nhưng chưa chứng minh", và
    một thứ chưa chứng minh không được chạy trên máy người dùng.
    """
    return (explanation_allowed(scenario_code)
            and explanation_maturity(scenario_code) == ENABLED_FOR_EXPLANATION)


def explanation_allowed(scenario_code: str) -> bool:
    """Kịch bản này có được kèm văn xuôi AI không.

    `UNKNOWN` LUÔN LUÔN không: khi Shield còn chưa biết đây là chuyện gì, để
    một model viết vài câu về nó là mời nó đoán — và đoán ở đúng chỗ ta vừa
    thú nhận là không biết thì tệ hơn im lặng.
    """
    code = str(scenario_code)
    if not code or code == UNKNOWN:
        return False
    scenario = BY_CODE.get(code)
    return scenario is not None and scenario.family in EXPLANATION_ELIGIBLE_FAMILIES

# `rule_id` CỐ Ý không có kịch bản riêng, kèm lý do. Khác hẳn "quên ánh xạ":
# một bài test đòi MỌI rule_id đang được phát ra phải hoặc có kịch bản, hoặc có
# mặt ở đây. Không có đường thứ ba, và không có đường im lặng.
INTENTIONAL_UNKNOWN: dict[str, str] = {
    "SHIELD_PROBLEM_RESOLVED":
        "thông báo 'đã hết vấn đề', không phải một phát hiện an ninh",
    "SHIELD_COLLECTOR_FAILED":
        "sức khoẻ nội bộ — đã có `collector_health` và `detect_problems` lo",
    "SHIELD_DATABASE_INTEGRITY_FAILED":
        "sức khoẻ nội bộ — cùng lý do trên",
}

# Họ `rule_id` sinh động, khai theo TIỀN TỐ. `problems.py` dựng id bằng
# f-string (`SHIELD_PROBLEM_{...}`), nên không liệt kê hết từng cái được — và
# một danh sách liệt kê thiếu sẽ im lặng đúng cái nó bỏ sót. Cả họ này là sức
# khoẻ nội bộ của Shield: `collector_health` và `detect_problems` đã lo, và một
# báo cáo sự cố an ninh cho "collector đang chậm" là một báo cáo sai loại.
INTENTIONAL_UNKNOWN_PREFIXES: dict[str, str] = {
    "SHIELD_PROBLEM_": "sức khoẻ nội bộ — `detect_problems` đã lo",
}


def is_intentionally_unknown(rule_id: str) -> bool:
    """Rule này CỐ Ý không có kịch bản không. Khác hẳn 'quên ánh xạ'."""
    rule_id = str(rule_id)
    if rule_id in INTENTIONAL_UNKNOWN:
        return True
    return any(rule_id.startswith(p) for p in INTENTIONAL_UNKNOWN_PREFIXES)


# LUẬT KHOÁ DỮ KIỆN, và nó là luật chứ không phải gợi ý:
#
#   required = GIAO của những khoá mọi `rule_id` trong kịch bản CHẮC CHẮN đặt
#   optional = HỢP trừ đi required
#
# Trước khi có luật này, `required_fact_keys` được viết theo trí nhớ:
# `PORT_SCAN` đòi `unique_ports`/`protocol` trong khi detector đặt
# `ports`/`scan_type_key`, và `SSH_BRUTE_FORCE` đòi `failed_attempts` trong khi
# detector đặt `fail_count`. Mọi báo cáo của hai kịch bản đó sẽ báo "thiếu dữ
# kiện bắt buộc" — sai, và sai theo kiểu làm người đọc mất tin vào cả mục.
#
# Corpus không bắt được vì corpus được sinh TỪ CHÍNH các tên khoá trong
# registry: một bài kiểm tự xác nhận chính nó. Nay có test đối chiếu registry
# với khoá đọc được từ AST của các chỗ phát alert.


@dataclasses.dataclass(frozen=True)
class Scenario:
    """Ánh xạ từ một phát hiện sang một khuôn báo cáo. Không hơn."""

    scenario_code: str
    family: str
    # `rule_id` đã có sinh ra kịch bản này. Đây là điểm nối DUY NHẤT tới
    # taxonomy detector — registry không tự định nghĩa phát hiện nào.
    rule_ids: tuple[str, ...]
    required_fact_keys: tuple[str, ...] = ()
    optional_fact_keys: tuple[str, ...] = ()
    allowed_hypothesis_codes: tuple[str, ...] = ()
    report_template_key: str = "report.template.generic"
    # Chỉ ID nằm trong allowlist của policy engine. Model không mở rộng được.
    allowed_recommendation_codes: tuple[str, ...] = ("snapshot_state",)
    minimum_evidence_refs: int = 1
    supported_locales: tuple[str, ...] = ("vi", "en")

    def template_key(self) -> str:
        return self.report_template_key or "report.template.generic"


def _s(code, family, rules, required=(), optional=(), hypotheses=(),
       recommendations=("snapshot_state",), min_evidence=1):
    return Scenario(
        scenario_code=code, family=family, rule_ids=tuple(rules),
        required_fact_keys=tuple(required), optional_fact_keys=tuple(optional),
        allowed_hypothesis_codes=tuple(hypotheses),
        report_template_key=f"report.template.{code.lower()}",
        allowed_recommendation_codes=tuple(recommendations),
        minimum_evidence_refs=min_evidence)


SCENARIOS: tuple[Scenario, ...] = (
    # --- MALWARE_EXECUTION ---
    _s("SUSPICIOUS_EXECUTION_CHAIN", "MALWARE_EXECUTION",
       ["BEHAVIOR_EXEC_WRITE_CONNECT"],
       required=["process_identity", "sequence"], optional=["dropped_paths"],
       hypotheses=["dropper_then_callout", "benign_installer"],
       recommendations=["snapshot_state", "stop_process"], min_evidence=2),
    _s("EXECUTION_FROM_SUSPICIOUS_PATH", "MALWARE_EXECUTION",
       ["ENDPOINT_SUSPICIOUS_EXEC_PATH"],
       # Evidence là `dict(ev.data)` — không khoá nào bảo đảm tĩnh, nên KHÔNG
       # khoá nào được khai là bắt buộc.
       optional=["exe", "exe_path", "path", "pid", "user", "process_identity"],
       hypotheses=["dropper_staging", "packaged_software_in_tmp"]),

    # --- AUTHENTICATION_ATTACK ---
    _s("SSH_BRUTE_FORCE", "AUTHENTICATION_ATTACK",
       ["LOCAL_SSH_BRUTEFORCE"],
       required=["src_ip", "fail_count"], optional=["window_min"],
       hypotheses=["credential_guessing", "misconfigured_client"],
       recommendations=["snapshot_state", "block_ip", "rate_limit_ip"]),
    _s("REPEATED_AUTH_FAILURES", "AUTHENTICATION_ATTACK",
       ["ACCUMULATED_AUTH_FAILURES"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts", "recommended_action"],
       hypotheses=["credential_guessing", "misconfigured_client"],
       recommendations=["snapshot_state", "block_ip", "rate_limit_ip"], min_evidence=2),
    _s("SSH_AUTH_FAILURE", "AUTHENTICATION_ATTACK",
       ["SSH_AUTH_FAILURE_OBSERVED"], optional=["src_ip", "user", "port"],
       hypotheses=["single_typo", "early_guessing"]),
    _s("SSH_ROOT_LOGIN", "AUTHENTICATION_ATTACK",
       ["SSH_ROOT_LOGIN_SUCCEEDED"], optional=["src_ip", "user", "session"],
       hypotheses=["operator_action", "compromised_credential"],
       recommendations=["snapshot_state", "block_ip"]),
    _s("SERVICE_ACCOUNT_LOGIN", "AUTHENTICATION_ATTACK",
       ["SSH_LOGIN_BY_SYSTEM_ACCOUNT"], optional=["user", "src_ip"],
       hypotheses=["misused_service_account", "automation"]),
    _s("LOGIN_AT_UNUSUAL_TIME", "AUTHENTICATION_ATTACK",
       ["ANOMALY_LOGIN_AT_UNUSUAL_TIME"],
       # `behavior_key`/`local_hour` xuất hiện 912/912 trên alert thật trong
       # database production — không phải suy đoán từ mã.
       required=["behavior_key", "local_hour"],
       optional=["previous_observations", "explanation", "user", "src_ip"],
       hypotheses=["off_hours_administration", "compromised_credential"]),
    _s("NETWORK_DEVICE_AUTH_FAILURE", "AUTHENTICATION_ATTACK",
       ["SYSLOG_AUTH_FAILURE"], optional=["device", "src_ip", "user", "host"],
       hypotheses=["credential_guessing", "operator_typo"]),

    # --- PRIVILEGE_ESCALATION ---
    _s("SUDO_FAILURE", "PRIVILEGE_ESCALATION",
       ["LOCAL_SUDO_FAIL"], required=["user"], optional=["message"],
       hypotheses=["unauthorised_escalation", "user_error"]),

    # --- RECONNAISSANCE ---
    _s("PORT_SCAN", "RECONNAISSANCE",
       ["SCAN_PORTSCAN"],
       required=["src_ip", "ports"],
       optional=["scan_type_key", "window_s", "ack_source", "acked_ports_matched"],
       hypotheses=["active_scanning", "vulnerability_scanner", "monitoring_tool"],
       recommendations=["snapshot_state", "block_ip", "rate_limit_ip"], min_evidence=2),
    _s("NEW_DEVICE_THEN_SCAN", "RECONNAISSANCE",
       ["CORRELATED_NEW_DEVICE_THEN_SCAN"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts", "recommended_action"],
       hypotheses=["unauthorised_device", "new_managed_device"],
       recommendations=["snapshot_state", "block_ip"], min_evidence=2),
    _s("RECON_THEN_SSH_ATTACK", "RECONNAISSANCE",
       ["CORRELATED_RECON_AND_SSH_ATTACK"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts", "recommended_action"],
       hypotheses=["staged_intrusion_attempt"],
       recommendations=["snapshot_state", "block_ip"], min_evidence=2),
    _s("TARPIT_CONTACT", "RECONNAISSANCE",
       ["TARPIT_CONNECTION"], required=["ip", "port"],
       hypotheses=["scanning_host", "misdirected_client"]),

    # --- SUSPICIOUS_NETWORK ---
    _s("ARP_SPOOFING", "SUSPICIOUS_NETWORK",
       # Giao của hai quy tắc: cả hai đặt `macs` và `window_s`; `ip` với `ip6`
       # chỉ một bên có, nên chúng là tuỳ chọn.
       ["MITM_ARP_CONFLICT", "MITM_NDP_CONFLICT"],
       required=["macs", "window_s"], optional=["ip", "ip6"],
       hypotheses=["arp_poisoning", "dhcp_lease_change"],
       recommendations=["snapshot_state", "isolate_endpoint"], min_evidence=2),
    _s("ARP_FLOOD", "SUSPICIOUS_NETWORK",
       ["NET_GRATUITOUS_ARP_FLOOD"],
       required=["mac", "rate_per_s"], optional=["threshold"],
       hypotheses=["arp_poisoning", "faulty_device"],
       recommendations=["snapshot_state", "isolate_endpoint"]),
    _s("GATEWAY_IMPERSONATION", "SUSPICIOUS_NETWORK",
       ["MITM_GATEWAY_MAC_CHANGED"],
       required=["gateway_ip", "observed_mac"], optional=["baseline_mac"],
       hypotheses=["gateway_spoofing", "router_replaced"],
       recommendations=["snapshot_state", "isolate_endpoint"], min_evidence=2),
    _s("ICMP_REDIRECT", "SUSPICIOUS_NETWORK",
       ["MITM_ICMP_REDIRECT"], required=["src_ip"],
       hypotheses=["route_hijack", "router_behaviour"],
       recommendations=["snapshot_state", "block_ip"]),
    _s("ROGUE_DHCP", "SUSPICIOUS_NETWORK",
       ["MITM_ROGUE_DHCP"], required=["rogue_dhcp"], optional=["known_dhcp"],
       hypotheses=["rogue_dhcp_server", "second_router"],
       recommendations=["snapshot_state", "isolate_endpoint"]),
    _s("DNS_RESOLVER_CHANGED", "SUSPICIOUS_NETWORK",
       ["DNS_RESOLVER_CHANGED"], required=["baseline", "current"],
       hypotheses=["dns_hijack", "network_reconfiguration"],
       recommendations=["snapshot_state", "block_ip"]),
    _s("UNEXPECTED_DNS_SERVER", "SUSPICIOUS_NETWORK",
       ["DNS_UNEXPECTED_SERVER"], required=["server_ip"], optional=["known_resolvers"],
       hypotheses=["dns_hijack", "misconfigured_client"],
       recommendations=["snapshot_state", "block_ip"]),
    _s("MITM_WITH_DNS_CHANGE", "SUSPICIOUS_NETWORK",
       ["CORRELATED_MITM_AND_DNS_CHANGE"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts", "recommended_action"],
       hypotheses=["active_interception"],
       recommendations=["snapshot_state", "isolate_endpoint"], min_evidence=2),

    # --- FILE_CONFIG_TAMPERING ---
    _s("FILE_INTEGRITY_CHANGE", "FILE_CONFIG_TAMPERING",
       ["FILE_INTEGRITY_CHANGED"], required=["path"], optional=["change", "pid", "exe"],
       hypotheses=["unauthorised_modification", "package_update"]),
    _s("NETWORK_DEVICE_CONFIG_CHANGE", "FILE_CONFIG_TAMPERING",
       ["SYSLOG_DEVICE_CONFIG_CHANGED"], optional=["device", "user", "host"],
       hypotheses=["unauthorised_reconfiguration", "maintenance_window"]),
    _s("REPEATED_DEVICE_CONFIG_CHANGES", "FILE_CONFIG_TAMPERING",
       ["ACCUMULATED_DEVICE_CONFIG_CHANGES"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts"],
       hypotheses=["unauthorised_reconfiguration", "maintenance_window"], min_evidence=2),

    # --- DEFENSE_EVASION ---
    _s("DELETED_RUNNING_EXECUTABLE", "DEFENSE_EVASION",
       ["ENDPOINT_DELETED_EXECUTABLE"],
       optional=["pid", "exe_path", "exe", "process_identity"],
       hypotheses=["self_deleting_payload", "in_place_upgrade"],
       recommendations=["snapshot_state", "stop_process"]),
    _s("SECURITY_CONFIG_DISABLED", "DEFENSE_EVASION",
       ["ENDPOINT_SECURITY_CONFIG_CHANGED"],
       optional=["component", "previous_state", "current_state", "path"],
       hypotheses=["defence_tampering", "administrator_change"]),
    _s("PROMISCUOUS_INTERFACE", "DEFENSE_EVASION",
       ["LOCAL_PROMISC_MODE"], required=["interface"], optional=["message"],
       hypotheses=["traffic_capture", "monitoring_tool"]),
    _s("UNSEEN_BEHAVIOUR", "DEFENSE_EVASION",
       ["ANOMALY_NEW_BEHAVIOR"], optional=["subject", "behaviour_kind", "first_seen"],
       hypotheses=["new_activity_after_access", "new_legitimate_workload"]),
    _s("ACCESS_THEN_UNSEEN_BEHAVIOUR", "DEFENSE_EVASION",
       ["CORRELATED_SSH_ACCESS_THEN_NEW_BEHAVIOR"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts"],
       hypotheses=["new_activity_after_access"], min_evidence=2),

    # --- RISKY_SERVICE_EXPOSURE ---
    _s("REMOTE_ACCESS_PORT_LISTENING", "RISKY_SERVICE_EXPOSURE",
       ["ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT", "ENDPOINT_SENSITIVE_LISTENER_OPENED",
        "RISKY_LISTENER_PRESENT_AT_STARTUP"],
       optional=["port", "bind_address", "owner_identities", "process_identity"],
       hypotheses=["intentional_remote_access", "unexpected_exposure"]),

    # --- DEVICE_INVENTORY ---
    _s("NEW_DEVICE_ON_NETWORK", "DEVICE_INVENTORY",
       ["DEVICE_NEW"], required=["ip", "mac"], optional=["vendor", "hostname"],
       hypotheses=["new_authorised_device", "unknown_device"]),
    _s("MAC_RANDOMISATION", "DEVICE_INVENTORY",
       ["DEVICE_MAC_RANDOMIZED"], required=["ip", "mac"],
       hypotheses=["privacy_feature", "identity_evasion"]),
    _s("USB_DEVICE_ATTACHED", "DEVICE_INVENTORY",
       # `ENDPOINT_USB_ADDED` là USB BẤT KỲ, không riêng thiết bị lưu trữ — nên
       # tên kịch bản nói "device", không nói "storage". Giao của ba quy tắc là
       # rỗng, nên không khoá nào bắt buộc.
       ["ENDPOINT_USB_STORAGE_ATTACHED", "ENDPOINT_USB_ADDED", "LOCAL_NEW_USB"],
       optional=["vendor_id", "product_id", "product", "serial", "message",
                 "mount_point"],
       hypotheses=["routine_use", "data_transfer_risk"]),
    _s("DEVICE_AT_UNUSUAL_TIME", "DEVICE_INVENTORY",
       ["ANOMALY_DEVICE_AT_UNUSUAL_TIME"],
       required=["behavior_key", "local_hour"],
       optional=["previous_observations", "explanation", "ip", "mac"],
       hypotheses=["off_hours_device", "unknown_device"]),
    _s("NETWORK_DEVICE_RESTART", "DEVICE_INVENTORY",
       ["SYSLOG_DEVICE_RESTARTED"], optional=["device", "host", "user"],
       hypotheses=["planned_reboot", "instability", "forced_restart"]),
    _s("REPEATED_DEVICE_RESTARTS", "DEVICE_INVENTORY",
       ["ACCUMULATED_DEVICE_RESTARTS"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts"],
       hypotheses=["instability", "forced_restart"], min_evidence=2),

    # --- SHIELD_SELF_INTEGRITY ---
    _s("AGENT_STOPPED", "SHIELD_SELF_INTEGRITY",
       ["GUARDIAN_AGENT_STOPPED", "GUARDIAN_AGENT_STOPPED_BY_OPERATOR",
        "GUARDIAN_AGENT_RESTART_STORM"],
       optional=["reason", "since", "restart_count", "detail"],
       hypotheses=["operator_action", "crash_loop", "tampering"]),
    _s("INSTALLATION_CHANGED", "SHIELD_SELF_INTEGRITY",
       ["GUARDIAN_INSTALLATION_CHANGED", "GUARDIAN_INSTALLATION_UNREADABLE",
        "TAMPER_AGENT_FILES_CHANGED"],
       optional=["changed", "signed", "path", "detail"],
       hypotheses=["package_upgrade", "tampering"]),
    _s("CLOCK_TAMPERING", "SHIELD_SELF_INTEGRITY",
       # Đồng hồ lùi làm MỌI mốc thời gian và cả chuỗi băm ledger mất nghĩa.
       # Tách khỏi `AUDIT_TRAIL_DAMAGED` vì cơ chế khác và cách xử lý khác.
       ["TAMPER_CLOCK_ROLLBACK"], optional=["observed", "expected", "drift_s"],
       hypotheses=["ntp_correction", "deliberate_rollback"]),
    _s("AUDIT_TRAIL_DAMAGED", "SHIELD_SELF_INTEGRITY",
       ["GUARDIAN_LEDGER_TRUNCATED", "GUARDIAN_LEDGER_UNREADABLE",
        "GUARDIAN_DATABASE_CORRUPT", "GUARDIAN_DATABASE_MISSING"],
       optional=["detail", "expected", "observed"],
       hypotheses=["storage_failure", "deliberate_truncation"]),
    _s("TELEMETRY_LOSS", "SHIELD_SELF_INTEGRITY",
       ["PROBE_LOG_GAP"], optional=["probe_id", "dropped", "since"],
       hypotheses=["overloaded_probe", "deliberate_log_suppression"]),
    _s("REPEATED_TELEMETRY_LOSS", "SHIELD_SELF_INTEGRITY",
       ["ACCUMULATED_PROBE_LOG_GAPS"],
       required=["rules", "observed_count"],
       optional=["window_s", "min_count", "contributing_alerts"],
       hypotheses=["overloaded_probe", "deliberate_log_suppression"], min_evidence=2),
    _s("RESPONSE_DID_NOT_APPLY", "SHIELD_SELF_INTEGRITY",
       # Giao của hai quy tắc là rỗng (`action` vs `job_id`/`detail`), nên
       # không khoá nào bắt buộc — khai bừa một khoá bắt buộc sẽ làm mọi báo
       # cáo của kịch bản này báo thiếu dữ kiện.
       ["RESPONSE_VERIFICATION_FAILED", "RESPONSE_ROLLBACK_FAILED"],
       optional=["action", "job_id", "detail"],
       hypotheses=["verification_failure", "external_interference"]),
    _s("ISOLATION_ROLLED_BACK", "SHIELD_SELF_INTEGRITY",
       ["ISOLATION_AUTO_ROLLED_BACK"],
       required=["target", "rollback_ok"], optional=["message", "observed"],
       hypotheses=["dead_man_switch_fired", "rollback_failure"]),
)

BY_CODE = {s.scenario_code: s for s in SCENARIOS}
BY_RULE = {rule: s for s in SCENARIOS for rule in s.rule_ids}


def for_rule(rule_id: str) -> Scenario | None:
    """`rule_id` (hoặc `incidents.correlation_id`) -> kịch bản, hoặc `None`.

    `None` là kết quả HỢP LỆ: một phát hiện chưa có khuôn riêng dùng khuôn
    chung. Ép nó vào kịch bản gần nhất là phân loại sai, và phân loại sai tệ
    hơn `UNKNOWN`.
    """
    return BY_RULE.get(str(rule_id))


def coverage() -> dict:
    """Coverage đọc được bằng máy. Dùng cho báo cáo, và có test đối chiếu."""
    families: dict[str, list[str]] = {}
    for scenario in SCENARIOS:
        families.setdefault(scenario.family, []).append(scenario.scenario_code)
    return {
        "families_supported": len(families),
        "scenario_codes": len(SCENARIOS),
        "rule_ids_mapped": len(BY_RULE),
        "by_family": {name: sorted(codes) for name, codes in sorted(families.items())},
        "families_unsupported": dict(sorted(UNSUPPORTED_FAMILIES.items())),
        "intentionally_unknown": dict(sorted(INTENTIONAL_UNKNOWN.items())),
    }
