"""Bảng chuỗi song ngữ VI/EN cho UI — 1 nguồn duy nhất, giống nguyên tắc
`theme.py` cho màu (không nơi nào tự chế chuỗi riêng).

Không dùng Qt `tr()`/`.ts` vì app chỉ có 2 ngôn ngữ cố định, không cần bộ máy
dịch runtime đầy đủ của Qt Linguist — 1 dict tra thẳng là đủ và dễ audit.

Cách dùng trong 1 widget: gọi `t("key")` lúc dựng UI để lấy chuỗi theo
`current_lang()`. Khi người dùng đổi ngôn ngữ (combo ở tab Cài đặt), mỗi tab
có 1 method `retranslate()` gọi lại `t()` cho từng widget đã lưu tham chiếu —
xem `shield/ui/__main__.py`. Mặc định mở app bằng English theo yêu cầu; đổi
sang Tiếng Việt qua combo trong Cài đặt.
"""

from __future__ import annotations

_lang = "en"

# key -> (Tiếng Việt, English)
STRINGS: dict[str, tuple[str, str]] = {
    # --- khung chung ---
    "app.title": ("Zuken Shield — Bảo mật Endpoint", "Zuken Shield — Endpoint Security"),
    "status.connected": ("Đã kết nối agent", "Agent connected"),
    "status.connected_health": (
        "Đã kết nối • {active}/{total} thành phần lõi hoạt động",
        "Connected • {active}/{total} core components active",
    ),
    "status.disconnected": ("Mất kết nối agent — đang thử lại...", "Agent connection lost — retrying..."),
    "status.connecting": ("Đang kết nối agent...", "Connecting to agent..."),
    "common.error": ("Lỗi", "Error"),
    # --- mức cảnh báo (dùng chung Tổng quan/Cảnh báo/Tự kiểm tra) ---
    "severity.info": ("Thông tin", "Info"),
    "severity.warning": ("Cảnh báo", "Warning"),
    "severity.critical": ("Nguy cấp", "Critical"),
    "alerts.col_risk": ("Điểm rủi ro", "Risk score"),
    "status.ok": ("Bình thường", "Normal"),
    "status.watching": ("Đang theo dõi", "Watching"),
    "status.alert": ("Có cảnh báo", "Alert active"),
    # --- sidebar ---
    "nav.overview": ("Tổng quan", "Overview"),
    "nav.devices": ("Thiết bị", "Devices"),
    "nav.alerts": ("Cảnh báo", "Alerts"),
    "nav.incidents": ("Sự cố", "Incidents"),
    "incidents.sub": ("Nhóm cảnh báo liên quan theo đối tượng trong 24 giờ gần nhất.", "Related findings grouped by subject over the last 24 hours."),
    "incidents.col_subject": ("Đối tượng", "Subject"),
    "incidents.col_risk": ("Rủi ro cao nhất", "Peak risk"),
    "incidents.col_count": ("Số cảnh báo", "Findings"),
    "incidents.col_rules": ("Rule liên quan", "Related rules"),
    "incidents.col_last": ("Gần nhất", "Last seen"),
    "response.preview_stop": ("Xem trước: dừng process", "Preview: stop process"),
    "response.preview_stop_tree": ("Xem trước: dừng toàn bộ process tree", "Preview: stop entire process tree"),
    "response.preview_quarantine": ("Xem trước: quarantine file", "Preview: quarantine file"),
    "response.confirm": ("Thực thi hành động này?\n\n{message}", "Execute this action?\n\n{message}"),
    "response.title": ("Phản ứng endpoint", "Endpoint response"),
    "playbook.title": ("Hướng xử lý", "Playbook"),
    "nav.traffic": ("Lưu lượng", "Traffic"),
    "nav.audit": ("Tự kiểm tra", "Self-Audit"),
    "nav.assessment": ("Đánh giá", "Assessment"),
    "nav.security_center": ("Trung tâm bảo mật", "Security Center"),
    "nav.log": ("Log máy", "System Log"),
    "nav.reports": ("Báo cáo", "Reports"),
    "reports.analyze": ("Phân tích cục bộ", "Analyze locally"),
    "reports.analysis_title": ("Phân tích log offline", "Offline log analysis"),
    "nav.dns": ("Kiểm soát DNS", "DNS Control"),
    "nav.wifi": ("Mật khẩu WiFi", "WiFi Passwords"),
    "nav.settings": ("Cài đặt", "Settings"),
    "nav.help": ("Trợ giúp", "Help"),
    # --- nhóm điều hướng chính ---
    "section.operations": ("Vận hành", "Operations"),
    "section.monitoring": ("Giám sát", "Monitoring"),
    "section.investigation": ("Điều tra", "Investigation"),
    "section.management": ("Quản trị", "Management"),
    "header.location": ("{section}  /  {page}", "{section}  /  {page}"),
    "header.operations_desc": (
        "Tình trạng hiện tại, sự cố ưu tiên và cảnh báo cần xử lý.",
        "Current posture, prioritized incidents, and actionable alerts.",
    ),
    "header.monitoring_desc": (
        "Telemetry endpoint, thiết bị, lưu lượng và bề mặt mạng.",
        "Endpoint telemetry, devices, traffic, and network surfaces.",
    ),
    "header.investigation_desc": (
        "Timeline, MITRE, assessment, bằng chứng và báo cáo.",
        "Timelines, MITRE, assessments, evidence, and reports.",
    ),
    "header.management_desc": (
        "Cấu hình, quyền riêng tư, giao diện và tài liệu sử dụng.",
        "Configuration, privacy, appearance, and product guidance.",
    ),
    "header.agent_online": ("● Agent hoạt động", "● Agent online"),
    # --- công tắc giám sát trên thanh tiêu đề (shield/agent/switch.py) ---
    "switch.state_running": ("● Đang giám sát", "● Monitoring"),
    "switch.state_all_paused": ("⏸ Đã tạm dừng toàn bộ", "⏸ All monitoring paused"),
    "switch.state_partial": ("⏸ Tạm dừng: {scopes}", "⏸ Paused: {scopes}"),
    "switch.resumes_in": ("Tự bật lại sau {minutes} phút", "Resumes automatically in {minutes} min"),
    "switch.pause_button": ("Tạm dừng", "Pause"),
    "switch.pause_tooltip": (
        "Tạm dừng giám sát mà không cần chạy lệnh. Dùng khi bạn đang ở mạng "
        "trường học, cơ quan hay nơi công cộng — quét mạng chủ động ở những "
        "nơi đó có thể bị coi là vi phạm quy định.",
        "Pause monitoring without running a command. Use this on a school, "
        "workplace, or public network — active network scanning there may "
        "breach the network's acceptable-use policy.",
    ),
    "switch.scope_active": (
        "Chỉ dừng quét chủ động (arp-scan, nmap)",
        "Pause active scanning only (arp-scan, nmap)",
    ),
    "switch.scope_all": ("Dừng toàn bộ giám sát", "Pause all monitoring"),
    "switch.for_15m": ("Trong 15 phút", "For 15 minutes"),
    "switch.for_1h": ("Trong 1 giờ", "For 1 hour"),
    "switch.for_8h": ("Trong 8 giờ", "For 8 hours"),
    "switch.until_resumed": ("Đến khi tôi bật lại", "Until I resume it"),
    "switch.resume_all": ("Bật lại tất cả", "Resume everything"),
    "switch.reason_manual": ("Người dùng tạm dừng từ trong app", "Paused by the operator from the app"),
    "switch.shutdown_button": ("Tắt Shield", "Shut down Shield"),
    "switch.shutdown_tooltip": (
        "Dừng hẳn agent. Shield sẽ không tự chạy lại cho tới khi bạn mở lại.",
        "Stop the agent entirely. Shield will not restart itself until you start it again.",
    ),
    "switch.shutdown_confirm_title": ("Tắt Shield?", "Shut down Shield?"),
    "switch.shutdown_confirm_body": (
        "Agent sẽ dừng hoàn toàn và máy này không còn được giám sát.\n\n"
        "Shield sẽ KHÔNG tự khởi động lại. Nếu bạn chỉ muốn ngừng quét mạng "
        "một lúc, hãy dùng \"Tạm dừng\" thay vì tắt hẳn.",
        "The agent will stop completely and this machine will no longer be "
        "monitored.\n\nShield will NOT restart itself. If you only want to "
        "stop scanning the network for a while, use \"Pause\" instead.",
    ),
    "switch.shutdown_done_title": ("Shield đang tắt", "Shield is shutting down"),
    "switch.shutdown_done_body": (
        "Agent đã nhận lệnh tắt. Máy này không còn được giám sát cho tới khi "
        "bạn khởi động lại Shield.",
        "The agent accepted the shutdown request. This machine is no longer "
        "monitored until you start Shield again.",
    ),
    "switch.status_running": ("Giám sát đang chạy đầy đủ", "Monitoring is fully active"),
    "switch.status_paused": ("Đã tạm dừng: {scopes}", "Paused: {scopes}"),
    "switch.status_shutting_down": ("Đang tắt agent...", "Shutting the agent down..."),
    "switch.status_capture_paused": (
        "Không ghi được lưu lượng: chức năng ghi đang tạm dừng",
        "Cannot capture traffic: capture is currently paused",
    ),
    "header.agent_offline": ("● Agent mất kết nối", "● Agent offline"),
    # --- Đánh giá pipeline phòng thủ ---
    "assessment.title": ("Đánh giá hệ thống phòng thủ", "Defensive system assessment"),
    "assessment.sub": (
        "Kiểm tra Event → Detection → Risk → Evidence bằng sự kiện mô phỏng trong bộ nhớ. Không khai thác, không chặn và không thay đổi hệ thống.",
        "Validate Event → Detection → Risk → Evidence with in-memory simulated events. No exploitation, blocking, or system changes.",
    ),
    "assessment.run": ("Chạy bộ kiểm thử an toàn", "Run safe assessment"),
    "assessment.running": ("Đang kiểm thử pipeline...", "Assessing the pipeline..."),
    "assessment.ready": ("Sẵn sàng", "Ready"),
    "assessment.done": ("Đã hoàn thành lúc {time}", "Completed at {time}"),
    "assessment.error": ("Không thể hoàn thành: {error}", "Could not complete: {error}"),
    "assessment.passed": ("Đạt", "Passed"),
    "assessment.failed": ("Không đạt", "Failed"),
    "assessment.inconclusive": ("Chưa kết luận", "Inconclusive"),
    "assessment.coverage": ("Rule coverage", "Rule coverage"),
    "assessment.col_test": ("Test case", "Test case"),
    "assessment.col_status": ("Kết quả", "Result"),
    "assessment.col_latency": ("Độ trễ", "Latency"),
    "assessment.col_assertions": ("Assertions", "Assertions"),
    "assessment.no_results": ("Chưa có phiên đánh giá nào.", "No assessment session yet."),
    "assessment.assertions_fmt": ("{passed}/{total} đạt", "{passed}/{total} passed"),
    "assessment.latency_fmt": ("{value:.1f} ms", "{value:.1f} ms"),
    "assessment.status.passed": ("Đạt", "Passed"),
    "assessment.status.failed": ("Không đạt", "Failed"),
    "assessment.status.inconclusive": ("Chưa kết luận", "Inconclusive"),
    "assessment.status.skipped": ("Bỏ qua", "Skipped"),
    # --- Trung tâm bảo mật chuyên sâu ---
    "advanced.title": ("Trung tâm bảo mật chuyên sâu", "Advanced Security Center"),
    "advanced.sub": (
        "Sức khỏe collector, MITRE ATT&CK, tìm kiếm timeline, hồ sơ điều tra, baseline hành vi, fleet và release lab trong một nơi.",
        "Collector health, MITRE ATT&CK, timeline search, investigation cases, behavior baseline, fleet, and release lab in one place.",
    ),
    "advanced.telemetry": ("Telemetry kernel", "Kernel telemetry"),
    "advanced.mitre": ("MITRE coverage", "MITRE coverage"),
    "advanced.cases": ("Hồ sơ đang mở", "Open cases"),
    "advanced.endpoints": ("Endpoint đã enroll", "Enrolled endpoints"),
    "advanced.health": ("Shield Health", "Shield Health"),
    "advanced.search_title": ("Tìm kiếm timeline và process tree", "Timeline and process-tree search"),
    "advanced.search_placeholder": ("PID, hash, IP, user, hostname hoặc đường dẫn...", "PID, hash, IP, user, hostname, or path..."),
    "advanced.search": ("Tìm", "Search"),
    "advanced.col_time": ("Thời gian", "Time"),
    "advanced.col_type": ("Loại", "Type"),
    "advanced.col_source": ("Nguồn", "Source"),
    "advanced.col_subject": ("Đối tượng", "Subject"),
    "advanced.col_provenance": ("Xuất xứ", "Provenance"),
    "advanced.actual": ("Dữ liệu thật", "Observed"),
    "advanced.synthetic": ("Mô phỏng", "Synthetic"),
    "advanced.no_results": ("Không có kết quả.", "No results."),
    "advanced.process_graph": ("Process graph: {nodes} node, {edges} cạnh", "Process graph: {nodes} nodes, {edges} edges"),
    "advanced.health_title": ("Sức khỏe collector", "Collector health"),
    "advanced.col_component": ("Thành phần", "Component"),
    "advanced.col_backend": ("Backend", "Backend"),
    "advanced.col_health": ("Sức khỏe", "Health"),
    "advanced.col_detail": ("Chi tiết", "Detail"),
    "advanced.col_heartbeat": ("Heartbeat cuối", "Last heartbeat"),
    "advanced.col_event": ("Event cuối", "Last event"),
    "advanced.col_restarts": ("Restart", "Restarts"),
    "advanced.col_dropped": ("Bị bỏ", "Dropped"),
    "advanced.system_health_title": ("Tài nguyên và độ tin cậy", "Resources and reliability"),
    "advanced.export_diagnostics": ("Xuất chẩn đoán", "Export diagnostics"),
    "advanced.export_diagnostics_done": ("Đã xuất gói chẩn đoán:\n{path}", "Diagnostic bundle exported:\n{path}"),
    "advanced.export_diagnostics_failed": ("Không thể xuất chẩn đoán: {error}", "Could not export diagnostics: {error}"),
    "advanced.col_metric": ("Chỉ số", "Metric"),
    "advanced.col_value": ("Giá trị", "Value"),
    "advanced.healthy": ("Hoạt động", "Healthy"),
    "advanced.unhealthy": ("Cần kiểm tra", "Needs attention"),
    "advanced.baseline_title": ("Baseline hành vi cục bộ", "Local behavior baseline"),
    "advanced.baseline_summary": ("{behaviors} hành vi / {observations} quan sát", "{behaviors} behaviors / {observations} observations"),
    "advanced.reset_baseline": ("Reset baseline", "Reset baseline"),
    "advanced.reset_confirm": ("Xóa toàn bộ baseline hành vi đã học? Thao tác được ghi forensic log.", "Delete the learned behavior baseline? The action is written to the forensic log."),
    "advanced.case_title": ("Hồ sơ điều tra", "Investigation cases"),
    "advanced.case_name": ("Tên hồ sơ", "Case title"),
    "advanced.case_subject": ("Đối tượng", "Subject"),
    "advanced.case_create": ("Tạo hồ sơ", "Create case"),
    "advanced.col_case": ("Hồ sơ", "Case"),
    "advanced.col_state": ("Trạng thái", "State"),
    "advanced.col_updated": ("Cập nhật", "Updated"),
    "advanced.case_note": ("Ghi chú điều tra cho hồ sơ đã chọn", "Investigation note for selected case"),
    "advanced.case_update": ("Cập nhật hồ sơ", "Update case"),
    "advanced.state.open": ("Đang mở", "Open"),
    "advanced.state.investigating": ("Đang điều tra", "Investigating"),
    "advanced.state.resolved": ("Đã xử lý", "Resolved"),
    "advanced.state.false_positive": ("False positive", "False positive"),
    "advanced.suppression_title": ("Suppression và ngoại lệ có thời hạn", "Time-bounded suppression and exceptions"),
    "advanced.suppression_rule": ("Rule pattern, ví dụ LOCAL_*", "Rule pattern, e.g. LOCAL_*"),
    "advanced.suppression_subject": ("Subject pattern", "Subject pattern"),
    "advanced.suppression_hours": ("Số giờ", "Hours"),
    "advanced.suppression_reason": ("Lý do", "Reason"),
    "advanced.suppression_add": ("Thêm suppression", "Add suppression"),
    "advanced.suppression_count": ("{count} suppression đang hoạt động", "{count} active suppressions"),
    "advanced.lab_title": ("Release lab bắt buộc", "Required release lab"),
    "advanced.lab_note": ("Các test root/VM chỉ được đánh dấu đạt sau khi chạy trong môi trường cô lập.", "Root/VM tests pass only after execution in an isolated environment."),
    "advanced.col_scenario": ("Kịch bản", "Scenario"),
    "advanced.col_isolation": ("Cô lập", "Isolation"),
    "advanced.col_validates": ("Kiểm chứng", "Validates"),
    "advanced.fleet_title": ("Fleet endpoint (certificate + RBAC)", "Fleet endpoints (certificate + RBAC)"),
    "advanced.col_endpoint": ("Endpoint", "Endpoint"),
    "advanced.col_role": ("Vai trò", "Role"),
    "advanced.col_fingerprint": ("Certificate fingerprint", "Certificate fingerprint"),
    "settings.appearance": ("Giao diện", "Appearance"),
    "settings.appearance_dark": ("Tối", "Dark"),
    "settings.appearance_light": ("Sáng", "Light"),
    "settings.appearance_contrast": ("Tương phản cao", "High contrast"),
    # --- Trợ giúp trong ứng dụng ---
    "help.welcome_title": ("Bắt đầu với Shield", "Getting started with Shield"),
    "help.welcome_body": (
        "Shield theo dõi máy Linux và mạng cục bộ. Thanh trên hiển thị vị trí hiện tại và trạng thái Agent. Bắt đầu tại Vận hành → Tổng quan/Sự cố. Màu xám là thông tin, vàng cần xem xét, đỏ cần điều tra sớm.",
        "Shield monitors this Linux endpoint and its local network. The top bar shows your current location and Agent status. Start in Operations → Overview/Incidents. Gray is informational, yellow needs review, and red needs prompt investigation.",
    ),
    "help.navigation_title": ("Điều hướng giao diện", "Navigating the interface"),
    "help.navigation_body": (
        "Vận hành: Tổng quan, Sự cố, Cảnh báo. Giám sát: Thiết bị, Lưu lượng, Log máy, DNS, WiFi. Điều tra: Trung tâm bảo mật, Đánh giá, Tự kiểm tra, Báo cáo. Quản trị: Cài đặt và Trợ giúp. Chọn nhóm bên trái, rồi chọn tab con phía trên.",
        "Operations contains Overview, Incidents, and Alerts. Monitoring contains Devices, Traffic, System Log, DNS, and WiFi. Investigation contains Security Center, Assessment, Self-Audit, and Reports. Management contains Settings and Help. Choose a section on the left, then a page across the top.",
    ),
    "help.incident_title": ("Điều tra một sự cố", "Investigating an incident"),
    "help.incident_body": (
        "Mở tab Sự cố để xem các cảnh báo được nhóm theo đối tượng. Nhấp đúp để xem timeline, sau đó mở Cảnh báo để đọc evidence và playbook. Điểm rủi ro là tín hiệu ưu tiên, không phải kết luận chắc chắn.",
        "Open Incidents to see findings grouped by subject. Double-click for the timeline, then use Alerts to inspect evidence and the playbook. Risk score is a prioritization signal, not a definitive verdict.",
    ),
    "help.response_title": ("Phản ứng và hoàn tác", "Response and rollback"),
    "help.response_body": (
        "Hành động nhạy cảm luôn có bước xem trước và xác nhận. Kiểm tra đúng PID, file hoặc địa chỉ trước khi chạy. Firewall tự hết hạn; file quarantine có mã hoàn tác và không ghi đè file mới tại vị trí cũ.",
        "Sensitive actions always require preview and confirmation. Verify the PID, file, or address before execution. Firewall blocks expire; quarantined files have rollback IDs and never overwrite a new file at the original path.",
    ),
    "help.ai_title": ("Phân tích cục bộ và quyền riêng tư", "Local analysis and privacy"),
    "help.ai_body": (
        "Nút Phân tích cục bộ dùng bộ tóm tắt nhẹ chạy offline, không cần GPU và không gửi log ra Internet. AI không có quyền chặn mạng, dừng process hay quarantine file.",
        "Analyze locally uses a lightweight offline summarizer, requires no GPU, and sends no logs to the Internet. AI has no permission to block traffic, stop processes, or quarantine files.",
    ),
    "help.advanced_title": ("Quy trình điều tra chuyên sâu", "Advanced investigation workflow"),
    "help.advanced_body": (
        "Trong Trung tâm bảo mật, kiểm tra Collector Health trước; dùng tìm kiếm theo PID/hash/IP/user/path để dựng timeline và process graph; tạo hồ sơ, thêm ghi chú và đổi trạng thái. MITRE coverage cho biết kỹ thuật đã quan sát, không phải phần trăm an toàn. Dữ liệu Mô phỏng đến từ Assessment và không huấn luyện baseline.",
        "In Security Center, check Collector Health first; search by PID/hash/IP/user/path to build a timeline and process graph; then create a case, add notes, and update its state. MITRE coverage shows observed techniques, not a safety percentage. Synthetic data comes from Assessment and never trains the baseline.",
    ),
    "help.assessment_title": ("Assessment và Release Lab", "Assessment and Release Lab"),
    "help.assessment_body": (
        "Assessment trong UI chỉ phát sự kiện an toàn trong bộ nhớ và không gọi response. Release Lab là năm kiểm thử thật cần network namespace hoặc VM dùng một lần; Shield không tự đánh dấu đạt. Endpoint isolation tiếp tục bị khóa cho tới khi kiểm thử firewall rollback đạt.",
        "The in-app Assessment emits safe in-memory events and never invokes response. Release Lab contains five real tests requiring a network namespace or disposable VM; Shield never marks them passed automatically. Endpoint isolation stays locked until the firewall rollback test passes.",
    ),
    "help.tools_title": ("Công cụ chính", "Main tools"),
    "help.tools_body": (
        "Trung tâm bảo mật: sức khỏe collector, MITRE, timeline, process graph, case, baseline và fleet. Đánh giá: kiểm thử pipeline an toàn và rule coverage. Thiết bị/DNS/Tự kiểm tra xử lý bề mặt mạng; Báo cáo xuất risk và forensic integrity.",
        "Security Center: collector health, MITRE, timeline, process graph, cases, baselines, and fleet. Assessment safely validates the pipeline and rule coverage. Devices/DNS/Self-Audit cover network surfaces; Reports export risk and forensic integrity.",
    ),
    "help.troubleshoot_title": ("Khắc phục sự cố", "Troubleshooting"),
    "help.troubleshoot_body": (
        "Nếu UI báo mất kết nối: kiểm tra `systemctl status shield-agent`, xem `journalctl -u shield-agent -e`, và bảo đảm user thuộc group `shield`. Sau khi thêm group cần đăng xuất/đăng nhập lại. Dữ liệu nằm tại `/var/lib/shield`.",
        "If the UI reports a lost connection: check `systemctl status shield-agent`, inspect `journalctl -u shield-agent -e`, and ensure your user belongs to the `shield` group. Log out and back in after group changes. Data lives under `/var/lib/shield`.",
    ),
    "help.safety_title": ("Giới hạn an toàn", "Safety boundaries"),
    "help.safety_body": (
        "Chỉ quét hệ thống và dải mạng bạn sở hữu hoặc được cấp phép. Plugin là mã tin cậy và mặc định tắt. Không bật phản ứng tự động trước khi đã kiểm thử preview/rollback trong môi trường của bạn.",
        "Scan only systems and ranges you own or are authorized to test. Plugins are trusted code and disabled by default. Do not enable automatic response until preview and rollback are tested in your environment.",
    ),
    # --- Tổng quan ---
    "overview.sub": (
        "Suy ra từ 5 cảnh báo gần nhất — không tính lịch sử cũ.",
        "Derived from the 5 most recent alerts — not the full history.",
    ),
    "overview.devices_online": ("Thiết bị online", "Devices online"),
    "overview.alerts_24h": ("Cảnh báo 24h", "Alerts (24h)"),
    "overview.active_blocks": ("Đang chặn", "Active blocks"),
    "overview.watching": ("Toàn vẹn forensic", "Forensic integrity"),
    "overview.ledger_ok": ("Hợp lệ", "Verified"),
    "overview.ledger_bad": ("Lỗi tại #{record}", "Invalid at #{record}"),
    "overview.recent_alerts": ("5 cảnh báo gần nhất", "5 most recent alerts"),
    "overview.online_of": ("{online} thiết bị online (5 phút gần nhất) / {total} đã từng thấy",
                            "{online} devices online (last 5 min) / {total} ever seen"),
    # --- Thiết bị ---
    "devices.sub": (
        "Danh sách thiết bị đã từng thấy trên mạng.",
        "Devices ever seen on the network.",
    ),
    "devices.scan_quick": ("Quét nhanh", "Quick scan"),
    "devices.scan_quick_tip": ("arp-scan --localnet — vài giây", "arp-scan --localnet — a few seconds"),
    "devices.scan_deep": ("Quét sâu", "Deep scan"),
    "devices.scan_deep_tip": ("nmap -sn toàn subnet — có thể mất 1–2 phút", "nmap -sn across the subnet — may take 1–2 minutes"),
    "devices.scanning_quick": ("Đang quét nhanh...", "Quick scan running..."),
    "devices.scanning_deep": ("Đang quét sâu...", "Deep scan running..."),
    "devices.scanning_range": ("Đang quét dải mạng được cấp phép...", "Scanning authorized range..."),
    "devices.col_action": ("Hành động", "Action"),
    "devices.col_monitor": ("Theo dõi", "Monitor"),
    "devices.dossier_online": (
        "● ĐANG ONLINE — có tín hiệu trong 5 phút gần nhất.",
        "● ONLINE NOW — seen within the last 5 minutes.",
    ),
    "devices.dossier_offline": (
        "○ Offline — không thấy tín hiệu đã {minutes} phút.",
        "○ Offline — no signal for {minutes} minutes.",
    ),
    "devices.dossier_addresses": (
        "Địa chỉ IP đã dùng: {ips} · {macs} địa chỉ MAC · {count} lần quan sát",
        "IP addresses used: {ips} · {macs} MAC address(es) · {count} observations",
    ),
    "devices.dossier_ports": (
        "Cổng đang mở: {ports}", "Open ports: {ports}",
    ),
    "devices.dossier_alerts": (
        "{count} cảnh báo liên quan (cao nhất: {severity}) · gần nhất {latest} — {rule}",
        "{count} related alert(s) (highest: {severity}) · latest {latest} — {rule}",
    ),
    "devices.dossier_no_alerts": (
        "Chưa có cảnh báo nào liên quan tới thiết bị này.",
        "No alerts have involved this device.",
    ),
    "devices.col_online": ("Kết nối", "Connection"),
    "devices.online": ("Online", "Online"),
    "devices.offline": ("Offline", "Offline"),
    "devices.unknown_name": ("Chưa rõ tên", "Unnamed"),
    "overview.devices_value": (
        "{online} online / {total}", "{online} online / {total}",
    ),
    "overview.online_title": (
        "Thiết bị đang online", "Devices online right now",
    ),
    "overview.online_note": (
        "Online = có tín hiệu trong {minutes} phút gần nhất. Số ở ô trên và số dòng "
        "trong bảng này luôn phải khớp nhau.",
        "Online = seen within the last {minutes} minutes. The number in the tile above "
        "and the row count here always match.",
    ),
    "overview.online_none": (
        "Chưa thấy thiết bị nào online. Nếu mạng đang có máy chạy thật thì hãy xem "
        "tốc độ sự kiện bên dưới — bằng 0 nghĩa là collector đã ngừng thu.",
        "No devices seen online. If machines really are running on this network, check "
        "the live event rate below — zero means collection has stopped.",
    ),
    "devices.col_status": ("Trạng thái", "Status"),
    "devices.col_name": ("Tên thiết bị", "Device name"),
    "devices.col_type": ("Loại dự đoán", "Likely type"),
    "devices.col_confidence": ("Độ tin cậy", "Confidence"),
    "devices.col_mac": ("MAC", "MAC"),
    "devices.col_ip": ("IP", "IP"),
    "devices.col_vendor": ("Vendor", "Vendor"),
    "devices.col_hostname": ("Hostname", "Hostname"),
    "devices.col_first_seen": ("Lần đầu thấy", "First seen"),
    "devices.col_last_seen": ("Lần cuối thấy", "Last seen"),
    "devices.col_risk": ("Rủi ro", "Risk"),
    "devices.trust_btn": ("Tin cậy", "Trust"),
    "devices.untrust_btn": ("Bỏ tin cậy", "Untrust"),
    "devices.watch_btn": ("Theo dõi", "Watch"),
    "devices.unwatch_btn": ("Dừng", "Stop"),
    "devices.audit_btn": ("Kiểm tra", "Audit"),
    "devices.status_trusted": ("✓ Tin cậy", "✓ Trusted"),
    "devices.status_new": ("? Mới", "? New"),
    "devices.profile_title": ("Hồ sơ thiết bị đã quan sát", "Observed device profile"),
    "devices.select_device": ("Chọn một thiết bị để xem hồ sơ.", "Select a device to view its profile."),
    "devices.identity_summary": (
        "{id} • Có khả năng: {type} ({confidence}%) • IP {ip} • MAC {mac} • Lần đầu {first} • Gần nhất {last}",
        "{id} • Likely: {type} ({confidence}%) • IP {ip} • MAC {mac} • First {first} • Latest {last}",
    ),
    "devices.name": ("Tên thiết bị", "Device name"),
    "devices.owner": ("Nhãn chủ sở hữu", "Owner label"),
    "devices.location": ("Phòng/vị trí", "Room/location"),
    "devices.purpose": ("Mục đích", "Purpose"),
    "devices.save_profile": ("Lưu hồ sơ", "Save profile"),
    "devices.why": ("Vì sao Shield đưa ra nhận định này", "Why Shield thinks this"),
    "devices.evidence_signal": ("Tín hiệu", "Signal"),
    "devices.evidence_value": ("Giá trị quan sát", "Observed value"),
    "devices.evidence_reason": ("Ý nghĩa", "Reason"),
    "devices.profile_disclaimer": (
        "Loại thiết bị là ước tính có thể giải thích, không phải sự thật đã xác nhận. Risk score dùng để ưu tiên điều tra, không chứng minh thiết bị đã bị xâm nhập.",
        "Device type is an explainable estimate, not a confirmed fact. Risk score prioritizes investigation; it does not prove compromise.",
    ),
    "devices.no_evidence": ("Chưa đủ tín hiệu để phân loại. Shield giữ loại Unknown thay vì đoán chắc chắn.", "Not enough signals to classify. Shield keeps this Unknown instead of making a confident guess."),
    "devices.merge": ("Gộp thiết bị", "Merge device"),
    "devices.split": ("Tách MAC", "Split MAC"),
    "devices.merge_confirm": ("Gộp hai identity này? Chỉ thực hiện khi bạn biết đó là cùng một thiết bị.", "Merge these identities? Continue only if you know they are the same device."),
    "devices.split_confirm": ("Tách MAC {mac} thành identity riêng?", "Split MAC {mac} into a separate identity?"),
    "devices.criticality.Critical": ("Tối quan trọng", "Critical"),
    "devices.criticality.Important": ("Quan trọng", "Important"),
    "devices.criticality.Normal": ("Bình thường", "Normal"),
    "devices.criticality.Low priority": ("Ưu tiên thấp", "Low priority"),
    "devices.evidence.mac_vendor": ("Nhà sản xuất MAC", "MAC vendor"),
    "devices.evidence.mac_vendor.reason": ("Nhà sản xuất thường gắn với loại thiết bị được dự đoán.", "The vendor is commonly associated with the predicted device type."),
    "devices.evidence.hostname": ("Hostname", "Hostname"),
    "devices.evidence.hostname.reason": ("Tên máy có đặc điểm thường gặp của loại thiết bị này.", "The hostname resembles this device type."),
    "devices.evidence.network_role": ("Vai trò mạng", "Network role"),
    "devices.evidence.network_role.reason": ("Thiết bị là default gateway đã được xác nhận.", "The device is the confirmed default gateway."),
    "devices.evidence.mac_address": ("Địa chỉ MAC", "MAC address"),
    "devices.evidence.mac_address.reason": ("MAC riêng tư thường xuất hiện trên thiết bị di động.", "Privacy MAC addresses are common on mobile devices."),
    "devices.evidence.open_ports": ("Cổng đang mở", "Open ports"),
    "devices.evidence.open_ports.reason": ("Các cổng quan sát được thường gắn với loại thiết bị này.", "The observed ports are commonly associated with this device type."),
    "devices.evidence.protocols": ("Giao thức", "Protocols"),
    "devices.evidence.protocols.reason": ("Các giao thức quan sát được hỗ trợ nhận định này.", "The observed protocols support this inference."),
    "devices.evidence.services": ("Dịch vụ", "Services"),
    "devices.evidence.services.reason": ("Dịch vụ quan sát được hỗ trợ nhận định này.", "The observed services support this inference."),
    "devices.evidence.file_services": ("Dịch vụ chia sẻ file", "File-sharing services"),
    "devices.evidence.file_services.reason": ("Dịch vụ chia sẻ file là tín hiệu thường gặp ở NAS.", "File-sharing services are a common NAS signal."),
    "devices.type.Phone": ("Điện thoại", "Phone"),
    "devices.type.Tablet": ("Máy tính bảng", "Tablet"),
    "devices.type.Laptop": ("Laptop", "Laptop"),
    "devices.type.Desktop": ("Máy tính bàn", "Desktop"),
    "devices.type.Router": ("Router", "Router"),
    "devices.type.Access Point": ("Điểm truy cập", "Access Point"),
    "devices.type.Smart TV": ("TV thông minh", "Smart TV"),
    "devices.type.Streaming Device": ("Thiết bị streaming", "Streaming Device"),
    "devices.type.Printer": ("Máy in", "Printer"),
    "devices.type.NAS": ("NAS", "NAS"),
    "devices.type.Server": ("Máy chủ", "Server"),
    "devices.type.Camera": ("Camera", "Camera"),
    "devices.type.IoT": ("IoT", "IoT"),
    "devices.type.Game Console": ("Máy chơi game", "Game Console"),
    "devices.type.Virtual Machine": ("Máy ảo", "Virtual Machine"),
    "devices.type.Unknown": ("Chưa xác định", "Unknown"),
    # --- Cảnh báo ---
    "alerts.sub": ("Nhấp đôi 1 dòng để mở playbook hành động.", "Double-click a row to open the action playbook."),
    "alerts.pin_gateway": ("Pin ARP gateway (chống MITM)", "Pin gateway ARP (anti-MITM)"),
    "alerts.col_time": ("Thời gian", "Time"),
    "alerts.col_severity": ("Mức", "Severity"),
    "alerts.col_title": ("Tiêu đề", "Title"),
    "alerts.col_detail": ("Chi tiết", "Detail"),
    "alerts.col_subject": ("Đối tượng", "Subject"),
    "audit.col_host": ("Máy", "Host"),
    "alerts.no_playbook": ("Alert này không có hành động gợi ý.", "This alert has no suggested actions."),
    "alerts.confirm_title": ("Xác nhận hành động", "Confirm action"),
    "alerts.pin_confirm": (
        "Sẽ chạy trên agent: ip neigh replace <gateway> lladdr <mac_đã_baseline> nud "
        "permanent.\n\nSau lệnh này, ARP spoof không lừa được máy bạn nữa. Cần đã xác "
        "nhận baseline gateway trước. Tiếp tục?",
        "Runs on the agent: ip neigh replace <gateway> lladdr <baseline_mac> nud "
        "permanent.\n\nAfter this, ARP spoofing can't fool your machine's gateway "
        "entry anymore. Requires the gateway baseline to be confirmed first. Continue?",
    ),
    # --- Lưu lượng ---
    "traffic.placeholder": (
        'Chưa theo dõi thiết bị nào — bấm "Theo dõi" ở tab Thiết bị',
        'No device being watched — click "Watch" in the Devices tab',
    ),
    "traffic.watching_fmt": ("Đang theo dõi: {ip} — {bps:,} bytes/s (giây gần nhất)",
                             "Watching: {ip} — {bps:,} bytes/s (last second)"),
    "traffic.axis_bps": ("Bytes/giây", "Bytes/second"),
    "traffic.axis_seconds": ("Giây gần nhất", "Recent seconds"),
    "traffic.no_pyqtgraph": (
        "(chưa cài pyqtgraph — chỉ hiện số liệu dạng chữ)",
        "(pyqtgraph not installed — showing text-only numbers)",
    ),
    # --- Tự kiểm tra ---
    "audit.sub": (
        "Quét cổng mở trên chính máy này và thiết bị đã đánh dấu tin cậy — chỉ liệt "
        "kê, không khai thác. Chỉ chạy khi bạn bấm, không tự động nền (trừ khi bạn bật "
        "lịch quét sâu ở Cài đặt).",
        "Scans open ports on this machine and devices you've marked trusted — "
        "listing only, never exploiting. Runs only when you click it, unless you "
        "enable the deep-scan schedule in Settings.",
    ),
    "audit.rescan_all": ("Quét lại tất cả host tin cậy", "Re-scan all trusted hosts"),
    "audit.rescan_one": ("Quét lại", "Re-scan"),
    "audit.col_port": ("Cổng", "Port"),
    "audit.col_service": ("Dịch vụ", "Service"),
    "audit.col_risk": ("Mức rủi ro", "Risk level"),
    "audit.col_suggestion": ("Nên làm gì", "What to do"),
    "audit.col_cve": ("Gợi ý CVE (tham khảo)", "CVE hint (reference)"),
    "audit.risk_danger": ("Nguy hiểm", "Danger"),
    "audit.risk_caution": ("Nên xem lại", "Review"),
    "audit.risk_safe": ("Bình thường", "Normal"),
    "audit.this_machine": ("Máy này", "This machine"),
    "audit.no_hosts": (
        "Chưa quét host nào — bấm \"Quét lại tất cả host tin cậy\" ở trên.",
        "No hosts scanned yet — click \"Re-scan all trusted hosts\" above.",
    ),
    "audit.scanning": ("Đang quét {host}...", "Scanning {host}..."),
    # --- Log máy ---
    "log.sub": (
        "Chỉ 4 loại đã lọc: SSH, sudo, USB mới, promiscuous mode — không phải toàn bộ journal.",
        "Only 4 filtered kinds: SSH, sudo, new USB, promiscuous mode — not the full journal.",
    ),
    "log.col_time": ("Thời gian", "Time"),
    "log.col_kind": ("Loại", "Kind"),
    "log.col_detail": ("Chi tiết", "Detail"),
    "log.kind.ssh_failed_password": ("SSH sai mật khẩu", "SSH wrong password"),
    "log.kind.sudo_failed": ("sudo thất bại", "sudo failure"),
    "log.kind.usb_new": ("USB mới cắm", "New USB plugged in"),
    "log.kind.promisc_mode": ("Interface vào promiscuous mode", "Interface entered promiscuous mode"),
    # --- Báo cáo ---
    "reports.sub": (
        "Nhìn tổng thể theo ngày/tuần thay vì chỉ phản ứng từng cảnh báo riêng lẻ.",
        "See the daily/weekly big picture instead of reacting to alerts one by one.",
    ),
    "reports.period_today": ("Hôm nay", "Today"),
    "reports.period_7d": ("7 ngày", "7 days"),
    "reports.period_30d": ("30 ngày", "30 days"),
    "reports.export": ("Xuất báo cáo (.txt)", "Export report (.txt)"),
    "reports.export_done": ("Đã lưu báo cáo: {path}", "Report saved: {path}"),
    "reports.new_devices": ("Thiết bị mới", "New devices"),
    "reports.critical_alerts": ("Cảnh báo nguy cấp", "Critical alerts"),
    "reports.standard_alerts": ("Cảnh báo mức thường", "Standard alerts"),
    "reports.actions_taken": ("Hành động đã thực hiện", "Actions taken"),
    "reports.alerts_by_day": ("Cảnh báo theo ngày", "Alerts by day"),
    "reports.digest": ("Tóm tắt", "Summary"),
    "reports.no_alerts": ("Không có cảnh báo nào trong khoảng thời gian này.",
                           "No alerts in this period."),
    "reports.export_pdf": ("Xuất báo cáo (.pdf)", "Export report (.pdf)"),
    "reports.pdf_report_title": (
        "Báo cáo giám sát mạng — Shield", "Network Monitoring Report — Shield",
    ),
    "reports.pdf_generated_at": (
        "Khoảng thời gian: {period} — Xuất lúc: {ts}",
        "Period: {period} — Generated at: {ts}",
    ),
    "reports.pdf_summary": ("Tóm tắt", "Summary"),
    "reports.pdf_evidence": ("Bảng bằng chứng (theo thời gian)", "Evidence table (chronological)"),
    "reports.pdf_detail": ("Chi tiết từng cảnh báo", "Per-alert detail"),
    "reports.pdf_col_ts": ("Thời gian", "Timestamp"),
    "reports.pdf_col_severity": ("Mức độ", "Severity"),
    "reports.pdf_col_title": ("Tiêu đề", "Title"),
    "reports.pdf_col_subject": ("Đối tượng", "Subject"),
    # --- Cài đặt ---
    "settings.sub": (
        "Nguồn sự thật là nftables/agent — các form dưới đây gửi lệnh, không tự ghi trạng thái.",
        "nftables/agent is the source of truth — these forms send commands, they don't write state directly.",
    ),
    "settings.language": ("Ngôn ngữ hiển thị", "Display language"),
    "settings.rescan_title": (
        "Làm mới phiên quét", "Reset the scan session",
    ),
    "settings.rescan_hint": (
        "Quên các thiết bị đã phát hiện rồi dò lại mạng từ đầu. Hữu ích khi bạn đổi "
        "mạng, hoặc khi danh sách đã đầy thiết bị cũ và điện thoại người qua đường. "
        "Lịch sử sự kiện, cảnh báo và sổ bằng chứng KHÔNG bị đụng tới.",
        "Forget the devices already discovered and scan the network again from scratch. "
        "Useful after changing networks, or when the list has filled up with old devices "
        "and passing phones. Event history, alerts and the forensic ledger are NOT touched.",
    ),
    "settings.rescan_7d": ("Chỉ thiết bị không thấy quá 7 ngày", "Only devices unseen for 7 days"),
    "settings.rescan_30d": ("Chỉ thiết bị không thấy quá 30 ngày", "Only devices unseen for 30 days"),
    "settings.rescan_all": ("Toàn bộ thiết bị", "Every device"),
    # --- Xuất log ra thư mục người dùng chọn ---
    # --- Điều tra bằng AI (Phase 2, chỉ đọc) ---
    # --- Phản ứng: hàng đợi việc, lịch sử trạng thái, bằng chứng hậu kiểm ---
    "nav.response": ("Phản ứng", "Response"),
    "respqueue.title": ("Hàng đợi phản ứng", "Response queue"),
    "response.kill_switch": ("Dừng mọi hành động phản ứng", "Stop all response actions"),
    "response.kill_switch_hint": (
        "Chặn mọi lần áp hành động mới. KHÔNG chặn việc gỡ — một công tắc an toàn mà "
        "cũng chặn đường gỡ sẽ đóng băng mọi luật firewall đang áp, và người bấm nó để "
        "dừng thiệt hại lại là người gây ra thiệt hại lớn hơn. Việc đã duyệt vẫn nằm chờ "
        "và chạy lại được khi bạn tắt công tắc.",
        "Blocks every new action from being applied. It does NOT block rollbacks — a "
        "safety switch that also blocked the way out would freeze every firewall rule in "
        "place, and the person pressing it to stop the damage would cause more. Approved "
        "work stays queued and runs once you turn the switch off.",
    ),
    "response.kill_switch_on": ("Phản ứng đang DỪNG.", "Response is STOPPED."),
    "response.kill_switch_off": ("Phản ứng đang hoạt động.", "Response is active."),
    # Lý do dịch được từ adapter. Agent gửi MÃ, giao diện dịch.
    "response.block_err_invalid": ("địa chỉ không hợp lệ", "the address is not valid"),
    "response.block_err_reserved": ("nằm trong dải luôn được bảo vệ",
                                     "it is inside an always-protected range"),
    "response.block_err_multicast": ("địa chỉ multicast", "it is a multicast address"),
    "response.block_err_gateway": (
        "đây là gateway — chặn nó là tự cắt mạng của chính máy này",
        "this is the gateway — blocking it cuts this machine off the network"),
    "response.block_err_management": (
        "đây là địa chỉ quản trị — chặn nó là mất đường vào để sửa",
        "this is the management address — blocking it removes the way back in"),
    "response.block_err_resolver": (
        "đây là máy chủ DNS — chặn nó làm hỏng mọi thứ dựa vào tên miền",
        "this is a DNS server — blocking it breaks everything that uses names"),
    "response.block_err_no_ttl": (
        "chặn phải có thời hạn — chặn vĩnh viễn thì không ai nhớ để gỡ",
        "a block must have a deadline — a permanent one is never remembered"),
    "response.block_err_no_helper": ("không có privileged helper để áp luật",
                                      "there is no privileged helper to apply the rule"),
    "response.verify_err_no_reader": (
        "không có cách đọc lại ruleset để kiểm chứng",
        "there is no way to read the ruleset back for verification"),
    "response.verify_err_unreadable": ("không đọc được ruleset: {error}",
                                        "the ruleset could not be read: {error}"),
    "response.verify_err_absent": (
        "{ip} không có trong set blocked_ips sau khi áp",
        "{ip} is not in the blocked_ips set after applying"),
    "response.ratelimit_err_absent": (
        "{ip} không có trong set ratelimited_ips sau khi áp",
        "{ip} is not in the ratelimited_ips set after applying"),
    "response.snapshot_err_no_dir": ("không tạo được thư mục chụp: {error}",
                                      "the snapshot directory could not be created: {error}"),
    "response.snapshot_err_disk_full": ("ổ đĩa sắp đầy", "the disk is nearly full"),
    "response.snapshot_err_no_path": ("không biết file nào để kiểm",
                                       "there is no file to check"),
    "response.snapshot_err_missing": ("file chụp không tồn tại: {path}",
                                       "the snapshot file does not exist: {path}"),
    "response.snapshot_err_empty": ("file chụp rỗng: {path}",
                                     "the snapshot file is empty: {path}"),
    "response.snapshot_err_too_big": ("file chụp vượt trần dung lượng: {path}",
                                       "the snapshot file exceeds its size limit: {path}"),
    "response.isolate_err_bad_plan": ("kế hoạch cách ly không hợp lệ: {error}",
                                       "the isolation plan is not valid: {error}"),
    "response.isolate_err_no_deadman": (
        "chưa có dead-man switch để tự gỡ — cách ly rồi mất khả năng gỡ là hỏng nặng hơn",
        "there is no dead-man switch to lift it — isolating with no way back is worse"),
    "response.isolate_err_no_helper": ("không có privileged helper để áp luật firewall",
                                        "there is no privileged helper to apply the rules"),
    "response.isolate_err_no_reader": (
        "không đọc lại được ruleset để kiểm chứng — không kiểm chứng được thì không áp",
        "the ruleset cannot be read back to verify — no verification means no apply"),
    "response.isolate_err_not_verified": ("cách ly không vượt qua kiểm chứng: {reason}",
                                           "isolation did not pass verification: {reason}"),
    "response.state.rate_limit_ip": ("Giới hạn tốc độ", "Rate limit"),
    "response.sub": (
        "Mọi hành động Shield định làm, đã làm, hoặc đã gỡ. Không hành động nào chạy mà "
        "không để lại đủ dấu vết để dựng lại sau này.",
        "Everything Shield intends to do, has done, or has rolled back. No action runs "
        "without leaving enough trace to reconstruct it later.",
    ),
    "response.col_action": ("Hành động", "Action"),
    "response.col_target": ("Đối tượng", "Target"),
    "response.col_state": ("Trạng thái", "State"),
    "response.col_ttl": ("Tự gỡ sau", "Lifts after"),
    "response.col_updated": ("Cập nhật", "Updated"),
    "response.empty": ("Chưa có hành động phản ứng nào.", "No response actions yet."),
    "response.approve": ("Duyệt", "Approve"),
    "response.deny": ("Từ chối", "Deny"),
    "response.rollback": ("Gỡ ngay", "Roll back now"),
    "response.refresh": ("Tải lại", "Reload"),
    "response.select_first": ("Chọn một hành động ở bảng trên trước.",
                              "Select an action in the table above first."),
    "response.history_title": ("Lịch sử trạng thái", "State history"),
    "response.history_empty": ("Chọn một hành động để xem lịch sử.",
                               "Select an action to see its history."),
    "response.verification_title": ("Bằng chứng hậu kiểm", "Post-verification evidence"),
    "response.verification_empty": (
        "Chưa kiểm chứng lần nào. Một hành động chưa kiểm chứng KHÔNG có nghĩa là đã "
        "thành công — chỉ có nghĩa là chưa ai đọc lại trạng thái hệ thống.",
        "No verification yet. An unverified action does NOT mean it succeeded — only "
        "that nobody has read the system state back.",
    ),
    "response.verified_yes": ("ĐÃ KIỂM CHỨNG từ trạng thái hệ thống thật",
                              "VERIFIED against real system state"),
    "response.verified_no": ("KIỂM CHỨNG THẤT BẠI — đừng tin là nó đã có hiệu lực",
                             "VERIFICATION FAILED — do not assume it took effect"),
    "response.observed": ("Quan sát được: {observed}", "Observed: {observed}"),
    "response.needs_human": ("Cần người duyệt", "Needs a human"),
    "response.automatic": ("Được phép tự động", "May run automatically"),
    "response.confirm_approve": (
        "Duyệt hành động {action} lên {target}?\n\nNó sẽ được áp rồi kiểm chứng lại từ "
        "trạng thái hệ thống thật, và tự gỡ sau {ttl} giây.",
        "Approve {action} against {target}?\n\nIt will be applied, then verified against "
        "real system state, and lifts itself after {ttl} seconds.",
    ),
    "response.confirm_rollback": (
        "Gỡ ngay hành động {action} lên {target}?",
        "Roll back {action} against {target} now?",
    ),
    # Tên trạng thái. Dịch được, vì "APPLY_FAILED" không nói gì với người không
    # đọc mã nguồn.
    "response.state.PROPOSED": ("Đang đề xuất", "Proposed"),
    "response.state.APPROVED": ("Đã duyệt", "Approved"),
    "response.state.DENIED": ("Đã từ chối", "Denied"),
    "response.state.EXPIRED": ("Hết hạn chờ", "Expired"),
    "response.state.APPLYING": ("Đang áp", "Applying"),
    "response.state.APPLIED": ("Đã áp, chưa kiểm chứng", "Applied, not yet verified"),
    "response.state.APPLY_FAILED": ("Áp thất bại", "Apply failed"),
    "response.state.VERIFYING": ("Đang kiểm chứng", "Verifying"),
    "response.state.VERIFIED": ("Đã kiểm chứng", "Verified"),
    "response.state.VERIFY_FAILED": ("Kiểm chứng thất bại", "Verification failed"),
    "response.state.ROLLING_BACK": ("Đang gỡ", "Rolling back"),
    "response.state.ROLLED_BACK": ("Đã gỡ", "Rolled back"),
    "response.state.ROLLBACK_FAILED": (
        "GỠ THẤT BẠI — hệ thống đang ở trạng thái không xác định",
        "ROLLBACK FAILED — the system is in an unknown state"),
    "ai.kill_switch": ("Tắt toàn bộ phân tích AI", "Turn off all AI analysis"),
    "ai.kill_switch_hint": (
        "Chặn mọi lời gọi công cụ của lớp phân tích. Phát hiện, chấm điểm và phản ứng "
        "KHÔNG bị ảnh hưởng — nếu tắt AI cũng làm ngừng phát hiện thì không ai dám tắt.",
        "Blocks every tool call from the analysis layer. Detection, scoring and response "
        "are NOT affected — if turning off AI also stopped detection, nobody would dare.",
    ),
    "ai.kill_switch_on": ("Phân tích AI đang TẮT.", "AI analysis is OFF."),
    "ai.kill_switch_off": ("Phân tích AI đang bật.", "AI analysis is on."),
    "ai.title": ("Phân tích điều tra", "Investigation analysis"),
    "ai.run": ("Phân tích incident đang chọn", "Analyse the selected incident"),
    "ai.disabled": (
        "AI analyst đang TẮT trên máy này. Mọi phát hiện dưới đây đến từ bộ phân tích "
        "cục bộ tất định — nó chỉ đếm và ghép quan hệ, không suy luận.",
        "The AI analyst is OFF on this machine. Everything below comes from the local "
        "deterministic analyser — it only counts and joins relations; it does not reason.",
    ),
    "ai.provider": ("Nguồn phân tích: {provider} / {model}, lúc {when}",
                    "Analysed by {provider} / {model} at {when}"),
    "ai.section_facts": ("Sự kiện quan sát được", "Observed facts"),
    "ai.section_detector": ("Phát hiện của detector", "Detector findings"),
    "ai.section_hypotheses": ("Giả thuyết (chưa được xác nhận)", "Hypotheses (not confirmed)"),
    "ai.section_supporting": ("Bằng chứng ủng hộ", "Supporting evidence"),
    "ai.section_against": ("Bằng chứng mâu thuẫn / còn thiếu",
                           "Contradicting or missing evidence"),
    "ai.section_next": ("Nên tra tiếp", "Suggested next queries"),
    "ai.section_actions": ("Hành động được đề xuất (cần người duyệt)",
                            "Recommended actions (a human must approve)"),
    "ai.no_result": ("Chưa phân tích incident nào.", "No incident analysed yet."),
    "ai.no_hypotheses": ("Không có giả thuyết nào đủ căn cứ để nêu.",
                          "No hypothesis had enough grounding to state."),
    "ai.status_unconfirmed": ("chưa xác nhận", "unconfirmed"),
    "ai.status_supported": ("có căn cứ", "supported"),
    "ai.status_contradicted": ("bị mâu thuẫn", "contradicted"),
    "ai.status_insufficient_evidence": ("thiếu bằng chứng", "insufficient evidence"),
    "ai.downgraded": ("Đã bị hạ cấp: {reason}", "Downgraded: {reason}"),
    "ai.validator": (
        "Bộ kiểm bằng chứng đã soi {checked} khẳng định, hạ cấp {downgraded}.",
        "The evidence validator checked {checked} claims and downgraded {downgraded}.",
    ),
    "ai.validator_unknown": (
        "{count} tham chiếu bằng chứng không tồn tại — model đã bịa.",
        "{count} evidence references do not exist — the model invented them.",
    ),
    "ai.validator_scope": (
        "{count} tham chiếu nằm ngoài phạm vi điều tra này.",
        "{count} references fall outside the scope of this investigation.",
    ),
    "ai.error": ("Phân tích không hoàn tất: {reason}", "The analysis did not complete: {reason}"),
    "ai.never_confirmed": (
        "Shield không bao giờ ghi \"đã xác nhận\" chỉ vì phân tích tự tin. Xác nhận là "
        "việc của bạn, sau khi đọc bằng chứng.",
        "Shield never writes \"confirmed\" just because an analysis sounds confident. "
        "Confirming is your job, after you have read the evidence.",
    ),
    "ai.select_first": ("Chọn một incident ở bảng trên trước.",
                        "Select an incident in the table above first."),
    # Câu do bộ phân tích cục bộ sinh ra. Nó là mã tất định của Shield, nên nó
    # nói bằng KHOÁ chứ không bằng câu — một model ngôn ngữ thì không thể, và
    # đó là khác biệt phải nhìn thấy được.
    "ai.local.summary": ("Phân tích cục bộ tất định. Quan hệ tìm thấy: {breakdown}.",
                          "Deterministic local analysis. Relations found: {breakdown}."),
    "ai.local.summary_empty": (
        "Phân tích cục bộ tất định. Không có quan hệ nào trong cửa sổ điều tra.",
        "Deterministic local analysis. No relations inside the investigation window."),
    "ai.local.h_write_connect": (
        "Tiến trình {process} ghi một file rồi mở kết nối ra ngoài trong cùng cửa sổ điều tra.",
        "Process {process} wrote a file and then opened an outbound connection inside the "
        "same window."),
    "ai.local.h_many_children": (
        "Tiến trình {process} sinh ra {count} tiến trình con.",
        "Process {process} spawned {count} child processes."),
    "ai.local.h_new_listener": (
        "Dịch vụ {service} mở cổng lắng nghe.",
        "Service {service} opened a listening port."),
    "ai.local.missing_exec": (
        "Chưa biết file đã ghi có được thực thi lại hay không.",
        "It is not known whether the written file was later executed."),
    "ai.local.missing_baseline": (
        "Chưa so với hành vi thường ngày của tiến trình này.",
        "This has not been compared against the process's usual behaviour."),
    "ai.local.missing_port_history": (
        "Chưa biết cổng này đã mở từ trước hay mới xuất hiện.",
        "It is not known whether this port was already open or is new."),
    "ai.local.limitation": (
        "Bộ phân tích cục bộ chỉ đếm và ghép quan hệ; nó không suy luận về ý đồ và "
        "không xác nhận được điều gì.",
        "The local analyser only counts and joins relations; it does not reason about "
        "intent and cannot confirm anything."),
    # Lượt điều tra không hoàn thành. Câu này phải nói rõ người đọc đang xem
    # gì — một bản tóm tắt tất định, KHÔNG phải kết luận của model. Không nói
    # rõ thì một bản dự phòng đọc y hệt một bản đầy đủ.
    "ai.fallback.limitation": (
        "Lượt điều tra không hoàn thành; đây là phân tích tất định cục bộ trên dữ "
        "liệu đã thu được, không phải kết luận của model.",
        "The investigation did not complete; this is a local deterministic analysis "
        "of the data already gathered, not a model's conclusion."),
    "ai.local.q_file_history": ("Tra lịch sử của file đã ghi", "Look up the written file's history"),
    "ai.local.q_ancestry": ("Tra chuỗi tiến trình cha", "Look up the process ancestry"),
    "ai.local.q_baseline": ("So số tiến trình con với hành vi thường ngày",
                             "Compare the child-process count against the baseline"),
    # --- Phase 3D: khuôn báo cáo sự cố ---
    #
    # Backend sinh KHOÁ, giao diện dịch. Không câu nào của báo cáo được viết
    # sẵn trong `shield/report/` — đó là bất biến đã phải học ba lần trong dự
    # án này, và một lần nữa ở Guardian.
    #
    # Giới hạn `unknown_scenario` CỐ Ý không nhắc tới AI: nó nói Shield chưa
    # có khuôn riêng, vì đó mới là sự thật — phân loại là tất định và không
    # model nào tham gia. Đổ lỗi cho AI ở đây sẽ dạy người đọc rằng bật AI
    # lên thì báo cáo sẽ tốt hơn, điều không đúng.
    "report.template.access_then_unseen_behaviour": (
        "Đăng nhập rồi có hành vi lạ",
        "Access followed by unseen behaviour"),
    "report.template.agent_stopped": (
        "Shield agent đã dừng",
        "The Shield agent stopped"),
    "report.template.arp_flood": (
        "Bão gói ARP",
        "Gratuitous ARP flood"),
    "report.template.arp_spoofing": (
        "Xung đột ARP — nghi giả mạo",
        "ARP conflict — possible spoofing"),
    "report.template.audit_trail_damaged": (
        "Nhật ký kiểm toán bị hỏng",
        "The audit trail is damaged"),
    "report.template.clock_tampering": (
        "Đồng hồ hệ thống bị lùi",
        "The system clock moved backwards"),
    "report.template.deleted_running_executable": (
        "File thực thi đã xoá vẫn đang chạy",
        "Deleted executable is still running"),
    "report.template.device_at_unusual_time": (
        "Thiết bị xuất hiện vào giờ bất thường",
        "Device appeared at an unusual hour"),
    "report.template.login_at_unusual_time": (
        "Đăng nhập vào giờ bất thường",
        "Login at an unusual hour"),
    "report.template.dns_resolver_changed": (
        "Máy chủ DNS bị đổi",
        "DNS resolver changed"),
    "report.template.execution_from_suspicious_path": (
        "Thực thi từ đường dẫn đáng ngờ",
        "Execution from a suspicious path"),
    "report.template.file_integrity_change": (
        "File quan trọng bị thay đổi",
        "A watched file changed"),
    "report.template.gateway_impersonation": (
        "Giả mạo gateway",
        "Gateway impersonation"),
    "report.template.generic": (
        "Sự cố an ninh",
        "Security incident"),
    "report.template.icmp_redirect": (
        "Chuyển hướng ICMP",
        "ICMP redirect"),
    "report.template.installation_changed": (
        "Bản cài Shield bị thay đổi",
        "The Shield installation changed"),
    "report.template.isolation_rolled_back": (
        "Cách ly hết hạn và đã được gỡ",
        "Endpoint isolation expired and was lifted"),
    "report.template.mac_randomisation": (
        "Địa chỉ MAC ngẫu nhiên hoá",
        "Randomised MAC address"),
    "report.template.mitm_with_dns_change": (
        "Giả mạo gateway kèm đổi DNS",
        "Gateway impersonation with a DNS change"),
    "report.template.network_device_auth_failure": (
        "Thiết bị mạng báo đăng nhập sai",
        "Network device reported a failed login"),
    "report.template.network_device_config_change": (
        "Thiết bị mạng bị đổi cấu hình",
        "Network device configuration changed"),
    "report.template.network_device_restart": (
        "Thiết bị mạng khởi động lại",
        "Network device restarted"),
    "report.template.new_device_on_network": (
        "Thiết bị mới trong mạng",
        "New device on the network"),
    "report.template.new_device_then_scan": (
        "Thiết bị lạ rồi quét cổng",
        "Unknown device joined, then scanned"),
    "report.template.port_scan": (
        "Quét cổng",
        "Port scan"),
    "report.template.promiscuous_interface": (
        "Card mạng ở chế độ nghe lén",
        "Interface in promiscuous mode"),
    "report.template.recon_then_ssh_attack": (
        "Dò tìm rồi tấn công SSH",
        "Reconnaissance followed by an SSH attack"),
    "report.template.remote_access_port_listening": (
        "Cổng truy cập từ xa đang mở",
        "Remote-access port is listening"),
    "report.template.repeated_auth_failures": (
        "Đăng nhập sai lặp lại",
        "Repeated authentication failures"),
    "report.template.repeated_device_config_changes": (
        "Thiết bị mạng bị đổi cấu hình liên tục",
        "Network device reconfigured repeatedly"),
    "report.template.repeated_device_restarts": (
        "Thiết bị mạng khởi động lại liên tục",
        "Network device keeps restarting"),
    "report.template.repeated_telemetry_loss": (
        "Mất bản ghi telemetry liên tục",
        "Telemetry records keep being lost"),
    "report.template.response_did_not_apply": (
        "Hành động phản ứng không áp được",
        "A response action did not apply"),
    "report.template.rogue_dhcp": (
        "Máy chủ DHCP lạ",
        "Rogue DHCP server"),
    "report.template.security_config_disabled": (
        "Cấu hình bảo mật bị tắt",
        "Security configuration was disabled"),
    "report.template.service_account_login": (
        "Tài khoản hệ thống đăng nhập",
        "System account signed in"),
    "report.template.ssh_auth_failure": (
        "Đăng nhập SSH thất bại",
        "Failed SSH login"),
    "report.template.ssh_brute_force": (
        "Dò mật khẩu SSH",
        "SSH password guessing"),
    "report.template.ssh_root_login": (
        "Đăng nhập root qua SSH",
        "Root login over SSH"),
    "report.template.sudo_failure": (
        "Nâng quyền sudo thất bại",
        "Failed sudo escalation"),
    "report.template.suspicious_execution_chain": (
        "Chuỗi thực thi đáng ngờ",
        "Suspicious execution chain"),
    "report.template.tarpit_contact": (
        "Kết nối vào bẫy tarpit",
        "Connection to the tarpit"),
    "report.template.telemetry_loss": (
        "Mất bản ghi telemetry",
        "Telemetry records were lost"),
    "report.template.unexpected_dns_server": (
        "Máy chủ DNS ngoài danh sách",
        "Unexpected DNS server"),
    "report.template.unseen_behaviour": (
        "Hành vi chưa từng thấy",
        "Behaviour never seen before"),
    "report.template.usb_device_attached": (
        "Thiết bị USB được cắm vào",
        "USB device attached"),
    "report.limitation.missing_facts": (
        "Thiếu dữ kiện bắt buộc cho loại sự cố này: {fields}.",
        "Required facts for this incident type are missing: {fields}."),
    "report.limitation.thin_evidence": (
        "Báo cáo này mới gắn được {have} tham chiếu bằng chứng, loại sự cố này cần {need}. Bằng chứng có thể vẫn tồn tại trong kho sự kiện mà chưa được liên kết vào sự cố.",
        "This report resolved {have} evidence references; this incident type expects {need}. Evidence may still exist in the event store without being linked to the incident."),
    "report.limitation.unknown_scenario": (
        "Shield chưa có khuôn báo cáo riêng cho loại phát hiện này, nên báo cáo dùng khuôn chung. Các dữ kiện và bằng chứng bên dưới vẫn đầy đủ và chính xác.",
        "Shield does not yet have a dedicated report template for this kind of detection, so the generic template is used. The facts and evidence below are complete and accurate."),
    "report.limitation.no_ai_explanation": (
        "Báo cáo này không kèm phần diễn giải tuỳ chọn. Mọi mục còn lại được dựng từ dữ liệu đo được và không phụ thuộc phần đó.",
        "This report carries no optional written explanation. Every other section is built from measured data and does not depend on it."),
    # --- Phase 3D: màn hình báo cáo sự cố + trạng thái giải thích ---
    #
    # Câu chữ ở đây được viết cẩn thận theo một luật: KHÔNG câu nào được làm
    # người đọc lo lắng về một thứ không đáng lo. Model hỏng là chuyện thường
    # và hậu quả bằng không — báo cáo vẫn đầy đủ — nên trạng thái hỏng nói
    # đúng như vậy thay vì kêu như một sự cố.
    "report.title": ("Báo cáo sự cố", "Incident report"),
    "report.empty": ("Chưa có báo cáo cho sự việc này.",
                     "No report for this incident yet."),
    "report.deterministic_title": ("Dữ liệu Shield đo được",
                                   "Data measured by Shield"),
    "report.field.scenario": ("Loại sự cố", "Incident type"),
    "report.field.family": ("Nhóm", "Family"),
    "report.field.rule": ("Quy tắc", "Rule"),
    "report.field.severity": ("Mức nghiêm trọng", "Severity"),
    "report.field.risk": ("Điểm rủi ro", "Risk score"),
    "report.field.first_seen": ("Thấy lần đầu", "First seen"),
    "report.field.last_seen": ("Thấy lần cuối", "Last seen"),
    "report.field.subject": ("Đối tượng", "Affected asset"),
    "report.no_facts": ("Chưa có dữ kiện nào được xác lập.",
                        "No facts established yet."),
    "report.missing_fact": ("Thiếu dữ kiện bắt buộc", "Missing required fact"),
    "report.evidence_ref": ("Bằng chứng", "Evidence"),
    "report.no_evidence": ("Chưa có tham chiếu bằng chứng nào được gắn.",
                           "No evidence references linked yet."),
    "report.supporting": ("Phát hiện liên quan", "Supporting detection"),
    "report.section.incident_type": ("Loại sự cố", "Incident type"),
    "report.section.severity": ("Mức nghiêm trọng", "Severity"),
    "report.section.time_window": ("Khoảng thời gian", "Time window"),
    "report.section.affected_asset": ("Đối tượng bị ảnh hưởng", "Affected asset"),
    "report.section.observed_activity": ("Hoạt động quan sát được",
                                         "Observed activity"),
    "report.section.confirmed_facts": ("Dữ kiện đã xác lập", "Confirmed facts"),
    "report.section.validated_evidence": ("Bằng chứng đã kiểm", "Validated evidence"),
    "report.section.supporting_detections": ("Phát hiện liên quan",
                                             "Supporting detections"),
    "report.section.recommended_next_steps": ("Bước tiếp theo nên làm",
                                              "Recommended next steps"),
    "report.section.limitations": ("Giới hạn của báo cáo này",
                                   "Limitations of this report"),
    # --- ô văn xuôi của model ---

    # Nhãn cho dữ kiện và hành động trong báo cáo sự cố.
    #
    # Thiếu chúng thì giao diện rơi về CHÍNH cái khoá: mục "Dữ kiện đã xác
    # lập" — phần quan trọng nhất của báo cáo — hiện ra
    # "report.fact.process_identity" thay vì "Định danh tiến trình". Bản cài
    # 3.0.0a1 đầu tiên trên máy thật đã hiện đúng như vậy.
    "report.fact.ack_source": ('Nguồn trả lời ACK', 'ACK source'),
    "report.fact.acked_ports_matched": ('Cổng có ACK khớp', 'Matching acked ports'),
    "report.fact.action": ('Hành động', 'Action'),
    "report.fact.baseline": ('Mốc chuẩn', 'Baseline'),
    "report.fact.baseline_mac": ('MAC theo mốc chuẩn', 'Baseline MAC'),
    "report.fact.behavior_key": ('Loại hành vi', 'Behaviour key'),
    "report.fact.behaviour_kind": ('Loại hành vi', 'Behaviour kind'),
    "report.fact.bind_address": ('Địa chỉ lắng nghe', 'Bind address'),
    "report.fact.change": ('Thay đổi', 'Change'),
    "report.fact.changed": ('Đã thay đổi', 'Changed'),
    "report.fact.component": ('Thành phần', 'Component'),
    "report.fact.contributing_alerts": ('Số cảnh báo góp phần', 'Contributing alerts'),
    "report.fact.current": ('Hiện tại', 'Current'),
    "report.fact.current_state": ('Trạng thái hiện tại', 'Current state'),
    "report.fact.detail": ('Chi tiết', 'Detail'),
    "report.fact.device": ('Thiết bị', 'Device'),
    "report.fact.drift_s": ('Lệch giờ (giây)', 'Clock drift (s)'),
    "report.fact.dropped": ('Đã bị bỏ', 'Dropped'),
    "report.fact.dropped_paths": ('Tệp được ghi ra', 'Files written'),
    "report.fact.exe": ('Tệp thực thi', 'Executable'),
    "report.fact.exe_path": ('Đường dẫn tệp thực thi', 'Executable path'),
    "report.fact.expected": ('Giá trị mong đợi', 'Expected'),
    "report.fact.explanation": ('Diễn giải', 'Explanation'),
    "report.fact.fail_count": ('Số lần hỏng', 'Failure count'),
    "report.fact.first_seen": ('Lần đầu thấy', 'First seen'),
    "report.fact.gateway_ip": ('IP gateway', 'Gateway IP'),
    "report.fact.host": ('Máy', 'Host'),
    "report.fact.hostname": ('Tên máy', 'Hostname'),
    "report.fact.interface": ('Giao diện mạng', 'Interface'),
    "report.fact.ip": ('Địa chỉ IP', 'IP address'),
    "report.fact.ip6": ('Địa chỉ IPv6', 'IPv6 address'),
    "report.fact.job_id": ('Mã công việc', 'Job id'),
    "report.fact.known_dhcp": ('DHCP đã biết', 'Known DHCP servers'),
    "report.fact.known_resolvers": ('Resolver đã biết', 'Known resolvers'),
    "report.fact.local_hour": ('Giờ địa phương', 'Local hour'),
    "report.fact.mac": ('Địa chỉ MAC', 'MAC address'),
    "report.fact.macs": ('Các địa chỉ MAC', 'MAC addresses'),
    "report.fact.message": ('Thông điệp', 'Message'),
    "report.fact.min_count": ('Ngưỡng tối thiểu', 'Minimum count'),
    "report.fact.mount_point": ('Điểm gắn kết', 'Mount point'),
    "report.fact.observed": ('Quan sát được', 'Observed'),
    "report.fact.observed_count": ('Số lần quan sát được', 'Observed count'),
    "report.fact.observed_mac": ('MAC quan sát được', 'Observed MAC'),
    "report.fact.owner_identities": ('Tiến trình sở hữu', 'Owning processes'),
    "report.fact.path": ('Đường dẫn', 'Path'),
    "report.fact.pid": ('Mã tiến trình', 'Process id'),
    "report.fact.port": ('Cổng', 'Port'),
    "report.fact.ports": ('Các cổng', 'Ports'),
    "report.fact.previous_observations": ('Lần quan sát trước', 'Previous observations'),
    "report.fact.previous_state": ('Trạng thái trước', 'Previous state'),
    "report.fact.probe_id": ('Mã probe', 'Probe id'),
    "report.fact.process_identity": ('Định danh tiến trình', 'Process identity'),
    "report.fact.product": ('Sản phẩm', 'Product'),
    "report.fact.product_id": ('Mã sản phẩm', 'Product id'),
    "report.fact.rate_per_s": ('Tốc độ mỗi giây', 'Rate per second'),
    "report.fact.reason": ('Lý do', 'Reason'),
    "report.fact.recommended_action": ('Hành động đề xuất', 'Recommended action'),
    "report.fact.restart_count": ('Số lần khởi động lại', 'Restart count'),
    "report.fact.rogue_dhcp": ('DHCP lạ', 'Rogue DHCP'),
    "report.fact.rollback_ok": ('Hoàn tác được', 'Rollback succeeded'),
    "report.fact.rules": ('Quy tắc đã kích hoạt', 'Rules fired'),
    "report.fact.scan_type_key": ('Kiểu quét', 'Scan type'),
    "report.fact.sequence": ('Chuỗi hành vi', 'Behaviour sequence'),
    "report.fact.serial": ('Số sê-ri', 'Serial'),
    "report.fact.server_ip": ('IP máy chủ', 'Server IP'),
    "report.fact.session": ('Phiên', 'Session'),
    "report.fact.signed": ('Đã ký', 'Signed'),
    "report.fact.since": ('Từ lúc', 'Since'),
    "report.fact.src_ip": ('IP nguồn', 'Source IP'),
    "report.fact.subject": ('Đối tượng', 'Subject'),
    "report.fact.target": ('Mục tiêu', 'Target'),
    "report.fact.threshold": ('Ngưỡng', 'Threshold'),
    "report.fact.user": ('Người dùng', 'User'),
    "report.fact.vendor": ('Nhà sản xuất', 'Vendor'),
    "report.fact.vendor_id": ('Mã nhà sản xuất', 'Vendor id'),
    "report.fact.window_min": ('Cửa sổ (phút)', 'Window (minutes)'),
    "report.fact.window_s": ('Cửa sổ (giây)', 'Window (seconds)'),

    "report.action.block_ip": ('Chặn địa chỉ IP', 'Block the IP address'),
    "report.action.isolate_endpoint": ('Cách ly máy khỏi mạng', 'Isolate the endpoint'),
    "report.action.rate_limit_ip": ('Giới hạn tốc độ từ IP', 'Rate-limit the IP address'),
    "report.action.snapshot_state": ('Chụp lại trạng thái để điều tra', 'Snapshot state for investigation'),
    "report.action.stop_process": ('Dừng tiến trình', 'Stop the process'),
    # --- Hỏi đáp gắn vào một sự cố (Incident Chat v0) ---
    "chat.title": ("Hỏi về sự cố này", "Ask about this incident"),
    "chat.answer.model_disabled": (
        "Câu hỏi này cần model cục bộ, và model đang tắt.",
        "That question needs the local model, and the model is off."),
    # 3.0.0a2: cả năm câu hỏi đều trả lời TẤT ĐỊNH từ dữ liệu đo được. Gọi nó
    # là "AI" khi không có model nào chạy là nói sai về chính sản phẩm.
    "chat.subordinate": (
        "Câu trả lời dựng từ chính dữ liệu Shield đo được ở trên, không qua "
        "model.",
        "Answers are built from the Shield data above, without a model."),
    "chat.placeholder": ("Hỏi về sự cố này…", "Ask about this incident…"),
    "chat.ask": ("Hỏi", "Ask"),
    "chat.you": ("Bạn", "You"),
    # Nhãn của bên trả lời. KHÔNG phải "AI": ở 3.0.0a2 không câu nào do model
    # viết, và một nhãn sai làm người đọc đánh giá sai độ tin của câu trả lời.
    "chat.ai": ("Shield", "Shield"),
    "chat.evidence": ("Bằng chứng", "Evidence"),
    "chat.limitations": ("Chưa xác lập được", "Not established"),
    "chat.state.pending": ("Đang soạn câu trả lời. Báo cáo phía trên đã đầy đủ.",
                           "Preparing an answer. The report above is already complete."),
    "chat.state.failed": ("Không tạo được câu trả lời lần này. Báo cáo không đổi.",
                          "No answer was produced this time. The report is unchanged."),
    "chat.state.disabled": ("Hỏi đáp đang tắt.", "Chat is off."),
    "chat.state.ineligible": ("Kịch bản này chỉ có báo cáo tất định.",
                              "Deterministic report only for this scenario."),
    "chat.rejected.question_in_flight": (
        "Đang trả lời một câu hỏi. Chờ xong rồi hỏi tiếp.",
        "One question is already being processed. Wait for it to finish."),
    "chat.rejected.session_full": ("Cuộc hội thoại này đã đầy.",
                                   "This conversation is full."),
    "chat.rejected.queue_full": ("Hàng đợi đang đầy. Thử lại sau.",
                                 "The queue is full. Try again shortly."),
    "chat.rejected.empty_question": ("Hãy nhập câu hỏi.", "Type a question."),
    "chat.rejected.unknown_session": ("Phiên không còn tồn tại.",
                                      "That session no longer exists."),
    "chat.question.INCIDENT_SUMMARY": ("Tóm tắt sự cố này.",
                                       "Summarise this incident."),
    "chat.question.EVIDENCE_EXPLANATION": ("Bằng chứng nào hỗ trợ kết luận này?",
                                           "Which evidence supports this?"),
    "chat.question.CERTAINTY": ("Có chắc chưa? Điều gì chưa được xác nhận?",
                                "How certain is this? What is unconfirmed?"),
    "chat.question.RELATED_PROCESS": ("Process nào liên quan?",
                                      "Which process was involved?"),
    "chat.question.NEXT_INVESTIGATION_STEP": ("Tôi nên kiểm tra gì tiếp theo?",
                                              "What should I check next?"),
    # Tóm tắt TẤT ĐỊNH. Từng mảnh là một câu rời, ghép lại bằng dấu cách, nên
    # không mảnh nào ngụ ý điều mảnh khác không nói. Cố ý KHÔNG có chữ nào
    # trong nhóm "bị chiếm quyền / tấn công / mã độc / trụ lại / lan ngang /
    # rút dữ liệu": tên kịch bản đã nói đúng mức, và thêm bất kỳ chữ nào trong
    # nhóm đó là khẳng định thứ dữ liệu không chứng minh.
    "chat.summary.observed": ("Shield ghi nhận: {scenario} trên {subject}.",
                              "Shield observed: {scenario} on {subject}."),
    "chat.summary.this_host": ("máy này", "this host"),
    "chat.summary.unknown_scenario": ("hoạt động chưa phân loại",
                                      "unclassified activity"),
    "chat.summary.facts": ("Dữ kiện đã xác lập — {facts}.",
                           "Established facts — {facts}."),
    "chat.summary.evidence.supported": (
        "Có {count} tham chiếu bằng chứng đã kiểm hỗ trợ cách đọc này; Shield "
        "chưa xác nhận nó.",
        "{count} validated evidence references support this reading; Shield has "
        "not confirmed it."),
    "chat.summary.evidence.unconfirmed": (
        "Có {count} tham chiếu bằng chứng đã kiểm. Vì sao chuỗi này xảy ra thì "
        "chưa xác định được.",
        "There are {count} validated evidence references. Why this occurred is "
        "not established."),
    "chat.summary.evidence.insufficient": (
        "Mới có {count} tham chiếu bằng chứng đã kiểm — chưa đủ để kết luận gì.",
        "Only {count} validated evidence references so far — not enough to "
        "conclude anything."),
    "chat.summary.limitation": ("Giới hạn: {limitation}",
                                "Limitation: {limitation}"),
    "chat.answer.no_data": ("Không có dữ liệu cho câu hỏi này.",
                            "There is no data for that question."),
    "chat.answer.no_summary": ("Chưa tạo được tóm tắt cho sự cố này.",
                               "No summary could be produced for this incident."),
    "chat.answer.no_evidence": (
        "Sự cố này chưa có tham chiếu bằng chứng nào được kiểm.",
        "This incident has no validated evidence references yet."),
    "chat.answer.evidence": (
        "Kết luận dựa trên {count} tham chiếu bằng chứng đã kiểm. Dữ kiện đã "
        "xác lập: {facts}.",
        "The conclusion rests on {count} validated evidence references. "
        "Established facts: {facts}."),
    "chat.answer.no_process": (
        "Sự cố này không có thông tin tiến trình đã xác lập.",
        "This incident has no confirmed process information."),
    "chat.answer.process": ("Tiến trình liên quan: {identity}.",
                            "Process involved: {identity}."),
    # Cố ý KHÔNG dùng chữ "chắc chắn"/"certainly": bộ dò khẳng định quá tay
    # bắt đúng những chữ đó, và một câu nói về mức độ tin cậy mà lại đọc như
    # một lời khẳng định là câu viết sai, không phải bộ dò sai.
    "chat.answer.certainty": ("Đánh giá của Shield: {state}.",
                              "Shield's assessment: {state}."),
    "chat.answer.certainty_limits": ("Chưa xác lập được: {limits}.",
                                     "Not established: {limits}."),
    "chat.answer.next_step": (
        "Nên xem xét: {steps}. Hỏi đáp không tự thực hiện bước nào.",
        "Worth examining: {steps}. Chat does not carry any of these out."),
    "chat.answer.no_next_step": ("Không có bước kiểm tra nào được đề xuất.",
                                 "No inspection step is suggested."),
    "chat.state_word.confirmed": ("đã xác nhận", "confirmed"),
    "chat.state_word.supported": ("có bằng chứng hỗ trợ, chưa xác nhận",
                                  "supported but not confirmed"),
    "chat.state_word.unconfirmed": ("chưa xác nhận", "not confirmed"),
    "chat.state_word.insufficient": ("chưa đủ bằng chứng", "insufficient evidence"),
    "chat.intent.INCIDENT_SUMMARY": ("Tóm tắt sự cố", "Summarise"),
    "chat.intent.EVIDENCE_EXPLANATION": ("Giải thích bằng chứng", "Explain evidence"),
    "chat.intent.CERTAINTY": ("Mức độ chắc chắn", "How certain?"),
    "chat.intent.RELATED_PROCESS": ("Process liên quan", "Related process"),
    "chat.intent.NEXT_INVESTIGATION_STEP": ("Nên kiểm tra gì tiếp theo",
                                            "What to inspect next"),
    "chat.answer.out_of_scope_chat": (
        "Tôi chỉ trả lời được một số câu hỏi giới hạn về sự cố này.",
        "I can answer a limited set of questions about this incident."),
    "chat.limited_notice": ("Hỏi đáp theo sự cố — bộ câu hỏi giới hạn",
                            "Incident-scoped guided Q&A — limited question set"),
    "chat.answer.action_request": (
        "Đây là một hành động, và hỏi đáp không thực hiện hành động nào. "
        "Tôi trả lời được về sự cố này và bằng chứng của nó.",
        "That is an action, and chat does not carry out actions. I can answer "
        "questions about this incident and its evidence."),
    "chat.answer.out_of_scope": (
        "Tôi chỉ trả lời về sự cố này và bằng chứng của nó.",
        "I can only answer questions about this incident and its evidence."),

    "report.ai.title": ("Giải thích do AI viết (tuỳ chọn)",
                        "AI-written explanation (optional)"),
    "report.ai.subordinate": (
        "Phần dưới đây do một model ngôn ngữ chạy cục bộ viết. Nó KHÔNG phải dữ "
        "liệu Shield đo được, và mọi mục phía trên đã đầy đủ mà không cần nó.",
        "The text below was written by a locally running language model. It is NOT "
        "data measured by Shield, and every section above is complete without it."),
    "report.ai.analysis": ("Phân tích", "Analysis"),
    "report.ai.rationale": ("Vì sao có thể như vậy", "Why this could be"),
    "report.ai.matters": ("Vì sao điều này đáng quan tâm", "Why this matters"),
    "report.ai.state.disabled": ("Phần giải thích bằng AI đang tắt.",
                                 "AI explanation is disabled."),
    "report.ai.state.ineligible": (
        "Loại sự cố này chỉ dùng báo cáo tất định.",
        "Deterministic report only for this scenario."),
    "report.ai.state.pending": (
        "Đang chuẩn bị phần giải thích. Báo cáo phía trên đã đầy đủ.",
        "AI explanation is being prepared. The report above is already complete."),
    "report.ai.state.ready": ("Đã có phần giải thích.", "Explanation ready."),
    "report.ai.state.failed": (
        "Lần này không tạo được phần giải thích. Báo cáo không bị ảnh hưởng.",
        "No explanation was produced this time. The report is unaffected."),
    "report.ai.state.deferred": (
        "Phần giải thích được hoãn lại. Báo cáo không bị ảnh hưởng.",
        "The explanation was deferred. The report is unaffected."),
    # --- bật/tắt có chủ ý ---
    "report.ai.opt_in": ("Bật phần giải thích bằng AI cục bộ",
                         "Enable local AI explanation"),
    "report.ai.opt_in_hint": (
        "Chạy một model ngôn ngữ NHỎ ngay trên máy này, ở chế độ nền, chỉ để viết "
        "vài câu diễn giải. Không gửi gì ra ngoài. Chỉ những loại sự cố đã được "
        "kiểm đủ mới nhận phần giải thích. Báo cáo vẫn đầy đủ khi tắt.",
        "Runs a SMALL language model on this machine, in the background, only to "
        "write a few sentences of interpretation. Nothing leaves the machine. Only "
        "scenario types that passed review receive prose. Reports stay complete "
        "when this is off."),
    "report.ai.opt_in_on": ("đang bật", "on"),
    "report.ai.opt_in_off": ("đang tắt", "off"),
    "report.ai.provider_missing": (
        "Chưa có model cục bộ nào được cấu hình trên máy này.",
        "No local model is configured on this machine."),
    "settings.export_title": ("Xuất log ra thư mục của bạn", "Export logs to your own folder"),
    "settings.export_hint": (
        "Shield có thể ghi thêm một bản log ra thư mục bạn chỉ định, để bạn tự lưu trữ, "
        "gửi cho người khác xem, hay nạp vào công cụ phân tích riêng. Bản chính vẫn nằm "
        "trong database của Shield — phần này chỉ là bản sao thêm.",
        "Shield can write an extra copy of its logs into a folder you choose, so you can "
        "archive them yourself, hand them to someone else, or load them into your own "
        "analysis tools. The primary copy stays in Shield's database; this is only an "
        "additional copy.",
    ),
    "settings.export_enable": ("Bật xuất log", "Enable log export"),
    "settings.export_folder": ("Thư mục", "Folder"),
    "settings.export_browse": ("Chọn thư mục…", "Choose folder…"),
    "settings.export_open": ("Mở thư mục", "Open folder"),
    "settings.export_quota": ("Tối đa cho Shield dùng", "Maximum Shield may use"),
    "settings.export_none": ("Chưa chọn thư mục", "No folder chosen"),
    "settings.export_apply": ("Áp dụng", "Apply"),
    "settings.export_events": ("Gồm event", "Include events"),
    "settings.export_alerts": ("Gồm cảnh báo", "Include alerts"),
    "settings.export_unlimited_warning": (
        "Không có lựa chọn 'không giới hạn'. Một hạn mức vô hạn nghĩa là Shield tự cho "
        "phép mình lấp đầy ổ đĩa của bạn.",
        "There is deliberately no 'unlimited' option. An unlimited quota means Shield "
        "gives itself permission to fill your disk.",
    ),
    "settings.export_status_off": ("Đang tắt", "Off"),
    "settings.export_status_used": (
        "Đang dùng {used} / {quota} ({percent}%) — {files} file",
        "Using {used} of {quota} ({percent}%) — {files} files",
    ),
    "settings.export_status_rate": (
        "Nhịp hiện tại khoảng {per_day}/ngày, nên hạn mức này giữ được khoảng {days} ngày.",
        "At the current rate of about {per_day} per day, this quota holds roughly {days} days.",
    ),
    "settings.export_status_rate_unknown": (
        "Chưa đủ dữ liệu để ước tính giữ được bao nhiêu ngày.",
        "Not enough data yet to estimate how many days this holds.",
    ),
    "settings.export_status_free": ("Ổ đĩa còn trống {free}.", "{free} free on the disk."),
    "settings.export_status_dropped": (
        "Đã bỏ {count} dòng vì chạm hạn mức hoặc lỗi ghi.",
        "{count} lines were dropped because the quota was reached or a write failed.",
    ),
    "settings.export_error": ("Không dùng được thư mục này: {reason}", "Cannot use this folder: {reason}"),
    # Lý do dịch được. Agent gửi MÃ, không gửi câu: nó không biết người đang
    # nhìn màn hình chọn ngôn ngữ nào — chỉ giao diện biết.
    "settings.export_err_empty": ("chưa chọn thư mục", "no folder chosen"),
    "settings.export_err_invalid_chars": (
        "đường dẫn chứa ký tự không hợp lệ", "the path contains an invalid character"),
    "settings.export_err_not_absolute": (
        "phải là đường dẫn tuyệt đối, bắt đầu bằng /",
        "must be an absolute path starting with /"),
    "settings.export_err_symlink": (
        "đường dẫn đi qua một liên kết tượng trưng, Shield không đi theo nó",
        "the path goes through a symbolic link, which Shield will not follow"),
    "settings.export_err_unreadable": ("không đọc được đường dẫn", "the path could not be read"),
    "settings.export_err_system_dir": (
        "nằm trong thư mục hệ thống", "it is inside a system directory"),
    "settings.export_err_shield_data": (
        "không được trỏ vào thư mục dữ liệu của Shield",
        "it must not point at Shield's own data directory"),
    "settings.export_err_missing": (
        "thư mục chưa tồn tại — hãy tạo nó trước",
        "the folder does not exist yet — create it first"),
    "settings.export_err_not_a_directory": (
        "đường dẫn không phải là thư mục", "the path is not a directory"),
    "settings.export_err_not_writable": (
        "Shield không có quyền ghi vào thư mục này",
        "Shield does not have permission to write there"),
    "settings.export_err_unknown": ("lý do không xác định", "an unknown reason"),
    "settings.export_full_note": (
        "Khi chạm hạn mức, Shield xoá file log CŨ NHẤT do chính nó tạo. Nó không bao giờ "
        "đụng tới file khác trong thư mục đó.",
        "When the quota is reached, Shield deletes the OLDEST log file it created itself. "
        "It never touches any other file in that folder.",
    ),

    "settings.rescan_btn": ("Làm mới phiên quét", "Reset scan session"),
    "settings.rescan_confirm_title": ("Làm mới phiên quét?", "Reset the scan session?"),
    "settings.rescan_confirm_days": (
        "Quên mọi thiết bị không thấy quá {days} ngày, gồm cả tên và ghi chú bạn đã đặt "
        "cho chúng. Sự kiện, cảnh báo và sổ bằng chứng vẫn còn nguyên. Tiếp tục?",
        "Forget every device unseen for more than {days} days, including the names and "
        "notes you gave them. Events, alerts and the forensic ledger stay intact. Continue?",
    ),
    "settings.rescan_confirm_all": (
        "Quên TOÀN BỘ thiết bị, gồm cả tên, chủ sở hữu và mức quan trọng bạn đã đặt — "
        "phần này không lấy lại được. Sự kiện, cảnh báo và sổ bằng chứng vẫn còn nguyên. "
        "Tiếp tục?",
        "Forget EVERY device, including the names, owners and criticality you set — that "
        "part cannot be recovered. Events, alerts and the forensic ledger stay intact. "
        "Continue?",
    ),
    "settings.rescan_done": (
        "Đã quên {count} thiết bị. Lượt quét tiếp theo sẽ dựng lại danh sách.",
        "Forgot {count} device(s). The next scan will rebuild the list.",
    ),
    "settings.backup_title": ("Backup và phục hồi", "Backup and recovery"),
    "settings.backup_enable": ("Tự động backup database mỗi ngày", "Automatically back up the database every day"),
    "settings.backup_now": ("Backup ngay", "Back up now"),
    "settings.backup_never": ("Chưa có backup", "No backup yet"),
    "settings.backup_last": ("Backup gần nhất: {time}", "Last backup: {time}"),
    "settings.backup_done": ("Backup thành công: {path}", "Backup completed: {path}"),
    "settings.backup_failed": ("Backup thất bại: {error}", "Backup failed: {error}"),
    "settings.blocking": ("Đang chặn", "Active blocks"),
    "settings.blocking_desc": ("Tự hết hạn sau 24h — kernel tự dọn.", "Auto-expires after 24h — the kernel cleans up."),
    "settings.col_type": ("Loại", "Type"),
    "settings.col_value": ("Giá trị", "Value"),
    "settings.col_expires": ("Hết hạn lúc", "Expires at"),
    "settings.unblock": ("Gỡ chặn", "Unblock"),
    "settings.schedule": ("Lịch quét sâu", "Deep scan schedule"),
    "settings.schedule_desc": (
        "Ngoài arp-scan 60s mặc định — tự chạy nmap toàn subnet + tự kiểm tra cổng "
        "theo lịch riêng.",
        "Besides the default 60s arp-scan — run a full-subnet nmap plus a self "
        "port-audit on its own schedule.",
    ),
    "settings.schedule_enable": ("Tự động quét sâu theo lịch", "Automatic scheduled deep scan"),
    "settings.schedule_time": ("Giờ chạy", "Run time"),
    "settings.authorized_ranges": ("Dải mạng được cấp phép", "Authorized scan ranges"),
    "settings.authorized_ranges_desc": (
        "Chỉ dùng cho mạng bạn CÓ quyền quét (ví dụ mạng công ty được ủy "
        "quyền bằng văn bản). Không thêm mạng bạn không sở hữu hoặc chưa "
        "được cho phép rõ ràng — quét trái phép có thể vi phạm pháp luật.",
        "Only for networks you are AUTHORIZED to scan (e.g. a work network "
        "with written permission). Do not add a network you don't own or "
        "haven't been explicitly granted access to — unauthorized scanning "
        "may be illegal.",
    ),
    "settings.range_cidr_placeholder": ("CIDR, ví dụ 10.0.0.0/24", "CIDR, e.g. 10.0.0.0/24"),
    "settings.range_note_placeholder": (
        "Lý do/căn cứ cấp phép (bắt buộc)", "Authorization reason (required)"
    ),
    "settings.range_confirm": (
        "Tôi xác nhận có quyền/được cấp phép quét dải mạng này",
        "I confirm I am authorized to scan this network range",
    ),
    "settings.range_add": ("Thêm dải", "Add range"),
    "settings.range_col_cidr": ("Dải", "Range"),
    "settings.range_col_note": ("Lý do cấp phép", "Authorization reason"),
    "settings.range_scan": ("Quét", "Scan"),
    "settings.range_remove": ("Gỡ", "Remove"),
    "settings.range_scan_confirm_title": ("Xác nhận quét", "Confirm scan"),
    "settings.range_scan_confirm_body": (
        "Sắp quét dải {cidr}.\n\nChỉ tiếp tục nếu bạn thực sự được cấp phép "
        "quét mạng này. Hành động này sẽ được ghi vào nhật ký kiểm toán.",
        "About to scan {cidr}.\n\nOnly continue if you are genuinely "
        "authorized to scan this network. This action will be recorded in "
        "the audit log.",
    ),
    "action.block_ip": ("Chặn IP (tự hết hạn 24h)", "Block IP (auto-expires in 24h)"),
    "action.block_mac": ("Chặn MAC (tự hết hạn 24h)", "Block MAC (auto-expires in 24h)"),
    "action.start_capture": ("Bắt đầu ghi bằng chứng (tcpdump)", "Start capturing evidence (tcpdump)"),
    "action.trust_device": ("Đánh dấu tin cậy", "Mark as trusted"),
    "action.snapshot_state": ("Lưu snapshot hiện trạng", "Save a state snapshot"),
    "action.pin_gateway_arp": ("Pin ARP gateway (chống MITM)", "Pin gateway ARP (anti-MITM)"),
    "common.save": ("Lưu", "Save"),
    "baseline.dialog_title": ("Xác nhận gateway", "Confirm gateway"),
    "baseline.dialog_body": (
        "MAC gateway hiện tại là {gw_mac} (IP {gw_ip}).\n\n"
        "Đây có đúng là router của bạn không? Chỉ xác nhận khi bạn chắc mạng "
        "đang sạch — mọi detector chống MITM sẽ dựa vào lựa chọn này.",
        "The current gateway MAC is {gw_mac} (IP {gw_ip}).\n\n"
        "Is this really your router? Only confirm if you're sure the network "
        "is clean — every anti-MITM detector relies on this choice.",
    ),
    "baseline.confirmed": (
        "Đã chốt baseline gateway {gw_ip} -> {gw_mac}",
        "Gateway baseline confirmed: {gw_ip} -> {gw_mac}",
    ),
    "baseline.declined": ("Chưa chốt baseline gateway", "Gateway baseline not confirmed"),
    "traffic.protocols_title": (
        "Giao thức đang dùng (nhận diện bằng engine Wireshark)",
        "Protocols in use (detected via Wireshark's engine)",
    ),
    "traffic.protocols_none": (
        "Chưa có dữ liệu — cần cài gói 'tshark' (sudo apt install tshark).",
        "No data yet — install the 'tshark' package (sudo apt install tshark).",
    ),
    "traffic.col_protocol": ("Giao thức", "Protocol"),
    "traffic.col_packets": ("Số gói", "Packets"),
    # --- Thông báo lỗi từ agent (dịch được; lỗi có nội dung động thì agent
    # gửi chuỗi thô, xem error_message()) ---
    "err.missing_note": (
        "Cần ghi rõ lý do/căn cứ cấp phép trước khi thêm",
        "You must state the reason/authorization before adding a range",
    ),
    "err.missing_router_host": ("Thiếu địa chỉ router", "Router address is missing"),
    "err.missing_script_path": ("Thiếu đường dẫn script", "Script path is missing"),
    "err.no_dns_servers": (
        "Chưa đọc được DNS server nào để lưu",
        "No DNS servers could be read, nothing to save",
    ),
    "err.no_interface_for_evasion": (
        "Không xác định được interface để đổi MAC/IP",
        "Could not determine which interface to rotate MAC/IP on",
    ),
    "settings.evasion_title": (
        "Né tránh khẩn cấp (đổi MAC + IP liên tục)",
        "Emergency evasion (rotate MAC + IP)",
    ),
    "settings.evasion_desc": (
        "Chỉ dùng khi bạn nghi ngờ đang bị nhắm tới trực tiếp và cần câu giờ "
        "trong lúc tìm giải pháp lâu dài. Đổi MAC + xin IP mới liên tục cho "
        "interface chính của máy cho tới khi bạn tự tắt. SẼ làm rớt mọi kết "
        "nối đang mở (SSH, video call, tải file...) mỗi lần đổi — không nên "
        "bật khi đang có việc quan trọng cần mạng ổn định.",
        "Only use this when you suspect you're being actively targeted and "
        "need to buy time while you find a lasting fix. Rotates this "
        "machine's main interface's MAC address and requests a new IP "
        "continuously until you turn it off. It WILL drop every open "
        "connection (SSH, video calls, downloads...) on each rotation — "
        "don't enable it while you need a stable connection for something "
        "important.",
    ),
    "settings.evasion_interval": ("Chu kỳ đổi", "Rotation interval"),
    "settings.evasion_turn_on": ("Bật né tránh", "Turn on evasion"),
    "settings.evasion_turn_off": ("Tắt né tránh", "Turn off evasion"),
    "settings.evasion_confirm_title": ("Bật né tránh khẩn cấp?", "Turn on emergency evasion?"),
    "settings.evasion_confirm_body": (
        "Máy sẽ liên tục đổi MAC và xin IP mới cho tới khi bạn bấm Tắt.\n\n"
        "Hậu quả ngay lập tức:\n"
        "• Mọi kết nối mạng đang mở sẽ bị rớt mỗi lần đổi (SSH, video call, "
        "tải file, họp online...).\n"
        "• Một số router/mạng công ty có thể chặn thiết bị đổi MAC liên tục.\n"
        "• Đây là biện pháp câu giờ tạm thời, không thay thế việc xử lý gốc "
        "rễ vấn đề.\n\n"
        "Chỉ tiếp tục nếu bạn thật sự nghi ngờ đang bị tấn công/theo dõi và "
        "chấp nhận đánh đổi trên.",
        "The machine will keep rotating its MAC address and requesting a new "
        "IP until you click Turn off.\n\n"
        "Immediate consequences:\n"
        "• Every open network connection will drop on each rotation (SSH, "
        "video calls, downloads, online meetings...).\n"
        "• Some routers/corporate networks may block a device that keeps "
        "changing its MAC.\n"
        "• This is a temporary stalling measure, not a fix for the "
        "underlying problem.\n\n"
        "Only proceed if you genuinely suspect you're being attacked or "
        "tracked and accept the trade-offs above.",
    ),
    "settings.evasion_status_off": ("Đang tắt.", "Currently off."),
    "settings.evasion_status_on": (
        "ĐANG BẬT — MAC hiện tại: {mac}, IP: {ip} (đổi lúc {ts})",
        "ON — current MAC: {mac}, IP: {ip} (rotated at {ts})",
    ),
    "settings.evasion_status_error": ("Lỗi khi đổi MAC/IP: {error}", "Error rotating MAC/IP: {error}"),
    "err.no_tarpit_ports": (
        "Chưa nhập cổng mồi hợp lệ nào",
        "No valid decoy ports were entered",
    ),
    "settings.tarpit_title": (
        "Tarpit phòng thủ (cổng mồi giữ chân)",
        "Defensive tarpit (decoy ports)",
    ),
    "settings.tarpit_desc": (
        "Mở vài cổng \"mồi\" trên chính máy này — hoàn toàn thụ động, KHÔNG tự "
        "gửi gì ra ngoài. Chỉ khi có ai đó tự kết nối tới các cổng này, Shield "
        "mới giữ kết nối lại thật lâu (nhỏ giọt vài byte rất chậm) để làm "
        "lãng phí thời gian/công cụ quét của họ. Dùng khi nghi ngờ đang bị "
        "dò/tấn công và muốn câu giờ.",
        "Opens a few \"decoy\" ports on this machine — entirely passive, it "
        "never sends anything out on its own. Only when someone connects to "
        "these ports themselves does Shield hold that connection open for a "
        "long time (drip-feeding a few bytes very slowly) to waste their "
        "scanning tool's time. Use this when you suspect you're being probed "
        "or attacked and want to stall.",
    ),
    "settings.tarpit_ports": ("Cổng mồi", "Decoy ports"),
    "settings.tarpit_turn_on": ("Bật tarpit", "Turn on tarpit"),
    "settings.tarpit_turn_off": ("Tắt tarpit", "Turn off tarpit"),
    "settings.tarpit_confirm_title": ("Bật tarpit phòng thủ?", "Turn on defensive tarpit?"),
    "settings.tarpit_confirm_body": (
        "Shield sẽ mở các cổng mồi đã nhập trên máy này. Tính năng này hoàn "
        "toàn thụ động — không tự kết nối hay gửi gì tới máy khác, chỉ phản "
        "ứng khi có ai đó tự kết nối tới cổng mồi.\n\n"
        "Lưu ý: nếu bạn nhập trùng cổng của 1 dịch vụ thật đang chạy trên máy "
        "(SSH, web server...), cổng đó sẽ không mở được cho tarpit — Shield sẽ "
        "bỏ qua cổng bị trùng, không làm gián đoạn dịch vụ thật.",
        "Shield will open the decoy ports you entered on this machine. This "
        "feature is entirely passive — it never connects to or sends "
        "anything toward another machine on its own; it only reacts when "
        "someone connects to a decoy port themselves.\n\n"
        "Note: if you enter a port already used by a real service on this "
        "machine (SSH, a web server...), that port simply won't open for the "
        "tarpit — Shield skips the conflicting port rather than disrupting "
        "the real service.",
    ),
    "settings.tarpit_status_off": ("Đang tắt.", "Currently off."),
    "settings.tarpit_status_on": (
        "ĐANG BẬT — nghe cổng: {ports}. Đang giữ {count} kết nối.",
        "ON — listening on: {ports}. Currently holding {count} connection(s).",
    ),
    "settings.tarpit_col_ip": ("IP kết nối tới", "Connecting IP"),
    "settings.tarpit_col_port": ("Cổng mồi", "Decoy port"),
    "settings.tarpit_col_since": ("Từ lúc", "Since"),
    "dns.title": ("Tự kiểm soát DNS", "DNS Self-Control"),
    "dns.sub": (
        "DNS bị đổi là cách chiếm quyền điều hướng cả máy mà không cần đụng "
        "từng gói tin. Mục này chỉ ĐỌC cấu hình và gửi truy vấn DNS thông "
        "thường — không sửa gì trên máy bạn.",
        "A hijacked DNS setting redirects everything on this machine without "
        "touching a single packet. This tab only READS your configuration and "
        "sends ordinary DNS queries — it changes nothing on your system.",
    ),
    "dns.refresh": ("Kiểm tra ngay", "Check now"),
    "dns.run_hijack_check": ("Chạy test chống hijack", "Run hijack test"),
    "dns.checking": ("Đang kiểm tra...", "Checking..."),
    "dns.set_baseline": ("Đặt làm baseline", "Set as baseline"),
    "dns.set_baseline_confirm": (
        "Lưu DNS server hiện tại làm mốc \"đã biết sạch\"?\n\n"
        "Chỉ làm điều này khi bạn chắc chắn mạng đang an toàn — ví dụ vừa đổi "
        "sang mạng Wi-Fi của chính bạn.",
        "Save the current DNS servers as the \"known good\" baseline?\n\n"
        "Only do this when you're confident the network is safe — for example "
        "right after switching to your own Wi-Fi.",
    ),
    "dns.resolvers_header": ("DNS server máy đang dùng", "DNS servers this machine uses"),
    "dns.current": ("Hiện tại: {servers}  (nguồn: {source})", "Current: {servers}  (source: {source})"),
    "dns.baseline": ("Baseline đã lưu: {servers}", "Saved baseline: {servers}"),
    "dns.no_baseline": (
        "Chưa có baseline — bấm \"Đặt làm baseline\" lúc mạng chắc chắn an toàn.",
        "No baseline yet — click \"Set as baseline\" while the network is known safe.",
    ),
    "dns.no_resolvers": (
        "Chưa đọc được DNS server nào — bấm \"Kiểm tra ngay\".",
        "No DNS servers read yet — click \"Check now\".",
    ),
    "dns.hosts_header": ("Dòng /etc/hosts cần xem lại", "/etc/hosts entries to review"),
    "dns.hosts_clean": (
        "Không có dòng bất thường nào ngoài mặc định hệ thống.",
        "Nothing beyond the standard system entries.",
    ),
    "dns.col_ip": ("IP", "IP"),
    "dns.col_names": ("Tên miền được trỏ về", "Names pointed here"),
    "dns.hijack_header": ("Test chống DNS hijack", "DNS hijack test"),
    "dns.hijack_note": (
        "So kết quả phân giải qua DNS của máy với DNS công khai (1.1.1.1/8.8.8.8). "
        "Khác nhau chưa chắc là bị tấn công — CDN trả IP khác theo vị trí là bình "
        "thường; hãy xem đây là gợi ý để điều tra thêm. Cần có internet và lệnh `dig`.",
        "Compares what your machine's DNS returns against public DNS (1.1.1.1/8.8.8.8). "
        "A difference isn't proof of an attack — CDNs legitimately return different IPs "
        "per location; treat it as a lead to investigate. Needs internet and `dig`.",
    ),
    "dns.hijack_not_run": (
        "Chưa chạy — bấm \"Chạy test chống hijack\".",
        "Not run yet — click \"Run hijack test\".",
    ),
    "dns.col_domain": ("Tên miền", "Domain"),
    "dns.col_local": ("DNS của máy trả về", "Your DNS returned"),
    "dns.col_public": ("DNS công khai trả về", "Public DNS returned"),
    "dns.col_verdict": ("Kết luận", "Verdict"),
    "dns.verdict_ok": ("Khớp", "Match"),
    "dns.verdict_suspect": ("Khác hoàn toàn", "Fully different"),
    "dns.verdict_unknown": ("Không đủ dữ liệu", "Not enough data"),
    "wifi.title": ("Mật khẩu WiFi đã lưu", "Saved WiFi Passwords"),
    "wifi.sub": (
        "Chỉ đọc lại mật khẩu WiFi mà NetworkManager của MÁY NÀY đã tự lưu — "
        "không dò/bẻ mật khẩu mạng khác.",
        "Only reads back WiFi passwords this machine's NetworkManager already "
        "saved — never cracks or guesses other networks' passwords.",
    ),
    "wifi.refresh": ("Làm mới", "Refresh"),
    "wifi.reveal": ("Hiện mật khẩu", "Reveal passwords"),
    "wifi.hide": ("Ẩn mật khẩu", "Hide passwords"),
    "wifi.col_ssid": ("Tên mạng (SSID)", "Network (SSID)"),
    "wifi.col_password": ("Mật khẩu", "Password"),
    "wifi.no_networks": (
        "Chưa có dữ liệu — bấm \"Làm mới\" để đọc từ NetworkManager.",
        "No data yet — click \"Refresh\" to read from NetworkManager.",
    ),
    "wifi.no_password": ("(không có/mạng mở)", "(none / open network)"),
    "audit.diff_changed": (
        "Thay đổi so với lần quét trước ở {host}: mở thêm cổng {added}, đóng cổng {removed}.",
        "Changed since the previous scan on {host}: newly open {added}, newly closed {removed}.",
    ),
    "router.title": ("Lưu lượng theo thiết bị (từ router)", "Per-device traffic (from router)"),
    "router.desc": (
        "Shield không tự thấy traffic của thiết bị khác trên mạng switch — "
        "số liệu này đọc trực tiếp từ router, không phải Shield tự bắt gói.",
        "Shield can't see other devices' traffic on a switched network by "
        "itself — these numbers come straight from the router, not from "
        "packet capture on this machine.",
    ),
    "router.backend_disabled": ("Tắt", "Disabled"),
    "router.backend_ssh": ("SSH vào router (Linux: OpenWrt/DD-WRT/...)", "SSH into router (Linux-based)"),
    "router.backend_script": ("Script tuỳ chỉnh", "Custom script"),
    "router.host_placeholder": ("IP router, ví dụ 192.168.1.1", "Router IP, e.g. 192.168.1.1"),
    "router.auto_detect": ("Tự động dò", "Auto-detect"),
    "router.auto_detect_failed": (
        "Không tự dò được IP gateway — nhập tay.",
        "Couldn't auto-detect the gateway IP — enter it manually.",
    ),
    "devices.gateway_tag": ("Gateway (router)", "Gateway (router)"),
    "router.user_placeholder": ("User SSH (mặc định root)", "SSH user (default root)"),
    "router.key_placeholder": ("Đường dẫn SSH key (tuỳ chọn)", "SSH key path (optional)"),
    "router.script_placeholder": ("Đường dẫn script (in JSON ra stdout)", "Script path (prints JSON to stdout)"),
    "router.save": ("Lưu cấu hình", "Save config"),
    "router.poll_now": ("Quét ngay", "Poll now"),
    "router.col_ip": ("IP", "IP"),
    "router.col_mac": ("MAC", "MAC"),
    "router.col_rx": ("Tải xuống", "Download"),
    "router.col_tx": ("Tải lên", "Upload"),
    "router.col_updated": ("Cập nhật lúc", "Updated at"),
    "router.no_data": (
        "Chưa có dữ liệu — cấu hình backend rồi bấm Quét ngay.",
        "No data yet — configure a backend then press Poll now.",
    ),
    "settings.gateway_baseline": ("Baseline gateway", "Gateway baseline"),
    "settings.gateway_baseline_desc": ("Mọi detector chống MITM dựa vào giá trị này.",
                                       "Every anti-MITM detector relies on this value."),
    "settings.no_baseline": ("Chưa xác nhận", "Not confirmed yet"),
    "day.mon": ("T2", "Mo"), "day.tue": ("T3", "Tu"), "day.wed": ("T4", "We"),
    "day.thu": ("T5", "Th"), "day.fri": ("T6", "Fr"), "day.sat": ("T7", "Sa"), "day.sun": ("CN", "Su"),
    # --- chung, dùng khi format evidence thiếu giá trị ---
    "common.unknown": ("không rõ", "unknown"),
    "portscan.scan_type.connect": ("connect-scan (handshake hoàn tất)", "connect-scan (handshake completed)"),
    "portscan.scan_type.syn": ("SYN-scan (half-open)", "SYN-scan (half-open)"),
    # --- alert title/detail theo rule_id (agent gửi tiếng Việt cố định trong
    # `evidence`; bảng này dịch lại ở UI theo `current_lang()` — xem
    # `alert_text()` bên dưới. Key thiếu -> UI tự rơi về title/detail thô do
    # agent gửi (luôn tiếng Việt), không crash.) ---
    "alert.MITM_GATEWAY_MAC_CHANGED.title": (
        "MAC của gateway đã đổi — nghi ngờ ARP spoofing",
        "Gateway MAC changed — suspected ARP spoofing",
    ),
    "alert.MITM_GATEWAY_MAC_CHANGED.detail": (
        "Gateway {gateway_ip} trước đây có MAC {baseline_mac}, giờ trả lời bằng MAC "
        "{observed_mac}. Đây là dấu hiệu MITM rõ nhất trên LAN nhà.",
        "Gateway {gateway_ip} previously had MAC {baseline_mac}, now answering with "
        "MAC {observed_mac}. This is the clearest MITM signal on a home LAN.",
    ),
    "alert.MITM_ARP_CONFLICT.title": (
        "IP {ip} bị nhiều MAC khác nhau claim",
        "IP {ip} claimed by multiple MACs",
    ),
    "alert.MITM_ARP_CONFLICT.detail": (
        "Trong {window_s}s qua, IP {ip} được claim bởi {mac_count} MAC khác nhau: {macs}.",
        "In the last {window_s}s, IP {ip} was claimed by {mac_count} different MACs: {macs}.",
    ),
    "alert.MITM_NDP_CONFLICT.title": (
        "Địa chỉ IPv6 {ip6} bị nhiều MAC khác nhau claim",
        "IPv6 address {ip6} claimed by multiple MACs",
    ),
    "alert.MITM_NDP_CONFLICT.detail": (
        "Trong {window_s}s qua, Neighbor Advertisement cho {ip6} tới từ {mac_count} MAC "
        "khác nhau: {macs}. Tương đương ARP conflict nhưng trên IPv6.",
        "In the last {window_s}s, Neighbor Advertisements for {ip6} came from {mac_count} "
        "different MACs: {macs}. IPv6 equivalent of an ARP conflict.",
    ),
    "alert.DNS_RESOLVER_CHANGED.title": (
        "DNS server của máy đã bị đổi",
        "This machine's DNS servers changed",
    ),
    "alert.DNS_RESOLVER_CHANGED.detail": (
        "Trước đây máy dùng DNS: {baseline}. Bây giờ là: {current}. Nếu bạn không tự "
        "đổi và cũng không vừa chuyển mạng Wi-Fi, đây là dấu hiệu rogue DHCP hoặc mã "
        "độc đổi cấu hình DNS.",
        "This machine previously used DNS: {baseline}. It now uses: {current}. If you "
        "didn't change this yourself and didn't just switch Wi-Fi networks, this "
        "suggests a rogue DHCP server or malware altering your DNS configuration.",
    ),
    "alert.DNS_UNEXPECTED_SERVER.title": (
        "Có truy vấn DNS đi tới server lạ {server_ip}",
        "DNS queries going to unexpected server {server_ip}",
    ),
    "alert.DNS_UNEXPECTED_SERVER.detail": (
        "Máy đang gửi truy vấn DNS tới {server_ip}, không nằm trong danh sách resolver "
        "hệ thống ({known_resolvers}). Có thể là ứng dụng tự cấu hình DNS riêng — hoặc "
        "DNS đang bị ép đi qua máy khác.",
        "This machine is sending DNS queries to {server_ip}, which is not among the "
        "system resolvers ({known_resolvers}). This may be an app using its own DNS — "
        "or DNS being forced through another machine.",
    ),
    "alert.TARPIT_CONNECTION.title": (
        "Có kết nối vào cổng mồi {port} từ {ip}",
        "Connection to decoy port {port} from {ip}",
    ),
    "alert.TARPIT_CONNECTION.detail": (
        "{ip} tự kết nối tới cổng mồi {port} trên máy này — cổng này không "
        "chạy dịch vụ thật, chỉ để câu giờ. Shield đang giữ kết nối lại chậm "
        "rãi, không gửi gì ra ngoài phạm vi kết nối họ tự mở.",
        "{ip} connected on its own to decoy port {port} on this machine — "
        "this port runs no real service, it exists only to stall. Shield is "
        "holding the connection open slowly and sends nothing beyond the "
        "connection they initiated themselves.",
    ),
    "alert.NET_GRATUITOUS_ARP_FLOOD.title": (
        "Có gratuitous ARP bất thường nhiều — nghi arpspoof/ettercap",
        "Unusually high gratuitous ARP rate — suspected arpspoof/ettercap",
    ),
    "alert.NET_GRATUITOUS_ARP_FLOOD.detail": (
        "{rate_per_s} gratuitous ARP/giây, vượt ngưỡng {threshold}. Đây là chữ ký "
        "của công cụ ARP spoof.",
        "{rate_per_s} gratuitous ARP/second, above the {threshold} threshold. This "
        "is a signature of ARP spoofing tools.",
    ),
    "alert.MITM_ROGUE_DHCP.title": (
        "Có DHCP server lạ đang phát OFFER",
        "An unknown DHCP server is sending OFFERs",
    ),
    "alert.MITM_ROGUE_DHCP.detail": (
        "DHCP server đã biết là {known_dhcp}, nhưng vừa thấy OFFER từ {rogue_dhcp}. "
        "Có thể là rogue DHCP để MITM toàn mạng.",
        "The known DHCP server is {known_dhcp}, but an OFFER was just seen from "
        "{rogue_dhcp}. This could be a rogue DHCP server used to MITM the whole network.",
    ),
    "alert.MITM_ICMP_REDIRECT.title": (
        "Nhận được ICMP Redirect",
        "Received an ICMP Redirect",
    ),
    "alert.MITM_ICMP_REDIRECT.detail": (
        "Gói ICMP Redirect từ {src_ip}. Mạng nhà bình thường không bao giờ cần gói "
        "này — chỉ cần thấy là đáng ngờ.",
        "ICMP Redirect packet from {src_ip}. A normal home network never needs this "
        "packet — seeing one at all is suspicious.",
    ),
    "alert.SCAN_PORTSCAN.title": (
        "Có port scan nhắm vào máy bạn từ {src_ip}",
        "A port scan targeting your machine from {src_ip}",
    ),
    "alert.SCAN_PORTSCAN.detail": (
        "{port_count} port khác nhau bị dò trong {window_s}s — {scan_type}.",
        "{port_count} different ports probed in {window_s}s — {scan_type}.",
    ),
    "alert.DEVICE_MAC_RANDOMIZED.title": (
        "Thiết bị dùng MAC ngẫu nhiên (riêng tư)",
        "Device using a randomized (private) MAC",
    ),
    "alert.DEVICE_MAC_RANDOMIZED.detail": (
        "IP {ip} dùng MAC riêng tư (locally-administered) — thường là điện thoại "
        "iOS/Android. Các MAC dạng này được gộp vào một dòng để tránh spam.",
        "IP {ip} is using a private (locally-administered) MAC — usually an "
        "iOS/Android phone. These MACs are grouped into a single row to avoid spam.",
    ),
    "alert.DEVICE_NEW.title": (
        "Thiết bị mới xuất hiện trong mạng",
        "A new device appeared on the network",
    ),
    "alert.DEVICE_NEW.detail": (
        "MAC {mac} ({vendor}), IP {ip}",
        "MAC {mac} ({vendor}), IP {ip}",
    ),
    "alert.LOCAL_SSH_BRUTEFORCE.title": (
        "SSH bị dò mật khẩu từ {src_ip}",
        "SSH password guessing from {src_ip}",
    ),
    "alert.LOCAL_SSH_BRUTEFORCE.detail": (
        "{fail_count} lần đăng nhập SSH sai trong {window_min} phút từ {src_ip}.",
        "{fail_count} failed SSH logins in {window_min} minutes from {src_ip}.",
    ),
    "alert.LOCAL_SUDO_FAIL.title": (
        "sudo thất bại (user: {user})",
        "sudo failure (user: {user})",
    ),
    # detail của 2 rule dưới là DÒNG LOG GỐC của hệ thống ({message}) — không
    # dịch nội dung đó (người dùng cần đúng chuỗi gốc để tra cứu), chỉ dịch
    # phần diễn giải bao quanh, để lịch sử vẫn đúng ngôn ngữ đang chọn.
    "alert.LOCAL_SUDO_FAIL.detail": (
        "Người dùng {user} chạy sudo không thành công. Dòng log gốc: {message}",
        "User {user} failed a sudo attempt. Original log line: {message}",
    ),
    "alert.LOCAL_NEW_USB.title": (
        "Có thiết bị USB mới được cắm vào",
        "A new USB device was plugged in",
    ),
    "alert.LOCAL_NEW_USB.detail": (
        "Kernel ghi nhận có USB mới cắm vào máy. Nếu không phải bạn cắm, hãy "
        "kiểm tra ngay. Dòng log gốc: {message}",
        "The kernel logged a newly attached USB device. If you didn't plug it "
        "in, check the machine now. Original log line: {message}",
    ),
    "alert.LOCAL_PROMISC_MODE.title": (
        "Interface {interface} chuyển sang promiscuous mode",
        "Interface {interface} entered promiscuous mode",
    ),
    "alert.LOCAL_PROMISC_MODE.detail": (
        "Có ai/chương trình gì đó bật sniff trên {interface} nhưng không phải "
        "Shield. Đáng nghi — có thể là công cụ nghe lén khác đang chạy.",
        "Something turned on packet sniffing on {interface} that isn't Shield. "
        "Suspicious — another eavesdropping tool may be running.",
    ),
    "alert.ENDPOINT_SUSPICIOUS_EXEC_PATH.title": (
        "Tiến trình chạy từ vị trí tạm thời đáng chú ý",
        "Process running from a suspicious temporary location",
    ),
    "alert.ENDPOINT_SUSPICIOUS_EXEC_PATH.detail": (
        "PID {pid} đang chạy {exe}.",
        "PID {pid} is running {exe}.",
    ),
    "alert.FILE_INTEGRITY_CHANGED.title": (
        "Baseline toàn vẹn file đã thay đổi",
        "File integrity baseline changed",
    ),
    "alert.FILE_INTEGRITY_CHANGED.detail": (
        "Phát hiện {change} tại {path}.",
        "Detected {change} at {path}.",
    ),
    "alert.ENDPOINT_USB_ADDED.title": (
        "Thiết bị USB mới được kết nối",
        "USB device connected",
    ),
    "alert.ENDPOINT_USB_ADDED.detail": (
        "USB {vendor_id}:{product_id} — {product}.",
        "USB {vendor_id}:{product_id} — {product}.",
    ),
    "alert.ENDPOINT_SENSITIVE_LISTENER_OPENED.title": (
        "Dịch vụ mạng nhạy cảm bắt đầu lắng nghe",
        "Sensitive network service started listening",
    ),
    "alert.ENDPOINT_SENSITIVE_LISTENER_OPENED.detail": (
        "{protocol} đang lắng nghe tại {ip}:{port}.",
        "{protocol} is listening on {ip}:{port}.",
    ),
    # Cổng nguy hiểm ĐÃ mở sẵn lúc Shield bắt đầu giám sát. Câu chữ ở đây phải
    # nói đúng thứ Shield biết và không hơn: nó KHÔNG biết cổng mở từ bao giờ,
    # nên không được nói "vừa mở", "mới xuất hiện", hay "kẻ tấn công mở".
    "alert.RISKY_LISTENER_PRESENT_AT_STARTUP.title": (
        "Cổng rủi ro đã mở sẵn khi bắt đầu giám sát",
        "Risky listener already present when monitoring started",
    ),
    "alert.RISKY_LISTENER_PRESENT_AT_STARTUP.detail": (
        "{protocol} đang lắng nghe tại {ip}:{port} từ trước khi Shield khởi "
        "động. Không rõ cổng này mở từ bao giờ.",
        "{protocol} was already listening on {ip}:{port} before Shield started. "
        "The opening time is unknown.",
    ),
    "alert.ENDPOINT_SECURITY_CONFIG_CHANGED.title": (
        "Cấu hình bảo mật quan trọng đã thay đổi",
        "Security-sensitive configuration changed",
    ),
    "alert.ENDPOINT_SECURITY_CONFIG_CHANGED.detail": (
        "{path} được thay đổi bởi PID {pid} ({exe}).",
        "{path} was changed by PID {pid} ({exe}).",
    ),
    "alert.RESPONSE_VERIFICATION_FAILED.title": (
        "Một hành động báo thành công nhưng hệ thống không hề thay đổi",
        "A response reported success but the system state did not change",
    ),
    "alert.RESPONSE_VERIFICATION_FAILED.detail": (
        "Hành động {action} không vượt qua kiểm chứng: {reason}. "
        "Đừng tin là nó đã được thực hiện.",
        "Action {action} did not pass verification: {reason}. "
        "Do not assume it took effect.",
    ),
    "alert.ENDPOINT_DELETED_EXECUTABLE.title": (
        "Executable đã xóa vẫn đang chạy",
        "Deleted executable is still running",
    ),
    "alert.ENDPOINT_DELETED_EXECUTABLE.detail": (
        "PID {pid} vẫn đang chạy executable đã xóa {exe}.",
        "PID {pid} is still running deleted executable {exe}.",
    ),
    "alert.CORRELATED_RECON_AND_SSH_ATTACK.title": (
        "Phát hiện chuỗi do thám và tấn công SSH",
        "Correlated reconnaissance and SSH attack",
    ),
    "alert.CORRELATED_RECON_AND_SSH_ATTACK.detail": (
        "Các rule liên quan xuất hiện trong cửa sổ {window_s} giây.",
        "Related rules matched within a {window_s}-second window.",
    ),
    # Luật ngưỡng: nói rõ ĐÃ THẤY BAO NHIÊU lần, vì con số mới là thứ khiến
    # người đọc phân biệt được nhiễu nền với một cuộc tấn công đang diễn ra.
    # --- Số liệu sống (overview) -----------------------------------------
    "live.title_stopped": (
        "Hoạt động thời gian thực — ĐÃ DỪNG", "Live activity — STOPPED",
    ),
    "live.stopped": (
        "Agent đã tắt. Các con số phía trên đã ngừng cập nhật — chúng KHÔNG phải "
        "tình hình hiện tại. Bấm \"Bật lại Shield\" trên thanh tiêu đề để giám sát trở lại.",
        "The agent is stopped. The numbers above are no longer updating — they do NOT "
        "reflect what is happening now. Use \"Start Shield\" in the header to resume monitoring.",
    ),
    "switch.start_btn": ("Bật lại Shield", "Start Shield"),
    "switch.start_hint": (
        "Khởi động lại agent. Cần quyền quản trị nên hệ thống sẽ hỏi mật khẩu.",
        "Start the agent again. This needs administrator rights, so you will be asked for a password.",
    ),
    "switch.start_failed": (
        "Không chạy được pkexec. Mở terminal và chạy: sudo systemctl start shield-agent",
        "Could not run pkexec. Open a terminal and run: sudo systemctl start shield-agent",
    ),
    "switch.state_agent_off": ("Agent đã tắt", "Agent stopped"),
    "switch.state_agent_off_hint": (
        "Máy này hiện KHÔNG được giám sát.", "This machine is NOT being monitored right now.",
    ),
    "live.title": (
        "Hoạt động thời gian thực", "Live activity",
    ),
    "live.events_per_s": ("Sự kiện / giây", "Events / second"),
    "live.events_session": ("Sự kiện phiên này", "Events this session"),
    "live.active_sources": ("Nguồn đang hoạt động", "Active sources"),
    "live.uptime": ("Agent đã chạy", "Agent uptime"),
    "live.paused_value": ("đã dừng", "paused"),
    "live.axis_events": ("sự kiện/giây", "events/s"),
    "live.axis_seconds": ("giây trước", "seconds ago"),
    "live.sources_title": ("Theo nguồn thu (60 giây qua)", "By source (last 60 seconds)"),
    "live.feed_title": ("Sự kiện đang tới", "Incoming events"),
    "live.col_source": ("Nguồn", "Source"),
    "live.col_per_minute": ("Sự kiện/phút", "Events/min"),
    "live.col_last": ("Gần nhất", "Last seen"),
    "live.col_kind": ("Loại", "Kind"),
    "live.feed_dropped": (
        "{count} dòng tới quá nhanh nên không hiện — đã ghi đầy đủ vào cơ sở dữ liệu.",
        "{count} lines arrived too fast to display — all of them are still recorded in the database.",
    ),
    "problems.banner": (
        "Shield đang gặp {count} vấn đề (nội dung giữ tiếng Anh, đúng như thông báo gửi đi):",
        "Shield has {count} problem(s):",
    ),
    "alert.ACCUMULATED_AUTH_FAILURES.title": (
        "Nhiều lần đăng nhập thất bại từ cùng một nguồn",
        "Repeated authentication failures from one source",
    ),
    "alert.ACCUMULATED_AUTH_FAILURES.detail": (
        "Ghi nhận {observed_count} lần thất bại trong {window_s} giây "
        "(ngưỡng {min_count}).",
        "{observed_count} failures within {window_s} seconds (threshold {min_count}).",
    ),
    "alert.ACCUMULATED_DEVICE_CONFIG_CHANGES.title": (
        "Một thiết bị bị đổi cấu hình liên tục",
        "A device is being reconfigured repeatedly",
    ),
    "alert.ACCUMULATED_DEVICE_CONFIG_CHANGES.detail": (
        "Ghi nhận {observed_count} lần đổi cấu hình trong {window_s} giây "
        "(ngưỡng {min_count}).",
        "{observed_count} configuration changes within {window_s} seconds "
        "(threshold {min_count}).",
    ),
    "alert.ACCUMULATED_DEVICE_RESTARTS.title": (
        "Một thiết bị khởi động lại nhiều lần", "A device keeps restarting",
    ),
    "alert.ACCUMULATED_DEVICE_RESTARTS.detail": (
        "Ghi nhận {observed_count} lần khởi động lại trong {window_s} giây "
        "(ngưỡng {min_count}). Hãy kiểm tra nguồn điện và tải trước khi coi "
        "đây là tấn công.",
        "{observed_count} restarts within {window_s} seconds (threshold "
        "{min_count}). Check power and load before treating this as an attack.",
    ),
    "alert.ACCUMULATED_PROBE_LOG_GAPS.title": (
        "Một probe liên tục mất bản ghi log", "A probe keeps losing log records",
    ),
    "alert.ACCUMULATED_PROBE_LOG_GAPS.detail": (
        "Ghi nhận {observed_count} lần đứt log trong {window_s} giây "
        "(ngưỡng {min_count}). Đứt lặp lại là probe hỏng hoặc có người xoá "
        "log — phải kiểm tra thẳng máy đó, không chỉ nhìn log của nó.",
        "{observed_count} log gaps within {window_s} seconds (threshold "
        "{min_count}). A repeated gap is either a failing probe or someone "
        "clearing logs — check the endpoint itself, not only its logs.",
    ),
    "alert.BEHAVIOR_EXEC_WRITE_CONNECT.title": (
        "Chuỗi thực thi đáng ngờ", "Suspicious execution chain",
    ),
    "alert.BEHAVIOR_EXEC_WRITE_CONNECT.detail": (
        "Một process đã chạy, ghi file rồi mở kết nối mạng.",
        "A process executed, wrote a file, then opened a network connection.",
    ),
    "alert.ANOMALY_DEVICE_AT_UNUSUAL_TIME.title": (
        "Thiết bị xuất hiện vào giờ nó chưa từng xuất hiện",
        "A device appeared at a time it never appears",
    ),
    "alert.ANOMALY_DEVICE_AT_UNUSUAL_TIME.detail": (
        "Thiết bị này chưa từng được thấy trong khung giờ đó. Một máy lạ lúc 3 "
        "giờ sáng khác hẳn cùng máy đó lúc 2 giờ chiều.",
        "This device has never been seen in that part of the day. An unfamiliar "
        "machine at 3am is a different thing from the same machine at 2pm.",
    ),
    "alert.ANOMALY_LOGIN_AT_UNUSUAL_TIME.title": (
        "Đăng nhập vào giờ bất thường với tài khoản này",
        "A login at an unusual hour for this account",
    ),
    "alert.ANOMALY_LOGIN_AT_UNUSUAL_TIME.detail": (
        "Tài khoản này chưa từng đăng nhập trong khung giờ đó.",
        "This account has never logged in during that time band before.",
    ),
    "alert.ANOMALY_NEW_BEHAVIOR.title": (
        "Hành vi mới ngoài baseline cục bộ", "New behavior outside local baseline",
    ),
    "alert.ANOMALY_NEW_BEHAVIOR.detail": (
        "Hành vi mới được phát hiện bằng baseline giải thích được trên máy này.",
        "A new behavior was identified by this endpoint's explainable local baseline.",
    ),
    "alert.TAMPER_CLOCK_ROLLBACK.title": (
        "Đồng hồ hệ thống bị lùi", "System clock moved backwards",
    ),
    "alert.TAMPER_CLOCK_ROLLBACK.detail": (
        "Phát hiện thời gian hệ thống lùi bất thường.", "An unusual backward wall-clock change was detected.",
    ),
    "alert.TAMPER_AGENT_FILES_CHANGED.title": (
        "File cài đặt Shield thay đổi khi đang chạy", "Shield installation changed at runtime",
    ),
    "alert.TAMPER_AGENT_FILES_CHANGED.detail": (
        "Tamper monitor phát hiện nội dung được bảo vệ đã thay đổi.",
        "The tamper monitor detected changes to protected content.",
    ),
    "advanced.health_score_tooltip": (
        "Điểm sức khoẻ của SHIELD (không phải mức an toàn của mạng). Đang bị "
        "trừ điểm bởi: {detail}",
        "Health score of SHIELD itself (not how safe your network is). Points "
        "currently lost to: {detail}",
    ),
    "incidents.set_state": ("Đổi trạng thái sự việc", "Change incident state"),
    "incidents.pick_one": (
        "Chọn một sự việc trong bảng trước đã.", "Select an incident in the table first.",
    ),
    "incidents.state.open": ("Đang mở", "Open"),
    "incidents.state.investigating": ("Đang điều tra", "Investigating"),
    "incidents.state.contained": ("Đã khống chế", "Contained"),
    "incidents.state.resolved": ("Đã xử lý xong", "Resolved"),
    "incidents.state.false_positive": ("Báo nhầm", "False positive"),
    "isolation.renewed": ("Đã gia hạn cách ly {target}", "Isolation of {target} renewed"),
    "isolation.not_armed": (
        "Không có lệnh cách ly nào đang chạy cho {target}",
        "No isolation is currently active for {target}",
    ),
    "incidents.correlated_title": (
        "Sự việc đã ghép (correlation)", "Correlated incidents",
    ),
    "incidents.grouped_title": (
        "Cảnh báo gom theo đối tượng", "Alerts grouped by subject",
    ),
    # --- lý do gộp (Phase 1 v10) ---
    # Mọi nhãn ở đây là NHÃN CỐ ĐỊNH. Nội dung thì đến từ
    # `incident_correlation_reasons` dưới dạng số và danh sách rule — không có
    # câu văn nào do máy sinh ra, và ở giai đoạn này không có câu nào do model
    # sinh ra.
    # --- Expert Evidence ---
    # Mọi nhãn ở đây là NHÃN CỐ ĐỊNH. Nội dung — đường dẫn, IP, hash, ID, tên
    # tiến trình — KHÔNG bao giờ dịch: dịch một bằng chứng là sửa nó.
    "nav.evidence": ("Bằng chứng", "Expert Evidence"),
    "evidence.sub": (
        "Xem thẳng event đã chuẩn hoá và nguồn gốc của chúng. Không có AI ở "
        "bất kỳ bước nào — đây là đường để bạn tự kiểm chứng kết luận của Shield.",
        "Read normalized events and their provenance directly. No AI is involved "
        "at any step — this is the path for verifying Shield's conclusions yourself.",
    ),
    "evidence.mode_live": ("Trực tiếp", "Live"),
    "evidence.mode_search": ("Tìm kiếm", "Historical search"),
    "evidence.search": ("Tìm", "Search"),
    "evidence.more": ("Trang tiếp", "Next page"),
    "evidence.window": ("Khoảng thời gian", "Time range"),
    "evidence.window.1h": ("1 giờ qua", "Last hour"),
    "evidence.window.6h": ("6 giờ qua", "Last 6 hours"),
    "evidence.window.24h": ("24 giờ qua", "Last 24 hours"),
    "evidence.window.7d": ("7 ngày qua", "Last 7 days"),
    "evidence.filter.kind": ("Loại", "Kind"),
    "evidence.filter.source": ("Nguồn", "Source"),
    "evidence.filter.origin": ("Xuất xứ", "Origin"),
    "evidence.filter.pid": ("PID", "PID"),
    "evidence.filter.ip": ("IP", "IP"),
    "evidence.filter.port": ("Cổng", "Port"),
    "evidence.filter.incident": ("Mã sự việc", "Incident ID"),
    "evidence.filter.alert": ("Mã cảnh báo", "Alert ID"),
    "evidence.filter.event": ("Mã event", "Event ID"),
    "evidence.col_time": ("Thời gian", "Time"),
    "evidence.col_kind": ("Loại", "Kind"),
    "evidence.col_source": ("Nguồn", "Source"),
    "evidence.col_subject": ("Đối tượng", "Subject"),
    "evidence.col_summary": ("Tóm tắt", "Summary"),
    "evidence.detail_title": ("Chi tiết bằng chứng", "Evidence detail"),
    "evidence.group.identity": ("Định danh", "Identity"),
    "evidence.group.provenance": ("Nguồn gốc", "Provenance"),
    "evidence.group.normalized": ("Dữ liệu đã chuẩn hoá", "Normalized data"),
    "evidence.group.links": ("Liên kết", "Links"),
    "evidence.group.raw": ("Dữ liệu gốc", "Original payload"),
    "evidence.field.event_id": ("Mã event", "Event ID"),
    "evidence.field.ts": ("Thời điểm xảy ra", "Observed at"),
    "evidence.field.kind": ("Loại", "Kind"),
    "evidence.field.source": ("Bộ thu thập", "Collector"),
    "evidence.field.origin": ("Xuất xứ", "Origin"),
    "evidence.field.trust": ("Mức tin cậy", "Trust"),
    "evidence.field.collector_version": ("Phiên bản collector", "Collector version"),
    "evidence.field.content_hash": ("Hash nội dung", "Content hash"),
    "evidence.field.signature_status": ("Chữ ký", "Signature"),
    "evidence.field.ts_ingested": ("Thời điểm nhận", "Ingested at"),
    "evidence.alert_ids": ("Cảnh báo liên quan", "Related alerts"),
    "evidence.incident_ids": ("Sự việc liên quan", "Related incidents"),
    "evidence.graph_ref": ("Tham chiếu đồ thị", "Graph reference"),
    "evidence.not_found": (
        "Không tìm thấy event này.", "No such event.",
    ),
    # Câu quan trọng nhất của màn hình: nói ra khi thứ được hỏi không tồn tại.
    "evidence.raw_not_retained": (
        "Shield không lưu payload gốc. Bảng event chỉ chứa bản đã chuẩn hoá ở "
        "trên. Những gì bạn thấy KHÔNG phải bản dựng lại của dữ liệu gốc.",
        "Original payload was not retained. The event table stores only the "
        "normalized record above. What you see is NOT a reconstruction of the "
        "original data.",
    ),
    "evidence.raw_available": ("Có payload gốc.", "Original payload retained."),
    "evidence.viewer_status": (
        "{rows}/{cap} dòng trên màn hình · {evicted} dòng đã cuộn khỏi khung "
        "(giới hạn màn hình, KHÔNG phải mất telemetry)",
        "{rows}/{cap} rows on screen · {evicted} rows scrolled out of view "
        "(a viewer limit, NOT telemetry loss)",
    ),
    "evidence.result_count": (
        "{count} event · cửa sổ {window}", "{count} events · {window} window",
    ),
    "evidence.pick_one": ("Chọn một event để xem chi tiết.", "Select an event to see its detail."),
    # --- người xem log: trần dòng và tạm dừng ---
    "log.pause": ("Tạm dừng", "Pause"),
    "log.resume": ("Tiếp tục", "Resume"),
    "log.viewer_status": (
        "{rows}/{cap} dòng trên màn hình · {evicted} dòng đã cuộn khỏi khung "
        "(dữ liệu vẫn còn trong database — đây KHÔNG phải mất log)",
        "{rows}/{cap} rows on screen · {evicted} rows scrolled out of view "
        "(the data is still in the database — this is NOT log loss)",
    ),
    "incidents.reasons_title": (
        "Vì sao đây là một sự việc", "Why these alerts are one incident",
    ),
    "incidents.reason.kind": ("Kiểu ghép", "Match type"),
    "incidents.reason.rule": ("Luật correlation", "Correlation rule"),
    "incidents.reason.window": ("Cửa sổ thời gian", "Time window"),
    "incidents.reason.required": ("Rule luật đòi hỏi", "Rules required"),
    "incidents.reason.observed": ("Rule quan sát được", "Rules observed"),
    "incidents.reason.counts": ("Ngưỡng / thực tế", "Threshold / observed"),
    "incidents.reason.first": ("Đóng góp đầu tiên", "First contribution"),
    "incidents.reason.last": ("Đóng góp gần nhất", "Last contribution"),
    "incidents.reason.alerts": ("Alert đóng góp", "Contributing alerts"),
    "incidents.reason.kind.rule_combination": (
        "Đủ tổ hợp rule", "Rule combination",
    ),
    "incidents.reason.kind.threshold_count": (
        "Vượt ngưỡng số lần", "Threshold exceeded",
    ),
    "incidents.reason.seconds": ("{value} giây", "{value} s"),
    "incidents.reason.none": (
        "Chưa chọn sự việc nào.", "No incident selected.",
    ),
    # Sự việc mở trước v10 không có dữ liệu này. Nói thẳng ra là dữ liệu KHÔNG
    # CÓ, không suy diễn một lý do nghe hợp lý — một lý do bịa cho một sự việc
    # cũ là thứ không ai kiểm lại được.
    "incidents.reason.legacy": (
        "Sự việc này mở trước phiên bản schema 10 nên không lưu lý do ghép. "
        "Dữ liệu không tồn tại, không phải bị ẩn.",
        "This incident was opened before schema version 10, so no correlation "
        "reason was recorded. The data does not exist; it is not hidden.",
    ),
    "incidents.reason.no_alert_ids": (
        "Không có (sự việc trước v10)", "None (pre-v10 incident)",
    ),
    "incidents.col_title": ("Sự việc", "Incident"),
    "incidents.col_state": ("Trạng thái", "State"),
    "incidents.col_mitre": ("MITRE", "MITRE"),
    "incidents.col_action": ("Khuyến nghị", "Recommended action"),
    "incidents.updated": (
        "Cập nhật sự việc: {count} đang theo dõi", "Incidents updated: {count} tracked",
    ),
    "alert.ISOLATION_AUTO_ROLLED_BACK.title": (
        "Cách ly hết hạn và đã tự gỡ", "Isolation expired and was rolled back",
    ),
    "alert.ISOLATION_AUTO_ROLLED_BACK.detail": (
        "Việc cách ly không được gia hạn đúng hạn nên đã tự gỡ. Đây là cơ chế "
        "an toàn: một máy bị cách ly vĩnh viễn thì không ai vào sửa được nữa.",
        "The isolation was not renewed in time and has been lifted. This is the "
        "safety mechanism: a permanently isolated machine cannot be repaired remotely.",
    ),
    # --- correlation / incident (mục B5) ---
    "alert.CORRELATED_NEW_DEVICE_THEN_SCAN.title": (
        "Thiết bị lạ vừa vào mạng đã quét ngay",
        "An unknown device joined and immediately scanned the network",
    ),
    "alert.CORRELATED_NEW_DEVICE_THEN_SCAN.detail": (
        "Một thiết bị chưa từng thấy vừa xuất hiện rồi quét cổng. Hãy xác định "
        "nó là máy nào trước khi cho phép ở lại trong mạng.",
        "A device never seen before appeared and then scanned for open ports. "
        "Identify it physically before letting it stay on the network.",
    ),
    "alert.CORRELATED_MITM_AND_DNS_CHANGE.title": (
        "Giả mạo gateway đi kèm chuyển hướng DNS",
        "Gateway impersonation combined with a DNS redirect",
    ),
    "alert.CORRELATED_MITM_AND_DNS_CHANGE.detail": (
        "MAC của gateway đổi và DNS cũng bị đổi trong cùng khoảng thời gian — "
        "đây là dạng tấn công chen giữa điển hình.",
        "The gateway MAC changed and DNS changed in the same window — this is "
        "the classic shape of a man-in-the-middle attack.",
    ),
    "alert.CORRELATED_SSH_ACCESS_THEN_NEW_BEHAVIOR.title": (
        "Root đăng nhập SSH rồi làm việc chưa từng thấy",
        "Root logged in over SSH and then did something never seen before",
    ),
    "alert.CORRELATED_SSH_ACCESS_THEN_NEW_BEHAVIOR.detail": (
        "Sau khi root đăng nhập, máy chạy thứ chưa từng có trong baseline. "
        "Xem dòng thời gian tiến trình trước khi phiên đó kết thúc.",
        "After the root login, the machine did something absent from its "
        "baseline. Review the process timeline before that session ends.",
    ),
    # --- rule pack theo lĩnh vực (mục B4) ---
    "alert.SSH_ROOT_LOGIN_SUCCEEDED.title": (
        "Đăng nhập SSH thẳng bằng root thành công", "Direct root login over SSH succeeded",
    ),
    "alert.SSH_ROOT_LOGIN_SUCCEEDED.detail": (
        "Tài khoản root vừa đăng nhập SSH. Cấu hình an toàn thường cấm hẳn việc này.",
        "The root account just logged in over SSH. A hardened configuration normally forbids this entirely.",
    ),
    "alert.SSH_AUTH_FAILURE_OBSERVED.title": (
        "Đăng nhập SSH thất bại", "SSH authentication failed",
    ),
    "alert.SSH_AUTH_FAILURE_OBSERVED.detail": (
        "Một lần đăng nhập SSH thất bại. Lẻ tẻ là bình thường; dồn dập mới đáng lo.",
        "A single failed SSH login. Isolated failures are normal; bursts are not.",
    ),
    "alert.SSH_LOGIN_BY_SYSTEM_ACCOUNT.title": (
        "Tài khoản hệ thống đăng nhập SSH", "A system account logged in over SSH",
    ),
    "alert.SSH_LOGIN_BY_SYSTEM_ACCOUNT.detail": (
        "Các tài khoản như www-data, mysql, nobody không bao giờ nên đăng nhập tương tác.",
        "Accounts such as www-data, mysql or nobody should never log in interactively.",
    ),
    "alert.PROBE_LOG_GAP.title": (
        "Probe làm mất log trước khi kịp gửi", "A probe lost log lines before sending them",
    ),
    "alert.PROBE_LOG_GAP.detail": (
        "Có một khoảng trống trong lịch sử của máy đó — khoảng lặng này KHÔNG "
        "đồng nghĩa với yên tĩnh.",
        "There is a gap in that machine's history — the silence does NOT mean nothing happened.",
    ),
    "alert.SYSLOG_AUTH_FAILURE.title": (
        "Thiết bị mạng báo đăng nhập thất bại", "A network device reported a failed login",
    ),
    "alert.SYSLOG_AUTH_FAILURE.detail": (
        "Log này đến từ nguồn KHÔNG xác thực được — dùng làm manh mối, không "
        "phải bằng chứng.",
        "This log came from an unauthenticated source — treat it as a lead, not as evidence.",
    ),
    "alert.SYSLOG_DEVICE_CONFIG_CHANGED.title": (
        "Thiết bị mạng báo cấu hình thay đổi", "A network device reported a configuration change",
    ),
    "alert.SYSLOG_DEVICE_CONFIG_CHANGED.detail": (
        "Router/switch báo cấu hình hoặc firmware vừa đổi. Nếu không phải bạn làm, hãy kiểm tra.",
        "A router or switch reported that its configuration or firmware changed. If that was not you, investigate.",
    ),
    "alert.SYSLOG_DEVICE_RESTARTED.title": (
        "Thiết bị mạng khởi động lại", "A network device restarted",
    ),
    "alert.SYSLOG_DEVICE_RESTARTED.detail": (
        "Thiết bị báo vừa khởi động lại.", "The device reported that it restarted.",
    ),
    "alert.ENDPOINT_USB_STORAGE_ATTACHED.title": (
        "Có thiết bị USB được cắm vào", "A USB device was attached",
    ),
    "alert.ENDPOINT_USB_STORAGE_ATTACHED.detail": (
        "Một thiết bị USB mới vừa được cắm vào máy được giám sát.",
        "A new USB device was attached to a monitored machine.",
    ),
    "alert.ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT.title": (
        "Có tiến trình mở cổng truy cập từ xa", "A remote-access port started listening",
    ),
    "alert.ENDPOINT_LISTENER_ON_REMOTE_ACCESS_PORT.detail": (
        "Cổng telnet/RDP/VNC/proxy hiếm khi được mở có chủ đích.",
        "Telnet, RDP, VNC and proxy ports are rarely opened on purpose.",
    ),
    # --- Probe & syslog (KE-HOACH-SHIELD-1.1.md phần A) ---
    "probe.table_title": ("Probe và syslog trong mạng", "Network probes and syslog"),
    "probe.hint": (
        "Chưa có máy nào gửi log về đây. Cài Shield Probe lên máy khác để "
        "gom log của chúng về một chỗ — xem PROBE.md trong thư mục tài liệu.",
        "No machine is sending logs here yet. Install Shield Probe on other "
        "machines to collect their logs in one place — see PROBE.md in the docs.",
    ),
    "probe.summary": (
        "{probes} probe đang ghi danh • syslog: {syslog} • đã nhận {accepted} dòng, "
        "từ chối {rejected}",
        "{probes} enrolled probes • syslog: {syslog} • {accepted} lines accepted, "
        "{rejected} rejected",
    ),
    "probe.syslog_on": ("đang nghe", "listening"),
    "probe.syslog_off": ("tắt", "off"),
    "probe.col_name": ("Probe", "Probe"),
    "probe.col_address": ("Địa chỉ", "Address"),
    "probe.col_last_seen": ("Lần cuối gửi", "Last seen"),
    "probe.col_lag": ("Độ trễ", "Lag"),
    "probe.col_lines": ("Số dòng", "Lines"),
    "probe.col_dropped": ("Bị bỏ", "Dropped"),
    # --- Guardian (shield/guardian/__main__.py) ---
    "alert.GUARDIAN_AGENT_STOPPED.title": (
        "Agent bị dừng mà không ai yêu cầu", "Agent stopped and nobody asked it to",
    ),
    "alert.GUARDIAN_AGENT_STOPPED.detail": (
        "Guardian thấy shield-agent không chạy, và không có lệnh tắt hợp lệ nào "
        "được ghi nhận. Máy này hiện KHÔNG được giám sát.",
        "Guardian found shield-agent not running, with no authorized shutdown on "
        "record. This machine is currently NOT monitored.",
    ),
    "alert.GUARDIAN_AGENT_STOPPED_BY_OPERATOR.title": (
        "Shield đã được tắt từ trong app", "Shield was shut down from the app",
    ),
    "alert.GUARDIAN_AGENT_STOPPED_BY_OPERATOR.detail": (
        "Người dùng chủ động tắt agent. Máy này không được giám sát cho tới khi "
        "bạn bật lại.",
        "An operator stopped the agent. This machine is not monitored until you "
        "start it again.",
    ),
    "alert.GUARDIAN_AGENT_RESTART_STORM.title": (
        "Agent khởi động lại liên tục", "Agent is restarting repeatedly",
    ),
    "alert.GUARDIAN_AGENT_RESTART_STORM.detail": (
        "Agent chết và tự sống lại nhiều lần — trạng thái \"active\" đang che "
        "một sự cố thật.",
        "The agent keeps dying and restarting — its \"active\" state is hiding a "
        "real failure.",
    ),
    "alert.GUARDIAN_INSTALLATION_CHANGED.title": (
        "File chương trình Shield đã bị thay đổi", "Shield program files were changed",
    ),
    "alert.GUARDIAN_INSTALLATION_CHANGED.detail": (
        "Guardian thấy file cài đặt khác với lần kiểm tra trước.",
        "Guardian found installed files that differ from the previous check.",
    ),
    'report.downgrade.out_of_scope': (
        'Bằng chứng nằm ngoài phạm vi điều tra',
        'Evidence was outside the investigation scope',
    ),
    'report.downgrade.unknown_evidence': (
        'Bằng chứng được viện dẫn không tồn tại',
        'The cited evidence does not exist',
    ),
    'report.downgrade.contradicted': (
        'Có bằng chứng mâu thuẫn',
        'Contradicting evidence exists',
    ),
    'report.downgrade.external_only': (
        'Chỉ có nguồn ngoài — đối chứng được, không xác nhận được',
        'External sources only — they corroborate, they do not confirm',
    ),
    'report.downgrade.untrusted_source': (
        'Nguồn không xác thực không thể một mình xác nhận',
        'An unauthenticated source cannot confirm this on its own',
    ),
    'report.downgrade.insufficient_evidence': (
        'Không đủ bằng chứng độc lập',
        'Not enough independent evidence',
    ),
    'report.downgrade.unconfirmed': (
        'Chưa xác nhận',
        'Unconfirmed',
    ),
    'report.downgrade.other': (
        'Đã hạ cấp vì một lý do khác',
        'Downgraded for another reason',
    ),
    'report.prose_dropped': (
        'Phần diễn giải của model đã bị bỏ vì chứa số liệu không khớp dữ liệu gốc',
        "The model's narrative was dropped because it contained values that do not match the source data",
    ),
    "alert.GUARDIAN_CHECK_FAILED.title": (
        "Một phép kiểm của Guardian không chạy được",
        "A guardian check could not run",
    ),
    "alert.GUARDIAN_CHECK_FAILED.detail": (
        "Một phép kiểm bị lỗi nên lượt canh này không đầy đủ. Guardian im lặng "
        "và Guardian bình thường nhìn giống hệt nhau, nên chỗ này phải nói ra.",
        "A check errored, so this round of watching was incomplete. A silent "
        "guardian and a healthy one look identical, so this has to be said.",
    ),
    "alert.GUARDIAN_PROTECTED_ROOT_UNAVAILABLE.title": (
        "Không kiểm tra được cây file cài đặt",
        "Guardian could not verify the protected installation tree",
    ),
    "alert.GUARDIAN_PROTECTED_ROOT_UNAVAILABLE.detail": (
        "Cây file được bảo vệ không có ở đó để so sánh. Không kiểm tra được "
        "KHÁC với kiểm tra đạt — Guardian chưa kết luận gì về nguyên nhân.",
        "The protected tree was not there to compare against. Unable to verify "
        "is not the same as verified — Guardian is not saying why.",
    ),
    "alert.GUARDIAN_INSTALLATION_UNREADABLE.title": (
        "Không kiểm tra được file cài đặt", "Shield installation could not be verified",
    ),
    "alert.GUARDIAN_INSTALLATION_UNREADABLE.detail": (
        "Guardian không đọc được cây file cài đặt để so sánh.",
        "Guardian could not read the installation tree to compare it.",
    ),
    "alert.GUARDIAN_DATABASE_MISSING.title": (
        "Database của Shield biến mất", "Shield database is gone",
    ),
    "alert.GUARDIAN_DATABASE_MISSING.detail": (
        "Không tìm thấy file database ở vị trí mong đợi.",
        "The database file is missing from its expected location.",
    ),
    "alert.GUARDIAN_DATABASE_CORRUPT.title": (
        "Database của Shield bị hỏng", "Shield database is corrupt",
    ),
    "alert.GUARDIAN_DATABASE_CORRUPT.detail": (
        "SQLite không mở được database.", "SQLite could not open the database.",
    ),
    "alert.GUARDIAN_LEDGER_UNREADABLE.title": (
        "Không đọc được sổ bằng chứng", "Forensic ledger could not be read",
    ),
    "alert.GUARDIAN_LEDGER_UNREADABLE.detail": (
        "Bảng forensic_ledger không truy vấn được.",
        "The forensic_ledger table could not be queried.",
    ),
    "alert.GUARDIAN_LEDGER_TRUNCATED.title": (
        "Sổ bằng chứng bị mất bản ghi", "Forensic ledger lost records",
    ),
    "alert.GUARDIAN_LEDGER_TRUNCATED.detail": (
        "Sổ bằng chứng chỉ được phép dài ra. Ngắn đi nghĩa là có người xoá.",
        "The forensic ledger may only ever grow. Shrinking means records were deleted.",
    ),
    "alert.SHIELD_DATABASE_RECOVERED.title": (
        "Database hỏng — đã dựng lại", "Database was corrupt and rebuilt",
    ),
    "alert.SHIELD_DATABASE_RECOVERED.detail": (
        "Database cũ được giữ nguyên làm bằng chứng; phần lịch sử cứu được đã "
        "chuyển sang database mới.",
        "The corrupt database is preserved as evidence; whatever history could "
        "be rescued was moved into a fresh database.",
    ),
    "alert.SHIELD_DATABASE_INTEGRITY_FAILED.title": (
        "Kiểm tra toàn vẹn database thất bại", "Database integrity check failed",
    ),
    "alert.SHIELD_DATABASE_INTEGRITY_FAILED.detail": (
        "SQLite báo database có lỗi cấu trúc.",
        "SQLite reported structural damage in the database.",
    ),
}


def current_lang() -> str:
    return _lang


def set_lang(lang: str) -> None:
    global _lang
    if lang in ("vi", "en"):
        _lang = lang


def t(key: str, **kwargs) -> str:
    """Tra chuỗi theo ngôn ngữ hiện tại. `key` lạ trả về chính nó (dễ phát
    hiện chuỗi thiếu bản dịch lúc chạy thay vì crash)."""
    vi, en = STRINGS.get(key, (key, key))
    raw = en if _lang == "en" else vi
    return raw.format(**kwargs) if kwargs else raw


def error_message(data: dict) -> str:
    """Thông báo lỗi từ agent, dịch theo ngôn ngữ đang chọn.

    Agent gửi kèm `error_key` cho các lỗi có nội dung cố định (thiếu ô bắt
    buộc, chưa đọc được gì...) — dịch được. Lỗi mang nội dung động (stderr
    của nmap/ssh, lý do CIDR sai) thì chỉ có `error` thô, hiện nguyên văn:
    dịch output của công cụ hệ thống là việc không làm được và cũng không
    nên làm (người dùng cần đúng chuỗi gốc để tra cứu).
    """
    key = data.get("error_key")
    if key and key in STRINGS:
        try:
            return t(key, **(data.get("error_params") or {}))
        except (KeyError, IndexError, ValueError):
            pass
    return data.get("error", "") or ""


def alert_text(alert: dict) -> tuple[str, str]:
    """Dịch title/detail của 1 alert theo `rule_id` + `evidence` thay vì hiện
    thẳng title/detail thô agent gửi (luôn tiếng Việt — xem giới hạn đã ghi
    trong README). Không có `alert.<rule_id>.title/.detail` trong STRINGS, hoặc
    evidence thiếu key mà template cần -> rơi về title/detail thô, không crash.
    """
    rule_id = alert.get("rule_id", "")
    evidence = dict(alert.get("evidence") or {})

    if "scan_type_key" in evidence:
        evidence["scan_type"] = t(f"portscan.scan_type.{evidence['scan_type_key']}")
    if isinstance(evidence.get("macs"), list):
        evidence["mac_count"] = len(evidence["macs"])
        evidence["macs"] = ", ".join(evidence["macs"])
    if isinstance(evidence.get("ports"), list):
        evidence["port_count"] = len(evidence["ports"])
        evidence["ports"] = ", ".join(str(p) for p in evidence["ports"])
    if isinstance(evidence.get("known_resolvers"), list):
        evidence["known_resolvers"] = (
            ", ".join(evidence["known_resolvers"]) or t("common.unknown")
        )
    if not evidence.get("vendor"):
        evidence["vendor"] = t("common.unknown")
    for k, v in evidence.items():
        if v is None:
            evidence[k] = t("common.unknown")

    title_key, detail_key = f"alert.{rule_id}.title", f"alert.{rule_id}.detail"
    try:
        title = t(title_key, **evidence) if title_key in STRINGS else alert.get("title", "")
    except (KeyError, IndexError, ValueError):
        title = alert.get("title", "")
    try:
        detail = t(detail_key, **evidence) if detail_key in STRINGS else alert.get("detail", "")
    except (KeyError, IndexError, ValueError):
        detail = alert.get("detail", "")
    return title, detail
