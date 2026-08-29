"""SQLite: agent ghi, UI đọc song song (WAL mode).

Đường dẫn DB không hard-code — dò theo thứ tự:
1. Biến môi trường SHIELD_DB.
2. /var/lib/shield/shield.db nếu thư mục ghi được (production, có systemd).
3. Fallback $XDG_DATA_HOME/shield/shield.db (dev, không cần root) — chạy
   giống nhau trên Ubuntu và Kali, không phụ thuộc distro.
"""

from __future__ import annotations

import dataclasses
import os
import hashlib
import hmac
import json
import logging
import sqlite3
import secrets
import threading
import time
import uuid
from pathlib import Path

from shield.common import sdnotify
from shield.common.models import Alert, Event
from shield.ai.audit import AI_AUDIT_INDEXES, AI_AUDIT_SCHEMA
from shield.ai.chat import CHAT_SCHEMA
from shield.ai.enrichment import ENRICHMENT_SCHEMA
from shield.decision.calibration import CALIBRATION_INDEXES, CALIBRATION_SCHEMA
from shield.evidence.graph import GRAPH_INDEXES, GRAPH_SCHEMA, EvidenceGraph
from shield.response.jobs import RESPONSE_INDEXES, RESPONSE_SCHEMA
from shield.security.knowledge import KNOWLEDGE_INDEXES, KNOWLEDGE_SCHEMA

logger = logging.getLogger("shield.store")

# --- Trần công việc cho MỘT lượt bảo trì ---
#
# Bảo trì phải TIẾN ĐỀU, không phải xong trong một lượt. Đo trên database
# production (1,59 triệu event, 1,24 triệu cạnh graph): một vòng "xoá 50k +
# dọn graph toàn bảng" mất 9,6 giây, và vòng lặp cũ chạy tới 40 vòng — gần 400
# giây giữ khoá `_ThreadSafeConnection`. Watchdog systemd ping mỗi 45 giây và
# lời ping đó phải đọc được store, tức phải chờ đúng cái khoá ấy. Kết quả đã
# quan sát được trên máy thật: bốn lần SIGABRT rồi service nằm ở `failed`.
#
# Các trần dưới đây giữ một lượt ở mức dưới hai giây trên cùng database đó.
SIZE_CAP_MAX_BATCHES = 1
RETENTION_DELETE_LIMIT = 50_000
GRAPH_PRUNE_MAX_EDGES = 20_000
# Con trỏ dọn graph, lưu trong `baseline` để một lần khởi động lại không làm
# lượt quét quay về đầu bảng mãi mãi.
GRAPH_PRUNE_CURSOR_KEY = "graph_prune_cursor"

SCHEMA_VERSION = 10
CONFIG_SCHEMA_VERSION = 1


class DatabaseIntegrityError(RuntimeError):
    """Raised without modifying the original database when SQLite is corrupt."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    -- origin: "local" | "probe:<endpoint_id>" | "syslog:<ip>". Một dòng log
    -- không nói được nó đến từ đâu thì vô giá trị khi điều tra.
    origin TEXT NOT NULL DEFAULT 'local',
    -- trust: "authenticated" (có danh tính mật mã) | "unauthenticated"
    -- (syslog thô — ai trong LAN cũng giả mạo được). Xem KE-HOACH-SHIELD-1.1
    -- mục A2: trust quyết định event có được vào forensic_ledger hay không.
    trust TEXT NOT NULL DEFAULT 'authenticated'
);

CREATE TABLE IF NOT EXISTS probe_health (
    probe_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT '',
    last_seen REAL NOT NULL DEFAULT 0,
    last_event_ts REAL NOT NULL DEFAULT 0,
    lines_total INTEGER NOT NULL DEFAULT 0,
    lines_dropped INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL,
    subject TEXT NOT NULL,
    evidence TEXT NOT NULL,
    playbook TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.5,
    policy_action TEXT NOT NULL DEFAULT 'alert',
    count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL DEFAULT 0,
    last_seen REAL NOT NULL DEFAULT 0,
    sources TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    vendor TEXT,
    hostname TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS device_identities (
    device_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    owner_label TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT 'Normal',
    created_ts REAL NOT NULL,
    updated_ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS device_links (
    mac TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    user_confirmed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(device_id) REFERENCES device_identities(device_id)
);
CREATE TABLE IF NOT EXISTS device_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    mac TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(device_id,mac,ip,hostname),
    FOREIGN KEY(device_id) REFERENCES device_identities(device_id)
);
CREATE TABLE IF NOT EXISTS device_profiles (
    device_id TEXT PRIMARY KEY,
    device_type TEXT NOT NULL,
    label TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence TEXT NOT NULL,
    signals TEXT NOT NULL,
    updated_ts REAL NOT NULL,
    FOREIGN KEY(device_id) REFERENCES device_identities(device_id)
);

CREATE TABLE IF NOT EXISTS trusted (
    mac TEXT PRIMARY KEY,
    note TEXT,
    added_ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    action_id TEXT NOT NULL,
    params TEXT NOT NULL,
    result TEXT NOT NULL
);

-- Giai đoạn 2: baseline gateway/DHCP server "sạch", mọi detector MITM dựa
-- vào đây (KE-HOACH-SHIELD.md mục 2.1). key/value đơn giản, không cần bảng riêng.
CREATE TABLE IF NOT EXISTS baseline (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    set_ts REAL NOT NULL
);

-- Giai đoạn 5: gương của set nftables blocked_ips/blocked_macs — để UI
-- (chỉ đọc SQLite) hiện được danh sách đang chặn + nút Gỡ chặn, không phải
-- gọi `nft` trực tiếp từ UI. Nguồn sự thật vẫn là nftables; bảng này chỉ để
-- hiển thị, kernel tự xoá theo TTL độc lập với bảng này (mục 3 kế hoạch).
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    blocked_ts REAL NOT NULL,
    expires_ts REAL NOT NULL
);

-- Dải mạng ngoài subnet nhà, được bạn xác nhận là có cấp phép quét (ví dụ
-- mạng công ty được ủy quyền). `scan_authorized_range` ở agent/__main__.py
-- CHỈ chạy nếu cidr yêu cầu nằm trong (hoặc trùng) một dòng ở đây — bảng này
-- là hàng rào bảo vệ, không phải chỗ ghi log thông thường.
CREATE TABLE IF NOT EXISTS authorized_ranges (
    cidr TEXT PRIMARY KEY,
    note TEXT NOT NULL,
    added_ts REAL NOT NULL
);

-- Lưu lượng theo thiết bị đọc TỪ ROUTER (shield/agent/router_backends.py),
-- không phải Shield tự sniff. Số cộng dồn (cumulative) từ router; UI/agent
-- tự tính delta để ra tốc độ. Cấu hình backend (ssh_conntrack/custom_script)
-- nằm trong bảng `baseline` (key ROUTER_BACKEND_CONFIG), tái dùng thay vì
-- tạo bảng riêng chỉ để lưu 1 blob JSON.
CREATE TABLE IF NOT EXISTS router_traffic (
    ip TEXT PRIMARY KEY,
    mac TEXT,
    rx_bytes INTEGER NOT NULL,
    tx_bytes INTEGER NOT NULL,
    updated_ts REAL NOT NULL
);

-- Lịch sử kết quả self_port_scan theo host, để so sánh 2 lần quét cách nhau
-- (vd tuần trước/tuần này) và thấy thay đổi âm thầm trong cấu hình mạng —
-- kiểm thử định kỳ cần cái này, trước đây self_port_scan chỉ broadcast kết
-- quả 1 lần, không lưu lại gì ngoài dòng tóm tắt trong audit_log.
CREATE TABLE IF NOT EXISTS audit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    ts REAL NOT NULL,
    ports TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fim_baselines (
    path TEXT PRIMARY KEY,
    metadata TEXT NOT NULL,
    updated_ts REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
    indicator_type TEXT NOT NULL,
    indicator TEXT NOT NULL,
    provider TEXT NOT NULL,
    verdict TEXT NOT NULL,
    payload TEXT NOT NULL,
    expires_ts REAL NOT NULL,
    PRIMARY KEY (indicator_type, indicator, provider)
);

CREATE TABLE IF NOT EXISTS forensic_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    category TEXT NOT NULL,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    auth_tag TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_sessions (
    session_id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    started_ts REAL NOT NULL,
    finished_ts REAL NOT NULL,
    result TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessment_ground_truth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    test_id TEXT NOT NULL,
    ts REAL NOT NULL,
    record TEXT NOT NULL
);

-- Incident: nhiều alert rời rạc gộp thành MỘT sự việc có đầu có cuối
-- (KE-HOACH-SHIELD-1.1.md mục B5). Trước 1.1, alert tương quan cũng chỉ là
-- một alert nữa, nên người dùng nhìn thấy 30 dòng thay vì 1 sự việc.
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    correlation_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.5,
    state TEXT NOT NULL DEFAULT 'open',
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    recommended_action TEXT NOT NULL DEFAULT '',
    alert_count INTEGER NOT NULL DEFAULT 0,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    UNIQUE(correlation_id, subject, state)
);
CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    alert_ts REAL NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    detail TEXT NOT NULL DEFAULT '',
    -- alerts.id — tham chiếu chính danh. Khoá chính bên dưới vẫn giữ nguyên
    -- (rule_id, alert_ts) để dữ liệu v9 đọc được không đổi; cột này là đường
    -- tra cứu ĐÚNG, còn cặp kia chỉ còn là khoá chống trùng lịch sử.
    alert_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(incident_id, rule_id, alert_ts),
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
);

-- LÝ DO GỘP, dạng có cấu trúc. Không có trường văn xuôi nào ở đây là cố ý:
-- một lý do viết bằng câu chữ thì không kiểm được, không so được giữa hai lần
-- chạy, và không truy được về cái gì đã tạo ra nó. Mỗi cột dưới đây hoặc là
-- ĐẦU VÀO của luật (`rule_id`, `window_s`, `required_rules`, `min_count`),
-- hoặc là thứ ĐO ĐƯỢC (`observed_rules`, `observed_count`, hai mốc thời gian).
--
-- Truy ngược: `rule_id` -> shield/rules/correlation.json (pack đã ký);
-- alert đóng góp -> incident_alerts.alert_id -> alerts.id.
CREATE TABLE IF NOT EXISTS incident_correlation_reasons (
    incident_id TEXT NOT NULL,
    -- 'rule_combination': đủ tổ hợp rule khác nhau trong cửa sổ.
    -- 'threshold_count': một loại rule lặp đủ số lần trong cửa sổ.
    reason_kind TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    window_s REAL NOT NULL,
    required_rules TEXT NOT NULL DEFAULT '[]',
    observed_rules TEXT NOT NULL DEFAULT '[]',
    min_count INTEGER NOT NULL DEFAULT 0,
    observed_count INTEGER NOT NULL DEFAULT 0,
    first_contributing_ts REAL NOT NULL,
    last_contributing_ts REAL NOT NULL,
    ts REAL NOT NULL,
    -- Khoá gồm cả hai mốc thời gian: cùng một luật khớp lại ở một khoảng khác
    -- là một lý do KHÁC, không phải bản ghi trùng. Cùng đầu vào thì cùng khoá,
    -- nên chạy lại cùng dữ liệu không sinh thêm dòng.
    PRIMARY KEY(incident_id, rule_id, first_contributing_ts, last_contributing_ts),
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
);

-- Tham chiếu sang các bảng ĐÃ CÓ. `ref_id` luôn là khoá chính của bảng gốc,
-- không phải một định danh mới:
--   'evidence' -> events.event_id
--   'asset'    -> graph_entities.entity_id
-- `response_job` KHÔNG có ở đây: `response_jobs.incident_id` đã tồn tại, nên
-- danh sách job của một incident được ĐỌC RA từ đó. Chép sang bảng thứ hai chỉ
-- tạo ra hai câu trả lời cho cùng một câu hỏi và một cơ hội để chúng lệch nhau.
CREATE TABLE IF NOT EXISTS incident_refs (
    incident_id TEXT NOT NULL,
    ref_kind TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    ts REAL NOT NULL,
    PRIMARY KEY(incident_id, ref_kind, ref_id),
    FOREIGN KEY(incident_id) REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS security_cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    subject TEXT NOT NULL,
    state TEXT NOT NULL,
    created_ts REAL NOT NULL,
    updated_ts REAL NOT NULL,
    alert_rules TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ts REAL NOT NULL,
    author TEXT NOT NULL,
    note TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES security_cases(case_id)
);
CREATE TABLE IF NOT EXISTS behavior_baselines (
    behavior_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    observation_count INTEGER NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    learning_until REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_pattern TEXT NOT NULL,
    subject_pattern TEXT NOT NULL,
    expires_ts REAL NOT NULL,
    reason TEXT NOT NULL,
    created_ts REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_endpoints (
    endpoint_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    certificate_fingerprint TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    enrolled_ts REAL NOT NULL,
    last_seen REAL NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collector_health (
    component TEXT PRIMARY KEY,
    backend TEXT NOT NULL,
    healthy INTEGER NOT NULL,
    detail TEXT NOT NULL,
    updated_ts REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'running',
    started_ts REAL NOT NULL DEFAULT 0,
    last_heartbeat REAL NOT NULL DEFAULT 0,
    last_event REAL NOT NULL DEFAULT 0,
    restart_count INTEGER NOT NULL DEFAULT 0,
    dropped_events INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS system_health (
    metric TEXT PRIMARY KEY,
    value REAL NOT NULL,
    unit TEXT NOT NULL,
    state TEXT NOT NULL,
    detail TEXT NOT NULL,
    updated_ts REAL NOT NULL
);
""" + GRAPH_SCHEMA + CALIBRATION_SCHEMA + RESPONSE_SCHEMA + AI_AUDIT_SCHEMA + KNOWLEDGE_SCHEMA + ENRICHMENT_SCHEMA + CHAT_SCHEMA

# Index tách khỏi SCHEMA có chủ ý: chúng tham chiếu cột mà một database cũ
# chưa có (v3 không có events.origin). CREATE TABLE IF NOT EXISTS là no-op
# trên bảng đã tồn tại, nên cột chỉ xuất hiện sau _migrate_schema(); tạo
# index trước đó sẽ đổ với "no such column". Thứ tự đúng: bảng → migrate →
# index.
SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_events_origin ON events(origin, ts);
-- Index theo THỜI GIAN là index quan trọng nhất của bảng này: gần như mọi
-- truy vấn đều hỏi "chuyện gì vừa xảy ra". Thiếu nó thì mỗi câu quét toàn
-- bảng — đo trên 892 nghìn dòng thật: "100 event mới nhất" mất 900ms, có
-- index còn 0,2ms. Với 30 ngày lưu trữ bảng này lên tới hàng chục triệu
-- dòng, và khi đó chênh lệch đó là ứng dụng dùng được hay không.
-- idx_events_origin(origin, ts) KHÔNG thay thế được: SQLite chỉ dùng được
-- cột ts của nó khi câu truy vấn đã cố định origin.
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_subject_rule ON alerts(subject, rule_id);
CREATE INDEX IF NOT EXISTS idx_audit_snapshots_host_ts ON audit_snapshots(host, ts);
CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state, last_seen);
CREATE INDEX IF NOT EXISTS idx_incident_refs_kind ON incident_refs(ref_kind, ref_id);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert ON incident_alerts(alert_id);
-- event_id là UNIQUE nhưng chỉ với dòng ĐÃ có id: 892 nghìn dòng có sẵn từ
-- schema v4 mang chuỗi rỗng, và một UNIQUE thường sẽ coi chúng là trùng nhau
-- rồi làm hỏng cả lượt migrate. Index một phần cho phép chống ingest trùng ở
-- dữ liệu mới mà không phải viết lại toàn bộ dữ liệu cũ.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_id
    ON events(event_id) WHERE event_id != '';
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ts_ingested);
-- Lọc theo nguồn. Không có index này thì câu "200 event mới nhất của nguồn X"
-- đi ngược index `ts` qua TOÀN BỘ bảng, và nghịch lý là nguồn càng HIẾM càng
-- chậm — nó không bao giờ gom đủ 200 dòng nên phải quét hết.
--
-- Đo trên database production, 1.837.445 dòng:
--     source=journal   (       13 dòng)   510,26 ms  ->  0,25 ms
--     source=kernel    (1.065.392 dòng)     0,17 ms  ->  0,23 ms
--     source=endpoint  (   58.717 dòng)     1,63 ms  ->  0,27 ms
-- Chi phí: dựng 0,9 giây, +47 MB.
CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source, ts);
""" + GRAPH_INDEXES + CALIBRATION_INDEXES + RESPONSE_INDEXES + AI_AUDIT_INDEXES + KNOWLEDGE_INDEXES


def _describe_path(path: Path) -> str:
    """`drwx------ root:root` — dùng trong thông báo lỗi về quyền."""
    import grp
    import pwd
    import stat as stat_module

    try:
        info = path.stat()
    except OSError as exc:
        return f"không đọc được ({exc})"
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner = str(info.st_uid)
    try:
        group = grp.getgrgid(info.st_gid).gr_name
    except KeyError:
        group = str(info.st_gid)
    return f"{stat_module.filemode(info.st_mode)} {owner}:{group}"


def default_db_path() -> Path:
    env = os.environ.get("SHIELD_DB")
    if env:
        return Path(env)

    prod_candidate = Path("/var/lib/shield/shield.db")
    if prod_candidate.parent.exists() and os.access(prod_candidate.parent, os.W_OK):
        return prod_candidate

    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
    return data_home / "shield" / "shield.db"


class _Result:
    """Kết quả đã đọc sẵn của một câu lệnh, để cursor không bị dùng tiếp sau
    khi đã nhả khoá. `conn.execute(...).fetchall()` ở call site nghĩa là cursor
    còn sống ngoài vùng khoá — mà đọc cursor vẫn là chạm vào connection."""

    __slots__ = ("_rows", "rowcount")

    def __init__(self, rows: list, rowcount: int) -> None:
        self._rows, self.rowcount = rows, rowcount

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list:
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


class _ThreadSafeConnection:
    """Bọc sqlite3.Connection bằng một khoá.

    Store mở connection với `check_same_thread=False` và được dùng từ nhiều
    luồng cùng lúc: event loop của agent, các `asyncio.to_thread(...)` (snapshot
    endpoint, backup DB, stop_process) và luồng callback của scapy AsyncSniffer.
    sqlite3.Connection KHÔNG an toàn khi nhiều luồng dùng chung mà không đồng
    bộ — biểu hiện thực tế là agent chết lúc khởi động với
    `sqlite3.OperationalError: cannot commit - no transaction is active` (luồng
    khác đã commit mất transaction ngầm mà luồng này vừa mở), hoặc
    `InterfaceError: bad parameter or other API misuse`.

    RLock chứ không phải Lock: một vài phương thức của Store gọi lẫn nhau
    (ví dụ set_collector_health -> đọc trạng thái cũ rồi ghi) trong cùng luồng.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.RLock()

    def __enter__(self) -> "_ThreadSafeConnection":
        # `with store.conn:` là transaction của sqlite3. Giữ khoá suốt cả khối
        # để transaction đó không bị luồng khác commit chen ngang.
        self._lock.acquire()
        try:
            self._conn.__enter__()
        except BaseException:
            self._lock.release()
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            return self._conn.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()

    def execute(self, sql: str, params=()) -> _Result:
        with self._lock:
            cursor = self._conn.execute(sql, params)
            return _Result(cursor.fetchall(), cursor.rowcount)

    def executemany(self, sql: str, params) -> _Result:
        with self._lock:
            cursor = self._conn.executemany(sql, params)
            return _Result(cursor.fetchall(), cursor.rowcount)

    def executescript(self, script: str) -> None:
        with self._lock:
            self._conn.executescript(script)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def backup(self, target: sqlite3.Connection) -> None:
        with self._lock:
            self._conn.backup(target)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class Store:
    def __init__(self, path: Path | None = None, *, recover_corrupt: bool = False,
                 # Mac dinh KHONG migrate: chi agent duoc doi schema, va mot mac
                 # dinh "duoc phep" nghia la moi cho goi moi tu dong co quyen do.
                 allow_migration: bool = False) -> None:
        """`recover_corrupt=True` là chế độ của agent nền (mục B3 kế hoạch 1.1).

        Mặc định vẫn là TỪ CHỐI mở DB hỏng và giữ nguyên file — công cụ dòng
        lệnh, UI hay script điều tra không được phép tự ý dịch chuyển database
        của người dùng. Chỉ agent — thứ buộc phải sống sót, nếu không sẽ
        crash-loop và máy mất hẳn giám sát — mới bật cờ này.
        """
        self.path = path or default_db_path()
        self._audit_key = os.environ.get("SHIELD_AUDIT_HMAC_KEY", "").encode()
        self._health_touch: dict[str, float] = {}
        self.recovery: dict | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists() and self.path.stat().st_size > 0
        self.conn = _ThreadSafeConnection(sqlite3.connect(self.path, check_same_thread=False))
        if existed:
            ok, message = self.check_integrity(quick=True)
            if not ok:
                self.conn.close()
                if not recover_corrupt:
                    raise DatabaseIntegrityError(
                        f"database integrity check failed; original preserved at {self.path}: {message}"
                    )
                self.recovery = self._recover_corrupt_database(message)
                self.conn = _ThreadSafeConnection(
                    sqlite3.connect(self.path, check_same_thread=False)
                )
                existed = False
        self.conn.execute("PRAGMA foreign_keys=ON;")
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self.conn.execute("PRAGMA journal_mode=WAL;")
        if not existed:
            # CHỈ đặt được trên database còn rỗng: đổi auto_vacuum trên database
            # đã có dữ liệu đòi một lượt VACUUM viết lại toàn bộ file. Với bản
            # cài mới thì từ đây DELETE trả lại đĩa thật; với database cũ,
            # `_enforce_size_cap` đo dung lượng LOGIC nên vẫn chặn được đà lớn.
            self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL;")
        previous_version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        self.schema_outdated = bool(existed and previous_version < SCHEMA_VERSION)
        if existed and not allow_migration:
            # CHỈ agent được đổi schema của một database đã có. Mọi tiến trình
            # khác — giao diện, guardian, công cụ dòng lệnh — chỉ được dùng
            # schema đang có sẵn.
            #
            # Hai tiến trình cùng migrate một database nghĩa là hai lần sao lưu
            # 204 MB và hai lượt đổi schema chồng lên nhau. Guardian đã sập vì
            # đúng chuyện này khi lên 1.1; giao diện sập vì đúng chuyện này khi
            # lên 2.0 (`sqlite3.OperationalError: database is locked` ngay lúc
            # mở app, trong khi agent đang migrate v4 -> v5).
            #
            # Điều kiện là `existed`, không phải `not allow_migration` một
            # mình: một database CHƯA tồn tại thì không có ai để đua, và trả về
            # sớm ở đó sẽ để lại một file rỗng không có bảng nào.
            return
        if existed and previous_version < SCHEMA_VERSION:
            self.backup_database(
                self.path.parent / "backups" /
                f"shield-pre-migration-v{previous_version}-{int(time.time())}.db"
            )
        self.conn.executescript(SCHEMA)
        self._migrate_schema()
        self.conn.executescript(SCHEMA_INDEXES)
        self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.conn.commit()
        self._backfill_device_identities()
        self._fix_group_permissions()
        if self.recovery:
            self.set_baseline("recovered_from_corruption_ts", str(self.recovery["ts"]))
            self.set_baseline("recovered_from_corruption_detail", json.dumps(self.recovery))

    @staticmethod
    def _row_total(conn: sqlite3.Connection) -> int:
        """Tổng số dòng mọi bảng — thước đo thô để so bản nào giữ được nhiều hơn."""
        total = 0
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall():
            quoted = '"' + name.replace('"', '""') + '"'
            try:
                total += conn.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0]
            except sqlite3.DatabaseError:
                continue
        return total

    def _restore_from_backup(self, rescued: int, quarantined: Path) -> Path | None:
        """Lấy bản sao lưu mới nhất còn lành lặn nếu nó giữ được nhiều hơn.

        Duyệt từ mới tới cũ và kiểm tra integrity từng bản: một bản sao lưu
        chép từ DB đã hỏng sẵn thì phục hồi vào chỉ đổi kiểu hỏng, không sửa
        được gì.

        Phần đã cứu được KHÔNG bị vứt — nó được giữ cạnh bản hỏng dưới đuôi
        `.salvaged.<ts>`, vì nó chứa những dòng mới hơn bản sao lưu.
        """
        backups = self.path.parent / "backups"
        if not backups.is_dir():
            return None
        candidates = sorted(
            (item for item in backups.glob("*.db") if item.is_file() and not item.is_symlink()),
            key=lambda item: item.stat().st_mtime, reverse=True,
        )
        for candidate in candidates:
            try:
                probe = sqlite3.connect(f"file:{candidate}?mode=ro", uri=True)
                probe.text_factory = lambda raw: raw.decode("utf-8", "replace")
                try:
                    if probe.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        continue
                    if self._row_total(probe) <= rescued:
                        # Bản cứu được đã bằng hoặc hơn — không lùi về bản cũ.
                        return None
                    salvaged_copy = Path(str(quarantined) + ".salvaged")
                    try:
                        os.replace(self.path, salvaged_copy)
                    except OSError:
                        pass
                    target = sqlite3.connect(self.path)
                    try:
                        probe.backup(target)
                    finally:
                        target.close()
                finally:
                    probe.close()
            except (sqlite3.DatabaseError, UnicodeDecodeError, ValueError):
                continue
            return candidate
        return None

    @staticmethod
    def _salvage_schema(source: sqlite3.Connection, fresh: sqlite3.Connection) -> list[str]:
        """Dựng lại bảng/index đọc được từ sqlite_master, trả về tên các bảng."""
        tables: list[str] = []
        rows = source.execute(
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL"
        ).fetchall()
        for kind, name, sql in rows:
            if name.startswith("sqlite_"):
                continue
            try:
                fresh.execute(sql)
            except sqlite3.DatabaseError:
                continue
            if kind == "table":
                tables.append(name)
        fresh.commit()
        return tables

    @staticmethod
    def _salvage_bounds(
        source: sqlite3.Connection, table: str, quoted: str
    ) -> tuple[int, int] | None:
        """Biên rowid của một bảng, KHÔNG được quét toàn bảng để lấy.

        `SELECT min(rowid), max(rowid)` quét hết b-tree nên chỉ cần một trang
        hỏng là cả câu đổ — và khi đó ta lại tưởng bảng không có rowid rồi bỏ
        qua, dù các dải rowid khác vẫn đọc được bình thường. Đó là lý do một
        lần thử phục hồi cứu đúng 2 dòng trên 5000.
        """
        try:
            bounds = source.execute(
                f"SELECT min(rowid), max(rowid) FROM {quoted}"
            ).fetchone()
            if bounds and bounds[0] is not None:
                return int(bounds[0]), int(bounds[1])
            return None
        except sqlite3.DatabaseError:
            pass
        # Bảng AUTOINCREMENT ghi rowid lớn nhất vào sqlite_sequence — một dòng,
        # không phải quét bảng.
        try:
            row = source.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = ?", (table,)
            ).fetchone()
            if row and row[0] is not None:
                return 1, int(row[0])
        except sqlite3.DatabaseError:
            pass
        # Cuối cùng: dò biên trên bằng cách nhân đôi. Lỗi đọc KHÔNG được coi là
        # "hết dữ liệu" — trang hỏng nằm giữa hai dải còn tốt là chuyện thường.
        high, empty_streak = 4096, 0
        for _ in range(40):
            try:
                found = source.execute(
                    f"SELECT 1 FROM {quoted} WHERE rowid BETWEEN ? AND ? LIMIT 1",
                    (high // 2 + 1, high),
                ).fetchone()
                empty_streak = 0 if found else empty_streak + 1
            except sqlite3.DatabaseError:
                empty_streak = 0
            if empty_streak >= 3:
                return 1, high
            high *= 2
        return 1, high

    @staticmethod
    def _salvage_table(
        source: sqlite3.Connection, fresh: sqlite3.Connection, table: str,
        chunk: int = 2000,
    ) -> tuple[int, int]:
        """Chép một bảng, bỏ qua đúng những dòng nằm trên trang hỏng.

        Trả về (số dòng cứu được, số dòng mất). Tên bảng lấy từ sqlite_master
        của chính file này nên không phải dữ liệu người ngoài đưa vào; vẫn bọc
        trong dấu nháy kép để tên có ký tự lạ không làm hỏng câu lệnh.
        """
        quoted = '"' + table.replace('"', '""') + '"'
        try:
            columns = [row[1] for row in source.execute(f"PRAGMA table_info({quoted})")]
        except sqlite3.DatabaseError:
            return 0, 0
        if not columns:
            return 0, 0
        placeholders = ", ".join("?" for _ in columns)
        insert = f"INSERT OR IGNORE INTO {quoted} VALUES ({placeholders})"
        bounds = Store._salvage_bounds(source, table, quoted)
        if bounds is None:
            # Bảng WITHOUT ROWID hoặc không đọc nổi biên: thử đọc cả bảng một lần.
            try:
                rows = source.execute(f"SELECT * FROM {quoted}").fetchall()
            except sqlite3.DatabaseError:
                return 0, 0
            fresh.executemany(insert, rows)
            fresh.commit()
            return len(rows), 0

        rescued = lost = 0
        pending = [bounds]
        while pending:
            low, high = pending.pop()
            if high - low + 1 > chunk:
                middle = (low + high) // 2
                pending.append((middle + 1, high))
                pending.append((low, middle))
                continue
            try:
                rows = source.execute(
                    f"SELECT * FROM {quoted} WHERE rowid BETWEEN ? AND ?", (low, high)
                ).fetchall()
            except sqlite3.DatabaseError:
                if low == high:
                    lost += 1          # đúng một dòng nằm trên trang hỏng
                else:
                    middle = (low + high) // 2
                    pending.append((middle + 1, high))
                    pending.append((low, middle))
                continue
            try:
                fresh.executemany(insert, rows)
                # Commit theo từng khối: nếu bước sau chết, phần đã cứu vẫn còn.
                fresh.commit()
                rescued += len(rows)
                # Cứu một DB lớn mất hàng chục giây, trong khi WatchdogSec=90.
                # Không ping ở đây thì systemd giết agent GIỮA LÚC đang cứu dữ
                # liệu. No-op khi không chạy dưới systemd.
                sdnotify.notify("WATCHDOG=1")
            except sqlite3.DatabaseError:
                lost += len(rows)
        return rescued, lost

    def _migrate_schema(self) -> None:
        """Small additive migrations for databases created by older Shield versions."""
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(alerts)")}
        for name, ddl in (
            ("risk_score", "INTEGER NOT NULL DEFAULT 0"),
            ("confidence", "REAL NOT NULL DEFAULT 0.5"),
            # Tên mới cho cùng con số. Additive: cột cũ ở lại và vẫn được ghi,
            # nên hạ cấp về bản trước vẫn đọc đúng. Sẽ bỏ khi không còn bản nào
            # đọc tên cũ.
            ("evidence_strength", "REAL NOT NULL DEFAULT 0.5"),
            ("policy_action", "TEXT NOT NULL DEFAULT 'alert'"),
            ("first_seen", "REAL NOT NULL DEFAULT 0"),
            ("last_seen", "REAL NOT NULL DEFAULT 0"),
            ("sources", "TEXT NOT NULL DEFAULT '[]'"),
        ):
            if name not in columns:
                self.conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {ddl}")
        # Schema v4 (kế hoạch 1.1 mục A3): log có thể đến từ máy khác.
        event_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(events)")}
        for name, ddl in (
            ("origin", "TEXT NOT NULL DEFAULT 'local'"),
            ("trust", "TEXT NOT NULL DEFAULT 'authenticated'"),
            # Schema v5 (kế hoạch 2.0 mục 1.1). Tất cả đều additive và có mặc
            # định, nên 892 nghìn dòng sẵn có không phải viết lại — chỉ thêm cột.
            # `event_id` để rỗng trên dòng cũ: bịa ID cho dữ liệu lịch sử sẽ tạo
            # ra những tham chiếu trông hợp lệ mà không truy ngược được về đâu.
            ("event_id", "TEXT NOT NULL DEFAULT ''"),
            ("ts_ingested", "REAL NOT NULL DEFAULT 0"),
            ("content_hash", "TEXT NOT NULL DEFAULT ''"),
            ("signature_status", "TEXT NOT NULL DEFAULT 'unsigned'"),
            ("collector_version", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in event_columns:
                self.conn.execute(f"ALTER TABLE events ADD COLUMN {name} {ddl}")
        # Dữ liệu cũ: chép sang tên mới đúng MỘT lần. Không ghi đè dòng đã có
        # giá trị — chạy migration hai lần không được làm hỏng gì.
        self.conn.execute(
            "UPDATE alerts SET evidence_strength=confidence "
            "WHERE evidence_strength=0.5 AND confidence<>0.5")
        self.conn.execute("UPDATE alerts SET first_seen=ts WHERE first_seen=0")
        self.conn.execute("UPDATE alerts SET last_seen=ts WHERE last_seen=0")
        # Cùng cách xử lý như `alerts.confidence`: thêm tên mới, giữ tên cũ làm
        # gương cho bản trước, chép dữ liệu cũ sang đúng một lần.
        incident_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(incidents)")}
        if "evidence_strength" not in incident_columns:
            self.conn.execute(
                "ALTER TABLE incidents ADD COLUMN evidence_strength REAL NOT NULL DEFAULT 0.5")
            self.conn.execute(
                "UPDATE incidents SET evidence_strength=confidence WHERE confidence<>0.5")

        # v10: tham chiếu alert chính danh + lý do gộp có cấu trúc + liên kết
        # sang evidence/asset. Toàn bộ là CỘNG THÊM: không cột nào bị xoá, không
        # khoá chính nào đổi, không dòng cũ nào bị viết lại. Một database v9 mở
        # bằng bản này đọc được nguyên vẹn; các cột mới nhận giá trị mặc định.
        #
        # Cố tình KHÔNG suy ngược `alert_id` cho dòng cũ: tra theo (rule_id, ts)
        # là đúng cái phỏng đoán mà cột này sinh ra để thay thế. Bịa tham chiếu
        # cho dữ liệu lịch sử còn tệ hơn để trống, vì để trống thì nhìn ra được.
        incident_alert_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(incident_alerts)")}
        if "alert_id" not in incident_alert_columns:
            self.conn.execute(
                "ALTER TABLE incident_alerts ADD COLUMN alert_id INTEGER NOT NULL DEFAULT 0")

        health_columns = {row[1] for row in self.conn.execute("PRAGMA table_info(collector_health)")}
        for name, ddl in (
            ("state", "TEXT NOT NULL DEFAULT 'running'"),
            ("started_ts", "REAL NOT NULL DEFAULT 0"),
            ("last_heartbeat", "REAL NOT NULL DEFAULT 0"),
            ("last_event", "REAL NOT NULL DEFAULT 0"),
            ("restart_count", "INTEGER NOT NULL DEFAULT 0"),
            ("dropped_events", "INTEGER NOT NULL DEFAULT 0"),
            ("error_message", "TEXT NOT NULL DEFAULT ''"),
        ):
            if name not in health_columns:
                self.conn.execute(f"ALTER TABLE collector_health ADD COLUMN {name} {ddl}")
        # Ba giai đoạn của một lượt điều tra AI (Phase 3A). Additive: DB cũ
        # chỉ có bản đã kiểm, và ba cột này rỗng cho tới lượt điều tra kế tiếp.
        tool_call_columns = {row[1] for row in self.conn.execute(
            "PRAGMA table_info(ai_tool_calls)")}
        if tool_call_columns:
            for name, ddl in (
                ("round_index", "INTEGER NOT NULL DEFAULT -1"),
                ("executed", "INTEGER NOT NULL DEFAULT 1"),
                ("outcome", "TEXT NOT NULL DEFAULT ''"),
            ):
                if name not in tool_call_columns:
                    self.conn.execute(
                        f"ALTER TABLE ai_tool_calls ADD COLUMN {name} {ddl}")
        investigation_columns = {row[1] for row in self.conn.execute(
            "PRAGMA table_info(investigations)")}
        if investigation_columns:
            for name, ddl in (
                ("original_summary", "TEXT NOT NULL DEFAULT ''"),
                ("final_summary", "TEXT NOT NULL DEFAULT ''"),
                ("output_metrics", "TEXT NOT NULL DEFAULT '{}'"),
            ):
                if name not in investigation_columns:
                    self.conn.execute(
                        f"ALTER TABLE investigations ADD COLUMN {name} {ddl}")
        self.conn.execute(
            "INSERT OR IGNORE INTO baseline(key,value,set_ts) VALUES('config_schema_version',?,?)",
            (str(CONFIG_SCHEMA_VERSION), time.time()),
        )
        self.conn.commit()

    def _backfill_device_identities(self) -> None:
        """Give devices discovered by pre-1.0 releases an explainable identity/profile."""
        rows = self.conn.execute(
            "SELECT d.mac,d.ip,d.vendor,d.hostname,d.first_seen,d.last_seen FROM devices d "
            "LEFT JOIN device_links l ON l.mac=d.mac WHERE l.mac IS NULL"
        ).fetchall()
        for mac, ip, vendor, hostname, first_seen, last_seen in rows:
            # Mốc thời gian THẬT của thiết bị, không phải lúc chạy backfill.
            self.observe_device_identity(mac, ip, vendor, hostname, {},
                                         first_seen=first_seen, last_seen=last_seen)
        self._repair_backfilled_timestamps()

    def _repair_backfilled_timestamps(self) -> None:
        """Sửa lại mốc thời gian đã bị các bản trước đóng dấu sai.

        Bản trước gán `time.time()` cho mọi thiết bị được dựng lại danh tính,
        nên máy tắt từ tuần trước hiện lên như đang online. Chỉ sửa những dòng
        có dấu hiệu rõ ràng của lượt dựng lại đó: quan sát đúng một lần, first
        và last bằng nhau, mà bảng `devices` lại ghi một mốc cũ hơn hẳn.
        """
        self.conn.execute(
            "UPDATE device_observations AS o SET "
            "  first_seen=(SELECT d.first_seen FROM devices d WHERE d.mac=o.mac), "
            "  last_seen =(SELECT d.last_seen  FROM devices d WHERE d.mac=o.mac) "
            # `first_seen=last_seen` so bằng số thực thì quá mong manh: chỉ cần
            # hai lời gọi time.time() lệch một phần triệu giây là trượt. Điều
            # kiện thật cần diễn đạt là "cả hai được đóng dấu cùng một khoảnh
            # khắc", nên so trong vòng một giây.
            "WHERE o.observation_count<=1 AND o.last_seen - o.first_seen < 1 "
            "  AND EXISTS (SELECT 1 FROM devices d WHERE d.mac=o.mac "
            "              AND d.last_seen < o.last_seen - 300)"
        )
        self.conn.commit()

    def _recover_corrupt_database(self, reason: str) -> dict:
        """Dời DB hỏng sang một bên, cứu được gì thì cứu, rồi chạy tiếp.

        Ba ràng buộc, theo đúng thứ tự quan trọng:

        1. KHÔNG BAO GIỜ xoá file hỏng. Nó là bằng chứng — có thể chính việc
           hỏng mới là dấu vết của cuộc tấn công. Đổi tên, không unlink.
        2. Agent phải chạy tiếp. Một Shield chết vì DB hỏng nghĩa là máy mất
           giám sát hoàn toàn, tệ hơn nhiều so với mất vài ngày lịch sử.
        3. Việc phục hồi phải nhìn thấy được, không được im lặng. Mốc thời
           gian ghi vào `baseline`, và agent phát alert từ đó.
        """
        ts = time.time()
        quarantined = self.path.with_suffix(self.path.suffix + f".corrupt.{int(ts)}")
        self.path.rename(quarantined)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            if sidecar.exists():
                sidecar.rename(Path(str(quarantined) + suffix))

        # Cứu dữ liệu theo từng bảng, chia khối theo rowid.
        #
        # Bản trước dùng iterdump() và mất TRẮNG dữ liệu: iterdump là generator,
        # khi chạm trang hỏng thì lỗi bật ra từ chính vòng lặp chứ không phải từ
        # câu execute, nên try/except bên trong không đỡ được — generator chết
        # hẳn, không nối lại được. Tệ hơn, lỗi nhảy qua commit() nên mọi thứ đã
        # ghi bị rollback sạch, trong khi bộ đếm vẫn báo "cứu được N".
        #
        # Hỏng do đĩa thường khu trú ở vài trang. Chia khối rồi chia đôi khối
        # lỗi cho phép bỏ đúng phần hỏng và giữ lại phần còn lại.
        rescued, failed = 0, 0
        fresh = sqlite3.connect(self.path)
        try:
            source = sqlite3.connect(f"file:{quarantined}?mode=ro", uri=True)
            # Đọc text CHỊU ĐƯỢC byte hỏng. Mặc định sqlite3 giải mã UTF-8
            # nghiêm ngặt và ném UnicodeDecodeError — một lỗi KHÔNG phải
            # DatabaseError, nên nó thoát khỏi mọi except ở đây và giết cả lượt
            # phục hồi. Nghĩa là: database hỏng đúng kiểu hay gặp nhất (byte
            # rác trong vùng text) là database duy nhất không cứu được.
            source.text_factory = lambda raw: raw.decode("utf-8", "replace")
            try:
                tables = self._salvage_schema(source, fresh)
                for table in tables:
                    got, lost = self._salvage_table(source, fresh, table)
                    rescued += got
                    failed += lost
            finally:
                source.close()
        except (sqlite3.DatabaseError, UnicodeDecodeError, ValueError):
            # File hỏng tới mức không đọc nổi cả sqlite_master.
            failed += 1
        finally:
            try:
                fresh.commit()
            except sqlite3.DatabaseError:
                pass
            fresh.close()

        # Dùng bản sao lưu khi nó chứa NHIỀU hơn số dòng cứu được. Hai trường
        # hợp thường gặp: hỏng trúng trang schema (SQLite không đọc nổi
        # sqlite_master thì không prepare được câu lệnh nào — đường SQL hết
        # cách), và hỏng nát b-tree khiến chỉ còn vài dòng lẻ. Bỏ trắng lịch sử
        # trong khi một bản sao lưu lành lặn nằm ngay thư mục bên cạnh là điều
        # không có lý do gì để xảy ra.
        restored_from = self._restore_from_backup(rescued, quarantined)

        os.chmod(self.path, 0o660)
        return {
            "ts": ts,
            "reason": reason,
            "quarantined_path": str(quarantined),
            "rows_recovered": rescued,
            "rows_lost": failed,
            "restored_from_backup": str(restored_from) if restored_from else None,
        }

    def check_integrity(self, *, quick: bool = False) -> tuple[bool, str]:
        """Database này còn đọc được không. KHÔNG BAO GIỜ ném ra ngoài.

        `UnicodeDecodeError` nằm trong danh sách bắt vì một lý do rất cụ thể:
        một database hỏng có thể làm SQLite trả về byte rác trong chính kết quả
        của PRAGMA, và sqlite3 cố giải mã chúng thành UTF-8. Lỗi đó KHÔNG phải
        `DatabaseError`, nên nó thoát ra ngoài và giết agent ngay ở dòng kiểm
        tra — tức là cơ chế phát hiện hỏng hóc tự sập vì đúng thứ nó sinh ra để
        phát hiện, và đường phục hồi không bao giờ chạy.
        """
        pragma = "quick_check(1)" if quick else "integrity_check"
        try:
            rows = [str(row[0]) for row in self.conn.execute(f"PRAGMA {pragma}").fetchall()]
        except sqlite3.DatabaseError as exc:
            return False, str(exc)
        except (UnicodeDecodeError, ValueError) as exc:
            return False, f"kết quả kiểm tra không đọc được (database hỏng nặng): {exc}"
        ok = rows == ["ok"]
        return ok, "ok" if ok else "; ".join(rows[:10])

    def _share_directory_with_group(self, directory: Path) -> None:
        """Cho thư mục này CÙNG nhóm và cùng quyền nhóm với thư mục database.

        `/var/lib/shield` là `drwxrwx--- root:shield` và file database là
        `-rw-rw---- root:shield` — mô hình quyền cố ý cho thành viên nhóm
        `shield` dùng được. Nhưng thư mục `backups/` do một lượt chạy root tạo
        ra với umask mặc định lại thành `drwx------ root:root`, và không có
        chỗ nào sửa lại.

        Hậu quả cụ thể đã xảy ra: một thành viên nhóm `shield` GHI ĐƯỢC
        database nhưng KHÔNG ghi được bản sao lưu của nó, nên mọi lượt nâng
        cấp schema chết ở bước sao lưu với `sqlite3.OperationalError: unable to
        open database file` — một thông báo không nói gì về quyền.

        `chmod` một mình không đủ với thư mục root vừa tạo: nhóm của nó là
        nhóm chính của tiến trình tạo (root), không phải nhóm của thư mục cha.
        Phải đặt lại nhóm trước.

        Chỉ chủ sở hữu (agent chạy root) làm được; tiến trình khác nuốt lỗi và
        đi tiếp, đúng như `_fix_group_permissions`.
        """
        try:
            parent_gid = self.path.parent.stat().st_gid
            if directory.stat().st_gid != parent_gid:
                os.chown(directory, -1, parent_gid)
        except OSError:
            pass
        try:
            # 1770: sticky bit là phần có chủ đích. Mở quyền ghi cho nhóm nghĩa
            # là thành viên nhóm xoá được file của người khác trong thư mục —
            # với thư mục chứa bản sao lưu thì không chấp nhận được. Cùng một
            # mode với `packaging/debian/preinst`, để hai bên không đè lẫn nhau
            # ở mỗi lần cài rồi mỗi lần khởi động.
            os.chmod(directory, 0o1770)
        except OSError:
            pass

    def backup_database(self, destination: Path) -> Path:
        """Create a transactionally consistent backup without replacing history."""
        destination = destination.expanduser().absolute()
        if destination.is_symlink():
            raise ValueError("backup destination must not be a symlink")
        destination = destination.parent.resolve() / destination.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._share_directory_with_group(destination.parent)
        # Hỏi TRƯỚC khi mở, để lỗi nói ra chuyện gì đã xảy ra. `sqlite3.connect`
        # vào một thư mục không ghi được chỉ trả về "unable to open database
        # file", và người đọc sẽ đi tìm database hỏng thay vì đi xem quyền.
        #
        # Fail closed, KHÔNG đổi sang chỗ khác: sao lưu ở một nơi mà lượt phục
        # hồi sẽ không tìm tới thì tệ hơn không sao lưu, vì nó trông như đã có.
        if not os.access(destination.parent, os.W_OK):
            raise PermissionError(
                f"không ghi được vào thư mục sao lưu {destination.parent}: "
                f"{_describe_path(destination.parent)}. Database đang dùng là "
                f"{self.path} ({_describe_path(self.path)}). "
                "Sao lưu trước khi đổi schema là bắt buộc nên tiến trình dừng ở "
                "đây. Sửa quyền cho đúng mô hình nhóm, ví dụ: "
                f"sudo chgrp shield {destination.parent} && "
                f"sudo chmod 770 {destination.parent}"
            )
        temp = destination.with_suffix(destination.suffix + ".tmp")
        if temp.is_symlink():
            raise ValueError("backup temporary path must not be a symlink")
        if temp.exists():
            temp.unlink()
        backup_conn = sqlite3.connect(temp)
        try:
            self.conn.backup(backup_conn)
        finally:
            backup_conn.close()
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
        return destination

    def database_stats(self) -> dict:
        page_count = int(self.conn.execute("PRAGMA page_count").fetchone()[0])
        page_size = int(self.conn.execute("PRAGMA page_size").fetchone()[0])
        return {
            "schema_version": int(self.conn.execute("PRAGMA user_version").fetchone()[0]),
            "database_bytes": page_count * page_size,
            "wal_bytes": Path(str(self.path) + "-wal").stat().st_size if Path(str(self.path) + "-wal").exists() else 0,
        }

    def _fix_group_permissions(self) -> None:
        """Agent chạy root tạo file DB lần đầu ở /var/lib/shield — mặc định
        chỉ owner (root) ghi được. UI (user thường, cùng group 'shield')
        cũng phải mở được đúng file này: không chỉ để ĐỌC, mà SQLite ở chế
        độ WAL bắt buộc mọi bên — kể cả reader — mở file `-shm` ở chế độ
        đọc/ghi để giữ read-lock (đây là yêu cầu kỹ thuật của SQLite, không
        phải sơ suất). Thiếu bước này, UI kiểm tra os.access(W_OK) thất bại
        và ÂM THẦM chuyển sang dùng 1 file DB khác (rỗng) ở
        ~/.local/share/shield/ — đây chính là bug "UI không thấy thiết bị
        nào dù agent đã quét ra" đã gặp.

        Chỉ agent (root, chủ sở hữu file) chmod thành công; nếu Store() này
        là của UI (không sở hữu file) thì OSError bị nuốt và bỏ qua — không
        cần làm gì vì agent đã lo việc này trước khi UI kịp kết nối."""
        try:
            os.chmod(self.path.parent, 0o770)
        except OSError:
            pass
        # `backups/` cũng thuộc mô hình quyền này. Bỏ sót nó nghĩa là thành
        # viên nhóm `shield` ghi được database mà không ghi được bản sao lưu
        # của nó — và lượt nâng cấp schema chết ở bước sao lưu.
        backups = self.path.parent / "backups"
        if backups.is_dir():
            self._share_directory_with_group(backups)
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.exists():
                try:
                    os.chmod(p, 0o660)
                except OSError:
                    pass

    def insert_event(self, ev: Event) -> None:
        import json

        # origin/trust do collector gắn vào Event.data — collector là nơi DUY
        # NHẤT biết dòng này đến từ đâu; detector phía sau không được sửa. Từ
        # schema v2 chúng cũng là trường của Event; data vẫn được ưu tiên để
        # collector cũ không đổi hành vi.
        origin = str(ev.data.get("origin") or ev.origin or "local")
        trust = "unauthenticated" if ev.data.get("trust") == "unauthenticated" else "authenticated"
        # INSERT OR IGNORE + unique index một phần trên event_id = chống ingest
        # trùng (mục 1.1). Quan trọng với probe: mất kết nối rồi phát lại spool
        # sẽ gửi lại những dòng đã gửi, và không có bước này thì mỗi lần mạng
        # chập là một lần timeline điều tra nhân đôi.
        self.conn.execute(
            "INSERT OR IGNORE INTO events (ts, source, kind, data, origin, trust, "
            "event_id, ts_ingested, content_hash, signature_status, collector_version) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ev.ts, ev.source, ev.kind, json.dumps(ev.data), origin, trust,
             ev.event_id, ev.ts_ingested, ev.content_hash_, ev.signature_status,
             ev.collector_version),
        )
        self.conn.commit()
        self.touch_collector_event(ev.source, ev.ts)

    # --- cấu hình xuất log (do người dùng chọn trong Cài đặt) ---

    LOG_EXPORT_KEY = "log_export_config"

    def get_log_export_config(self) -> dict:
        """Cấu hình đã lưu, hoặc mặc định TẮT.

        Mọi đường hỏng đều trả về "tắt". Cấu hình hỏng mà vẫn cố dùng một nửa
        nghĩa là Shield ghi dữ liệu ra một chỗ không ai chủ ý chọn.
        """
        raw = self.get_baseline(self.LOG_EXPORT_KEY)
        if not raw:
            return {}
        try:
            value = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("Cấu hình xuất log hỏng — coi như tắt")
            return {}
        return value if isinstance(value, dict) else {}

    def set_log_export_config(self, config: dict) -> None:
        self.set_baseline(self.LOG_EXPORT_KEY, json.dumps(config, sort_keys=True))

    def graph_ingest_event(self, ev: Event) -> tuple[int, int]:
        """Ghi bằng chứng rồi dựng node/edge từ một event (mục 1.3).

        Bằng chứng được ghi TRƯỚC cạnh, luôn luôn. `upsert_edge` từ chối mọi
        evidence_ref chưa tồn tại, nên đảo thứ tự sẽ làm mọi cạnh bị từ chối —
        và đó là hành vi đúng: gate Phase 1 cấm orphan evidence reference, nên
        thà không có cạnh còn hơn có một cạnh không truy ngược được.
        """
        from shield.evidence.resolver import resolve

        entities, edges = resolve(ev)
        if not entities and not edges:
            return 0, 0
        # KHÔNG ghi evidence_objects cho event: bảng `events` đã là nguồn sự
        # thật, và `EvidenceGraph._resolves` tra thẳng vào đó. Nhờ vậy khi hạn
        # lưu trữ cắt event, cạnh dựa vào nó thành mồ côi ngay và bị `prune()`
        # gỡ — thay vì sống sót sau khi bằng chứng đã biến mất.
        graph = EvidenceGraph(self.conn)
        with self.conn:
            written = graph.ingest(entities, edges)
        return written

    @property
    def graph(self) -> EvidenceGraph:
        return EvidenceGraph(self.conn)

    def record_probe_health(
        self, probe_id: str, *, display_name: str = "", remote_addr: str = "",
        lines: int = 0, dropped: int = 0, last_event_ts: float = 0.0, error: str = "",
    ) -> None:
        """Sức khoẻ từng probe. Đếm cộng dồn để UI thấy được probe nào im lặng."""
        now_ts = time.time()
        self.conn.execute(
            "INSERT INTO probe_health(probe_id,display_name,remote_addr,last_seen,"
            "last_event_ts,lines_total,lines_dropped,last_error) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(probe_id) DO UPDATE SET "
            "display_name=CASE WHEN excluded.display_name<>'' THEN excluded.display_name ELSE display_name END,"
            "remote_addr=CASE WHEN excluded.remote_addr<>'' THEN excluded.remote_addr ELSE remote_addr END,"
            "last_seen=excluded.last_seen,"
            "last_event_ts=MAX(last_event_ts,excluded.last_event_ts),"
            "lines_total=lines_total+excluded.lines_total,"
            "lines_dropped=lines_dropped+excluded.lines_dropped,"
            "last_error=excluded.last_error",
            (probe_id, display_name, remote_addr, now_ts, last_event_ts, lines, dropped, error),
        )
        self.conn.commit()

    def list_probe_health(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT probe_id,display_name,remote_addr,last_seen,last_event_ts,"
            "lines_total,lines_dropped,last_error FROM probe_health "
            "ORDER BY last_seen DESC LIMIT ?", (int(limit),),
        ).fetchall()
        return [
            {"probe_id": r[0], "display_name": r[1], "remote_addr": r[2], "last_seen": r[3],
             "last_event_ts": r[4], "lines_total": r[5], "lines_dropped": r[6],
             "last_error": r[7], "lag_s": max(0.0, time.time() - r[3]) if r[3] else None}
            for r in rows
        ]

    def recent_events(self, source: str | None = None, limit: int = 100) -> list[dict]:
        """Đọc lại event thô — dùng cho tab Log máy hiện lịch sử lúc mở UI."""
        import json

        if source:
            rows = self.conn.execute(
                "SELECT ts, source, kind, data FROM events WHERE source=? ORDER BY ts DESC LIMIT ?",
                (source, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT ts, source, kind, data FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {"ts": ts, "source": src, "kind": kind, "data": json.loads(data)}
            for ts, src, kind, data in rows
        ]

    def insert_alert(self, alert: Alert, dedupe_window_s: float = 300.0) -> Alert:
        """Chống spam: subject+rule_id trùng trong dedupe_window_s chỉ tăng count."""
        import json

        source = str(alert.evidence.get("source") or alert.evidence.get("collector") or "unknown")
        row = self.conn.execute(
            "SELECT id, count, sources FROM alerts WHERE subject=? AND rule_id=? AND ts > ? "
            "ORDER BY ts DESC LIMIT 1",
            (alert.subject, alert.rule_id, alert.ts - dedupe_window_s),
        ).fetchone()
        if row:
            alert_id, count, sources_raw = row
            try:
                sources = set(json.loads(sources_raw))
            except (TypeError, ValueError):
                sources = set()
            sources.add(source)
            self.conn.execute(
                # Ghi CẢ HAI cột cùng một giá trị: cột cũ là gương để bản
                # trước đọc được, không phải một con số độc lập có thể lệch.
                "UPDATE alerts SET count=?,ts=?,last_seen=?,sources=?,evidence=?,"
                "risk_score=MAX(risk_score,?),confidence=MAX(confidence,?),"
                "evidence_strength=MAX(evidence_strength,?) WHERE id=?",
                (count + 1, alert.ts, alert.ts, json.dumps(sorted(sources)),
                 json.dumps(alert.evidence), alert.risk_score,
                 alert.evidence_strength, alert.evidence_strength, alert_id),
            )
            self.conn.commit()
            # Mang theo khoá chính của dòng đã có. Không có bước này thì bên
            # gọi không có cách nào trỏ tới alert vừa gộp ngoài phỏng đoán.
            return dataclasses.replace(alert, alert_id=int(alert_id))

        self.conn.execute(
            "INSERT INTO alerts (ts, rule_id, severity, title, detail, subject, evidence, playbook, "
            "risk_score,confidence,evidence_strength,policy_action,first_seen,last_seen,sources) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.ts,
                alert.rule_id,
                alert.severity,
                alert.title,
                alert.detail,
                alert.subject,
                json.dumps(alert.evidence),
                json.dumps(alert.playbook),
                alert.risk_score,
                alert.evidence_strength,
                alert.evidence_strength,
                alert.policy_action,
                alert.ts,
                alert.ts,
                json.dumps([source]),
            ),
        )
        # `last_insert_rowid()` thay cho `cursor.lastrowid`: kết nối ở đây đi qua
        # một lớp bọc không có thuộc tính đó, và nó chạy trên cùng kết nối nên
        # vẫn là dòng vừa chèn.
        row_id = int(self.conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        self.conn.commit()
        return dataclasses.replace(alert, alert_id=row_id)

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        import json

        rows = self.conn.execute(
            "SELECT ts, rule_id, severity, title, detail, subject, evidence, playbook, count, "
            "risk_score,confidence,policy_action,first_seen,last_seen,sources "
            "FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        out = []
        for ts, rule_id, severity, title, detail, subject, evidence, playbook, count, risk_score, confidence, policy_action, first_seen, last_seen, sources in rows:
            out.append(
                {
                    "ts": ts,
                    "rule_id": rule_id,
                    "severity": severity,
                    "title": title,
                    "detail": detail,
                    "subject": subject,
                    "evidence": json.loads(evidence),
                    "playbook": json.loads(playbook),
                    "count": count,
                    "risk_score": risk_score,
                    "confidence": confidence,
                    "policy_action": policy_action,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "source_count": len(json.loads(sources or "[]")),
                }
            )
        return out

    # --- Thiết bị (giai đoạn 1, xem KE-HOACH-SHIELD.md mục 2.2) ---

    def upsert_device(
        self, mac: str, ip: str | None, vendor_hint: str | None = None,
        observation: dict | None = None,
    ) -> tuple[bool, str | None]:
        """Ghi nhận một MAC vừa thấy. Trả về (is_new, vendor)."""
        from shield.agent.oui import lookup_vendor

        ts = time.time()
        mac = mac.lower()
        observation = dict(observation or {})
        hostname = str(observation.get("hostname") or "")[:255] or None
        row = self.conn.execute("SELECT vendor FROM devices WHERE mac=?", (mac,)).fetchone()
        vendor = lookup_vendor(mac) or vendor_hint

        if row is not None:
            self.conn.execute(
                "UPDATE devices SET ip=?,last_seen=?,vendor=COALESCE(vendor,?),"
                "hostname=COALESCE(?,hostname) WHERE mac=?",
                (ip, ts, vendor, hostname, mac),
            )
            self.conn.commit()
            self.observe_device_identity(mac, ip, row[0] or vendor, hostname, observation)
            return False, row[0] or vendor

        self.conn.execute(
            "INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (mac, ip, vendor, hostname, ts, ts),
        )
        self.conn.commit()
        self.observe_device_identity(mac, ip, vendor, hostname, observation)
        return True, vendor

    def touch_device(self, mac: str, ip: str | None) -> None:
        """Cập nhật last_seen cho thiết bị đã biết (không sinh alert) — dùng cho MAC tin cậy."""
        ts = time.time()
        cur = self.conn.execute(
            "UPDATE devices SET ip=COALESCE(?, ip), last_seen=? WHERE mac=?", (ip, ts, mac)
        )
        if cur.rowcount == 0:
            self.conn.execute(
                "INSERT INTO devices (mac, ip, vendor, hostname, first_seen, last_seen) "
                "VALUES (?, ?, NULL, NULL, ?, ?)",
                (mac, ip, ts, ts),
            )
        self.conn.commit()
        self.observe_device_identity(mac, ip, None, None, {})

    def _new_device_id(self) -> str:
        while True:
            device_id = f"DEVICE-{secrets.token_hex(4).upper()}"
            if not self.conn.execute(
                "SELECT 1 FROM device_identities WHERE device_id=?", (device_id,)
            ).fetchone():
                return device_id

    def observe_device_identity(
        self, mac: str, ip: str | None, vendor: str | None,
        hostname: str | None, signals: dict,
        first_seen: float | None = None, last_seen: float | None = None,
    ) -> str:
        """Link one stable MAC observation; never auto-merges different MACs.

        `first_seen`/`last_seen` phải truyền vào khi dựng lại danh tính cho dữ
        liệu CŨ. Đóng dấu `time.time()` cho một thiết bị thấy lần cuối tám ngày
        trước sẽ biến nó thành "vừa thấy ngay bây giờ" — và với công cụ điều
        tra thì "thấy lần đầu / lần cuối" chính là dữ kiện người ta dựa vào.
        """
        mac = mac.lower()
        ts = time.time()
        observed_first = float(first_seen) if first_seen else ts
        observed_last = float(last_seen) if last_seen else ts
        row = self.conn.execute("SELECT device_id FROM device_links WHERE mac=?", (mac,)).fetchone()
        if row:
            device_id = row[0]
        else:
            device_id = self._new_device_id()
            display_name = (hostname or vendor or device_id)[:120]
            with self.conn:
                self.conn.execute(
                    "INSERT INTO device_identities(device_id,display_name,created_ts,updated_ts) VALUES(?,?,?,?)",
                    (device_id, display_name, ts, ts),
                )
                self.conn.execute(
                    "INSERT INTO device_links(mac,device_id,confidence,reason,user_confirmed) VALUES(?,?,?,?,0)",
                    (mac, device_id, 1.0, "stable MAC observation"),
                )
        with self.conn:
            self.conn.execute(
                "INSERT INTO device_observations(device_id,mac,ip,hostname,vendor,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id,mac,ip,hostname) DO UPDATE SET "
                # max(): last_seen không bao giờ được lùi lại. Một lượt dựng
                # lại danh tính chạy sau đó không được xoá mất lần thấy mới hơn.
                "last_seen=max(last_seen,excluded.last_seen),"
                "first_seen=min(first_seen,excluded.first_seen),"
                "observation_count=observation_count+1,"
                "vendor=CASE WHEN excluded.vendor<>'' THEN excluded.vendor ELSE vendor END",
                (device_id, mac, ip or "", hostname or "", vendor or "",
                 observed_first, observed_last),
            )
            self.conn.execute("UPDATE device_identities SET updated_ts=? WHERE device_id=?", (ts, device_id))
        merged_signals = self._device_profile_signals(device_id)
        merged_signals.update({key: value for key, value in signals.items() if value not in (None, "", [])})
        try:
            merged_signals["randomized_mac"] = bool(int(mac.split(":")[0], 16) & 2)
        except (ValueError, IndexError):
            merged_signals["randomized_mac"] = False
        merged_signals.update({"vendor": vendor or merged_signals.get("vendor", ""),
                               "hostname": hostname or merged_signals.get("hostname", "")})
        self._save_inferred_profile(device_id, merged_signals)
        return device_id

    def _device_profile_signals(self, device_id: str) -> dict:
        row = self.conn.execute("SELECT signals FROM device_profiles WHERE device_id=?", (device_id,)).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row[0])
        except (TypeError, ValueError):
            return {}

    def _save_inferred_profile(self, device_id: str, signals: dict) -> dict:
        from shield.security.device_intelligence import infer_device_profile

        profile = infer_device_profile(signals).to_dict()
        self.conn.execute(
            "INSERT INTO device_profiles(device_id,device_type,label,confidence,evidence,signals,updated_ts) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET "
            "device_type=excluded.device_type,label=excluded.label,confidence=excluded.confidence,"
            "evidence=excluded.evidence,signals=excluded.signals,updated_ts=excluded.updated_ts",
            (device_id, profile["device_type"], profile["label"], profile["confidence"],
             json.dumps(profile["evidence"], ensure_ascii=False),
             json.dumps(signals, ensure_ascii=False, sort_keys=True), time.time()),
        )
        self.conn.commit()
        return profile

    def update_device_service_signals(self, ip: str, ports: list[dict]) -> None:
        row = self.conn.execute(
            "SELECT l.device_id FROM devices d JOIN device_links l ON l.mac=d.mac WHERE d.ip=? "
            "ORDER BY d.last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        if not row:
            return
        device_id = row[0]
        signals = self._device_profile_signals(device_id)
        signals["open_ports"] = sorted({int(item["port"]) for item in ports if "port" in item})
        signals["services"] = sorted({str(item.get("service", "")) for item in ports if item.get("service")})
        self._save_inferred_profile(device_id, signals)

    def reset_scan_session(self, older_than_days: float | None = None) -> dict:
        """Quên các thiết bị đã phát hiện và quét lại từ đầu.

        Vì sao cần: danh sách thiết bị chỉ tích thêm, không bao giờ tự bớt. Máy
        này đang có 101 thiết bị trong khi 9 cái online — phần còn lại là mạng
        cũ, khách vãng lai, và MAC ngẫu nhiên của điện thoại người qua đường.
        Một danh sách như vậy làm chính nó vô dụng: không ai soi 101 dòng để
        tìm cái lạ.

        Hai ranh giới cứng:

        1. **Không đụng vào `events`, `alerts`, `forensic_ledger`.** Đó là bằng
           chứng. Quên một thiết bị nghĩa là quên phần MÔ TẢ nó, không phải xoá
           lịch sử những gì nó đã làm.
        2. **Ghi lại đã quên những gì**, vào audit log. Một thao tác xoá không
           để lại dấu vết là thứ kẻ tấn công sẽ dùng.

        `older_than_days=None` nghĩa là quên tất cả.
        """
        cutoff = time.time() - float(older_than_days) * 86400 if older_than_days else None
        if cutoff is None:
            macs = [row[0] for row in self.conn.execute("SELECT mac FROM devices")]
        else:
            macs = [row[0] for row in self.conn.execute(
                "SELECT mac FROM devices WHERE last_seen < ?", (cutoff,))]
        if not macs:
            return {"devices_removed": 0, "identities_removed": 0, "macs": []}

        placeholders = ",".join("?" for _ in macs)
        with self.conn:
            device_ids = [row[0] for row in self.conn.execute(
                f"SELECT DISTINCT device_id FROM device_links WHERE mac IN ({placeholders})",
                tuple(macs))]
            self.conn.execute(f"DELETE FROM devices WHERE mac IN ({placeholders})", tuple(macs))
            self.conn.execute(f"DELETE FROM device_links WHERE mac IN ({placeholders})", tuple(macs))
            self.conn.execute(
                f"DELETE FROM device_observations WHERE mac IN ({placeholders})", tuple(macs))
            removed_identities = 0
            for device_id in device_ids:
                # Chỉ xoá danh tính khi nó KHÔNG còn MAC nào — một danh tính
                # gộp nhiều MAC mà mới quên một cái thì phải giữ lại.
                remaining = self.conn.execute(
                    "SELECT count(*) FROM device_links WHERE device_id=?", (device_id,)
                ).fetchone()[0]
                if remaining == 0:
                    # Bảng con TRƯỚC: device_profiles tham chiếu device_identities.
                    self.conn.execute("DELETE FROM device_profiles WHERE device_id=?", (device_id,))
                    self.conn.execute("DELETE FROM device_identities WHERE device_id=?", (device_id,))
                    removed_identities += 1
        self.add_audit_log(
            "reset_scan_session",
            {"older_than_days": older_than_days, "devices_removed": len(macs),
             "identities_removed": removed_identities, "macs": macs[:200]},
            f"quên {len(macs)} thiết bị, quét lại từ đầu",
        )
        return {"devices_removed": len(macs), "identities_removed": removed_identities,
                "macs": macs}

    def device_dossier(self, device_id: str, online_window_s: float = 300.0) -> dict:
        """Mọi thứ đã biết về một thiết bị, gom vào một chỗ.

        Bảng thiết bị trả lời "máy này là gì"; hồ sơ này trả lời những câu hỏi
        người điều tra hỏi tiếp: nó đã dùng những IP nào, đổi MAC bao giờ, mở
        cổng gì, và đã dính vào cảnh báo nào. Trước đây phải tự ghép từ ba tab
        khác nhau mới ra được.
        """
        at = time.time()
        observations = [
            {"mac": row[0], "ip": row[1], "hostname": row[2], "vendor": row[3],
             "first_seen": row[4], "last_seen": row[5], "count": row[6]}
            for row in self.conn.execute(
                "SELECT mac,ip,hostname,vendor,first_seen,last_seen,observation_count "
                "FROM device_observations WHERE device_id=? ORDER BY last_seen DESC",
                (device_id,),
            )
        ]
        last_seen = max((item["last_seen"] for item in observations), default=0.0)
        subjects = {item["mac"] for item in observations}
        subjects |= {item["ip"] for item in observations if item["ip"]}

        alerts = []
        if subjects:
            placeholders = ",".join("?" for _ in subjects)
            alerts = [
                {"ts": row[0], "rule_id": row[1], "severity": row[2], "title": row[3],
                 "subject": row[4], "risk_score": row[5]}
                for row in self.conn.execute(
                    f"SELECT ts,rule_id,severity,title,subject,risk_score FROM alerts "
                    f"WHERE subject IN ({placeholders}) ORDER BY ts DESC LIMIT 20",
                    tuple(subjects),
                )
            ]

        signals = self._device_profile_signals(device_id)
        ports = signals.get("open_ports") or signals.get("ports") or []
        return {
            "device_id": device_id,
            "online": bool(last_seen and at - last_seen <= online_window_s),
            "last_seen": last_seen,
            "seen_ago_s": (at - last_seen) if last_seen else 0.0,
            "observations": observations,
            "ip_addresses": sorted({item["ip"] for item in observations if item["ip"]}),
            "macs": sorted(subjects & {item["mac"] for item in observations}),
            "observation_count": sum(int(item["count"] or 0) for item in observations),
            "open_ports": ports if isinstance(ports, list) else [],
            "alerts": alerts,
            "alert_count": len(alerts),
            "worst_severity": next(
                (level for level in ("critical", "warning", "info")
                 if any(item["severity"] == level for item in alerts)),
                "",
            ),
        }

    def list_device_identities(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT i.device_id,i.display_name,i.owner_label,i.location,i.purpose,i.criticality,"
            "i.created_ts,i.updated_ts,p.device_type,p.label,p.confidence,p.evidence,p.signals "
            "FROM device_identities i LEFT JOIN device_profiles p ON p.device_id=i.device_id "
            "ORDER BY i.updated_ts DESC LIMIT ?", (limit,)
        ).fetchall()
        output = []
        for row in rows:
            observations = self.conn.execute(
                "SELECT mac,ip,hostname,vendor,first_seen,last_seen,observation_count "
                "FROM device_observations WHERE device_id=? ORDER BY last_seen DESC", (row[0],)
            ).fetchall()
            macs = [item[0] for item in observations]
            current = observations[0] if observations else ("", "", "", "", 0, 0, 0)
            subjects = {item[0] for item in observations} | {item[1] for item in observations if item[1]}
            risk_score = 0
            if subjects:
                placeholders = ",".join("?" for _ in subjects)
                risk_row = self.conn.execute(
                    f"SELECT COALESCE(MAX(risk_score),0) FROM alerts WHERE subject IN ({placeholders})",
                    tuple(subjects),
                ).fetchone()
                risk_score = int(risk_row[0] or 0)
            risk_score = max(0, min(100, risk_score + {
                "Critical": 15, "Important": 8, "Normal": 0, "Low priority": -5,
            }.get(row[5], 0)))
            output.append({
                "device_id": row[0], "display_name": row[1], "owner_label": row[2],
                "location": row[3], "purpose": row[4], "criticality": row[5],
                "first_seen": min((item[4] for item in observations), default=row[6]),
                "last_seen": max((item[5] for item in observations), default=row[7]),
                "device_type": row[8] or "Unknown", "profile_label": row[9] or "Unknown device",
                "confidence": row[10] or 0.2, "profile_evidence": json.loads(row[11] or "[]"),
                "profile_signals": json.loads(row[12] or "{}"), "macs": macs,
                "current_mac": current[0], "current_ip": current[1], "hostname": current[2],
                "vendor": current[3], "trusted": any(self.is_trusted(mac) for mac in macs),
                "risk_score": risk_score,
            })
        return output

    def update_device_metadata(
        self, device_id: str, *, display_name: str, owner_label: str = "",
        location: str = "", purpose: str = "", criticality: str = "Normal",
    ) -> None:
        if criticality not in {"Critical", "Important", "Normal", "Low priority"}:
            raise ValueError("invalid asset criticality")
        fields = [display_name.strip(), owner_label.strip(), location.strip(), purpose.strip()]
        if not fields[0] or any(len(value) > 200 for value in fields):
            raise ValueError("invalid device metadata")
        changed = self.conn.execute(
            "UPDATE device_identities SET display_name=?,owner_label=?,location=?,purpose=?,"
            "criticality=?,updated_ts=? WHERE device_id=?",
            (*fields, criticality, time.time(), device_id),
        ).rowcount
        if not changed:
            raise ValueError("device identity not found")
        self.conn.commit()

    def merge_device_identities(self, primary_id: str, secondary_id: str) -> None:
        if primary_id == secondary_id:
            raise ValueError("cannot merge a device with itself")
        primary_signals = self._device_profile_signals(primary_id)
        secondary_signals = self._device_profile_signals(secondary_id)
        with self.conn:
            if not self.conn.execute("SELECT 1 FROM device_identities WHERE device_id=?", (primary_id,)).fetchone():
                raise ValueError("primary device not found")
            if not self.conn.execute("SELECT 1 FROM device_identities WHERE device_id=?", (secondary_id,)).fetchone():
                raise ValueError("secondary device not found")
            for mac, ip, hostname, vendor, first_seen, last_seen, count in self.conn.execute(
                "SELECT mac,ip,hostname,vendor,first_seen,last_seen,observation_count "
                "FROM device_observations WHERE device_id=?", (secondary_id,)
            ).fetchall():
                self.conn.execute(
                    "INSERT INTO device_observations(device_id,mac,ip,hostname,vendor,first_seen,last_seen,observation_count) "
                    "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(device_id,mac,ip,hostname) DO UPDATE SET "
                    "first_seen=MIN(first_seen,excluded.first_seen),last_seen=MAX(last_seen,excluded.last_seen),"
                    "observation_count=observation_count+excluded.observation_count",
                    (primary_id, mac, ip, hostname, vendor, first_seen, last_seen, count),
                )
            self.conn.execute("UPDATE device_links SET device_id=?,user_confirmed=1,reason='user merge' WHERE device_id=?", (primary_id, secondary_id))
            self.conn.execute("DELETE FROM device_observations WHERE device_id=?", (secondary_id,))
            self.conn.execute("DELETE FROM device_profiles WHERE device_id=?", (secondary_id,))
            self.conn.execute("DELETE FROM device_identities WHERE device_id=?", (secondary_id,))
            self._append_forensic_record(time.time(), "device_merge", {"primary": primary_id, "secondary": secondary_id})
        merged_signals = {**primary_signals, **secondary_signals}
        for key in ("open_ports", "services", "protocols"):
            merged_signals[key] = sorted(set(primary_signals.get(key, [])) | set(secondary_signals.get(key, [])))
        self._save_inferred_profile(primary_id, merged_signals)

    def split_device_identity(self, device_id: str, mac: str) -> str:
        mac = mac.lower()
        row = self.conn.execute(
            "SELECT 1 FROM device_links WHERE device_id=? AND mac=?", (device_id, mac)
        ).fetchone()
        count = self.conn.execute("SELECT COUNT(*) FROM device_links WHERE device_id=?", (device_id,)).fetchone()[0]
        if not row or count < 2:
            raise ValueError("split requires a linked MAC and at least two MACs")
        new_id = self._new_device_id()
        ts = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT INTO device_identities(device_id,display_name,created_ts,updated_ts) VALUES(?,?,?,?)",
                (new_id, new_id, ts, ts),
            )
            self.conn.execute(
                "UPDATE device_links SET device_id=?,user_confirmed=1,reason='user split' WHERE mac=?",
                (new_id, mac),
            )
            self.conn.execute(
                "UPDATE device_observations SET device_id=? WHERE device_id=? AND mac=?",
                (new_id, device_id, mac),
            )
            self._append_forensic_record(ts, "device_split", {"source": device_id, "new": new_id, "mac": mac})
        self._save_inferred_profile(new_id, self._device_profile_signals(device_id))
        return new_id

    def is_trusted(self, mac: str) -> bool:
        row = self.conn.execute("SELECT 1 FROM trusted WHERE mac=?", (mac,)).fetchone()
        return row is not None

    def risk_context(self, subject: str) -> dict:
        """Ngữ cảnh ngoài alert dùng để chấm điểm rủi ro (KE-HOACH-SHIELD-1.1
        mục B1): giá trị tài sản, mức tin cậy, số lần lặp lại, và verdict
        threat intel.

        `subject` có thể là MAC, IP, hoặc một khoá bất kỳ do detector đặt
        (behavior_key chẳng hạn) — cái gì tra không ra thì rơi về mặc định
        trung tính, không bao giờ ném lỗi: chấm điểm không được phép làm
        đường ống alert đứt.
        """
        subject = (subject or "").strip()
        context = {
            "asset_criticality": "Normal",
            "trusted": False,
            "repetition": 1,
            "threat_verdict": "unknown",
            "threat_confidence": 0.0,
        }
        if not subject:
            return context

        lowered = subject.lower()
        # Giá trị tài sản + tin cậy: subject có thể là MAC hoặc IP, thử cả hai.
        row = self.conn.execute(
            "SELECT i.criticality, d.mac FROM devices d "
            "JOIN device_links l ON l.mac = d.mac "
            "JOIN device_identities i ON i.device_id = l.device_id "
            "WHERE d.mac = ? OR d.ip = ? ORDER BY d.last_seen DESC LIMIT 1",
            (lowered, subject),
        ).fetchone()
        if row:
            context["asset_criticality"] = row[0]
            context["trusted"] = self.is_trusted(row[1])
        elif self.is_trusted(lowered):
            context["trusted"] = True

        # Lặp lại: dùng thẳng bộ đếm dedupe đã có trên bảng alerts.
        repetition = self.conn.execute(
            "SELECT MAX(count) FROM alerts WHERE subject = ?", (subject,)
        ).fetchone()
        if repetition and repetition[0]:
            context["repetition"] = int(repetition[0])

        # Threat intel: chỉ lấy bản ghi còn hạn, ưu tiên verdict nặng nhất.
        rows = self.conn.execute(
            "SELECT verdict, payload FROM threat_intel_cache "
            "WHERE indicator = ? AND expires_ts > ?", (subject, time.time()),
        ).fetchall()
        severity_rank = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}
        best_rank = -1
        for verdict, payload_raw in rows:
            rank = severity_rank.get(verdict, 1)
            if rank <= best_rank:
                continue
            best_rank = rank
            context["threat_verdict"] = verdict
            try:
                context["threat_confidence"] = float(json.loads(payload_raw).get("confidence", 0.0))
            except (TypeError, ValueError, AttributeError):
                context["threat_confidence"] = 0.0
        return context

    def add_trusted(self, mac: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted (mac, note, added_ts) VALUES (?, ?, ?)",
            (mac, note, time.time()),
        )
        self.conn.commit()

    def remove_trusted(self, mac: str) -> None:
        self.conn.execute("DELETE FROM trusted WHERE mac=?", (mac.lower(),))
        self.conn.commit()

    def mark_gateway_device(self, gateway_ip: str) -> None:
        row = self.conn.execute(
            "SELECT l.device_id FROM devices d JOIN device_links l ON l.mac=d.mac "
            "WHERE d.ip=? ORDER BY d.last_seen DESC LIMIT 1", (gateway_ip,),
        ).fetchone()
        if row:
            signals = self._device_profile_signals(row[0])
            signals["is_gateway"] = True
            self._save_inferred_profile(row[0], signals)

    def list_devices(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT d.mac, d.ip, d.vendor, d.hostname, d.first_seen, d.last_seen, "
            "       (t.mac IS NOT NULL) AS trusted "
            "FROM devices d LEFT JOIN trusted t ON t.mac = d.mac "
            "ORDER BY d.last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "mac": mac,
                "ip": ip,
                "vendor": vendor,
                "hostname": hostname,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "trusted": bool(trusted),
            }
            for mac, ip, vendor, hostname, first_seen, last_seen, trusted in rows
        ]

    # --- Baseline chống MITM (giai đoạn 2, xem KE-HOACH-SHIELD.md mục 2.1) ---

    def get_baseline(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM baseline WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def set_baseline(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO baseline (key, value, set_ts) VALUES (?, ?, ?)",
            (key, value, time.time()),
        )
        self.conn.commit()

    def load_fim_baseline(self) -> dict[str, dict]:
        import json
        rows = self.conn.execute("SELECT path, metadata FROM fim_baselines").fetchall()
        return {path: json.loads(metadata) for path, metadata in rows}

    def replace_fim_baseline(self, snapshot: dict[str, dict]) -> None:
        """Atomically replace FIM state so offline changes are visible next boot."""
        import json
        ts = time.time()
        with self.conn:
            self.conn.execute("DELETE FROM fim_baselines")
            self.conn.executemany(
                "INSERT INTO fim_baselines(path, metadata, updated_ts) VALUES (?, ?, ?)",
                [(path, json.dumps(metadata, sort_keys=True), ts) for path, metadata in snapshot.items()],
            )

    def record_block(self, kind: str, value: str, ttl_hours: float = 24.0) -> None:
        now_ts = time.time()
        self.conn.execute(
            "INSERT INTO blocks (kind, value, blocked_ts, expires_ts) VALUES (?, ?, ?, ?)",
            (kind, value, now_ts, now_ts + ttl_hours * 3600),
        )
        self.conn.commit()

    def remove_block(self, kind: str, value: str) -> None:
        self.conn.execute("DELETE FROM blocks WHERE kind=? AND value=?", (kind, value))
        self.conn.commit()

    def list_active_blocks(self) -> list[dict]:
        now_ts = time.time()
        rows = self.conn.execute(
            "SELECT kind, value, blocked_ts, expires_ts FROM blocks WHERE expires_ts > ? "
            "ORDER BY blocked_ts DESC",
            (now_ts,),
        ).fetchall()
        return [
            {"kind": kind, "value": value, "blocked_ts": blocked_ts, "expires_ts": expires_ts}
            for kind, value, blocked_ts, expires_ts in rows
        ]

    # --- Dải mạng được cấp phép (quét ngoài mạng nhà) ---

    def add_authorized_range(self, cidr: str, note: str) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO authorized_ranges (cidr, note, added_ts) VALUES (?, ?, ?)",
            (cidr, note, time.time()),
        )
        self.conn.commit()

    def remove_authorized_range(self, cidr: str) -> None:
        self.conn.execute("DELETE FROM authorized_ranges WHERE cidr=?", (cidr,))
        self.conn.commit()

    def list_authorized_ranges(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT cidr, note, added_ts FROM authorized_ranges ORDER BY added_ts DESC"
        ).fetchall()
        return [{"cidr": cidr, "note": note, "added_ts": ts} for cidr, note, ts in rows]

    # --- Lưu lượng theo thiết bị đọc từ router ---

    def upsert_router_traffic(self, ip: str, mac: str | None, rx_bytes: int, tx_bytes: int) -> None:
        self.conn.execute(
            "INSERT INTO router_traffic (ip, mac, rx_bytes, tx_bytes, updated_ts) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, rx_bytes=excluded.rx_bytes, "
            "tx_bytes=excluded.tx_bytes, updated_ts=excluded.updated_ts",
            (ip, mac, rx_bytes, tx_bytes, time.time()),
        )
        self.conn.commit()

    def list_router_traffic(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT ip, mac, rx_bytes, tx_bytes, updated_ts FROM router_traffic "
            "ORDER BY (rx_bytes + tx_bytes) DESC"
        ).fetchall()
        return [
            {"ip": ip, "mac": mac, "rx_bytes": rx, "tx_bytes": tx, "updated_ts": ts}
            for ip, mac, rx, tx, ts in rows
        ]

    # --- Lịch sử self-audit theo host (so sánh 2 lần quét cách nhau) ---

    def save_audit_snapshot(self, host: str, ports: list[dict]) -> None:
        import json

        self.conn.execute(
            "INSERT INTO audit_snapshots (host, ts, ports) VALUES (?, ?, ?)",
            (host, time.time(), json.dumps(ports)),
        )
        self.conn.commit()

    def list_audit_snapshots(self, host: str, limit: int = 20) -> list[dict]:
        import json

        rows = self.conn.execute(
            "SELECT ts, ports FROM audit_snapshots WHERE host=? ORDER BY ts DESC LIMIT ?",
            (host, limit),
        ).fetchall()
        return [{"ts": ts, "ports": json.loads(ports)} for ts, ports in rows]

    def diff_latest_audit_snapshots(self, host: str) -> dict | None:
        """So 2 snapshot gần nhất của `host`. Trả None nếu chưa đủ 2 lần quét
        (chưa có gì để so sánh). Diff theo (port, proto) — đổi version/service
        cùng port không tính là "thêm/bớt", chỉ tính cổng mở/đóng thật sự."""
        snapshots = self.list_audit_snapshots(host, limit=2)
        if len(snapshots) < 2:
            return None

        newest, previous = snapshots[0], snapshots[1]
        newest_keys = {(p["port"], p["proto"]): p for p in newest["ports"]}
        previous_keys = {(p["port"], p["proto"]): p for p in previous["ports"]}

        added = [newest_keys[k] for k in newest_keys.keys() - previous_keys.keys()]
        removed = [previous_keys[k] for k in previous_keys.keys() - newest_keys.keys()]
        return {
            "host": host,
            "previous_ts": previous["ts"],
            "newest_ts": newest["ts"],
            "added": sorted(added, key=lambda p: p["port"]),
            "removed": sorted(removed, key=lambda p: p["port"]),
        }

    def add_audit_log(self, action_id: str, params: dict, result: str) -> None:
        ts = time.time()
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit_log (ts, action_id, params, result) VALUES (?, ?, ?, ?)",
                (ts, action_id, json.dumps(params, sort_keys=True), result),
            )
            self._append_forensic_record(ts, "audit", {"action_id": action_id, "params": params, "result": result})

    def _append_forensic_record(self, ts: float, category: str, payload: dict) -> str:
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        row = self.conn.execute("SELECT entry_hash FROM forensic_ledger ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else "0" * 64
        canonical = f"{ts:.6f}\n{category}\n{payload_json}\n{prev_hash}".encode()
        entry_hash = hashlib.sha256(canonical).hexdigest()
        auth_tag = hmac.new(self._audit_key, canonical, hashlib.sha256).hexdigest() if self._audit_key else ""
        self.conn.execute(
            "INSERT INTO forensic_ledger(ts, category, payload, prev_hash, entry_hash, auth_tag) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, category, payload_json, prev_hash, entry_hash, auth_tag),
        )
        return entry_hash

    def add_forensic_record(self, category: str, payload: dict) -> str:
        with self.conn:
            return self._append_forensic_record(time.time(), category, payload)

    def verify_forensic_ledger(self) -> tuple[bool, int | None, str]:
        previous = "0" * 64
        rows = self.conn.execute(
            "SELECT id, ts, category, payload, prev_hash, entry_hash, auth_tag FROM forensic_ledger ORDER BY id"
        ).fetchall()
        for row_id, ts, category, payload, prev_hash, entry_hash, auth_tag in rows:
            canonical = f"{ts:.6f}\n{category}\n{payload}\n{prev_hash}".encode()
            expected = hashlib.sha256(canonical).hexdigest()
            if prev_hash != previous or not hmac.compare_digest(entry_hash, expected):
                return False, row_id, "hash chain mismatch"
            if self._audit_key:
                expected_tag = hmac.new(self._audit_key, canonical, hashlib.sha256).hexdigest()
                if not auth_tag or not hmac.compare_digest(auth_tag, expected_tag):
                    return False, row_id, "HMAC mismatch"
            previous = entry_hash
        return True, None, f"verified {len(rows)} records"

    def create_forensic_checkpoint(self, path: Path) -> dict:
        row = self.conn.execute("SELECT id, entry_hash FROM forensic_ledger ORDER BY id DESC LIMIT 1").fetchone()
        checkpoint = {"schema_version": 1, "record_id": row[0] if row else 0, "entry_hash": row[1] if row else "0" * 64, "ts": time.time()}
        canonical = json.dumps(checkpoint, sort_keys=True, separators=(",", ":")).encode()
        checkpoint["hmac"] = hmac.new(self._audit_key, canonical, hashlib.sha256).hexdigest() if self._audit_key else ""
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(checkpoint, sort_keys=True), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, path)
        return checkpoint

    def verify_forensic_checkpoint(self, path: Path) -> tuple[bool, str]:
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
            tag = checkpoint.pop("hmac")
        except (OSError, json.JSONDecodeError, KeyError):
            return False, "checkpoint missing or invalid"
        canonical = json.dumps(checkpoint, sort_keys=True, separators=(",", ":")).encode()
        if self._audit_key:
            expected = hmac.new(self._audit_key, canonical, hashlib.sha256).hexdigest()
            if not tag or not hmac.compare_digest(tag, expected):
                return False, "checkpoint HMAC mismatch"
        row = self.conn.execute("SELECT entry_hash FROM forensic_ledger WHERE id=?", (checkpoint["record_id"],)).fetchone()
        if checkpoint["record_id"] and (not row or row[0] != checkpoint["entry_hash"]):
            return False, "ledger was truncated or diverged from checkpoint"
        latest = self.conn.execute("SELECT MAX(id) FROM forensic_ledger").fetchone()[0] or 0
        if latest < checkpoint["record_id"]:
            return False, "ledger tail was truncated"
        return True, f"checkpoint verified at record {checkpoint['record_id']}"

    def get_threat_intel_cache(self, indicator_type: str, indicator: str, provider: str) -> dict | None:
        row = self.conn.execute(
            "SELECT verdict, payload, expires_ts FROM threat_intel_cache WHERE indicator_type=? AND indicator=? AND provider=?",
            (indicator_type, indicator, provider),
        ).fetchone()
        if not row or row[2] <= time.time():
            return None
        return {"verdict": row[0], "payload": json.loads(row[1]), "expires_ts": row[2]}

    def put_threat_intel_cache(self, indicator_type: str, indicator: str, provider: str, verdict: str, payload: dict, ttl_s: float) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO threat_intel_cache(indicator_type, indicator, provider, verdict, payload, expires_ts) VALUES (?, ?, ?, ?, ?, ?)",
            (indicator_type, indicator, provider, verdict, json.dumps(payload, sort_keys=True), time.time() + max(1.0, ttl_s)),
        )
        self.conn.commit()

    def maintain(
        self, event_days: int = 30, alert_days: int = 90,
        snapshot_days: int = 30, database_max_bytes: int = 0,
    ) -> dict[str, int]:
        """Bound DB growth; forensic ledger is deliberately never pruned here.

        `database_max_bytes` là trần THẬT SỰ được thi hành. Trước đây tham số
        đó chỉ dùng để tô màu "degraded" trong tab Sức khoẻ trong khi database
        cứ lớn mãi — một con số trông như giới hạn nhưng không giới hạn gì là
        cái bẫy, vì người đọc tin rằng đã có ai đó lo phần này.
        """
        now_ts = time.time()
        with self.conn:
            # `LIMIT` trên câu xoá theo hạn lưu trữ: một database bỏ quên nhiều
            # ngày có thể có hàng triệu dòng quá hạn, và xoá tất cả trong MỘT
            # câu giữ khoá đúng bằng thời gian đó. Phần còn lại đi tiếp ở lượt
            # sau — `more_work` dưới đây nói cho vòng bảo trì biết là còn.
            events = self.conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ? "
                "ORDER BY ts LIMIT ?)",
                (now_ts - event_days * 86400, RETENTION_DELETE_LIMIT)).rowcount
            alerts = self.conn.execute(
                "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE ts < ? "
                "ORDER BY ts LIMIT ?)",
                (now_ts - alert_days * 86400, RETENTION_DELETE_LIMIT)).rowcount
            snapshots = self.conn.execute(
                "DELETE FROM audit_snapshots WHERE ts < ?", (now_ts - snapshot_days * 86400,)
            ).rowcount
            intel = self.conn.execute("DELETE FROM threat_intel_cache WHERE expires_ts <= ?", (now_ts,)).rowcount
        self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        trimmed = 0
        if database_max_bytes > 0:
            trimmed = self._enforce_size_cap(int(database_max_bytes))
            events += trimmed
        # Dọn graph SAU khi đã cắt event. Thứ tự này bắt buộc: `prune` xác định
        # cạnh mồ côi bằng cách tra ngược bảng `events`, nên chạy trước thì nó
        # thấy mọi bằng chứng vẫn còn nguyên và không gỡ gì.
        #
        # Bỏ bước này nghĩa là graph chỉ lớn lên, không bao giờ nhỏ lại — và
        # tệ hơn dung lượng: nó sẽ đầy những cạnh trỏ tới event đã bị xoá, tức
        # những khẳng định không ai kiểm chứng lại được nữa.
        graph_pruned = {"edges_removed": 0, "entities_removed": 0, "evidence_removed": 0}
        if events or trimmed:
            graph_pruned = self._prune_graph_slice(
                older_than_ts=now_ts - alert_days * 86400)
        # Vết model và hồ sơ điều tra có hạn RIÊNG (mục 7): vết nhiều và nhanh
        # cũ, hồ sơ thì không. Một hạn chung sẽ hoặc giữ vết quá lâu, hoặc xoá
        # hồ sơ quá sớm.
        from shield.ai.audit import InvestigationAudit

        with self.conn:
            ai_pruned = InvestigationAudit(self.conn).prune()
        # CÒN VIỆC KHÔNG. Mỗi lượt bị chặn trần, nên "đã chạy xong một lượt"
        # không còn đồng nghĩa với "đã dọn xong". Vòng bảo trì đọc cờ này để
        # quay lại sớm thay vì ngủ tiếp sáu tiếng trong lúc database vẫn ở trên
        # trần — nếu không, việc chặn trần chỉ đổi một lần treo dài thành một
        # đống rác không bao giờ được dọn.
        more_work = bool(
            events >= RETENTION_DELETE_LIMIT
            or alerts >= RETENTION_DELETE_LIMIT
            or not graph_pruned.get("complete", True)
            or (database_max_bytes > 0
                and self.database_used_bytes() > int(database_max_bytes))
        )
        return {
            "events_deleted": events, "alerts_deleted": alerts,
            "snapshots_deleted": snapshots, "intel_deleted": intel,
            "events_trimmed_for_size": trimmed,
            "graph_edges_deleted": graph_pruned["edges_removed"],
            "graph_edges_scanned": graph_pruned.get("edges_scanned", 0),
            "graph_entities_deleted": graph_pruned["entities_removed"],
            "ai_traces_deleted": ai_pruned["traces_removed"],
            "investigations_deleted": ai_pruned["investigations_removed"],
            "more_work": more_work,
        }

    def _prune_graph_slice(self, older_than_ts: float = 0.0,
                           max_edges: int = GRAPH_PRUNE_MAX_EDGES) -> dict:
        """Dọn MỘT lát graph, tiếp từ chỗ lượt trước dừng.

        Con trỏ nằm trong `baseline` nên nó sống qua khởi động lại. Hết bảng
        thì `prune` trả con trỏ rỗng và lượt sau bắt đầu lại từ đầu — graph
        luôn được quét vòng tròn, không có phần nào bị bỏ quên vĩnh viễn.
        """
        after = self.get_baseline(GRAPH_PRUNE_CURSOR_KEY) or ""
        with self.conn:
            result = EvidenceGraph(self.conn).prune(
                older_than_ts, max_edges=max_edges, after=after)
        self.set_baseline(GRAPH_PRUNE_CURSOR_KEY, result.get("next_cursor", ""))
        return result

    def _enforce_size_cap(self, maximum_bytes: int, batch: int = 50_000,
                          max_batches: int = SIZE_CAP_MAX_BATCHES) -> int:
        """Xoá event CŨ NHẤT, TỐI ĐA `max_batches` lô mỗi lượt.

        Trước đây vòng lặp này chạy tới 40 lô, mỗi lô kèm một lượt dọn graph
        toàn bảng: đo được 9,6 giây một vòng trên database production, tức tới
        gần 400 giây một lượt bảo trì. Watchdog systemd là 45 giây ping / 90
        giây timeout, và lời gọi chứng minh store còn sống phải chờ cùng cái
        khoá mà vòng lặp này đang giữ — nên agent bị SIGABRT bốn lần rồi nằm ở
        trạng thái failed. Việc dọn không cần xong trong một lượt; nó chỉ cần
        tiến đều và không được giữ khoá quá lâu.

        Chỉ đụng vào `events` và phần graph phụ thuộc vào chúng.
        `forensic_ledger` và `alerts` không bao giờ bị cắt ở đây: bằng chứng và
        kết luận nhỏ hơn nhiều lần và là thứ người ta cần lại sau này.

        Graph được dọn NGAY TRONG vòng lặp, sau mỗi lô. Dọn sau vòng lặp là một
        cái bẫy đã đo được: từ schema v5, graph chiếm khoảng một phần ba
        database (29 MB trên 58 MB ở phép đo 50 nghìn event). Vòng lặp xoá
        event rồi đo lại tổng dung lượng, nhưng dung lượng đó vẫn bị phần graph
        mồ côi giữ nguyên — nên nó xoá tiếp, và tiếp, cho tới khi hết sạch
        event mà vẫn chưa dưới trần. Lần chạy bảo trì đầu tiên sau khi chạm
        trần sẽ xoá gần như toàn bộ lịch sử thay vì đúng phần cần cắt.
        """
        removed = 0
        for _ in range(max(1, int(max_batches))):
            if self.database_used_bytes() <= maximum_bytes:
                break
            with self.conn:
                deleted = self.conn.execute(
                    "DELETE FROM events WHERE id IN "
                    "(SELECT id FROM events ORDER BY ts LIMIT ?)", (batch,)
                ).rowcount
            if not deleted:
                break
            removed += deleted
            self._prune_graph_slice()
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            # Trả trang tự do về hệ điều hành nếu database này bật được
            # auto_vacuum (bản cài mới). Không bật thì đây là no-op, và trần
            # vẫn có tác dụng nhờ đo dung lượng logic.
            self.conn.execute("PRAGMA incremental_vacuum")
        if removed:
            logger.warning(
                "Cắt bớt %d event cũ nhất để giữ database dưới %d byte", removed, maximum_bytes)
        return removed

    def database_used_bytes(self) -> int:
        """Dung lượng ĐANG DÙNG: trang đã cấp trừ trang tự do, cộng WAL.

        Đây mới là con số dùng để thi hành trần, không phải kích thước file.
        SQLite mặc định `auto_vacuum=NONE`: xoá dòng chỉ đưa trang vào danh
        sách tự do, file không bao giờ tự nhỏ lại. Đo kích thước file rồi xoá
        dòng và đo lại sẽ luôn thấy y nguyên — vòng lặp cắt bớt chạy đủ 40 lượt,
        xoá tới 2 triệu event, và kết thúc vẫn "trên trần". Một cái trần xoá
        sạch lịch sử mà không thu lại được byte nào.

        Đo dung lượng logic thì trần có nghĩa thật: trang tự do được tái sử
        dụng, nên file ngừng lớn ngay cả khi nó không co lại.
        """
        page_size = int(self.conn.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(self.conn.execute("PRAGMA page_count").fetchone()[0])
        free = int(self.conn.execute("PRAGMA freelist_count").fetchone()[0])
        wal = 0
        try:
            wal = Path(str(self.path) + "-wal").stat().st_size
        except OSError:
            pass
        return max(0, page_count - free) * page_size + wal

    def database_bytes(self) -> int:
        """Kích thước file thật, gồm cả WAL. Dùng để BÁO CÁO, không để thi hành
        trần — xem `database_used_bytes`."""
        total = 0
        for suffix in ("", "-wal"):
            try:
                total += (Path(str(self.path) + suffix)).stat().st_size
            except OSError:
                continue
        return total

    def save_assessment_result(self, result: dict) -> None:
        payload = json.dumps(result, sort_keys=True, ensure_ascii=False)
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO assessment_sessions(session_id, profile_id, started_ts, finished_ts, result) VALUES (?, ?, ?, ?, ?)",
                (result["session_id"], result["profile_id"], result["started_ts"], result["finished_ts"], payload),
            )
            self.conn.execute("DELETE FROM assessment_ground_truth WHERE session_id=?", (result["session_id"],))
            self.conn.executemany(
                "INSERT INTO assessment_ground_truth(session_id, test_id, ts, record) VALUES (?, ?, ?, ?)",
                [(result["session_id"], item["test_id"], item["ts"], json.dumps(item, sort_keys=True)) for item in result.get("ground_truth", [])],
            )
            self._append_forensic_record(time.time(), "assessment", {"session_id": result["session_id"], "profile_id": result["profile_id"], "counts": {status: sum(r["status"] == status for r in result["results"]) for status in ("passed", "failed", "inconclusive", "skipped")}})

    def recent_assessments(self, limit: int = 20) -> list[dict]:
        rows = self.conn.execute("SELECT result FROM assessment_sessions ORDER BY finished_ts DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    # --- Advanced investigation, anomaly, suppression and fleet state ---

    # --- phiên bản định dạng khoá baseline + học lại theo TỪNG loại ---
    #
    # Vì sao cần: `behavior_key()` dựng khoá từ các trường của event. Khi
    # telemetry giàu thêm một trường, khoá đổi, và MỌI thứ đã học trở thành
    # "chưa từng thấy".
    #
    # Đã xảy ra thật ở Phase 2: thêm `uid` vào ảnh chụp procfs làm khoá đi từ
    # `process_started|system|2|/usr/bin/sleep` thành `process_started|0|2|...`,
    # biến 640 khoá đã học thành vô dụng và mở đầu một trận ~640 cảnh báo
    # `warning`. Không mất dữ liệu, không sai kết luận — nhưng đúng thứ
    # `security/trust.py` cảnh báo: người dùng học được rằng cảnh báo của
    # Shield là nhiễu, rồi bỏ qua cả cảnh báo thật.
    #
    # Phiên bản đặt theo TỪNG LOẠI event, không phải một số chung: đổi cách
    # dựng khoá của `process_started` không có lý do gì bắt `host_seen` hay
    # `listener_opened` học lại.
    _FORMAT_KEY = "behavior_key_format:"
    _RELEARN_KEY = "anomaly_relearn_until:"

    def _relearn_until_for(self, kind: str) -> float:
        """Mốc hết hạn học lại của một loại. 0 nếu không học lại.

        Nhớ trong bộ nhớ vì hàm này chạy trên MỖI event — ở đỉnh là vài trăm
        lần mỗi giây. Nhớ một mốc thời gian là an toàn: nó không đổi giữa hai
        lần khởi động, và khi thời gian trôi qua mốc thì so sánh tự sai đi,
        nên không cần khởi động lại agent để thoát chế độ học lại.
        """
        cache = getattr(self, "_relearn_cache", None)
        if cache is None:
            cache = {}
            for key, value in self.conn.execute(
                    "SELECT key, value FROM baseline WHERE key LIKE ?",
                    (self._RELEARN_KEY + "%",)).fetchall():
                try:
                    cache[key[len(self._RELEARN_KEY):]] = float(value)
                except (TypeError, ValueError):
                    continue
            self._relearn_cache = cache
        return cache.get(kind, 0.0)

    def behavior_key_formats(self) -> dict[str, int]:
        """Định dạng khoá đã ghi nhận cho từng loại."""
        out: dict[str, int] = {}
        for key, value in self.conn.execute(
                "SELECT key, value FROM baseline WHERE key LIKE ?",
                (self._FORMAT_KEY + "%",)).fetchall():
            try:
                out[key[len(self._FORMAT_KEY):]] = int(value)
            except (TypeError, ValueError):
                continue
        return out

    def relearning_kinds(self, at: float | None = None) -> dict[str, float]:
        """Loại nào đang học lại và tới khi nào. Dùng cho sức khoẻ và giao diện.

        Đọc thẳng từ database, không qua bộ nhớ đệm: hàm này chạy 30 giây một
        lần cho báo cáo sức khoẻ, và nó phải nói đúng cả khi một tiến trình
        khác vừa đổi trạng thái.
        """
        now_ts = time.time() if at is None else at
        out: dict[str, float] = {}
        for key, value in self.conn.execute(
                "SELECT key, value FROM baseline WHERE key LIKE ?",
                (self._RELEARN_KEY + "%",)).fetchall():
            try:
                until = float(value)
            except (TypeError, ValueError):
                continue
            if until > now_ts:
                out[key[len(self._RELEARN_KEY):]] = until
        return out

    def restart_behavior_learning(self, kind: str, learning_days: int = 7,
                                  old_format: int = 0, new_format: int = 0) -> dict:
        """Xoá baseline của ĐÚNG một loại và cho nó học lại trong im lặng.

        KHÔNG dùng `reset_behavior_baseline()`: hàm đó xoá sạch mọi loại, kể cả
        những loại mà cách dựng khoá không hề đổi — ở lần này là 3.397 khoá
        `process_exec` hoàn toàn còn đúng.

        Idempotent theo nghĩa: gọi lại với cùng cặp phiên bản cho ra cùng trạng
        thái. Việc chỉ gọi khi phiên bản ĐỔI là trách nhiệm của
        `reconcile_behavior_key_formats`.
        """
        ts = time.time()
        until = ts + max(1, int(learning_days)) * 86400
        with self.conn:
            deleted = self.conn.execute(
                "DELETE FROM behavior_baselines WHERE kind=?", (str(kind),)).rowcount
            self.conn.execute(
                "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES(?,?,?)",
                (self._RELEARN_KEY + str(kind), str(until), ts))
            self.conn.execute(
                "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES(?,?,?)",
                (self._FORMAT_KEY + str(kind), str(int(new_format)), ts))
        self._relearn_cache = None
        record = {"kind": str(kind), "deleted_keys": int(deleted or 0),
                  "old_format": int(old_format), "new_format": int(new_format),
                  "relearn_until": until, "learning_days": int(learning_days)}
        # Xoá baseline là một thay đổi trạng thái an ninh. Nó phải để lại dấu
        # vết nói RÕ vì sao, nếu không thì sáu tháng nữa "baseline biến mất"
        # là một bí ẩn.
        self.add_audit_log(
            "behavior_baseline_relearn", record,
            f"định dạng khoá {kind} đổi {old_format} -> {new_format}; "
            f"xoá {record['deleted_keys']} khoá, học lại {learning_days} ngày")
        return record

    def reconcile_behavior_key_formats(self, formats: dict[str, int],
                                       learning_days: int = 7) -> list[dict]:
        """So phiên bản trong mã với phiên bản đã lưu; loại nào đổi thì học lại.

        Chạy trong MỘT giao dịch cho mỗi loại, và chỉ tiến trình có quyền đổi
        schema mới gọi — nên hai lần khởi động chồng nhau không tạo được hai
        lượt xoá: lượt sau thấy phiên bản đã bằng nhau và không làm gì.

        Lần chạy đầu tiên (chưa có gì lưu) cần phân biệt hai trường hợp, và
        đây là chỗ dễ sai nhất:

        - Loại còn ở **phiên bản 1**: định dạng chưa từng đổi, nên baseline
          đang có chắc chắn cùng định dạng với mã hiện tại. Ghi nhận rồi đi
          tiếp — coi nó là "đã đổi" sẽ xoá sạch baseline của mọi máy đang chạy
          chỉ vì ta vừa thêm cơ chế đánh số.
        - Loại đã ở **phiên bản ≥ 2**: định dạng đã đổi ít nhất một lần, mà
          baseline này không ghi phiên bản nào — tức là nó có TRƯỚC cơ chế
          đánh số, và ta KHÔNG biết nó học bằng định dạng nào. Không biết thì
          phải học lại.

        Trường hợp thứ hai không phải giả thuyết: máy đang chạy có 657 khoá
        `process_started` học bằng định dạng cũ và đang bắn cảnh báo, còn cơ
        chế này thì vừa được thêm vào. Nếu lần chạy đầu chỉ ghi nhận rồi đi
        tiếp, trận cảnh báo đó vẫn tiếp diễn nguyên vẹn.
        """
        stored = self.behavior_key_formats()
        # Máy này đã từng ghi nhận định dạng cho ÍT NHẤT một loại chưa? Đó là
        # thứ phân biệt hai tình huống mà `known is None` một mình không phân
        # biệt được:
        #
        # - Bảng RỖNG: hoặc là cài mới, hoặc là bản cài có trước cơ chế đánh
        #   số. Cả hai đều không được đụng vào baseline đang có — cửa sổ học
        #   toàn cục lo phần còn lại.
        # - Bảng KHÔNG rỗng nhưng thiếu loại này: một loại MỚI vừa được thêm
        #   vào một máy đang chạy. Cửa sổ học toàn cục của máy đó có thể đã
        #   đóng từ lâu, nên nếu chỉ ghi nhận rồi đi tiếp thì mọi khoá đầu tiên
        #   của loại mới đều bắn cảnh báo — ba lần mỗi khoá, vì
        #   `minimum_observations = 3` đếm TRƯỚC khi tăng. Đo trên máy thật:
        #   cửa sổ toàn cục đã đóng 1,9 ngày, và một loại mới sẽ sinh 204 tới
        #   2.352 cảnh báo trong ngày đầu.
        da_ghi_nhan_dinh_dang = bool(stored)
        changed: list[dict] = []
        for kind, version in sorted(formats.items()):
            known = stored.get(kind)
            if known == int(version):
                # Phiên bản không đổi: KHÔNG gia hạn cửa sổ học lại. Đây là
                # thứ làm hàm này idempotent qua mỗi lần khởi động.
                continue
            if known is None and int(version) <= 1 and not da_ghi_nhan_dinh_dang:
                with self.conn:
                    self.conn.execute(
                        "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES(?,?,?)",
                        (self._FORMAT_KEY + kind, str(int(version)), time.time()))
                continue
            changed.append(self.restart_behavior_learning(
                kind, learning_days, old_format=known or 0, new_format=int(version)))
        self._relearn_cache = None
        return changed

    _GRAPH_FORMAT_KEY = "graph_key_format:"

    def graph_key_formats(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for key, value in self.conn.execute(
                "SELECT key, value FROM baseline WHERE key LIKE ?",
                (self._GRAPH_FORMAT_KEY + "%",)).fetchall():
            try:
                out[key[len(self._GRAPH_FORMAT_KEY):]] = int(value)
            except (TypeError, ValueError):
                continue
        return out

    def reconcile_graph_key_formats(self, formats: dict[str, int]) -> list[dict]:
        """Loại thực thể nào có cách dựng khoá đã đổi thì dựng lại từ đầu.

        Cùng khuôn với `reconcile_behavior_key_formats`, và cùng quy tắc cho
        lần chạy đầu: phiên bản 1 nghĩa là định dạng chưa từng đổi nên dữ liệu
        đang có vẫn đúng; phiên bản >= 2 mà không ghi phiên bản nào nghĩa là dữ
        liệu có TRƯỚC cơ chế đánh số, và ta không biết nó dùng định dạng nào —
        không biết thì phải dựng lại.

        Đồ thị dựng lại được: mỗi lần agent khởi động phát lại toàn bộ listener
        qua `listener_observed`. Event và bằng chứng KHÔNG bị chạm.
        """
        from shield.evidence.graph import EvidenceGraph

        stored = self.graph_key_formats()
        changed: list[dict] = []
        for entity_type, version in sorted(formats.items()):
            known = stored.get(entity_type)
            if known == int(version):
                continue
            if known is None and int(version) <= 1:
                with self.conn:
                    self.conn.execute(
                        "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES(?,?,?)",
                        (self._GRAPH_FORMAT_KEY + entity_type, str(int(version)), time.time()))
                continue
            result = EvidenceGraph(self.conn).drop_entities_of_type(entity_type)
            with self.conn:
                self.conn.execute(
                    "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES(?,?,?)",
                    (self._GRAPH_FORMAT_KEY + entity_type, str(int(version)), time.time()))
            record = {"entity_type": entity_type, "old_format": known or 0,
                      "new_format": int(version), **result}
            self.add_audit_log(
                "graph_key_format_rebuild", record,
                f"định dạng khoá {entity_type} đổi {known or 0} -> {version}; "
                f"xoá {result['entities_removed']} thực thể, {result['edges_removed']} cạnh")
            changed.append(record)
        return changed

    def observe_behavior(self, key: str, kind: str, learning_days: int = 7) -> tuple[int, bool]:
        ts = time.time()
        global_row = self.conn.execute("SELECT value FROM baseline WHERE key='anomaly_learning_started'").fetchone()
        if global_row:
            learning_started = float(global_row[0])
        else:
            learning_started = ts
            self.conn.execute(
                "INSERT OR REPLACE INTO baseline(key,value,set_ts) VALUES('anomaly_learning_started',?,?)",
                (str(ts), ts),
            )
            self.conn.commit()
        global_learning_until = learning_started + max(1, learning_days) * 86400
        # Loại đang học lại thì khoá MỚI mang mốc học lại, không mang mốc học
        # toàn cục đã đóng từ lâu. Đây là chỗ duy nhất biến "đã đổi định dạng
        # khoá" thành "im lặng cho tới khi biết lại cái gì là bình thường".
        relearn_until = self._relearn_until_for(kind)
        if relearn_until > global_learning_until:
            global_learning_until = relearn_until
        row = self.conn.execute(
            "SELECT observation_count, learning_until FROM behavior_baselines WHERE behavior_key=?", (key,)
        ).fetchone()
        previous = int(row[0]) if row else 0
        learning_until = float(row[1]) if row else global_learning_until
        with self.conn:
            self.conn.execute(
                "INSERT INTO behavior_baselines(behavior_key,kind,observation_count,first_seen,last_seen,learning_until) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(behavior_key) DO UPDATE SET observation_count=observation_count+1,last_seen=excluded.last_seen",
                (key, kind, 1, ts, ts, learning_until),
            )
        return previous, ts < learning_until

    def reset_behavior_baseline(self) -> None:
        with self.conn:
            self.conn.execute("DELETE FROM behavior_baselines")
            self.conn.execute("DELETE FROM baseline WHERE key='anomaly_learning_started'")
            self._append_forensic_record(time.time(), "baseline_reset", {"scope": "local_behavior"})

    def behavior_baseline_summary(self) -> dict:
        row = self.conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(observation_count),0), COALESCE(MAX(learning_until),0) FROM behavior_baselines"
        ).fetchone()
        return {"behaviors": row[0], "observations": row[1], "learning_until": row[2]}

    def save_case(self, case: dict) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO security_cases(case_id,title,subject,state,created_ts,updated_ts,alert_rules) VALUES(?,?,?,?,?,?,?)",
                (case["case_id"], case["title"], case["subject"], case["state"], case["created_ts"], case["updated_ts"], json.dumps(case.get("alert_rules", []))),
            )
            self._append_forensic_record(time.time(), "case_created", case)

    def update_case_state(self, case_id: str, state: str) -> None:
        with self.conn:
            changed = self.conn.execute(
                "UPDATE security_cases SET state=?,updated_ts=? WHERE case_id=?", (state, time.time(), case_id)
            ).rowcount
            if not changed:
                raise ValueError("case not found")
            self._append_forensic_record(time.time(), "case_state", {"case_id": case_id, "state": state})

    def add_case_note(self, case_id: str, author: str, note: str) -> None:
        ts = time.time()
        with self.conn:
            if not self.conn.execute("SELECT 1 FROM security_cases WHERE case_id=?", (case_id,)).fetchone():
                raise ValueError("case not found")
            self.conn.execute("INSERT INTO case_notes(case_id,ts,author,note) VALUES(?,?,?,?)", (case_id, ts, author, note))
            self.conn.execute("UPDATE security_cases SET updated_ts=? WHERE case_id=?", (ts, case_id))
            self._append_forensic_record(ts, "case_note", {"case_id": case_id, "author": author, "note": note})

    def list_cases(self, limit: int = 200) -> list[dict]:
        rows = self.conn.execute(
            "SELECT case_id,title,subject,state,created_ts,updated_ts,alert_rules FROM security_cases ORDER BY updated_ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [{"case_id": row[0], "title": row[1], "subject": row[2], "state": row[3],
                 "created_ts": row[4], "updated_ts": row[5], "alert_rules": json.loads(row[6])} for row in rows]

    def case_notes(self, case_id: str) -> list[dict]:
        rows = self.conn.execute("SELECT ts,author,note FROM case_notes WHERE case_id=? ORDER BY ts", (case_id,)).fetchall()
        return [{"ts": ts, "author": author, "note": note} for ts, author, note in rows]

    def search_security_records(self, query: str, since_ts: float = 0, limit: int = 1000) -> list[dict]:
        query = query.strip()[:300]
        if not query:
            return []
        pattern = f"%{query.replace('%', '').replace('_', '')}%"
        events = self.conn.execute(
            "SELECT ts,source,kind,data FROM events WHERE ts>=? AND (source LIKE ? OR kind LIKE ? OR data LIKE ?) ORDER BY ts DESC LIMIT ?",
            (since_ts, pattern, pattern, pattern, limit),
        ).fetchall()
        alerts = self.conn.execute(
            "SELECT ts,rule_id,severity,title,detail,subject,evidence FROM alerts WHERE ts>=? AND (rule_id LIKE ? OR title LIKE ? OR detail LIKE ? OR subject LIKE ? OR evidence LIKE ?) ORDER BY ts DESC LIMIT ?",
            (since_ts, pattern, pattern, pattern, pattern, pattern, limit),
        ).fetchall()
        output = [{"record_type": "event", "ts": row[0], "source": row[1], "kind": row[2], "data": json.loads(row[3])} for row in events]
        output += [{"record_type": "alert", "ts": row[0], "rule_id": row[1], "severity": row[2], "title": row[3], "detail": row[4], "subject": row[5], "evidence": json.loads(row[6])} for row in alerts]
        return sorted(output, key=lambda item: item["ts"], reverse=True)[:limit]

    def add_suppression(self, rule_pattern: str, subject_pattern: str, expires_ts: float, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO suppressions(rule_pattern,subject_pattern,expires_ts,reason,created_ts) VALUES(?,?,?,?,?)",
            (rule_pattern, subject_pattern, expires_ts, reason, time.time()),
        )
        self.conn.commit()

    def active_suppressions(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id,rule_pattern,subject_pattern,expires_ts,reason FROM suppressions WHERE expires_ts=0 OR expires_ts>? ORDER BY id DESC", (time.time(),)
        ).fetchall()
        return [{"id": row[0], "rule_pattern": row[1], "subject_pattern": row[2], "expires_ts": row[3], "reason": row[4]} for row in rows]

    def upsert_endpoint(self, endpoint: dict) -> None:
        self.conn.execute(
            "INSERT INTO fleet_endpoints(endpoint_id,display_name,certificate_fingerprint,role,enrolled_ts,last_seen,status) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(endpoint_id) DO UPDATE SET display_name=excluded.display_name,role=excluded.role,last_seen=excluded.last_seen,status=excluded.status",
            (endpoint["endpoint_id"], endpoint["display_name"], endpoint["certificate_fingerprint"], endpoint["role"], endpoint["enrolled_ts"], time.time(), "enrolled"),
        )
        self.conn.commit()

    def get_endpoint_by_fingerprint(self, fingerprint: str) -> dict | None:
        row = self.conn.execute(
            "SELECT endpoint_id,display_name,certificate_fingerprint,role,enrolled_ts,last_seen,status FROM fleet_endpoints WHERE certificate_fingerprint=?", (fingerprint,)
        ).fetchone()
        return ({"endpoint_id": row[0], "display_name": row[1], "certificate_fingerprint": row[2], "role": row[3], "enrolled_ts": row[4], "last_seen": row[5], "status": row[6]} if row else None)

    def list_endpoints(self) -> list[dict]:
        rows = self.conn.execute("SELECT endpoint_id,display_name,certificate_fingerprint,role,enrolled_ts,last_seen,status FROM fleet_endpoints ORDER BY display_name").fetchall()
        return [{"endpoint_id": row[0], "display_name": row[1], "certificate_fingerprint": row[2], "role": row[3], "enrolled_ts": row[4], "last_seen": row[5], "status": row[6]} for row in rows]

    def open_or_update_incident(
        self, *, correlation_id: str, subject: str, title: str, severity: str,
        risk_score: int = 0, evidence_strength: float = 0.5,
        mitre_techniques: list | None = None,
        recommended_action: str = "", contributing: list[dict] | None = None,
        reason: dict | None = None,
        evidence_refs: list | tuple = (), asset_refs: list | tuple = (),
    ) -> dict:
        """Mở incident mới, hoặc gộp vào incident đang mở của cùng sự việc.

        Khoá gộp là (correlation_id, subject, state='open'): cùng một kiểu
        tấn công nhắm cùng một đối tượng là MỘT sự việc, dù nó kéo dài cả
        buổi. Đóng rồi mà tái diễn thì mở incident mới — để dòng thời gian
        không bị nhập nhèm giữa hai đợt tấn công khác nhau.
        """
        ts = time.time()
        row = self.conn.execute(
            "SELECT incident_id, alert_count, risk_score, confidence, first_seen "
            "FROM incidents WHERE correlation_id=? AND subject=? AND state='open'",
            (correlation_id, subject),
        ).fetchone()
        contributing = contributing or []

        if row:
            incident_id, alert_count, old_score, old_confidence, first_seen = row
            self.conn.execute(
                "UPDATE incidents SET severity=?,risk_score=MAX(risk_score,?),"
                "confidence=MAX(confidence,?),evidence_strength=MAX(evidence_strength,?),"
                "last_seen=?,alert_count=?,"
                "mitre_techniques=?,recommended_action=? WHERE incident_id=?",
                (severity, int(risk_score), float(evidence_strength),
                 float(evidence_strength), ts,
                 alert_count + len(contributing),
                 json.dumps(sorted(set(mitre_techniques or []))), recommended_action, incident_id),
            )
        else:
            incident_id = uuid.uuid4().hex
            first_seen = ts
            self.conn.execute(
                "INSERT INTO incidents(incident_id,correlation_id,subject,title,severity,"
                "risk_score,confidence,evidence_strength,state,mitre_techniques,"
                "recommended_action,alert_count,first_seen,last_seen) "
                "VALUES(?,?,?,?,?,?,?,?,'open',?,?,?,?,?)",
                (incident_id, correlation_id, subject, title, severity, int(risk_score),
                 float(evidence_strength), float(evidence_strength),
                 json.dumps(sorted(set(mitre_techniques or []))),
                 recommended_action, len(contributing), ts, ts),
            )
        for item in contributing:
            self.conn.execute(
                "INSERT OR IGNORE INTO incident_alerts"
                "(incident_id,rule_id,alert_ts,severity,detail,alert_id) "
                "VALUES(?,?,?,?,?,?)",
                (incident_id, str(item.get("rule_id", "")), float(item.get("ts", ts)),
                 str(item.get("severity", "info")), str(item.get("detail", ""))[:500],
                 int(item.get("alert_id", 0) or 0)),
            )
        if reason is not None:
            self._record_correlation_reason(incident_id, reason, ts)
        # Tham chiếu treo bị TỪ CHỐI, không lưu im lặng. Một incident trỏ tới
        # bằng chứng không tồn tại còn tệ hơn một incident không có tham chiếu
        # nào: cái sau nhìn ra được là thiếu, cái trước trông như đầy đủ.
        self._link_incident_refs(incident_id, "evidence", evidence_refs, ts)
        self._link_incident_refs(incident_id, "asset", asset_refs, ts)
        self.conn.commit()
        return {"incident_id": incident_id, "first_seen": first_seen, "last_seen": ts}

    # Bảng gốc cho từng loại tham chiếu. Không có bảng nào ở đây do Phase 1
    # tạo ra — đó là điều kiện: tái dùng khoá chính đã có, không mở namespace
    # thứ hai. `response_job` không nằm trong bảng này vì `response_jobs` đã
    # có sẵn cột `incident_id`; xem `incident_response_jobs()`.
    _REF_SOURCES = {
        "evidence": ("events", "event_id"),
        "asset": ("graph_entities", "entity_id"),
    }

    def _link_incident_refs(self, incident_id: str, kind: str, refs, ts: float) -> None:
        if not refs:
            return
        table, column = self._REF_SOURCES[kind]
        for raw in refs:
            ref = str(raw)
            if not ref:
                raise ValueError(f"tham chiếu {kind} rỗng")
            exists = self.conn.execute(
                f"SELECT 1 FROM {table} WHERE {column}=? LIMIT 1", (ref,)
            ).fetchone()
            if exists is None:
                raise ValueError(
                    f"tham chiếu {kind} treo: {ref!r} không có trong {table}.{column}")
            self.conn.execute(
                "INSERT OR IGNORE INTO incident_refs(incident_id,ref_kind,ref_id,ts) "
                "VALUES(?,?,?,?)", (incident_id, kind, ref, ts))

    _REASON_KINDS = {"rule_combination", "threshold_count"}

    def _record_correlation_reason(self, incident_id: str, reason: dict, ts: float) -> None:
        """Ghi MỘT lý do gộp. Mọi trường đều là đầu vào luật hoặc số đo được.

        Không nhận trường lạ: một khoá không ai đọc là chỗ để nhét văn xuôi vào
        sau này, và lúc đó thì "structured" chỉ còn là tên gọi.
        """
        unknown = set(reason) - {
            "reason_kind", "rule_id", "subject", "window_s", "required_rules",
            "observed_rules", "min_count", "observed_count",
            "first_contributing_ts", "last_contributing_ts",
        }
        if unknown:
            raise ValueError(f"lý do gộp có trường lạ: {sorted(unknown)}")
        kind = str(reason.get("reason_kind", ""))
        if kind not in self._REASON_KINDS:
            raise ValueError(f"reason_kind không hợp lệ: {kind!r}")
        rule_id = str(reason.get("rule_id", ""))
        if not rule_id:
            raise ValueError("lý do gộp phải trỏ về rule đã tạo ra nó")
        self.conn.execute(
            "INSERT OR IGNORE INTO incident_correlation_reasons("
            "incident_id,reason_kind,rule_id,subject,window_s,required_rules,"
            "observed_rules,min_count,observed_count,first_contributing_ts,"
            "last_contributing_ts,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (incident_id, kind, rule_id, str(reason.get("subject", "")),
             float(reason.get("window_s", 0.0)),
             json.dumps(sorted(str(r) for r in reason.get("required_rules", ()))),
             json.dumps(sorted(str(r) for r in reason.get("observed_rules", ()))),
             int(reason.get("min_count", 0) or 0),
             int(reason.get("observed_count", 0) or 0),
             float(reason.get("first_contributing_ts", 0.0)),
             float(reason.get("last_contributing_ts", 0.0)), ts),
        )

    # --- đọc ---

    def incident_correlation_reasons(self, incident_id: str) -> list[dict]:
        """Vì sao những alert này là MỘT sự việc. Thứ tự cố định để so được."""
        rows = self.conn.execute(
            "SELECT reason_kind,rule_id,subject,window_s,required_rules,observed_rules,"
            "min_count,observed_count,first_contributing_ts,last_contributing_ts "
            "FROM incident_correlation_reasons WHERE incident_id=? "
            "ORDER BY first_contributing_ts, rule_id", (str(incident_id),),
        ).fetchall()
        return [{
            "reason_kind": r[0], "rule_id": r[1], "subject": r[2], "window_s": r[3],
            "required_rules": json.loads(r[4]), "observed_rules": json.loads(r[5]),
            "min_count": r[6], "observed_count": r[7],
            "first_contributing_ts": r[8], "last_contributing_ts": r[9],
        } for r in rows]

    def incident_refs(self, incident_id: str, kind: str = "") -> list[dict]:
        if kind and kind not in self._REF_SOURCES:
            raise ValueError(f"loại tham chiếu không hợp lệ: {kind!r}")
        sql = "SELECT ref_kind,ref_id FROM incident_refs WHERE incident_id=?"
        params: list = [str(incident_id)]
        if kind:
            sql += " AND ref_kind=?"
            params.append(kind)
        rows = self.conn.execute(sql + " ORDER BY ref_kind, ref_id", params).fetchall()
        return [{"ref_kind": r[0], "ref_id": r[1]} for r in rows]

    def incident_response_jobs(self, incident_id: str) -> list[str]:
        """Job của một incident, ĐỌC RA từ `response_jobs.incident_id`.

        Không có bảng liên kết riêng: cột đó đã tồn tại từ 2.0, và một bản chép
        thứ hai chỉ thêm một chỗ để lệch.
        """
        rows = self.conn.execute(
            "SELECT job_id FROM response_jobs WHERE incident_id=? ORDER BY job_id",
            (str(incident_id),),
        ).fetchall()
        return [r[0] for r in rows]

    def existing_event_ids(self, refs) -> list[str]:
        """Lọc lấy những `event_id` THỰC SỰ còn trong bảng `events`.

        Vì sao cần bước lọc này thay vì để `_link_incident_refs` ném lỗi: giữ
        dung lượng có thể đã xoá event cũ trong lúc incident mở ra muộn hơn.
        Nếu để lỗi bay lên, một event bị dọn theo chính sách lưu trữ sẽ làm
        SẬP đường xử lý alert — một cơ chế dọn dẹp bình thường không được phép
        biến thành sự cố.

        Ranh giới vì thế là: bên gọi chỉ đưa vào thứ đã kiểm; `Store` vẫn từ
        chối thẳng tham chiếu treo, để lỗi lập trình không lọt qua im lặng.

        Tất định: cùng tập vào + cùng database cho ra cùng danh sách, đã sắp.
        """
        wanted = sorted({str(ref) for ref in refs if str(ref)})
        if not wanted:
            return []
        found = []
        # Chia lô: một câu IN với vài nghìn tham số vượt trần biến của SQLite.
        for start in range(0, len(wanted), 200):
            batch = wanted[start:start + 200]
            placeholders = ",".join("?" * len(batch))
            # `event_id != ''` KHÔNG thừa. Index trên `event_id` là index MỘT
            # PHẦN (`WHERE event_id != ''`), vì 892 nghìn dòng có sẵn từ schema
            # v4 mang chuỗi rỗng. SQLite chỉ dùng được index một phần khi câu
            # truy vấn CHỨNG MINH được vị từ của nó — mà một tham số ràng buộc
            # thì không chứng minh được gì.
            #
            # Đo trên database production, 1.837.445 dòng:
            #     không có vị từ:  256,93 ms   SCAN events
            #     có vị từ:          0,18 ms   SEARCH ... USING COVERING INDEX
            #
            # Đây là ĐƯỜNG NÓNG: chạy mỗi lần correlation mở một incident. Cùng
            # một cái bẫy đã làm agent đốt trọn một nhân CPU ở 2.0, và tôi vừa
            # đặt lại nó ở Phase 1.
            rows = self.conn.execute(
                f"SELECT event_id FROM events WHERE event_id != '' "
                f"AND event_id IN ({placeholders})",
                batch,
            ).fetchall()
            found.extend(r[0] for r in rows)
        return sorted(set(found))

    def incidents_for_alert(self, alert_id: int) -> list[str]:
        """Cùng một alert thuộc những incident nào.

        Tiêu chí chấp nhận của Phase 1: một event không được âm thầm nằm trong
        hai incident mâu thuẫn nhau mà không có quan hệ tường minh. Trước v10
        câu hỏi này KHÔNG trả lời được — liên kết là cặp (rule_id, alert_ts), mà
        `alert_ts` thì bị gộp trùng làm dịch đi. Với `alert_id` thì nó là một
        câu truy vấn, nên "âm thầm" không còn là trạng thái có thể xảy ra.
        """
        if int(alert_id) <= 0:
            return []
        rows = self.conn.execute(
            "SELECT DISTINCT incident_id FROM incident_alerts WHERE alert_id=? "
            "ORDER BY incident_id", (int(alert_id),),
        ).fetchall()
        return [r[0] for r in rows]

    def entity_ids_for_key(self, canonical_key: str, limit: int = 20) -> list[str]:
        """Thực thể trong đồ thị mang đúng khoá này. Dùng để nối incident với
        tài sản mà KHÔNG tạo bảng ánh xạ mới: `graph_entities.canonical_key` đã
        là chỗ trả lời câu hỏi 'MAC/IP này là thực thể nào'."""
        key = str(canonical_key)
        if not key:
            return []
        rows = self.conn.execute(
            "SELECT entity_id FROM graph_entities WHERE canonical_key=? "
            "ORDER BY entity_id LIMIT ?", (key, int(limit)),
        ).fetchall()
        return [r[0] for r in rows]

    def incident_alert_ids(self, incident_id: str) -> list[int]:
        """`alerts.id` của các alert đóng góp. Dòng cũ (v9) có alert_id=0 và
        bị bỏ qua — chúng không có tham chiếu, và bịa ra một cái thì tệ hơn."""
        rows = self.conn.execute(
            "SELECT DISTINCT alert_id FROM incident_alerts "
            "WHERE incident_id=? AND alert_id>0 ORDER BY alert_id",
            (str(incident_id),),
        ).fetchall()
        return [int(r[0]) for r in rows]

    def set_incident_state(self, incident_id: str, state: str) -> bool:
        if state not in {"open", "investigating", "contained", "resolved", "false_positive"}:
            raise ValueError("invalid incident state")
        result = self.conn.execute(
            "UPDATE incidents SET state=?,last_seen=? WHERE incident_id=?",
            (state, time.time(), incident_id),
        )
        self.conn.commit()
        return result.rowcount > 0

    def list_incidents(self, limit: int = 200, include_closed: bool = True) -> list[dict]:
        query = (
            "SELECT incident_id,correlation_id,subject,title,severity,risk_score,confidence,"
            "state,mitre_techniques,recommended_action,alert_count,first_seen,last_seen "
            "FROM incidents "
        )
        if not include_closed:
            query += "WHERE state IN ('open','investigating') "
        query += "ORDER BY risk_score DESC, last_seen DESC LIMIT ?"
        rows = self.conn.execute(query, (int(limit),)).fetchall()
        return [{
            "incident_id": r[0], "correlation_id": r[1], "subject": r[2], "title": r[3],
            "severity": r[4], "risk_score": r[5], "confidence": r[6], "state": r[7],
            "mitre_techniques": json.loads(r[8] or "[]"), "recommended_action": r[9],
            "alert_count": r[10], "first_seen": r[11], "last_seen": r[12],
        } for r in rows]

    def incident(self, incident_id: str) -> dict | None:
        """Một dòng incident theo id. `None` nếu không có.

        `list_incidents` đã trả về cùng các cột, nhưng lấy 200 dòng rồi lọc một
        dòng là đọc thừa — và một báo cáo sự cố tra đúng một incident.
        """
        row = self.conn.execute(
            "SELECT incident_id,correlation_id,subject,title,severity,risk_score,"
            "confidence,state,mitre_techniques,recommended_action,alert_count,"
            "first_seen,last_seen FROM incidents WHERE incident_id=?",
            (str(incident_id),),
        ).fetchone()
        if row is None:
            return None
        return {
            "incident_id": row[0], "correlation_id": row[1], "subject": row[2],
            "title": row[3], "severity": row[4], "risk_score": row[5],
            "confidence": row[6], "state": row[7],
            "mitre_techniques": json.loads(row[8] or "[]"),
            "recommended_action": row[9], "alert_count": row[10],
            "first_seen": row[11], "last_seen": row[12],
        }

    def incident_subjects(self, incident_id: str) -> list[str]:
        """Đối tượng của một incident — điểm bắt đầu cho một cuộc điều tra.

        Gồm cả `subject` của chính incident và `subject` của các alert thuộc
        về nó: correlation ghép theo một đối tượng, nhưng các alert bên trong
        có thể trỏ tới nhiều đối tượng khác nhau, và bỏ sót chúng nghĩa là bắt
        đầu điều tra từ một nửa sự việc.
        """
        row = self.conn.execute(
            "SELECT subject FROM incidents WHERE incident_id=?", (str(incident_id),)
        ).fetchone()
        subjects = [row[0]] if row else []
        subjects.extend(
            item[0] for item in self.conn.execute(
                "SELECT DISTINCT a.subject FROM alerts a "
                "JOIN incident_alerts ia ON ia.rule_id=a.rule_id AND ia.alert_ts=a.ts "
                "WHERE ia.incident_id=? LIMIT 50", (str(incident_id),)
            ).fetchall()
        )
        return [s for s in dict.fromkeys(subjects) if s]

    def incident_alerts(self, incident_id: str, limit: int = 500) -> list[dict]:
        rows = self.conn.execute(
            "SELECT rule_id,alert_ts,severity,detail FROM incident_alerts "
            "WHERE incident_id=? ORDER BY alert_ts ASC LIMIT ?", (incident_id, int(limit)),
        ).fetchall()
        return [{"rule_id": r[0], "ts": r[1], "severity": r[2], "detail": r[3]} for r in rows]

    def revoke_endpoint(self, endpoint_id: str) -> bool:
        """Thu hồi một probe/endpoint. Xoá hẳn dòng chứ không chỉ đổi status:
        `get_endpoint_by_fingerprint` là thứ duy nhất log_ingest tra cứu, nên
        thu hồi phải làm cho fingerprint đó biến mất, không để lại đường vào."""
        result = self.conn.execute(
            "DELETE FROM fleet_endpoints WHERE endpoint_id=?", (endpoint_id,)
        )
        self.conn.commit()
        return result.rowcount > 0

    def set_collector_health(
        self, component: str, backend: str, healthy: bool, detail: str,
        *, state: str | None = None, started_ts: float | None = None,
        last_heartbeat: float | None = None, last_event: float | None = None,
        restart_count: int | None = None, dropped_events: int | None = None,
        error_message: str = "",
    ) -> None:
        """Upsert a detailed collector state while preserving unspecified counters.

        `dropped_events` nghĩa là: **số event telemetry mà thành phần này đã
        quan sát được nhưng không giao đi**, tính từ lúc nó khởi động. Trước
        đây trường này không được định nghĩa ở đâu và chỉ có hai hàng bus ghi
        vào, nên `kernel_telemetry.file_write` hiện `dropped_events = 0` trong
        khi `detail` nói "đã bỏ 13992 event do giới hạn tốc độ" — thứ đọc được
        bằng mắt biết là có mất, thứ đọc được bằng máy nói là không.

        Thuộc về trường này: gói bị bỏ vì trần tốc độ, event bị bỏ vì hàng đợi
        đầy. Cả hai đều là mất MỘT event một.

        KHÔNG thuộc về trường này:

        - Người xem giao diện đọc chậm (`evidence_feed`). Đó là giới hạn màn
          hình, không phải mất telemetry — event vẫn nằm nguyên trong database.
        - Tràn trần khoá của `FlowAggregator`. Đơn vị khác hẳn: mất một KHOÁ
          gộp, không phải một event. Cộng chung vào đây sẽ ra một con số không
          còn nghĩa gì. Nó ở lại `detail`.

        Truyền None để GIỮ NGUYÊN giá trị cũ; truyền một số để ghi đè.
        """
        now_ts = time.time()
        current = self.conn.execute(
            "SELECT started_ts,last_heartbeat,last_event,restart_count,dropped_events "
            "FROM collector_health WHERE component=?", (component,)
        ).fetchone()
        old = current or (0.0, 0.0, 0.0, 0, 0)
        resolved_state = state or ("running" if healthy else "degraded")
        values = (
            component, backend, int(healthy), detail, now_ts, resolved_state,
            started_ts if started_ts is not None else (old[0] or now_ts),
            last_heartbeat if last_heartbeat is not None else (old[1] or now_ts),
            last_event if last_event is not None else old[2],
            restart_count if restart_count is not None else old[3],
            dropped_events if dropped_events is not None else old[4],
            error_message,
        )
        self.conn.execute(
            "INSERT OR REPLACE INTO collector_health("
            "component,backend,healthy,detail,updated_ts,state,started_ts,last_heartbeat,"
            "last_event,restart_count,dropped_events,error_message) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            values,
        )
        self.conn.commit()

    def touch_collector_event(self, component: str, event_ts: float | None = None) -> None:
        """Record event progress at most once every five seconds per component."""
        now_ts = time.time()
        if now_ts - self._health_touch.get(component, 0.0) < 5.0:
            return
        self._health_touch[component] = now_ts
        changed = self.conn.execute(
            "UPDATE collector_health SET last_event=?,last_heartbeat=?,updated_ts=? WHERE component=?",
            (event_ts or now_ts, now_ts, now_ts, component),
        ).rowcount
        if not changed:
            self.set_collector_health(
                component, component, True, "events observed", state="running",
                last_event=event_ts or now_ts,
            )
        else:
            self.conn.commit()

    def set_system_health(
        self, metric: str, value: float, unit: str, state: str = "healthy", detail: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO system_health(metric,value,unit,state,detail,updated_ts) "
            "VALUES(?,?,?,?,?,?)",
            (metric, float(value), unit, state, detail, time.time()),
        )
        self.conn.commit()

    def system_health(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT metric,value,unit,state,detail,updated_ts FROM system_health ORDER BY metric"
        ).fetchall()
        return [
            {"metric": row[0], "value": row[1], "unit": row[2], "state": row[3],
             "detail": row[4], "updated_ts": row[5]}
            for row in rows
        ]

    def collector_health(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT component,backend,healthy,detail,updated_ts,state,started_ts,last_heartbeat,"
            "last_event,restart_count,dropped_events,error_message "
            "FROM collector_health ORDER BY component"
        ).fetchall()
        now_ts = time.time()
        return [
            {"component": row[0], "backend": row[1], "healthy": bool(row[2]),
             "detail": row[3], "updated_ts": row[4], "state": row[5],
             "started_ts": row[6], "last_heartbeat": row[7], "last_event": row[8],
             "restart_count": row[9], "dropped_events": row[10],
             "error_message": row[11], "uptime_s": max(0.0, now_ts - row[6]) if row[6] else 0.0}
            for row in rows
        ]

    def recent_audit_logs(self, since_ts: float = 0.0, limit: int = 2000) -> list[dict]:
        """Nhật ký hành động đã chạy, mới nhất trước. UI dùng để đếm ô "Hành
        động đã thực hiện" ở tab Báo cáo — trước đây ô đó luôn hiện "—" vì
        không có accessor nào đọc bảng audit_log từ phía UI."""
        import json

        rows = self.conn.execute(
            "SELECT ts, action_id, params, result FROM audit_log "
            "WHERE ts >= ? ORDER BY ts DESC LIMIT ?",
            (since_ts, limit),
        ).fetchall()
        out = []
        for ts, action_id, params, result in rows:
            try:
                parsed = json.loads(params) if params else {}
            except (ValueError, TypeError):
                parsed = {}
            out.append({"ts": ts, "action_id": action_id, "params": parsed, "result": result})
        return out

    def close(self) -> None:
        self.conn.close()
