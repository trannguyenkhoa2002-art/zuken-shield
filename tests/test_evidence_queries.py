"""Query service read-only: trần cứng, redaction, audit, và fuzz (mục 1.4).

Gate Phase 1, điều cuối: "Query fuzz test không gây SQL injection hoặc
unbounded result."

Lớp này sẽ đứng giữa AI analyst và database ở Phase 2. Nó được test khắt khe
từ bây giờ vì một ranh giới thêm vào sau khi đã có người đi vòng qua nó thì
không còn là ranh giới.
"""

from __future__ import annotations

import random
import time

import pytest

from shield.agent.store import Store
from shield.common.models import Event
from shield.evidence.graph import MAX_LIMIT
from shield.evidence.models import entity_id_for
from shield.evidence.queries import (
    DEFAULT_LIMIT,
    MAX_DEPTH,
    REDACTED,
    EvidenceQueries,
    QueryAudit,
    QueryTimeout,
    redact,
)
from shield.evidence.resolver import resolve


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "shield.db")


def ingest(store: Store, event: Event) -> None:
    with store.conn:
        store.conn.execute(
            "INSERT OR IGNORE INTO events(ts,source,kind,data,origin,trust,event_id,"
            "ts_ingested,content_hash,signature_status,collector_version) "
            "VALUES(?,?,?,'{}',?,?,?,?,?,'unsigned','')",
            (event.ts, event.source, event.kind,
             str(event.data.get("origin") or event.origin), str(event.trust),
             event.event_id, event.ts_ingested, event.content_hash_),
        )
        store.graph.ingest(*resolve(event))


@pytest.fixture()
def queries(store):
    return EvidenceQueries(store.conn, caller="test")


@pytest.fixture()
def populated(store, queries):
    base = 1_000_000.0
    ingest(store, Event(base, "journal", "ssh_login",
                        {"user": "khoa", "src_ip": "192.168.1.20", "method": "publickey"}))
    ingest(store, Event(base + 1, "kernel", "process_exec",
                        {"pid": 500, "start_ticks": "10", "comm": "bash", "exe": "/bin/bash"}))
    ingest(store, Event(base + 2, "kernel", "process_exec",
                        {"pid": 501, "start_ticks": "11", "comm": "curl", "exe": "/usr/bin/curl",
                         "ppid": 500, "parent_start_ticks": "10"}))
    ingest(store, Event(base + 3, "kernel", "file_write",
                        {"pid": 501, "start_ticks": "11", "path": "/tmp/payload"}))
    ingest(store, Event(base + 4, "kernel", "socket_connect",
                        {"pid": 501, "start_ticks": "11", "remote_ip": "93.184.216.34",
                         "remote_port": 443}))
    return queries


# --- không nhận SQL ---


INJECTIONS = [
    "'; DROP TABLE graph_edges; --",
    "' OR '1'='1",
    "1; DELETE FROM events",
    "x' UNION SELECT sql FROM sqlite_master --",
    "%",
    "_",
    "*",
    '" OR ""="',
    "\x00",
    "../../etc/passwd",
    "\\'; PRAGMA writable_schema=1; --",
]


@pytest.mark.parametrize("payload", INJECTIONS)
def test_injection_in_an_entity_id_changes_nothing(populated, store, payload):
    """Tham số đi qua placeholder; không có đường nào thành một phần câu lệnh."""
    before = store.graph.counts()
    assert populated.get_entity(payload) is None
    assert populated.get_neighbors(payload) == []
    assert store.graph.counts() == before
    assert store.conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='graph_edges'").fetchone()[0] == 1


@pytest.mark.parametrize("payload", INJECTIONS)
def test_injection_in_a_canonical_key_changes_nothing(populated, store, payload):
    before = store.graph.counts()
    assert populated.find_entity("host", payload) is None
    assert store.graph.counts() == before


def test_wildcards_are_not_treated_as_patterns(populated):
    """`%` phải là một chuỗi bình thường, không phải 'khớp mọi thứ'.

    Nếu ở đâu đó dùng LIKE, một dấu `%` sẽ kéo về toàn bộ bảng — đúng nghĩa
    unbounded result mà gate cấm.
    """
    assert populated.find_entity("host", "%") is None
    assert populated.get_entity("%") is None


def test_an_unknown_entity_type_is_refused_not_passed_through(populated):
    with pytest.raises(ValueError):
        populated.list_entities("'; DROP TABLE graph_entities; --")
    with pytest.raises(ValueError):
        populated.find_entity("khong_ton_tai", "x")


def test_an_unknown_relation_is_refused(populated):
    with pytest.raises(ValueError):
        populated.get_neighbors("host:x", relations=["'; DELETE FROM graph_edges; --"])


def test_an_unknown_direction_is_refused(populated):
    with pytest.raises(ValueError):
        populated.get_neighbors("host:x", direction="sideways")


# --- trần cứng ---


@pytest.mark.parametrize("limit", [10 ** 9, -1, 0, 10 ** 18, "500000", None, "abc", 1.5])
def test_no_caller_can_ask_for_an_unbounded_result(populated, limit):
    """Kể cả mã của chính Shield cũng không xin được không giới hạn."""
    for rows in (populated.get_neighbors("host:x", limit=limit),
                 populated.list_entities("host", limit=limit),
                 populated.get_network_peers("ip:x", limit=limit)):
        assert isinstance(rows, list)
        assert len(rows) <= MAX_LIMIT


def test_a_large_graph_is_still_capped(store, queries):
    for pid in range(MAX_LIMIT + 250):
        ingest(store, Event(1_000_000.0 + pid, "kernel", "process_exec",
                            {"pid": pid, "start_ticks": "1", "comm": "x"}))
    rows = queries.get_neighbors(entity_id_for("host", "local"), limit=10 ** 9)
    assert len(rows) == MAX_LIMIT


def test_depth_is_capped_regardless_of_what_is_asked(populated):
    """Mỗi bước nhân số cạnh lên; một truy vấn sâu trên node trung tâm sẽ kéo
    về nửa graph."""
    deep = populated.get_neighbors(entity_id_for("host", "local"), depth=10 ** 6)
    assert len(deep) <= MAX_LIMIT
    entry = next(e for e in reversed(populated.audit.entries) if e["query"] == "get_neighbors")
    assert entry["params"]["depth"] == MAX_DEPTH


def test_ancestry_terminates_on_a_cycle(store, queries):
    """Dữ liệu hỏng có thể tạo chu trình cha-con; đi theo con trỏ cha mà không
    có trần sẽ chạy mãi."""
    ingest(store, Event(1000.0, "kernel", "process_exec",
                        {"pid": 1, "start_ticks": "1", "ppid": 2, "parent_start_ticks": "2"}))
    ingest(store, Event(1001.0, "kernel", "process_exec",
                        {"pid": 2, "start_ticks": "2", "ppid": 1, "parent_start_ticks": "1"}))
    started = time.monotonic()
    chain = queries.get_process_ancestry(entity_id_for("process", "local:1:1"))
    assert time.monotonic() - started < 2.0
    assert len(chain) <= 32


# --- redaction ---


def test_secrets_are_redacted_by_key_name():
    payload = {"user": "khoa", "password": "hunter2", "api_key": "abc",
               "Authorization": "Bearer x", "session_id": "s1", "note": "bình thường"}
    cleaned = redact(payload)
    assert cleaned["user"] == "khoa" and cleaned["note"] == "bình thường"
    for key in ("password", "api_key", "Authorization", "session_id"):
        assert cleaned[key] == REDACTED


def test_secrets_are_redacted_by_value_shape():
    """Khoá vô hại nhưng giá trị rõ ràng là bí mật."""
    assert redact({"note": "-----BEGIN RSA PRIVATE KEY-----\nAAA"})["note"] == REDACTED
    assert redact({"h": "Bearer eyJhbGciOiJIUzI1NiJ9abcdefghij"})["h"] == REDACTED


def test_redaction_reaches_into_nested_structures():
    payload = {"outer": [{"inner": {"token": "t"}}, {"ok": "giữ nguyên"}]}
    cleaned = redact(payload)
    assert cleaned["outer"][0]["inner"]["token"] == REDACTED
    assert cleaned["outer"][1]["ok"] == "giữ nguyên"


def test_query_results_are_redacted_before_leaving_the_layer(store, queries):
    """Che TRƯỚC khi rời lớp này, không phải ở chỗ hiển thị.

    Che ở UI nghĩa là bí mật đã đi qua log, qua IPC và qua prompt của model
    trước khi ai đó nghĩ tới việc che nó.
    """
    ingest(store, Event(1000.0, "kernel", "process_exec",
                        {"pid": 9, "start_ticks": "1", "comm": "x",
                         "exe": "/usr/bin/x", "password": "hunter2"}))
    entity = queries.find_entity("process", "local:9:1")
    assert "hunter2" not in str(entity)


def test_audited_parameters_are_redacted_too(queries):
    """Nhật ký truy vấn không được trở thành chỗ rò bí mật."""
    queries.find_entity("host", "token=abcdef")
    queries.audit.record("fake", {"password": "hunter2"}, 0, 0.0, "test")
    assert "hunter2" not in str(queries.audit.entries)


# --- audit ---


def test_every_query_is_recorded(populated):
    populated.audit.entries.clear()
    populated.counts()
    populated.get_entity("host:x")
    names = [entry["query"] for entry in populated.audit.entries]
    assert names == ["counts", "get_entity"]
    for entry in populated.audit.entries:
        assert entry["caller"] == "test"
        assert entry["elapsed_s"] >= 0
        assert "ts" in entry


def test_a_failing_query_is_recorded_with_its_error(queries):
    with pytest.raises(ValueError):
        queries.list_entities("khong_ton_tai")
    # ValueError bị ném trước khi vào _run, nên không có dòng nhật ký — kiểm
    # rằng lỗi PHÁT SINH bên trong thì có ghi.
    queries.audit.entries.clear()
    with pytest.raises(RuntimeError):
        queries._run("no_op", {}, lambda _d: (_ for _ in ()).throw(RuntimeError("vỡ")))
    assert queries.audit.entries[-1]["error"].startswith("RuntimeError")


def test_the_audit_log_is_bounded(queries):
    queries.audit.max_entries = 50
    for i in range(200):
        queries.audit.record("q", {"i": i}, 0, 0.0, "test")
    assert len(queries.audit.entries) == 50
    assert queries.audit.entries[-1]["params"]["i"] == 199, "phải giữ dòng MỚI nhất"


def test_an_audit_log_can_be_shared_between_query_objects(store):
    shared = QueryAudit()
    EvidenceQueries(store.conn, caller="a", audit=shared).counts()
    EvidenceQueries(store.conn, caller="b", audit=shared).counts()
    assert [entry["caller"] for entry in shared.entries] == ["a", "b"]


# --- timeout ---


def test_a_slow_query_is_cut_off(store):
    slow = EvidenceQueries(store.conn, caller="test", timeout_s=0.1)
    with pytest.raises(QueryTimeout):
        slow._run("slow", {}, lambda deadline: (time.sleep(0.2),
                                                slow._check_deadline(deadline))[1])
    assert slow.audit.entries[-1]["error"]


def test_the_timeout_has_a_floor(store):
    """timeout_s=0 nghĩa là mọi câu đều hỏng ngay — không dùng được."""
    assert EvidenceQueries(store.conn, timeout_s=0).timeout_s >= 0.1
    assert EvidenceQueries(store.conn, timeout_s=-5).timeout_s >= 0.1


# --- ngữ nghĩa ---


def test_a_timeline_reads_in_the_order_things_happened(populated):
    """Người điều tra đọc một sự việc theo chiều nó đã xảy ra."""
    curl = entity_id_for("process", "local:501:11")
    timeline = populated.get_entity_timeline(curl, window_s=86400)
    stamps = [edge["first_seen"] for edge in timeline]
    assert stamps == sorted(stamps)
    assert {edge["relation"] for edge in timeline} >= {"wrote", "connected_to", "spawned"}


def test_ancestry_walks_up_to_the_parent(populated):
    chain = populated.get_process_ancestry(entity_id_for("process", "local:501:11"))
    assert [item["entity"]["canonical_key"] for item in chain] == ["local:500:10"]


def test_network_peers_answer_the_reverse_question(populated):
    peers = populated.get_network_peers(entity_id_for("ip", "93.184.216.34"))
    assert [edge["relation"] for edge in peers] == ["connected_to"]


def test_the_integrity_report_sees_a_broken_graph(populated, store):
    assert populated.integrity_report()["orphan_count"] == 0
    with store.conn:
        store.conn.execute("DELETE FROM events")
    assert populated.integrity_report()["orphan_count"] > 0


# --- fuzz ---


def test_random_garbage_never_crashes_and_never_exceeds_the_cap(populated):
    """Gate Phase 1: fuzz không gây SQL injection cũng không cho kết quả vô hạn.

    Mọi phương thức đọc bị bắn dữ liệu rác. Điều kiện đạt là: không ném lỗi lạ,
    không vượt trần, và graph không thay đổi.
    """
    random.seed(20260822)
    alphabet = "abc'\"\\;%_-*() \t\n\x00[]{}/<>=|&$#0123456789ÁđêÀ" + chr(0x1F600)
    methods = [
        populated.get_entity, populated.get_neighbors, populated.get_process_ancestry,
        populated.get_file_history, populated.get_user_login_history,
        populated.get_network_peers, populated.get_evidence, populated.get_entity_timeline,
    ]
    for _ in range(400):
        junk = "".join(random.choice(alphabet) for _ in range(random.randint(0, 60)))
        method = random.choice(methods)
        try:
            result = method(junk)
        except (ValueError, TypeError) as exc:
            # Từ chối tường minh là hành vi đúng; im lặng nuốt thì không.
            assert str(exc)
            continue
        if isinstance(result, list):
            assert len(result) <= MAX_LIMIT


def test_fuzzing_leaves_the_database_untouched(populated, store):
    random.seed(1)
    before = store.graph.counts()
    tables_before = store.conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    for _ in range(200):
        junk = "".join(random.choice("';-- \x00%_") for _ in range(random.randint(0, 30)))
        populated.get_entity(junk)
        populated.get_neighbors(junk, limit=random.randint(-5, 10 ** 6))
    assert store.graph.counts() == before
    assert store.conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0] == tables_before


def test_fuzzing_relation_filters_is_always_refused(populated):
    random.seed(2)
    for _ in range(100):
        junk = "".join(random.choice("abc';-- ") for _ in range(random.randint(1, 20)))
        with pytest.raises(ValueError):
            populated.get_neighbors("host:x", relations=[junk])


def test_the_default_limit_is_well_below_the_hard_cap():
    """Trần cứng là lưới an toàn, không phải mặc định."""
    assert DEFAULT_LIMIT < MAX_LIMIT


# --- node trung tâm ---


def test_traversal_does_not_expand_through_a_hub(store, queries):
    """Đo trên dữ liệu thật: thực thể `host` cục bộ có bậc 23.588 trên 23.598
    cạnh — gần như MỌI cạnh đều chạm vào nó.

    Đi xuyên qua nó biến "tiến trình này liên quan tới gì" thành "mọi thứ từng
    chạy trên máy này". Kết quả vẫn dưới trần cứng nên nhìn thì an toàn, nhưng
    500 dòng ngẫu nhiên trong 23 nghìn tệ hơn không trả gì: nó trông như một
    câu trả lời.
    """
    from shield.evidence.queries import HUB_DEGREE

    # Bắt đầu từ 1: PID 0 không phải một tiến trình, và resolver từ chối nó.
    for pid in range(1, HUB_DEGREE + 50):
        ingest(store, Event(1_000_000.0 + pid, "kernel", "process_exec",
                            {"pid": pid, "start_ticks": "1", "comm": "x"}))
    # Một tiến trình có thêm một cạnh riêng, không đi qua host.
    ingest(store, Event(2_000_000.0, "kernel", "socket_connect",
                        {"pid": 1, "start_ticks": "1", "remote_ip": "1.1.1.1",
                         "remote_port": 443}))

    one_process = entity_id_for("process", "local:1:1")
    deep = queries.get_neighbors(one_process, depth=3, limit=200)

    # Cạnh của chính nó có mặt...
    assert {edge["relation"] for edge in deep} >= {"ran_on", "connected_to"}
    # ...nhưng hàng trăm tiến trình không liên quan thì không.
    others = [edge for edge in deep
              if edge["src_id"] not in {one_process}
              and edge["relation"] == "ran_on"]
    assert len(others) < HUB_DEGREE, "truy vấn đã đi xuyên qua node trung tâm"


def test_asking_about_the_hub_directly_still_answers(store, queries):
    """Không mở rộng QUA node trung tâm không có nghĩa là giấu nó đi."""
    from shield.evidence.queries import HUB_DEGREE

    for pid in range(1, HUB_DEGREE + 50):
        ingest(store, Event(1_000_000.0 + pid, "kernel", "process_exec",
                            {"pid": pid, "start_ticks": "1", "comm": "x"}))
    rows = queries.get_neighbors(entity_id_for("host", "local"), depth=1, limit=200)
    assert len(rows) == 200


def test_degree_counting_stops_early(store, queries):
    """Chỉ cần biết 'lớn hơn ngưỡng hay không'."""
    from shield.evidence.queries import HUB_DEGREE

    for pid in range(1, HUB_DEGREE + 200):
        ingest(store, Event(1_000_000.0 + pid, "kernel", "process_exec",
                            {"pid": pid, "start_ticks": "1", "comm": "x"}))
    assert queries._degree(entity_id_for("host", "local")) == HUB_DEGREE + 1
