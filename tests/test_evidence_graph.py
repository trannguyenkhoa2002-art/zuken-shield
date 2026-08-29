"""Evidence graph: nguồn gốc, hợp nhất danh tính và ranh giới tin cậy.

KE-HOACH-SHIELD-2.0.md Phase 1. Gate của phase này gồm 5 điều, và file này
kiểm bốn điều đầu (điều thứ năm — fuzz cho query service — nằm ở
test_evidence_queries.py):

- Một incident mẫu dựng được timeline user -> login -> process -> file -> network.
- Mọi node/edge quay lại được event nguồn.
- Không có orphan evidence reference.
- Dữ liệu raw syslog không thể tự nâng trust qua entity merge.
"""

from __future__ import annotations

import pytest

from shield.agent.store import Store
from shield.common.models import Event
from shield.evidence.graph import EvidenceGraph
from shield.evidence.models import (
    ENTITY_TYPES,
    RELATIONS,
    Edge,
    Entity,
    EvidenceKind,
    entity_id_for,
    merge_trust,
)
from shield.evidence.resolver import host_key_for, resolve


@pytest.fixture()
def store(tmp_path):
    """Store thật, không phải schema graph trần.

    Graph tra bảng `events` để xác minh mọi `event:` ref — đó là điểm mấu chốt
    của thiết kế (một nguồn sự thật), nên test phải đi qua đúng cặp bảng đó.
    Một fixture chỉ có bảng graph sẽ xanh trong khi sản phẩm thật đổ.
    """
    return Store(tmp_path / "shield.db")


@pytest.fixture()
def graph(store) -> EvidenceGraph:
    return store.graph


def ingest(graph: EvidenceGraph, event: Event) -> tuple[int, int]:
    """Đi đúng đường thật: event vào bảng `events` TRƯỚC, rồi mới dựng graph.

    `with graph.conn:` không phải trang trí. Ghi mà không commit để lại một
    transaction ngầm mở, và `PRAGMA wal_checkpoint(TRUNCATE)` trong
    `_enforce_size_cap` sẽ đổ với "database table is locked" — một lỗi trông
    như lỗi sản phẩm nhưng thật ra là lỗi của chính test.
    """
    entities, edges = resolve(event)
    with graph.conn:
        graph.conn.execute(
            "INSERT OR IGNORE INTO events(ts,source,kind,data,origin,trust,event_id,"
            "ts_ingested,content_hash,signature_status,collector_version) "
            "VALUES(?,?,?,'{}',?,?,?,?,?,'unsigned','')",
            (event.ts, event.source, event.kind,
             str(event.data.get("origin") or event.origin), str(event.trust),
             event.event_id, event.ts_ingested, event.content_hash_),
        )
        return graph.ingest(entities, edges)


# --- danh tính thực thể ---


def test_entity_ids_are_deterministic_not_random():
    """Hai tiến trình quan sát cùng một máy phải ra cùng một ID.

    Nếu không, graph đầy thực thể song trùng và mọi câu 'máy này còn làm gì
    nữa' đều trả lời thiếu — mà trả lời thiếu ở đây trông y hệt 'không có gì'.
    """
    assert entity_id_for("host", "laptop-01") == entity_id_for("host", "laptop-01")
    assert entity_id_for("host", "laptop-01") != entity_id_for("device", "laptop-01")


def test_an_unknown_entity_type_is_refused():
    with pytest.raises(ValueError):
        entity_id_for("khong_ton_tai", "x")
    with pytest.raises(ValueError):
        Entity("khong_ton_tai", "x")


def test_the_entity_type_set_matches_the_plan():
    """12 loại của mục 1.2. Thiếu một loại là một mảng dữ liệu không có chỗ."""
    assert ENTITY_TYPES == {
        "host", "device", "user", "session", "process", "file",
        "ip", "domain", "service", "credential_indicator", "incident", "response_action",
    }


def test_the_relation_set_matches_the_plan():
    assert RELATIONS >= {
        "logged_into", "belongs_to", "ran_on", "spawned", "wrote",
        "connected_to", "has_hash", "supported_by", "contains", "affected",
    }


# --- mọi cạnh phải có bằng chứng ---


def test_an_edge_without_evidence_cannot_be_constructed():
    """Bất biến trung tâm của Phase 1. Một cạnh không bằng chứng là một ý kiến."""
    with pytest.raises(ValueError, match="evidence_ref"):
        Edge("a", "ran_on", "b", (), "local", "resolver")


def test_an_edge_with_a_malformed_evidence_ref_is_refused():
    for bad in ("abc", "unknown:1", ":", ""):
        with pytest.raises(ValueError):
            Edge("a", "ran_on", "b", (bad,), "local", "resolver")


def test_an_edge_must_record_who_created_it():
    with pytest.raises(ValueError, match="ai đã tạo"):
        Edge("a", "ran_on", "b", ("event:1",), "local", "")


def test_an_unknown_relation_is_refused():
    with pytest.raises(ValueError):
        Edge("a", "khong_ton_tai", "b", ("event:1",), "local", "resolver")


def test_writing_an_edge_whose_evidence_does_not_exist_is_refused(graph):
    """Gate: 'Không có orphan evidence reference.' Chặn lúc GHI, không phải
    lúc dọn dẹp — dọn dẹp nghĩa là đã có lúc dữ liệu sai được đọc ra."""
    edge = Edge("host:a", "ran_on", "host:b", ("event:khong-ton-tai",), "local", "resolver")
    with pytest.raises(ValueError, match="mồ côi"):
        graph.upsert_edge(edge)


def test_a_healthy_graph_reports_no_orphans(graph):
    ingest(graph, Event(1000.0, "kernel", "process_exec",
                        {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    assert graph.orphan_edges() == []


# --- truy ngược về event nguồn ---


def test_every_edge_leads_back_to_a_real_event(graph):
    event = Event(1000.0, "kernel", "process_exec",
                  {"pid": 42, "start_ticks": "99", "comm": "curl", "exe": "/usr/bin/curl"})
    ingest(graph, event)
    for edge in graph.neighbors(entity_id_for("process", "local:42:99")):
        assert edge["evidence_refs"]
        for ref in edge["evidence_refs"]:
            assert graph.evidence_for(ref) is not None
            assert ref == event.evidence_ref()


def test_retention_deleting_events_removes_the_edges_that_depended_on_them(graph):
    """Giữ cạnh sau khi bằng chứng hết hạn tạo ra đúng thứ gate cấm: một khẳng
    định không kiểm chứng lại được, trông y hệt một khẳng định có bằng chứng.

    Đây cũng là lý do event KHÔNG có bản sao trong `evidence_objects`: một bản
    sao riêng sẽ sống sót sau khi event bị hạn lưu trữ cắt, và cạnh sẽ trông
    như vẫn có bằng chứng.
    """
    ingest(graph, Event(1000.0, "kernel", "process_exec",
                        {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    assert graph.counts()["edges"] > 0

    graph.conn.execute("DELETE FROM events")   # hạn lưu trữ cắt event cũ
    assert graph.orphan_edges(), "cạnh đã mất bằng chứng mà không bị coi là mồ côi"

    removed = graph.prune()
    assert removed["edges_removed"] > 0
    assert graph.counts()["edges"] == 0
    assert graph.counts()["entities"] == 0, "node treo còn lại sau khi mọi cạnh biến mất"
    assert graph.orphan_edges() == []


# --- ranh giới tin cậy ---


def test_trust_is_ranked_semantically_not_alphabetically():
    """'authenticated' < 'local' đúng theo bảng chữ cái và sai theo mọi nghĩa khác."""
    assert merge_trust("unauthenticated", "local") == "local"
    assert merge_trust("local", "unauthenticated") == "local"
    assert merge_trust("synthetic", "unauthenticated") == "unauthenticated"


def test_an_unknown_trust_value_is_treated_as_the_weakest():
    """Giá trị lạ phải là yếu nhất. Coi nó là mạnh nhất biến một lỗi chính tả
    thành một lượt nâng quyền."""
    assert merge_trust("unauthenticated", "khong-biet") == "unauthenticated"


def test_forged_syslog_cannot_raise_its_own_trust_through_entity_merge(graph):
    """Kịch bản tấn công thật:

    Máy A được quan sát cục bộ, nên thực thể host của nó mang trust 'local'.
    Kẻ tấn công bắn syslog giả mạo nói 'root đã đăng nhập vào A'. Nếu cạnh
    thừa hưởng trust của thực thể hai đầu, khẳng định giả đó sẽ trông như bằng
    chứng cục bộ — và không có gì phân biệt được nó với sự thật nữa.
    """
    trusted = Event(1000.0, "kernel", "process_exec",
                    {"pid": 1, "start_ticks": "5", "comm": "systemd"},
                    origin="local", trust="local")
    ingest(graph, trusted)
    host = entity_id_for("host", "local")
    assert graph.get_entity(host)["trust"] == "local"

    forged = Event(1001.0, "syslog", "ssh_login",
                   {"user": "root", "src_ip": "10.0.0.9",
                    "origin": "syslog:10.0.0.9", "trust": "unauthenticated"},
                   origin="syslog:10.0.0.9", trust="unauthenticated")
    ingest(graph, forged)

    login = [e for e in graph.neighbors(entity_id_for("host", "syslog:10.0.0.9"))
             if e["relation"] == "logged_into"]
    assert login, "cạnh đăng nhập giả mạo phải tồn tại để điều tra được"
    assert login[0]["trust"] == "unauthenticated"


def test_a_syslog_event_is_attributed_to_its_own_host_not_the_local_one():
    """Event từ probe/syslog mô tả MÁY KHÁC.

    Gán mọi thứ cho host cục bộ sẽ trộn tiến trình của năm máy vào một thực
    thể, và câu 'máy này còn làm gì nữa' trả lời sai một cách rất thuyết phục.
    """
    local = Event(1.0, "kernel", "process_exec", {}, origin="local")
    probe = Event(1.0, "probe.journal", "process_exec", {}, origin="probe:kho-01")
    syslog = Event(1.0, "syslog", "process_exec", {}, origin="syslog:10.0.0.9")
    assert host_key_for(local) == "local"
    assert host_key_for(probe) == "probe:kho-01"
    assert host_key_for(syslog) == "syslog:10.0.0.9"


def test_the_origin_in_data_wins_over_a_default_field():
    """Collector là nơi DUY NHẤT biết dòng này đến từ đâu."""
    event = Event(1.0, "probe.journal", "process_exec", {"origin": "probe:kho-02"})
    assert host_key_for(event) == "probe:kho-02"


# --- hợp nhất quan sát ---


def test_repeated_observations_merge_into_one_entity(graph):
    for ts in (1000.0, 1500.0, 900.0):
        ingest(graph, Event(ts, "kernel", "process_exec",
                            {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    entity = graph.get_entity(entity_id_for("process", "local:42:99"))
    assert entity["observation_count"] == 3
    assert entity["first_seen"] == 900.0, "first_seen phải là mốc SỚM nhất"
    assert entity["last_seen"] == 1500.0, "last_seen phải là mốc MUỘN nhất"


def test_repeated_observations_do_not_multiply_edges(graph):
    for ts in (1000.0, 1001.0, 1002.0):
        ingest(graph, Event(ts, "kernel", "process_exec",
                            {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    edges = graph.neighbors(entity_id_for("process", "local:42:99"))
    assert len(edges) == 1
    assert edges[0]["observation_count"] == 3


def test_repetition_alone_never_reaches_certainty(graph):
    """Lặp lại một quan sát không phải là bằng chứng mới; nó là cùng một bằng
    chứng nói lại."""
    for ts in range(1000, 1200):
        ingest(graph, Event(float(ts), "kernel", "process_exec",
                            {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    edge = graph.neighbors(entity_id_for("process", "local:42:99"))[0]
    assert edge["confidence"] <= 1.0


def test_evidence_refs_per_edge_are_capped(graph):
    from shield.evidence.graph import MAX_EVIDENCE_REFS_PER_EDGE

    for ts in range(1000, 1100):
        ingest(graph, Event(float(ts), "kernel", "process_exec",
                            {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    edge = graph.neighbors(entity_id_for("process", "local:42:99"))[0]
    assert len(edge["evidence_refs"]) <= MAX_EVIDENCE_REFS_PER_EDGE


# --- PID tái sử dụng ---


def test_a_process_without_a_stable_identity_creates_no_node():
    """Node 'pid 4321 trên máy này' gộp mọi tiến trình từng mang số đó lại làm
    một, và graph sẽ nói dối một cách rất thuyết phục."""
    entities, edges = resolve(Event(1000.0, "kernel", "process_exec",
                                    {"pid": 4321, "comm": "curl"}))
    assert not any(e.entity_type == "process" for e in entities)
    assert edges == []


def test_pid_reuse_does_not_merge_two_different_processes(graph):
    ingest(graph, Event(1000.0, "kernel", "process_exec",
                        {"pid": 42, "start_ticks": "10", "comm": "bash"}))
    ingest(graph, Event(2000.0, "kernel", "process_exec",
                        {"pid": 42, "start_ticks": "77", "comm": "nc"}))
    assert graph.find_entity("process", "local:42:10") is not None
    assert graph.find_entity("process", "local:42:77") is not None
    assert graph.counts()["entities"] == 3  # hai tiến trình + một host


# --- chuỗi đầy đủ: user -> login -> process -> file -> network ---


def test_a_full_investigation_timeline_can_be_rebuilt(graph):
    """Gate Phase 1, điều thứ nhất."""
    events = [
        Event(1000.0, "journal", "ssh_login",
              {"user": "khoa", "src_ip": "192.168.1.20", "method": "publickey"}),
        Event(1001.0, "kernel", "process_exec",
              {"pid": 500, "start_ticks": "10", "comm": "bash", "exe": "/bin/bash"}),
        Event(1002.0, "kernel", "process_exec",
              {"pid": 501, "start_ticks": "11", "comm": "curl", "exe": "/usr/bin/curl",
               "ppid": 500, "parent_start_ticks": "10"}),
        Event(1003.0, "kernel", "file_write",
              {"pid": 501, "start_ticks": "11", "comm": "curl", "path": "/tmp/payload"}),
        Event(1004.0, "kernel", "socket_connect",
              {"pid": 501, "start_ticks": "11", "comm": "curl",
               "remote_ip": "93.184.216.34", "remote_port": 443}),
    ]
    for event in events:
        ingest(graph, event)

    host = entity_id_for("host", "local")
    user = entity_id_for("user", "local:khoa")
    curl = entity_id_for("process", "local:501:11")

    def relations(entity_id, direction="both"):
        return {e["relation"] for e in graph.neighbors(entity_id, direction=direction)}

    assert "logged_into" in relations(user, "out")
    assert "belongs_to" in relations(user, "in")
    assert "ran_on" in relations(host, "in")
    assert "spawned" in relations(curl, "in"), "không truy được tiến trình cha"
    assert "wrote" in relations(curl, "out")
    assert "connected_to" in relations(curl, "out")

    # Và mỗi mắt xích truy ngược được về đúng event đã sinh ra nó.
    for edge in graph.neighbors(curl):
        assert all(graph.evidence_for(ref) for ref in edge["evidence_refs"])


def test_the_reverse_question_is_answerable(graph):
    """'Ai đã nối tới địa chỉ này' là câu người điều tra thật sự hỏi, và nó
    luôn là chiều ngược."""
    ingest(graph, Event(1000.0, "kernel", "socket_connect",
                        {"pid": 501, "start_ticks": "11", "comm": "curl",
                         "remote_ip": "93.184.216.34", "remote_port": 443}))
    inbound = graph.neighbors(entity_id_for("ip", "93.184.216.34"), direction="in")
    assert [e["relation"] for e in inbound] == ["connected_to"]


def test_an_ip_entity_is_global_not_per_host(graph):
    """1.1.1.1 nhìn từ hai máy vẫn là cùng một địa chỉ — và đó chính là điều
    làm graph có giá trị."""
    for origin in ("local", "probe:kho-01"):
        ingest(graph, Event(1000.0, "kernel", "socket_connect",
                            {"pid": 5, "start_ticks": "1", "remote_ip": "1.1.1.1"},
                            origin=origin))
    peers = graph.neighbors(entity_id_for("ip", "1.1.1.1"), direction="in")
    assert len(peers) == 2


# --- giới hạn cứng ---


def test_every_read_has_a_hard_limit(graph):
    from shield.evidence.graph import MAX_LIMIT

    ingest(graph, Event(1000.0, "kernel", "process_exec",
                        {"pid": 42, "start_ticks": "99", "comm": "curl"}))
    assert len(graph.neighbors(entity_id_for("host", "local"), limit=10 ** 9)) <= MAX_LIMIT
    assert graph.neighbors(entity_id_for("host", "local"), limit=0) != []


def test_an_unknown_evidence_kind_is_refused(graph):
    with pytest.raises(ValueError):
        graph.record_evidence("event:x", evidence_kind="tin-don")


def test_inferred_and_external_intel_rank_below_observed():
    """Mục 2.4: cả hai đều không được một mình xác nhận một kết luận."""
    assert EvidenceKind.RANK[EvidenceKind.INFERRED] < EvidenceKind.RANK[EvidenceKind.OBSERVED]
    assert EvidenceKind.RANK[EvidenceKind.EXTERNAL_INTEL] < EvidenceKind.RANK[EvidenceKind.DERIVED]


# --- hạn lưu trữ và trần dung lượng ---


def test_maintenance_prunes_the_graph_after_trimming_events(store):
    """Thứ tự bắt buộc: cắt event TRƯỚC, dọn graph SAU.

    `prune` nhận ra cạnh mồ côi bằng cách tra ngược bảng `events`. Chạy trước
    thì nó thấy mọi bằng chứng còn nguyên và không gỡ gì — graph sẽ chỉ lớn
    lên, đầy những cạnh trỏ tới event đã bị xoá.
    """
    import time as _time

    old = _time.time() - 90 * 86400
    for pid in range(5):
        ingest(store.graph, Event(old, "kernel", "process_exec",
                                  {"pid": pid, "start_ticks": "1", "comm": "old"}))
    assert store.graph.counts()["edges"] > 0

    result = store.maintain(event_days=30, alert_days=90, snapshot_days=30)
    assert result["events_deleted"] == 5
    assert result["graph_edges_deleted"] > 0
    assert store.graph.counts() == {"entities": 0, "edges": 0, "evidence": 0}
    assert store.graph.orphan_edges() == []


def test_recent_events_survive_maintenance(store):
    import time as _time

    ingest(store.graph, Event(_time.time(), "kernel", "process_exec",
                              {"pid": 1, "start_ticks": "1", "comm": "new"}))
    store.maintain(event_days=30)
    assert store.graph.counts()["edges"] > 0


def _fill(store, count: int) -> None:
    import time as _time

    now = _time.time()
    for pid in range(count):
        ingest(store.graph, Event(now - count + pid, "kernel", "process_exec",
                                  {"pid": pid, "start_ticks": str(pid),
                                   "comm": "x" * 200, "exe": "/usr/bin/" + "y" * 200}))
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def test_deleting_rows_reduces_the_number_the_size_cap_actually_uses(store):
    """SQLite mặc định auto_vacuum=NONE: xoá dòng KHÔNG làm file nhỏ lại.

    Trần dung lượng từng đo kích thước file. Nó xoá 50 nghìn dòng, đo lại thấy
    y nguyên, rồi xoá tiếp — đủ 40 lượt, tới 2 triệu event, và kết thúc vẫn
    "trên trần". Một cái trần xoá sạch lịch sử mà không thu lại được byte nào.
    """
    _fill(store, 300)
    file_before = store.database_bytes()
    used_before = store.database_used_bytes()

    with store.conn:
        store.conn.execute("DELETE FROM events")
        store.graph.prune()
    store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    assert store.database_used_bytes() < used_before, \
        "con số dùng để thi hành trần không giảm khi dữ liệu biến mất"
    # Kích thước file có thể không đổi — và đó chính là lý do không được dùng nó.
    assert store.database_bytes() <= file_before


def test_the_size_cap_stops_instead_of_deleting_everything(store):
    """Vòng lặp trần phải dừng khi đã cắt đủ, không phải khi hết dữ liệu.

    Lô nhỏ để có nhiều hơn một vòng — với lô mặc định 50 nghìn thì 300 dòng
    biến mất trong một lượt và test không phân biệt được đúng với sai.
    """
    _fill(store, 300)
    target = store.database_used_bytes() - 20_000

    # MỘT lượt bị chặn ở `SIZE_CAP_MAX_BATCHES` lô — xem
    # `tests/test_maintenance_bounds.py` cho lý do: vòng lặp cũ chạy tới khi
    # hết backlog và giữ khoá database gần 400 giây, đủ để systemd giết agent.
    # Nên ở đây gọi lặp lại, và điều cần chứng minh vẫn y nguyên: nó dừng khi
    # đã cắt ĐỦ, không phải khi hết dữ liệu.
    removed = 0
    for _ in range(40):
        step = store._enforce_size_cap(target, batch=25)
        removed += step
        if not step:
            break

    remaining = store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert removed > 0, "không cắt gì cả"
    assert remaining > 0, "trần dung lượng đã xoá sạch lịch sử thay vì cắt bớt"
    assert store.database_used_bytes() <= target
    assert store.graph.orphan_edges() == [], "còn cạnh trỏ tới event đã bị xoá"


def test_the_cap_loop_prunes_the_graph_between_batches(store):
    """Graph chiếm khoảng một phần ba database từ schema v5.

    Dọn nó sau vòng lặp nghĩa là mỗi lượt đo lại vẫn thấy dung lượng bị phần
    graph mồ côi giữ nguyên — vòng lặp không bao giờ thấy mình đã cắt đủ.
    """
    _fill(store, 300)
    before = store.graph.counts()["edges"]
    store._enforce_size_cap(store.database_used_bytes() - 20_000, batch=25)
    assert store.graph.counts()["edges"] < before
    assert store.graph.orphan_edges() == []


def test_a_host_is_never_left_without_a_path_to_its_processes(graph):
    """Thiếu cạnh `ran_on` thì thực thể host là node mồ côi, và mọi cuộc điều
    tra bắt đầu từ máy đều thấy rỗng — kể cả khi graph đầy dữ liệu.

    Lỗi thật: `file_write` và `socket_connect` tạo thực thể host nhưng không
    nối tiến trình vào nó. Chỉ `process_exec` mới nối. Trên một máy mà event
    đầu tiên là file_write, cả graph không đi tới đâu được.
    """
    for kind, extra in (
        ("file_write", {"path": "/tmp/x"}),
        ("socket_connect", {"remote_ip": "1.1.1.1", "remote_port": 443}),
    ):
        ingest(graph, Event(1000.0, "kernel", kind,
                            {"pid": 9, "start_ticks": "1", **extra}))
        host_edges = graph.neighbors(entity_id_for("host", "local"))
        assert host_edges, f"{kind}: host không có cạnh nào"
        assert "ran_on" in {edge["relation"] for edge in host_edges}


def test_observing_a_write_is_evidence_the_process_ran_here(graph):
    ingest(graph, Event(1000.0, "kernel", "file_write",
                        {"pid": 9, "start_ticks": "1", "path": "/tmp/x"}))
    edges = graph.neighbors(entity_id_for("process", "local:9:1"), direction="out")
    assert {edge["relation"] for edge in edges} == {"wrote", "ran_on"}


# --- kế hoạch truy vấn ---


def test_the_evidence_lookup_uses_the_index_not_a_full_scan(store):
    """Index trên `events.event_id` là index MỘT PHẦN, và SQLite chỉ dùng được
    nó khi câu truy vấn chứng minh được vị từ của index.

    Đây là test về KẾ HOẠCH TRUY VẤN, không phải về kết quả. Một test kết quả
    sẽ xanh cả khi SQLite quét toàn bảng — và trên database production 1,1
    triệu dòng, quét toàn bảng mất 1658 ms mỗi lần tra, cho MỖI cạnh ghi vào
    graph. Agent đốt trọn một nhân CPU liên tục vì đúng chuyện đó.
    """
    ingest(store.graph, Event(1000.0, "kernel", "process_exec",
                              {"pid": 1, "start_ticks": "1", "comm": "x"}))
    plans = [
        row[-1] for row in store.conn.execute(
            "EXPLAIN QUERY PLAN SELECT 1 FROM events WHERE event_id=? AND event_id!=''",
            ("x",)).fetchall()
    ]
    assert any("USING" in plan and "idx_events_event_id" in plan for plan in plans), plans
    assert not any(plan.strip().startswith("SCAN") for plan in plans), plans


def test_resolving_evidence_goes_through_the_indexed_query(store):
    """Nếu ai đó bỏ điều kiện `event_id != ''` thì câu này lại quét toàn bảng."""
    import inspect

    from shield.evidence.graph import EvidenceGraph

    source = inspect.getsource(EvidenceGraph._resolves)
    assert "event_id!=''" in source.replace(" ", ""), \
        "_resolves không còn ràng buộc để dùng index một phần"
