"""Đổi định dạng khoá baseline không được biến cái đã học thành báo nhầm.

`behavior_key()` dựng khoá từ các trường của event. Thêm một trường vào
telemetry là đổi khoá, và mọi thứ đã học trở thành "chưa từng thấy".

Đã xảy ra thật ở Phase 2/A2: ảnh chụp procfs thêm `uid`, khoá đi từ
`process_started|system|<dải>|<exe>` thành `process_started|<uid>|<dải>|<exe>`.
Đo trên máy đang chạy: 640 khoá đã học thành vô dụng, ~200 cảnh báo `warning`
mỗi giờ lúc đầu, trong khi 3.397 khoá `process_exec` hoàn toàn còn đúng.

Cái giá của việc làm telemetry giàu hơn không được là dạy người dùng bỏ qua
cảnh báo.
"""

from __future__ import annotations

import time

import pytest

from shield.agent.store import Store
from shield.common.models import Event
from shield.security.anomaly import BEHAVIOR_KEY_FORMATS, LocalBaselineDetector, behavior_key


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "s.db", allow_migration=True)


def _started(exe: str, uid: int = 0, ts: float | None = None) -> Event:
    return Event(ts or time.time(), "endpoint", "process_started",
                 {"exe": exe, "uid": uid, "pid": 1})


def _exec(exe: str, uid: int = 0, ts: float | None = None) -> Event:
    return Event(ts or time.time(), "kernel", "process_exec",
                 {"exe": exe, "uid": uid, "pid": 1, "comm": "x"})


def _settle(store) -> None:
    """Đưa store về trạng thái "phiên bản đã ghi nhận, không còn học lại".

    Lần đối chiếu đầu tiên trên một database chưa từng ghi phiên bản LUÔN cho
    `process_started` học lại (mã đã ở phiên bản 2, mà baseline thì không nói
    nó học bằng định dạng nào). Các bài test bên dưới muốn kiểm chuyện KHÁC,
    nên chúng bắt đầu từ sau bước đó.
    """
    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    store.conn.execute("DELETE FROM baseline WHERE key LIKE 'anomaly_relearn_until:%'")
    store.conn.commit()
    store._relearn_cache = None


def _learn(store, event: Event, times: int = 5, past_learning: bool = True) -> None:
    """Đưa một khoá ra khỏi cửa sổ học và vào baseline."""
    if past_learning:
        store.conn.execute(
            "INSERT OR REPLACE INTO baseline(key,value,set_ts) "
            "VALUES('anomaly_learning_started',?,?)",
            (str(time.time() - 30 * 86400), time.time()))
        store.conn.commit()
    for _ in range(times):
        store.observe_behavior(behavior_key(event), event.kind)


# --- đối chiếu phiên bản ---


def test_the_first_run_keeps_baselines_of_kinds_still_at_version_one(store):
    """Định dạng chưa từng đổi -> baseline đang có chắc chắn còn đúng. Coi nó
    là "đã đổi" sẽ xoá sạch baseline của mọi máy đang chạy chỉ vì ta vừa thêm
    cơ chế đánh số."""
    _learn(store, _exec("/usr/bin/curl"))
    before = store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_exec'").fetchone()[0]
    assert before > 0

    changed = store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    assert [record["kind"] for record in changed] == ["process_started"]
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_exec'"
    ).fetchone()[0] == before
    assert store.behavior_key_formats()["process_exec"] == 1


def test_the_first_run_relearns_a_kind_whose_format_already_changed(store):
    """Baseline không ghi phiên bản nào mà mã đã ở phiên bản 2: nó có TRƯỚC cơ
    chế đánh số, nên ta không biết nó học bằng định dạng nào. Không biết thì
    phải học lại.

    Đây không phải giả thuyết: máy đang chạy có 657 khoá `process_started` học
    bằng định dạng cũ và đang bắn cảnh báo, còn cơ chế này thì vừa được thêm.
    """
    _learn(store, _started("/usr/bin/sleep"))
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_started'"
    ).fetchone()[0] > 0

    changed = store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    assert [record["kind"] for record in changed] == ["process_started"]
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_started'"
    ).fetchone()[0] == 0
    assert set(store.relearning_kinds()) == {"process_started"}


def test_an_unchanged_format_does_not_relearn(store):
    _settle(store)
    _learn(store, _started("/usr/bin/sleep"))
    before = store.conn.execute("SELECT COUNT(*) FROM behavior_baselines").fetchone()[0]

    assert store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS) == []
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines").fetchone()[0] == before
    assert store.relearning_kinds() == {}


def test_a_changed_format_relearns_only_that_kind(store):
    _settle(store)
    _learn(store, _started("/usr/bin/sleep"))
    _learn(store, _exec("/usr/bin/curl"))
    kept = store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_exec'").fetchone()[0]
    assert kept > 0

    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    changed = store.reconcile_behavior_key_formats(bumped)

    assert [record["kind"] for record in changed] == ["process_started"]
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_started'"
    ).fetchone()[0] == 0, "khoá của loại đã đổi phải bị xoá"
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_exec'"
    ).fetchone()[0] == kept, "loại KHÔNG đổi định dạng bị xoá lây"
    assert set(store.relearning_kinds()) == {"process_started"}


def test_the_reason_and_both_versions_are_audited(store):
    _settle(store)
    _learn(store, _started("/usr/bin/sleep"))
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] = 9
    store.reconcile_behavior_key_formats(bumped)

    rows = [row for row in store.recent_audit_logs(50)
            if row["action_id"] == "behavior_baseline_relearn"]
    params = rows[0]["params"]
    assert params["kind"] == "process_started"
    assert params["old_format"] == BEHAVIOR_KEY_FORMATS["process_started"]
    assert params["new_format"] == 9
    assert params["deleted_keys"] >= 1


def test_reconcile_is_idempotent(store):
    _settle(store)
    _learn(store, _started("/usr/bin/sleep"))
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] = 5

    first = store.reconcile_behavior_key_formats(bumped)
    until_first = store.relearning_kinds()["process_started"]
    _learn(store, _started("/usr/bin/sleep"), past_learning=False)

    second = store.reconcile_behavior_key_formats(bumped)
    assert second == [], "gọi lại mà phiên bản không đổi vẫn xoá baseline"
    assert store.relearning_kinds()["process_started"] == until_first, \
        "cửa sổ học lại bị kéo dài dù không có thay đổi mới"
    assert store.conn.execute(
        "SELECT COUNT(*) FROM behavior_baselines WHERE kind='process_started'"
    ).fetchone()[0] > 0, "baseline vừa học lại bị xoá lần nữa"
    assert len(first) == 1


def test_two_startups_in_a_row_do_not_race(store, tmp_path):
    """Hai lượt khởi động chồng nhau: lượt sau thấy phiên bản đã bằng nhau và
    không làm gì. Không có cửa sổ nào để xoá baseline hai lần."""
    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    _learn(store, _started("/usr/bin/sleep"))
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] = 7

    second = Store(tmp_path / "s.db", allow_migration=True)
    first_result = store.reconcile_behavior_key_formats(bumped)
    second_result = second.reconcile_behavior_key_formats(bumped)
    assert len(first_result) == 1 and second_result == []


# --- hành vi trong cửa sổ học lại ---


def _detector(store):
    return LocalBaselineDetector(store, minimum_observations=3)


def test_no_alert_is_raised_while_the_kind_is_relearning(store):
    _settle(store)
    _learn(store, _started("/usr/bin/sleep"))
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)

    detector = _detector(store)
    alerts = []
    for index in range(30):
        alerts += detector.handle_event(_started(f"/usr/bin/tool{index}", uid=1000))
    assert alerts == [], f"vẫn phát {len(alerts)} cảnh báo trong lúc học lại"
    assert detector.suppressed_by_relearn["process_started"] == 30


def test_the_baseline_is_still_being_built_while_relearning(store):
    _settle(store)
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)

    detector = _detector(store)
    for _ in range(4):
        detector.handle_event(_started("/usr/bin/sleep", uid=0))
    row = store.conn.execute(
        "SELECT observation_count FROM behavior_baselines WHERE kind='process_started'"
    ).fetchone()
    assert row is not None and row[0] == 4, "học lại mà không học gì cả"


def test_other_kinds_still_alert_during_the_relearn(store):
    """Nén phải hẹp. Một cửa sổ học lại của `process_started` không được làm
    câm cả `process_exec`."""
    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    _learn(store, _exec("/usr/bin/curl"))     # đẩy cửa sổ học toàn cục vào quá khứ
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)

    detector = _detector(store)
    assert detector.handle_event(_started("/usr/bin/new-thing", uid=0)) == []
    alerts = detector.handle_event(_exec("/usr/bin/never-seen", uid=0))
    assert len(alerts) == 1 and alerts[0].rule_id == "ANOMALY_NEW_BEHAVIOR"


def test_alerts_resume_when_the_relearn_window_expires(store):
    """Hết hạn là một mốc THỜI GIAN, không phải một sự kiện. Không cần khởi
    động lại agent để thoát chế độ học lại."""
    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)

    detector = _detector(store)
    assert detector.handle_event(_started("/usr/bin/a", uid=0)) == []

    # Đẩy cả mốc học toàn cục lẫn mốc học lại về quá khứ, KHÔNG dựng lại Store.
    past = time.time() - 3600
    store.conn.execute(
        "UPDATE baseline SET value=? WHERE key='anomaly_relearn_until:process_started'",
        (str(past),))
    store.conn.execute(
        "INSERT OR REPLACE INTO baseline(key,value,set_ts) "
        "VALUES('anomaly_learning_started',?,?)", (str(time.time() - 30 * 86400), time.time()))
    store.conn.commit()
    store._relearn_cache = None

    alerts = detector.handle_event(_started("/usr/bin/b", uid=0))
    assert len(alerts) == 1 and alerts[0].rule_id == "ANOMALY_NEW_BEHAVIOR"


def test_the_relearn_state_survives_an_agent_restart(store, tmp_path):
    _settle(store)
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)
    store.close()

    restarted = Store(tmp_path / "s.db", allow_migration=True)
    assert restarted.reconcile_behavior_key_formats(bumped) == []
    assert set(restarted.relearning_kinds()) == {"process_started"}
    detector = _detector(restarted)
    assert detector.handle_event(_started("/usr/bin/anything", uid=0)) == []


# --- nhìn thấy được ---


def test_the_relearn_shows_up_in_collector_health(store):
    from shield.agent.__main__ import _report_baseline_relearn

    store.reconcile_behavior_key_formats(BEHAVIOR_KEY_FORMATS)
    bumped = dict(BEHAVIOR_KEY_FORMATS)
    bumped["process_started"] += 1
    store.reconcile_behavior_key_formats(bumped)

    detector = _detector(store)
    for index in range(3):
        detector.handle_event(_started(f"/usr/bin/x{index}", uid=0))
    _report_baseline_relearn(store, detector)

    row = {r["component"]: r for r in store.collector_health()}["behavior_baseline"]
    assert "process_started" in row["detail"]
    assert "đã nén 3" in row["detail"]
    assert row["state"] == "degraded", "nén cảnh báo mà báo là bình thường"


def test_health_says_so_when_the_relearn_is_over(store):
    from shield.agent.__main__ import _report_baseline_relearn

    _settle(store)   # xoá luôn mốc học lại -> không loại nào đang học lại
    detector = _detector(store)
    detector.suppressed_by_relearn["process_started"] = 12
    _report_baseline_relearn(store, detector)

    row = {r["component"]: r for r in store.collector_health()}["behavior_baseline"]
    assert row["healthy"] and "bình thường" in row["detail"]
    assert detector.suppressed_by_relearn == {}


def test_the_global_reset_stays_a_deliberate_human_action():
    """`reset_behavior_baseline()` xoá MỌI loại — dùng nó cho việc học lại là
    vứt 3.397 khoá `process_exec` hoàn toàn còn đúng.

    Nó vẫn được phép tồn tại ở đúng MỘT chỗ: lệnh `baseline_reset` do người
    dùng bấm, có `confirm=True`. Không được xuất hiện trên đường khởi động.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    source = (root / "shield" / "agent" / "__main__.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    holders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = ast.dump(node)
        if "'reset_behavior_baseline'" in body or '"reset_behavior_baseline"' in body:
            holders.append(node.name)
    assert holders, "không tìm thấy chỗ gọi nào — bài test này đã hết tác dụng"
    assert "main_async" not in holders, "đường khởi động gọi reset baseline toàn cục"
    for name in holders:
        function = next(n for n in ast.walk(tree)
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and n.name == name)
        dumped = ast.dump(function)
        assert "'confirm'" in dumped, f"{name}: xoá baseline mà không hỏi xác nhận"
