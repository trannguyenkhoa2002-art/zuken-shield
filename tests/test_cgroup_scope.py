"""Worker model chạy trong một cgroup scope ANH EM của agent (Phase 3C-1).

Phase 3C-0 đo được: `RLIMIT_AS` là công cụ sai cho llama.cpp — nó đếm địa chỉ
ảo ĐẶT CHỖ (~3,2 GiB) chứ không đếm bộ nhớ thật chạm tới (~0,9–2,0 GiB), nên
mọi giá trị đủ nhỏ để là một trần đều chặn model nạp.

cgroup đếm đúng thứ đáng đếm. Nhưng một cgroup CON của `shield-agent.service`
vẫn nằm dưới `MemoryMax=1G` của service, nên scope phải là ANH EM — và nếu
không dựng được scope thì model bị TỪ CHỐI, không có đường chạy kèm agent.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys

import pytest

from shield.ai.worker import scope
from shield.ai.worker.protocol import WorkerRequest
from shield.ai.worker.supervisor import WorkerFailure, WorkerSupervisor

HOSTILE = os.path.join(os.path.dirname(__file__), "hostile_workers")
SCOPE = {"memory_max": "256M", "cpu_quota": "100%", "tasks_max": "32"}

systemd = pytest.mark.skipif(
    not shutil.which("systemctl") or not os.path.isdir("/sys/fs/cgroup"),
    reason="máy này không có systemd/cgroup v2")


def _run(coro):
    return asyncio.run(coro)


def _live_scopes(prefix="shield-ai-worker"):
    out = subprocess.run(["systemctl", "--user", "list-units", "--all", "--no-legend",
                          "--type=scope"], capture_output=True, text=True,
                         check=False).stdout
    return [line.split()[0] for line in out.splitlines() if prefix in line]


# --------------------------------------------------------------------------
# 1. argv: không shell, không tra PATH, tên thuộc tính ĐÓNG


def test_the_systemd_binary_comes_from_a_trusted_absolute_path():
    assert all(candidate.startswith("/") for candidate in scope.SYSTEMD_RUN_CANDIDATES)
    assert all(candidate.startswith("/") for candidate in scope.SYSTEMCTL_CANDIDATES)


def test_the_scope_argv_is_a_list_with_no_shell():
    argv, unit = scope.prefix(memory_max="2560M", cpu_quota="300%",
                              tasks_max="96", euid=0)
    assert isinstance(argv, tuple) and all(isinstance(a, str) for a in argv)
    assert argv[0].startswith("/") and argv[1] == "--scope"
    assert "--collect" in argv, "không --collect thì unit hỏng nằm lại mãi"
    assert "--user" not in argv, "đường root phải dùng scope HỆ THỐNG"
    assert unit.endswith(".scope")
    for element in argv:
        assert ";" not in element and "|" not in element and "&" not in element


def test_the_dev_path_uses_a_user_scope():
    argv, _unit = scope.prefix(memory_max="1G", cpu_quota="100%",
                               tasks_max="32", euid=1000)
    assert "--user" in argv


@pytest.mark.parametrize("value", ["2G; rm -rf /", "$(id)", "`id`", "2G 3G", "", "x" * 64])
def test_a_property_value_that_could_inject_is_refused(value):
    with pytest.raises(scope.ScopeUnavailable):
        scope.properties(memory_max=value, cpu_quota="100%", tasks_max="32")


def test_only_the_closed_property_set_is_allowed():
    assert scope.ALLOWED_PROPERTIES == {
        "MemoryMax", "MemorySwapMax", "CPUQuota", "TasksMax"}
    argv, _ = scope.prefix(memory_max="1G", cpu_quota="100%", tasks_max="32", euid=0)
    for element in argv:
        if element.startswith("--property="):
            key = element.removeprefix("--property=").split("=", 1)[0]
            assert key in scope.ALLOWED_PROPERTIES, key


def test_swap_is_pinned_to_zero():
    """Trần bộ nhớ mà còn swap thì không phải trần, chỉ là một lời đề nghị."""
    argv, _ = scope.prefix(memory_max="1G", cpu_quota="100%", tasks_max="32", euid=0)
    assert "--property=MemorySwapMax=0" in argv


def test_the_unit_name_is_predictable_and_unique():
    _a, first = scope.prefix(memory_max="1G", cpu_quota="1%", tasks_max="1", euid=0)
    _b, second = scope.prefix(memory_max="1G", cpu_quota="1%", tasks_max="1", euid=0)
    assert first != second
    assert first.startswith("shield-ai-worker-") and first.endswith(".scope")


def test_the_launcher_env_stays_empty_in_production():
    """Production chạy root và dùng bus HỆ THỐNG ở đường dẫn cố định, nên môi
    trường worker vẫn đúng như hợp đồng 3C-0 mô tả."""
    assert scope.launcher_env(euid=0) == {}
    dev = scope.launcher_env(euid=1000, source={"XDG_RUNTIME_DIR": "/run/user/1000",
                                                "DBUS_SESSION_BUS_ADDRESS": "unix:x"})
    assert set(dev) == {"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"}


def test_cleanup_kills_by_unit_not_by_pid():
    """Bài học đắt nhất của phase này: `systemd-run --scope` THOÁT sau khi đăng
    ký scope trong khi payload chạy tiếp bên trong cgroup. Giết pid ta cầm chỉ
    giết cái vỏ — một worker phớt lờ SIGTERM sống sót nguyên vẹn."""
    argv = scope.stop_argv("shield-ai-worker-abc123.scope", euid=0)
    assert argv[1:] == ("kill", "--signal=SIGKILL", "--kill-whom=all",
                        "shield-ai-worker-abc123.scope")


@pytest.mark.parametrize("unit", ["../etc/passwd", "a b", "x;y", "", "A" * 80])
def test_a_bad_unit_name_is_refused(unit):
    with pytest.raises(scope.ScopeUnavailable):
        scope.stop_argv(unit, euid=0)


# --------------------------------------------------------------------------
# 2. Fail closed


def test_a_missing_systemd_run_disables_the_model(monkeypatch):
    """Không có đường "chạy tạm trong cgroup của agent" — đó đúng là thứ scope
    tồn tại để ngăn."""
    monkeypatch.setattr(scope, "SYSTEMD_RUN_CANDIDATES", ("/khong/co/systemd-run",))
    supervisor = WorkerSupervisor(command=(sys.executable, "-I", "-c", "pass"),
                                  cgroup_scope=SCOPE, network="allow")
    with pytest.raises(WorkerFailure) as caught:
        _run(supervisor.request(WorkerRequest(request_id="x")))
    assert caught.value.code == "scope_unavailable"
    assert supervisor.health.scope_start_failures == 1
    assert supervisor.health.spawns == 0, "không được sinh tiến trình nào"


def test_the_memory_rlimit_is_off_when_the_cgroup_owns_memory():
    from shield.ai.worker.limits import ResourceLimits, apply

    assert ResourceLimits.from_json('{"memory_bytes": 0}').memory_bytes == 0
    import inspect

    source = inspect.getsource(apply)
    assert 'if name == "RLIMIT_AS" and not value' in source


def test_the_adapter_hands_memory_to_the_cgroup():
    from shield.ai.local_model import (
        SCOPE_CPU_QUOTA, SCOPE_MEMORY_MAX, LocalModelAnalyst)
    from shield.ai.model_config import ModelConfig

    analyst = LocalModelAnalyst(ModelConfig())
    assert analyst.supervisor.limits.memory_bytes == 0
    assert analyst.supervisor.cgroup_scope["memory_max"] == SCOPE_MEMORY_MAX
    assert analyst.supervisor.cgroup_scope["cpu_quota"] == SCOPE_CPU_QUOTA
    assert analyst.supervisor.network == "deny"


def test_the_worker_receives_a_validated_model_config():
    """Trước sửa này môi trường tối thiểu không có `SHIELD_AI_MODEL_*`, nên
    `from_environment()` trong worker LUÔN trả `None` và model không bao giờ
    nạp được trong sản phẩm."""
    from shield.ai.local_model import LocalModelAnalyst
    from shield.ai.model_config import ENV_CONFIG, ModelConfig

    analyst = LocalModelAnalyst(ModelConfig(model_path="/opt/shield/models/x.gguf"))
    assert "/opt/shield/models/x.gguf" in analyst.supervisor.model_config_json
    import inspect

    from shield.ai.worker.supervisor import WorkerSupervisor as WS

    assert ENV_CONFIG in inspect.getsource(WS._spawn) or "ENV_CONFIG" in inspect.getsource(WS._spawn)


# --------------------------------------------------------------------------
# 3. Thật: scope dựng được, trần áp được, dọn sạch


@systemd
def test_a_scope_actually_bounds_and_collects():
    before = set(_live_scopes())
    supervisor = WorkerSupervisor(
        command=(sys.executable, "-I", os.path.join(HOSTILE, "normal.py")),
        request_timeout_s=30.0, network="allow", cgroup_scope=SCOPE)
    response = _run(supervisor.request(WorkerRequest(request_id="scope-ok")))
    assert response.ok
    assert supervisor.health.scope_start_failures == 0
    assert supervisor.health.cleanup_failures == 0
    assert set(_live_scopes()) - before == set(), "scope phải tự dọn"


@systemd
def test_a_worker_that_ignores_sigterm_leaves_no_scope_behind():
    """Hồi quy: bản đầu để lại một scope còn ĐANG CHẠY worker bên trong."""
    before = set(_live_scopes())
    supervisor = WorkerSupervisor(
        command=(sys.executable, "-I", os.path.join(HOSTILE, "ignores_sigterm.py")),
        request_timeout_s=2.0, network="allow", cgroup_scope=SCOPE)
    with pytest.raises(WorkerFailure):
        _run(supervisor.request(WorkerRequest(request_id="stubborn")))
    import time

    time.sleep(0.6)
    assert set(_live_scopes()) - before == set(), "scope còn sót sau khi giết"


@systemd
def test_a_cgroup_oom_is_counted_as_a_resource_limit_not_a_crash():
    """Qua `systemd-run`, tín hiệu hiện ra thành mã thoát 128+N chứ không phải
    `returncode` âm. Không dịch lại thì OOM bị đếm là "worker tự sập", và số
    liệu tài nguyên luôn bằng 0 đúng lúc nó đáng đọc nhất."""
    supervisor = WorkerSupervisor(
        command=(sys.executable, "-I", os.path.join(HOSTILE, "eats_memory.py")),
        request_timeout_s=30.0, network="allow",
        cgroup_scope={"memory_max": "64M", "cpu_quota": "100%", "tasks_max": "32"})
    with pytest.raises(WorkerFailure):
        _run(supervisor.request(WorkerRequest(request_id="oom")))
    assert supervisor.health.resource_limit_exits == 1
    assert supervisor.health.crashes == 0


@systemd
def test_network_deny_survives_the_scope():
    """Không được nới cách ly mạng để scope chạy được."""
    supervisor = WorkerSupervisor(
        command=(sys.executable, "-I", os.path.join(HOSTILE, "probes_network.py")),
        request_timeout_s=40.0, network="deny", cgroup_scope=SCOPE)
    result = _run(supervisor.request(WorkerRequest(request_id="net"))).result
    for target in ("public", "lan", "loopback", "dns"):
        assert result[target].startswith("denied"), f"{target} -> {result[target]}"


# --------------------------------------------------------------------------
# 4. Sức khoẻ


def test_the_health_counters_cover_the_scope_lifecycle():
    from shield.ai.worker.supervisor import WorkerHealth

    data = WorkerHealth().to_dict()
    for field in ("requests", "successes", "fallbacks", "timeouts", "crashes",
                  "resource_limit_exits", "scope_start_failures",
                  "cleanup_failures", "spawns", "restarts"):
        assert field in data, field


def test_scope_failures_never_carry_worker_output():
    import json

    from shield.ai.worker.supervisor import WorkerHealth, publish_health

    rows = []

    class FakeStore:
        def set_collector_health(self, component, backend, healthy, detail, **kw):
            rows.append((component, detail, kw))

    health = WorkerHealth(state="degraded", scope_start_failures=2,
                          cleanup_failures=1, last_error_code="scope_unavailable")
    publish_health(FakeStore(), health)
    _component, detail, kw = rows[-1]
    assert "scope_start_failures=2" in detail and "cleanup_failures=1" in detail
    assert kw["error_message"] == "scope_unavailable"
    assert "AKIA" not in json.dumps(rows)


# --------------------------------------------------------------------------
# 5. Model đã provision vào đường dẫn tin cậy (§5)


PROVISIONED = "/opt/shield/models"

provisioned = pytest.mark.skipif(
    not os.path.isdir(PROVISIONED) or
    not [f for f in os.listdir(PROVISIONED) if f.endswith(".gguf")]
    if os.path.isdir(PROVISIONED) else True,
    reason="máy này chưa provision GGUF vào /opt/shield/models")


@provisioned
def test_a_provisioned_model_satisfies_the_trusted_path_policy():
    """Model production phải nằm ở đường dẫn tin cậy, root:root 0644, file
    thường, không symlink, dưới trần tier nhỏ. Bản trong `~/.cache` chỉ dùng
    cho eval và KHÔNG đạt chính sách này."""
    import stat

    from shield.ai.model_config import MAX_MODEL_BYTES, MODEL_PREFIXES, ModelConfig

    from pathlib import Path

    found = sorted(Path(PROVISIONED).glob("*.gguf"))
    assert found, "không có GGUF nào"
    for model in found:
        info = model.lstat()
        assert not model.is_symlink(), model
        assert stat.S_ISREG(info.st_mode), model
        assert info.st_uid == 0 and info.st_gid == 0, f"{model} không thuộc root:root"
        assert stat.S_IMODE(info.st_mode) == 0o644, f"{model} quyền {oct(info.st_mode)}"
        assert info.st_size <= MAX_MODEL_BYTES, f"{model} vượt trần tier nhỏ"
        assert any(model.is_relative_to(prefix) for prefix in MODEL_PREFIXES)
        # Và chính sách của sản phẩm phải chấp nhận nó.
        assert ModelConfig(model_path=str(model)).validate_model() == model.resolve()


@provisioned
def test_the_eval_copy_outside_the_trusted_path_is_refused():
    """Bản eval trong `~/.cache/shield-models` KHÔNG được dùng cho production."""
    from pathlib import Path

    from shield.ai.model_config import ModelConfig, ModelConfigError

    eval_copy = Path.home() / ".cache/shield-models"
    if not eval_copy.is_dir():
        pytest.skip("không có bản eval")
    for model in eval_copy.glob("*.gguf"):
        with pytest.raises(ModelConfigError):
            ModelConfig(model_path=str(model)).validate_model()


def test_a_transient_scope_is_a_sibling_not_a_child():
    """Bất biến kiến trúc: unit systemd KHÔNG lồng nhau, chỉ slice mới lồng.

    Một scope tạo từ BÊN TRONG một unit khác vẫn nằm cạnh nó, không nằm dưới
    nó — nên worker model không bị `MemoryMax=1G` của `shield-agent.service`
    bao ngoài. Đây là toàn bộ lý do dùng scope thay vì một cgroup con.

    Kiểm bằng nguồn: `prefix()` KHÔNG được truyền `--slice` trỏ vào unit gọi
    nó, vì làm thế sẽ lồng scope vào đúng chỗ ta đang tránh.
    """
    argv, _unit = scope.prefix(memory_max="1G", cpu_quota="100%",
                               tasks_max="32", euid=0)
    assert not any(a.startswith("--slice") for a in argv), \
        "không được ghim slice — mặc định system.slice mới là anh em của agent"
    assert "--scope" in argv
