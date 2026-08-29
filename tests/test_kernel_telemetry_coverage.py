"""Telemetry nhân: coverage được ĐO, không được khai (mục 0.4).

Trước 2.0, `KernelTelemetrySelector` khai eBPF cung cấp
("process", "file", "socket", ...) chỉ vì `/sys/kernel/btf/vmlinux` tồn tại,
trong khi collector phát duy nhất `process_exec`. `BehaviorChainDetector` chờ
`process_exec -> file_write -> socket_connect`, nên chuỗi hành vi chưa bao giờ
kích hoạt từ dữ liệu thật — nhưng UI vẫn hiển thị nó như đang hoạt động.
"""

from __future__ import annotations

import pytest

from shield.agent.collectors.kernel import (
    PROBES,
    RATE_LIMIT_PER_S,
    TAGS,
    ProbeSupport,
    RateLimiter as _RateLimiter,
    build_program,
    chain_status,
    parse_line,
)
from shield.security.mitre import BehaviorChainDetector
from shield.security.telemetry import KernelTelemetrySelector


# --- không khai quá khả năng ---


def test_the_selector_only_advertises_kinds_shield_actually_collects(tmp_path):
    """Năng lực khai ra phải trùng đúng tên kind mà collector có probe.

    Một tên viết khác đi ("file" thay vì "file_write") là một khả năng tưởng
    tượng: không có gì đối chiếu được nó với thực tế.
    """
    btf = tmp_path / "sys/kernel/btf"
    btf.mkdir(parents=True)
    (btf / "vmlinux").write_text("")
    capability = KernelTelemetrySelector(tmp_path).detect()
    if capability.backend == "ebpf":
        assert set(capability.capabilities) == set(PROBES)


def test_advertised_capability_is_never_marked_as_measured(tmp_path):
    """Dò file trên đĩa là dự đoán, không phải bằng chứng."""
    assert KernelTelemetrySelector(tmp_path).detect().measured is False


def test_every_advertised_kind_has_a_probe_and_a_tag():
    assert set(PROBES) == set(TAGS.values())
    assert set(PROBES) == set(RATE_LIMIT_PER_S)


def test_the_probe_set_covers_the_whole_behavior_chain():
    """Nếu chuỗi cần một loại mà không probe nào thu được, chuỗi là code chết."""
    assert set(BehaviorChainDetector.ORDER) <= set(PROBES)


# --- chuỗi hành vi không được tự nhận là đang chạy ---


def test_the_chain_is_inactive_when_a_link_is_missing():
    """Đúng hiện trạng trước 2.0: chỉ có process_exec."""
    status = chain_status(ProbeSupport(supported={"process_exec": "execve"}))
    assert status["active"] is False
    assert status["missing"] == ["file_write", "socket_connect"]
    assert "file_write" in status["reason"]


def test_the_chain_is_active_only_with_every_link():
    status = chain_status(ProbeSupport(supported=dict.fromkeys(PROBES, "x")))
    assert status["active"] is True
    assert status["missing"] == [] and status["reason"] == ""


def test_no_telemetry_at_all_is_not_reported_as_an_active_chain():
    status = chain_status(ProbeSupport())
    assert status["active"] is False
    assert set(status["missing"]) == set(BehaviorChainDetector.ORDER)


# --- fallback tường minh ---


def test_socket_connect_has_a_fallback_variant():
    """Kernel không đọc được sockaddr vẫn phải đóng góp được mắt xích thứ ba."""
    assert len(PROBES["socket_connect"]) >= 2


def test_the_program_is_built_only_from_supported_kinds():
    program = build_program({"process_exec": "execve tracepoint"})
    assert "sys_enter_execve" in program
    assert "sys_enter_connect" not in program
    assert "sys_enter_openat" not in program


def test_the_chosen_variant_is_the_one_that_attached():
    """Gắn được phương án dự phòng thì phải chạy đúng phương án đó, không phải
    phương án ưu tiên đã hỏng."""
    program = build_program({"socket_connect": "connect tracepoint without destination"})
    assert "sockaddr" not in program
    assert "sys_enter_connect" in program


def test_file_write_never_traces_the_write_syscall():
    """`write()` bắn mỗi dòng log — hàng chục nghìn sự kiện/giây trên máy nhàn
    rỗi. Nó sẽ nhấn chìm bus và bỏ đói mọi collector khác."""
    program = build_program(dict.fromkeys(PROBES, None))
    assert "sys_enter_write" not in program


def test_no_probe_program_is_ever_built_from_outside_input():
    """Chương trình bpftrace chỉ đến từ hằng số trong mã nguồn."""
    program = build_program({"process_exec": "không-phải-tên-phương-án-nào"})
    assert program == PROBES["process_exec"][0][1]


# --- phân tích dòng từ kernel ---


def test_an_exec_line_becomes_an_event():
    kind, data = parse_line("X\t4321\t1000\tbash\t/usr/bin/curl\n")
    assert kind == "process_exec"
    assert data["pid"] == 4321 and data["uid"] == 1000 and data["exe"] == "/usr/bin/curl"


def test_a_file_write_line_becomes_an_event():
    kind, data = parse_line("W\t4321\t0\tcurl\t/tmp/payload\n")
    assert kind == "file_write" and data["path"] == "/tmp/payload"


def test_a_connect_line_carries_the_destination_when_available():
    kind, data = parse_line("C\t4321\t0\tcurl\t93.184.216.34\t443\n")
    assert kind == "socket_connect"
    assert data["remote_ip"] == "93.184.216.34" and data["remote_port"] == 443


def test_a_fallback_connect_line_says_the_destination_is_unknown():
    """Thiếu địa chỉ không được đọc nhầm thành kết nối nội bộ."""
    kind, data = parse_line("C\t4321\t0\tcurl\n")
    assert kind == "socket_connect"
    assert data["destination_known"] is False
    assert "remote_ip" not in data


@pytest.mark.parametrize("line", [
    "", "\n", "Z\t1\t2\tx\ty\n", "X\n", "X\t\t\t\n", "X\tabc\t0\tbash\t/bin/ls\n",
    "X\t0\t0\tbash\t/bin/ls\n", "X\t-5\t0\tbash\t/bin/ls\n", "C\t1\t0\tcurl\t1.1.1.1\tport\n",
    "X\t1\t0\tbash\n", "W\t1\t0\tbash\n",
])
def test_malformed_lines_are_dropped_not_crashed(line):
    """Đây là chỗ dữ liệu từ kernel đi vào Shield; nó phải chịu được dòng cụt."""
    assert parse_line(line) is None


def test_a_path_with_tabs_and_unicode_survives():
    kind, data = parse_line("W\t7\t0\tapp\t/tmp/tên có dấu\tvà tab\n")
    assert kind == "file_write" and data["path"].startswith("/tmp/tên có dấu")


def test_oversized_fields_are_truncated():
    kind, data = parse_line(f"W\t7\t0\t{'c' * 5000}\t{'/x' * 5000}\n")
    assert len(data["comm"]) == 256 and len(data["path"]) == 4096


# --- giới hạn tốc độ có đếm ---


def test_the_rate_limiter_caps_a_burst():
    limiter = _RateLimiter({"file_write": 3})
    allowed = [limiter.allow("file_write", 1000.0) for _ in range(5)]
    assert allowed == [True, True, True, False, False]


def test_dropped_events_are_counted_not_silently_lost():
    """Giới hạn tốc độ mà không có bộ đếm là mất dữ liệu trong im lặng."""
    limiter = _RateLimiter({"file_write": 1})
    for _ in range(10):
        limiter.allow("file_write", 1000.0)
    assert limiter.dropped["file_write"] == 9


def test_the_budget_resets_every_second():
    limiter = _RateLimiter({"file_write": 2})
    assert [limiter.allow("file_write", 1000.0) for _ in range(3)] == [True, True, False]
    assert limiter.allow("file_write", 1001.0) is True


def test_one_noisy_kind_does_not_consume_another_kinds_budget():
    limiter = _RateLimiter({"file_write": 1, "process_exec": 1})
    limiter.allow("file_write", 1000.0)
    limiter.allow("file_write", 1000.0)
    assert limiter.allow("process_exec", 1000.0) is True


def test_an_unknown_kind_gets_no_budget():
    assert _RateLimiter({}).allow("something_new", 1000.0) is False


# --- danh tính tiến trình ổn định ---


@pytest.fixture(autouse=True)
def _clear_identity_cache():
    from shield.agent.collectors.kernel import _identity_cache

    _identity_cache.clear()
    yield
    _identity_cache.clear()


def test_a_short_lived_exec_still_gets_a_stable_identity(tmp_path):
    """Đo trên máy thật: 62% event process_exec không đọc kịp /proc — tiến
    trình đã chết trước khi mở được /proc/<pid>/stat.

    Không có danh tính ổn định thì 62% telemetry tiến trình không vào được
    evidence graph và không ghép được chuỗi hành vi, vì "pid:unknown" gộp mọi
    tiến trình từng mang số đó lại làm một.
    """
    from shield.agent.collectors.kernel import _identity

    identity = _identity(4321, "process_exec", 1_700_000_000.5, proc_root=tmp_path)
    assert identity["identity_source"] == "exec_ts"
    assert identity["process_identity"] == "4321:x1700000000500"
    assert not identity["process_identity"].endswith(":unknown")


def test_the_whole_chain_shares_one_identity_for_a_dead_process(tmp_path):
    """exec -> write -> connect phải khớp nhau, kể cả khi /proc đã biến mất.

    Đây chính là mắt xích: ba event ba danh tính khác nhau thì chuỗi hành vi
    không bao giờ hoàn chỉnh, dù cả ba đã được thu đầy đủ.
    """
    from shield.agent.collectors.kernel import _identity

    exec_id = _identity(4321, "process_exec", 1_700_000_000.5, proc_root=tmp_path)
    write_id = _identity(4321, "file_write", 1_700_000_001.0, proc_root=tmp_path)
    conn_id = _identity(4321, "socket_connect", 1_700_000_002.0, proc_root=tmp_path)
    assert exec_id["process_identity"] == write_id["process_identity"] == conn_id["process_identity"]


def test_a_new_exec_resets_the_identity_for_a_reused_pid(tmp_path):
    """Cùng PID sau một lượt exec là một tiến trình KHÁC.

    Giữ danh tính cũ nghĩa là gán hành vi của tiến trình trước cho tiến trình
    sau — graph sẽ nói dối một cách rất thuyết phục.
    """
    from shield.agent.collectors.kernel import _identity

    first = _identity(4321, "process_exec", 1_700_000_000.0, proc_root=tmp_path)
    second = _identity(4321, "process_exec", 1_700_000_500.0, proc_root=tmp_path)
    assert first["process_identity"] != second["process_identity"]
    later = _identity(4321, "socket_connect", 1_700_000_501.0, proc_root=tmp_path)
    assert later["process_identity"] == second["process_identity"]


def test_a_real_proc_identity_is_preferred_over_a_synthesised_one(tmp_path):
    """/proc đọc được là bằng chứng trực tiếp và phải thắng bảng nhớ."""
    from shield.agent.collectors.kernel import _identity

    proc = tmp_path / "9"
    proc.mkdir()
    # Sau ") " các trường là: state, ppid, ... và starttime nằm ở chỉ số 19.
    # Đếm tay ở đây là cố ý: đó chính là chỗ dễ lệch một nấc, và lệch một nấc
    # nghĩa là mọi danh tính tiến trình đều sai mà vẫn trông hợp lệ.
    fields = ["S", "1"] + [str(i) for i in range(17)] + ["777"]
    assert fields[19] == "777"
    (proc / "stat").write_text("9 (bash) " + " ".join(fields) + " tail")
    identity = _identity(9, "process_exec", 1_700_000_000.0, proc_root=tmp_path)
    assert identity["identity_source"] == "proc"
    assert identity["process_identity"] == "9:777"


def test_an_unseen_dead_process_is_honestly_unknown(tmp_path):
    """Chưa từng thấy lượt exec và /proc đã biến mất: phải nói là không biết.

    Một node gộp nhầm còn tệ hơn một node thiếu.
    """
    from shield.agent.collectors.kernel import _identity

    identity = _identity(999, "socket_connect", 1_700_000_000.0, proc_root=tmp_path)
    assert identity["process_identity"] == "999:unknown"
    assert identity["identity_source"] == "unknown"


def test_the_identity_cache_is_bounded(tmp_path):
    """Bảng nhớ theo PID không được trở thành chỗ rò bộ nhớ."""
    from shield.agent.collectors.kernel import _IDENTITY_CACHE_MAX, _identity, _identity_cache

    for pid in range(1, _IDENTITY_CACHE_MAX + 500):
        _identity(pid, "process_exec", 1_700_000_000.0, proc_root=tmp_path)
    assert len(_identity_cache) <= _IDENTITY_CACHE_MAX


def test_a_synthesised_identity_is_labelled_as_such(tmp_path):
    """Không ai được nhầm nó với start_ticks đọc được thật."""
    from shield.agent.collectors.kernel import _identity

    assert _identity(1, "process_exec", 1.0, proc_root=tmp_path)["start_ticks"] == ""
    assert _identity(1, "process_exec", 1.0, proc_root=tmp_path)["identity_source"] == "exec_ts"


# --- ai sở hữu hàng sức khoẻ nào ---


class _FakeStore:
    def __init__(self) -> None:
        self.rows: dict[str, tuple] = {}
        self.kwargs: dict[str, dict] = {}

    def set_collector_health(self, component, backend, healthy, detail, **kwargs) -> None:
        self.rows[component] = (backend, healthy, detail)
        self.kwargs[component] = kwargs


def test_the_collector_does_not_fight_the_supervisor_for_one_row():
    """Hàng "kernel_telemetry" thuộc về CollectorSupervisor, và nó ghi đè bằng
    "collector running" vài giây một lần.

    Hai bên cùng ghi một hàng nghĩa là bên nào ghi sau thắng — số event bị bỏ
    do giới hạn tốc độ đã biến mất đúng như vậy trên máy thật.
    """
    from shield.agent.collectors.kernel import _report

    store = _FakeStore()
    _report(store, ProbeSupport(supported=dict.fromkeys(PROBES, "ok")), True, "chạy")
    assert "kernel_telemetry" not in store.rows
    assert set(store.rows) == {f"kernel_telemetry.{k}" for k in PROBES} | {"behavior_chain"}


def test_dropped_counts_land_in_the_row_of_the_kind_that_was_dropped():
    """Mất log mà không có bộ đếm là mất log trong im lặng — và một bộ đếm bị
    ghi đè cũng vậy."""
    from shield.agent.collectors.kernel import _report

    store = _FakeStore()
    _report(store, ProbeSupport(supported=dict.fromkeys(PROBES, "ok")), True, "chạy",
            {"file_write": 4200})
    assert "4200" in store.rows["kernel_telemetry.file_write"][2]
    assert "4200" not in store.rows["kernel_telemetry.process_exec"][2]


# --- socket_connect nhìn được cả IPv6 ---
#
# Probe cũ lọc `sa_family == 2` (AF_INET), nên `::1` và mọi đích IPv6 hoàn toàn
# vô hình. Đo trên database production: 11.809 event `socket_connect`, trong đó
# **0** có địa chỉ IPv6. Một detector dựa vào nguồn này để phát hiện dò cổng
# local sẽ bị né chỉ bằng cách đổi một ký tự.


def test_the_connect_probe_tries_both_families_before_falling_back():
    """Ba phương án, thử theo thứ tự, và năng lực được ĐO chứ không khai.

    Gộp IPv6 vào một chương trình duy nhất sẽ làm một kernel thiếu BTF cho
    `sockaddr_in6` hỏng luôn nhánh IPv4 — mất một thứ đang chạy tốt để đổi lấy
    một thứ chưa chắc có.
    """
    labels = [label for label, _program in PROBES["socket_connect"]]
    assert labels[0] == "connect tracepoint with IPv4+IPv6 sockaddr"
    assert labels[1] == "connect tracepoint with IPv4 sockaddr only"
    assert labels[2] == "connect tracepoint without destination"

    dual = PROBES["socket_connect"][0][1]
    assert "sa_family == 2" in dual and "sa_family == 10" in dual
    assert "sockaddr_in6" in dual and "in6_u.u6_addr32" in dual
    # Lưới an toàn phải KHÔNG nhắc tới IPv6, nếu không nó hỏng cùng lý do.
    assert "sockaddr_in6" not in PROBES["socket_connect"][1][1]


def test_the_ipv6_branch_emits_raw_words_not_a_string():
    """`ntop()` trả về "::" cho MỌI địa chỉ IPv6 trên kernel này.

    Xác minh bằng bốn biến thể chương trình — nguyên bản, `uptr()`, khai họ
    tường minh, cả hai — đều ra `::`. Nguyên nhân đo được: bpftrace đọc VÔ
    HƯỚNG từ vùng nhớ người dùng thì được, đọc MẢNG thì trả về 0. Cổng (2
    byte) và `u6_addr32[i]` (4 byte) đúng; `u6_addr8[i]` và copy cả struct
    đều ra 0.

    `::` là địa chỉ IPv6 HỢP LỆ nên lỗi không tự lộ: nó ghi mọi kết nối IPv6
    là đi tới `::` và mọi test tổng hợp vẫn xanh.
    """
    dual = PROBES["socket_connect"][0][1]
    assert "u6_addr32[0]" in dual and "u6_addr32[3]" in dual
    assert "u6_addr8" not in dual, "mảng u8 đọc từ userspace trả về 0"
    assert "ntop(" in dual.split("sa_family == 10")[0], "nhánh IPv4 vẫn dùng ntop"
    assert "ntop(" not in dual.split("sa_family == 10")[1], \
        "nhánh IPv6 dùng ntop — nó trả về :: trên kernel này"


@pytest.mark.parametrize("address,words", [
    ("::1", ["00000000", "00000000", "00000000", "01000000"]),
    ("2001:db8::1", ["b80d0120", "00000000", "00000000", "01000000"]),
    ("fe80::82c7:9e9b:7f61:39ee", ["000080fe", "00000000", "9b9ec782", "ee39617f"]),
    ("ff02::c", ["000002ff", "00000000", "00000000", "0c000000"]),
    ("::ffff:127.0.0.1", ["00000000", "00000000", "ffff0000", "0100007f"]),
])
def test_four_raw_words_rebuild_the_canonical_address(address, words):
    """Bộ số đầu tiên là dữ liệu THẬT bpftrace in ra khi connect tới ::1."""
    kind, data = parse_line("6\t42\t0\tcurl\t" + "\t".join(words) + "\t443\n")
    assert kind == "socket_connect"
    assert data["remote_ip"] == address
    assert data["remote_port"] == 443


def test_a_truncated_ipv6_line_is_refused():
    assert parse_line("6\t42\t0\tcurl\t0\t0\t0\n") is None


def test_a_malformed_ipv6_word_is_refused():
    assert parse_line("6\t42\t0\tcurl\tzz\t0\t0\t0\t9\n") is None


def test_the_port_byte_order_is_swapped_for_both_families():
    dual = PROBES["socket_connect"][0][1]
    assert dual.count(">> 8) & 0xff") == 2
    assert "sin_port" in dual and "sin6_port" in dual


@pytest.mark.parametrize("address", ["127.0.0.1", "0.0.0.0", "8.8.8.8"])
def test_the_ipv4_branch_still_carries_text(address):
    """Nhánh IPv4 không đổi: `ntop()` cho IPv4 vẫn đúng, và đổi nó đi là mạo
    hiểm một thứ đang chạy để đồng bộ hình thức."""
    kind, data = parse_line(f"C\t42\t0\tcurl\t{address}\t8080\n")
    assert kind == "socket_connect"
    assert data["remote_ip"] == address
    assert data["remote_port"] == 8080
    assert "destination_known" not in data


def test_an_ipv4_mapped_address_is_not_rewritten_as_ipv4():
    """Không quy `::ffff:127.0.0.1` về `127.0.0.1`. Đó là hai cách viết mà
    kernel phân biệt được, và một luật quy đổi ngầm sẽ làm người điều tra đọc
    sai thứ tiến trình thực sự đã yêu cầu."""
    _kind, data = parse_line(
        "6\t42\t0\tcurl\t00000000\t00000000\tffff0000\t0100007f\t22\n")
    assert data["remote_ip"] == "::ffff:127.0.0.1"


def test_a_missing_destination_still_fails_closed():
    """Phương án dự phòng không đổi: biết có kết nối, không biết tới đâu — và
    nói ra điều đó thay vì đoán."""
    _kind, data = parse_line("C\t42\t0\tcurl\n")
    assert data["destination_known"] is False
    assert "remote_ip" not in data


def test_a_malformed_port_is_refused():
    assert parse_line("C\t42\t0\tcurl\t::1\tkhong-phai-so\n") is None


def test_an_ipv6_destination_builds_the_same_graph_shape():
    from shield.common.models import Event
    from shield.evidence.resolver import resolve

    entities, edges = resolve(Event(1.0, "kernel", "socket_connect", {
        "pid": 7, "uid": 0, "comm": "curl", "start_ticks": "9",
        "process_identity": "7:9", "remote_ip": "::1", "remote_port": 22}))
    peers = [e.canonical_key for e in entities if e.entity_type == "ip"]
    assert peers == ["::1"], peers
    assert "connected_to" in {e.relation for e in edges}


def test_process_identity_is_untouched_by_the_ipv6_change():
    _kind, data = parse_line(
        "6\t4242\t1000\tcurl\t00000000\t00000000\t00000000\t01000000\t443\n")
    assert data["pid"] == 4242 and data["uid"] == 1000 and data["comm"] == "curl"
    assert data["telemetry_backend"] == "ebpf"


def test_the_rate_limit_still_covers_socket_connect():
    assert RATE_LIMIT_PER_S["socket_connect"] == 200


# --- danh tính executable trong socket_connect ---
#
# `socket_connect` trước đây chỉ mang `comm`, và `comm` không đủ để nói tiến
# trình nào đã kết nối: kernel cắt nó còn 15 ký tự, và các binary khác nhau
# dùng chung tên luồng. Đo trên corpus production 13.590 event: chỉ 54,9% event
# ghép được sang một `exe` qua `process_exec`, và phần trượt lệch hẳn về các
# daemon chạy TRƯỚC agent (systemd-resolve 3.158 lượt, chronyd 1.309,
# NetworkManager 549) — đúng nhóm gọi connect nhiều nhất.


def _fake_proc(root, pid, start_ticks="777", ppid="1"):
    """Một mục /proc tối thiểu đủ để `_read_proc_stat` đọc được."""
    proc = root / str(pid)
    proc.mkdir(parents=True, exist_ok=True)
    fields = ["S", ppid] + [str(i) for i in range(17)] + [start_ticks]
    assert fields[19] == start_ticks
    (proc / "stat").write_text(f"{pid} (bash) " + " ".join(fields) + " tail")
    return proc


def test_a_connect_carries_the_executable_path(tmp_path):
    from shield.agent.collectors.kernel import _identity

    proc = _fake_proc(tmp_path, 9)
    (proc / "exe").symlink_to("/usr/bin/curl")
    assert _identity(9, "socket_connect", 1.0, proc_root=tmp_path)["exe"] == "/usr/bin/curl"


def test_the_kernel_resolves_symlinks_and_we_keep_what_it_returns(tmp_path):
    """Chạy qua một symlink thì kernel trả về binary THẬT.

    Đo trên máy thật: chạy `/bin/sleep` cho `/usr/lib/cargo/bin/coreutils/sleep`.
    Đường dẫn đó không khớp thứ người dùng gõ, và đó chính là điều đáng ghi —
    symlink không giả mạo được danh tính executable. Không "sửa lại cho quen
    mắt".
    """
    from shield.agent.collectors.kernel import _read_proc_exe

    real = tmp_path / "that_su"
    real.write_text("#!/bin/sh\n")
    middle = tmp_path / "lien_ket"
    middle.symlink_to(real)
    proc = _fake_proc(tmp_path, 11)
    (proc / "exe").symlink_to(middle.resolve())
    assert _read_proc_exe(11, tmp_path) == str(real)


def test_a_deleted_executable_keeps_its_suffix(tmp_path):
    """Kernel trả `'/path (deleted)'` cho binary đã bị xoá — GIỮ NGUYÊN.

    Một tiến trình đang chạy từ binary đã biến mất là dấu hiệu điều tra cổ
    điển. Cắt hậu tố cho "sạch đường dẫn" là xoá đúng thứ đáng báo.
    """
    from shield.agent.collectors.kernel import _read_proc_exe

    proc = _fake_proc(tmp_path, 12)
    (proc / "exe").symlink_to("/tmp/da-bay-mau (deleted)")
    assert _read_proc_exe(12, tmp_path) == "/tmp/da-bay-mau (deleted)"


@pytest.mark.parametrize("dung", ["thoat", "khong_phai_symlink", "khong_co_proc"])
def test_an_unreadable_exe_is_absent_never_guessed(tmp_path, dung):
    """Không đọc được thì KHÔNG có trường `exe` — không đoán, không dùng `comm`.

    `comm` bị cắt còn 15 ký tự và bị dùng chung: đo trên máy thật,
    `ThreadPoolForeg` ứng với cả `/usr/bin/opera` lẫn `/usr/bin/claude-desktop`.
    Lấy nó làm executable là bịa ra một danh tính.
    """
    from shield.agent.collectors.kernel import _identity, _read_proc_exe

    if dung != "khong_co_proc":
        proc = _fake_proc(tmp_path, 13)
        if dung == "khong_phai_symlink":
            (proc / "exe").write_text("day khong phai symlink")
    assert _read_proc_exe(13, tmp_path) is None
    assert "exe" not in _identity(13, "socket_connect", 1.0, proc_root=tmp_path)


def test_an_exec_that_keeps_start_ticks_still_changes_the_executable(tmp_path):
    """REGRESSION BẮT BUỘC — chống bảng nhớ giữ executable cũ.

    Đo trên máy thật: `exec()` KHÔNG đổi `start_ticks` (8888000 trước và sau).
    Nên `pid:start_ticks` — danh tính đang dùng — không chứng minh được
    executable không đổi. Một bảng nhớ `exe` khoá theo danh tính đó sẽ trả về
    binary cũ mãi mãi sau lượt exec thứ hai, và không có gì tự báo.
    """
    from shield.agent.collectors.kernel import _identity

    proc = _fake_proc(tmp_path, 14, start_ticks="8888000")
    (proc / "exe").symlink_to("/usr/bin/A")
    truoc = _identity(14, "socket_connect", 1.0, proc_root=tmp_path)
    assert truoc["exe"] == "/usr/bin/A"

    (proc / "exe").unlink()
    (proc / "exe").symlink_to("/usr/bin/B")
    sau = _identity(14, "socket_connect", 2.0, proc_root=tmp_path)

    assert sau["process_identity"] == truoc["process_identity"], "start_ticks phải giữ nguyên qua exec"
    assert sau["exe"] == "/usr/bin/B", "bảng nhớ đang giữ executable cũ sau exec"


def test_the_cache_never_supplies_an_exe_that_proc_no_longer_confirms(tmp_path):
    """Bảng nhớ được giữ ảnh chụp, nhưng không được mới hơn /proc.

    Đọc được `stat` mà không đọc được `exe` là "không biết", không phải "vẫn
    như lần trước".
    """
    from shield.agent.collectors.kernel import _identity

    proc = _fake_proc(tmp_path, 15)
    (proc / "exe").symlink_to("/usr/bin/A")
    assert _identity(15, "socket_connect", 1.0, proc_root=tmp_path)["exe"] == "/usr/bin/A"

    (proc / "exe").unlink()
    assert "exe" not in _identity(15, "socket_connect", 2.0, proc_root=tmp_path)


def test_a_process_exec_keeps_the_executable_the_probe_reported(tmp_path):
    """Probe bắt ở `sys_enter_execve` — TRƯỚC khi exec xảy ra.

    `/proc/<pid>/exe` lúc đó vẫn là binary CŨ, còn probe đưa binary SẮP chạy.
    Vì `data.update(_identity(...))` để identity ghi đè, `_identity` không được
    trả `exe` cho `process_exec`, nếu không đường dẫn đúng sẽ bị thay bằng
    đường dẫn của tiến trình gọi (`bash` thay cho `curl`).
    """
    from shield.agent.collectors.kernel import _identity

    proc = _fake_proc(tmp_path, 16)
    (proc / "exe").symlink_to("/bin/bash")

    data = {"pid": 16, "comm": "bash", "exe": "/usr/bin/curl"}
    data.update(_identity(16, "process_exec", 1.0, proc_root=tmp_path))
    assert data["exe"] == "/usr/bin/curl"

    # và mục nhớ không được rò rỉ binary cũ sang các event sau của cùng PID
    (proc / "exe").unlink()
    assert "exe" not in _identity(16, "socket_connect", 2.0, proc_root=tmp_path)
