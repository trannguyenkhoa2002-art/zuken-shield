"""Xuất log ra thư mục người dùng chọn: đường dẫn, hạn mức, và an toàn.

Agent chạy dưới root còn đường dẫn đến từ giao diện. Một tiến trình root ghi
file vào chỗ do người dùng chỉ định là công thức kinh điển của leo thang đặc
quyền — phần lớn file test này nói về đúng chuyện đó.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shield.agent.log_export import (
    FILE_PREFIX,
    FILE_SUFFIX,
    MAX_QUOTA_MB,
    MIN_QUOTA_MB,
    ExportConfig,
    ExportPathError,
    LogExporter,
    validate_directory,
)


# --- kiểm đường dẫn ---


def test_a_normal_directory_is_accepted(tmp_path):
    target = tmp_path / "logs"
    target.mkdir()
    assert validate_directory(str(target)) == target


@pytest.mark.parametrize("bad", ["", "   ", "relative/path", "logs", "~/logs"])
def test_a_non_absolute_path_is_refused(bad):
    with pytest.raises(ExportPathError):
        validate_directory(bad)


def test_a_path_with_a_null_byte_is_refused():
    with pytest.raises(ExportPathError, match="không hợp lệ"):
        validate_directory("/tmp/a\x00b")


def test_a_missing_directory_is_refused_not_created(tmp_path):
    """Shield không tự tạo thư mục sâu trong hệ thống file hộ ai."""
    target = tmp_path / "chua-ton-tai"
    with pytest.raises(ExportPathError, match="chưa tồn tại"):
        validate_directory(str(target))
    assert not target.exists()


def test_a_file_is_not_a_directory(tmp_path):
    target = tmp_path / "file.txt"
    target.write_text("x")
    with pytest.raises(ExportPathError, match="không phải là thư mục"):
        validate_directory(str(target))


def test_a_symlinked_directory_is_refused(tmp_path):
    """Chỉ cần một symlink trong đường dẫn là root ghi đè được /etc/shadow."""
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(ExportPathError, match="liên kết tượng trưng"):
        validate_directory(str(link))


def test_a_symlink_anywhere_in_the_path_is_refused(tmp_path):
    """Kiểm phải theo TỪNG cấp. `Path.resolve()` đi theo symlink rồi trả về
    đích — nó giấu đúng thứ cần phát hiện."""
    real = tmp_path / "real"
    (real / "deep").mkdir(parents=True)
    link = tmp_path / "middle"
    link.symlink_to(real)
    with pytest.raises(ExportPathError, match="liên kết tượng trưng"):
        validate_directory(str(link / "deep"))


@pytest.mark.parametrize("system_dir", ["/", "/etc", "/usr", "/boot", "/proc", "/sys", "/var/lib"])
def test_system_directories_are_refused(system_dir):
    with pytest.raises(ExportPathError, match="hệ thống"):
        validate_directory(system_dir)


def test_a_subdirectory_of_a_system_directory_is_refused():
    with pytest.raises(ExportPathError, match="hệ thống"):
        validate_directory("/etc/shield-logs")


def test_the_shield_data_directory_is_refused(tmp_path):
    """Hạn mức log ăn vào trần dung lượng database, và hai cơ chế dọn dẹp sẽ
    giẫm lên nhau."""
    data = tmp_path / "shield"
    (data / "logs").mkdir(parents=True)
    with pytest.raises(ExportPathError, match="dữ liệu của Shield"):
        validate_directory(str(data / "logs"), shield_data_dir=data)


def test_an_unwritable_directory_is_refused_with_a_useful_reason(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ghi được mọi nơi")
    target = tmp_path / "readonly"
    target.mkdir(mode=0o500)
    with pytest.raises(ExportPathError, match="quyền ghi"):
        validate_directory(str(target))


def test_every_rejection_explains_itself_in_words(tmp_path):
    """Một hộp thoại 'đường dẫn không hợp lệ' không giúp ai sửa được gì."""
    for bad in ("", "relative", "/etc", str(tmp_path / "missing")):
        with pytest.raises(ExportPathError) as info:
            validate_directory(bad)
        assert len(str(info.value)) > 10


# --- cấu hình ---


def test_the_quota_is_clamped_to_a_sane_range():
    assert ExportConfig.from_dict({"max_mb": 1}).max_bytes == MIN_QUOTA_MB * 1024 ** 2
    assert ExportConfig.from_dict({"max_mb": 10 ** 9}).max_bytes == MAX_QUOTA_MB * 1024 ** 2


def test_a_garbage_quota_falls_back_to_a_default():
    for junk in ({"max_mb": "abc"}, {"max_mb": None}, {}):
        config = ExportConfig.from_dict(junk)
        assert MIN_QUOTA_MB * 1024 ** 2 <= config.max_bytes <= MAX_QUOTA_MB * 1024 ** 2


def test_export_is_off_by_default():
    """Ghi dữ liệu ra ngoài thư mục của Shield phải là lựa chọn có ý thức."""
    assert ExportConfig().enabled is False
    assert ExportConfig.from_dict({}).enabled is False


# --- ghi ---


@pytest.fixture()
def exporter(tmp_path):
    target = tmp_path / "logs"
    target.mkdir()
    return LogExporter(ExportConfig(enabled=True, directory=str(target), max_bytes=64 * 1024))


def test_records_are_written_as_jsonl(exporter, tmp_path):
    assert exporter.write({"ts": 1.0, "kind": "process_exec"}) is True
    exporter.close()
    files = list((tmp_path / "logs").glob(f"{FILE_PREFIX}*{FILE_SUFFIX}"))
    assert len(files) == 1
    line = files[0].read_text(encoding="utf-8").strip()
    assert json.loads(line)["kind"] == "process_exec"


def test_written_files_are_not_world_readable(exporter, tmp_path):
    exporter.write({"a": 1})
    exporter.close()
    path = next((tmp_path / "logs").glob(f"{FILE_PREFIX}*"))
    assert path.stat().st_mode & 0o007 == 0, "log endpoint không được cho cả máy đọc"


def test_a_disabled_exporter_writes_nothing(tmp_path):
    off = LogExporter(ExportConfig(enabled=False, directory=str(tmp_path)))
    assert off.write({"a": 1}) is False
    assert list(tmp_path.iterdir()) == []


def test_an_invalid_directory_disables_export_with_a_reason(tmp_path):
    broken = LogExporter(ExportConfig(enabled=True, directory="/etc"))
    assert broken.directory is None
    assert "hệ thống" in broken.last_error
    assert broken.write({"a": 1}) is False


def test_unserialisable_records_are_counted_not_crashed(exporter):
    class Weird:
        pass

    assert exporter.write({"obj": Weird()}) is True   # default=str xử lý được
    circular: dict = {}
    circular["self"] = circular
    assert exporter.write(circular) is False
    assert exporter.dropped_lines == 1


# --- hạn mức ---


def test_the_quota_deletes_the_oldest_files_first(tmp_path):
    target = tmp_path / "logs"
    target.mkdir()
    for i in range(5):
        (target / f"{FILE_PREFIX}{1000 + i}{FILE_SUFFIX}").write_bytes(b"x" * 10_000)
    exporter = LogExporter(ExportConfig(enabled=True, directory=str(target),
                                        max_bytes=25_000))
    exporter.enforce_quota()
    remaining = sorted(p.name for p in target.glob(f"{FILE_PREFIX}*"))
    assert remaining == [f"{FILE_PREFIX}1003{FILE_SUFFIX}", f"{FILE_PREFIX}1004{FILE_SUFFIX}"]


def test_the_quota_never_touches_files_shield_did_not_create(tmp_path):
    """Người dùng trỏ vào thư mục Documents của họ thì Shield không được đụng
    vào bất cứ thứ gì khác trong đó."""
    target = tmp_path / "logs"
    target.mkdir()
    precious = target / "luan-van-tot-nghiep.docx"
    precious.write_bytes(b"y" * 500_000)
    (target / f"{FILE_PREFIX}1000{FILE_SUFFIX}").write_bytes(b"x" * 100_000)

    exporter = LogExporter(ExportConfig(enabled=True, directory=str(target), max_bytes=1024))
    exporter.enforce_quota()

    assert precious.exists() and precious.stat().st_size == 500_000
    assert not (target / f"{FILE_PREFIX}1000{FILE_SUFFIX}").exists()


def test_used_bytes_only_counts_shield_files(tmp_path):
    target = tmp_path / "logs"
    target.mkdir()
    (target / "khong-phai-cua-shield.txt").write_bytes(b"z" * 100_000)
    (target / f"{FILE_PREFIX}1{FILE_SUFFIX}").write_bytes(b"x" * 1000)
    exporter = LogExporter(ExportConfig(enabled=True, directory=str(target)))
    assert exporter.used_bytes() == 1000


def test_the_file_being_written_is_never_deleted(exporter):
    """Ghi tiếp vào một inode đã bị gỡ tên nghĩa là dữ liệu biến mất trong im lặng."""
    exporter.write({"a": "x" * 100})
    current = exporter._current
    exporter.enforce_quota(target=0)
    assert current is not None and current.exists()


def test_writing_past_the_quota_frees_space_instead_of_failing(tmp_path):
    target = tmp_path / "logs"
    target.mkdir()
    for i in range(4):
        (target / f"{FILE_PREFIX}{1000 + i}{FILE_SUFFIX}").write_bytes(b"x" * 20_000)
    exporter = LogExporter(ExportConfig(enabled=True, directory=str(target),
                                        max_bytes=50_000))
    assert exporter.write({"a": 1}) is True
    assert exporter.used_bytes() <= 50_000


def test_a_symlink_placed_after_validation_still_cannot_be_followed(tmp_path):
    """O_NOFOLLOW: kể cả khi ai đó đặt symlink vào giữa hai lần kiểm."""
    target = tmp_path / "logs"
    target.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("nội dung gốc")
    exporter = LogExporter(ExportConfig(enabled=True, directory=str(target)))

    # Giả lập kẻ tấn công đặt sẵn symlink đúng tên file Shield sắp tạo.
    import time as _time
    planted = target / f"{FILE_PREFIX}{int(_time.time())}{FILE_SUFFIX}"
    planted.symlink_to(victim)

    exporter.write({"a": 1})
    assert victim.read_text() == "nội dung gốc", "root đã ghi xuyên qua symlink"


# --- thông tin cho người dùng ---


def test_stats_answer_the_question_the_user_actually_has(exporter):
    """'10 GB' không nói gì; 'khoảng 12 ngày' thì nói rất nhiều."""
    exporter.write({"a": 1})
    stats = exporter.stats(rate_lines_per_s=4.2, average_line_bytes=220)
    assert stats["days_retained_estimate"] is not None
    assert stats["bytes_per_day_estimate"] > 0
    assert 0 <= stats["used_percent"] <= 100
    assert stats["file_count"] == 1
    assert stats["disk_free_bytes"] > 0


def test_stats_do_not_invent_an_estimate_without_a_rate(exporter):
    assert exporter.stats(rate_lines_per_s=0.0)["days_retained_estimate"] is None


def test_dropped_lines_are_visible(tmp_path):
    """Mất log mà không có bộ đếm là mất log trong im lặng."""
    off = LogExporter(ExportConfig(enabled=True, directory="/etc"))
    off.write({"a": 1})
    assert off.stats()["last_error"]
    assert off.stats()["active"] is False


# --- đấu nối giao diện ---


def _ui_source() -> str:
    return (Path(__file__).resolve().parent.parent / "shield/ui/__main__.py").read_text(encoding="utf-8")


def _agent_source() -> str:
    return (Path(__file__).resolve().parent.parent / "shield/agent/__main__.py").read_text(encoding="utf-8")


def test_the_ui_asks_for_the_current_config_on_connect():
    """Người dùng có thể đã bật từ phiên trước. Hiện mặc định 'tắt' nghĩa là
    họ tưởng chưa bật rồi bật lại lên một thư mục khác."""
    assert '"cmd": "get_log_export_status"' in _ui_source()


def test_the_ui_handles_the_status_broadcast():
    source = _ui_source()
    assert 'msg_type == "log_export_status"' in source
    assert "on_log_export_status" in source


def test_the_status_handler_reads_the_data_envelope():
    """Mọi broadcast là {'type': ..., 'data': {...}}. Đọc nhầm tầng phong bì
    làm handler im lặng không làm gì — đã xảy ra với sáu handler cùng lúc."""
    source = _ui_source()
    index = source.index('msg_type == "log_export_status"')
    assert 'msg.get("data")' in source[index:index + 200]


def test_the_agent_refuses_to_persist_a_rejected_directory():
    """Lưu cấu hình hỏng rồi báo lỗi nghĩa là lần khởi động sau Shield lại thử
    đúng đường dẫn đó và lại hỏng, âm thầm."""
    source = _agent_source()
    index = source.index('elif cmd == "set_log_export"')
    block = source[index:index + 2000]
    reject = block.index("if error:")
    persist = block.index("set_log_export_config")
    assert reject < persist, "cấu hình được lưu trước khi kiểm lỗi"


def test_export_writes_happen_off_the_event_loop():
    """Thư mục người dùng chọn có thể nằm trên ổ ngoài hay ổ mạng; một lần ghi
    chậm sẽ làm nghẽn TOÀN BỘ đường event của Shield."""
    source = _agent_source()
    assert "asyncio.to_thread(exporter.write" in source


def test_both_languages_are_present_for_every_export_string():
    from shield.ui.i18n import STRINGS

    keys = [k for k in STRINGS if k.startswith("settings.export")]
    assert len(keys) >= 15
    for key in keys:
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip(), key
        assert vietnamese != english, f"{key} chưa được dịch"


def test_the_placeholders_match_between_languages():
    """Một chỗ giữ chỗ thiếu ở một ngôn ngữ là một KeyError chỉ xảy ra với
    người dùng ngôn ngữ đó — dạng lỗi không ai gặp khi test bằng tiếng còn lại."""
    import re

    from shield.ui.i18n import STRINGS

    for key in (k for k in STRINGS if k.startswith("settings.export")):
        vietnamese, english = STRINGS[key]
        assert set(re.findall(r"\{(\w+)\}", vietnamese)) == \
               set(re.findall(r"\{(\w+)\}", english)), key


def test_there_is_no_unlimited_quota_option():
    """Một hạn mức vô hạn nghĩa là Shield tự cho phép mình lấp đầy ổ đĩa."""
    from shield.agent.log_export import MAX_QUOTA_MB, QUOTA_CHOICES_MB

    assert all(0 < choice <= MAX_QUOTA_MB for choice in QUOTA_CHOICES_MB)
    assert MAX_QUOTA_MB < 10 ** 7


# --- lý do lỗi phải dịch được ---


def test_every_rejection_carries_a_machine_readable_code(tmp_path):
    """Agent không biết người đang nhìn màn hình chọn ngôn ngữ nào.

    Trả về câu đã viết sẵn nghĩa là người dùng tiếng Anh nhận một câu tiếng
    Việt — lỗi đã xảy ra đúng ở đây trong lần dựng đầu tiên.
    """
    cases = ["", "relative", "/etc", "/var/lib", str(tmp_path / "missing"), "/tmp/a\x00b"]
    seen = set()
    for bad in cases:
        with pytest.raises(ExportPathError) as info:
            validate_directory(bad)
        assert info.value.code, f"{bad!r} không có mã lỗi"
        assert info.value.code.isidentifier()
        seen.add(info.value.code)
    assert len(seen) >= 5


def test_every_error_code_has_a_translation_in_both_languages(tmp_path):
    from shield.ui.i18n import STRINGS

    codes = set()
    probes = ["", "relative", "/etc", "/var/lib", str(tmp_path / "missing"),
              "/tmp/a\x00b"]
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    probes.append(str(link))
    data = tmp_path / "shielddata"
    (data / "sub").mkdir(parents=True)
    for bad in probes:
        with pytest.raises(ExportPathError) as info:
            validate_directory(bad)
        codes.add(info.value.code)
    with pytest.raises(ExportPathError) as info:
        validate_directory(str(data / "sub"), shield_data_dir=data)
    codes.add(info.value.code)

    for code in codes:
        key = f"settings.export_err_{code}"
        assert key in STRINGS, f"mã {code} chưa có bản dịch"
        vietnamese, english = STRINGS[key]
        assert vietnamese.strip() and english.strip() and vietnamese != english, key


def test_the_ui_translates_from_the_code_not_the_agent_sentence():
    source = _ui_source()
    index = source.index("settings.export_error")
    window = source[max(0, index - 900):index + 200]
    assert "export_err_" in window, "giao diện đang hiện thẳng câu của agent"


def test_the_untranslatable_detail_is_kept_separate(tmp_path):
    """Đường dẫn cụ thể và thông báo của hệ điều hành không dịch được — chúng
    phải nằm ở `detail`, không trộn vào câu đã dịch."""
    with pytest.raises(ExportPathError) as info:
        validate_directory("/etc")
    assert info.value.detail == "/etc"
    assert info.value.code == "system_dir"
