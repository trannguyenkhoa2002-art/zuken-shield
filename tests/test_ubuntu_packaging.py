import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def test_launcher_is_one_command_ui_and_starts_backends():
    launcher = (ROOT / "packaging/assets/shield-launcher").read_text()
    assert "systemctl start shield-privileged.service shield-agent.service" in launcher
    assert "sg shield" in launcher
    assert "-m shield.ui" in launcher


def test_deb_installs_both_services_and_offline_python_code():
    build = (ROOT / "packaging/build-deb.sh").read_text()
    postinst = (ROOT / "packaging/debian/postinst").read_text()
    preinst = (ROOT / "packaging/debian/preinst").read_text()
    assert "shield-privileged.service" in build
    assert "shield-agent.service" in build
    assert 'assets/shield-assess' in build
    assert 'assets/shield-admin' in build
    assert "--no-index --no-deps --no-build-isolation" in postinst
    assert "exit 1" in postinst
    assert "enable --now shield-privileged.service shield-agent.service" in postinst
    assert 'debian/preinst' in build
    # Dừng theo tên từng unit, không so nguyên câu lệnh: thêm một unit mới
    # (guardian) không được phép làm test này đỏ một cách vô nghĩa.
    stop_line = next(line for line in preinst.splitlines() if "systemctl stop" in line)
    assert "shield-agent.service" in stop_line
    assert "shield-privileged.service" in stop_line
    assert "source.backup(target)" in preinst
    assert "is-active --quiet shield-privileged.service shield-agent.service" in postinst
    # pyproject.toml references these paths while postinst builds an offline
    # wheel from /opt/shield, so all of them must be staged in that source tree.
    assert '"$ROOT_DIR/systemd" "$ROOT_DIR/scripts"' in build
    assert '"$STAGE/opt/shield/packaging/99-shield.rules"' in build


def test_every_documented_shield_command_is_installed_by_the_deb():
    """vm-smoke.sh gọi `shield-benchmark`, docs/USER_GUIDE.md §12 cũng bảo
    operator chạy nó sau khi cài — nhưng gói từng không cài lệnh đó, nên smoke
    test chết ngay với `shield-benchmark: command not found` trên máy thật.
    """
    build = (ROOT / "packaging/build-deb.sh").read_text()
    referenced = {"shield-benchmark", "shield-assess", "shield-admin"}
    for command in referenced:
        assert f'"$STAGE/usr/bin/{command}"' in build, f"gói không cài {command}"
        assert (ROOT / "packaging/assets" / command).is_file(), f"thiếu wrapper {command}"


def test_vm_smoke_uses_the_interpreter_the_package_actually_installs():
    """Gói cài code vào /opt/shield/.venv, python3 hệ thống không import được."""
    smoke = (ROOT / "scripts/vm-smoke.sh").read_text()
    assert "/opt/shield/.venv/bin/python3 - <<" in smoke
    assert "\npython3 - <<" not in smoke


def test_vm_smoke_pins_the_real_agent_database():
    """Không pin SHIELD_DB thì store.py rơi về DB rỗng trong home của người
    chạy, và verify_forensic_ledger() trên DB rỗng luôn PASS -> smoke test báo
    xanh mà không kiểm gì."""
    smoke = (ROOT / "scripts/vm-smoke.sh").read_text()
    assert "export SHIELD_DB=/var/lib/shield/shield.db" in smoke


def test_deb_declares_ubuntu_gui_and_security_dependencies():
    control = (ROOT / "packaging/debian/control").read_text()
    for package in ("python3-setuptools", "python3-pyside6.qtwidgets",
                    "python3-pyqtgraph", "nftables", "polkitd", "pkexec"):
        assert package in control
    assert "policykit-1" not in control


def test_the_core_deb_does_not_pull_in_scapy():
    """Ranh giới giấy phép phải nhìn thấy được ở tầng đóng gói.

    scapy (GPL-2.0) thuộc về gói `shield-packet-collector`. Nếu nó quay lại
    `Depends` của lõi thì việc tách tiến trình chỉ còn là hình thức: cài lõi sẽ
    lại kéo scapy về máy.
    """
    control = (ROOT / "packaging/debian/control").read_text()
    depends = [l for l in control.splitlines() if l.startswith("Depends:")][0]
    assert "scapy" not in depends, depends
    assert "Suggests: shield-packet-collector" in control


def test_systemd_restart_loops_are_bounded():
    for unit in ("shield-agent.service", "shield-privileged.service"):
        text = (ROOT / "systemd" / unit).read_text()
        assert "StartLimitIntervalSec=600" in text
        assert "StartLimitBurst=5" in text


def test_the_guardian_timer_is_packaged_and_enabled():
    """Guardian là thứ duy nhất phát hiện được việc agent bị dừng trái phép
    (mục B2). Nếu gói quên nó, lỗ hổng quay lại nguyên vẹn mà không ai biết."""
    build = (ROOT / "packaging/build-deb.sh").read_text()
    postinst = (ROOT / "packaging/debian/postinst").read_text()
    postrm = (ROOT / "packaging/debian/postrm").read_text()
    for unit in ("shield-guardian.service", "shield-guardian.timer"):
        assert unit in build, f"build-deb.sh không cài {unit}"
    assert "assets/shield-guardian" in build
    assert "enable --now shield-guardian.timer" in postinst
    assert "shield-guardian.timer" in postrm


def test_the_agent_unit_has_a_watchdog_and_keeps_the_in_app_off_switch_working():
    """WatchdogSec bắt agent TREO (Restart= chỉ bắt được agent CHẾT).
    Restart=always sẽ làm nút "Tắt Shield" trong app vô dụng — phải là
    on-failure."""
    unit = (ROOT / "systemd/shield-agent.service").read_text()
    assert "WatchdogSec=" in unit
    assert "Restart=on-failure" in unit
    assert "Restart=always" not in unit


def test_the_guardian_unit_cannot_touch_the_network_or_change_anything():
    """Guardian chỉ đọc. Siết chặt hơn agent là có chủ ý: một Guardian bị
    chiếm quyền không được phép làm gì cả."""
    unit = (ROOT / "systemd/shield-guardian.service").read_text()
    assert "PrivateNetwork=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "NoNewPrivileges=yes" in unit


def test_the_probe_package_is_built_separately_and_stays_light():
    """Máy chỉ cần gửi log không được phải cài PySide6 + scapy + reportlab.
    Nếu gói probe kéo theo pyproject của Shield, cả lý do tồn tại của nó biến mất."""
    import tomllib

    build = (ROOT / "packaging" / "build-probe-deb.sh").read_text()
    # Đọc TOML chứ không grep văn bản: chú thích trong file có nhắc tên PySide6
    # để giải thích VÌ SAO không dùng nó, và grep sẽ bắt nhầm chính lời giải
    # thích đó — người sửa sau sẽ học cách xoá chú thích để né test.
    config = tomllib.loads((ROOT / "packaging" / "probe-pyproject.toml").read_bytes().decode())
    assert config["project"]["dependencies"] == []
    assert config["project"]["scripts"] == {"shield-probe": "probe.__main__:main"}
    assert config["tool"]["setuptools"]["packages"]["find"]["include"] == ["probe*"]
    # Chỉ đóng gói package `probe`, không đụng `shield`.
    assert 'cp -r "$ROOT_DIR/probe"' in build
    assert '"$ROOT_DIR/shield"' not in build
    assert "shield-probe.service" in build


def test_the_probe_service_cannot_sniff_or_touch_the_network_config():
    """Probe chỉ đọc log. Cho nó AF_PACKET/AF_NETLINK là biến một máy bị
    chiếm quyền thành bàn đạp tấn công mạng."""
    unit = (ROOT / "systemd" / "shield-probe.service").read_text()
    families = next(line for line in unit.splitlines() if line.startswith("RestrictAddressFamilies="))
    assert "AF_PACKET" not in families
    assert "AF_NETLINK" not in families
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=yes" in unit


def test_the_probe_config_example_ships_with_the_package():
    """Không có file mẫu thì người dùng phải tự đoán tên khoá JSON."""
    build = (ROOT / "packaging" / "build-probe-deb.sh").read_text()
    assert "probe-config.example.json" in build
    example = json.loads((ROOT / "packaging" / "probe-config.example.json").read_text())
    for key in ("server_host", "probe_id", "certificate", "private_key", "server_ca"):
        assert key in example


def test_the_vm_smoke_script_checks_the_new_1_1_surface():
    """vm-smoke là thứ duy nhất kiểm bản ĐÃ CÀI. Nếu nó không biết tới
    guardian, một gói quên guardian vẫn PASS."""
    smoke = (ROOT / "scripts" / "vm-smoke.sh").read_text()
    assert "shield-guardian" in smoke


def test_state_directory_is_group_writable():
    """UI đọc database bằng user thường; WAL bắt buộc tạo được -wal/-shm.

    systemd áp lại quyền thư mục mỗi lần service khởi động, nên để mặc định
    0755 là UI mất khả năng đọc database ngay khi agent tắt — kể cả chỉ SELECT.
    Agent tự chmod lại sau khi chạy không cứu được, vì quyền mất theo lúc tắt.
    """
    for name in ("shield-agent.service", "shield-guardian.service"):
        unit = (ROOT / "systemd" / name).read_text(encoding="utf-8")
        if "StateDirectory=" not in unit:
            continue
        assert "StateDirectoryMode=0770" in unit, f"{name} thiếu StateDirectoryMode=0770"
