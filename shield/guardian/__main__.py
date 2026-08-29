"""Guardian: canh chừng Shield từ BÊN NGOÀI tiến trình agent.

Vì sao phải là tiến trình riêng (KE-HOACH-SHIELD-1.1.md mục B2):

`tamper_monitor_loop` trong agent kiểm tra hash file cài đặt mỗi 5 phút — rất
tốt, nhưng nó chạy BÊN TRONG chính agent. Kẻ tấn công chỉ cần:

    systemctl stop shield-agent

là toàn bộ cơ chế tự bảo vệ biến mất cùng lúc với thứ nó đang bảo vệ. Tệ hơn,
`Restart=on-failure` KHÔNG bật lại khi service bị dừng chủ động — nên máy nằm
im, không cảnh báo, và giao diện thì chỉ hiện "mất kết nối agent" như một sự
cố mạng bình thường.

Guardian chạy theo systemd timer mỗi 60 giây, mỗi lần là một tiến trình
ngắn. Timer chứ không phải daemon là có chủ ý: một daemon canh chừng thì lại
cần thứ khác canh chừng nó; còn timer do systemd giữ, và systemd là thứ
người tấn công phải phá trước — việc đó ồn ào hơn nhiều so với giết một
tiến trình Python.

Guardian phân biệt được hai việc nhìn giống hệt nhau từ bên ngoài:
- người dùng tự bấm "Tắt Shield" trong app (switch.py ghi dấu vết trước khi
  tắt) -> ghi nhận, không báo động;
- ai đó giết agent -> alert critical.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import sqlite3
import time
from pathlib import Path

from shield.agent.store import DatabaseIntegrityError, Store, default_db_path
from shield.common.models import Alert, now
from shield.security.tamper import signed_snapshot, verify_snapshot

logger = logging.getLogger("shield.guardian")

AGENT_UNIT = "shield-agent.service"
STATE_FILENAME = "guardian-state.json"

# Cửa sổ coi một lần tắt là "do người dùng chủ động". Người dùng bấm Tắt trong
# app rồi Guardian chạy ở giây thứ 59 — vẫn phải hiểu là hợp lệ.
AUTHORIZED_SHUTDOWN_WINDOW_S = 900.0


def state_path() -> Path:
    return Path(os.environ.get("SHIELD_STATE_DIR", "/var/lib/shield")) / STATE_FILENAME


def code_root() -> Path:
    return Path(__file__).resolve().parent.parent


def read_state(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_state(path: Path, state: dict) -> None:
    """Ghi nguyên tử: Guardian có thể bị giết giữa chừng, và một file state
    cụt sẽ khiến lần chạy sau tưởng ledger vừa bị cắt ngắn."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def systemctl(*args: str, timeout: float = 10.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - đường dẫn cố định, tham số cố định
            ["/usr/bin/systemctl", *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)
    return proc.returncode, (proc.stdout or proc.stderr).strip()


def unit_state(unit: str = AGENT_UNIT) -> dict:
    code, output = systemctl("show", unit, "--property=ActiveState,SubState,NRestarts,Result,ExecMainStatus")
    if code != 0:
        return {"available": False, "raw": output}
    values = dict(
        line.split("=", 1) for line in output.splitlines() if "=" in line
    )
    return {"available": True, **values}


# --------------------------------------------------------------------------
# Từng kiểm tra một. Mỗi hàm trả về list các "phát hiện" (dict), không tự phát
# alert — để test gọi thẳng được mà không cần DB hay systemd.


def check_agent_is_running(unit: dict, authorized_shutdown: dict | None) -> list[dict]:
    if not unit.get("available"):
        return []  # không chạy dưới systemd (dev/test) — không phải phát hiện
    active = unit.get("ActiveState", "")
    if active == "active":
        return []
    if authorized_shutdown:
        return [{
            "rule_id": "GUARDIAN_AGENT_STOPPED_BY_OPERATOR", "severity": "info",
            "title": "Shield was shut down from the app",
            "detail": f"Operator stopped the agent at {authorized_shutdown.get('ts')}",
            "evidence": {"unit_state": active, **authorized_shutdown},
        }]
    return [{
        "rule_id": "GUARDIAN_AGENT_STOPPED", "severity": "critical",
        "title": "Shield agent is not running and nobody asked it to stop",
        "detail": f"{AGENT_UNIT} is {active}/{unit.get('SubState', '?')} "
                  f"with no operator shutdown recorded",
        "evidence": {"unit_state": active, "sub_state": unit.get("SubState", ""),
                     "result": unit.get("Result", ""), "restarts": unit.get("NRestarts", "0")},
    }]


def check_restart_storm(unit: dict, previous: dict) -> list[dict]:
    """`Restart=always` giữ agent sống, nhưng cũng che luôn một crash-loop.

    Nếu không đếm, một agent chết-sống 20 lần mỗi phút vẫn hiện "active" và
    trông hoàn toàn khoẻ mạnh.
    """
    try:
        restarts = int(unit.get("NRestarts", 0))
    except (TypeError, ValueError):
        return []
    before = int(previous.get("restarts", restarts))
    delta = restarts - before
    if delta < 3:
        return []
    return [{
        "rule_id": "GUARDIAN_AGENT_RESTART_STORM", "severity": "warning",
        "title": "Shield agent is restarting repeatedly",
        "detail": f"{delta} restarts since the previous guardian check",
        "evidence": {"restarts_now": restarts, "restarts_before": before, "delta": delta},
    }]


# --------------------------------------------------------------------------
# NGỮ CẢNH GÓI — CHỈ LÀ NGỮ CẢNH.
#
# Không một trường nào dưới đây là bằng chứng xác thực, và không trường nào
# được phép đổi severity. Gói này KHÔNG được ký (`ar t` trên .deb: không có
# `_gpgorigin`), `build-deb.sh` không có một dòng ký nào, và nó được cài từ
# file cục bộ nên apt cũng không xác minh chữ ký nào. `md5sums` của dpkg là
# tính toàn vẹn, không phải tính xác thực: nó là file thường trong
# /var/lib/dpkg/info mà root ghi lại được.
#
# Cái này trả lời đúng MỘT câu cho người vận hành: "thay đổi critical này có
# trùng thời điểm với một giao dịch của trình quản lý gói không?" — chứ không
# phải "lần nâng cấp này đã được xác thực".

PACKAGE_NAME = "shield-monitor"
DPKG_INFO_DIR = Path("/var/lib/dpkg/info")
DPKG_STATUS = Path("/var/lib/dpkg/status")


# Ba hàm dưới đây tra hằng số module TRONG THÂN HÀM, không lấy làm giá trị mặc
# định của tham số: mặc định được gắn lúc ĐỊNH NGHĨA hàm, nên một đường dẫn ghim
# ở đó thì không đổi được nữa — không test được, và cũng không đọc lại được nếu
# sau này vị trí dpkg khác đi.


def dpkg_status_mtime(status: Path | None = None) -> float:
    try:
        return (status or DPKG_STATUS).stat().st_mtime
    except OSError:
        return 0.0


def installed_package_version(package: str | None = None) -> str:
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package or PACKAGE_NAME],
            capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def package_owned_paths(package: str | None = None,
                        info_dir: Path | None = None) -> set[str] | None:
    """Đường dẫn tuyệt đối dpkg ghi nhận cho gói. None nếu không đọc được."""
    path = (info_dir or DPKG_INFO_DIR) / f"{package or PACKAGE_NAME}.list"
    try:
        return {line.strip() for line in
                path.read_text(encoding="utf-8").splitlines() if line.strip()}
    except OSError:
        return None


def package_context(root: Path, changed: list[str], base: dict) -> dict:
    """Ngữ cảnh tất định quanh một thay đổi cài đặt. Không bao giờ là lòng tin.

    Đo trên máy thật: Guardian băm cây trong venv, còn dpkg sở hữu
    `/opt/shield/shield` — KHÔNG một mục nào trong `md5sums` nhắc tới
    site-packages. Nên `package_owned_changed` thường bằng 0, và con số 0 đó
    chính là thứ đáng hiện ra: nó nói thẳng rằng những file vừa đổi không nằm
    trong thứ dpkg theo dõi. Xem nợ kỹ thuật
    GUARDIAN_PROTECTED_TREE_NOT_PACKAGE_OWNED.
    """
    thuoc_goi = package_owned_paths()
    if thuoc_goi is None:
        so_thuoc_goi = so_khong_thuoc = None
    else:
        so_thuoc_goi = sum(1 for r in changed if str(root / r) in thuoc_goi)
        so_khong_thuoc = len(changed) - so_thuoc_goi
    return {
        "package_name": PACKAGE_NAME,
        "package_version": installed_package_version() or "unknown",
        "changed_total": len(changed),
        "package_owned_changed": so_thuoc_goi if so_thuoc_goi is not None else "unknown",
        "non_package_owned_changed": so_khong_thuoc if so_khong_thuoc is not None else "unknown",
        # Trường này tồn tại để KHÔNG ai đọc nhầm mấy trường trên thành chữ ký.
        "authenticity": "unverified",
        **base,
    }


def package_manager_context(previous: dict, status: Path = DPKG_STATUS) -> dict:
    """Có giao dịch dpkg nào giữa lượt kiểm này và lượt trước không.

    So mtime của `/var/lib/dpkg/status` với giá trị lượt trước — tất định, chỉ
    đọc, và không phụ thuộc việc bắt được tiến trình apt/dpkg đang chạy (tới
    lúc Guardian chạy thì nó đã xong từ lâu).

    Lần đầu chưa có mốc để so thì là "unknown", KHÔNG phải "false".
    """
    hien_tai = dpkg_status_mtime(status)
    truoc = previous.get("dpkg_status_mtime")
    if not hien_tai or truoc is None:
        trang_thai = "unknown"
    else:
        trang_thai = "true" if hien_tai > float(truoc) else "false"
    return {"package_manager_context": trang_thai,
            "previous_package_version": previous.get("package_version", "") or "unknown"}


def protected_root_state(root: Path) -> tuple[bool, str]:
    """(kiểm tra được không, mã lý do). Không ném lỗi, không đoán."""
    try:
        if not root.exists():
            return False, "missing"
        if not root.is_dir():
            return False, "not_a_directory"
        os.listdir(root)
    except PermissionError:
        return False, "permission_denied"
    except OSError as exc:
        return False, f"unreadable:{exc.errno}"
    return True, "ok"


def check_installation_integrity(root: Path, previous: dict, key: bytes,
                                 context: dict | None = None) -> tuple[list[dict], dict]:
    """So hash cây file cài đặt với ảnh chụp lần trước.

    Lần chạy đầu chỉ chụp ảnh, không báo gì — nếu không, mọi lần cài đặt mới
    đều mở màn bằng một alert giả.
    """
    baseline = previous.get("snapshot")
    kiem_tra_duoc, ly_do = protected_root_state(root)

    if not kiem_tra_duoc:
        # KHÔNG dựng một diff giả với toàn bộ ảnh chụp cũ.
        #
        # `hash_tree` trên cây không tồn tại trả về {}, nên mọi đường dẫn từng
        # biết đều thành "đã đổi": một lần nâng cấp bình thường sẽ báo 125 file
        # thay đổi, đọc y hệt một vụ xoá sạch cài đặt. Đo trên máy thật:
        # `postinst` chạy `venv --clear` rồi `pip install`, và cây được bảo vệ
        # KHÔNG tồn tại trong 3,67 giây; timer chạy mỗi 60 giây, nên xác suất
        # rơi đúng cửa sổ đó là ~6% mỗi lần nâng cấp.
        #
        # Và KHÔNG ghi đè ảnh chụp cũ bằng một ảnh rỗng: làm vậy là âm thầm
        # lấy lại nền, nên một cây quay lại ĐÃ BỊ SỬA sẽ được coi là bình
        # thường. Ảnh chụp cũ được giữ nguyên tới khi có cây thật để so.
        return [{
            "rule_id": "GUARDIAN_PROTECTED_ROOT_UNAVAILABLE", "severity": "warning",
            "title": "Guardian could not verify the protected installation tree",
            "detail": f"protected root is not available for verification ({ly_do})",
            "evidence": {
                "protected_root": str(root),
                "exists": root.exists(),
                "readable": False,
                "reason": ly_do,
                "previous_snapshot_files": len((baseline or {}).get("files") or {}),
                "checked_ts": time.time(),
                # Không kiểm tra được KHÁC với kiểm tra đạt.
                "verified": False,
                **(context or {}),
            },
        }], previous.get("snapshot", {})

    snapshot = signed_snapshot(root, key)
    if not baseline:
        return [], snapshot
    try:
        valid, changed = verify_snapshot(baseline, root, key)
    except (OSError, ValueError) as exc:
        return [{
            "rule_id": "GUARDIAN_INSTALLATION_UNREADABLE", "severity": "critical",
            "title": "Shield installation could not be verified",
            "detail": str(exc),
            "evidence": {"root": str(root), "verified": False, **(context or {})},
        }], snapshot
    if valid:
        return [], snapshot
    return [{
        "rule_id": "GUARDIAN_INSTALLATION_CHANGED", "severity": "critical",
        "title": "Shield program files changed while the agent was not looking",
        "detail": f"{len(changed)} protected paths differ from the previous check",
        "evidence": {"changed": changed[:100], "root": str(root), "signed": bool(key),
                     **package_context(root, changed, context or {})},
    }], snapshot


def check_database(path: Path) -> tuple[list[dict], dict]:
    """Database còn đó, mở được, và ledger không bị cắt ngắn.

    Ledger chỉ được phép DÀI RA. Ngắn đi nghĩa là có người xoá bằng chứng —
    `maintain()` cố ý không bao giờ prune bảng này.
    """
    if not path.exists():
        return [{
            "rule_id": "GUARDIAN_DATABASE_MISSING", "severity": "critical",
            "title": "Shield database is gone",
            "detail": f"Expected database at {path}",
            "evidence": {"path": str(path)},
        }], {}
    # CHỈ ĐỌC. Mở qua Store sẽ chạy migration và ghi bản sao lưu — watchdog
    # không được sửa cái nó đang canh, và cũng không được chết chỉ vì thư mục
    # sao lưu không ghi được.
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        return [{
            "rule_id": "GUARDIAN_DATABASE_CORRUPT", "severity": "critical",
            "title": "Shield database is corrupt",
            "detail": str(exc), "evidence": {"path": str(path)},
        }], {}
    try:
        verdict = conn.execute("PRAGMA quick_check").fetchone()
        if not verdict or verdict[0] != "ok":
            return [{
                "rule_id": "GUARDIAN_DATABASE_CORRUPT", "severity": "critical",
                "title": "Shield database is corrupt",
                "detail": str(verdict[0] if verdict else "quick_check failed"),
                "evidence": {"path": str(path)},
            }], {}
    except sqlite3.DatabaseError as exc:
        return [{
            "rule_id": "GUARDIAN_DATABASE_CORRUPT", "severity": "critical",
            "title": "Shield database is corrupt",
            "detail": str(exc), "evidence": {"path": str(path)},
        }], {}
    try:
        rows = conn.execute("SELECT COUNT(*) FROM forensic_ledger").fetchone()
        ledger_rows = int(rows[0]) if rows else 0
    except Exception as exc:  # noqa: BLE001 - bảng có thể chưa tồn tại ở bản rất cũ
        return [{
            "rule_id": "GUARDIAN_LEDGER_UNREADABLE", "severity": "critical",
            "title": "Forensic ledger could not be read",
            "detail": str(exc), "evidence": {"path": str(path)},
        }], {}
    finally:
        conn.close()
    return [], {"ledger_rows": ledger_rows}


def check_ledger_growth(current: dict, previous: dict) -> list[dict]:
    before = previous.get("ledger_rows")
    nowe = current.get("ledger_rows")
    if before is None or nowe is None or nowe >= before:
        return []
    return [{
        "rule_id": "GUARDIAN_LEDGER_TRUNCATED", "severity": "critical",
        "title": "Forensic ledger lost records",
        "detail": f"Ledger went from {before} to {nowe} records — it must only ever grow",
        "evidence": {"rows_before": before, "rows_now": nowe},
    }]


def authorized_shutdown(path: Path) -> dict | None:
    """Có ai đó vừa bấm "Tắt Shield" trong app không?

    Đọc từ audit log — thứ `switch.py` ghi TRƯỚC khi agent tắt. Nếu DB không
    mở được thì trả None: khi nghi ngờ thì báo động, không im lặng.
    """
    if not path.exists():
        return None
    # CHỈ ĐỌC, và cố ý không đi qua Store: Store sẽ chạy migration, tạo bản sao
    # lưu, sửa quyền file — một watchdog không được phép thay đổi chính cái nó
    # đang canh, và cũng không được chết vì thư mục sao lưu không ghi được.
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return None
    try:
        row = conn.execute(
            "SELECT ts, params FROM audit_log WHERE action_id='shutdown_agent' "
            "ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    except Exception:  # noqa: BLE001
        return None
    finally:
        conn.close()
    if not row or time.time() - float(row[0]) > AUTHORIZED_SHUTDOWN_WINDOW_S:
        return None
    try:
        params = json.loads(row[1])
    except (TypeError, ValueError):
        params = {}
    return {"ts": float(row[0]), "reason": params.get("reason", ""),
            "principal": params.get("principal", "")}


# --------------------------------------------------------------------------


def run_once(db_path: Path | None = None, state_file: Path | None = None,
             root: Path | None = None) -> dict:
    db_path = db_path or default_db_path()
    state_file = state_file or state_path()
    root = root or code_root()
    key = os.environ.get("SHIELD_INTEGRITY_HMAC_KEY", "").encode()

    previous = read_state(state_file)
    unit = unit_state()
    findings: list[dict] = []

    # Mỗi phép kiểm chạy trong vỏ bọc riêng. Một watchdog chết giữa chừng vì
    # một phép kiểm ném lỗi sẽ im lặng đúng vào lúc cần nó nhất — và "im lặng"
    # với watchdog thì không phân biệt được với "mọi thứ đều ổn".
    def guarded(name, function, *arguments, default=None):
        try:
            return function(*arguments)
        except Exception as exc:  # noqa: BLE001
            logger.exception("phép kiểm %s lỗi", name)
            # Tiếng Anh như mọi phát hiện khác của Guardian: agent sinh mã và
            # dữ liệu, giao diện dịch. Câu tiếng Việt viết cứng ở đây sẽ hiện
            # nguyên văn cho người dùng bản tiếng Anh — lỗi đã lặp ba lần
            # trong dự án này.
            findings.append({
                "rule_id": "GUARDIAN_CHECK_FAILED", "severity": "warning",
                "title": "A guardian check could not run",
                "detail": f"check {name} failed: {exc}",
                "evidence": {"check": name, "error": str(exc), "verified": False},
            })
            return default

    findings += guarded(
        "agent_running", lambda: check_agent_is_running(
            unit, guarded("authorized_shutdown", authorized_shutdown, db_path)
        ), default=[]) or []
    findings += guarded("restart_storm", check_restart_storm, unit, previous, default=[]) or []

    context = guarded("package_manager_context", package_manager_context, previous,
                      default={"package_manager_context": "unknown"}) or {}
    integrity_findings, snapshot = guarded(
        "installation_integrity", check_installation_integrity, root, previous, key, context,
        default=([], previous.get("snapshot", {})),
    )
    findings += integrity_findings

    database_findings, database_state = guarded(
        "database", check_database, db_path, default=([], {}),
    )
    findings += database_findings
    findings += guarded(
        "ledger_growth", check_ledger_growth, database_state, previous, default=[]) or []

    state = {
        "checked_ts": time.time(),
        "restarts": unit.get("NRestarts", previous.get("restarts", 0)),
        "snapshot": snapshot,
        # Ghi lại để lượt sau so được: có giao dịch dpkg nào ở giữa không, và
        # phiên bản gói đã đổi chưa. Chỉ là ngữ cảnh, không phải lòng tin.
        "dpkg_status_mtime": dpkg_status_mtime(),
        "package_version": installed_package_version(),
        **database_state,
    }
    write_state(state_file, state)
    try:
        record_findings(db_path, findings)
    except Exception:  # noqa: BLE001
        # Không ghi được vào DB thì vẫn đã log ra journald ở trên. Mất đường
        # ghi KHÔNG được phép làm mất luôn cả lượt kiểm tra.
        logger.exception("không ghi được phát hiện vào database")
    return {"findings": findings, "state": state, "unit": unit}


def record_findings(db_path: Path, findings: list[dict]) -> None:
    """Ghi phát hiện vào DB nếu còn ghi được; journald luôn nhận được bản sao.

    Guardian cố ý ghi THẲNG vào store, không đi qua agent: nếu phải nhờ agent
    thì lúc agent chết cũng là lúc mất luôn đường báo cáo.
    """
    for finding in findings:
        level = logging.CRITICAL if finding["severity"] == "critical" else logging.WARNING
        logger.log(level, "%s: %s", finding["rule_id"], finding["detail"])
    if not findings or not db_path.exists():
        return
    try:
        # allow_migration=False: guardian KHÔNG được migrate database nó đang
        # canh. Việc đó là của agent; làm song song thì hai tiến trình cùng sao
        # lưu và cùng đổi schema một file.
        store = Store(db_path, allow_migration=False)
    except (DatabaseIntegrityError, sqlite3.DatabaseError):
        return
    if getattr(store, "schema_outdated", False):
        # Schema cũ hơn mã: agent sẽ migrate khi nó khởi động. Phát hiện đã ra
        # journald ở trên rồi, không mất gì — ghi vào một schema chưa đủ cột
        # mới là thứ gây hỏng.
        logger.warning("bỏ qua ghi vào database: schema cũ hơn mã, chờ agent migrate")
        store.close()
        return
    try:
        for finding in findings:
            alert = Alert(
                now(), finding["rule_id"], finding["severity"], finding["title"],
                finding["detail"], "shield-guardian",
                evidence={"observed": True, "source": "guardian", **finding.get("evidence", {})},
                playbook=["snapshot_state"],
            )
            store.insert_alert(alert)
            store.add_forensic_record("guardian", alert.to_dict())
    except Exception:  # noqa: BLE001 - đã log ra journald rồi, không được chết ở đây
        logger.exception("Guardian không ghi được phát hiện vào database")
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="shield-guardian",
        description="Kiểm tra một lần xem Shield còn nguyên vẹn và còn chạy không.",
    )
    parser.add_argument("--db", type=Path, default=None, help="Đường dẫn database")
    parser.add_argument("--state", type=Path, default=None, help="File state của guardian")
    parser.add_argument("--json", action="store_true", help="In kết quả dạng JSON")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    result = run_once(args.db, args.state)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
    critical = [f for f in result["findings"] if f["severity"] == "critical"]
    if critical:
        return 2
    return 1 if result["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
