#!/usr/bin/env python3
"""Kiểm chứng telemetry nhân trên kernel THẬT (KE-HOACH-SHIELD-2.0.md mục 0.4).

Chạy:

    sudo PYTHONPATH="$PWD" .venv/bin/python scripts/verify-kernel-telemetry.py

Script này trả lời ba câu mà không unit test nào trả lời được:

1. Từng đoạn bpftrace có gắn được vào kernel này không?
2. Chạy thật thì có event nào đi ra không, và thuộc những loại nào?
3. Chuỗi `process_exec -> file_write -> socket_connect` có kích hoạt được từ
   telemetry THẬT không, hay chỉ từ event tổng hợp trong test?

Nó tự sinh hoạt động để quan sát (chạy một tiến trình con, tiến trình đó ghi
một file trong thư mục tạm rồi mở một kết nối TCP tới chính máy này). Không
chạm mạng ngoài, không sửa gì ngoài thư mục tạm của chính nó.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shield.agent.collectors.kernel import (  # noqa: E402
    PROBES,
    ProbeSupport,
    build_program,
    chain_status,
    parse_line,
    probe_support,
)
from shield.common.models import Event  # noqa: E402
from shield.security.mitre import BehaviorChainDetector  # noqa: E402

GREEN, RED, YELLOW, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def say(ok: bool | None, text: str) -> None:
    mark = {True: f"{GREEN}PASS{RESET}", False: f"{RED}FAIL{RESET}", None: f"{YELLOW}····{RESET}"}[ok]
    print(f"  [{mark}] {text}")


async def step_one_attach() -> ProbeSupport:
    print("\n=== 1. Từng probe có gắn được vào kernel này không ===")
    support = await probe_support()
    for kind in PROBES:
        if kind in support.supported:
            say(True, f"{kind}: {support.supported[kind]}")
        else:
            say(False, f"{kind}: {support.unsupported.get(kind, 'không rõ lý do')}")
    return support


def generate_activity(port: int) -> None:
    """Sinh đúng ba việc trong MỘT tiến trình con, theo đúng thứ tự của chuỗi.

    Phải cùng một tiến trình: chuỗi hành vi ghép theo danh tính tiến trình, nên
    ba việc ở ba tiến trình khác nhau sẽ không bao giờ khớp — và nếu script này
    làm sai chỗ đó, nó sẽ báo FAIL cho một sản phẩm đang chạy đúng.
    """
    workdir = tempfile.mkdtemp(prefix="shield-telemetry-")
    program = (
        "import socket, sys, time\n"
        f"open({workdir!r} + '/payload', 'w').write('x' * 64)\n"
        "time.sleep(0.2)\n"
        "s = socket.socket()\n"
        "s.settimeout(1)\n"
        f"s.connect(('127.0.0.1', {port}))\n"
        "s.close()\n"
    )
    # exec (chính lần chạy này) -> file_write -> socket_connect, cùng một PID.
    subprocess.run([sys.executable, "-c", program], check=False, capture_output=True, timeout=10)


async def step_two_capture(support: ProbeSupport) -> list[Event]:
    print("\n=== 2. Chạy thật: có event nào đi ra không ===")
    if not support.supported:
        say(False, "không có probe nào gắn được — bỏ qua")
        return []

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    process = await asyncio.create_subprocess_exec(
        "bpftrace", "-q", "-e", build_program(support.supported),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=64 * 1024,
    )
    await asyncio.sleep(3)  # bpftrace cần thời gian gắn probe trước khi ta sinh hoạt động

    events: list[Event] = []
    stop = time.monotonic() + 12

    async def reader() -> None:
        while time.monotonic() < stop:
            try:
                line = await asyncio.wait_for(process.stdout.readline(), 1.0)
            except TimeoutError:
                continue
            if not line:
                break
            parsed = parse_line(line.decode(errors="replace"))
            if parsed is None:
                continue
            kind, data = parsed
            from shield.agent.collectors.kernel import _identity
            data.update(_identity(data["pid"], kind, time.time()))
            events.append(Event(time.time(), "kernel", kind, data))

    task = asyncio.create_task(reader())
    for _ in range(3):
        await asyncio.to_thread(generate_activity, port)
        try:
            conn, _ = await asyncio.to_thread(listener.accept)
            conn.close()
        except OSError:
            pass
        await asyncio.sleep(0.5)
    await task

    process.terminate()
    await process.wait()
    listener.close()

    for kind in PROBES:
        count = sum(1 for event in events if event.kind == kind)
        expected = kind in support.supported
        say(count > 0 if expected else None,
            f"{kind}: {count} event" + ("" if expected else " (probe không gắn được)"))
    stderr = (await process.stderr.read()).decode(errors="replace").strip()
    if stderr:
        print(f"  bpftrace stderr: {stderr[:400]}")
    return events


def step_three_chain(support: ProbeSupport, events: list[Event]) -> bool:
    print("\n=== 3. Chuỗi hành vi có kích hoạt từ telemetry THẬT không ===")
    status = chain_status(support)
    if not status["active"]:
        say(False, f"chuỗi không đủ mắt xích: {status['reason']}")
        return False

    detector = BehaviorChainDetector()
    alerts = []
    for event in sorted(events, key=lambda item: item.ts):
        alerts.extend(detector.handle_event(event))

    if alerts:
        alert = alerts[0]
        say(True, f"chuỗi kích hoạt: {alert.rule_id} trên {alert.subject}")
        say(True, f"thứ tự quan sát được: {' -> '.join(alert.evidence.get('sequence', []))}")
        return True

    identities = {
        event.data.get("process_identity"): sorted(
            {e.kind for e in events if e.data.get("process_identity") == event.data.get("process_identity")}
        )
        for event in events
    }
    interesting = {k: v for k, v in identities.items() if len(v) > 1}
    say(False, "không có chuỗi nào hoàn chỉnh trong dữ liệu thu được")
    if interesting:
        print("  Danh tính có nhiều hơn một loại event:")
        for identity, kinds in list(interesting.items())[:10]:
            print(f"    {identity}: {', '.join(kinds)}")
    return False


async def main() -> int:
    if os.geteuid() != 0:
        print("Cần chạy dưới root (bpftrace cần gắn probe vào kernel).")
        return 2
    print("Kiểm chứng telemetry nhân — KE-HOACH-SHIELD-2.0.md mục 0.4")
    support = await step_one_attach()
    events = await step_two_capture(support)
    chain_ok = step_three_chain(support, events)

    print("\n=== Kết luận ===")
    covered = sorted(support.supported)
    print(f"  Loại thu được: {', '.join(covered) if covered else 'không có'}")
    print(f"  Tổng event quan sát: {len(events)}")
    if chain_ok:
        print(f"  {GREEN}Chuỗi hành vi hoạt động trên telemetry thật.{RESET}")
        return 0
    print(f"  {RED}Chuỗi hành vi CHƯA chứng minh được trên telemetry thật.{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
