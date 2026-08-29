"""Kiểm tra trước khi bật model cục bộ: `python -m shield.ai.preflight`.

Phase 3D mục 10 liệt kê những gì phải xác minh sau khi quản trị viên cài model.
Gom chúng vào MỘT lệnh có chủ ý: một danh sách kiểm bằng tay là một danh sách
có người bỏ qua bước bốn, và bước bốn ở đây là "mạng có thật sự bị cắt không".

Nó chỉ ĐỌC và chỉ báo cáo. Không cài gì, không tải gì, không sửa cấu hình —
việc provision là hành động có ý thức của con người, và một công cụ tự làm hộ
sẽ khiến không ai biết máy mình đang chạy gì.
"""

from __future__ import annotations

import asyncio
import json

CHECKS = ("config", "model_path", "model_size", "runtime", "network_deny", "smoke")


def _ok(name, detail="", **extra):
    return {"check": name, "ok": True, "detail": detail, **extra}


def _fail(name, detail, **extra):
    return {"check": name, "ok": False, "detail": detail, **extra}


async def run() -> dict:
    """-> báo cáo có cấu trúc. Không bao giờ ném."""
    from shield.ai.model_config import MAX_MODEL_BYTES, ModelConfigError, from_environment

    results = []

    # 1–3. Cấu hình, đường dẫn, kích thước.
    config = None
    try:
        config = from_environment()
    except ModelConfigError as exc:
        results.append(_fail("config", str(exc)))
    if config is None:
        results.append(_fail("config", "chưa cấu hình model cục bộ "
                                       "(đặt SHIELD_AI_MODEL_PATH)"))
        return _summary(results)
    results.append(_ok("config", f"runtime={config.runtime} "
                                 f"locale={config.target_locale}"))

    try:
        path = config.validate_model()
        results.append(_ok("model_path", str(path)))
        size = path.stat().st_size
        results.append(_ok("model_size", f"{size / 1024 ** 3:.2f} GiB",
                           bytes=size, limit=MAX_MODEL_BYTES))
    except ModelConfigError as exc:
        results.append(_fail("model_path", str(exc)))
        return _summary(results)

    # 4. Runtime nạp được không. Chạy TRONG worker, không nạp vào agent: nạp
    # một thư viện native vào tiến trình agent là đúng thứ 3C-0 dựng ra để tránh.
    from shield.ai.worker.protocol import WorkerRequest
    from shield.ai.worker.supervisor import WorkerFailure, WorkerSupervisor

    supervisor = WorkerSupervisor(request_timeout_s=config.timeout_s, network="deny")
    probe = WorkerRequest(request_id="preflight", facts=(
        {"relation": "wrote", "src_id": "p", "evidence_refs": ["event:a"]},
        {"relation": "connected_to", "src_id": "p", "evidence_refs": ["event:b"]}))
    try:
        response = await supervisor.request(probe)
        if response.ok:
            results.append(_ok("runtime", "worker nạp và trả lời được"))
            results.append(_ok("smoke", f"{len(response.result.get('hypotheses', []))} giả thuyết"))
        else:
            results.append(_fail("runtime", f"worker từ chối: {response.failure_code}"))
            results.append(_fail("smoke", "bỏ qua"))
    except WorkerFailure as exc:
        results.append(_fail("runtime", f"{exc.code}: {exc.detail}"))
        results.append(_fail("smoke", "bỏ qua"))

    # 5. Mạng ĐÃ bị cắt chưa. Kiểm lại ở đây chứ không tin cấu hình: đây là
    # điều kiện bắt buộc của 3C, và một điều kiện chỉ được tin khi vừa đo.
    from shield.ai.worker import netns

    plan = netns.plan()
    if plan["mechanism"] == "none":
        results.append(_fail("network_deny",
                             "không cơ chế nào cắt được mạng — worker sẽ bị từ chối"))
    else:
        results.append(_ok("network_deny", f"cơ chế: {plan['mechanism']}"))

    return _summary(results)


def _summary(results: list) -> dict:
    return {"checks": results,
            "ok": all(item["ok"] for item in results),
            "passed": sum(1 for item in results if item["ok"]),
            "total": len(results)}


def main() -> int:
    report = asyncio.run(run())
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
