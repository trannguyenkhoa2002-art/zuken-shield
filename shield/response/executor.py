"""Lái một response job qua máy trạng thái (mục 4.1 và 4.4).

Thứ tự bắt buộc, và mỗi bước có lý do riêng:

    kiểm tiền điều kiện -> áp -> ĐỌC LẠI hệ thống để kiểm chứng -> chỉ khi đó
    mới coi là xong; kiểm chứng hỏng thì gỡ ngay.

Bất biến quan trọng nhất: **không bao giờ báo thành công dựa trên thông điệp
của chính mình.** `apply()` trả về "đã thêm vào set" không chứng minh được gì —
`verify()` phải đọc trạng thái thật. Đây là bài học của Batch 2.0-P0, nơi ba
chỗ khác nhau cùng báo thành công mà không đổi trạng thái hệ thống.

Bất biến thứ hai: **rollback thất bại là sự cố của chính Shield**, không phải
một dòng log. Nó để lại một luật firewall không ai gỡ, và người vận hành phải
biết ngay chứ không phải phát hiện ra khi mạng đã đứt hai ngày.
"""

from __future__ import annotations

import logging

from shield.response.adapters.base import ApplyResult
from shield.response.jobs import JobState, ResponseJob, ResponseJobStore, TransitionError

logger = logging.getLogger("shield.response.executor")

RESPONSE_KILL_SWITCH_ENV = "SHIELD_RESPONSE_KILL_SWITCH"


def response_automation_killed() -> bool:
    """Công tắc dừng mọi hành động phản ứng.

    Đọc lại biến môi trường MỖI LẦN, không cache: người vận hành bật nó lúc
    đang có sự cố, và một giá trị đã cache nghĩa là công tắc không có tác dụng
    cho tới lần khởi động lại — đúng lúc họ không muốn khởi động lại gì cả.

    Nó KHÔNG chặn `rollback`. Đây là điểm khác biệt quan trọng nhất so với kill
    switch của AI: một công tắc an toàn mà cũng chặn luôn đường GỠ sẽ đóng băng
    mọi luật firewall đang áp, và người bấm nó để dừng thiệt hại lại là người
    gây ra thiệt hại lớn hơn. Dừng làm thêm, không dừng dọn dẹp.
    """
    import os

    return os.environ.get(RESPONSE_KILL_SWITCH_ENV, "").strip().lower() in {
        "1", "true", "yes", "on"}


class ResponseExecutorV2:
    def __init__(self, jobs: ResponseJobStore, adapters: dict, *,
                 on_critical=None) -> None:
        self.jobs = jobs
        self.adapters = dict(adapters)
        # Gọi khi rollback thất bại. Bắt buộc phải đi RA NGOÀI agent (thông báo
        # hệ thống, Telegram) — một sự cố về chính cơ chế phản ứng mà chỉ được
        # ghi vào database của cơ chế đó thì không ai đọc.
        self.on_critical = on_critical

    # --- vòng đời ---

    async def approve(self, job_id: str, *, actor: str) -> ResponseJob:
        """Người duyệt. `actor` bắt buộc: một lượt duyệt không rõ ai duyệt là
        một lượt duyệt không truy trách nhiệm được."""
        if not actor:
            raise ValueError("phải ghi ai đã duyệt")
        if response_automation_killed():
            return self.jobs.transition(
                job_id, JobState.DENIED, actor=actor,
                detail="công tắc dừng phản ứng đang bật")
        return self.jobs.transition(job_id, JobState.APPROVED, actor=actor,
                                    detail="người vận hành đã duyệt")

    async def deny(self, job_id: str, *, actor: str, reason: str = "") -> ResponseJob:
        return self.jobs.transition(job_id, JobState.DENIED, actor=actor,
                                    detail=reason or "người vận hành từ chối")

    async def run(self, job_id: str) -> ResponseJob:
        """Chạy một job đã duyệt cho tới trạng thái nghỉ."""
        job = self.jobs.get(job_id)
        if job is None:
            raise TransitionError(f"không có job {job_id!r}")
        adapter = self.adapters.get(job.action)
        if adapter is None:
            return self.jobs.transition(job_id, JobState.APPLY_FAILED, actor="system",
                                        detail=f"không có adapter cho {job.action}")
        if job.state != JobState.APPROVED:
            raise TransitionError(f"job đang ở {job.state}, chưa được duyệt")
        if response_automation_killed():
            # Chặn TRƯỚC khi chạm vào hệ thống. Job đã duyệt vẫn nằm nguyên ở
            # APPROVED để chạy lại được khi công tắc tắt — không huỷ, vì huỷ
            # nghĩa là người vận hành phải duyệt lại từ đầu sau sự cố.
            logger.warning("Công tắc dừng phản ứng đang bật; job %s không được chạy",
                           job.job_id)
            return job

        plan = {**job.target, "ttl_s": job.ttl_s}

        check = await adapter.check_preconditions(plan)
        if not check.ok:
            # Chưa chạm vào hệ thống, nên KHÔNG đi qua ROLLING_BACK: gỡ một thứ
            # chưa từng được áp là gỡ nhầm. Vẫn đi qua APPLYING để lịch sử ghi
            # lại rằng job đã được lấy ra chạy, không phải bị bỏ quên.
            self.jobs.transition(job_id, JobState.APPLYING, actor="system",
                                 detail="kiểm tiền điều kiện")
            return self.jobs.transition(
                job_id, JobState.APPLY_FAILED, actor="system",
                detail=f"tiền điều kiện không đạt: {check.detail}",
                apply_result=check.to_dict())

        job = self.jobs.transition(job_id, JobState.APPLYING, actor="system",
                                   detail="đang áp")
        applied = await adapter.apply(plan, job.idempotency_key)
        if not applied.ok:
            job = self.jobs.transition(job_id, JobState.APPLY_FAILED, actor="system",
                                       detail=applied.detail, apply_result=applied.to_dict())
            # Áp hỏng GIỮA CHỪNG có thể đã để lại luật rác. Gỡ để chắc chắn —
            # rollback idempotent nên gỡ một thứ không tồn tại là vô hại, còn
            # bỏ qua thì có thể để lại đúng thứ nguy hiểm.
            return await self._rollback(job, adapter, plan, applied,
                                        reason="dọn sau khi áp thất bại")
        if adapter.reversible and not applied.rollback_token:
            # Adapter khai là gỡ được nhưng không trả về thứ để gỡ. Đây là lỗi
            # lập trình, và phát hiện nó SAU khi đã áp thì đã muộn — nên gỡ ngay.
            logger.error("Adapter %s khai reversible nhưng không trả rollback_token",
                         adapter.action)

        job = self.jobs.transition(job_id, JobState.APPLIED, actor="system",
                                   detail=applied.detail, apply_result=applied.to_dict())

        job = self.jobs.transition(job_id, JobState.VERIFYING, actor="system",
                                   detail="đọc lại trạng thái hệ thống")
        verified = await adapter.verify(plan, applied)
        self.jobs.record_verification(job_id, verified=verified.verified,
                                      observed=verified.observed, reason=verified.reason,
                                      reason_key=verified.reason_key,
                                      reason_params=verified.reason_params)
        if not verified.verified:
            job = self.jobs.transition(job_id, JobState.VERIFY_FAILED, actor="system",
                                       detail=verified.reason,
                                       verify_result=verified.to_dict())
            if adapter.reversible:
                # Kiểm chứng hỏng nghĩa là ta KHÔNG BIẾT hệ thống đang ở đâu.
                # Với action đảo ngược được, quay về trạng thái đã biết là lựa
                # chọn an toàn hơn ở lại một trạng thái không xác định.
                return await self._rollback(job, adapter, plan, applied,
                                            reason="kiểm chứng thất bại")
            return job

        return self.jobs.transition(job_id, JobState.VERIFIED, actor="system",
                                    detail="đã kiểm chứng từ trạng thái hệ thống",
                                    verify_result=verified.to_dict())

    async def rollback(self, job_id: str, *, actor: str = "system",
                       reason: str = "") -> ResponseJob:
        job = self.jobs.get(job_id)
        if job is None:
            raise TransitionError(f"không có job {job_id!r}")
        adapter = self.adapters.get(job.action)
        if adapter is None:
            self.jobs.transition(job_id, JobState.ROLLING_BACK, actor=actor,
                                 detail="không có adapter")
            return self.jobs.transition(job_id, JobState.ROLLBACK_FAILED, actor=actor,
                                        detail=f"không có adapter cho {job.action}")
        applied = ApplyResult(True, "", dict(job.apply_result.get("rollback_token") or {}))
        return await self._rollback(job, adapter, {**job.target, "ttl_s": job.ttl_s},
                                    applied, reason=reason, actor=actor)

    async def _rollback(self, job: ResponseJob, adapter, plan: dict,
                        applied: ApplyResult, *, reason: str,
                        actor: str = "system") -> ResponseJob:
        job = self.jobs.transition(job.job_id, JobState.ROLLING_BACK, actor=actor,
                                   detail=reason)
        result = await adapter.rollback(plan, applied)
        if result.ok:
            return self.jobs.transition(job.job_id, JobState.ROLLED_BACK, actor=actor,
                                        detail=result.detail,
                                        rollback_result=result.to_dict())

        job = self.jobs.transition(job.job_id, JobState.ROLLBACK_FAILED, actor=actor,
                                   detail=result.detail,
                                   rollback_result=result.to_dict())
        logger.error("GỠ THẤT BẠI cho job %s (%s): %s — hệ thống đang ở trạng thái "
                     "không xác định", job.job_id, job.action, result.detail)
        if self.on_critical is not None:
            try:
                self.on_critical(job, result.detail)
            except Exception:  # noqa: BLE001 — báo động hỏng không được che sự cố
                logger.exception("Không gửi được cảnh báo gỡ thất bại")
        return job

    # --- phục hồi sau crash ---

    async def recover(self) -> list[dict]:
        """Xử lý job dang dở khi agent khởi động lại.

        Gate Phase 4: "Kill agent tại mọi state vẫn recover hoặc rollback đúng."

        Nguyên tắc: trạng thái dang dở nghĩa là ta KHÔNG BIẾT hệ thống đang ở
        đâu. Với action đảo ngược được, gỡ về trạng thái đã biết. Với action
        không đảo ngược được, để nguyên và báo cho người — tự động "sửa" một
        thứ không đảo ngược được là cách làm hỏng thêm.
        """
        handled: list[dict] = []
        for job in self.jobs.unfinished():
            adapter = self.adapters.get(job.action)
            if adapter is None:
                self.jobs.transition(job.job_id, JobState.ROLLING_BACK, actor="recovery",
                                     detail="khởi động lại: không có adapter")
                self.jobs.transition(job.job_id, JobState.ROLLBACK_FAILED, actor="recovery",
                                     detail=f"không có adapter cho {job.action}")
                handled.append({"job_id": job.job_id, "outcome": "no_adapter"})
                continue
            if not adapter.reversible:
                handled.append({"job_id": job.job_id, "outcome": "left_for_human"})
                logger.error("Job %s (%s) dang dở và KHÔNG đảo ngược được — cần người xử lý",
                             job.job_id, job.action)
                continue
            applied = ApplyResult(True, "", dict(job.apply_result.get("rollback_token") or {}))
            result = await self._rollback(job, adapter, {**job.target, "ttl_s": job.ttl_s},
                                          applied, reason="phục hồi sau khi agent khởi động lại",
                                          actor="recovery")
            handled.append({"job_id": job.job_id, "outcome": result.state})
        return handled

    async def expire_due(self) -> list[dict]:
        """Gỡ các job đã quá TTL. Đây là thứ biến 'chặn tạm thời' thành tạm thời."""
        expired: list[dict] = []
        for job in self.jobs.expired():
            result = await self.rollback(job.job_id, actor="ttl",
                                         reason=f"hết hạn {job.ttl_s}s")
            expired.append({"job_id": job.job_id, "outcome": result.state})
        return expired
