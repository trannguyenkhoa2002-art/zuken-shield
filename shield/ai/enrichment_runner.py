"""Thực thi job làm giàu — NGOÀI vòng lặp đọc IPC (Phase 3D rollout).

Vì sao tách khỏi vòng lặp IPC: `await self._on_command(msg)` chạy ngay trong
vòng đọc của một kết nối, nên một lượt suy luận 15 giây khoá luôn mọi lệnh tiếp
theo của client đó. Người dùng bấm "điều tra" rồi không bấm được gì nữa trong
15 giây — cho một kết quả họ đã có sau 0,1 giây.

Runner này là một task nền DUY NHẤT, có chủ sở hữu rõ ràng (agent tạo và huỷ
nó), giới hạn đồng thời bằng 1, và không có hàng đợi trong bộ nhớ — hàng đợi
nằm trong bảng, nên một lần khởi động lại không làm mất việc và cũng không để
lại việc ma.

Đây KHÔNG phải một khung tác vụ nền tổng quát. Nó chạy đúng một loại việc.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from shield.ai import enrichment

logger = logging.getLogger("shield.ai.enrichment")

# Nhịp thăm dò. Đủ nhanh để văn xuôi tới trong khi người dùng còn nhìn báo cáo,
# đủ chậm để không đánh thức tiến trình vô ích khi không có việc.
POLL_INTERVAL_S = 2.0


# Đồng thời TOÀN CỤC cho mọi việc cần model. Một worker chạy chiếm ~2 GiB
# trong scope riêng và 300% CPU; hai worker cùng lúc là 5 GiB và 600% trên một
# máy mà chính agent bị giới hạn 1 GiB. Trần này thuộc về RUNNER, không thuộc
# về kho: mỗi kho đếm hàng của riêng nó, nên hai kho tự đếm sẽ cho hai job cùng
# chạy mà vẫn "đúng" theo cách đếm của từng cái.
MAX_CONCURRENT_MODEL_WORKERS = 1


class Queue:
    """Một nguồn việc cho runner: kho + hàm chạy.

    `store` phải có `oldest_pending()`, `claim()`, `finish_ready(id, payload)`,
    `finish_failed(id, code)`, `mark_stale(id)`. Đó là toàn bộ hợp đồng —
    runner không biết gì về fingerprint, ô văn xuôi hay lượt hội thoại.
    """

    __slots__ = ("kind", "store", "execute")

    def __init__(self, kind: str, store, execute) -> None:
        self.kind = kind
        self.store = store
        self.execute = execute


class SharedAiRunner:
    """MỘT task nền cho TẤT CẢ việc cần model. Một job tại một thời điểm.

    Hai hàng đợi — làm giàu báo cáo và hỏi đáp sự cố — dùng chung đúng một
    worker. Chúng KHÔNG dùng chung bảng: mỗi kho giữ máy trạng thái của mình,
    runner chỉ giữ trần đồng thời và thứ tự.

    Chọn việc: cũ nhất trước, phá hoà bằng `(created_at, id)` nên thứ tự là
    ĐỊNH SẴN. Sau mỗi lượt claim thành công, lượt sau ưu tiên hàng đợi CÒN LẠI
    nếu nó có việc — một người dùng hỏi liên tục không được đẩy phần làm giàu
    lùi vô hạn, và ngược lại. Đây là một luật công bằng, không phải một bộ lập
    lịch.

    Đây KHÔNG phải khung tác vụ nền tổng quát. Nó chạy đúng những loại việc
    được khai báo ở đây.
    """

    def __init__(self, *queues: Queue, poll_interval_s: float = POLL_INTERVAL_S) -> None:
        self.queues = [q for q in queues if q is not None]
        self.poll_interval_s = poll_interval_s
        self._task: asyncio.Task | None = None
        self._last_kind = ""
        self.processed = 0
        self.processed_by_kind: dict[str, int] = {}

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop(), name="ai-shared-runner")

    async def stop(self) -> None:
        """Huỷ AN TOÀN. Job đang chạy quay về `pending` để lượt sau làm lại."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._task
        self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                did_work = await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Runner AI lỗi ngoài dự kiến")
                did_work = False
            await asyncio.sleep(0 if did_work else self.poll_interval_s)

    def _order(self) -> list:
        """Thứ tự xét hàng đợi cho lượt này. Thuần, nên test được."""
        ready = []
        for queue in self.queues:
            job = queue.store.oldest_pending()
            if job is not None:
                ready.append((getattr(job, "created_at", 0.0),
                              str(getattr(job, "job_id", "")), queue))
        if not ready:
            return []
        ready.sort(key=lambda item: (item[0], item[1]))
        # Luật công bằng: nếu lượt trước đã chạy loại này và loại kia cũng có
        # việc, nhường loại kia. Không có nó, một bên bận liên tục sẽ luôn có
        # job cũ nhất và bên kia không bao giờ tới lượt.
        if len(ready) > 1 and ready[0][2].kind == self._last_kind:
            for index in range(1, len(ready)):
                if ready[index][2].kind != self._last_kind:
                    ready.insert(0, ready.pop(index))
                    break
        return [item[2] for item in ready]

    async def tick(self) -> bool:
        """Làm nhiều nhất MỘT job, từ nhiều nhất MỘT hàng đợi."""
        for queue in await asyncio.to_thread(self._order):
            job = await asyncio.to_thread(queue.store.claim)
            if job is None:
                continue
            self._last_kind = queue.kind
            await self._run(queue, job)
            return True
        return False

    async def _run(self, queue: Queue, job) -> None:
        try:
            payload, failure = await queue.execute(job)
        except asyncio.CancelledError:
            # Agent đang tắt. Trả job về hàng đợi thay vì bỏ nó ở `running` —
            # một job `running` không ai theo dõi sẽ chặn hàng đợi tới khi có
            # người khởi động lại và chạy `reconcile_startup`.
            await asyncio.to_thread(queue.store.finish_failed, job.job_id,
                                    "internal_error")
            raise
        except Exception as exc:  # noqa: BLE001 — mã model là mã không đáng tin
            logger.warning("Job %s %s lỗi: %s", queue.kind, job.job_id,
                           type(exc).__name__)
            await asyncio.to_thread(queue.store.finish_failed, job.job_id,
                                    "internal_error")
            return
        self.processed += 1
        self.processed_by_kind[queue.kind] = self.processed_by_kind.get(queue.kind, 0) + 1
        if failure:
            await asyncio.to_thread(queue.store.finish_failed, job.job_id, failure)
        elif payload is None:
            # Bằng chứng đã đổi trong lúc suy luận. Kết quả nói về một dữ liệu
            # không còn tồn tại, nên nó không được gắn vào đâu cả.
            await asyncio.to_thread(queue.store.mark_stale, job.job_id)
        else:
            await asyncio.to_thread(queue.store.finish_ready, job.job_id, payload)


def client_status(job) -> str:
    """Trạng thái job -> trạng thái client, cả hai đều ĐÓNG."""
    if job is None:
        return enrichment.CLIENT_DEFERRED
    return {
        enrichment.PENDING: enrichment.CLIENT_PENDING,
        enrichment.RUNNING: enrichment.CLIENT_PENDING,
        enrichment.READY: enrichment.CLIENT_READY,
        enrichment.FAILED: enrichment.CLIENT_FAILED,
        enrichment.STALE: enrichment.CLIENT_FAILED,
    }.get(job.status, enrichment.CLIENT_FAILED)
