"""Sinh, nuôi, và GIẾT tiến trình worker model. Phía agent.

Đây là chỗ duy nhất trong `shield.ai` chạm tới `os.kill`. Nó tồn tại vì một
sự thật khó chịu: `asyncio.wait_for` không giết được gì. Nó bỏ chờ, rồi trả
điều khiển cho agent trong khi tiến trình bên kia vẫn quay CPU và vẫn cấp phát
bộ nhớ. Với một model treo, đó chỉ là agent thôi nhìn vào một đám cháy vẫn
đang cháy.

Bốn bất biến, và mỗi cái tương ứng một cách worker có thể phản bội:

1. **Đọc CÓ TRẦN.** Không `communicate()`, không `readline()`. Cả hai đều đọc
   tới khi worker ngừng nói, và một worker thù địch không bao giờ ngừng nói.
   Ở đây agent đọc đúng số byte tiền tố độ dài khai báo, sau khi đã kiểm số
   đó — nên một khung khai báo 4 GiB bị từ chối trước khi cấp phát byte nào.
2. **Giết theo NHÓM tiến trình.** `start_new_session=True` đặt worker vào một
   session/process group riêng, nên `killpg` quét cả cháu chắt. Giết mỗi tiến
   trình con để lại một cây tiến trình mồ côi mà không ai còn nhớ.
3. **SIGTERM -> ân hạn -> SIGKILL.** Cho cơ hội thoát sạch, rồi không hỏi nữa.
   SIGKILL không chặn được, nên đây là đường dứt điểm thật sự.
4. **Luôn `wait()`.** Một tiến trình đã giết mà không thu hoạch là một zombie,
   và zombie ăn slot trong bảng tiến trình của cả hệ thống.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import os
import signal
import sys
import time

from shield.ai.capability import ai_tools_killed
from shield.ai.worker import netns, protocol, scope
from shield.ai.worker.limits import ResourceLimits

logger = logging.getLogger("shield.ai.worker")

# Ân hạn giữa SIGTERM và SIGKILL. Đủ để một worker lành mạnh đóng sổ, đủ ngắn
# để một worker thù địch không kéo dài được lượt tắt.
TERM_GRACE_S = 2.0

# Trần byte cho stderr giữ lại. stderr của worker là thứ hữu ích nhất khi
# chẩn đoán một lần sập — và cũng là kênh rẻ nhất để làm agent hết bộ nhớ.
MAX_STDERR_BYTES = 64 * 1024

# Số worker chạy đồng thời. Một là con số đúng cho 3C-0: mỗi incident đã bị
# giới hạn một lượt điều tra tại một thời điểm từ Phase 2, và nhiều worker
# song song nghĩa là nhân trần bộ nhớ lên đúng bấy nhiêu lần.
MAX_CONCURRENT_WORKERS = 1

# Điểm vào mặc định. `-I` bỏ qua mọi biến PYTHON* của người dùng và KHÔNG thêm
# thư mục làm việc vào `sys.path` — một file `json.py` nằm cạnh đó không được
# trở thành module `json` của worker.
DEFAULT_COMMAND = (sys.executable, "-I", "-m", "shield.ai.worker")


class WorkerFailure(RuntimeError):
    """Worker không trả lời được. Mang MÃ đóng, không phải một câu văn."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code if code in protocol.FAILURE_CODES else "crashed"
        self.detail = detail


@dataclasses.dataclass
class WorkerHealth:
    """Số liệu vận hành của ranh giới tiến trình. KHÔNG chứa output model.

    Không một byte nào worker sinh ra được đi vào đây: `last_error_code` là mã
    đóng của Shield, không phải thông điệp của worker. Bảng sức khoẻ hiển thị
    lên giao diện và sống lâu hơn lượt điều tra — một bí mật lọt vào đây sẽ ở
    lại rất lâu.
    """

    state: str = "disabled"         # running | idle | degraded | disabled
    requests: int = 0
    successes: int = 0
    fallbacks: int = 0
    malformed_outputs: int = 0
    spawns: int = 0
    restarts: int = 0
    scope_start_failures: int = 0
    cleanup_failures: int = 0
    timeouts: int = 0
    crashes: int = 0
    resource_limit_exits: int = 0
    malformed_frames: int = 0
    kills: int = 0
    last_error_code: str = ""
    last_exit_signal: int = 0
    last_request_ms: float = 0.0

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _signal_name(returncode: int | None) -> str:
    if returncode is None or returncode >= 0:
        return ""
    with contextlib.suppress(ValueError):
        return signal.Signals(-returncode).name
    return ""


# Tín hiệu nói rằng KERNEL đã can thiệp vì tài nguyên, không phải worker tự
# hỏng. Phân biệt được hai thứ này là khác nhau giữa "model này quá nặng cho
# máy" và "model này có lỗi" — hai kết luận dẫn tới hai hành động khác nhau.
_RESOURCE_SIGNALS = {
    getattr(signal, name).value
    for name in ("SIGXCPU", "SIGXFSZ", "SIGKILL")
    if hasattr(signal, name)
}


class WorkerSupervisor:
    """Vòng đời của một tiến trình worker, mỗi yêu cầu một tiến trình.

    Mỗi yêu cầu một tiến trình MỚI, có chủ ý: một worker sống qua nhiều yêu cầu
    mang theo trạng thái từ lượt trước, và trạng thái đó là đúng thứ một lần
    prompt injection cần để sống sót sang incident kế tiếp. Chi phí sinh tiến
    trình được đo trong benchmark, không phỏng đoán.
    """

    def __init__(self, *, command: tuple[str, ...] = (),
                 limits: ResourceLimits | None = None,
                 request_timeout_s: float = 30.0,
                 max_concurrent: int = MAX_CONCURRENT_WORKERS,
                 network: str = "deny",
                 cgroup_scope: dict | None = None,
                 model_config_json: str = "") -> None:
        # `command` do MÃ AGENT chọn, không bao giờ do worker hay dữ liệu điều
        # tra chọn. Nó là một seam có chủ ý: một supervisor không chỉ định được
        # chương trình để chạy thì không chứng minh được nó sống sót trước một
        # worker thù địch — và bộ test đó chính là lý do lớp này tồn tại.
        # Bất biến an ninh nằm ở thứ ĐƯA CHO worker (không DB, không token,
        # không đường dẫn), không ở chỗ điểm vào là bất biến.
        self.command = tuple(command) or DEFAULT_COMMAND
        self.limits = limits or ResourceLimits()
        self.request_timeout_s = float(request_timeout_s)
        # `deny` là MẶC ĐỊNH, và mặc định là chỗ duy nhất quan trọng: một tuỳ
        # chọn an toàn phải bật sẵn thì mới có tác dụng. `allow` tồn tại cho
        # bộ test cách ly của 3C-0 — những bài đó đo việc giết tiến trình, và
        # bọc thêm một namespace chỉ làm chậm mà không đo thêm gì.
        if network not in {"deny", "allow"}:
            raise ValueError(f"network phải là 'deny' hoặc 'allow', không phải {network!r}")
        self.network = network
        # `None` = không dùng scope (bộ test cách ly của 3C-0 đo việc giết tiến
        # trình, không đo bộ nhớ). Một dict = trần cgroup, và khi đó KHÔNG dựng
        # được scope là lý do TỪ CHỐI chạy — không có đường chạy tạm trong
        # cgroup của agent, vì đó đúng là thứ scope tồn tại để ngăn.
        self.cgroup_scope = dict(cgroup_scope) if cgroup_scope else None
        # Unit của lượt đang chạy. Dọn dẹp phải giết theo UNIT, không theo pid:
        # `systemd-run --scope` thoát sau khi đăng ký scope trong khi payload
        # tiếp tục chạy bên trong cgroup.
        self._scope_unit: str = ""
        # Ta có chủ động giết lượt này không. Quyết định phân loại mã thoát:
        # 137 do ta gửi SIGKILL khác hẳn 137 do kernel OOM-kill.
        self._we_killed = False
        # Cấu hình model đi vào worker QUA ĐÂY, không qua môi trường thừa kế.
        #
        # Trước sửa này, `_spawn` dựng một môi trường tối thiểu không có
        # `SHIELD_AI_MODEL_*`, nên `from_environment()` bên trong worker LUÔN
        # trả `None` và vỏ worker luôn rơi về bộ phân tích tất định — model
        # không bao giờ nạp được trong sản phẩm. Lỗi chỉ lộ ra khi chạy model
        # thật qua đúng supervisor.
        #
        # Truyền chuỗi JSON ĐÃ KIỂM thay vì để worker đọc môi trường xung
        # quanh: adapter đã `ModelConfig.parse` nó, nên worker nhận đúng thứ
        # agent chấp nhận chứ không phải thứ ai đó đặt vào environment.
        self.model_config_json = str(model_config_json or "")
        self.health = WorkerHealth()
        self._semaphore = asyncio.Semaphore(max(1, int(max_concurrent)))

    # --- sinh ---

    async def _spawn(self) -> asyncio.subprocess.Process:
        """Môi trường TỐI THIỂU, không thừa một biến.

        Không `SHIELD_DB`, không `SHIELD_HELPER_SOCK`, không `SHIELD_SOCK`.
        Worker không cần biết chúng tồn tại, và một biến môi trường bị thừa là
        một đường dẫn kẻ tấn công không phải tự đoán ra.
        """
        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "PYTHONHASHSEED": "0",     # cùng đầu vào, cùng thứ tự băm
            "PYTHONDONTWRITEBYTECODE": "1",
            "SHIELD_WORKER_LIMITS": self.limits.to_json(),
        }
        if self.model_config_json:
            from shield.ai.model_config import ENV_CONFIG

            env[ENV_CONFIG] = self.model_config_json
        command = self.command
        self._scope_unit = ""
        if self.cgroup_scope is not None:
            try:
                scope_argv, self._scope_unit = scope.prefix(**self.cgroup_scope)
                command = scope_argv + command
                # Chỉ đường phát triển mới thêm gì: xem `launcher_env`.
                env.update(scope.launcher_env())
            except scope.ScopeUnavailable as exc:
                self.health.scope_start_failures += 1
                self.health.last_error_code = "scope_unavailable"
                self.health.state = "degraded"
                raise WorkerFailure("scope_unavailable", str(exc)) from exc
        if self.network == "deny":
            decision = netns.plan()
            if decision["mechanism"] == "none":
                # FAIL CLOSED. Không có "chạy tạm không cách ly": một mặc định
                # thất bại theo hướng mở là một mặc định không tồn tại.
                self.health.last_error_code = "spawn_failed"
                self.health.state = "degraded"
                raise WorkerFailure(
                    "spawn_failed",
                    "không cắt được mạng cho worker — từ chối chạy model")
            if decision["worker_unshares"]:
                env[netns.NETNS_ENV] = "1"
            command = tuple(decision["prefix"]) + command
        try:
            return await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=env,
                # Session riêng: đây là thứ làm `killpg` quét được cả cháu.
                start_new_session=True,
                # Và là thứ ngắt worker khỏi terminal của agent — Ctrl-C ở
                # agent không được đi thẳng vào tiến trình model.
                cwd="/",
            )
        except OSError as exc:
            self.health.last_error_code = "spawn_failed"
            self.health.state = "degraded"
            raise WorkerFailure("spawn_failed", type(exc).__name__) from exc

    # --- giết ---

    async def _terminate(self, process: asyncio.subprocess.Process,
                         *, natural_grace_s: float = 0.0) -> None:
        """SIGTERM -> ân hạn -> SIGKILL, trên cả NHÓM. Rồi thu hoạch.

        `natural_grace_s` cho một worker ĐÃ TRẢ LỜI XONG cơ hội tự thoát. Không
        có nó, mọi lượt thành công đều kết thúc bằng SIGTERM và bị `_classify_exit`
        đếm là một lần sập — sức khoẻ khi ấy báo `degraded` sau một lượt hoàn
        hảo, và một chỉ số luôn đỏ là một chỉ số không ai đọc.

        Không bao giờ ném: đây là đường dọn dẹp, và một ngoại lệ ở đây sẽ để
        lại đúng thứ nó được gọi để dọn.
        """
        if natural_grace_s > 0 and process.returncode is None:
            with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(process.wait()), natural_grace_s)
        if process.returncode is not None:
            with contextlib.suppress(Exception):
                await process.wait()
            return
        try:
            pgid = os.getpgid(process.pid)
        except (ProcessLookupError, PermissionError):
            pgid = None

        self._we_killed = True
        for sig, wait_s in ((signal.SIGTERM, TERM_GRACE_S), (signal.SIGKILL, 5.0)):
            if process.returncode is not None:
                break
            with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
                if pgid is not None:
                    os.killpg(pgid, sig)
                else:
                    process.send_signal(sig)
            self.health.kills += 1
            with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(asyncio.shield(process.wait()), wait_s)

        # Thu hoạch dù thế nào: một tiến trình đã giết mà không `wait()` là một
        # zombie, và zombie ăn slot trong bảng tiến trình của cả hệ thống.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(asyncio.shield(process.wait()), 5.0)
        await self._collect_scope()

    async def _collect_scope(self) -> None:
        """Giết mọi tiến trình còn trong scope, rồi để `--collect` dọn unit.

        Không làm bước này thì một worker phớt lờ SIGTERM sống sót nguyên vẹn
        bên trong một scope không ai còn nhớ — đã quan sát được đúng như vậy
        trước khi có hàm này.
        """
        if not self._scope_unit:
            return
        unit, self._scope_unit = self._scope_unit, ""
        try:
            argv = scope.stop_argv(unit)
        except scope.ScopeUnavailable:
            self.health.cleanup_failures += 1
            return
        try:
            killer = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(killer.wait(), 5.0)
        except (TimeoutError, OSError, asyncio.CancelledError):
            # Không ném: đây là đường dọn dẹp. Nhưng ĐẾM — một scope không dọn
            # được là một cgroup còn giữ bộ nhớ mà không ai nhìn.
            self.health.cleanup_failures += 1

    # --- đọc có trần ---

    @staticmethod
    async def _read_exactly(stream, size: int) -> bytes:
        """Đọc đúng `size` byte, hoặc `IncompleteReadError` khi ống đóng sớm.

        `readexactly` đúng ở đây vì `size` ĐÃ được kiểm trần trước khi gọi —
        agent không bao giờ cấp phát theo một con số worker tự chọn.
        """
        return await stream.readexactly(size)

    async def _drain_stderr(self, process) -> bytes:
        """Giữ tối đa `MAX_STDERR_BYTES`, phần thừa ĐỌC RỒI BỎ.

        Không đóng ống và cũng không ngừng đọc: một ống stderr đầy làm worker
        chặn ở `write` mãi mãi, và khi đó nó trông y hệt một model đang treo.
        """
        chunks, kept = [], 0
        try:
            while True:
                chunk = await process.stderr.read(16 * 1024)
                if not chunk:
                    break
                if kept < MAX_STDERR_BYTES:
                    take = MAX_STDERR_BYTES - kept
                    chunks.append(chunk[:take])
                    kept += len(chunk[:take])
        except (asyncio.CancelledError, ConnectionError, ValueError):
            pass
        return b"".join(chunks)

    # --- một yêu cầu ---

    async def request(self, worker_request: protocol.WorkerRequest) -> protocol.WorkerResponse:
        """Một yêu cầu, một tiến trình. Ném `WorkerFailure` với MÃ đóng.

        KHÔNG BAO GIỜ để tiến trình sống sót quá lời gọi này, dù thoát bằng
        đường nào — kể cả khi chính lời gọi này bị huỷ.
        """
        if ai_tools_killed():
            # Kill switch chặn TRƯỚC khi sinh tiến trình. Người vận hành bật nó
            # vì họ nghi ngờ chính lớp này; sinh một tiến trình model rồi mới
            # giết nó đi là đã chạy đúng thứ họ vừa cấm.
            self.health.last_error_code = "kill_switch"
            self.health.state = "stopped"
            raise WorkerFailure("kill_switch", "kill switch AI đang bật")

        if self._semaphore.locked():
            self.health.last_error_code = "busy"
            raise WorkerFailure("busy", "đã có worker đang chạy")

        async with self._semaphore:
            started = time.monotonic()
            self.health.requests += 1
            self._we_killed = False
            process = await self._spawn()
            self.health.spawns += 1
            self.health.state = "running"
            stderr_task = asyncio.create_task(self._drain_stderr(process))
            answered = False
            try:
                response = await self._await_exchange(process, worker_request)
                answered = True
                if response.ok:
                    self.health.successes += 1
                else:
                    self.health.malformed_outputs += 1
                    self.health.last_error_code = response.failure_code
                return response
            except TimeoutError:
                self.health.timeouts += 1
                self.health.last_error_code = "timeout"
                raise WorkerFailure("timeout", "worker quá hạn") from None
            except protocol.FrameError as exc:
                self.health.malformed_frames += 1
                self.health.last_error_code = "malformed_frame"
                raise WorkerFailure("malformed_frame", str(exc)) from None
            except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
                self.health.last_error_code = "pipe_closed"
                raise WorkerFailure("pipe_closed", "worker đóng ống giữa chừng") from None
            finally:
                # `finally`, KHÔNG phải cuối đường thành công: timeout, sập,
                # khung hỏng, và cả lúc lời gọi này bị huỷ — mọi đường đều
                # thoát qua đây, và mỗi lần thoát mà không giết là một tiến
                # trình model còn sống mà không ai nhớ.
                await self._terminate(process, natural_grace_s=1.0 if answered else 0.0)
                stderr_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await stderr_task
                # Một worker đã trả lời rồi mới bị ta giết KHÔNG phải một lần
                # sập. Đếm nó như sập làm một model hoàn hảo trông như hỏng.
                if not answered:
                    self._classify_exit(process)
                if self.health.state == "running":
                    # Không còn tiến trình nào chạy sau lời gọi này. `running`
                    # ở đây sẽ là một trạng thái không bao giờ đúng.
                    self.health.state = "idle"
                self.health.last_request_ms = round(
                    (time.monotonic() - started) * 1000, 3)

    async def _await_exchange(self, process, worker_request) -> protocol.WorkerResponse:
        """Chờ phản hồi, nhưng CÙNG LÚC canh kill switch.

        Chỉ kiểm kill switch lúc sinh là không đủ: một lượt điều tra có thể
        chạy hàng chục giây, và người vận hành bật công tắc GIỮA lúc đó chính
        là tình huống công tắc tồn tại để phục vụ. Bắt họ chờ hết `deadline`
        biến công tắc "dừng ngay" thành công tắc "dừng lát nữa".
        """
        exchange = asyncio.create_task(self._exchange(process, worker_request))
        watch = asyncio.create_task(self._watch_kill_switch())
        try:
            done, _pending = await asyncio.wait(
                {exchange, watch}, timeout=self.request_timeout_s,
                return_when=asyncio.FIRST_COMPLETED)
            if exchange in done:
                return exchange.result()
            if watch in done:
                self.health.last_error_code = "kill_switch"
                self.health.state = "stopped"
                raise WorkerFailure("kill_switch", "kill switch bật giữa lượt")
            raise TimeoutError
        finally:
            for task in (exchange, watch):
                task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.gather(exchange, watch, return_exceptions=True)

    @staticmethod
    async def _watch_kill_switch(interval_s: float = 0.2) -> None:
        """Trả về khi kill switch bật. Đọc biến môi trường MỖI LẦN, không cache
        — cùng lý do `ai_tools_killed()` không cache."""
        while not ai_tools_killed():
            await asyncio.sleep(interval_s)

    async def _exchange(self, process, worker_request) -> protocol.WorkerResponse:
        frame = protocol.encode_frame(worker_request.to_payload(),
                                      limit=protocol.MAX_REQUEST_BYTES)
        process.stdin.write(frame)
        await process.stdin.drain()
        # Đóng stdin ngay: worker không có gì thêm để đọc, và một ống mở là
        # một lý do để nó chờ mãi.
        with contextlib.suppress(BrokenPipeError, ConnectionError, OSError):
            process.stdin.close()

        header = await self._read_exactly(process.stdout, protocol.HEADER_BYTES)
        size = protocol.decode_header(header, limit=protocol.MAX_RESPONSE_BYTES)
        body = await self._read_exactly(process.stdout, size)
        payload = protocol.decode_body(body)
        return protocol.WorkerResponse.parse(payload, expect_id=worker_request.request_id)

    def _classify_exit(self, process) -> None:
        """Mã thoát -> số liệu. Phân biệt kernel can thiệp với worker tự hỏng.

        Qua `systemd-run`, một tiến trình bị tín hiệu giết KHÔNG còn hiện ra
        thành `returncode` âm: launcher thoát với 128+N. Không dịch lại thì một
        lần cgroup OOM-kill (137) bị đếm là "worker tự sập", và số liệu tài
        nguyên luôn bằng 0 đúng lúc nó đáng đọc nhất.
        """
        code = process.returncode
        if code is None or code == 0:
            return
        if 128 < code < 128 + 65 and self.cgroup_scope is not None:
            signalled = code - 128
            self.health.last_exit_signal = signalled
            if signalled == int(signal.SIGKILL) and not self._we_killed:
                # Ta không giết, nhưng nó chết vì SIGKILL -> kernel/cgroup đã
                # can thiệp. Trên đường có scope, đó gần như luôn là OOM.
                self.health.resource_limit_exits += 1
                self.health.last_error_code = "resource_limit"
            else:
                self.health.crashes += 1
                if not self.health.last_error_code:
                    self.health.last_error_code = "crashed"
            self.health.state = "degraded"
            return
        if code < 0:
            self.health.last_exit_signal = -code
            if -code in _RESOURCE_SIGNALS and self.health.last_error_code != "timeout":
                self.health.resource_limit_exits += 1
                self.health.last_error_code = "resource_limit"
            else:
                self.health.crashes += 1
                if not self.health.last_error_code:
                    self.health.last_error_code = "crashed"
            self.health.state = "degraded"
        else:
            self.health.crashes += 1
            self.health.state = "degraded"
            if not self.health.last_error_code:
                self.health.last_error_code = "worker_exit"


# --- sức khoẻ có cấu trúc ---

HEALTH_COMPONENT = "ai_model_worker"


def publish_health(store, health: WorkerHealth, *, enabled: bool = True) -> None:
    """Đưa trạng thái worker vào bảng sức khoẻ chung. KHÔNG rò output model.

    `detail` được dựng từ BỘ ĐẾM, không từ một byte nào worker sinh ra. Bảng
    này hiển thị lên giao diện và sống lâu hơn lượt điều tra; một bí mật lọt
    vào đây sẽ ở lại rất lâu.

    `backend="disabled"` khi AI tắt là có chủ ý: `problems.component_is_enabled`
    đọc đúng nhãn đó để không báo động về một tính năng chưa bao giờ bật.

    Thành phần này nằm trong `NON_TELEMETRY_COMPONENTS`, nên nó KHÔNG trừ điểm
    sức khoẻ tổng — xem `shield.security.health`. Một worker sập không làm
    Shield mù mảng nào: detection chạy y nguyên và điều tra rơi về phương án
    tất định của Phase 3B.
    """
    if not enabled:
        # `disabled` là một TRẠNG THÁI, không phải một lỗi. Kill switch bật,
        # hoặc chưa ai cấu hình model — cả hai đều là "đang tắt đúng như mong
        # đợi", và hiện chúng như hỏng dạy người dùng bỏ qua bảng sức khoẻ.
        store.set_collector_health(HEALTH_COMPONENT, "disabled", True,
                                   "AI analysis is disabled", state="disabled")
        return
    detail = (f"requests={health.requests} successes={health.successes} "
              f"fallbacks={health.fallbacks} timeouts={health.timeouts} "
              f"crashes={health.crashes} "
              f"malformed_outputs={health.malformed_outputs} "
              f"resource_limit_exits={health.resource_limit_exits} "
              f"scope_start_failures={health.scope_start_failures} "
              f"cleanup_failures={health.cleanup_failures} "
              f"spawns={health.spawns}")
    store.set_collector_health(
        HEALTH_COMPONENT, "isolated-subprocess",
        health.state in {"running", "idle", "disabled"},
        detail, state=health.state, restart_count=health.restarts,
        # MÃ đóng, không phải thông điệp của worker.
        error_message=health.last_error_code,
    )
