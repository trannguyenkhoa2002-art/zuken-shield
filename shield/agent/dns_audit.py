"""Tự kiểm soát DNS của chính máy này (KE-HOACH-SHIELD.md mục 7 — chỉ đọc
cấu hình + truy vấn DNS bình thường, không tấn công, không giả mạo gì).

Ba việc tách bạch:

1. `read_resolvers()` — DNS server máy đang THẬT SỰ dùng. Ưu tiên
   `resolvectl status` (systemd-resolved, mặc định trên Ubuntu hiện đại) vì
   `/etc/resolv.conf` ở đó chỉ trỏ tới 127.0.0.53 — đọc mỗi resolv.conf sẽ
   luôn thấy "127.0.0.53" và không bao giờ phát hiện được DNS bị đổi. Rơi
   về `/etc/resolv.conf` khi không có systemd-resolved.

2. `read_hosts_overrides()` — dòng bất thường trong /etc/hosts. Sửa
   /etc/hosts là cách chiếm domain cục bộ kinh điển của malware: không cần
   đụng mạng, không log ở đâu, mọi trình duyệt đều dính.

3. `hijack_check()` — hỏi cùng 1 domain qua resolver của máy và qua resolver
   công khai đã biết, so IP trả về. Đây là truy vấn DNS thông thường như mọi
   ứng dụng khác vẫn làm, chỉ khác là hỏi 2 nơi rồi đối chiếu.

Lưu ý về "khác nhau": CDN lớn (google.com, cloudflare.com) trả IP khác nhau
theo vị trí/lần hỏi là BÌNH THƯỜNG. Vì vậy hijack_check chỉ báo "nghi ngờ"
khi tập IP rời nhau hoàn toàn VÀ domain nằm trong danh sách domain có IP
tương đối ổn định — kết quả luôn cần người đọc tự đánh giá, không tự sinh
alert critical.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from pathlib import Path

logger = logging.getLogger("shield.dns_audit")

HOSTS_PATH = Path("/etc/hosts")
RESOLV_CONF_PATH = Path("/etc/resolv.conf")

# Resolver công khai dùng làm "ý kiến thứ hai" khi test hijack. Cố tình dùng
# 2 nhà cung cấp khác nhau để 1 bên bị chặn/lỗi không kết luận sai.
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"]

# Domain dùng để test — chọn loại có IP tương đối ổn định, KHÔNG dùng CDN lớn
# (google.com/facebook.com) vì chúng trả IP khác nhau theo vị trí là bình
# thường, sẽ báo động giả liên tục.
HIJACK_TEST_DOMAINS = ["example.com", "iana.org", "debian.org"]

DNS_QUERY_TIMEOUT_S = 5

# Các entry mặc định của mọi bản Ubuntu/Debian — không phải "override".
_DEFAULT_HOSTS_NAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
}

_RESOLVECTL_DNS_RE = re.compile(r"(?:Current DNS Server|DNS Servers):\s*(.+)")
_IP_TOKEN_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\b")


async def _run(cmd: list[str], timeout: float = DNS_QUERY_TIMEOUT_S) -> tuple[bool, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except FileNotFoundError:
        return False, f"Không có lệnh {cmd[0]}"
    except asyncio.TimeoutError:
        return False, f"Quá thời gian chờ ({timeout}s)"
    if proc.returncode != 0:
        return False, stderr.decode(errors="ignore").strip()
    return True, stdout.decode(errors="ignore")


# --- 1. Resolver đang dùng thật ---


def parse_resolvectl(output: str) -> list[str]:
    """Lấy danh sách DNS server từ output `resolvectl status`.

    Output có nhiều block (Global + từng link); gom hết IP thấy được rồi khử
    trùng, giữ nguyên thứ tự xuất hiện — thứ tự phản ánh độ ưu tiên.
    """
    servers: list[str] = []
    for m in _RESOLVECTL_DNS_RE.finditer(output):
        for token in _IP_TOKEN_RE.findall(m.group(1)):
            try:
                ipaddress.ip_address(token)
            except ValueError:
                continue
            if token not in servers:
                servers.append(token)
    return servers


def parse_resolv_conf(content: str) -> list[str]:
    """Lấy `nameserver <ip>` từ nội dung /etc/resolv.conf, bỏ dòng comment."""
    servers: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            try:
                ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if parts[1] not in servers:
                servers.append(parts[1])
    return servers


async def read_resolvers() -> tuple[list[str], str]:
    """Trả (danh sách DNS server, nguồn đọc được). Nguồn là 'resolvectl' hoặc
    'resolv.conf' — hiển thị cho người dùng biết số liệu tới từ đâu."""
    ok, out = await _run(["resolvectl", "status"])
    if ok:
        servers = parse_resolvectl(out)
        # 127.0.0.53 là stub của chính systemd-resolved, không phải DNS thật
        # upstream — lọc ra để baseline không bị vô nghĩa.
        servers = [s for s in servers if not s.startswith("127.0.0.53")]
        if servers:
            return servers, "resolvectl"

    try:
        content = RESOLV_CONF_PATH.read_text(errors="ignore")
    except OSError as e:
        logger.warning("Không đọc được %s: %s", RESOLV_CONF_PATH, e)
        return [], "không đọc được"
    return parse_resolv_conf(content), "resolv.conf"


# --- 2. /etc/hosts ---


def parse_hosts_overrides(content: str, hostname: str | None = None) -> list[dict]:
    """Dòng /etc/hosts trỏ 1 tên KHÔNG phải loopback mặc định.

    Không tự kết luận "độc hại" — lập trình viên tự thêm entry dev là chuyện
    thường. Chỉ liệt kê để người dùng nhìn lại xem có dòng nào mình không
    thêm hay không.

    `hostname` (tên máy) được lọc bỏ vì Debian/Ubuntu luôn tự tạo dòng
    `127.0.1.1 <tên-máy>` lúc cài — để lại thì tab DNS lúc nào cũng hiện 1
    dòng "bất thường" giả, đúng kiểu cảnh báo nhiễu làm người dùng bỏ qua
    luôn cả cảnh báo thật.

    Lưu ý: entry trỏ về 127.0.0.1 KHÔNG bị bỏ qua — chặn domain bằng cách
    trỏ về loopback vừa là mẹo chặn quảng cáo, vừa là cách mã độc chặn cập
    nhật phần mềm diệt virus, nên vẫn đáng để người dùng nhìn lại.
    """
    ignored_names = set(_DEFAULT_HOSTS_NAMES)
    if hostname:
        ignored_names.add(hostname)
        ignored_names.add(f"{hostname}.localdomain")

    overrides: list[dict] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip, names = parts[0], parts[1:]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        interesting = [n for n in names if n not in ignored_names]
        if not interesting:
            continue
        overrides.append({"ip": ip, "names": interesting, "line": line})
    return overrides


def read_hosts_overrides() -> list[dict]:
    import socket

    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = None
    try:
        return parse_hosts_overrides(HOSTS_PATH.read_text(errors="ignore"), hostname)
    except OSError as e:
        logger.warning("Không đọc được %s: %s", HOSTS_PATH, e)
        return []


# --- 3. Test hijack: so resolver máy vs resolver công khai ---


def parse_dig_answers(output: str) -> list[str]:
    """Lấy danh sách IP từ `dig +short <domain> A`. Bỏ dòng CNAME/rác."""
    ips: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            continue
        if line not in ips:
            ips.append(line)
    return ips


async def _resolve(domain: str, server: str | None) -> list[str]:
    cmd = ["dig", "+short", "+time=3", "+tries=1"]
    if server:
        cmd.append(f"@{server}")
    cmd += [domain, "A"]
    ok, out = await _run(cmd)
    return parse_dig_answers(out) if ok else []


def compare_answers(local: list[str], public: list[str]) -> str:
    """'ok' nếu có ít nhất 1 IP chung, 'suspect' nếu 2 tập rời nhau hoàn
    toàn, 'unknown' nếu 1 bên không trả lời được (mạng hỏng/bị chặn — không
    đủ căn cứ để kết luận)."""
    if not local or not public:
        return "unknown"
    return "ok" if set(local) & set(public) else "suspect"


async def hijack_check() -> tuple[bool, str, list[dict]]:
    """So kết quả phân giải giữa resolver của máy và resolver công khai.

    Chỉ gửi truy vấn DNS thông thường (qua `dig`) — không giả mạo, không can
    thiệp gì vào mạng. Cần `dnsutils` (`dig`) và cần internet lúc chạy test.
    """
    ok, _ = await _run(["dig", "-v"], timeout=3)
    if not ok:
        # `dig -v` in ra stderr và trả về 0 trên vài bản; thử cách khác trước
        # khi kết luận thiếu công cụ.
        probe_ok, _ = await _run(["which", "dig"], timeout=3)
        if not probe_ok:
            return False, "Thiếu lệnh `dig` — cài bằng: sudo apt install dnsutils", []

    results: list[dict] = []
    for domain in HIJACK_TEST_DOMAINS:
        local = await _resolve(domain, None)
        public: list[str] = []
        for resolver in PUBLIC_RESOLVERS:
            public = await _resolve(domain, resolver)
            if public:
                break
        results.append(
            {
                "domain": domain,
                "local": local,
                "public": public,
                "verdict": compare_answers(local, public),
            }
        )

    suspects = sum(1 for r in results if r["verdict"] == "suspect")
    logger.info("hijack_check: %d/%d domain nghi ngờ", suspects, len(results))
    return True, "OK", results
