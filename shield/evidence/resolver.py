"""Từ Event ra thực thể và quan hệ — tất định, không gọi I/O (mục 1.2, 1.3).

Đây là chỗ duy nhất biết cách đọc một `Event` thành node và edge. Nó là hàm
thuần: cùng một event luôn cho cùng một kết quả, không đọc đĩa, không đọc đồng
hồ, không đọc mạng. Nhờ vậy toàn bộ ngữ nghĩa của graph test được mà không cần
database, và hai máy khác nhau quan sát cùng một sự việc sẽ dựng ra cùng một
graph.

Một điểm dễ sai và tốn kém nếu sai: **event đến từ probe mô tả MÁY KHÁC.** Gán
mọi thứ cho host cục bộ sẽ trộn tiến trình của năm máy vào một thực thể, và mọi
câu hỏi "máy này còn làm gì nữa" đều trả lời sai. Host được suy ra từ `origin`,
không phải từ nơi Shield đang chạy.
"""

from __future__ import annotations

import ipaddress

from shield.common.models import Event
from shield.evidence.models import Edge, Entity, EvidenceKind, entity_id_for

RESOLVER = "shield.evidence.resolver"

# Loại event mà resolver hiểu. Tập đóng và tường minh: một loại không có ở đây
# đơn giản là không sinh cạnh nào — im lặng bỏ qua thì tốt hơn là đoán bừa một
# quan hệ rồi để người điều tra tin vào nó.
# Phiên bản định dạng khoá của thực thể đồ thị. Tăng khi cách dựng
# `canonical_key` đổi — node cũ khi đó mang một danh tính không còn đúng và
# phải được dựng lại, chứ không được để lẫn với node mới.
GRAPH_KEY_FORMATS: dict[str, int] = {
    # 1 -> 2: thêm địa chỉ bind vào khoá service.
    "service": 2,
}

SUPPORTED_KINDS = frozenset({
    "process_exec", "process_started", "file_write", "file_modified",
    "security_file_changed", "socket_connect", "listener_opened",
    "listener_observed",
    "ssh_login", "ssh_auth_success", "host_seen",
})


def host_key_for(event: Event) -> str:
    """Máy nào đã sinh ra event này.

    `local` -> máy đang chạy Shield. `probe:<id>` -> máy có probe đó.
    `syslog:<ip>` -> máy ở địa chỉ đó, và nó KHÔNG có danh tính mật mã nên mọi
    thứ suy ra từ nó mang trust thấp.
    """
    # `data` được hỏi TRƯỚC. Collector đặt origin vào `data` (xem
    # log_ingest.py: "origin/trust do SERVER gắn"), còn trường `Event.origin`
    # có mặc định "local" — một giá trị truthy. Hỏi trường trước thì mặc định
    # luôn thắng và MỌI event từ probe bị gán cho máy cục bộ, trộn tiến trình
    # của mọi máy vào một thực thể. Cùng thứ tự với Store.insert_event.
    origin = str(event.data.get("origin") or event.origin or "local")
    if origin.startswith("probe:"):
        return f"probe:{origin.split(':', 1)[1]}"
    if origin.startswith("syslog:"):
        return f"syslog:{origin.split(':', 1)[1]}"
    return "local"


def _trust_of(event: Event) -> str:
    # Cùng thứ tự ưu tiên, cùng lý do như origin.
    return str(event.data.get("trust") or event.trust or "local")


def _process_key(host_key: str, data: dict) -> str | None:
    """Khoá tiến trình: máy + PID + thời điểm khởi động.

    Chỉ PID là KHÔNG đủ: Linux tái sử dụng PID, nên hai tiến trình cách nhau
    vài phút có thể trùng số. Ghép thêm start_ticks để hai lần chạy khác nhau
    không bị hợp nhất thành một — hợp nhất nhầm ở đây nghĩa là gán hành vi của
    tiến trình này cho tiến trình khác.
    """
    pid = data.get("pid")
    if pid in (None, "", 0):
        return None
    ticks = str(data.get("start_ticks") or "")
    if not ticks:
        identity = str(data.get("process_identity") or "")
        ticks = identity.split(":", 1)[1] if ":" in identity else ""
    if not ticks or ticks == "unknown":
        # Không có danh tính ổn định thì KHÔNG tạo thực thể tiến trình. Một node
        # "pid 4321 trên máy này" gộp mọi tiến trình từng mang số đó lại làm
        # một, và graph sẽ nói dối một cách rất thuyết phục.
        return None
    return f"{host_key}:{pid}:{ticks}"


def _clean_path(value) -> str:
    path = str(value or "").strip()
    return path[:4096] if path else ""


def resolve(event: Event) -> tuple[list[Entity], list[Edge]]:
    """(thực thể, cạnh) suy ra từ một event. Rỗng nếu không hiểu được event."""
    if event.kind not in SUPPORTED_KINDS:
        return [], []

    ts = event.ts
    trust = _trust_of(event)
    ref = event.evidence_ref()
    host_key = host_key_for(event)
    data = event.data

    entities: list[Entity] = []
    edges: list[Edge] = []

    def entity(entity_type: str, key: str, **attributes) -> str:
        entities.append(Entity(
            entity_type=entity_type, canonical_key=key, attributes=attributes,
            first_seen=ts, last_seen=ts, trust=trust, provenance=ref,
        ))
        return entity_id_for(entity_type, key)

    def edge(src: str, relation: str, dst: str, *,
             kind: str = EvidenceKind.OBSERVED, confidence: float = 1.0) -> None:
        edges.append(Edge(
            src_id=src, relation=relation, dst_id=dst, evidence_refs=(ref,),
            trust=trust, derived_by=RESOLVER, evidence_kind=kind,
            first_seen=ts, last_seen=ts, confidence=confidence,
        ))

    host = entity("host", host_key, origin=str(event.origin or "local"))

    if event.kind in {"process_exec", "process_started"}:
        key = _process_key(host_key, data)
        if key is None:
            return entities, edges
        process = entity(
            "process", key,
            pid=data.get("pid"), uid=data.get("uid"),
            comm=str(data.get("comm") or data.get("name") or "")[:256],
            exe=_clean_path(data.get("exe") or data.get("path")),
        )
        edge(process, "ran_on", host)
        parent_key = _process_key(host_key, {"pid": data.get("ppid"),
                                             "start_ticks": data.get("parent_start_ticks")})
        if parent_key and parent_key != key:
            parent = entity("process", parent_key, pid=data.get("ppid"))
            edge(parent, "spawned", process)
        # UID được giữ trong thuộc tính của tiến trình, KHÔNG thành một thực
        # thể user riêng. Tập quan hệ của mục 1.3 không có "chạy dưới quyền",
        # và mượn tạm `logged_into` sẽ khiến mọi tiến trình hệ thống trông như
        # một lần đăng nhập — biến câu hỏi "ai đã vào máy" thành vô nghĩa. Thêm
        # quan hệ mới là việc của một batch có chủ đích, không phải việc lén.
        return entities, edges

    if event.kind in {"file_write", "file_modified", "security_file_changed"}:
        path = _clean_path(data.get("path") or data.get("file"))
        if not path:
            return entities, edges
        file_entity = entity("file", f"{host_key}:{path}", path=path)
        digest = str(data.get("sha256") or data.get("hash") or "")
        if digest:
            indicator = entity("credential_indicator", f"sha256:{digest}", sha256=digest)
            edge(file_entity, "has_hash", indicator)
        key = _process_key(host_key, data)
        if key:
            process = entity("process", key, pid=data.get("pid"),
                             comm=str(data.get("comm") or "")[:256])
            edge(process, "wrote", file_entity)
            # Quan sát một tiến trình ghi file TRÊN máy này CŨNG là bằng chứng
            # rằng nó chạy trên máy này. Thiếu cạnh đó thì thực thể host không
            # có đường nào tới tiến trình, và mọi cuộc điều tra bắt đầu từ máy
            # đều thấy rỗng — kể cả khi graph đầy dữ liệu.
            edge(process, "ran_on", host)
        return entities, edges

    if event.kind == "socket_connect":
        key = _process_key(host_key, data)
        remote = str(data.get("remote_ip") or "")
        if not remote or key is None:
            return entities, edges
        try:
            remote = str(ipaddress.ip_address(remote))
        except ValueError:
            return entities, edges
        process = entity("process", key, pid=data.get("pid"),
                         comm=str(data.get("comm") or "")[:256])
        edge(process, "ran_on", host)
        # IP là thực thể TOÀN CỤC, không gắn với máy nào: 1.1.1.1 nhìn từ hai
        # máy vẫn là cùng một địa chỉ, và đó chính là điều làm graph có giá trị
        # — nó nối được hai máy cùng nói chuyện với một nơi.
        peer = entity("ip", remote, port=data.get("remote_port"))
        edge(process, "connected_to", peer)
        return entities, edges

    if event.kind in {"listener_opened", "listener_observed"}:
        port = data.get("port")
        if port in (None, ""):
            return entities, edges
        # `protocol` trước `proto`: collector phát "tcp4"/"tcp6". Trước đây chỗ
        # này chỉ đọc `proto` — khoá luôn thành "tcp", nên một cổng nghe trên
        # IPv4 và cùng cổng đó trên IPv6 gộp thành MỘT thực thể. Hai socket
        # khác nhau, một node: đúng kiểu graph nói dối một cách thuyết phục.
        proto = str(data.get("protocol") or data.get("proto") or "tcp")
        # ĐỊA CHỈ BIND THUỘC DANH TÍNH.
        #
        # Khoá cũ `host:proto:port` mô hình hoá "một dịch vụ trên một cổng",
        # nhưng thứ Shield quan sát được là "một socket đã bind". Đo trên máy
        # thật: 40 socket gộp thành 33 node, và ca tệ nhất là
        #
        #     udp4:5353   0.0.0.0 (pid 1573)  +  224.0.0.251 (pid 15398)
        #
        # Hai tiến trình KHÔNG liên quan cùng trỏ vào một node như thể chúng
        # phục vụ một thứ. Đó không phải mất dữ liệu, đó là một khẳng định sai.
        #
        # `inode` KHÔNG vào khoá: nó đổi mỗi lần socket được tạo lại, nên đưa
        # vào sẽ xoá sạch lịch sử quan sát mỗi lần dịch vụ khởi động lại. Hệ
        # quả có chủ ý: cùng tiến trình tham gia một nhóm multicast hai lần
        # (hai inode, cùng địa chỉ) vẫn là MỘT node — đúng về ngữ nghĩa.
        #
        # Ngoặc vuông quanh địa chỉ để `local:tcp6:[::]:3306` đọc được bằng
        # mắt; băm thì không mơ hồ, nhưng con người sẽ đọc nhầm.
        #
        # Địa chỉ rỗng cho ra `[]` — "không biết bind ở đâu", KHÁC hẳn
        # `[0.0.0.0]` là "bind mọi địa chỉ IPv4".
        bind = str(data.get("ip") or "")
        service = entity(
            "service", f"{host_key}:{proto}:[{bind}]:{port}",
            port=port, proto=proto, ip=str(data.get("ip") or ""),
            # Trạng thái phân giải chủ sở hữu, giữ NGUYÊN VĂN. "không tìm ra"
            # khác "không được phép nhìn", và người điều tra phải phân biệt
            # được hai điều đó.
            owner_resolution=str(data.get("resolution") or ""),
            observed_pids=list(data.get("observed_pids") or ()),
            # CỐ Ý KHÔNG có trường `discovery` ở đây.
            #
            # `upsert_entity` ghi đè toàn bộ thuộc tính, nên một node được phát
            # hiện live rồi quan sát lại lúc khởi động sẽ ghi "bootstrap" — tên
            # trường hứa "phát hiện lần đầu bằng cách nào", giá trị lại là
            # "lần quan sát gần nhất thuộc loại nào".
            #
            # Thông tin đó đã có sẵn, chính xác và không bị ghi đè, trong chuỗi
            # bằng chứng: cạnh mang `evidence_refs` -> event -> `kind` là
            # `listener_observed` hay `listener_opened`. Bảng `events` là
            # append-only nên nó trả lời được cả "lần đầu", "gần nhất" và "bao
            # nhiêu lần mỗi loại". Thêm máy móc merge để cứu một trường dẫn
            # xuất là đi sai hướng.
        )
        edge(service, "ran_on", host)
        # Chủ sở hữu: chỉ những cái có DANH TÍNH ĐẦY ĐỦ. `_process_key` từ chối
        # khi thiếu `start_ticks`, nên một pid quan sát được mà không xác nhận
        # được danh tính sẽ KHÔNG sinh cạnh — nó nằm lại trong `observed_pids`
        # như một quan sát, không phải một kết luận.
        #
        # Mơ hồ thì dựng cạnh cho TẤT CẢ, không bốc một cái: một socket do hai
        # tiến trình cùng giữ là sự thật, còn chọn một trong hai là bịa.
        for owner in data.get("owners") or ():
            key = _process_key(host_key, owner)
            if not key:
                continue
            process = entity("process", key, pid=owner.get("pid"))
            edge(process, "listens_on", service)
            # Giữ tiến trình nối được với máy, cùng lý do đã ghi ở nhánh
            # file_write: thiếu cạnh này thì host không có đường nào tới nó.
            edge(process, "ran_on", host)
        return entities, edges

    if event.kind in {"ssh_login", "ssh_auth_success"}:
        username = str(data.get("user") or data.get("username") or "").strip()
        if not username:
            return entities, edges
        user = entity("user", f"{host_key}:{username}", username=username)
        edge(user, "logged_into", host)
        src_ip = str(data.get("src_ip") or data.get("source_ip") or "")
        session_key = f"{host_key}:{username}:{src_ip}:{int(ts)}"
        session = entity("session", session_key, username=username, src_ip=src_ip,
                         method=str(data.get("method") or "")[:64])
        edge(session, "belongs_to", user)
        if src_ip:
            try:
                peer = entity("ip", str(ipaddress.ip_address(src_ip)))
            except ValueError:
                return entities, edges
            # Phiên bắt nguồn TỪ địa chỉ đó. Dùng `connected_to` theo chiều
            # session -> ip để một câu truy vấn "ai từng nối tới địa chỉ này"
            # tìm thấy cả tiến trình lẫn phiên đăng nhập.
            edge(session, "connected_to", peer)
        return entities, edges

    if event.kind == "host_seen":
        mac = str(data.get("mac") or "").lower()
        ip_text = str(data.get("ip") or "")
        if not mac:
            return entities, edges
        device = entity("device", mac, mac=mac,
                        vendor=str(data.get("vendor") or "")[:128],
                        hostname=str(data.get("hostname") or "")[:255])
        if ip_text:
            try:
                peer = entity("ip", str(ipaddress.ip_address(ip_text)))
            except ValueError:
                return entities, edges
            edge(device, "connected_to", peer, kind=EvidenceKind.DERIVED, confidence=0.9)
        return entities, edges

    return entities, edges
