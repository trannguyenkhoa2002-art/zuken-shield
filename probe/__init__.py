"""Shield Probe — agent nhỏ đọc log trên máy khác rồi gửi về Shield chính.

Cố ý KHÔNG nằm trong package `shield`: probe cài lên máy không có PySide6,
không có scapy, và chỉ được phép dùng thư viện chuẩn của Python. Tách package
làm ranh giới đó thành thứ kiểm được bằng test, chứ không phải một lời hứa
trong tài liệu.

Probe CHỈ ĐỌC. Không nftables, không kill process, không quarantine. Một probe
bị chiếm quyền cũng không trở thành vũ khí tấn công ngược vào LAN — xem
KE-HOACH-SHIELD-1.1.md mục A1.
"""

__version__ = "1.1.0a1"
