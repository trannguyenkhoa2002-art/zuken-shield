"""Shield Packet Collector — bắt gói tin, TÁCH KHỎI lõi Shield.

Cố ý KHÔNG nằm trong package `shield`, đúng như `probe/`: thành phần này import
`scapy` (GPL-2.0), còn lõi Shield nhắm tới Apache-2.0. Tách thành hai chương
trình chạy hai tiến trình khác nhau làm ranh giới đó thành thứ KIỂM ĐƯỢC BẰNG
TEST, chứ không phải một lời hứa trong tài liệu.

Việc tách này là kiến trúc, không phải một kết luận pháp lý. Nó làm ranh giới
giấy phép trở nên rõ ràng và kiểm được; nó không tự nó khẳng định điều gì về
luật. Xem NOTICE.

Helper CHỈ ĐỌC gói tin và CHỈ PHÁT quan sát có cấu trúc. Nó không có kho dữ
liệu, không có capability token, không gọi được hành động phản ứng, và không
nhận lệnh nào từ lõi ngoài việc bị dừng.
"""

__version__ = "1.0.0"
