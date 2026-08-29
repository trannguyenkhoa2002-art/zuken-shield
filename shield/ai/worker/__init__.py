"""Ranh giới TIẾN TRÌNH giữa agent và mã chạy model (Phase 3C-0).

Mọi lớp phòng thủ của Phase 2–3B đều nằm TRONG một tiến trình: contracts,
validator, coordinator, capability token, fallback. Chúng chặn được một model
nói sai. Chúng không chặn được một model **ăn hết RAM**, **quay CPU vô hạn**,
**segfault**, hay **treo** — vì tất cả những thứ đó giết chính tiến trình đang
chạy các lớp phòng thủ ấy.

Một endpoint mất detection vì lớp AI đói bộ nhớ thì lớp AI đã trở thành lỗ
hổng nó sinh ra để vá. Nên trước khi có bất kỳ model thật nào, phải có ranh
giới tiến trình — và ranh giới đó phải chứng minh được bằng test, không phải
bằng một dòng trong tài liệu.

Mô hình đe doạ: **mã model là compute KHÔNG ĐÁNG TIN.** Không phải "có thể sai"
mà là "có thể thù địch". Nó không có DB handle, không có capability token,
không có tool registry, không biết đường dẫn nào ngoài file model của nó, và
không tự gọi được `READ_ONLY_TOOLS`. Vòng lặp tool ở lại phía agent, trong
Coordinator, y như 3B.
"""
