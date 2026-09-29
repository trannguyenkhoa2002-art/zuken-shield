"""Helper bắt gói phải biết MỌI địa chỉ cục bộ, và cập nhật khi chúng đổi.

Tìm ra khi chạy test netns (bị skip từ trước vì cần root) trong container:
helper chỉ lấy IP qua /etc/hosts và default route, MỘT lần lúc khởi động.
Laptop đổi mạng -> IP mới -> mọi SYN bị bỏ qua -> port scan không bao giờ
được phát hiện, không có lỗi nào được ghi.
"""

from __future__ import annotations

from packet_helper import __main__ as helper

FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 192.0.2.0/24 2 0 2
        |-- 192.0.2.17
           /32 host LOCAL
        |-- 192.0.2.255
           /32 link BROADCAST
     |-- 172.17.0.1
        /32 host LOCAL
Local:
  |-- 10.8.0.5
     /32 host LOCAL
  |-- 127.0.0.1
     /32 host LOCAL
"""


def test_every_local_interface_address_is_read_from_the_kernel_table():
    assert helper.addresses_from_fib_trie(FIB_TRIE) == {
        "192.0.2.17", "172.17.0.1", "10.8.0.5", "127.0.0.1"}


def test_broadcast_and_network_addresses_are_not_local():
    found = helper.addresses_from_fib_trie(FIB_TRIE)
    assert "192.0.2.255" not in found and "0.0.0.0" not in found


def test_the_address_book_follows_an_ip_change():
    states = [{"127.0.0.1", "192.0.2.17"}, {"127.0.0.1", "10.20.30.40"}]
    book = helper.AddressBook(reader=lambda: states[0])
    assert "192.0.2.17" in book.current
    states.pop(0)
    assert book.refresh() is True
    assert "10.20.30.40" in book.current and "192.0.2.17" not in book.current
    assert book.refresh() is False


def test_the_sniffer_reads_the_live_address_book():
    source = (helper.__file__)
    text = open(source, encoding="utf-8").read()
    assert "from_tcp_packet(pkt, book.current)" in text
    assert "refresh_addresses(book)" in text
