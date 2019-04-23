from modules.ip_utils import (
    dot_to_long,
    long_to_dot,
    ip_range,
    is_valid_ip,
    is_valid_port_number,
    ip_checksum,
    make_tcp_packet,
    make_udp_packet,
    make_icmp_packet,
)
from binascii import unhexlify


def test_dot_to_long_private_ip() -> None:
    assert(dot_to_long("192.168.1.0") == 0xC0A80100)


def test_long_to_dot_private_ip() -> None:
    assert(long_to_dot(0xC0A80100) == "192.168.1.0")


def test_dot_to_long_localhost() -> None:
    assert(dot_to_long("127.0.0.1") == 0x7F000001)


def test_long_to_dot_localhost() -> None:
    assert(long_to_dot(0x7F000001) == "127.0.0.1")


def test_is_valid_ip_localhost_long() -> None:
    assert is_valid_ip(0x7F000001)


def test_is_valid_ip_localhost() -> None:
    assert is_valid_ip("127.0.0.1")


def test_is_not_valid_ip_5_zeros_dotted() -> None:
    assert not is_valid_ip("0.0.0.0.0")


def test_is_not_valid_ip_5_255s_long() -> None:
    assert not is_valid_ip(0xFF_FF_FF_FF_FF)


def test_is_valid_port_number_0() -> None:
    assert is_valid_port_number(0)


def test_is_valid_port_number_65535() -> None:
    assert is_valid_port_number(65535)


def test_is_not_valid_port_number_negative_one() -> None:
    assert not is_valid_port_number(-1)


def test_is_not_valid_port_number_65536() -> None:
    assert not is_valid_port_number(65536)


def test_ip_range() -> None:
    assert(
        ip_range("192.168.1.0", 28) == {
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5",
            "192.168.1.6",
            "192.168.1.7",
            "192.168.1.8",
            "192.168.1.9",
            "192.168.1.10",
            "192.168.1.11",
            "192.168.1.12",
            "192.168.1.13",
            "192.168.1.14",
        }
    )


def test_ip_checksum_verify() -> None:
    packet = unhexlify(
        "45000073000040004011b861c0a80001c0a800c7"
    )
    assert ip_checksum(packet) == 0


def test_ip_checksum_generate() -> None:
    packet = unhexlify(
        "450000730000400040110000c0a80001c0a800c7"
    )
    assert ip_checksum(packet) == 0xB861


def test_make_tcp_packet() -> None:
    correct = unhexlify(
        "e54700500000000000000000600204002af50000020405b4"
    )
    info = 58695, 80, "192.168.1.45", "192.168.1.28", 2
    assert correct == make_tcp_packet(*info)


def test_make_udp_packet() -> None:
    correct = unhexlify(
        "e5470050003a0000"
    )
    info = 58695, 80
    # clipping the packet at 8 simply removes the data section
    assert correct == make_udp_packet(*info)[:8]
