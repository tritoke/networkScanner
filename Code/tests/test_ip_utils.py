from ip_utils import (
    dot_to_long,
    long_to_dot,
    ip_range,
    is_valid_ip,
    is_valid_port_number
)


def test_dot_to_long() -> None:
    assert(dot_to_long("127.0.0.1") == 0x7F000001)


def test_long_to_dot() -> None:
    assert(long_to_dot(0x7F000001) == "127.0.0.1")


def test_is_valid_ip() -> None:
    assert(
        is_valid_ip(0x7F000001)
        and is_valid_ip("127.0.0.1")
        and not is_valid_ip("0.0.0.0.0")
        and not is_valid_ip(0xFF_FF_FF_FF_FF)
    )


def test_is_valid_port_number() -> None:
    assert(
        is_valid_port_number(0)
        and is_valid_port_number(65535)
        and not is_valid_port_number(-1)
        and not is_valid_port_number(2**16)
    )


def test_ip_range() -> None:
    assert(
        ip_range("192.168.1.0", 28) == {
            "192.168.1.0",
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
            "192.168.1.15"
        }
    )
