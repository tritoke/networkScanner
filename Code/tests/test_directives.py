from modules.directives import (
    parse_ports
)
from collections import defaultdict
from typing import DefaultDict


def test_parse_probes_single() -> None:
    portstring = "12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["ANY"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_range() -> None:
    portstring = "10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["ANY"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_single_and_range() -> None:
    portstring = "1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["ANY"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_tcp_single() -> None:
    portstring = "T:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_tcp_range() -> None:
    portstring = "T:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_tcp_single_and_range() -> None:
    portstring = "T:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_single() -> None:
    portstring = "U:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_range() -> None:
    portstring = "U:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_single_and_range() -> None:
    portstring = "U:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_tcp_single() -> None:
    portstring = "12345 T:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([12345])
    expected["ANY"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_tcp_range() -> None:
    portstring = "10-20 T:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set(range(10, 21))
    expected["ANY"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_tcp_single_and_range() -> None:
    portstring = "1,2,3,10-20,6,7,8 T:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    expected["ANY"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_udp_single() -> None:
    portstring = "12345 U:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set([12345])
    expected["ANY"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_udp_range() -> None:
    portstring = "10-20 U:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set(range(10, 21))
    expected["ANY"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_any_and_udp_single_and_range() -> None:
    portstring = "1,2,3,10-20,6,7,8 U:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["UDP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    expected["ANY"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_and_tcp_single() -> None:
    portstring = "U:12345 T:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([12345])
    expected["UDP"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_and_tcp_range() -> None:
    portstring = "U:10-20 T:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set(range(10, 21))
    expected["UDP"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_udp_and_tcp_single_and_range() -> None:
    portstring = "U:1,2,3,10-20,6,7,8 T:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    expected["UDP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)


def test_parse_probes_all_single() -> None:
    portstring = "12345 U:12345 T:12345"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([12345])
    expected["UDP"] = set([12345])
    expected["ANY"] = set([12345])
    assert expected == parse_ports(portstring)


def test_parse_probes_all_range() -> None:
    portstring = "10-20 U:10-20 T:10-20"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set(range(10, 21))
    expected["UDP"] = set(range(10, 21))
    expected["ANY"] = set(range(10, 21))
    assert expected == parse_ports(portstring)


def test_parse_probes_all_single_and_range() -> None:
    portstring = "1,2,3,10-20,6,7,8 U:1,2,3,10-20,6,7,8 T:1,2,3,10-20,6,7,8"
    expected: DefaultDict[str, set] = defaultdict(set)
    expected["TCP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    expected["UDP"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    expected["ANY"] = set([1, 2, 3, *range(10, 21), 6, 7, 8])
    assert expected == parse_ports(portstring)
