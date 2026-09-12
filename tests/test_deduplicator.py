"""Тесты дедупликации."""

from src.deduplicator import dedup, sort_for_export
from src.parsers import parse_uri

from .conftest import SS_NEW, TROJAN_WS, VLESS_REALITY_TCP, VMESS_TCP


def _cfg(line, src):
    return parse_uri(line, src)


def test_dedup_identical_from_two_sources():
    configs = [_cfg(VLESS_REALITY_TCP, "s1"), _cfg(VLESS_REALITY_TCP, "s2")]
    unique, dups = dedup(configs)
    assert len(unique) == 1
    assert dups == 1
    assert sorted(unique[0].source) == ["s1", "s2"]


def test_dedup_same_server_different_credentials():
    a = _cfg(VLESS_REALITY_TCP, "s1")
    b = _cfg(VLESS_REALITY_TCP.replace("17c1b548-97db-4b58-a410-cab03d1f09c4", "2c9a1111-2222-3333-4444-555566667777"), "s2")
    unique, dups = dedup([a, b])
    assert len(unique) == 2
    assert dups == 0


def test_dedup_mixed_protocols_kept():
    configs = [_cfg(VLESS_REALITY_TCP, "s"), _cfg(SS_NEW, "s"), _cfg(TROJAN_WS, "s"), _cfg(VMESS_TCP, "s")]
    unique, dups = dedup(configs)
    assert len(unique) == 4
    assert dups == 0


def test_sort_for_export_protocol_order():
    configs = [
        _cfg(TROJAN_WS, "s"),
        _cfg(VLESS_REALITY_TCP, "s"),
        _cfg(SS_NEW, "s"),
        _cfg(VMESS_TCP, "s"),
    ]
    ordered = sort_for_export(configs)
    assert [c.protocol for c in ordered] == ["vless", "trojan", "ss", "vmess"]
