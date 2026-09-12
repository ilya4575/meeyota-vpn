"""Тесты дедупликации и wifi-политики."""
import time

from src.deduplicator import dedupe
from src.models.config import VpnConfig
from src.checks.checker import CheckResult, wifi_eligible


def _vless(addr="1.2.3.4", port=443, uuid="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
           network="tcp", flow="", sni="a.example.com", raw=None):
    return VpnConfig(
        protocol="vless", address=addr, port=port,
        uuid=uuid, network=network, flow=flow, sni=sni,
        raw=raw or f"vless://{uuid}@{addr}:{port}")


def test_dedupe_same_server_different_fp_is_one():
    a = _vless()
    b = _vless(raw="vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?fp=edge#x")
    res = dedupe([a, b])
    assert len(res.unique) == 1 and res.duplicates == 1


def test_dedupe_different_port_kept():
    a = _vless(port=443)
    b = _vless(port=8443)
    res = dedupe([a, b])
    assert len(res.unique) == 2


def test_dedupe_different_flow_kept():
    a = _vless(flow="")
    b = _vless(flow="xtls-rprx-vision")
    res = dedupe([a, b])
    assert len(res.unique) == 2


def test_dedupe_first_wins_source_priority():
    a = _vless(raw="first")
    b = _vless(raw="second")
    res = dedupe([a, b])
    assert res.unique[0].raw == "first"


def _cr(**kw):
    base = dict(fingerprint="f", ok=True,
                checked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                ip4="1.1.1.1", cc4="US")
    base.update(kw)
    return CheckResult(**base)


def test_wifi_ok():
    ok, reason = wifi_eligible(_cr(), ttl_hours=24)
    assert ok, reason


def test_wifi_no_ipv6_ok():
    ok, reason = wifi_eligible(_cr(ip6=None, cc6=None), ttl_hours=24)
    assert ok, reason


def test_wifi_ipv6_same_country_ok():
    ok, reason = wifi_eligible(_cr(ip6="2001:db8::1", cc6="US"), ttl_hours=24)
    assert ok, reason


def test_wifi_ru_rejected():
    ok, reason = wifi_eligible(_cr(cc4="RU"), ttl_hours=24)
    assert not ok and "RU" in reason


def test_wifi_ipv6_ru_rejected():
    ok, reason = wifi_eligible(_cr(ip6="2001:db8::1", cc6="RU"), ttl_hours=24)
    assert not ok and "RU" in reason


def test_wifi_conflict_rejected():
    ok, reason = wifi_eligible(_cr(ip6="2001:db8::1", cc6="NL"), ttl_hours=24)
    assert not ok and "противоречие" in reason


def test_wifi_unknown_country_rejected():
    ok, reason = wifi_eligible(_cr(cc4=None), ttl_hours=24)
    assert not ok


def test_wifi_stale_rejected():
    old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 48 * 3600))
    ok, reason = wifi_eligible(_cr(checked_at=old), ttl_hours=24)
    assert not ok and "устарела" in reason


def test_wifi_not_checked_rejected():
    ok, reason = wifi_eligible(None, ttl_hours=24)
    assert not ok


def test_wifi_failed_check_rejected():
    ok, reason = wifi_eligible(_cr(ok=False, error="нет IPv4-выхода"), ttl_hours=24)
    assert not ok
