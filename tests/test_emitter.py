"""Тесты эмиттера full Xray JSON."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.emitter.xray import build_full_xray_config
from src.models.config import VpnConfig


def _make_vless_cfg(host="node1.example.com", port=443, sni="cf.com", pbk="A" * 44, sid="abcd", fp="chrome"):
    return VpnConfig(
        scheme="vless",
        raw="",
        host=host,
        port=port,
        params={"security": "reality", "type": "tcp", "sni": sni, "pbk": pbk, "sid": sid, "fp": fp},
        fragment="Test",
        name="Test",
        protocol_data={"uuid": "11111111-1111-1111-1111-111111111111"},
    )


def _make_trojan_cfg(host="node2.example.com", port=443, sni="cf.com"):
    return VpnConfig(
        scheme="trojan",
        raw="",
        host=host,
        port=port,
        params={"security": "tls", "type": "tcp", "sni": sni, "fp": "chrome"},
        fragment="T2",
        name="T2",
        protocol_data={"password": "pass123"},
    )


def test_emit_minimal():
    cfg = build_full_xray_config(
        [_make_vless_cfg(), _make_trojan_cfg(host="node3.example.com")],
        profile_name="VPN whitelist meeyota",
    )
    assert "inbounds" in cfg and "outbounds" in cfg
    assert cfg["outbounds"][0]["tag"] == "VPN whitelist meeyota"
    assert cfg["outbounds"][1]["tag"] == "proxy-1"
    # 2 proxy outbounds, потом direct, потом block
    assert any(o["tag"] == "direct" for o in cfg["outbounds"])
    assert any(o["tag"] == "block" for o in cfg["outbounds"])
    assert cfg["outbounds"][-2]["tag"] == "direct"
    assert cfg["outbounds"][-1]["tag"] == "block"

    balancers = cfg["routing"]["balancers"]
    assert len(balancers) == 1
    assert "VPN whitelist meeyota" in balancers[0]["selector"]
    assert "proxy-" in balancers[0]["selector"]

    rules = cfg["routing"]["rules"]
    assert any(r.get("balancerTag") == "meeyota-auto" for r in rules)

    obs = cfg["burstObservatory"]
    assert "VPN whitelist meeyota" in obs["subjectSelector"]
    assert "proxy-" in obs["subjectSelector"]

    print("✓ test_emit_minimal")


def test_emit_scalable():
    cfgs = [_make_vless_cfg(host=f"node{i}.example.com", port=443) for i in range(1000)]
    cfg = build_full_xray_config(cfgs, "VPN whitelist meeyota")
    proxy_outbounds = [o for o in cfg["outbounds"] if o["tag"].startswith("proxy-") or o["tag"] == "VPN whitelist meeyota"]
    assert len(proxy_outbounds) == 1000
    # первый тег = profile_name
    assert cfg["outbounds"][0]["tag"] == "VPN whitelist meeyota"
    # последний proxy — proxy-999
    assert cfg["outbounds"][999]["tag"] == "proxy-999"
    print("✓ test_emit_scalable")


def test_emit_first_outbound_matches_profile_name():
    """Критическое требование: Incy показывает тег первого outbound'а как имя сервера."""
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    first_proxy = next(o for o in cfg["outbounds"] if o["protocol"] != "freedom" and o["protocol"] != "blackhole")
    assert first_proxy["tag"] == "VPN whitelist meeyota"
    print("✓ test_emit_first_outbound_matches_profile_name")


def test_emit_balancer_selector_covers_all_proxies():
    """Все proxy-* outbounds должны попадать в selector."""
    cfgs = [_make_vless_cfg(host=f"n{i}.example.com") for i in range(50)]
    cfg = build_full_xray_config(cfgs, "VPN whitelist meeyota")
    selectors = cfg["routing"]["balancers"][0]["selector"]
    proxy_tags = [o["tag"] for o in cfg["outbounds"] if o["tag"].startswith("proxy-") or o["tag"] == "VPN whitelist meeyota"]
    for tag in proxy_tags:
        matched = any(tag.startswith(s) for s in selectors)
        assert matched, f"tag {tag} not matched by selectors {selectors}"
    print("✓ test_emit_balancer_selector_covers_all_proxies")


def test_emit_fallback_tag_set():
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    assert cfg["routing"]["balancers"][0]["fallbackTag"] == "direct"
    print("✓ test_emit_fallback_tag_set")


def test_emit_routing_rule_references_balancer():
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    balancer_tag = cfg["routing"]["balancers"][0]["tag"]
    has_rule = any(r.get("balancerTag") == balancer_tag for r in cfg["routing"]["rules"])
    assert has_rule, f"no rule references balancer {balancer_tag}"
    print("✓ test_emit_routing_rule_references_balancer")


def test_emit_json_serializable():
    cfg = build_full_xray_config([_make_vless_cfg(), _make_trojan_cfg()], "VPN whitelist meeyota")
    s = json.dumps(cfg, indent=2)
    assert "VPN whitelist meeyota" in s
    print("✓ test_emit_json_serializable")


def test_policy_levels_is_dict_not_list():
    """Regression: Xray-core требует policy.levels как dict {"0": {...}}, а не list.

    JSON-массив levels ломает unmarshal map<uint32, Policy> и Xray-core
    отказывается стартовать со всем конфигом целиком.
    """
    cfg = build_full_xray_config([_make_vless_cfg(), _make_trojan_cfg()], "VPN whitelist meeyota")
    assert "policy" in cfg, "emitter must include 'policy' section"
    levels = cfg["policy"]["levels"]
    assert isinstance(levels, dict), f"policy.levels must be dict, got {type(levels).__name__}"
    assert not isinstance(levels, list)
    assert "0" in levels, 'policy.levels must contain key "0"'
    assert levels["0"]["handshake"] == 2
    assert levels["0"]["connIdle"] == 300
    assert levels["0"]["uplinkOnly"] == 2
    assert levels["0"]["downlinkOnly"] == 5
    # Ключ обязан парситься как uint32
    assert 0 <= int("0") <= 4294967295
    print("✓ test_policy_levels_is_dict_not_list")


if __name__ == "__main__":
    test_emit_minimal()
    test_emit_scalable()
    test_emit_first_outbound_matches_profile_name()
    test_emit_balancer_selector_covers_all_proxies()
    test_emit_fallback_tag_set()
    test_emit_routing_rule_references_balancer()
    test_emit_json_serializable()
    test_policy_levels_is_dict_not_list()
    print("\nAll emitter tests passed.")
