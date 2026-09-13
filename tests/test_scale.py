"""Тест масштабирования: проверка, что JSON с любым количеством outbounds
всё равно отображается в Incy как ОДИН сервер."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.emitter.xray import build_full_xray_config, render_json
from src.models.config import VpnConfig
from simulate_incy_import import simulate_incy_import


def _make_outbounds(n: int) -> list:
    out = []
    for i in range(n):
        out.append(
            VpnConfig(
                scheme="vless",
                raw="",
                host=f"node{i}.example.com",
                port=443,
                params={
                    "security": "reality",
                    "type": "tcp",
                    "sni": "cf.com",
                    "pbk": "A" * 44,
                    "sid": "ab" * 4,
                    "fp": "chrome",
                },
                fragment=f"N{i}",
                name=f"N{i}",
                protocol_data={"uuid": f"{i:08x}-1111-2222-3333-444444444444"},
            )
        )
    return out


def test_scale(name: str, profile_name: str, n: int) -> None:
    cfgs = _make_outbounds(n)
    cfg = build_full_xray_config(cfgs, profile_name)
    body = render_json(cfg)
    servers = simulate_incy_import(body)

    if len(servers) != 1:
        print(f"❌ FAIL: {name}: expected 1 server, got {len(servers)}")
        sys.exit(1)

    if servers[0]["name"] != profile_name:
        print(f"❌ FAIL: {name}: expected name {profile_name!r}, got {servers[0]['name']!r}")
        sys.exit(1)

    proxy_count = sum(1 for o in cfg["outbounds"] if o["tag"].startswith("proxy-") or o["tag"] == profile_name)
    print(f"  ✓ {name}: {proxy_count} proxy outbounds → 1 server ({profile_name})")


if __name__ == "__main__":
    print("=== Scaling tests: outbounds → exactly 1 server in Incy ===\n")
    test_scale("Small whitelist", "VPN whitelist meeyota", 10)
    test_scale("Medium whitelist", "VPN whitelist meeyota", 100)
    test_scale("Large whitelist", "VPN whitelist meeyota", 1000)
    test_scale("Very large whitelist", "VPN whitelist meeyota", 2500)
    test_scale("Small wifi", "VPN Wi-fi meeyota", 10)
    test_scale("Large wifi", "VPN Wi-fi meeyota", 500)

    print("\n" + "=" * 60)
    print("All scaling tests PASSED.")
    print("Result: regardless of outbounds count, Incy shows ONE server.")
    print("=" * 60)
