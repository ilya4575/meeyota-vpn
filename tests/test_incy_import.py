"""Тесты симуляции Incy-импорта и валидации структуры full Xray JSON.

Симулирует поведение парсера Incy при импорте подписки.
Проверяет, что каждый итоговый JSON отображается как ОДИН сервер.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from simulate_incy_import import simulate_incy_import
from validate_incy_profile import validate_profile


def _generate_full_xray(n_outbounds: int, profile_name: str) -> dict:
    """Генерирует full Xray JSON через production emitter."""
    from src.emitter.xray import build_full_xray_config
    from src.models.config import VpnConfig

    configs = []
    for i in range(n_outbounds):
        configs.append(
            VpnConfig(
                scheme="vless",
                raw="",
                host=f"node{i}.example.com",
                port=443,
                params={
                    "security": "reality",
                    "type": "tcp",
                    "sni": "www.cloudflare.com",
                    "pbk": "A" * 44,
                    "sid": "ab" * 4,
                    "fp": "chrome",
                },
                fragment=f"Node{i}",
                name=f"Node{i}",
                protocol_data={"uuid": f"{i:08x}-1111-2222-3333-444444444444"},
            )
        )
    return build_full_xray_config(configs, profile_name)


def test_emitted_whitelist_is_single_server():
    cfg = _generate_full_xray(100, "VPN whitelist meeyota")
    body = json.dumps(cfg, indent=2).encode()
    servers = simulate_incy_import(body)
    assert len(servers) == 1, f"expected 1 server, got {len(servers)}"
    assert servers[0]["name"] == "VPN whitelist meeyota"
    assert servers[0]["type"] == "full_xray_config"
    print("✓ test_emitted_whitelist_is_single_server")


def test_emitted_wifi_is_single_server():
    cfg = _generate_full_xray(50, "VPN Wi-fi meeyota")
    body = json.dumps(cfg, indent=2).encode()
    servers = simulate_incy_import(body)
    assert len(servers) == 1
    assert servers[0]["name"] == "VPN Wi-fi meeyota"
    print("✓ test_emitted_wifi_is_single_server")


def test_emitted_large_scale_is_single_server():
    cfg = _generate_full_xray(2000, "VPN whitelist meeyota")
    body = json.dumps(cfg, indent=2).encode()
    servers = simulate_incy_import(body)
    assert len(servers) == 1
    assert servers[0]["name"] == "VPN whitelist meeyota"
    print("✓ test_emitted_large_scale_is_single_server")


def test_validate_smoke_whitelist():
    """Валидация smoke-test файла whitelist."""
    smoke = Path(__file__).parent.parent / "docs" / "SMOKE-TEST-whitelist.json"
    validate_profile(smoke, "VPN whitelist meeyota")
    print("✓ test_validate_smoke_whitelist")


def test_validate_smoke_wifi():
    smoke = Path(__file__).parent.parent / "docs" / "SMOKE-TEST-wifi.json"
    validate_profile(smoke, "VPN Wi-fi meeyota")
    print("✓ test_validate_smoke_wifi")


def test_no_proxy_leaked_as_server_name():
    cfg = _generate_full_xray(500, "VPN whitelist meeyota")
    body = json.dumps(cfg, indent=2).encode()
    servers = simulate_incy_import(body)
    assert len(servers) == 1
    # ни одного proxy-* среди server names
    leaked = [n for n in [s["name"] for s in servers] if n.startswith("proxy-")]
    assert not leaked, f"proxy-* names leaked: {leaked}"
    print("✓ test_no_proxy_leaked_as_server_name")


if __name__ == "__main__":
    test_emitted_whitelist_is_single_server()
    test_emitted_wifi_is_single_server()
    test_emitted_large_scale_is_single_server()
    test_validate_smoke_whitelist()
    test_validate_smoke_wifi()
    test_no_proxy_leaked_as_server_name()
    print("\nAll Incy-import simulation tests passed.")
