"""Regression tests: policy.levels MUST be a dict {"0": {...}}, never a list.

Xray-core unmarshals policy.levels into map<uint32, Policy>. A JSON array
breaks the whole config at startup, so every emitter output and every
checked-in example JSON must use the dict form.

8 cases:
  1. emitter (whitelist profile) returns dict with key "0"
  2. emitter (wifi profile) returns dict with key "0"
  3. serialized JSON (dumps + loads round-trip) keeps dict form
  4. docs/SMOKE-TEST-whitelist.json uses dict form
  5. docs/SMOKE-TEST-wifi.json uses dict form
  6. docs/TEST-JSON-EXAMPLE.json uses dict form
  7. output/vpn-whitelist-meeyota.json + output/vpn-wifi-meeyota.json use dict form
  8. every level key parses as valid uint32
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.emitter.xray import build_full_xray_config, render_json
from src.models.config import VpnConfig


REPO_ROOT = Path(__file__).parent.parent
EXPECTED_LEVEL_0 = {"handshake": 2, "connIdle": 300, "uplinkOnly": 2, "downlinkOnly": 5}


def _make_vless_cfg(host="node1.example.com"):
    return VpnConfig(
        scheme="vless",
        raw="",
        host=host,
        port=443,
        params={"security": "reality", "type": "tcp", "sni": "cf.com",
                "pbk": "A" * 44, "sid": "abcd", "fp": "chrome"},
        fragment="Test",
        name="Test",
        protocol_data={"uuid": "11111111-1111-1111-1111-111111111111"},
    )


def _assert_levels_shape(cfg: dict, where: str) -> dict:
    assert "policy" in cfg, f"{where}: missing 'policy' section"
    levels = cfg["policy"].get("levels")
    assert not isinstance(levels, list), (
        f"{where}: policy.levels is a LIST — Xray-core expects a dict "
        'like {"0": {...}} and will reject the whole config'
    )
    assert isinstance(levels, dict), f"{where}: policy.levels must be dict, got {type(levels).__name__}"
    assert "0" in levels, f'{where}: policy.levels must contain key "0"'
    assert levels["0"] == EXPECTED_LEVEL_0, f"{where}: policy.levels['0'] mismatch: {levels['0']!r}"
    return levels


def _assert_keys_uint32(levels: dict, where: str) -> None:
    for key in levels:
        assert isinstance(key, str), f"{where}: level key {key!r} must be a string"
        num = int(key)  # raises ValueError on non-numeric
        assert 0 <= num <= 4294967295, f"{where}: level key {key!r} out of uint32 range"


def test_emitter_whitelist_levels_dict():
    """Case 1: emitter (whitelist profile) returns dict with key "0"."""
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    _assert_levels_shape(cfg, "emitter/whitelist")
    print("✓ test_emitter_whitelist_levels_dict")


def test_emitter_wifi_levels_dict():
    """Case 2: emitter (wifi profile) returns dict with key "0"."""
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN Wi-fi meeyota", burst_interval="60s")
    _assert_levels_shape(cfg, "emitter/wifi")
    print("✓ test_emitter_wifi_levels_dict")


def test_serialized_json_keeps_dict():
    """Case 3: dumps + loads round-trip keeps the dict form."""
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    raw = render_json(cfg)
    assert b'"levels": {' in raw or b'"levels":{' in raw.replace(b" ", b""), "serialized JSON must contain dict-form levels"
    reloaded = json.loads(raw.decode("utf-8"))
    _assert_levels_shape(reloaded, "serialized-json")
    print("✓ test_serialized_json_keeps_dict")


def test_smoke_whitelist_json():
    """Case 4: docs/SMOKE-TEST-whitelist.json uses dict form."""
    p = REPO_ROOT / "docs" / "SMOKE-TEST-whitelist.json"
    _assert_levels_shape(json.loads(p.read_text(encoding="utf-8")), str(p))
    print("✓ test_smoke_whitelist_json")


def test_smoke_wifi_json():
    """Case 5: docs/SMOKE-TEST-wifi.json uses dict form."""
    p = REPO_ROOT / "docs" / "SMOKE-TEST-wifi.json"
    _assert_levels_shape(json.loads(p.read_text(encoding="utf-8")), str(p))
    print("✓ test_smoke_wifi_json")


def test_example_json():
    """Case 6: docs/TEST-JSON-EXAMPLE.json uses dict form."""
    p = REPO_ROOT / "docs" / "TEST-JSON-EXAMPLE.json"
    _assert_levels_shape(json.loads(p.read_text(encoding="utf-8")), str(p))
    print("✓ test_example_json")


def test_production_outputs():
    """Case 7: output/*.json production files use dict form."""
    for name in ("vpn-whitelist-meeyota.json", "vpn-wifi-meeyota.json"):
        p = REPO_ROOT / "output" / name
        assert p.is_file(), f"missing production output: {p}"
        _assert_levels_shape(json.loads(p.read_text(encoding="utf-8")), str(p))
    print("✓ test_production_outputs")


def test_level_keys_are_uint32():
    """Case 8: every level key parses as valid uint32."""
    cfg = build_full_xray_config([_make_vless_cfg()], "VPN whitelist meeyota")
    levels = _assert_levels_shape(cfg, "emitter/whitelist")
    _assert_keys_uint32(levels, "emitter/whitelist")
    for rel in ("docs/SMOKE-TEST-whitelist.json", "docs/SMOKE-TEST-wifi.json",
                "docs/TEST-JSON-EXAMPLE.json", "output/vpn-whitelist-meeyota.json",
                "output/vpn-wifi-meeyota.json"):
        p = REPO_ROOT / rel
        data = json.loads(p.read_text(encoding="utf-8"))
        _assert_keys_uint32(data["policy"]["levels"], str(p))
    print("✓ test_level_keys_are_uint32")


if __name__ == "__main__":
    test_emitter_whitelist_levels_dict()
    test_emitter_wifi_levels_dict()
    test_serialized_json_keeps_dict()
    test_smoke_whitelist_json()
    test_smoke_wifi_json()
    test_example_json()
    test_production_outputs()
    test_level_keys_are_uint32()
    print("\nAll policy.levels regression tests passed (8/8).")
