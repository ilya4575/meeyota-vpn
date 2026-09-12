"""Тесты модуля проверок: sing-box-конфиги, вердикты, оркестрация (mock'и)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.checks.connectivity import (
    UnsupportedProtocol,
    build_singbox_config,
    build_singbox_outbound,
)
from src.checks.verifier import (
    VERDICT_CONFLICT,
    VERDICT_ERROR,
    VERDICT_OK,
    VERDICT_RU,
    CheckResults,
    _judge,
    group_configs,
    verify,
)
from src.models.config import VpnConfig
from src.parsers import parse_uri

from .conftest import (
    HY2_SNI,
    SOCKS5_AUTH,
    SS_NEW,
    TROJAN_WS,
    VLESS_REALITY_TCP,
    VMESS_TCP,
)


def make_cfg(line: str) -> VpnConfig:
    return parse_uri(line, "test")


# ---------------------------------------------------------------------------
# Сборка конфигурации sing-box
# ---------------------------------------------------------------------------

def test_singbox_vless_reality():
    out = build_singbox_outbound(make_cfg(VLESS_REALITY_TCP))
    assert out["type"] == "vless"
    assert out["server"] == "47.88.107.209"
    assert out["server_port"] == 443
    assert out["flow"] == "xtls-rprx-vision"
    assert out["tls"]["enabled"] is True
    assert out["tls"]["server_name"] == "www.cloudflare.com"
    assert out["tls"]["fingerprint"] == "chrome"
    assert out["tls"]["reality"]["public_key"].startswith("uxMpQ2V3")
    assert out["tls"]["reality"]["short_id"] == "1b2c3d4e5f607182"


def test_singbox_vless_ws():
    from .conftest import VLESS_WS_NONE

    out = build_singbox_outbound(make_cfg(VLESS_WS_NONE))
    assert "tls" not in out  # security=none → без TLS
    assert out["transport"]["type"] == "websocket"
    assert out["transport"]["headers"]["Host"] == "long-smoke-b6cb.290-cd1.workers.dev"


def test_singbox_vmess():
    out = build_singbox_outbound(make_cfg(VMESS_TCP))
    assert out["type"] == "vmess"
    assert out["uuid"] == "d4603cc2-e0ee-4651-83f5-1db5b7168177"
    assert out["security"] == "auto"
    assert out["server_port"] == 48111


def test_singbox_ss():
    out = build_singbox_outbound(make_cfg(SS_NEW))
    assert out["type"] == "shadowsocks"
    assert out["method"] == "chacha20-ietf-poly1305"
    assert out["password"] == "k1dBOmOB4oqi7Ump37a1bQ"


def test_singbox_trojan():
    out = build_singbox_outbound(make_cfg(TROJAN_WS))
    assert out["type"] == "trojan"
    assert out["password"] == "humanity"
    assert out["tls"]["server_name"] == "www.ignitelimit.com"
    assert out["transport"]["type"] == "websocket"


def test_singbox_hysteria2():
    out = build_singbox_outbound(make_cfg(HY2_SNI))
    assert out["type"] == "hysteria2"
    assert out["tls"]["server_name"] == "uk.shamanapp.online"


def test_singbox_socks5():
    out = build_singbox_outbound(make_cfg(SOCKS5_AUTH))
    assert out["type"] == "socks"
    assert out["username"] == "user"


def test_singbox_config_full():
    cfg = make_cfg(SS_NEW)
    full = build_singbox_config(cfg, 18110)
    assert full["inbounds"][0]["type"] == "mixed"
    assert full["inbounds"][0]["listen_port"] == 18110
    assert full["outbounds"][0]["tag"] == "proxy"
    assert full["outbounds"][1]["type"] == "direct"


# ---------------------------------------------------------------------------
# Вердикты (строгие правила подписки Wi-fi)
# ---------------------------------------------------------------------------

def test_judge_ok():
    assert _judge("1.2.3.4", None, "NL", None)[0] == VERDICT_OK
    assert _judge(None, "2001:db8::1", None, "DE")[0] == VERDICT_OK


def test_judge_ru_ipv4():
    assert _judge("1.2.3.4", None, "RU", None)[0] == VERDICT_RU


def test_judge_ru_ipv6():
    assert _judge("1.2.3.4", "2001:db8::1", "NL", "RU")[0] == VERDICT_RU


def test_judge_conflict():
    verdict, country, ip, _ = _judge("1.2.3.4", "2001:db8::1", "NL", "DE")
    assert verdict == VERDICT_CONFLICT
    assert country is None


def test_judge_unknown_country():
    # соединение есть, но страна не определена — строго: не включаем
    assert _judge("1.2.3.4", None, None, None)[0] == VERDICT_ERROR


def test_judge_no_connection():
    assert _judge(None, None, None, None)[0] == VERDICT_ERROR


# ---------------------------------------------------------------------------
# Группировка и оркестрация (mock'и)
# ---------------------------------------------------------------------------

def test_group_configs():
    a = make_cfg(VLESS_REALITY_TCP)
    b = parse_uri(VLESS_REALITY_TCP.replace("47.88.107.209", "1.1.1.1"), "t")
    c = parse_uri(SS_NEW, "t")
    groups = group_configs([a, b, c])
    assert len(groups) == 3
    assert a.server_key in groups


def _settings(tmp_path: Path, **kw) -> SimpleNamespace:
    base = dict(
        data_dir=str(tmp_path),
        check_ttl_days=3,
        geo_ttl_days=7,
        geo_cache_max=100,
        results_max_groups=1000,
        results_max_configs=10000,
        check_workers=2,
        check_minutes=5,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_verify_no_singbox_uses_cache_only(tmp_path, monkeypatch):
    configs = [make_cfg(VLESS_REALITY_TCP), make_cfg(SS_NEW)]
    results = CheckResults()
    stats = verify(configs, _settings(tmp_path), results, singbox_bin=None)
    assert stats["no_singbox"] is True
    assert stats["checked"] == 0


def test_verify_with_mock_probe(tmp_path, monkeypatch):
    """Сервер 47.88.107.209 → NL (ok); 82.38.31.200 → RU (ru)."""
    import src.checks.verifier as verifier

    fakes = {
        ("47.88.107.209:443"): ("94.102.1.1", None, ""),
        ("82.38.31.200:8080"): ("77.88.1.1", None, ""),
    }
    geo = {
        "94.102.1.1": "NL",
        "77.88.1.1": "RU",
    }

    def fake_probe(cfg, singbox_bin, port, timeout=25):
        return fakes[f"{cfg.address}:{cfg.port}"]

    monkeypatch.setattr(verifier, "probe_config", fake_probe)

    class FakeGeo:
        def country(self, ip):
            return geo.get(ip)

        def save(self):
            pass

    monkeypatch.setattr(verifier, "GeoLookup", lambda *a, **k: FakeGeo())

    a = make_cfg(VLESS_REALITY_TCP)
    b = make_cfg(SS_NEW)
    results = CheckResults()
    stats = verify(configs=[a, b], settings=_settings(tmp_path), results=results,
                   singbox_bin="fake-sb")
    assert stats["checked"] == 2
    assert stats["verdicts"][VERDICT_OK] == 1
    assert stats["verdicts"][VERDICT_RU] == 1
    assert results.configs[a.hash]["verdict"] == VERDICT_OK
    assert results.configs[a.hash]["country"] == "NL"
    assert results.configs[b.hash]["verdict"] == VERDICT_RU


def test_verify_cache_skips_fresh(tmp_path, monkeypatch):
    import src.checks.verifier as verifier
    from datetime import datetime, timezone

    a = make_cfg(VLESS_REALITY_TCP)
    results = CheckResults()
    results.groups[a.server_key] = {
        "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": VERDICT_OK,
        "country": "NL",
        "ip": "94.102.1.1",
    }
    results.configs[a.hash] = {
        "last_check": "2026-01-01T00:00:00Z",
        "country": "NL",
        "ip": "94.102.1.1",
        "verdict": VERDICT_OK,
    }

    called = []

    def fake_probe(cfg, singbox_bin, port, timeout=25):
        called.append(cfg)
        return ("94.102.1.1", None, "")

    monkeypatch.setattr(verifier, "probe_config", fake_probe)
    stats = verify(configs=[a], settings=_settings(tmp_path), results=results,
                   singbox_bin="fake-sb")
    assert stats["cached"] == 1
    assert stats["checked"] == 0
    assert called == []


def test_results_save_load_roundtrip(tmp_path):
    results = CheckResults()
    results.groups["1.2.3.4:443"] = {"checked_at": "2026-01-01T00:00:00Z", "verdict": "ok"}
    results.configs["abc"] = {"last_check": "2026-01-01T00:00:00Z", "verdict": "ok"}
    path = tmp_path / "check_results.json"
    results.save(path)
    loaded = CheckResults.load(path)
    assert loaded.groups["1.2.3.4:443"]["verdict"] == "ok"
    assert loaded.configs["abc"]["verdict"] == "ok"


def test_probe_without_singbox():
    from src.checks.connectivity import probe_config

    ip4, ip6, detail = probe_config(make_cfg(SS_NEW), None, 18100)
    assert ip4 is None and ip6 is None
    assert "sing-box" in detail
