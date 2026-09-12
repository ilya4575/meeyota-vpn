"""Герметичные тесты пайплайна проверок: стаб-xray + monkeypatch геолокации.

Стаб-xray — исполняемый python-скрипт, который читает конфиг (как реальный xray:
`xray run -c <cfg>`), поднимает локальный порт и ждёт — достаточно, чтобы
протестировать процесс-менеджмент, ожидание порта, kill и всю логику выше.
"""
import json
from pathlib import Path

import pytest
import requests

from src.checks import geo as geo_mod
from src.checks import xray as xray_mod
from src.checks.checker import run_checks, wifi_eligible
from src.parsers.uri import parse_uri

STUB_XRAY = """#!/usr/bin/env python3
import json, socket, sys
args = sys.argv[1:]
assert args[0] == "run" and args[1] == "-c", args
cfg = json.load(open(args[2]))
port = cfg["inbounds"][0]["port"]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
s.settimeout(30)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except socket.timeout:
        break
"""

STUB_XRAY_NO_PORT = """#!/usr/bin/env python3
import time
time.sleep(30)
"""


@pytest.fixture()
def stub_xray(tmp_path: Path) -> Path:
    p = tmp_path / "xray-stub"
    p.write_text(STUB_XRAY)
    p.chmod(0o755)
    return p


@pytest.fixture()
def stub_xray_no_port(tmp_path: Path) -> Path:
    p = tmp_path / "xray-stub-noport"
    p.write_text(STUB_XRAY_NO_PORT)
    p.chmod(0o755)
    return p


def _cfg(addr="203.0.113.10", port=443):
    return parse_uri(
        f"vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@{addr}:{port}"
        "?security=none&type=tcp#test")


def test_probe_config_spawns_waits_and_kills(stub_xray, monkeypatch, tmp_path):
    def fake_get_ip(session, urls, port, timeout):
        if urls is xray_mod.IP_FALLBACKS_V4:
            return "203.0.113.10"
        return "2001:db8::99"
    monkeypatch.setattr(xray_mod, "_get_ip", fake_get_ip)
    ip4, ip6, err = xray_mod.probe_config(
        stub_xray, _cfg(), tmp_path / "wd", session=None,
        per_request_timeout=2.0, overall_timeout=10.0)
    assert err == "", err
    assert ip4 == "203.0.113.10"
    assert ip6 == "2001:db8::99"
    # конфиг-файл удалён, процесс убит
    assert not list((tmp_path / "wd").glob("probe-*.json"))


def test_probe_config_dead_binary(stub_xray_no_port, monkeypatch, tmp_path):
    monkeypatch.setattr(xray_mod, "_wait_port", lambda port, timeout=10.0: False)
    ip4, ip6, err = xray_mod.probe_config(
        stub_xray_no_port, _cfg(), tmp_path / "wd", session=None,
        per_request_timeout=2.0, overall_timeout=5.0)
    assert ip4 is None and ip6 is None
    assert "порт" in err


def test_run_checks_and_wifi_policy(stub_xray, monkeypatch, tmp_path):
    cfgs = [_cfg("203.0.113.10"), _cfg("198.51.100.7")]
    monkeypatch.setattr(xray_mod, "_get_ip",
                        lambda s, urls, port, timeout:
                        "203.0.113.10" if urls is xray_mod.IP_FALLBACKS_V4 else None)
    monkeypatch.setattr(geo_mod, "geolocate",
                        lambda s, ip, cache, timeout=8:
                        ("US" if ip == "203.0.113.10" else "DE", "stub"))
    cache = run_checks(cfgs, stub_xray, {}, ttl_hours=24, max_checks=5,
                       workers=2, work_dir=tmp_path / "wd")
    assert len(cache) == 2
    r = cache[cfgs[0].fingerprint]
    assert r.ok and r.ip4 == "203.0.113.10" and r.cc4 == "US" and r.ip6 is None
    ok, reason = wifi_eligible(r, 24)
    assert ok, reason


def test_run_checks_ipv6_conflict(stub_xray, monkeypatch, tmp_path):
    cfgs = [_cfg()]
    monkeypatch.setattr(xray_mod, "_get_ip",
                        lambda s, urls, port, timeout:
                        "203.0.113.10" if urls is xray_mod.IP_FALLBACKS_V4
                        else "2001:db8::99")
    monkeypatch.setattr(geo_mod, "geolocate",
                        lambda s, ip, cache, timeout=8:
                        ("US" if ip.startswith("203") else "DE", "stub"))
    cache = run_checks(cfgs, stub_xray, {}, ttl_hours=24, max_checks=1,
                       workers=1, work_dir=tmp_path / "wd")
    r = cache[cfgs[0].fingerprint]
    assert r.ok
    ok, reason = wifi_eligible(r, 24)
    assert not ok and "противоречие" in reason


def test_run_checks_ru_excluded(stub_xray, monkeypatch, tmp_path):
    cfgs = [_cfg()]
    monkeypatch.setattr(xray_mod, "_get_ip",
                        lambda s, urls, port, timeout:
                        "203.0.113.10" if urls is xray_mod.IP_FALLBACKS_V4 else None)
    monkeypatch.setattr(geo_mod, "geolocate",
                        lambda s, ip, cache, timeout=8: ("RU", "stub"))
    cache = run_checks(cfgs, stub_xray, {}, ttl_hours=24, max_checks=1,
                       workers=1, work_dir=tmp_path / "wd")
    ok, reason = wifi_eligible(cache[cfgs[0].fingerprint], 24)
    assert not ok and "RU" in reason


def test_run_checks_max_checks_limit(stub_xray, monkeypatch, tmp_path):
    cfgs = [_cfg(f"203.0.113.{i}") for i in range(1, 6)]
    monkeypatch.setattr(xray_mod, "_get_ip",
                        lambda s, urls, port, timeout:
                        "203.0.113.10" if urls is xray_mod.IP_FALLBACKS_V4 else None)
    monkeypatch.setattr(geo_mod, "geolocate",
                        lambda s, ip, cache, timeout=8: ("US", "stub"))
    cache = run_checks(cfgs, stub_xray, {}, ttl_hours=24, max_checks=2,
                       workers=2, work_dir=tmp_path / "wd")
    assert len(cache) == 2  # лимит за запуска


def test_ensure_xray_existing_binary(tmp_path):
    b = tmp_path / "xray" / "xray"
    b.parent.mkdir(parents=True)
    b.write_text("#!/bin/sh\nexit 0\n")
    b.chmod(0o755)
    assert xray_mod.ensure_xray(tmp_path, requests.Session()) == b
