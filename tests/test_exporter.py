"""Тесты экспорта: подписки, защита от обнуления, Incy-ссылки, README-блок."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace

from src.exporter import (
    INCY_BEGIN,
    INCY_END,
    WHITELIST_FILE,
    WIFI_FILE,
    count_uris,
    incy_add,
    incy_import,
    render_incy_links,
    render_subscription,
    update_readme_links,
    wipeout_ok,
    write_outputs,
)
from src.models.config import VpnConfig
from src.parsers import parse_uri

from .conftest import VLESS_REALITY_TCP, SS_NEW


def make_settings() -> SimpleNamespace:
    return SimpleNamespace(
        pages_username="USERNAME",
        pages_repository="REPOSITORY",
        update_interval_hours=6,
    )


def cfgs():
    a = parse_uri(VLESS_REALITY_TCP, "s1")
    b = parse_uri(SS_NEW, "s1")
    return [a, b]


def test_render_subscription_header():
    text = render_subscription(cfgs(), "VPN Whitelist meeyota", make_settings())
    assert text.startswith("#profile-title: VPN Whitelist meeyota\n")
    assert "#profile-update-interval: 6" in text
    assert "#profile-web-page-url: https://USERNAME.github.io/REPOSITORY" in text
    assert "# Количество: 2" in text
    assert VLESS_REALITY_TCP in text
    assert SS_NEW in text


def test_render_subscription_checked_comments():
    a, b = cfgs()
    checked = {
        a.hash: {"last_check": "2026-01-01T00:00:00Z", "country": "NL", "ip": "1.2.3.4"},
    }
    text = render_subscription([a, b], "VPN Wi-fi meeyota", make_settings(), checked=checked)
    assert "# checked: 2026-01-01T00:00:00Z | country: NL | ip: 1.2.3.4" in text
    # у b нет результатов проверки → без комментария
    assert text.count("# checked:") == 1


def test_count_uris(tmp_path: Path):
    p = tmp_path / "sub.txt"
    p.write_text(
        "#profile-title: x\nvless://a@1.1.1.1:443\nss://b@2.2.2.2:8388\n# comment\n",
        encoding="utf-8",
    )
    assert count_uris(p) == 2
    assert count_uris(tmp_path / "missing.txt") == 0


def test_wipeout_rules():
    # нормальный случай
    assert wipeout_ok(0, 500, 50, 0.5)[0] is True
    # первый запуск: меньше минимума
    ok, reason = wipeout_ok(0, 10, 50, 0.5)
    assert ok is False and "минимум" in reason
    # резкое падение при старом большом списке
    ok, reason = wipeout_ok(5000, 2000, 50, 0.5)
    assert ok is False and "сократился" in reason
    # умеренное изменение — ок
    assert wipeout_ok(5000, 4000, 50, 0.5)[0] is True


def test_write_outputs(tmp_path: Path):
    a, b = cfgs()
    a.verdict = "ok"
    a.country = "NL"
    a.ip = "1.2.3.4"
    a.last_check = "2026-01-01T00:00:00Z"
    b.verdict = "ru"
    checked = {a.hash: {"last_check": a.last_check, "country": "NL", "ip": "1.2.3.4"}}
    paths = write_outputs(tmp_path, [a, b], [a], make_settings(), checked)
    assert paths["whitelist"].name == WHITELIST_FILE
    assert paths["wifi"].name == WIFI_FILE
    wl = paths["whitelist"].read_text()
    wf = paths["wifi"].read_text()
    assert VLESS_REALITY_TCP in wl and SS_NEW in wl
    assert VLESS_REALITY_TCP in wf and SS_NEW not in wf
    assert "# checked:" in wf


def test_incy_links():
    s = SimpleNamespace(pages_username="ilya4575", pages_repository="meeyota-vpn")
    block = render_incy_links(s)
    assert "incy://add/https://ilya4575.github.io/meeyota-vpn/vpn-whitelist-meeyota.txt" in block
    assert "incy://add/https://ilya4575.github.io/meeyota-vpn/vpn-wifi-meeyota.txt" in block


def test_incy_import_roundtrip():
    payload = "vless://x@1.1.1.1:443#n\n"
    link = incy_import(payload)
    assert link.startswith("incy://import/")
    decoded = base64.b64decode(link[len("incy://import/"):]).decode()
    assert decoded == payload
    assert incy_add("https://a/b.txt") == "incy://add/https://a/b.txt"


def test_update_readme_links(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text("# Test\n\nКонтент.\n", encoding="utf-8")
    block_text = "## 🔗 Ссылки\n\nincy://add/https://u.github.io/r/a.txt\n"
    changed = update_readme_links(readme, block_text)
    assert changed is True
    text = readme.read_text()
    assert INCY_BEGIN in text and INCY_END in text
    assert "incy://add/https://u.github.io/r/a.txt" in text

    # повторное обновление того же блока — без изменений
    changed2 = update_readme_links(readme, block_text)
    assert changed2 is False
