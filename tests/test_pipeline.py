"""Интеграционный тест пайплайна на локальных файлах (file://) — без сети."""
import base64
import json
import textwrap
from pathlib import Path

import pytest

from src.config import Settings
from src.main import run_pipeline


V1 = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?security=reality&pbk=pbk1&type=tcp&sni=a.example.com&flow=xtls-rprx-vision#n1"
V2 = "vless://bbbbbbbb-cccc-dddd-eeee-ffffffffffff@5.6.7.8:8443?security=none&type=ws&path=/x&host=b.example.com#n2"
SS = "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:secret").decode() + "@9.9.9.9:8388#ss1"
TROJAN = "trojan://pw@7.7.7.7:443?security=tls&sni=c.example.com&type=ws&path=/y#t1"
BROKEN = "vless://not-a-uuid@1.2.3.4:443#broken"


def _make_sources(tmp: Path) -> Path:
    f1 = tmp / "sub1.txt"
    f1.write_text(f"# comment line\n{V1}\n{V1}&\n{V2}\n{SS}\n{BROKEN}\n", encoding="utf-8")
    # base64-источник с дубликатом V1 + trojan
    f2 = tmp / "sub2.b64"
    f2.write_text(base64.b64encode(f"{V1}\n{TROJAN}\n".encode()).decode(), encoding="utf-8")
    # пустой источник
    f3 = tmp / "empty.txt"
    f3.write_text("# only comments\n", encoding="utf-8")

    src = tmp / "sources.yaml"
    src.write_text(textwrap.dedent(f"""
        defaults:
          timeout: 10
          retries: 1
        sources:
          - id: t1
            name: Test1
            url: file://{f1}
          - id: t2
            name: Test2
            url: file://{f2}
          - id: t3
            name: Test3
            url: file://{f3}
        """), encoding="utf-8")
    return src


def _settings(tmp: Path) -> Settings:
    return Settings(
        sources_path=tmp / "sources.yaml",
        data_dir=tmp / "data",
        output_dir=tmp / "output",
        readme_path=tmp / "README.md",
        skip_checks=True,
        username="TESTUSER",
        repository="testrepo",
    )


def test_pipeline_end_to_end(tmp_path: Path):
    (tmp_path / "README.md").write_text("# Test README\n", encoding="utf-8")
    _make_sources(tmp_path)
    rc = run_pipeline(_settings(tmp_path))
    assert rc == 0

    wl = (tmp_path / "output" / "vpn-whitelist-meeyota.txt").read_text(encoding="utf-8")
    lines = [l for l in wl.splitlines() if l.strip()]
    # V1 (раз — дедуп), V2, SS, TROJAN; BROKEN отброшен
    assert len(lines) == 4
    assert V1 in lines and V2 in lines and TROJAN in lines
    assert not any("not-a-uuid" in l for l in lines)

    # configs.json — схема из ТЗ
    recs = json.loads((tmp_path / "data" / "configs.json").read_text(encoding="utf-8"))
    assert len(recs) == 4
    keys = {"protocol", "address", "port", "name", "source", "raw", "hash",
            "last_check", "country", "ip"}
    assert keys <= set(recs[0].keys())
    by_proto = {r["protocol"] for r in recs}
    assert by_proto == {"vless", "trojan", "shadowsocks"}

    # stats.json
    stats = json.loads((tmp_path / "data" / "stats.json").read_text(encoding="utf-8"))
    assert stats["sources"]["sources_ok"] == 3
    assert stats["parse"]["invalid"] == 1
    assert stats["duplicates"] == 2  # V1& (повтор строки) + V1 из base64-источника

    # incy-ссылки в README
    readme = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert "incy://add/https://testuser.github.io/testrepo/vpn-whitelist-meeyota.txt" in readme
    assert "incy://add/https://testuser.github.io/testrepo/vpn-wifi-meeyota.txt" in readme

    # wifi-подпись: проверки не было -> пустой файл существует
    wifi_path = tmp_path / "output" / "vpn-wifi-meeyota.txt"
    assert wifi_path.is_file()
    assert [l for l in wifi_path.read_text().splitlines() if l.strip()] == []


def test_guard_keeps_old_whitelist_on_wipe(tmp_path: Path):
    (tmp_path / "README.md").write_text("# R\n", encoding="utf-8")
    _make_sources(tmp_path)
    s = _settings(tmp_path)
    assert run_pipeline(s) == 0
    old = (tmp_path / "output" / "vpn-whitelist-meeyota.txt").read_text(encoding="utf-8")

    # «временный сбой»: единственный не-пустой источник стал пустым
    (tmp_path / "sub1.txt").write_text("# всё пропало\n", encoding="utf-8")
    # t2 (base64) жив: V1+TROJAN остаются -> без фолбэка whitelist=2 < 30% от 4 -> guard?
    # 2 >= 10? нет, порог min_keep_abs=10, prev=4 < 10 -> guard по whitelist НЕ срабатывает
    # (защита от обнуления работает на больших списках). Убедимся, что всё равно rc==0.
    assert run_pipeline(s) == 0

    # теперь настоящий сценарий обнуления: whitelist 40 -> 1
    many = "\n".join(
        f"vless://{i:08x}-aaaa-bbbb-cccc-0000000000{i:02d}@{100 + i // 200}.{i % 200}.{i % 50}.{i % 30}:443?security=none&type=tcp#x{i}"
        for i in range(40))
    (tmp_path / "sub1.txt").write_text(many + "\n", encoding="utf-8")
    assert run_pipeline(s) == 0
    wl = [l for l in (tmp_path / "output" / "vpn-whitelist-meeyota.txt").read_text().splitlines() if l]
    assert len(wl) == 42  # 40 (many) + V1 + TROJAN из t2

    # сбой: sub1 снова пуст, t2 жив -> whitelist=2, было 42 -> guard срабатывает
    (tmp_path / "sub1.txt").write_text("# empty again\n", encoding="utf-8")
    rc = run_pipeline(s)
    assert rc == 1  # guard abort
    wl_after = [l for l in (tmp_path / "output" / "vpn-whitelist-meeyota.txt").read_text().splitlines() if l]
    assert len(wl_after) == 42  # старый файл не тронут


def test_wifi_guard_nonfatal_whitelist_still_updates(tmp_path: Path):
    (tmp_path / "README.md").write_text("# R\n", encoding="utf-8")
    _make_sources(tmp_path)
    s = _settings(tmp_path)
    assert run_pipeline(s) == 0
    wifi_path = tmp_path / "output" / "vpn-wifi-meeyota.txt"
    # имитируем: в wifi-подписке уже есть проверенный конфиг
    wifi_path.write_text(
        "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?security=none&type=tcp#old\n",
        encoding="utf-8")
    # следующий запуск: checks не выполнялись (skip_checks), wifi стал бы пустым
    # -> guard по wifi срабатывает, но НЕ фатально: whitelist обновляется,
    # старый wifi-список сохраняется, rc=0
    rc = run_pipeline(s)
    assert rc == 0
    assert "#old" in wifi_path.read_text(encoding="utf-8")
    wl = [l for l in (tmp_path / "output" / "vpn-whitelist-meeyota.txt").read_text().splitlines() if l]
    assert len(wl) == 4


def test_all_sources_down_fails_safely(tmp_path: Path):
    (tmp_path / "README.md").write_text("# R\n", encoding="utf-8")
    _make_sources(tmp_path)
    s = _settings(tmp_path)
    # все URL битые
    src = tmp_path / "sources.yaml"
    src.write_text(textwrap.dedent("""
        sources:
          - id: bad1
            name: Bad
            url: file:///nonexistent/nope.txt
            retries: 1
          - id: bad2
            name: Bad2
            url: file:///nonexistent/nope2.txt
            retries: 1
        """), encoding="utf-8")
    rc = run_pipeline(s)
    assert rc == 2  # фатально: ни одного источника и кэш пуст
