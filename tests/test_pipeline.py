"""Интеграционный тест: полный пайплайн на локальном HTTP-сервере.

Проверяется: sources.yaml (url-источник) → скачивание → парсинг →
дедупликация → экспорт двух подписок + data/stats.json + data/configs.json
+ защита от обнуления. Внешний интернет не требуется.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from src.config import ConfigError, load_settings
from src.main import main

SAMPLE_A = (
    "#profile-title: test\n"
    "vless://11111111-2222-3333-4444-555555555555@93.184.216.34:443?security=none&type=tcp#srv-1\n"
    "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@93.184.216.34:8443?security=none&type=tcp#srv-2\n"
    "ss://YWVzLTI1Ni1nY206cGFzcw==@203.0.113.9:8388#srv-3\n"
    "vless://11111111-2222-3333-4444-555555555555@93.184.216.34:443?security=none&type=tcp#srv-1-dup\n"
    "vless://not-a-uuid@93.184.216.34:443\n"
)

SAMPLE_B = (
    "trojan://secret@198.51.100.7:443?sni=example.com#srv-4\n"
    "vless://11111111-2222-3333-4444-555555555555@93.184.216.34:443?security=none&type=tcp#srv-1\n"
)


class Handler(BaseHTTPRequestHandler):
    files = {"/a.txt": SAMPLE_A, "/b.txt": SAMPLE_B}

    def do_GET(self):  # noqa: N802
        body = self.files.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # тихий сервер
        pass


@pytest.fixture()
def project(tmp_path: Path):
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    sources = tmp_path / "sources.yaml"
    sources.write_text(
        f"""
settings:
  timeout: 10
  retries: 1
  cache_dir: data/cache
pages:
  username: TESTUSER
  repository: testrepo
safety:
  min_configs: 2
  max_drop_ratio: 0.5
sources:
  - id: local-a
    type: url
    files:
      - http://127.0.0.1:{port}/a.txt
  - id: local-b
    type: url
    files:
      - http://127.0.0.1:{port}/b.txt
""",
        encoding="utf-8",
    )
    readme = tmp_path / "README.md"
    readme.write_text("# Test README\n", encoding="utf-8")
    yield tmp_path, sources
    server.shutdown()


def test_full_pipeline(project):
    root, sources = project
    rc = main(["--config", str(sources)])
    assert rc == 0

    out = root / "output"
    wl = (out / "vpn-whitelist-meeyota.txt").read_text(encoding="utf-8")
    wf = (out / "vpn-wifi-meeyota.txt").read_text(encoding="utf-8")

    # 5 URI в источниках: 1 дубликат (srv-1 из b), 1 битый → 4 уникальных
    assert "# Количество: 4" in wl
    assert wl.count("vless://") == 2
    assert "trojan://" in wl
    assert "# Количество: 0" in wf  # проверки не выполнялись

    stats = json.loads((root / "data/stats.json").read_text(encoding="utf-8"))
    assert stats["found"] == 6
    assert stats["invalid"] == 1
    assert stats["unique"] == 4
    assert stats["duplicates"] == 2  # srv-1 (в a дубль + в b)
    assert stats["whitelist"] == 4
    assert stats["wifi"] == 0
    assert len(stats["sources"]) == 2
    assert all(s["status"] == "ok" for s in stats["sources"])

    configs = json.loads((root / "data/configs.json").read_text(encoding="utf-8"))
    assert len(configs) == 4
    c0 = configs[0]
    for key in ("protocol", "address", "port", "name", "source", "raw", "hash",
                "last_check", "country", "ip"):
        assert key in c0

    # дедупликация: srv-1 из обоих источников
    srv1 = [c for c in configs if c["name"] == "srv-1"]
    assert len(srv1) == 1
    assert sorted(srv1[0]["source"]) == ["local-a", "local-b"]

    # README получил блок Incy-ссылок
    readme_text = (root / "README.md").read_text(encoding="utf-8")
    assert "incy://add/https://TESTUSER.github.io/testrepo/vpn-whitelist-meeyota.txt" in readme_text


def test_wipeout_protection(project):
    root, sources = project
    assert main(["--config", str(sources)]) == 0

    # теперь все источники недоступны (сервер отключён новым пустым sources)
    bad = root / "bad_sources.yaml"
    bad.write_text(
        """
settings:
  retries: 1
  cache_dir: data/cache
pages:
  username: TESTUSER
  repository: testrepo
safety:
  min_configs: 2
sources:
  - id: dead
    type: url
    files:
      - http://127.0.0.1:1/none.txt
""",
        encoding="utf-8",
    )
    rc = main(["--config", str(bad)])
    assert rc == 2  # обнуление заблокировано

    # прежний whitelist не тронут
    wl = (root / "output/vpn-whitelist-meeyota.txt").read_text(encoding="utf-8")
    assert "# Количество: 4" in wl
    stats = json.loads((root / "data/stats.json").read_text(encoding="utf-8"))
    assert stats["aborted"]
