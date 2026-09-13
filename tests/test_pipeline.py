"""Smoke-test pipeline: проверяет, что main.py корректно собирает output.

Это не реальный e2e (без сетевых запросов), а проверка структуры pipeline
с моком коллектора.
"""

import json
import sys
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import main as m


class _MockResult:
    def __init__(self, content: bytes):
        self.content = content
        self.error = None
        self.from_cache = False
        self.duration_ms = 1


class _MockCollector:
    def __init__(self, text_by_file: dict):
        self.text_by_file = text_by_file
        self.calls: list = []

    def download(self, source_id, repo, branch, file_path):
        self.calls.append((source_id, repo, branch, file_path))
        return _MockResult(self.text_by_file[file_path].encode("utf-8"))


def _setup_cfg(tmp_path: Path) -> m.RunStats:
    # минимальный yaml-конфиг
    cfg_path = tmp_path / "sources.yaml"
    cfg_path.write_text(
        """
version: 1
settings:
  timeout: 5
  retries: 1
  backoff: 1.0
  max_file_size_mb: 5
  use_api_fallback: false
  cache_dir: data/cache
pages:
  username: test
  repository: test-repo
safety:
  min_configs_whitelist: 1
  min_configs_wifi: 1
  max_drop_ratio: 0.5
  max_outbounds_whitelist: 10
  max_outbounds_wifi: 10
checks:
  workers: 1
  per_check_timeout: 1
  check_url: "http://example.com"
  ttl_days: 1
  results_max_configs: 100
  geo_primary: "ipwho.is"
  geo_fallback: "ip-api.com"
update_interval_hours: 6
sources:
  - id: t1
    name: "test1"
    type: github
    repo: owner/repo
    branch: main
    files:
      - a.txt
"""
    )
    return cfg_path


def test_pipeline_runs(tmp_path: Path):
    cfg_path = _setup_cfg(tmp_path)
    text = """
vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@example.com:443?security=tls&type=tcp&sni=cf.com&fp=chrome#Test1
trojan://pass@server2.com:443?security=tls&type=tcp&sni=cf.com#Test2
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server3.com:8388#Test3
"""
    mock = _MockCollector({"a.txt": text})
    # monkeypatch
    orig = m.GithubCollector
    m.GithubCollector = lambda **kwargs: mock
    try:
        cfg = m.load_config(cfg_path)
        stats = m._run_pipeline(cfg)
    finally:
        m.GithubCollector = orig

    assert stats.parsed_total >= 3
    assert stats.whitelist_count >= 3
    assert stats.wifi_count >= 3

    out_wl = Path("output/vpn-whitelist-meeyota.json")
    out_wf = Path("output/vpn-wifi-meeyota.json")
    assert out_wl.exists()
    assert out_wf.exists()

    # проверяем что JSON корректный
    wl = json.loads(out_wl.read_text())
    wf = json.loads(out_wf.read_text())
    assert wl["outbounds"][0]["tag"] == "VPN whitelist meeyota"
    assert wf["outbounds"][0]["tag"] == "VPN Wi-fi meeyota"
    print("✓ test_pipeline_runs")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        test_pipeline_runs(Path(d))
    print("\nPipeline smoke-test passed.")
