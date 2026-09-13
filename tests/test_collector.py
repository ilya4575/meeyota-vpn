"""Тест коллектора с моком requests — без реальных сетевых вызовов."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.github import GithubCollector


class _FakeResponse:
    def __init__(self, status, body=b"", headers=None):
        self.status_code = status
        self.content = body
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=65536):
        yield self.content


class _FakeSession:
    def __init__(self):
        self.responses = []
        self.calls = []

    def queue(self, r):
        self.responses.append(r)

    def get(self, url, headers=None, timeout=None, stream=False):
        self.calls.append({"url": url, "headers": headers or {}})
        if not self.responses:
            raise RuntimeError("no response queued")
        r = self.responses.pop(0)
        return r


def test_download_raw_ok(tmp_path):
    coll = GithubCollector(cache_dir=tmp_path, retries=1)
    body = b"vless://abc@server.com:443?security=tls#X\n"
    coll.session = _FakeSession()
    coll.session.queue(_FakeResponse(200, body, {"etag": "W/\"abc\""}))
    r = coll.download("src1", "owner/repo", "main", "file.txt")
    assert r.error is None
    assert r.content == body
    assert len(coll.session.calls) == 1
    print("✓ test_download_raw_ok")


def test_download_304_uses_cache(tmp_path):
    coll = GithubCollector(cache_dir=tmp_path, retries=1)
    body = b"vless://abc@server.com:443?security=tls#X\n"
    cache_path = coll._cache_path("owner/repo", "file.txt")
    cache_path.write_bytes(body)
    etag_path = coll._cache_path("etag::owner/repo", "file.txt")
    etag_path.write_text('W/"xyz"')

    coll.session = _FakeSession()
    coll.session.queue(_FakeResponse(304))
    r = coll.download("src1", "owner/repo", "main", "file.txt")
    assert r.error is None
    assert r.content == body
    assert r.from_cache is True
    print("✓ test_download_304_uses_cache")


def test_download_retry_on_error(tmp_path):
    coll = GithubCollector(cache_dir=tmp_path, retries=2, backoff=1.0)
    coll.session = _FakeSession()
    # 500, потом 200
    coll.session.queue(_FakeResponse(500))
    coll.session.queue(_FakeResponse(200, b"vless://abc@server.com:443?security=tls#X\n"))
    r = coll.download("src1", "owner/repo", "main", "file.txt")
    assert r.error is None
    assert len(coll.session.calls) == 2
    print("✓ test_download_retry_on_error")


def test_download_returns_error_when_all_retries_fail(tmp_path):
    coll = GithubCollector(cache_dir=tmp_path, retries=2, backoff=1.0, use_api_fallback=False)
    coll.session = _FakeSession()
    coll.session.queue(_FakeResponse(500))
    coll.session.queue(_FakeResponse(500))
    r = coll.download("src1", "owner/repo", "main", "file.txt")
    assert r.error is not None
    print("✓ test_download_returns_error_when_all_retries_fail")


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        test_download_raw_ok(Path(d))
        test_download_304_uses_cache(Path(d))
        test_download_retry_on_error(Path(d))
        test_download_returns_error_when_all_retries_fail(Path(d))
    print("\nAll collector tests passed.")
