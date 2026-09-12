"""Тесты коллектора: ретраи, ETag-кэш, лимит размера, API-fallback.

HTTP mocked (requests), внешний интернет не нужен.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from src.collectors import Collector, SourceError


def make_settings(tmp_path: Path, **overrides) -> SimpleNamespace:
    base = dict(
        timeout=5,
        retries=3,
        backoff=0.01,
        max_file_size_mb=1,
        use_api_fallback=True,
        cache_dir=str(tmp_path / "cache"),
        data_dir=str(tmp_path),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class FakeResponse:
    def __init__(self, payload: bytes, etag: str | None, status: int):
        self.payload = payload
        self.status_code = status
        self.headers = {"ETag": etag} if etag else {}
        self.ok = status == 200

    def iter_content(self, _n=65536):
        if self.payload:
            yield self.payload

    def json(self):
        return json.loads(self.payload.decode())

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def ok_response(payload: bytes, etag: str | None = '"abc"', status: int = 200):
    return FakeResponse(payload, etag, status)


class FakeSession:
    """Эмулирует requests.Session: элементы списка — ответы либо исключения."""

    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[str] = []
        self.headers = {}

    def get(self, url, **kwargs):
        self.calls.append(url)
        if not self.responses:
            raise AssertionError(f"неожиданный запрос: {url}")
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def test_fetch_github_ok(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    payload = "vless://uuid@1.2.3.4:443\n"
    c.session = FakeSession([ok_response(payload.encode())])
    text = c.fetch_github("owner/repo", "main", "sub.txt")
    assert text == payload
    assert c.session.calls[0] == "https://raw.githubusercontent.com/owner/repo/main/sub.txt"


def test_fetch_github_304_uses_cache(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    payload = "vless://uuid@1.2.3.4:443\n"
    c.session = FakeSession([ok_response(payload.encode(), etag='"v1"')])
    assert c.fetch_github("owner/repo", "main", "sub.txt") == payload

    # повторный запуск: 304 → используется кэш, тело не скачивается
    c.session = FakeSession([ok_response(b"", status=304, etag='"v1"')])
    text = c.fetch_github("owner/repo", "main", "sub.txt")
    assert text == payload


def test_fetch_github_retries_then_success(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    payload = "line\n"
    err = requests.ConnectionError("boom")
    c.session = FakeSession([err, err, ok_response(payload.encode())])
    text = c.fetch_github("owner/repo", "main", "f.txt")
    assert text == payload
    assert len(c.session.calls) == 3


def test_fetch_github_404_no_retry(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    c.session = FakeSession([ok_response(b"{}", status=404)])
    with pytest.raises(SourceError, match="404"):
        c.fetch_github("owner/repo", "main", "missing.txt")
    assert len(c.session.calls) == 1  # 404 не ретраится


def test_fetch_github_size_limit(tmp_path):
    settings = make_settings(tmp_path, max_file_size_mb=0.001)  # ~1 КБ
    c = Collector(settings, root=tmp_path)
    big = b"x" * 5000
    c.session = FakeSession([ok_response(big)])
    with pytest.raises(SourceError, match="лимит"):
        c.fetch_github("owner/repo", "main", "big.txt")


def test_fetch_github_api_fallback(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    payload = "vless://uuid@1.2.3.4:443#name\n"
    b64 = base64.b64encode(payload.encode()).decode()
    err = requests.ConnectionError("raw down")
    c.session = FakeSession([
        err,  # попытка 1 raw
        err,  # попытка 2 raw
        err,  # попытка 3 raw
        ok_response(json.dumps({"name": "f.txt", "path": "f.txt", "sha": "deadbeef",
                                "content": b64, "encoding": "base64", "size": len(payload)}).encode()),
    ])
    text = c.fetch_github("owner/repo", "main", "f.txt")
    assert text == payload
    assert any(calls.startswith("https://api.github.com/repos/owner/repo/contents/") for calls in c.session.calls)


def test_fetch_github_api_fallback_blob_for_big_file(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    payload = "vless://uuid@1.2.3.4:443\n" * 2000  # > 1 МБ
    b64 = base64.b64encode(payload.encode()).decode()
    err = requests.ConnectionError("raw down")
    c.session = FakeSession([
        err, err, err,
        ok_response(json.dumps({"name": "big.txt", "path": "big.txt", "sha": "cafebabe",
                                "content": "", "encoding": "none", "size": len(payload)}).encode()),
        ok_response(json.dumps({"sha": "cafebabe", "content": b64, "encoding": "base64"}).encode()),
    ])
    text = c.fetch_github("owner/repo", "main", "big.txt")
    assert text == payload
    assert any("/git/blobs/cafebabe" in call for call in c.session.calls)


def test_fetch_url_bad_scheme(tmp_path):
    settings = make_settings(tmp_path)
    c = Collector(settings, root=tmp_path)
    with pytest.raises(SourceError):
        c.fetch_url("ftp://example.com/file")
