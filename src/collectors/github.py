"""Коллектор: скачивание файлов из GitHub (raw + API fallback)."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests


@dataclass
class DownloadResult:
    source_id: str
    file_path: str
    content: bytes
    from_cache: bool
    duration_ms: int
    error: str | None = None


class GithubCollector:
    """Скачивает файлы из GitHub с retry, ETag-кэшем и API fallback."""

    def __init__(
        self,
        cache_dir: Path,
        timeout: int = 30,
        retries: int = 3,
        backoff: float = 2.0,
        max_file_size_mb: int = 25,
        user_agent: str = "meeyota-vpn/1.0",
        use_api_fallback: bool = True,
        github_token: str | None = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_bytes = max_file_size_mb * 1024 * 1024
        self.user_agent = user_agent
        self.use_api_fallback = use_api_fallback
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN", "")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    def _cache_path(self, source_id: str, file_path: str) -> Path:
        key = hashlib.sha256(f"{source_id}::{file_path}".encode()).hexdigest()[:16]
        return self.cache_dir / f"{key}-{Path(file_path).name}"

    def _download_raw(self, repo: str, branch: str, file_path: str) -> tuple[bytes, str | None]:
        url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file_path}"
        headers: dict = {}
        etag_path = self._cache_path(f"etag::{repo}", file_path)
        if etag_path.exists():
            headers["If-None-Match"] = etag_path.read_text().strip()
        r = self.session.get(url, headers=headers, timeout=self.timeout, stream=True)
        if r.status_code == 304:
            # not modified — отдаём кэш
            cached = self._cache_path(repo, file_path)
            if cached.exists():
                return cached.read_bytes(), "etag"
            # нет кэша — попробуем ещё раз без etag
            r = self.session.get(url, timeout=self.timeout, stream=True)
        r.raise_for_status()
        if "etag" in r.headers:
            etag_path.write_text(r.headers["etag"])
        # читаем с лимитом
        buf = bytearray()
        for chunk in r.iter_content(chunk_size=65536):
            buf.extend(chunk)
            if len(buf) > self.max_bytes:
                raise ValueError(
                    f"file {file_path!r} exceeds max size {self.max_bytes} bytes"
                )
        return bytes(buf), None

    def _download_api(self, repo: str, branch: str, file_path: str) -> bytes:
        """Fallback: GitHub API с base64."""
        url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
        headers = {"Accept": "application/vnd.github.raw+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        r = self.session.get(url, headers=headers, timeout=self.timeout)
        r.raise_for_status()
        return r.content[: self.max_bytes]

    def download(self, source_id: str, repo: str, branch: str, file_path: str) -> DownloadResult:
        started = time.monotonic()
        cache_path = self._cache_path(source_id, file_path)
        last_error: str | None = None
        for attempt in range(1, self.retries + 1):
            try:
                content, from_cache_reason = self._download_raw(repo, branch, file_path)
                if not from_cache_reason:
                    cache_path.write_bytes(content)
                return DownloadResult(
                    source_id=source_id,
                    file_path=file_path,
                    content=content,
                    from_cache=bool(from_cache_reason),
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                if attempt < self.retries:
                    time.sleep(self.backoff ** attempt)
        # raw не сработал — пробуем API fallback
        if self.use_api_fallback:
            try:
                content = self._download_api(repo, branch, file_path)
                cache_path.write_bytes(content)
                return DownloadResult(
                    source_id=source_id,
                    file_path=file_path,
                    content=content,
                    from_cache=False,
                    duration_ms=int((time.monotonic() - started) * 1000),
                )
            except Exception as e:
                last_error = f"raw={last_error}; api={type(e).__name__}: {e}"

        return DownloadResult(
            source_id=source_id,
            file_path=file_path,
            content=b"",
            from_cache=False,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=last_error,
        )
