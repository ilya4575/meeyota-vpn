"""Скачивание файлов-источников.

* Основной путь — ``https://raw.githubusercontent.com/{repo}/{branch}/{path}``.
* Fallback (если raw недоступен) — GitHub REST API (``/contents`` или
  ``/git/blobs`` для файлов больше 1 МБ).
* Повторные попытки с экспоненциальной задержкой, таймаут, лимит размера.
* Кэш файлов и ETag: при повторном запуске без изменений файл не
  скачивается повторно (HTTP 304).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

log = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_RAW_BASE = "https://raw.githubusercontent.com"


class SourceError(Exception):
    """Источниковый файл недоступен / повреждён / слишком велик."""


class SourceNotFound(SourceError):
    """Файл отсутствует (404) — retry/fallback бессмысленны."""


class SourceTooLarge(SourceError):
    """Файл превышает лимит размера — источник отклонён целенаправленно."""


class Collector:
    def __init__(self, settings: Any, root: Path | None = None):
        self.settings = settings
        self.root = Path(root) if root else Path(".")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "meeyota-vpn-aggregator/1.0"})
        self.cache_dir = self.root / settings.cache_dir / "files"
        self.etag_path = self.root / settings.cache_dir / "etags.json"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.etags: dict[str, str] = self._load_json(self.etag_path, default={})

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def fetch_github(self, repo: str, branch: str, path: str, max_size_mb: float | None = None) -> str:
        """Скачивает файл из GitHub-репозитория (raw → API fallback)."""
        raw_url = f"{_RAW_BASE}/{repo}/{branch}/{quote(path, safe='/')}"
        cache_file = self._cache_file(raw_url)
        etag = self.etags.get(raw_url)

        try:
            text, new_etag = self._http_get(raw_url, etag=etag, max_size_mb=max_size_mb)
            if text is None:  # 304 Not Modified
                if cache_file.exists():
                    log.info("304 Not Modified (использован кэш): %s", raw_url)
                    return cache_file.read_text(encoding="utf-8")
                raise SourceError("получен 304, но кэш отсутствует")
            cache_file.write_text(text, encoding="utf-8")
            if new_etag:
                self.etags[raw_url] = new_etag
                self._save_etags()
            return text
        except (SourceNotFound, SourceTooLarge):
            # фатальные: нет смысла пробовать API
            raise
        except SourceError as e:
            if not self.settings.use_api_fallback:
                raise
            log.warning("raw недоступен (%s) — пробую GitHub API: %s", e, raw_url)

        text = self._fetch_via_api(repo, branch, path, max_size_mb=max_size_mb)
        cache_file.write_text(text, encoding="utf-8")
        return text

    def fetch_url(self, url: str, max_size_mb: float | None = None) -> str:
        """Скачивает произвольный HTTPS-URL."""
        if not url.lower().startswith(("http://", "https://")):
            raise SourceError(f"некорректный URL: {url!r}")
        cache_file = self._cache_file(url)
        etag = self.etags.get(url)
        text, new_etag = self._http_get(url, etag=etag, max_size_mb=max_size_mb)
        if text is None:
            if cache_file.exists():
                log.info("304 Not Modified (использован кэш): %s", url)
                return cache_file.read_text(encoding="utf-8")
            raise SourceError("получен 304, но кэш отсутствует")
        cache_file.write_text(text, encoding="utf-8")
        if new_etag:
            self.etags[url] = new_etag
            self._save_etags()
        return text

    # ------------------------------------------------------------------
    # Внутреннее
    # ------------------------------------------------------------------

    def _cache_file(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]
        return self.cache_dir / f"{digest}.txt"

    def _http_get(
        self, url: str, etag: str | None = None, max_size_mb: float | None = None
    ) -> tuple[str | None, str | None]:
        """GET с ретраями. Возвращает (text|None-при-304, etag)."""
        limit = (max_size_mb or self.settings.max_file_size_mb) * 1024 * 1024
        last_err: str = "unknown"
        for attempt in range(1, self.settings.retries + 1):
            headers = {"If-None-Match": etag} if etag else {}
            try:
                with self.session.get(
                    url, headers=headers, timeout=self.settings.timeout, stream=True
                ) as r:
                    if r.status_code == 304:
                        return None, etag
                    if r.status_code == 200:
                        chunks: list[bytes] = []
                        size = 0
                        for chunk in r.iter_content(65536):
                            size += len(chunk)
                            if size > limit:
                                raise SourceTooLarge(
                                    f"файл больше лимита {max_size_mb or self.settings.max_file_size_mb} МБ"
                                )
                            chunks.append(chunk)
                        new_etag = r.headers.get("ETag")
                        return b"".join(chunks).decode("utf-8", "replace"), new_etag
                    if r.status_code == 404:
                        raise SourceNotFound("HTTP 404: файл не найден")
                    last_err = f"HTTP {r.status_code}"
            except SourceError:
                raise
            except requests.RequestException as e:
                last_err = f"{type(e).__name__}: {e}"
            if attempt < self.settings.retries:
                delay = self.settings.backoff ** attempt
                log.warning(
                    "повтор %d/%d через %.1f с — %s (%s)",
                    attempt, self.settings.retries, delay, url, last_err,
                )
                time.sleep(delay)
        raise SourceError(f"недоступен после {self.settings.retries} попыток: {url} ({last_err})")

    def _fetch_via_api(self, repo: str, branch: str, path: str, max_size_mb: float | None = None) -> str:
        limit = (max_size_mb or self.settings.max_file_size_mb) * 1024 * 1024
        contents_url = f"{_API_BASE}/repos/{repo}/contents/{quote(path, safe='/')}?ref={branch}"
        last_err = "unknown"
        for attempt in range(1, self.settings.retries + 1):
            try:
                r = self.session.get(contents_url, timeout=self.settings.timeout)
            except requests.RequestException as e:
                r = None
                last_err = str(e)
            if r is not None:
                if r.status_code == 200:
                    d = r.json()
                    if d.get("content"):
                        data = base64.b64decode(d["content"]).decode("utf-8", "replace")
                        if len(data.encode("utf-8")) > limit:
                            raise SourceError("файл больше лимита (API)")
                        return data
                    # файл > 1 МБ: contents API не возвращает содержимое
                    blob_url = f"{_API_BASE}/repos/{repo}/git/blobs/{d['sha']}"
                    try:
                        br = self.session.get(blob_url, timeout=max(120, self.settings.timeout * 4))
                        if br.status_code == 200:
                            data = base64.b64decode(br.json()["content"]).decode("utf-8", "replace")
                            return data
                        last_err = f"blobs HTTP {br.status_code}"
                    except requests.RequestException as e:
                        last_err = str(e)
                elif r.status_code == 404:
                    raise SourceNotFound(f"HTTP 404 (API): {path}")
                else:
                    last_err = f"HTTP {r.status_code}"
            if attempt < self.settings.retries:
                delay = self.settings.backoff ** attempt
                time.sleep(delay)
        raise SourceError(f"GitHub API недоступен: {path} ({last_err})")

    # ------------------------------------------------------------------

    @staticmethod
    def _load_json(path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _save_etags(self) -> None:
        try:
            self.etag_path.parent.mkdir(parents=True, exist_ok=True)
            self.etag_path.write_text(
                json.dumps(self.etags, ensure_ascii=False, indent=0), encoding="utf-8"
            )
        except OSError as e:
            log.warning("не удалось сохранить ETag-кэш: %s", e)
