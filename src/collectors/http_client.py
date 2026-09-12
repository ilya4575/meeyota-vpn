"""HTTP-клиент: timeout, retry с backoff, ограничение размера, поддержка file:// (для тестов)."""
from __future__ import annotations

import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote, urlsplit

import requests

log = logging.getLogger("meeyota.http")


class FetchError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


@dataclass
class FetchResult:
    url: str
    text: str
    size: int
    sha256: str
    status: int
    elapsed: float
    truncated: bool = False


def _fetch_file_url(url: str, max_bytes: int) -> FetchResult:
    path = unquote(urlsplit(url).path)
    if not os.path.isfile(path):
        raise FetchError(f"file not found: {path}")
    t0 = time.time()
    with open(path, "rb") as f:
        data = f.read(max_bytes + 1)
    truncated = len(data) > max_bytes
    data = data[:max_bytes]
    import hashlib
    return FetchResult(
        url=url,
        text=data.decode("utf-8", "replace"),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        status=200,
        elapsed=time.time() - t0,
        truncated=truncated,
    )


class HttpClient:
    def __init__(self, user_agent: str, timeout: float = 30.0,
                 retries: int = 3, retry_delay: float = 5.0):
        self.timeout = timeout
        self.retries = max(1, retries)
        self.retry_delay = retry_delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "*/*",
        })

    def fetch(self, url: str, timeout: Optional[float] = None,
              max_bytes: int = 25_000_000) -> FetchResult:
        """Скачать текст. Retry на сетевых ошибках/5xx. FetchError — если не получилось."""
        if url.startswith("file://"):
            return _fetch_file_url(url, max_bytes)
        t0 = time.time()
        last_err: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                r = self.session.get(url, timeout=timeout or self.timeout, stream=True)
                if r.status_code == 200:
                    chunks = []
                    total = 0
                    truncated = False
                    for chunk in r.iter_content(chunk_size=65536):
                        total += len(chunk)
                        if total > max_bytes:
                            truncated = True
                            break
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    r.close()
                    import hashlib
                    return FetchResult(
                        url=url,
                        text=data.decode("utf-8", "replace"),
                        size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                        status=200,
                        elapsed=time.time() - t0,
                        truncated=truncated,
                    )
                # 4xx (кроме 429) — ретраем бессмысленно
                if 400 <= r.status_code < 500 and r.status_code != 429:
                    raise FetchError(f"HTTP {r.status_code}", status=r.status_code)
                last_err = FetchError(f"HTTP {r.status_code}", status=r.status_code)
                r.close()
            except FetchError as e:
                last_err = e
                if e.status is not None and 400 <= e.status < 500 and e.status != 429:
                    break  # 404 и т.п. — повторять не стоит
            except (requests.RequestException, OSError) as e:
                last_err = e
            if attempt < self.retries:
                delay = self.retry_delay * attempt + random.uniform(0, 1.0)
                log.warning("fetch %s: попытка %d/%d не удалась (%s), retry через %.1fs",
                            url, attempt, self.retries, last_err, delay)
                time.sleep(delay)
        raise FetchError(f"не удалось скачать {url}: {last_err}")
