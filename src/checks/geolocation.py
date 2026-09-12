"""Геолокация внешнего IP.

Источники (бесплатные, без ключей):
    1. https://ipwho.is/{ip}
    2. http://ip-api.com/{ip}?fields=countryCode,status  (fallback, только http)

Результат кэшируется в ``data/geo_cache.json`` на ``geo_ttl_days`` дней,
чтобы повторные запуски не нагружали API и не «прыгали» между базами.

Важно: IP-базы могут ошибаться и обновляются с задержкой. Поэтому:
    * «неизвестная» страна (оба API молчат) => результат считается
      НЕУДАЧНЫМ для подписки Wi-fi (строгий режим);
    * результат кэшируется, чтобы одна сессия видела одну и ту же базу.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)


class GeoLookup:
    def __init__(
        self,
        cache_path: Path,
        ttl_days: float = 7,
        max_entries: int = 20000,
        session: requests.Session | None = None,
        timeout: float = 10,
    ):
        self.cache_path = Path(cache_path)
        self.ttl = ttl_days * 86400
        self.max_entries = max_entries
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": "meeyota-vpn-aggregator/1.0"})
        self.timeout = timeout
        self.cache: dict[str, dict[str, Any]] = self._load(self.cache_path)
        self._dirty = False

    # ------------------------------------------------------------------

    def country(self, ip: str) -> str | None:
        """Код страны (ISO 3166-1 alpha-2, например 'NL') или None."""
        entry = self.cache.get(ip)
        if entry and (time.time() - float(entry.get("at", 0))) < self.ttl:
            return entry.get("cc")
        cc = self._query(ip)
        if cc is None:
            return None
        self._add(ip, cc)
        return cc

    # ------------------------------------------------------------------

    def _query(self, ip: str) -> str | None:
        # 1) ipwho.is
        try:
            r = self.session.get(f"https://ipwho.is/{ip}", timeout=self.timeout)
            if r.status_code == 200:
                d = r.json()
                if d.get("success") is not False and d.get("country_code"):
                    return str(d["country_code"]).upper()
                if d.get("country_code") is None and d.get("success") is not False:
                    # IP без известной страны — не «RU», но и не подтверждённый результат
                    log.debug("ipwho.is: %s без страны", ip)
        except (requests.RequestException, ValueError) as e:
            log.debug("ipwho.is недоступен для %s: %s", ip, e)
        # 2) ip-api.com
        try:
            r = self.session.get(
                f"http://ip-api.com/{ip}?fields=countryCode,status", timeout=self.timeout
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success" and d.get("countryCode"):
                    return str(d["countryCode"]).upper()
        except (requests.RequestException, ValueError) as e:
            log.debug("ip-api.com недоступен для %s: %s", ip, e)
        return None

    # ------------------------------------------------------------------

    def _add(self, ip: str, cc: str) -> None:
        self.cache[ip] = {"cc": cc, "at": time.time()}
        if len(self.cache) > self.max_entries:
            oldest = sorted(self.cache.items(), key=lambda kv: float(kv[1].get("at", 0)))
            for key, _ in oldest[: len(self.cache) - self.max_entries]:
                self.cache.pop(key, None)
        self._dirty = True

    def save(self) -> None:
        if not self._dirty and self.cache_path.exists():
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.cache_path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.cache_path)
            self._dirty = False
        except OSError as e:
            log.warning("не удалось сохранить geo-кэш: %s", e)

    @staticmethod
    def _load(path: Path) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, ValueError):
            pass
        return {}
