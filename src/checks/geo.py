"""Геолокация IP через публичные API (без ключей): ipwho.is -> ip-api.com -> ipinfo.io.

Важно: IP-базы могут ошибаться или устаревать — считаем результат индикатором,
а не абсолютной истиной (см. README, раздел «Честное предупреждение»).
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from typing import Dict, Optional, Tuple

import requests

log = logging.getLogger("meeyota.geo")

PROVIDER_TIMEOUT = 8.0
_POLITE_DELAY = 0.12  # сек между запросами, чтобы не грузить публичные API


class GeoCache:
    """Промежуточный кэш IP -> (country, ts) на время одного запуска."""

    def __init__(self) -> None:
        self._d: Dict[str, Tuple[Optional[str], float]] = {}
        self._lock = threading.Lock()

    def get(self, ip: str) -> Optional[str]:
        with self._lock:
            v = self._d.get(ip)
            return v[0] if v else None

    def set(self, ip: str, cc: Optional[str]) -> None:
        with self._lock:
            self._d[ip] = (cc, time.time())

    def size(self) -> int:
        with self._lock:
            return len(self._d)


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def geolocate(session: requests.Session, ip: str, cache: GeoCache,
              timeout: float = PROVIDER_TIMEOUT) -> Tuple[Optional[str], Optional[str]]:
    """-> (country_code|None, provider|None)."""
    ip = ip.strip()
    if not _valid_ip(ip):
        return None, None
    cached = cache.get(ip)
    if cached is not None:
        return cached, "cache"

    cc: Optional[str] = None
    provider: Optional[str] = None

    # 1) ipwho.is — https, без ключа
    try:
        r = session.get(f"https://ipwho.is/{ip}", timeout=timeout)
        j = r.json()
        if j.get("success") is not False and j.get("country_code"):
            cc, provider = j["country_code"].upper(), "ipwho.is"
    except (requests.RequestException, ValueError) as e:
        log.debug("ipwho.is(%s): %s", ip, e)

    # 2) ip-api.com — http, без ключа, 45 req/min
    if cc is None:
        time.sleep(_POLITE_DELAY)
        try:
            r = session.get(f"http://ip-api.com/json/{ip}",
                            params={"fields": "status,countryCode"}, timeout=timeout)
            j = r.json()
            if j.get("status") == "success" and j.get("countryCode"):
                cc, provider = j["countryCode"].upper(), "ip-api.com"
        except (requests.RequestException, ValueError) as e:
            log.debug("ip-api(%s): %s", ip, e)

    # 3) ipinfo.io — https, без ключа
    if cc is None:
        time.sleep(_POLITE_DELAY)
        try:
            r = session.get(f"https://ipinfo.io/{ip}/json", timeout=timeout)
            j = r.json()
            if j.get("country"):
                cc, provider = j["country"].upper(), "ipinfo.io"
        except (requests.RequestException, ValueError) as e:
            log.debug("ipinfo(%s): %s", ip, e)

    cache.set(ip, cc)
    if cc is None:
        log.warning("геолокация не удалась для %s (все провайдеры)", ip)
    return cc, provider
