"""Геолокация IP через ipwho.is (primary) и ip-api.com (fallback)."""

from __future__ import annotations

import requests
import time


class GeoResult:
    __slots__ = ("country", "source", "raw")

    def __init__(self, country: str, source: str, raw: dict | None = None):
        self.country = country.upper().strip() if country else ""
        self.source = source
        self.raw = raw or {}

    @property
    def is_unknown(self) -> bool:
        return self.country == "" or self.country in {"UNKNOWN", "-"}


def _query_ipwho(ip: str, timeout: int) -> GeoResult | None:
    try:
        r = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=timeout,
            headers={"User-Agent": "meeyota-vpn/1.0"},
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if not d.get("success", True):
            return None
        return GeoResult(country=d.get("country_code", ""), source="ipwho.is", raw=d)
    except Exception:
        return None


def _query_ipapi(ip: str, timeout: int) -> GeoResult | None:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode,status",
            timeout=timeout,
            headers={"User-Agent": "meeyota-vpn/1.0"},
        )
        if r.status_code != 200:
            return None
        d = r.json()
        if d.get("status") != "success":
            return None
        return GeoResult(country=d.get("countryCode", ""), source="ip-api.com", raw=d)
    except Exception:
        return None


def geo_lookup(ip: str, timeout: int = 8) -> GeoResult:
    """Сначала ipwho.is, при ошибке — ip-api.com."""
    primary = _query_ipwho(ip, timeout)
    if primary and not primary.is_unknown:
        return primary
    fallback = _query_ipapi(ip, timeout)
    if fallback:
        return fallback
    return GeoResult(country="", source="none")
