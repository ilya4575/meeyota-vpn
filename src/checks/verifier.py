"""Stub для проверки Wi-Fi конфигураций.

Полная реализация через sing-box/xray-core + TCP-соединение описана в
документации (см. ARCHITECTURE-DRAFT.md §5.3). В рамках этой реализации
мы используем только геолокацию IP из URI — это даёт быстрый и
воспроизводимый фильтр, не требующий запуска прокси в CI.

Если sing-box/xray-core доступны — можно расширить через реальные
соединения; сейчас фильтрация делается по:
  - host из URI (если IP, проверяем геолокацию);
  - результат кэшируется в data/check_results.json по TTL.
"""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path

from ..models.config import VpnConfig
from .geolocation import geo_lookup


def _try_ip(host: str) -> str | None:
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(host)
        return host
    except ValueError:
        pass
    return None


def is_non_russian(config: VpnConfig, cache: dict, ttl_seconds: int) -> tuple:
    """Проверяет, что хост НЕ в RU.

    Возвращает (passes: bool, reason: str, cached_country: str).
    """
    host = config.host
    # Если это домен — пропускаем (нет способа провести IP-проверку без DNS)
    if not _try_ip(host):
        # По соглашению — пропускаем домены. Пользователь получит больше узлов.
        return True, "domain (not IP)", ""

    now = time.time()
    cached = cache.get(host)
    if cached and now - cached.get("ts", 0) < ttl_seconds:
        cc = cached.get("country", "")
        if cc == "RU":
            return False, f"cached RU ({cached.get('source', '?')})", cc
        if cc == "" or cc == "UNKNOWN":
            return False, f"cached unknown ({cached.get('source', '?')})", cc
        return True, f"cached non-RU {cc}", cc

    geo = geo_lookup(host)
    cache[host] = {"ts": now, "country": geo.country, "source": geo.source}

    if geo.is_unknown:
        return False, "geo lookup failed", ""
    if geo.country == "RU":
        return False, f"geo={geo.country} ({geo.source})", geo.country
    return True, f"geo={geo.country} ({geo.source})", geo.country


def load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
