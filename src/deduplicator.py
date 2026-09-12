"""Дедупликация и сортировка конфигураций.

Два URI считаются одним и тем же конфигом, если совпадает канонический хеш
(протокол + сервер + порт + учётные данные + транспорт). Первый встреченный
вариант остаётся, остальные источники дописываются в поле ``source``.
"""

from __future__ import annotations

import logging
from collections import OrderedDict

from .models.config import VpnConfig

log = logging.getLogger(__name__)

PROTOCOL_ORDER = {
    "vless": 0,
    "trojan": 1,
    "ss": 2,
    "vmess": 3,
    "hysteria2": 4,
    "tuic": 5,
    "hysteria": 6,
    "ssr": 7,
    "socks5": 8,
}


def dedup(configs: list[VpnConfig]) -> tuple[list[VpnConfig], int]:
    """Убирает дубликаты.

    :return: (уникальные конфиги в порядке первого вхождения, число дублей)
    """
    unique: "OrderedDict[str, VpnConfig]" = OrderedDict()
    duplicates = 0
    for c in configs:
        if not c.hash:
            continue
        holder = unique.get(c.hash)
        if holder is None:
            unique[c.hash] = c
        else:
            duplicates += 1
            for s in c.source:
                if s not in holder.source:
                    holder.source.append(s)
    return list(unique.values()), duplicates


def sort_for_export(configs: list[VpnConfig]) -> list[VpnConfig]:
    """Стабильный порядок для подписки: по протоколам, затем по имени/серверу."""
    return sorted(
        configs,
        key=lambda c: (
            PROTOCOL_ORDER.get(c.protocol, 99),
            c.protocol,
            c.name.lower(),
            c.address.lower(),
            c.port,
        ),
    )
