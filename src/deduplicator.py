"""Дедупликация VpnConfig по каноническому хешу."""

from __future__ import annotations

from .models.config import VpnConfig, make_hash


def deduplicate(configs: list) -> tuple:
    """Возвращает (unique, dropped_count)."""
    seen: set = set()
    unique: list = []
    dropped = 0
    for c in configs:
        h = make_hash(c)
        if h in seen:
            dropped += 1
            continue
        seen.add(h)
        unique.append(c)
    return unique, dropped
