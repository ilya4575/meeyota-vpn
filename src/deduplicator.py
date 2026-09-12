"""Дедупликация конфигураций по fingerprint (первый встреченный выигрывает).

Порядок конфигураций = приоритет источников (как в sources.yaml).
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .models.config import VpnConfig


@dataclass
class DedupeResult:
    unique: List[VpnConfig] = field(default_factory=list)
    duplicates: int = 0
    by_protocol: Dict[str, int] = field(default_factory=dict)


def dedupe(configs: List[VpnConfig]) -> DedupeResult:
    seen: set = set()
    res = DedupeResult()
    for cfg in configs:
        fp = cfg.fingerprint
        if fp in seen:
            res.duplicates += 1
            continue
        seen.add(fp)
        res.unique.append(cfg)
        res.by_protocol[cfg.protocol] = res.by_protocol.get(cfg.protocol, 0) + 1
    return res
