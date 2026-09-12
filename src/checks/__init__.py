"""Проверки конфигураций для подписки «VPN Wi-fi meeyota»:
реальное соединение + геолокация внешнего IPv4/IPv6."""

from __future__ import annotations

from .connectivity import UnsupportedProtocol, build_singbox_config, probe_config
from .geolocation import GeoLookup
from .verifier import CheckResults, check_stats_dict, group_configs, verify

__all__ = [
    "UnsupportedProtocol",
    "build_singbox_config",
    "probe_config",
    "GeoLookup",
    "CheckResults",
    "check_stats_dict",
    "group_configs",
    "verify",
]
