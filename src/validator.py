"""Структурная валидация VpnConfig."""

from __future__ import annotations

import ipaddress
import re

from .models.config import VpnConfig


class ValidationError(ValueError):
    pass


# Поля, обязательные для конкретного протокола.
_REQUIRED_PROTOCOL_DATA = {
    "vless": ["uuid"],
    "vmess": ["uuid"],
    "trojan": ["password"],
    "ss": ["method"],
    "hysteria2": ["password"],
}


def _is_valid_host(host: str) -> bool:
    if not host or len(host) > 255:
        return False
    # Доменное имя
    if re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", host, re.IGNORECASE):
        return True
    # IPv4
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        pass
    # IPv6 (без скобок после _clean_host)
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        pass
    return False


def validate(c: VpnConfig) -> VpnConfig:
    """Проверяет структуру. Бросает ValidationError на битом URI."""
    if c.scheme not in _REQUIRED_PROTOCOL_DATA:
        raise ValidationError(f"unsupported scheme {c.scheme!r}")
    if not _is_valid_host(c.host):
        raise ValidationError(f"bad host {c.host!r}")
    if not (1 <= c.port <= 65535):
        raise ValidationError(f"bad port {c.port}")
    for field_name in _REQUIRED_PROTOCOL_DATA[c.scheme]:
        v = c.protocol_data.get(field_name, "")
        if not v or (isinstance(v, str) and not v.strip()):
            raise ValidationError(f"missing {field_name}")
    return c


def validate_all(configs: list) -> tuple:
    """Возвращает (valid, errors)."""
    valid: list = []
    errors: list = []
    for c in configs:
        try:
            validate(c)
            valid.append(c)
        except ValidationError as e:
            errors.append((c, str(e)))
    return valid, errors
