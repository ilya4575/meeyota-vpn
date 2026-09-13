"""Нормализация VpnConfig."""

from __future__ import annotations

import re

from .models.config import VpnConfig


_LOWERCASE_PARAMS = frozenset(
    {
        "security",
        "type",
        "network",
        "headerType",
        "flow",
        "mode",
        "alpn",
        "fp",
        "encryption",
        "packetEncoding",
        "packet-encoding",
        "allowInsecure",
        "insecure",
        "host",
        "sni",
    }
)


def normalise(c: VpnConfig) -> VpnConfig:
    """Нормализует копию конфига. Возвращает новый объект."""
    new_params: dict = {}
    for k, v in c.params.items():
        if k in _LOWERCASE_PARAMS:
            new_params[k] = v.lower() if isinstance(v, str) else v
        else:
            new_params[k] = v
    # Host — lowercased
    new_host = c.host.lower()
    # Fragment — cleaned (no double spaces, no trailing/leading)
    new_frag = re.sub(r"\s+", " ", c.fragment).strip() if c.fragment else ""
    new_name = re.sub(r"\s+", " ", c.name).strip() if c.name else ""
    return VpnConfig(
        scheme=c.scheme.lower(),
        raw=c.raw,
        host=new_host,
        port=c.port,
        params=new_params,
        fragment=new_frag,
        name=new_name,
        protocol_data=dict(c.protocol_data),
        source_id=c.source_id,
    )


def normalise_all(configs: list) -> list:
    return [normalise(c) for c in configs]
