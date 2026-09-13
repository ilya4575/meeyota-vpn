"""VpnConfig — нормализованное представление одной VPN-конфигурации."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class VpnConfig:
    """Нормализованное представление одной VPN-конфигурации."""

    scheme: str
    raw: str
    host: str
    port: int
    params: dict
    fragment: str
    name: str
    protocol_data: dict = field(default_factory=dict)
    source_id: str = ""

    def make_hash(self) -> str:
        """Канонический хеш для дедупликации.

        Сравниваются только семантически значимые поля. Не учитываются:
        - Telegram=, fm=, _t=, descriptions=, fp в разных регистрах;
        - query-порядок параметров;
        - фрагмент (имя сервера).
        """
        keys = (
            "sni",
            "host",
            "path",
            "serviceName",
            "type",
            "alpn",
            "pbk",
            "sid",
            "fp",
            "method",
            "password",
            "encryption",
            "flow",
            "security",
            "network",
            "headerType",
            "allowInsecure",
            "insecure",
            "mode",
            "packetEncoding",
            "packet-encoding",
            "spx",
            "authority",
        )
        params_subset = sorted(
            f"{k}={self.params.get(k, self.protocol_data.get(k, ''))}" for k in keys
        )
        critical = "|".join(
            (
                self.scheme.lower(),
                self.host.lower(),
                str(self.port),
                str(self.params.get("security", "")),
                str(self.params.get("type", "")),
                str(self.protocol_data.get("uuid", "")),
                str(self.protocol_data.get("password", "")),
                str(self.protocol_data.get("method", "")),
            )
            + tuple(params_subset)
        )
        return hashlib.sha256(critical.encode("utf-8")).hexdigest()


def make_hash(c: VpnConfig) -> str:
    """Удобная функция-хелпер."""
    return c.make_hash()
