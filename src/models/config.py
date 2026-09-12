"""Нормализованная модель VPN-конфигурации.

Каждый конфиг хранит:
    protocol  — протокол (vless, vmess, trojan, ss, ssr, hysteria2, tuic, socks5, ...)
    address   — сервер (IP или домен), нормализованный (lowercase, без точки)
    port      — порт
    name      — человекочитаемое имя
    source    — id источников, из которых найден конфиг (может быть несколько)
    raw       — ОРИГИНАЛЬНАЯ строка URI (без изменений)
    hash      — канонический SHA-256 для дедупликации
    last_check / country / ip — результат последней проверки (подписка «Wi-fi»)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


def make_hash(protocol: str, address: str, port: int, identity: dict[str, Any]) -> str:
    """Канонический хеш конфигурации.

    В хеш попадают только поля, определяющие «кто это»: сервер, порт,
    учётные данные и транспорт. Косметические параметры (fingerprint,
    allowInsecure и т.п.) в хеш не попадают.
    """
    canonical = {
        "protocol": protocol.lower(),
        "address": str(address).strip().lower().rstrip("."),
        "port": int(port),
        "identity": {k: ("" if v is None else v) for k, v in sorted(identity.items())},
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class VpnConfig:
    protocol: str
    address: str
    port: int
    name: str
    source: list[str]
    raw: str
    params: dict[str, Any] = field(default_factory=dict)
    hash: str = ""
    last_check: str | None = None
    country: str | None = None
    ip: str | None = None
    verdict: str | None = None   # ok | ru | conflict | error | None(не проверено)
    detail: str | None = None

    @property
    def server_key(self) -> str:
        """Ключ «сервер» для группировки проверок: адрес и порт."""
        return f"{self.address.lower().rstrip('.')}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        """Сериализация в схеме, требуемой спецификацией."""
        return {
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
            "name": self.name,
            "source": list(self.source),
            "raw": self.raw,
            "hash": self.hash,
            "last_check": self.last_check,
            "country": self.country,
            "ip": self.ip,
        }
