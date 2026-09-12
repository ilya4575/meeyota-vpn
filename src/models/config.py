"""Модель VPN-конфигурации: нормализация, fingerprint, экспорт в xray-JSON."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Поддерживаемые методы Shadowsocks (иначе конфиг считается битым)
KNOWN_SS_METHODS = {
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf", "chacha20-ietf-poly1305",
    "chacha20-poly1305", "chacha20",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "salsa20", "rc4", "rc4-md5",
}

VALID_FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "qq", "360", "random"}
VALID_SECURITY = {"none", "tls", "reality"}


def _valid_hostname(name: str) -> bool:
    """SNI/hostname: нет пробелов, '/', '@', скобок — т.е. вменяемое имя."""
    if not name or len(name) > 253:
        return False
    if any(ch.isspace() for ch in name):
        return False
    if "/" in name or "@" in name or "\\" in name or "(" in name or ")" in name:
        return False
    if name.startswith(("%", ",")):
        return False
    return True


def _valid_port(port: Optional[int]) -> bool:
    return isinstance(port, int) and 0 < port <= 65535


@dataclass
class VpnConfig:
    protocol: str                 # vless | vmess | trojan | shadowsocks | hysteria2 | socks5 | http | mtproto | tuic
    address: str                  # IP или домен
    port: int
    name: str = ""
    source: str = ""              # id/имя источника (sources.yaml)
    raw: str = ""                 # оригинальный URI — сохраняется и публикуется как есть

    # учётные данные / шифрование
    uuid: str = ""                # vless/vmess/tuic
    password: str = ""            # trojan/ss/hy2/socks/http/mtproto
    method: str = ""              # shadowsocks cipher
    alter_id: int = 0             # vmess
    encryption: str = "none"      # vless encryption (обычно none)

    # транспорт
    network: str = "tcp"          # tcp | ws | grpc | http | kcp | h2
    security: str = "none"        # none | tls | reality
    sni: str = ""
    host: str = ""                # ws/grpc Host-заголовок
    path: str = ""
    fp: str = ""                  # TLS fingerprint
    alpn: List[str] = field(default_factory=list)
    flow: str = ""                # vless/trojan (xtls-rprx-vision и т.п.)
    service_name: str = ""        # grpc

    # reality
    pbk: str = ""                 # publicKey
    sid: str = ""                 # shortId
    spx: str = ""                 # spiderX

    # состояние проверки (заполняется checks/)
    last_check: Optional[str] = None
    country: Optional[str] = None
    ip: Optional[str] = None

    # помечается парсером, если xray-проверку прогнать нельзя
    checkable: bool = True
    check_reason: str = ""        # причина, почему не проверяем

    extra: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ utils
    @property
    def hash(self) -> str:
        return hashlib.sha256(self.raw.encode("utf-8", "replace")).hexdigest()

    @property
    def fingerprint(self) -> str:
        """Ключ дедупликации: сервер + учётные данные + транспорт (без «косметики»: fp, junk-параметры)."""
        a = self.address.lower().strip(".")
        p = int(self.port or 0)
        proto = self.protocol
        if proto == "vless":
            return f"vless|{a}:{p}|{self.uuid.lower()}|{self.network}|{self.flow}|{self.sni.lower()}"
        if proto == "vmess":
            return f"vmess|{a}:{p}|{self.uuid.lower()}|{self.alter_id}|{self.network}|{self.sni.lower()}"
        if proto == "trojan":
            return f"trojan|{a}:{p}|{self.password}|{self.network}|{self.sni.lower()}"
        if proto == "shadowsocks":
            return f"ss|{a}:{p}|{self.method}|{self.password}"
        if proto == "hysteria2":
            return f"hy2|{a}:{p}|{self.password}|{self.sni.lower()}"
        if proto in ("socks5", "http"):
            return f"{proto}|{a}:{p}|{self.extra.get('user', '')}|{self.password}"
        if proto == "mtproto":
            return f"mtproto|{a}:{p}|{self.password}"
        if proto == "tuic":
            return f"tuic|{a}:{p}|{self.uuid.lower()}|{self.password}"
        return f"{proto}|{a}:{p}|{self.uuid}|{self.password}"

    # ------------------------------------------------------------------ запись
    def to_record(self) -> Dict[str, Any]:
        """Каноническая запись для data/configs.json (схема из ТЗ)."""
        return {
            "protocol": self.protocol,
            "address": self.address,
            "port": self.port,
            "name": self.name,
            "source": self.source,
            "raw": self.raw,
            "hash": self.hash,
            "last_check": self.last_check,
            "country": self.country,
            "ip": self.ip,
            "fingerprint": self.fingerprint,
        }

    # --------------------------------------------------------------- xray JSON
    def _stream_settings(self) -> Dict[str, Any]:
        st: Dict[str, Any] = {"network": self.network}
        sec = self.security or "none"
        if sec == "tls":
            tls: Dict[str, Any] = {"allowInsecure": True}
            if _valid_hostname(self.sni):
                tls["serverName"] = self.sni
            if self.alpn:
                tls["alpn"] = self.alpn
            if self.fp in VALID_FINGERPRINTS:
                tls["fingerprint"] = self.fp
            st["security"] = "tls"
            st["tlsSettings"] = tls
        elif sec == "reality":
            r: Dict[str, Any] = {"show": False, "xver": 0}
            if _valid_hostname(self.sni):
                r["serverName"] = self.sni
            if self.fp in VALID_FINGERPRINTS:
                r["fingerprint"] = self.fp
            if self.pbk:
                r["publicKey"] = self.pbk
            if self.sid:
                r["shortId"] = self.sid
            if self.spx:
                r["spiderX"] = self.spx
            st["security"] = "reality"
            st["realitySettings"] = r
        else:
            st["security"] = "none"

        if self.network == "ws":
            ws: Dict[str, Any] = {"path": self.path or "/"}
            if self.host:
                ws["headers"] = {"Host": self.host}
            st["wsSettings"] = ws
        elif self.network == "grpc":
            st["grpcSettings"] = {
                "serviceName": self.service_name or "vless",
                "multiMode": bool(self.extra.get("multi_mode")),
            }
        elif self.network == "http":
            http: Dict[str, Any] = {"method": "GET", "path": self.path or "/", "upgrade": True}
            if self.host:
                http["host"] = self.host
            st["httpSettings"] = http
        return st

    def to_xray_outbound(self) -> Optional[Dict[str, Any]]:
        """Возвращает JSON outbound для Xray-core (для проверки внешнего IP).
        None — если конфиг нельзя проверить через xray."""
        if not self.checkable:
            return None
        a = self.address
        p = self.port
        if self.protocol == "vless":
            user = {"id": self.uuid, "encryption": self.encryption or "none"}
            if self.flow:
                user["flow"] = self.flow
            out = {
                "protocol": "vless",
                "tag": "vpn",
                "settings": {"vnext": [{"address": a, "port": p, "users": [user]}]},
                "streamSettings": self._stream_settings(),
            }
            if self.network == "grpc" and not self.service_name:
                return None
            return out
        if self.protocol == "vmess":
            user = {"id": self.uuid, "alterId": self.alter_id,
                    "security": self.method or "auto", "encryption": "auto"}
            out = {
                "protocol": "vmess",
                "tag": "vpn",
                "settings": {"vnext": [{"address": a, "port": p, "users": [user]}]},
                "streamSettings": self._stream_settings(),
            }
            if self.network == "grpc" and not self.service_name:
                return None
            return out
        if self.protocol == "trojan":
            srv: Dict[str, Any] = {"address": a, "port": p, "password": self.password}
            if self.flow:
                srv["flow"] = self.flow
            return {
                "protocol": "trojan",
                "tag": "vpn",
                "settings": {"servers": [srv]},
                "streamSettings": self._stream_settings(),
            }
        if self.protocol == "shadowsocks":
            return {
                "protocol": "shadowsocks",
                "tag": "vpn",
                "settings": {"servers": [{"address": a, "port": p,
                                          "method": self.method,
                                          "password": self.password,
                                          "uot": False}]},
            }
        if self.protocol == "hysteria2":
            srv = {"address": a, "port": p, "password": self.password}
            st: Dict[str, Any] = {"security": "tls"}
            tls: Dict[str, Any] = {"allowInsecure": True}
            if _valid_hostname(self.sni):
                tls["serverName"] = self.sni
            st["tlsSettings"] = tls
            return {
                "protocol": "hysteria2",
                "tag": "vpn",
                "settings": {"servers": [srv]},
                "streamSettings": st,
            }
        if self.protocol == "socks5":
            servers = [{"address": a, "port": p}]
            user = self.extra.get("user", "")
            if user or self.password:
                servers[0]["users"] = [{"user": user, "password": self.password}]
            return {"protocol": "socks", "tag": "vpn", "settings": {"servers": servers}}
        if self.protocol == "http":
            return {
                "protocol": "http",
                "tag": "vpn",
                "settings": {"servers": [{"address": a, "port": p,
                                          "username": self.extra.get("user", ""),
                                          "password": self.password}]},
            }
        return None  # mtproto/tuic — xray не поддерживает
