"""Парсинг и нормализация VPN-URI.

Поддерживаемые протоколы (схемы URI):
    vless://, vmess://, trojan://, ss:// (shadowsocks), ssr://,
    hysteria:// (Hysteria1), hysteria2:// / hy2:// (Hysteria2),
    tuic:// (TUIC v5), socks5://

Особенности:
    * исходный URI сохраняется в поле ``raw`` без изменений;
    * в query-строке раскрываются HTML-сущности (``&amp;`` → ``&``) —
      некоторые источники публикуют «заэкранированные» конфиги;
    * допускаются IPv6-адреса в скобках, «хвостовый» слэш после порта
      и пустые значения параметров;
    * файлы целиком в base64 (или отдельные строки в base64) распознаются
      и декодируются автоматически.
"""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote

from ..models.config import VpnConfig, make_hash

__all__ = [
    "ParseError",
    "parse_uri",
    "parse_text",
    "looks_like_b64_blob",
    "decode_b64",
    "NON_SINGBOX_TRANSPORTS",
]

# ---------------------------------------------------------------------------
# Общие утилиты
# ---------------------------------------------------------------------------

ZERO_WIDTH_RE = re.compile(r"[\ufeff\u200b-\u200f\u00a0\u2028\u2029]")
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", re.S)
DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")

SCHEME_ALIASES = {
    "shadowsocks": "ss",
    "hysteria2": "hy2",
    "hy2": "hy2",
    "hysteria": "hysteria",
    "hy": "hysteria",
    "socks": "socks5",
}

TRUE_FLAGS = {"1", "true", "yes", "on", "enabled"}


class ParseError(ValueError):
    """Повреждённая или непонятная конфигурация."""


def _clean(line: str) -> str:
    return ZERO_WIDTH_RE.sub("", line or "").strip()


def decode_b64(data: str) -> bytes:
    """Base64 (стандартный или URL-safe, с любым выравниванием)."""
    s = data.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s + pad, validate=False)
    except Exception:
        return base64.urlsafe_b64decode(s + pad)


def looks_like_b64_blob(text: str) -> bool:
    """Похож ли ТЕКСТ (весь файл) на base64-представление подписки."""
    t = (text or "").strip()
    if len(t) < 100:
        return False
    if any(ch in t for ch in ":\u0000@?#\n\r\t "):
        return False
    if not B64_CHARS_RE.match(t):
        return False
    try:
        dec = decode_b64(t).decode("utf-8", "replace")
    except Exception:
        return False
    return bool(SCHEME_RE.search(dec)) and "://" in dec


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in TRUE_FLAGS


def _valid_address(addr: str) -> bool:
    a = (addr or "").strip().strip("[]").rstrip(".")
    if not a:
        return False
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        pass
    if len(a) > 253:
        return False
    return bool(DOMAIN_RE.match(a))


def _split_hostport(hostport: str) -> tuple[str, int]:
    """Разбирает 'host:port', 'host:port/', 'host:port?' (пустой query), '[::1]:443'."""
    hp = (hostport or "").strip().split("?", 1)[0].strip().rstrip("/").strip()
    if not hp:
        raise ParseError("пустой адрес сервера")
    if hp.startswith("["):
        # IPv6 в скобках: [addr]:port
        end = hp.find("]")
        if end < 0 or end + 1 >= len(hp) or hp[end + 1] != ":":
            raise ParseError(f"некорректный IPv6-адрес: {hostport!r}")
        addr = hp[1:end]
        port_s = hp[end + 2 :]
    else:
        idx = hp.rfind(":")
        if idx < 0:
            addr, port_s = hp, "443"
        else:
            addr, port_s = hp[:idx], hp[idx + 1 :]
    addr = addr.strip().rstrip(".")
    try:
        port = int(port_s)
    except (TypeError, ValueError):
        raise ParseError(f"некорректный порт: {port_s!r}")
    if not 1 <= port <= 65535:
        raise ParseError(f"порт вне диапазона 1-65535: {port}")
    if not _valid_address(addr):
        raise ParseError(f"некорректный адрес: {addr!r}")
    return addr, port


def _query(qs: str) -> dict[str, str]:
    """Query-строка → dict. Раскрывает HTML-сущности (&amp; → &).

    Обычные разделители ``&`` (не образующие сущности) html.unescape не трогает,
    поэтому применять его ко всей строке безопасно.
    """
    if not qs:
        return {}
    try:
        qs = html.unescape(qs)
    except Exception:
        pass
    out: dict[str, str] = {}
    for k, v in parse_qsl(qs, keep_blank_values=True, strict_parsing=False):
        k = k.strip()
        if k:
            out[k.lower()] = v
    return out


def _name_from(uri_tail: str, fallback: str) -> str:
    """Имя из фрагмента #name (раскодируется percent-encoding)."""
    if "#" not in uri_tail:
        return fallback
    frag = uri_tail.split("#", 1)[1]
    try:
        name = unquote(frag)
    except Exception:
        name = frag
    name = name.strip()
    return name or fallback


def _make(
    protocol: str,
    addr: str,
    port: int,
    name: str,
    raw: str,
    source_id: str,
    params: dict[str, Any],
    identity: dict[str, Any],
) -> VpnConfig:
    cfg = VpnConfig(
        protocol=protocol,
        address=addr,
        port=port,
        name=name,
        source=[source_id],
        raw=raw,
        params=params,
    )
    cfg.hash = make_hash(protocol, addr, port, identity)
    return cfg


# ---------------------------------------------------------------------------
# VLESS
# ---------------------------------------------------------------------------

_VLESS_TRANSPORTS = {"tcp", "ws", "grpc", "http", "h2", "splithttp", "xhttp", "httpupgrade"}
_TRANSPORT_ALIASES = {"raw": "tcp"}  # некоторые источники пишут type=raw вместо tcp
# транспорты, которые поддерживают xray/v2rayN/Incy, но не sing-box
# (такие конфиги попадают в whitelist, но для Wi-fi-подписки не проверяются)
NON_SINGBOX_TRANSPORTS = {"xhttp", "httpupgrade"}


def _parse_vless(rest: str, raw: str, source_id: str) -> VpnConfig:
    if "@" not in rest:
        raise ParseError("vless: отсутствует uuid")
    userinfo, _, tail = rest.partition("@")
    uuid = userinfo.strip().lower()
    if not UUID_RE.match(uuid):
        raise ParseError(f"vless: некорректный uuid: {userinfo.strip()!r}")

    tail = tail.split("#", 1)[0]
    hostport, _, query_str = tail.partition("?")
    addr, port = _split_hostport(hostport)
    q = _query(query_str)

    security = (q.get("security") or "none").strip().lower()
    security = {"off": "none", "0": "none", "false": "none", "": "none"}.get(security, security)
    if security not in ("none", "tls", "reality"):
        raise ParseError(f"vless: неизвестный security={security!r}")
    # encryption: historically 'none'; новые ядра добавляют PQ-параметры
    # (например mlkem768x25519) — сохраняем как есть, клиент решит сам.
    encryption = (q.get("encryption") or "none").strip().lower()
    transport = (q.get("type") or "tcp").strip().lower()
    transport = _TRANSPORT_ALIASES.get(transport, transport)
    if transport not in _VLESS_TRANSPORTS:
        raise ParseError(f"vless: неизвестный транспорт type={transport!r}")

    sni = (q.get("sni") or q.get("servername") or "").strip()
    pbk = (q.get("pbk") or q.get("publickey") or "").strip()
    sid = (q.get("sid") or q.get("shortid") or "").strip()
    spx = (q.get("spx") or "").strip()
    flow = (q.get("flow") or "").strip()
    if security == "none" and flow:
        flow = ""  # flow только при TLS/Reality
    if security == "reality" and not pbk:
        raise ParseError("vless: security=reality без pbk (public key)")

    path = (q.get("path") or "").strip()
    ws_host = (q.get("host") or "").strip()
    service = (q.get("servicename") or q.get("service_name") or "").strip()

    params: dict[str, Any] = {
        "uuid": uuid,
        "security": security,
        "type": transport,
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
        "flow": flow,
        "fp": (q.get("fp") or "").strip().lower(),
        "insecure": _flag(q.get("allowinsecure") or q.get("insecure")),
        "path": path,
        "host": ws_host,
        "serviceName": service,
        "alpn": _split_csv(q.get("alpn") or ""),
        "headerType": (q.get("headertype") or "").strip().lower(),
        "encryption": encryption,
    }
    identity = {
        "uuid": uuid,
        "security": security,
        "type": transport,
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
        "spx": spx,
        "flow": flow,
        "path": path,
        "host": ws_host,
        "serviceName": service,
    }
    name = _name_from(rest, f"vless {addr}:{port}")
    return _make("vless", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# VMess
# ---------------------------------------------------------------------------

_VMESS_NETS = {"tcp", "ws", "grpc", "http", "h2", "xhttp"}


def _parse_vmess(rest: str, raw: str, source_id: str) -> VpnConfig:
    payload = (rest or "").strip()
    if not payload:
        raise ParseError("vmess: пустой payload")
    try:
        obj = json.loads(decode_b64(payload).decode("utf-8", "replace"))
    except Exception as e:
        raise ParseError(f"vmess: payload не является base64(json): {e}") from e
    if not isinstance(obj, dict):
        raise ParseError("vmess: JSON payload не объект")

    addr_s = str(obj.get("add") or "").strip()
    port_raw = obj.get("port")
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        raise ParseError(f"vmess: некорректный порт: {port_raw!r}")
    if not 1 <= port <= 65535:
        raise ParseError(f"vmess: порт вне диапазона: {port}")
    if not _valid_address(addr_s):
        raise ParseError(f"vmess: некорректный адрес: {addr_s!r}")

    uuid = str(obj.get("id") or "").strip().lower()
    if not uuid:
        raise ParseError("vmess: отсутствует id (uuid)")
    try:
        aid = int(obj.get("aid") or 0)
    except (TypeError, ValueError):
        raise ParseError("vmess: некорректный aid")

    net = str(obj.get("net") or "tcp").strip().lower()
    net = _TRANSPORT_ALIASES.get(net, net)
    if net not in _VMESS_NETS:
        raise ParseError(f"vmess: неизвестный транспорт net={net!r}")
    tls = str(obj.get("tls") or "").strip().lower() == "tls"
    host = str(obj.get("host") or "").strip()
    path = str(obj.get("path") or "").strip()
    sni = str(obj.get("sni") or (host if tls else "")).strip()
    scy = str(obj.get("scy") or "auto").strip() or "auto"

    params: dict[str, Any] = {
        "uuid": uuid,
        "aid": aid,
        "scy": scy,
        "net": net,
        "tls": tls,
        "sni": sni,
        "host": host,
        "path": path,
        "type": str(obj.get("type") or "none").strip().lower(),
        "alpn": _split_csv(str(obj.get("alpn") or "")),
    }
    identity = {
        "uuid": uuid,
        "aid": aid,
        "scy": scy,
        "net": net,
        "tls": tls,
        "sni": sni,
        "host": host,
        "path": path,
    }
    name = str(obj.get("ps") or "").strip() or f"vmess {addr_s}:{port}"
    return _make("vmess", addr_s, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# Trojan
# ---------------------------------------------------------------------------

def _parse_trojan(rest: str, raw: str, source_id: str) -> VpnConfig:
    if "@" not in rest:
        raise ParseError("trojan: отсутствует пароль (user@host)")
    password, _, tail = rest.rpartition("@")
    password = unquote(password.strip())
    if not password:
        raise ParseError("trojan: пустой пароль")

    tail = tail.split("#", 1)[0]
    hostport, _, query_str = tail.partition("?")
    addr, port = _split_hostport(hostport)
    q = _query(query_str)

    transport = (q.get("type") or "tcp").strip().lower()
    transport = _TRANSPORT_ALIASES.get(transport, transport)
    if transport not in _VLESS_TRANSPORTS:
        raise ParseError(f"trojan: неизвестный транспорт type={transport!r}")
    sni = (q.get("sni") or q.get("sni_server") or "").strip()
    path = (q.get("path") or "").strip()
    ws_host = (q.get("host") or "").strip()
    service = (q.get("servicename") or "").strip()

    params: dict[str, Any] = {
        "password": password,
        "type": transport,
        "sni": sni,
        "insecure": _flag(q.get("allowinsecure") or q.get("insecure")),
        "path": path,
        "host": ws_host,
        "serviceName": service,
        "alpn": _split_csv(q.get("alpn") or ""),
        "fp": (q.get("fp") or "").strip().lower(),
    }
    identity = {
        "password": password,
        "type": transport,
        "sni": sni,
        "path": path,
        "host": ws_host,
        "serviceName": service,
    }
    name = _name_from(rest, f"trojan {addr}:{port}")
    return _make("trojan", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# Shadowsocks
# ---------------------------------------------------------------------------

def _parse_ss(rest: str, raw: str, source_id: str) -> VpnConfig:
    rest = (rest or "").strip()
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)

    if "@" in rest:
        # ss://base64(method:password)@host:port#name
        userinfo, _, hostport = rest.partition("@")
        try:
            creds = decode_b64(userinfo).decode("utf-8", "replace")
        except Exception as e:
            raise ParseError(f"ss: userinfo не base64: {e}") from e
        if ":" not in creds:
            raise ParseError("ss: ожидается method:password")
        method, password = creds.split(":", 1)
    else:
        # ss://base64(method:password@host:port)#name
        try:
            decoded = decode_b64(rest).decode("utf-8", "replace")
        except Exception as e:
            raise ParseError(f"ss: payload не base64: {e}") from e
        if "@" not in decoded:
            raise ParseError("ss: ожидается method:password@host:port")
        creds, _, hostport = decoded.rpartition("@")
        if ":" not in creds:
            raise ParseError("ss: ожидается method:password")
        method, password = creds.split(":", 1)

    method = method.strip()
    if not method:
        raise ParseError("ss: пустой method")
    addr, port = _split_hostport(hostport)

    params: dict[str, Any] = {"method": method, "password": password}
    identity = {"method": method, "password": password}
    name = _name_from(f"placeholder#{frag}", f"ss {addr}:{port}") if frag else f"ss {addr}:{port}"
    return _make("ss", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# ShadowsocksR
# ---------------------------------------------------------------------------

def _parse_ssr(rest: str, raw: str, source_id: str) -> VpnConfig:
    try:
        payload = decode_b64((rest or "").strip()).decode("utf-8", "replace")
    except Exception as e:
        raise ParseError(f"ssr: payload не base64: {e}") from e
    parts = payload.split(":")
    if len(parts) != 6:
        raise ParseError(f"ssr: ожидается 6 полей, получено {len(parts)}")
    method, password, proto, cipher, obfs, b64_params = parts
    if not method or not cipher:
        raise ParseError("ssr: пустой method/cipher")
    try:
        inner = decode_b64(b64_params).decode("utf-8", "replace")
    except Exception:
        inner = ""
    p = dict(parse_qsl(inner, keep_blank_values=True))
    addr_s = (p.get("addr") or "").strip()
    try:
        port = int(p.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not addr_s or not 1 <= port <= 65535:
        raise ParseError("ssr: отсутствуют addr/port")
    if not _valid_address(addr_s):
        raise ParseError(f"ssr: некорректный адрес: {addr_s!r}")

    params: dict[str, Any] = {
        "method": method,
        "password": password,
        "protocol": proto,
        "cipher": cipher,
        "obfs": obfs,
        "obfsparam": p.get("obfsparam") or "",
        "protoparam": p.get("protoparam") or "",
    }
    identity = {
        "method": method,
        "password": password,
        "protocol": proto,
        "cipher": cipher,
        "obfs": obfs,
    }
    name = (p.get("remarks") or "").strip() or f"ssr {addr_s}:{port}"
    return _make("ssr", addr_s, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# Hysteria / Hysteria2
# ---------------------------------------------------------------------------

def _parse_hysteria2(rest: str, raw: str, source_id: str) -> VpnConfig:
    if "@" not in rest:
        raise ParseError("hysteria2: отсутствует пароль (password@host)")
    password, _, tail = rest.rpartition("@")
    password = unquote(password.strip())
    tail = tail.split("#", 1)[0]
    hostport, _, query_str = tail.partition("?")
    addr, port = _split_hostport(hostport)
    q = _query(query_str)

    if not password and not q.get("auth"):
        raise ParseError("hysteria2: пустой пароль (и нет auth)")
    sni = (q.get("sni") or "").strip()
    pin = (q.get("pinsha256") or "").strip()

    params: dict[str, Any] = {
        "password": password,
        "auth": (q.get("auth") or "").strip(),
        "sni": sni,
        "pinsha256": pin,
        "insecure": _flag(q.get("insecure") or q.get("allowinsecure")),
        "obfs": (q.get("obfs") or "").strip().lower(),
        "obfsPassword": (q.get("obfs-password") or q.get("obfs_password") or "").strip(),
        "mport": (q.get("mport") or "").strip(),
        "alpn": _split_csv(q.get("alpn") or ""),
    }
    identity = {
        "password": password,
        "auth": params["auth"],
        "sni": sni,
        "pinsha256": pin,
        "obfs": params["obfs"],
        "obfsPassword": params["obfsPassword"],
    }
    name = _name_from(rest, f"hysteria2 {addr}:{port}")
    return _make("hysteria2", addr, port, name, raw, source_id, params, identity)


def _parse_hysteria1(rest: str, raw: str, source_id: str) -> VpnConfig:
    if "@" not in rest:
        raise ParseError("hysteria: отсутствует пользователь/пароль")
    userinfo, _, tail = rest.partition("@")
    tail = tail.split("#", 1)[0]
    hostport, _, query_str = tail.partition("?")
    addr, port = _split_hostport(hostport)
    q = _query(query_str)

    if ":" in userinfo:
        user, _, password = userinfo.partition(":")
    else:
        user, password = userinfo, ""
    sni = (q.get("sni") or q.get("sni_server") or "").strip()
    pin = (q.get("pinsha256") or "").strip()

    params: dict[str, Any] = {
        "user": unquote(user.strip()),
        "password": unquote(password.strip()),
        "sni": sni,
        "pinsha256": pin,
        "insecure": _flag(q.get("insecure") or q.get("allowinsecure")),
        "obfs": (q.get("obfs") or "").strip().lower(),
        "obfsPassword": (q.get("obfs-password") or q.get("obfs_password") or "").strip(),
        "alpn": _split_csv(q.get("alpn") or ""),
    }
    identity = {
        "user": params["user"],
        "password": params["password"],
        "sni": sni,
        "pinsha256": pin,
        "obfs": params["obfs"],
        "obfsPassword": params["obfsPassword"],
    }
    name = _name_from(rest, f"hysteria {addr}:{port}")
    return _make("hysteria", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# TUIC
# ---------------------------------------------------------------------------

def _parse_tuic(rest: str, raw: str, source_id: str) -> VpnConfig:
    if "@" not in rest:
        raise ParseError("tuic: отсутствует uuid")
    userinfo, _, tail = rest.partition("@")
    tail = tail.split("#", 1)[0]
    hostport, _, query_str = tail.partition("?")
    addr, port = _split_hostport(hostport)
    q = _query(query_str)

    if ":" in userinfo:
        uuid, _, password = userinfo.partition(":")
    else:
        uuid, password = userinfo, ""
    uuid = unquote(uuid.strip().lower())
    password = unquote(password.strip())
    if not UUID_RE.match(uuid):
        raise ParseError(f"tuic: некорректный uuid: {uuid!r}")

    sni = (q.get("sni") or q.get("sni_server") or "").strip()
    cc = (q.get("congestion_control") or q.get("cc") or "bbr").strip().lower()
    if cc not in ("bbr", "cubic", "fast"):
        cc = "bbr"

    params: dict[str, Any] = {
        "uuid": uuid,
        "password": password,
        "sni": sni,
        "alpn": _split_csv(q.get("alpn") or ""),
        "congestion_control": cc,
        "insecure": _flag(q.get("allow_insecure") or q.get("insecure") or q.get("allowinsecure")),
    }
    identity = {"uuid": uuid, "password": password, "sni": sni, "alpn": params["alpn"]}
    name = _name_from(rest, f"tuic {addr}:{port}")
    return _make("tuic", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# SOCKS5
# ---------------------------------------------------------------------------

def _parse_socks5(rest: str, raw: str, source_id: str) -> VpnConfig:
    rest = rest.split("#", 1)[0]
    tail = rest
    user = password = ""
    if "@" in rest:
        userinfo, _, tail = rest.rpartition("@")
        if ":" in userinfo:
            user, _, password = userinfo.partition(":")
        else:
            user = userinfo
    addr, port = _split_hostport(tail)

    params: dict[str, Any] = {
        "username": unquote(user.strip()),
        "password": unquote(password.strip()),
    }
    identity = {"username": params["username"], "password": params["password"]}
    name = f"socks5 {addr}:{port}"
    return _make("socks5", addr, port, name, raw, source_id, params, identity)


# ---------------------------------------------------------------------------
# Диспетчер
# ---------------------------------------------------------------------------

_HANDLERS = {
    "vless": _parse_vless,
    "vmess": _parse_vmess,
    "trojan": _parse_trojan,
    "ss": _parse_ss,
    "ssr": _parse_ssr,
    "hy2": _parse_hysteria2,
    "hysteria2": _parse_hysteria2,
    "hysteria": _parse_hysteria1,
    "hy": _parse_hysteria1,
    "tuic": _parse_tuic,
    "socks5": _parse_socks5,
}


def parse_uri(line: str, source_id: str) -> VpnConfig:
    """Разбирает одну строку подписки в VpnConfig.

    :raises ParseError: если конфигурация повреждена или не поддерживается.
    """
    line = _clean(line)
    if not line:
        raise ParseError("пустая строка")
    m = SCHEME_RE.match(line)
    if not m:
        raise ParseError(f"нет схемы URI: {line[:60]!r}")
    scheme = m.group(1).lower()
    scheme = SCHEME_ALIASES.get(scheme, scheme)
    handler = _HANDLERS.get(scheme)
    if handler is None:
        raise ParseError(f"неподдерживаемый протокол: {m.group(1)!r}")
    rest = m.group(2)
    if rest.startswith("//"):
        rest = rest[2:]
    return handler(rest, line, source_id)


def parse_text(text: str, source_id: str) -> tuple[list[VpnConfig], int]:
    """Разбирает содержимое файла подписки.

    :return: (список валидных конфигов, количество битых строк)
    """
    decoded = _decode_container(text)
    configs: list[VpnConfig] = []
    invalid = 0
    for raw_line in decoded.splitlines():
        line = _clean(raw_line)
        if not line or line.startswith("#"):
            continue
        try:
            configs.append(parse_uri(line, source_id))
        except ParseError:
            invalid += 1
    return configs, invalid


def _decode_container(text: str) -> str:
    """Распаковка base64: весь файл одним блоком или base64-строки построчно."""
    if looks_like_b64_blob(text):
        try:
            return decode_b64(text).decode("utf-8", "replace")
        except Exception:
            return text
    out: list[str] = []
    for line in text.splitlines():
        stripped = _clean(line)
        if not stripped or stripped.startswith("#"):
            out.append(line)
            continue
        if (
            not SCHEME_RE.match(stripped)
            and len(stripped) > 20
            and B64_CHARS_RE.match(stripped)
            and not any(ch in stripped for ch in " \t")
        ):
            try:
                dec = decode_b64(stripped).decode("utf-8", "replace")
                if SCHEME_RE.match(dec) and "://" in dec:
                    out.append(dec)
                    continue
            except Exception:
                pass
        out.append(line)
    return "\n".join(out)
