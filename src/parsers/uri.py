"""Парсеры URI-форматов: vless, vmess/v2ray, trojan, ss, hysteria2(hy2), socks5, http, tuic, MTProto.

Вход — строка подписки (один URI). Выход — VpnConfig или ParseError.
Реальные подписки содержат грязные данные: HTML-эскейп '&amp;', пустые значения
параметров, мусорные параметры (nonce/seq/__rand/Telegram=...), битый SNI — всё обрабатывается.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from ..models.config import (
    KNOWN_SS_METHODS,
    VALID_SECURITY,
    VpnConfig,
    _valid_hostname,
    _valid_port,
)


class ParseError(Exception):
    """Конфиг выглядит как URI, но бит/некорректен."""


SCHEMES = (
    "vless://", "vmess://", "v2ray://", "trojan://", "ss://", "ssr://",
    "hysteria2://", "hy2://", "socks5://", "socks://", "tuic://",
    "http://", "https://", "tg://",
)

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


# --------------------------------------------------------------------- helpers
def _clean(s: Optional[str]) -> str:
    return (s or "").strip()


def _sanitize_name(name: str) -> str:
    name = re.sub(r"[\x00-\x1f\x7f]", "", name or "")
    return name.strip()[:200]


def _b64decode(s: str) -> bytes:
    s = s.strip().replace("\n", "").replace(" ", "")
    pad = (-len(s)) % 4
    for variant in (s, s + "=" * pad):
        try:
            return base64.b64decode(variant, validate=False)
        except (binascii.Error, ValueError):
            pass
    try:
        return base64.urlsafe_b64decode(variant)
    except (binascii.Error, ValueError):
        raise ParseError("некорректный base64")


def _parse_query(qs: str) -> Dict[str, str]:
    """parse_qsl с нижним регистром ключей (в подписках type/Type/type смешаны)."""
    out: Dict[str, str] = {}
    for k, v in parse_qsl(qs, keep_blank_values=True):
        out.setdefault(k.strip().lower(), unquote(v))
    return out


def _map_network(t: str, header_type: str = "") -> str:
    t = (t or "").strip().lower()
    h = (header_type or "").strip().lower()
    if t in ("", "tcp", "raw", "none"):
        if h == "websocket":
            return "ws"
        if h == "grpc":
            return "grpc"
        if h in ("http",):
            return "http"
        return "tcp"
    if t in ("ws", "websocket"):
        return "ws"
    if t in ("grpc",):
        return "grpc"
    if t in ("http", "xhttp", "splithttp"):
        return "http"
    if t in ("kcp",):
        return "kcp"
    if t in ("h2",):
        return "h2"
    return t  # неизвестный транспорт — останется как есть, xray отклонит


def _map_security(s: str) -> str:
    s = (s or "").strip().lower()
    if s in ("", "none", "off", "false", "no", "0", "auto"):
        # 'auto' трактуем как none: если TLS реально нужен, проверка xray
        # просто не пройдёт, а в whitelist-подписку конфиг попадёт
        return "none"
    if s in ("tls", "xtls"):
        return "tls"
    if s == "reality":
        return "reality"
    return s  # неизвестное — валидация отметит


def _parse_alpn(s: str) -> List[str]:
    if not s:
        return []
    if "://" in s:  # иногда alpn=стек-текст-мусор
        return []
    parts = [p.strip() for p in s.split(",") if p.strip()]
    return [p for p in parts if "/" in p or p in ("h2", "http/1.1", "http", "2")][:4]


def _host_from_netloc(netloc: str) -> Tuple[str, Optional[int]]:
    """netloc вида [user:pass@]host:port (host может быть IP6 в []) -> (host, port|None)."""
    netloc = netloc.strip()
    # отбрасываем userinfo (uuid@ / user:pass@) — берём всё после последнего '@'
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    if netloc.startswith("["):  # [ipv6]:port
        rest = netloc[1:]
        host, _, port_s = rest.partition("]")
        port_s = port_s.lstrip(":")
    else:
        host, _, port_s = netloc.rpartition(":")
        if not host:
            host, port_s = netloc, ""
    port: Optional[int] = None
    if port_s:
        if not port_s.isdigit():
            raise ParseError(f"битый порт: {port_s!r}")
        port = int(port_s)
    host = host.strip()
    return host, port


def _finalize(cfg: VpnConfig) -> None:
    """Финальная валидация: отбрасываем битое, помечаем непроверяемое."""
    if not _valid_hostname(cfg.address):
        raise ParseError(f"некорректный адрес: {cfg.address!r}")
    if not _valid_port(cfg.port):
        raise ParseError(f"некорректный порт: {cfg.port!r}")
    if cfg.sni and not _valid_hostname(cfg.sni):
        raise ParseError(f"битый SNI: {cfg.sni!r}")
    if cfg.security not in VALID_SECURITY:
        raise ParseError(f"неизвестный security: {cfg.security!r}")

    if cfg.protocol == "vless":
        u = cfg.uuid.lower()
        if not (_UUID_RE.match(u) or re.fullmatch(r"[0-9a-f]{32}", u)):
            raise ParseError("vless: некорректный UUID")
        if cfg.security == "reality" and not cfg.pbk:
            cfg.checkable, cfg.check_reason = False, "reality без pbk"
    if cfg.protocol == "vmess":
        if not cfg.uuid or len(cfg.uuid) < 10:
            raise ParseError("vmess: некорректный id")
    if cfg.protocol == "trojan" and not cfg.password:
        raise ParseError("trojan: пустой пароль")
    if cfg.protocol == "shadowsocks":
        if cfg.method not in KNOWN_SS_METHODS:
            raise ParseError(f"shadowsocks: неизвестный метод {cfg.method!r}")
        if not cfg.password:
            raise ParseError("shadowsocks: пустой пароль")
    if cfg.protocol == "hysteria2":
        if not cfg.password:
            raise ParseError("hysteria2: пустой пароль")
    if cfg.flow and cfg.security == "none":
        cfg.checkable, cfg.check_reason = False, "flow требует tls/reality"
    if cfg.network == "grpc" and not cfg.service_name:
        cfg.checkable, cfg.check_reason = False, "grpc без serviceName"
    if cfg.network not in ("tcp", "ws", "grpc", "http"):
        cfg.checkable, cfg.check_reason = False, f"транспорт не поддерживается: {cfg.network}"


# ------------------------------------------------------------------ vless/trojan
def _parse_generic(raw: str, proto: str) -> VpnConfig:
    s = urlsplit(raw)
    host, port = _host_from_netloc(s.netloc)
    q = _parse_query(s.query)
    net = _map_network(q.get("type", ""), q.get("headertype", "") or q.get("header_type", ""))
    sec = _map_security(q.get("security", ""))
    cfg = VpnConfig(
        protocol=proto,
        address=host,
        port=port if port is not None else 0,
        name=_sanitize_name(unquote(s.fragment)),
        raw=raw,
        network=net,
        security=sec,
        sni=_clean(q.get("sni") or q.get("peer")),
        host=_clean(q.get("host")),
        path=_clean(q.get("path")),
        fp=_clean(q.get("fp") or q.get("fingerprint")),
        alpn=_parse_alpn(q.get("alpn", "")),
        flow=_clean(q.get("flow")),
        service_name=_clean(q.get("servicename") or q.get("serviceName") or ""),
        pbk=_clean(q.get("pbk")),
        sid=_clean(q.get("sid")),
        spx=_clean(q.get("spx")),
    )
    cfg.service_name = _clean(q.get("servicename")) or cfg.service_name
    mode = (q.get("mode") or "").lower()
    if mode == "multi":
        cfg.extra["multi_mode"] = True
    if proto == "vless":
        cfg.uuid = _clean(unquote(s.username or ""))
        enc = (q.get("encryption") or "none").lower()
        cfg.encryption = enc if enc in ("none", "aes-128-gcm", "chacha20-poly1305") else "none"
    else:  # trojan
        cfg.password = _clean(unquote(s.password or s.username or ""))
    _finalize(cfg)
    return cfg


# ---------------------------------------------------------------------- vmess
def _parse_vmess(raw: str) -> VpnConfig:
    body = raw.split("://", 1)[1]
    # имя может идти после base64 через '#'
    name = ""
    if "#" in body:
        body, frag = body.split("#", 1)
        name = _sanitize_name(unquote(frag))
    data: Dict[str, Any]
    try:
        data = json.loads(_b64decode(body))
    except (ParseError, json.JSONDecodeError) as e:
        raise ParseError(f"vmess: не base64-json ({e})")
    if not isinstance(data, dict):
        raise ParseError("vmess: JSON не объект")

    addr = _clean(str(data.get("add") or data.get("address") or ""))
    port_raw = data.get("port") or data.get("portstr") or 0
    try:
        port = int(str(port_raw).strip())
    except (TypeError, ValueError):
        raise ParseError("vmess: некорректный порт")

    net = _map_network(_clean(str(data.get("net") or data.get("network") or "")),
                       _clean(str(data.get("type") or "")))
    sec = _map_security(_clean(str(data.get("tls") or "")))
    try:
        aid = int(str(data.get("aid") or 0).strip() or 0)
    except (TypeError, ValueError):
        aid = 0
    cfg = VpnConfig(
        protocol="vmess",
        address=addr,
        port=port,
        name=_sanitize_name(_clean(str(data.get("ps") or ""))) or name,
        raw=raw,
        uuid=_clean(str(data.get("id") or "")),
        alter_id=int(data.get("aid") or 0),
        method=_clean(str(data.get("scy") or "auto")),
        network=net,
        security=sec,
        sni=_clean(str(data.get("sni") or data.get("host") or "")),
        host=_clean(str(data.get("host") or "")),
        path=_clean(str(data.get("path") or "")),
        fp=_clean(str(data.get("fp") or "")),
        alpn=_parse_alpn(_clean(str(data.get("alpn") or "")) if isinstance(data.get("alpn"), str)
                         else ",".join(data.get("alpn") or [])),
        service_name=_clean(str(data.get("serviceName") or data.get("servicename") or "")),
    )
    _finalize(cfg)
    return cfg


# --------------------------------------------------------------------- shadowsocks
def _parse_ss(raw: str) -> VpnConfig:
    body = raw.split("://", 1)[1]
    frag_raw = ""
    name = ""
    if "#" in body:
        body, frag_raw = body.split("#", 1)
        name = _sanitize_name(unquote(frag_raw))

    # query-параметры в ss-URI встречаются в реальных подписках — отделяем
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)

    method = password = host = ""
    port: Optional[int] = None

    if "@" in body:
        # Вариант 1 (SIP002): ss://base64(method:password)@host:port#name
        # '@'-разделитель — последний (сам пароль может содержать '@')
        userinfo, rest = body.rsplit("@", 1)
        userinfo = unquote(userinfo)  # b64 может быть URL-эскейпнут (%3D и т.п.)
        dec = None
        if _B64_RE.match(userinfo):
            try:
                dec = _b64decode(userinfo).decode("utf-8", "replace")
            except ParseError:
                dec = None

        # Хэвстик: префикс 'ss://' ошибочно навешен на vless-конфиг
        # (uuid в userinfo + vless-параметры в query: security/pbk/sni/flow/...)
        q = _parse_query(query)
        vless_keys = {"security", "pbk", "sni", "flow", "encryption", "alpn"}
        uuid_cand = userinfo.strip() or (dec.strip() if dec else "")
        if uuid_cand and _UUID_RE.match(uuid_cand) and (vless_keys & set(q)):
            rebuilt = f"vless://{userinfo}@{rest}"
            if query:
                rebuilt += "?" + query
            if frag_raw:
                rebuilt += "#" + frag_raw
            return _parse_generic(rebuilt, "vless")

        # Хэвстик: 'ss://' навешен на vmess (b64-decode даёт JSON с "add"/"id")
        if dec and dec.lstrip().startswith("{") and '"id"' in dec:
            return _parse_vmess("vmess://" + userinfo)

        cand = dec if dec is not None else userinfo
        if ":" in cand and "@" not in cand:
            method, password = cand.split(":", 1)
            host, port = _host_from_netloc(rest)
        elif dec and ":" in dec:
            # сначала пробуем: пароль содержит '@', а host:port снаружи (rest)
            try:
                host, port = _host_from_netloc(rest)
                if not (isinstance(port, int) and 0 < port <= 65535):
                    raise ParseError("no port")
                method, password = dec.split(":", 1)
            except ParseError:
                # иначе: 'method:password@host:port' целиком внутри b64
                if "@" not in dec:
                    raise ParseError("ss: не удалось разобрать userinfo")
                mp, rest2 = dec.rsplit("@", 1)
                if ":" not in mp:
                    raise ParseError("ss: не удалось разобрать userinfo")
                method, password = mp.split(":", 1)
                host, port = _host_from_netloc(rest2)
        else:
            raise ParseError("ss: не удалось разобрать userinfo")
    else:
        # Вариант 2 (legacy): ss://base64(method:password@host:port)#name
        dec = _b64decode(body).decode("utf-8", "replace")
        # Хэвстик: 'ss://' навешен на vmess (JSON в b64)
        if dec.lstrip().startswith("{") and '"id"' in dec:
            return _parse_vmess("vmess://" + unquote(body))
        if "@" not in dec:
            raise ParseError("ss: некорректный legacy-формат")
        mp, rest = dec.rsplit("@", 1)
        if ":" not in mp:
            raise ParseError("ss: в b64 нет method:password")
        method, password = mp.split(":", 1)
        host, port = _host_from_netloc(rest)

    cfg = VpnConfig(
        protocol="shadowsocks",
        address=host,
        port=port if port is not None else 0,
        name=name,
        raw=raw,
        method=method.strip().lower(),
        password=password,
        network="tcp",
        security="none",
    )
    _finalize(cfg)
    return cfg


# ------------------------------------------------------------------ hysteria2
def _parse_hysteria2(raw: str) -> VpnConfig:
    s = urlsplit(raw)
    q = _parse_query(s.query)
    host, port = _host_from_netloc(s.netloc)
    if port is None:
        port_s = q.get("port", "")
        if port_s.isdigit():
            port = int(port_s)
    cfg = VpnConfig(
        protocol="hysteria2",
        address=host,
        port=port if port is not None else 0,
        name=_sanitize_name(unquote(s.fragment)),
        raw=raw,
        password=_clean(unquote(s.password or s.username or "")),
        sni=_clean(q.get("sni")),
        security="tls",
        network="tcp",
    )
    for k in ("upmbps", "downmbps"):
        if q.get(k):
            cfg.extra[k] = q[k]
    _finalize(cfg)
    return cfg


# ----------------------------------------------------------------- socks5 / http
def _parse_simple_proxy(raw: str, proto: str) -> VpnConfig:
    s = urlsplit(raw)
    if (s.path or "").strip("/") not in ("", "proxy"):
        raise ParseError("не похоже на прокси (есть путь)")
    host, port = _host_from_netloc(s.netloc)
    if port is None:
        raise ParseError("прокси без порта")
    cfg = VpnConfig(
        protocol=proto,
        address=host,
        port=port,
        name=_sanitize_name(unquote(s.fragment)),
        raw=raw,
        password=_clean(unquote(s.password or "")),
        network="tcp",
    )
    cfg.extra["user"] = _clean(unquote(s.username or ""))
    _finalize(cfg)
    return cfg


# ------------------------------------------------------------------- mtproto
def _parse_mtproto(raw: str) -> VpnConfig:
    s = urlsplit(raw)
    q = _parse_query(s.query)
    server = _clean(q.get("server"))
    port_s = _clean(q.get("port"))
    secret = _clean(q.get("secret"))
    if not server or not port_s.isdigit() or not secret:
        raise ParseError("mtproto: нет server/port/secret")
    cfg = VpnConfig(
        protocol="mtproto",
        address=server,
        port=int(port_s),
        name=_sanitize_name(unquote(s.fragment)) or f"mtproto {server}",
        raw=raw,
        password=secret,
        checkable=False,
        check_reason="MTProto не поддерживается xray",
    )
    _finalize(cfg)
    return cfg


# ----------------------------------------------------------------------- tuic
def _parse_tuic(raw: str) -> VpnConfig:
    s = urlsplit(raw)
    q = _parse_query(s.query)
    host, port = _host_from_netloc(s.netloc)
    cfg = VpnConfig(
        protocol="tuic",
        address=host,
        port=port if port is not None else 0,
        name=_sanitize_name(unquote(s.fragment)),
        raw=raw,
        uuid=_clean(q.get("uuid")),
        password=_clean(q.get("password")),
        sni=_clean(q.get("sni")),
        security="tls" if q.get("alpn") else "none",
        alpn=_parse_alpn(q.get("alpn", "")),
        checkable=False,
        check_reason="TUIC не поддерживается xray",
    )
    _finalize(cfg)
    return cfg


# ------------------------------------------------------------------ dispatch
def is_uri(line: str) -> bool:
    return line.startswith(SCHEMES)


def parse_uri(line: str) -> VpnConfig:
    """Один URI -> VpnConfig. ParseError — битый конфиг."""
    raw = line.strip()
    if not raw:
        raise ParseError("пустая строка")
    # HTML-эскейп '&' в некоторых подписках
    raw = raw.replace("&amp;", "&")
    low = raw.lower()
    if low.startswith("vless://"):
        return _parse_generic(raw, "vless")
    if low.startswith(("vmess://", "v2ray://")):
        return _parse_vmess(raw)
    if low.startswith("trojan://"):
        return _parse_generic(raw, "trojan")
    if low.startswith(("ss://", "ssr://")):
        return _parse_ss(raw)
    if low.startswith(("hysteria2://", "hy2://")):
        return _parse_hysteria2(raw)
    if low.startswith(("socks5://", "socks://")):
        return _parse_simple_proxy(raw, "socks5")
    if low.startswith("tuic://"):
        return _parse_tuic(raw)
    if low.startswith("tg://proxy") or (low.startswith("https://t.me/proxy") and "server=" in low):
        return _parse_mtproto(raw)
    if low.startswith(("http://", "https://")):
        return _parse_simple_proxy(raw, "http")
    raise ParseError(f"неизвестный формат: {raw[:60]!r}")
