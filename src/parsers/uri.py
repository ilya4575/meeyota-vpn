"""Парсер VPN-URI (vless / vmess / trojan / ss / hysteria2)."""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
from urllib.parse import parse_qsl, unquote

from ..models.config import VpnConfig


class ParseError(ValueError):
    """Ошибка парсинга URI."""


# Поддерживаемые схемы.
SUPPORTED_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "hy2"}

# Схемы, которые Incy распознаёт, но НЕ парсит — пропускаем.
# (документация Incy: ssr://, tuic://, hysteria:// — recognized but skipped)
SKIPPED_SCHEMES = {"ssr", "tuic", "hysteria"}

ZERO_WIDTH = re.compile(r"[\ufeff\u200b-\u200f\u00a0\u2028\u2029]")
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\\-]*):(.*)$", re.S)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _strip_ws(s: str) -> str:
    return ZERO_WIDTH.sub("", s).strip()


def _clean_host(h: str) -> str:
    """Убираем IPv6-скобки, схемы, лишние символы."""
    if not h:
        return ""
    h = h.strip().strip("[]")
    return h


def _parse_int(s: str | None, default: int | None = None) -> int:
    if s is None or s == "":
        if default is None:
            raise ParseError("missing port")
        return default
    try:
        port = int(s)
    except (TypeError, ValueError) as e:
        raise ParseError(f"bad port: {s!r}") from e
    if not (1 <= port <= 65535):
        raise ParseError(f"port out of range: {port}")
    return port


def parse_query(qs: str) -> dict:
    """Парсит query-строку, раскрывая HTML-сущности (&amp; → &)."""
    qs = html.unescape(qs)
    out: dict = {}
    for k, v in parse_qsl(qs, keep_blank_values=True):
        out[k] = v
    return out


def parse_vless(uri: str, fragment: str, source_id: str) -> VpnConfig:
    body = uri.split("://", 1)[1]
    if "@" not in body:
        raise ParseError("vless without @")
    userinfo, _, rest = body.partition("@")
    uuid = userinfo.strip()
    if not UUID_RE.match(uuid):
        raise ParseError(f"vless bad uuid: {uuid!r}")
    if "?" in rest:
        hostport, _, qs = rest.partition("?")
    else:
        hostport, qs = rest, ""
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
    else:
        host, port_s = hostport, ""
    host = _clean_host(host)
    port = _parse_int(port_s)
    params = parse_query(qs)
    name = _decode_fragment(fragment)
    return VpnConfig(
        scheme="vless",
        raw=uri,
        host=host,
        port=port,
        params=params,
        fragment=fragment,
        name=name,
        protocol_data={"uuid": uuid},
        source_id=source_id,
    )


def parse_vmess(uri: str, source_id: str) -> VpnConfig:
    """vmess:// — base64 JSON."""
    body = uri.split("://", 1)[1]
    # Может быть URL-safe base64
    b64 = body.strip().replace("-", "+").replace("_", "/")
    # padding
    b64 += "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(b64).decode("utf-8", errors="replace")
    except Exception as e:
        raise ParseError(f"vmess bad base64: {e}") from e
    try:
        cfg = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ParseError(f"vmess bad json: {e}") from e
    host = _clean_host(cfg.get("add", ""))
    port = _parse_int(str(cfg.get("port", "")))
    uuid = cfg.get("id", "").strip()
    if not UUID_RE.match(uuid):
        raise ParseError(f"vmess bad uuid: {uuid!r}")
    params = {
        "security": cfg.get("tls", "") or "none",
        "type": cfg.get("type", "tcp") or "tcp",
        "host": cfg.get("host", ""),
        "path": cfg.get("path", ""),
        "sni": cfg.get("sni", "") or cfg.get("host", ""),
        "alpn": cfg.get("alpn", ""),
        "fp": cfg.get("fp", ""),
    }
    # удалить пустые
    params = {k: v for k, v in params.items() if v not in ("", None)}
    name = cfg.get("ps", "").strip() or "vmess"
    return VpnConfig(
        scheme="vmess",
        raw=uri,
        host=host,
        port=port,
        params=params,
        fragment=name,
        name=name,
        protocol_data={"uuid": uuid, "alterId": cfg.get("aid", 0)},
        source_id=source_id,
    )


def parse_trojan(uri: str, fragment: str, source_id: str) -> VpnConfig:
    body = uri.split("://", 1)[1]
    if "@" not in body:
        raise ParseError("trojan without @")
    password, _, rest = body.partition("@")
    password = unquote(password)
    if not password:
        raise ParseError("trojan empty password")
    if "?" in rest:
        hostport, _, qs = rest.partition("?")
    else:
        hostport, qs = rest, ""
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
    else:
        host, port_s = hostport, ""
    host = _clean_host(host)
    port = _parse_int(port_s)
    params = parse_query(qs)
    name = _decode_fragment(fragment)
    return VpnConfig(
        scheme="trojan",
        raw=uri,
        host=host,
        port=port,
        params=params,
        fragment=fragment,
        name=name,
        protocol_data={"password": password},
        source_id=source_id,
    )


def parse_ss(uri: str, fragment: str, source_id: str) -> VpnConfig:
    """ss:// — SIP002 (user:pass@host:port#name) ИЛИ legacy (base64(method:password)@host:port)."""
    body = uri.split("://", 1)[1]
    if "@" not in body:
        # Legacy form: ss://base64(method:password)@host:port
        # Но обычно base64 идёт целиком до @, и это legacy.
        # Современные клиенты используют SIP002.
        raise ParseError("ss without @ (only SIP002 supported)")
    userinfo, _, rest = body.partition("@")
    # userinfo может быть "method:password" в base64 (legacy) ИЛИ plain (SIP002).
    decoded = userinfo
    # Попытка декодировать как base64 (если похоже на base64)
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", userinfo):
        try:
            decoded = base64.b64decode(
                userinfo.replace("-", "+").replace("_", "/") + "=" * (-len(userinfo) % 4)
            ).decode("utf-8", errors="replace")
        except Exception:
            decoded = userinfo
    method = ""
    password = ""
    if ":" in decoded:
        method, _, password = decoded.partition(":")
    else:
        method = decoded
    if not method:
        raise ParseError("ss missing method")
    if "?" in rest:
        hostport, _, qs = rest.partition("?")
    else:
        hostport, qs = rest, ""
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
    else:
        host, port_s = hostport, ""
    host = _clean_host(host)
    port = _parse_int(port_s)
    params = parse_query(qs)
    name = _decode_fragment(fragment)
    return VpnConfig(
        scheme="ss",
        raw=uri,
        host=host,
        port=port,
        params=params,
        fragment=fragment,
        name=name,
        protocol_data={"method": method, "password": password},
        source_id=source_id,
    )


def parse_hy2(uri: str, fragment: str, source_id: str) -> VpnConfig:
    """hysteria2:// — auth@host:port?params#name"""
    body = uri.split("://", 1)[1]
    if "@" not in body:
        raise ParseError("hy2 without @")
    auth, _, rest = body.partition("@")
    auth = unquote(auth)
    if "?" in rest:
        hostport, _, qs = rest.partition("?")
    else:
        hostport, qs = rest, ""
    if ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
    else:
        host, port_s = hostport, ""
    host = _clean_host(host)
    port = _parse_int(port_s)
    params = parse_query(qs)
    name = _decode_fragment(fragment)
    return VpnConfig(
        scheme="hysteria2",
        raw=uri,
        host=host,
        port=port,
        params=params,
        fragment=fragment,
        name=name,
        protocol_data={"password": auth},
        source_id=source_id,
    )


def _decode_fragment(fragment: str) -> str:
    if not fragment:
        return ""
    try:
        return unquote(fragment)
    except Exception:
        return fragment


def parse_uri(uri: str, source_id: str = "") -> VpnConfig:
    """Главная точка входа: парсит один URI → VpnConfig.

    Поддерживаемые: vless, vmess, trojan, ss, hysteria2/hy2.
    Неподдерживаемые схемы (ssr, tuic, hysteria v1) → ParseError.
    """
    uri = _strip_ws(uri)
    if not uri:
        raise ParseError("empty uri")
    m = SCHEME_RE.match(uri)
    if not m:
        raise ParseError(f"not a URI: {uri[:80]!r}")
    scheme, _ = m.groups()
    scheme = scheme.lower()
    if scheme in SKIPPED_SCHEMES:
        raise ParseError(f"scheme {scheme!r} recognized by Incy but skipped (not parsed)")
    if scheme not in SUPPORTED_SCHEMES:
        raise ParseError(f"unsupported scheme {scheme!r}")

    # Отделяем #fragment
    if "#" in uri:
        body, _, frag = uri.partition("#")
        frag = unquote(frag)
    else:
        body, frag = uri, ""

    if scheme == "vless":
        return parse_vless(body, frag, source_id)
    if scheme == "vmess":
        return parse_vmess(body, source_id)
    if scheme == "trojan":
        return parse_trojan(body, frag, source_id)
    if scheme == "ss":
        return parse_ss(body, frag, source_id)
    if scheme in ("hysteria2", "hy2"):
        return parse_hy2(body, frag, source_id)

    raise ParseError(f"unhandled scheme {scheme!r}")


def looks_like_base64_blob(text: str) -> bool:
    """Грубая эвристика: похож ли текст на base64 без схемы."""
    text = text.strip()
    if not text or "://" in text:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_\s-]+", text)) and len(text) > 32


def decode_base64(text: str) -> str:
    """Декодирует текст из base64 (URL-safe)."""
    t = text.strip().replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    return base64.b64decode(t).decode("utf-8", errors="replace")


def parse_text(text: str, source_id: str = "") -> tuple[list, list]:
    """Парсит многострочный текст.

    Возвращает (parsed, errors):
      parsed — список VpnConfig
      errors — список (line_number, line, error_message)
    """
    parsed: list = []
    errors: list = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = _strip_ws(raw_line)
        if not line or line.startswith("#"):
            continue
        # Если вся строка base64 без URI — пытаемся декодировать
        if "://" not in line and looks_like_base64_blob(line):
            try:
                decoded = decode_base64(line)
                inner_parsed, inner_errors = parse_text(decoded, source_id)
                parsed.extend(inner_parsed)
                for e in inner_errors:
                    errors.append((i, line[:60], f"(decoded) {e[2]}"))
                continue
            except Exception:
                pass  # fall through — пробуем как обычный URI
        try:
            cfg = parse_uri(line, source_id=source_id)
            parsed.append(cfg)
        except ParseError as e:
            errors.append((i, line[:80], str(e)))
    return parsed, errors
