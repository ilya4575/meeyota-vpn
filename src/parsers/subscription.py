"""Разбор содержимого подписки: текст файла -> список URI-строк.

Учитывает реальные особенности источников:
- целое содержимое может быть base64 (один блок) — декодируем;
- строки-комментарии '#' (profile-title, announce, ...);
- HTML-эскейп '&amp;' (частично, полный разбор в uri.parse_uri);
- в строке может быть несколько URI, разделённых пробелом.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import List

from .uri import is_uri

_B64_BLOCK_RE = re.compile(r"^[A-Za-z0-9+/=\r\n\s]+$")
_SCHEME_HINTS = (b"vless://", b"vmess://", b"trojan://", b"ss://", b"hysteria2://",
                 b"hy2://", b"socks5://", b"tuic://", b"http://", b"v2ray://", b"tg://")
# в отдельных подписках URI в строке склеены БЕЗ разделителей:
# '...:443#@v2rayng3ss://...' — ищем все начала scheme:// (поиск слева-направо,
# без перекрытия: 'ss://' внутри 'vless://' не даёт отдельного совпадения)
_SCHEME_START_RE = re.compile(
    r"(?:hysteria2|vless|vmess|v2ray|trojan|socks5|socks|hy2|tuic|https|http|ssr|ss|tg)://")


def _try_decode_base64(text: str) -> str:
    """Если весь текст — один base64-блок с URI внутри, вернуть декодированное."""
    stripped = text.strip()
    if len(stripped) < 64:
        return text
    if stripped.count("\n") > 4:  # допускаем немного переносов (wrapped base64)
        return text
    if not _B64_BLOCK_RE.match(stripped):
        return text
    compact = re.sub(r"\s+", "", stripped)
    try:
        decoded = base64.b64decode(compact + "=" * ((-len(compact)) % 4)).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return text
    blob = decoded.encode("utf-8", "replace")
    if any(h in blob for h in _SCHEME_HINTS):
        return decoded
    return text


def extract_uris(text: str) -> List[str]:
    """Текст подписки -> список «чистых» URI-строк (по одному URI в строке)."""
    if not text:
        return []
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    text = _try_decode_base64(text)

    out: List[str] = []
    for line in text.split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # позиции начал всех URI в строке (слева-направо, без перекрытия)
        starts = [m.start() for m in _SCHEME_START_RE.finditer(s)]
        if not starts:
            continue
        for i, st in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else len(s)
            p = s[st:end].strip()
            if p:
                out.append(p)
    return out


@dataclass
class ParseStats:
    lines: int = 0
    uris: int = 0
    parsed: int = 0
    invalid: int = 0
    errors: List[str] = field(default_factory=list)
