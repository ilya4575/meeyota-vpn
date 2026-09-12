"""Парсинг подписок: определение схемы URI, протоколов, base64-блоков."""

from __future__ import annotations

from .uri import ParseError, parse_text, parse_uri

__all__ = ["ParseError", "parse_text", "parse_uri"]
