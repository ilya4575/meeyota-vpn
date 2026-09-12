"""Скачивание файлов источников (GitHub raw с API-fallback и произвольные URL)."""

from __future__ import annotations

from .github import Collector, SourceError, SourceNotFound, SourceTooLarge

__all__ = ["Collector", "SourceError", "SourceNotFound", "SourceTooLarge"]
