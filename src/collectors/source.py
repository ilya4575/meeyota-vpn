"""Сборка одного источника: fetch + кэш-фолбэк (защита от обнуления при сбое источника)."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import SourceSpec
from .http_client import FetchError, FetchResult, HttpClient

log = logging.getLogger("meeyota.collect")


@dataclass
class SourceResult:
    spec: SourceSpec
    ok: bool
    text: str = ""
    from_cache: bool = False
    error: str = ""
    sha256: str = ""
    fetched_at: float = 0.0
    truncated: bool = False


def _cache_path(cache_dir: Path, spec: SourceSpec) -> Path:
    return cache_dir / f"{spec.id}.json"


def _load_cache(cache_dir: Path, spec: SourceSpec, ttl_days: float) -> Optional[str]:
    p = _cache_path(cache_dir, spec)
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        age_days = (time.time() - float(d.get("fetched_at", 0))) / 86400
        if age_days > ttl_days:
            log.warning("%s: кэш старше %.1f дн. — не используется", spec.id, age_days)
            return None
        return str(d.get("text", ""))
    except (json.JSONDecodeError, OSError, ValueError) as e:
        log.warning("%s: кэш повреждён (%s)", spec.id, e)
        return None


def _save_cache(cache_dir: Path, spec: SourceSpec, res: FetchResult) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        p = _cache_path(cache_dir, spec)
        p.write_text(json.dumps({
            "id": spec.id,
            "url": spec.url,
            "fetched_at": time.time(),
            "sha256": res.sha256,
            "text": res.text,
        }, ensure_ascii=False), encoding="utf-8")
    except OSError as e:
        log.warning("%s: не удалось сохранить кэш: %s", spec.id, e)


def collect_source(spec: SourceSpec, client: HttpClient, cache_dir: Path,
                   cache_ttl_days: float = 14.0) -> SourceResult:
    """Скачать источник. При неудаче — фолбэк на последний кэш."""
    try:
        res = client.fetch(spec.url, timeout=spec.timeout, max_bytes=spec.max_bytes)
    except (FetchError, Exception) as e:  # noqa: BLE001 — источник не должен ронять пайплайн
        log.error("%s: НЕДОСТУПЕН: %s", spec.id, e)
        cached = _load_cache(cache_dir, spec, cache_ttl_days)
        if cached is not None:
            log.warning("%s: используется КЭШ (последний успешный fetch)", spec.id)
            return SourceResult(spec=spec, ok=True, text=cached, from_cache=True,
                                error=f"live failed, cache used: {e}")
        return SourceResult(spec=spec, ok=False, error=str(e))

    _save_cache(cache_dir, spec, res)
    if res.truncated:
        log.warning("%s: файл обрезан до %d байт (max_bytes)", spec.id, spec.max_bytes)
    log.info("%s: OK, %d байт, %.1fs", spec.id, res.size, res.elapsed)
    return SourceResult(spec=spec, ok=True, text=res.text, sha256=res.sha256,
                        fetched_at=time.time(), truncated=res.truncated)
