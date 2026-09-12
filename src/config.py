"""Загрузка конфигурации: sources.yaml + параметры запуска."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass
class SourceSpec:
    id: str
    name: str
    url: str
    enabled: bool = True
    timeout: float = 30.0
    retries: int = 3
    retry_delay: float = 5.0
    max_bytes: int = 25_000_000
    note: str = ""


DEFAULT_SOURCES: Dict[str, Any] = {
    "timeout": 30,
    "retries": 3,
    "retry_delay": 5,
    "max_bytes": 25_000_000,
    "user_agent": "meeyota-vpn-aggregator/1.0 (GitHub Actions)",
    "cache_ttl_days": 14,
}


def load_sources(path: Path) -> List[SourceSpec]:
    """sources.yaml -> список SourceSpec. Ошибка формата -> ValueError."""
    raw: Any = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if isinstance(raw, list):  # допустим формат «сразу список источников»
        raw = {"sources": raw}
    if not isinstance(raw, dict):
        raise ValueError("sources.yaml: ожидается объект")
    defaults = {**DEFAULT_SOURCES, **(raw.get("defaults") or {})}
    entries = raw.get("sources") or []
    if not isinstance(entries, list) or not entries:
        raise ValueError("sources.yaml: пустой раздел 'sources'")

    specs: List[SourceSpec] = []
    seen = set()
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise ValueError(f"sources.yaml: источник #{i} не объект")
        url = str(e.get("url") or "").strip()
        if not url:
            raise ValueError(f"sources.yaml: источник #{i} без 'url'")
        sid = str(e.get("id") or f"source-{i}").strip()
        if sid in seen:
            raise ValueError(f"sources.yaml: дублирующийся id '{sid}'")
        seen.add(sid)
        specs.append(SourceSpec(
            id=sid,
            name=str(e.get("name") or sid).strip(),
            url=url,
            enabled=bool(e.get("enabled", True)),
            timeout=float(e.get("timeout", defaults["timeout"])),
            retries=int(e.get("retries", defaults["retries"])),
            retry_delay=float(e.get("retry_delay", defaults["retry_delay"])),
            max_bytes=int(e.get("max_bytes", defaults["max_bytes"])),
            note=str(e.get("note") or ""),
        ))
    return specs


@dataclass
class Settings:
    sources_path: Path = Path("sources.yaml")
    data_dir: Path = Path("data")
    output_dir: Path = Path("output")
    readme_path: Path = Path("README.md")

    whitelist_file: str = "vpn-whitelist-meeyota.txt"
    wifi_file: str = "vpn-wifi-meeyota.txt"

    skip_checks: bool = False
    recheck_all: bool = False
    max_checks: int = 400
    workers: int = 5
    check_ttl_hours: float = 24.0
    check_timeout_s: float = 45.0

    xray_bin_dir: Path = Path("data/bin")

    # защита от обнуления
    min_keep_ratio: float = 0.30   # новый whitelist < 30% от прежнего -> abort
    min_keep_abs: int = 10
    dry_run: bool = False

    username: str = ""   # для incy://add/... (пусто -> USERNAME/REPOSITORY плейсхолдеры)
    repository: str = ""

    extra: Dict[str, Any] = field(default_factory=dict)
