"""Загрузка и валидация sources.yaml."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SourceFile:
    path: str
    max_size_mb: int | None = None


@dataclass
class Source:
    id: str
    name: str
    type: str  # 'github' | 'url'
    repo: str = ""
    branch: str = "main"
    files: list = field(default_factory=list)


@dataclass
class Settings:
    timeout: int = 30
    retries: int = 3
    backoff: float = 2.0
    max_file_size_mb: int = 25
    use_api_fallback: bool = True
    cache_dir: str = "data/cache"


@dataclass
class Pages:
    username: str = "ilya4575"
    repository: str = "meeyota-vpn"


@dataclass
class Safety:
    min_configs_whitelist: int = 50
    min_configs_wifi: int = 5
    max_drop_ratio: float = 0.5
    max_outbounds_whitelist: int = 3000
    max_outbounds_wifi: int = 500


@dataclass
class Checks:
    workers: int = 10
    per_check_timeout: int = 12
    check_url: str = "http://www.google.com/generate_204"
    ttl_days: int = 3
    results_max_configs: int = 20000
    geo_primary: str = "ipwho.is"
    geo_fallback: str = "ip-api.com"


@dataclass
class Config:
    version: int
    settings: Settings
    pages: Pages
    safety: Safety
    checks: Checks
    update_interval_hours: int
    sources: list


def _parse_source(d: dict) -> Source:
    files_raw = d.get("files", [])
    files: list = []
    for f in files_raw:
        if isinstance(f, str):
            files.append(SourceFile(path=f))
        elif isinstance(f, dict):
            files.append(SourceFile(path=f["path"], max_size_mb=f.get("max_size_mb")))
    return Source(
        id=d["id"],
        name=d.get("name", d["id"]),
        type=d.get("type", "github"),
        repo=d.get("repo", ""),
        branch=d.get("branch", "main"),
        files=files,
    )


def load_config(path: str | Path) -> Config:
    path = Path(path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    s = raw.get("settings", {})
    p = raw.get("pages", {})
    sf = raw.get("safety", {})
    c = raw.get("checks", {})
    sources = [_parse_source(d) for d in raw.get("sources", [])]
    return Config(
        version=raw.get("version", 1),
        settings=Settings(**s),
        pages=Pages(**p),
        safety=Safety(**sf),
        checks=Checks(**c),
        update_interval_hours=raw.get("update_interval_hours", 6),
        sources=sources,
    )
