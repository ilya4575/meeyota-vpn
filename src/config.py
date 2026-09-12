"""Загрузка и валидация настроек проекта (sources.yaml)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

import yaml


class ConfigError(ValueError):
    """Ошибка конфигурации sources.yaml."""


@dataclass
class FileRef:
    path: str
    max_size_mb: float | None = None


@dataclass
class Source:
    id: str
    files: list[FileRef]
    type: str = "github"
    repo: str = ""
    branch: str = "main"
    url: str = ""
    name: str = ""
    enabled: bool = True


@dataclass
class Settings:
    # --- HTTP / скачивание ---
    timeout: int = 30
    retries: int = 3
    backoff: float = 2.0
    max_file_size_mb: float = 25.0
    use_api_fallback: bool = True
    cache_dir: str = "data/cache"
    # --- GitHub Pages ---
    pages_username: str = "USERNAME"
    pages_repository: str = "REPOSITORY"
    # --- защита от обнуления ---
    min_configs: int = 50
    max_drop_ratio: float = 0.5
    # --- проверки (подписка VPN Wi-fi) ---
    check_workers: int = 10
    check_minutes: int = 110
    check_ttl_days: int = 3
    geo_ttl_days: int = 7
    geo_cache_max: int = 20000
    results_max_groups: int = 6000
    results_max_configs: int = 20000
    # --- подписки ---
    update_interval_hours: int = 6
    sources: list[Source] = field(default_factory=list)

    @property
    def data_dir(self) -> str:
        return "data"


def _as_int(value: Any, name: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"настройка {name} должна быть числом, получено: {value!r}")


def _as_float(value: Any, name: str, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"настройка {name} должна быть числом, получено: {value!r}")


def _as_bool(value: Any, name: str, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("1", "true", "yes", "on"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"настройка {name} должна быть true/false, получено: {value!r}")


def load_settings(path: Union[str, Path]) -> Settings:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"файл конфигурации не найден: {p}")
    try:
        raw: Any = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"ошибка YAML в {p}: {e}") from e
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("sources.yaml должен содержать маппинг в корне")

    s = Settings()
    st = raw.get("settings") or {}
    if not isinstance(st, dict):
        raise ConfigError("секция settings должна быть маппингом")
    if "timeout" in st:
        s.timeout = _as_int(st["timeout"], "settings.timeout", s.timeout)
    if "retries" in st:
        s.retries = _as_int(st["retries"], "settings.retries", s.retries)
    if "backoff" in st:
        s.backoff = _as_float(st["backoff"], "settings.backoff", s.backoff)
    if "max_file_size_mb" in st:
        s.max_file_size_mb = _as_float(st["max_file_size_mb"], "settings.max_file_size_mb", s.max_file_size_mb)
    if "use_api_fallback" in st:
        s.use_api_fallback = _as_bool(st["use_api_fallback"], "settings.use_api_fallback", s.use_api_fallback)
    if "cache_dir" in st:
        s.cache_dir = str(st["cache_dir"])

    pages = raw.get("pages") or {}
    if not isinstance(pages, dict):
        raise ConfigError("секция pages должна быть маппингом")
    s.pages_username = str(pages.get("username") or "USERNAME")
    s.pages_repository = str(pages.get("repository") or "REPOSITORY")

    safety = raw.get("safety") or {}
    if not isinstance(safety, dict):
        raise ConfigError("секция safety должна быть маппингом")
    if "min_configs" in safety:
        s.min_configs = _as_int(safety["min_configs"], "safety.min_configs", s.min_configs)
    if "max_drop_ratio" in safety:
        s.max_drop_ratio = _as_float(safety["max_drop_ratio"], "safety.max_drop_ratio", s.max_drop_ratio)
    if not 0 < s.max_drop_ratio < 1:
        raise ConfigError("safety.max_drop_ratio должен быть в диапазоне (0, 1)")

    checks = raw.get("checks") or {}
    if not isinstance(checks, dict):
        raise ConfigError("секция checks должна быть маппингом")
    if "workers" in checks:
        s.check_workers = _as_int(checks["workers"], "checks.workers", s.check_workers)
    if "minutes" in checks:
        s.check_minutes = _as_int(checks["minutes"], "checks.minutes", s.check_minutes)
    if "ttl_days" in checks:
        s.check_ttl_days = _as_float(checks["ttl_days"], "checks.ttl_days", s.check_ttl_days)
    if "geo_ttl_days" in checks:
        s.geo_ttl_days = _as_float(checks["geo_ttl_days"], "checks.geo_ttl_days", s.geo_ttl_days)
    if "geo_cache_max" in checks:
        s.geo_cache_max = _as_int(checks["geo_cache_max"], "checks.geo_cache_max", s.geo_cache_max)
    if "results_max_groups" in checks:
        s.results_max_groups = _as_int(checks["results_max_groups"], "checks.results_max_groups", s.results_max_groups)
    if "results_max_configs" in checks:
        s.results_max_configs = _as_int(checks["results_max_configs"], "checks.results_max_configs", s.results_max_configs)

    if "update_interval_hours" in raw:
        s.update_interval_hours = _as_int(raw["update_interval_hours"], "update_interval_hours", s.update_interval_hours)

    sources_raw = raw.get("sources") or []
    if not isinstance(sources_raw, list):
        raise ConfigError("секция sources должна быть списком")
    if not sources_raw:
        raise ConfigError("в sources.yaml не задано ни одного источника")

    seen_ids: set[str] = set()
    for idx, item in enumerate(sources_raw):
        if not isinstance(item, dict):
            raise ConfigError(f"источник #{idx + 1}: должно быть маппингом")
        src_id = str(item.get("id") or "").strip()
        if not src_id:
            raise ConfigError(f"источник #{idx + 1}: отсутствует поле id")
        if src_id in seen_ids:
            raise ConfigError(f"дублирующийся id источника: {src_id}")
        seen_ids.add(src_id)

        stype = str(item.get("type") or "github").strip().lower()
        if stype not in ("github", "url"):
            raise ConfigError(f"источник {src_id}: неизвестный type={stype!r} (github|url)")

        repo = str(item.get("repo") or "").strip()
        branch = str(item.get("branch") or "main").strip()
        if stype == "github":
            if "/" not in repo or len(repo.split("/")) != 2:
                raise ConfigError(f"источник {src_id}: repo должен иметь вид owner/repo")

        files_raw = item.get("files") or []
        if not isinstance(files_raw, list) or not files_raw:
            raise ConfigError(f"источник {src_id}: files — непустой список обязателен")
        files: list[FileRef] = []
        for fitem in files_raw:
            if isinstance(fitem, str):
                path = fitem.strip()
                size = None
            elif isinstance(fitem, dict):
                path = str(fitem.get("path") or "").strip()
                size = fitem.get("max_size_mb")
                if size is not None:
                    size = _as_float(size, f"{src_id}.max_size_mb", 0)
            else:
                raise ConfigError(f"источник {src_id}: элемент files должен быть строкой или маппингом")
            if not path:
                raise ConfigError(f"источник {src_id}: пустой путь файла")
            files.append(FileRef(path=path, max_size_mb=size))

        s.sources.append(
            Source(
                id=src_id,
                files=files,
                type=stype,
                repo=repo,
                branch=branch,
                url=str(item.get("url") or "").strip(),
                name=str(item.get("name") or src_id),
                enabled=_as_bool(item.get("enabled", True), f"{src_id}.enabled", True),
            )
        )

    return s
