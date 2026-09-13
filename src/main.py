"""Главная точка входа: pipeline сбора → парсинга → нормализации → дедупликации → валидации → эмиссии."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .collectors.github import GithubCollector
from .config import Config, load_config
from .deduplicator import deduplicate
from .emitter.xray import build_full_xray_config, render_json
from .models.config import VpnConfig
from .normaliser import normalise
from .parsers.uri import parse_text
from .validator import validate_all


log = logging.getLogger("meeyota-vpn")


@dataclass
class RunStats:
    started_at: float = field(default_factory=time.time)
    by_source_downloaded: Counter = field(default_factory=Counter)
    by_source_lines: Counter = field(default_factory=Counter)
    by_scheme_parsed: Counter = field(default_factory=Counter)
    by_scheme_after_validate: Counter = field(default_factory=Counter)
    parsed_total: int = 0
    normalised_total: int = 0
    dedup_dropped: int = 0
    validation_errors: int = 0
    whitelist_count: int = 0
    wifi_count: int = 0
    wifi_filtered_out: int = 0
    source_errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": time.time(),
            "by_source_downloaded_bytes": dict(self.by_source_downloaded),
            "by_source_lines": dict(self.by_source_lines),
            "by_scheme_parsed": dict(self.by_scheme_parsed),
            "by_scheme_after_validate": dict(self.by_scheme_after_validate),
            "parsed_total": self.parsed_total,
            "normalised_total": self.normalised_total,
            "dedup_dropped": self.dedup_dropped,
            "validation_errors": self.validation_errors,
            "whitelist_count": self.whitelist_count,
            "wifi_count": self.wifi_count,
            "wifi_filtered_out": self.wifi_filtered_out,
            "source_errors": self.source_errors,
        }


def _collect_source(coll: GithubCollector, src, stats: RunStats) -> list:
    """Скачивает все файлы источника, парсит, возвращает список VpnConfig."""
    out: list = []
    for f in src.files:
        r = coll.download(src.id, src.repo, src.branch, f.path)
        if r.error:
            stats.source_errors.append(
                f"{src.id}/{f.path}: {r.error}"
            )
            log.warning("source error: %s/%s: %s", src.id, f.path, r.error)
            continue
        stats.by_source_downloaded[f"{src.id}/{f.path}"] += len(r.content)
        text = r.content.decode("utf-8", errors="replace")
        parsed, errors = parse_text(text, source_id=src.id)
        for cfg in parsed:
            cfg.source_id = src.id
        out.extend(parsed)
        stats.by_source_lines[f"{src.id}/{f.path}"] += len(parsed)
        for _ in errors:
            pass  # parse errors уже не считаем (статистика через parsed_total)
        log.info(
            "%s/%s: parsed %d configs (cache=%s, %dms)",
            src.id,
            f.path,
            len(parsed),
            r.from_cache,
            r.duration_ms,
        )
    return out


def _run_pipeline(cfg: Config) -> RunStats:
    stats = RunStats()
    coll = GithubCollector(
        cache_dir=Path(cfg.settings.cache_dir),
        timeout=cfg.settings.timeout,
        retries=cfg.settings.retries,
        backoff=cfg.settings.backoff,
        max_file_size_mb=cfg.settings.max_file_size_mb,
        use_api_fallback=cfg.settings.use_api_fallback,
    )

    all_configs: list = []
    for src in cfg.sources:
        if src.type == "github":
            cfgs = _collect_source(coll, src, stats)
        else:
            log.warning("unsupported source type: %s", src.type)
            continue
        all_configs.extend(cfgs)

    # Схемы — статистика
    for c in all_configs:
        stats.by_scheme_parsed[c.scheme] += 1
    stats.parsed_total = len(all_configs)
    log.info("parsed total: %d", stats.parsed_total)

    # Нормализация
    normalised = [normalise(c) for c in all_configs]
    stats.normalised_total = len(normalised)

    # Валидация
    valid, errors = validate_all(normalised)
    stats.validation_errors = len(errors)
    for c in valid:
        stats.by_scheme_after_validate[c.scheme] += 1
    log.info(
        "valid: %d, errors: %d",
        len(valid),
        len(errors),
    )

    # Дедупликация
    unique, dropped = deduplicate(valid)
    stats.dedup_dropped = dropped
    log.info("unique: %d, dropped by dedup: %d", len(unique), dropped)

    # Лимит на размер whitelist
    whitelist = unique[: cfg.safety.max_outbounds_whitelist]
    stats.whitelist_count = len(whitelist)
    log.info("whitelist count (capped): %d", len(whitelist))

    # Wi-Fi: фильтрация по геолокации
    wifi = _filter_wifi(unique, cfg, stats)
    stats.wifi_count = len(wifi)

    # Эмиссия
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)

    wl_config = build_full_xray_config(
        whitelist, "VPN whitelist meeyota", burst_interval="30s"
    )
    (out_dir / "vpn-whitelist-meeyota.json").write_bytes(render_json(wl_config))

    wifi_config = build_full_xray_config(
        wifi, "VPN Wi-fi meeyota", burst_interval="60s"
    )
    (out_dir / "vpn-wifi-meeyota.json").write_bytes(render_json(wifi_config))

    log.info(
        "emitted: whitelist=%d outbounds, wifi=%d outbounds",
        len(whitelist),
        len(wifi),
    )

    return stats


def _filter_wifi(configs: list, cfg: Config, stats: RunStats) -> list:
    """Фильтрация Wi-Fi: пропускаем только non-RU IP-узлы.

    Использует persistent cache в data/check_results.json.
    Доменные узлы пропускаются (нет способа провести IP-проверку без DNS).
    """
    from .checks.verifier import (
        is_non_russian,
        load_cache,
        save_cache,
    )

    cache_path = Path("data/check_results.json")
    cache = load_cache(cache_path)
    ttl_seconds = cfg.checks.ttl_days * 24 * 3600

    wifi: list = []
    filtered_out = 0
    for c in configs:
        ok, reason, country = is_non_russian(c, cache, ttl_seconds)
        if ok:
            wifi.append(c)
        else:
            filtered_out += 1
    stats.wifi_filtered_out = filtered_out
    save_cache(cache_path, cache)

    # Лимит на wifi
    wifi = wifi[: cfg.safety.max_outbounds_wifi]
    return wifi


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="meeyota-vpn: aggregate public VPN configs into full Xray JSON profiles"
    )
    parser.add_argument(
        "--config",
        default="sources.yaml",
        help="path to sources.yaml (default: sources.yaml)",
    )
    parser.add_argument(
        "--stats-output",
        default="data/stats.json",
        help="path for stats.json (default: data/stats.json)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="reduce log noise",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cfg = load_config(args.config)

    # Safety: пустой результат не перезаписываем
    try:
        stats = _run_pipeline(cfg)
    except Exception as e:
        log.exception("pipeline failed: %s", e)
        return 1

    out_dir = Path("output")
    wl_json = out_dir / "vpn-whitelist-meeyota.json"
    wf_json = out_dir / "vpn-wifi-meeyota.json"

    if not wl_json.exists() or not wf_json.exists():
        log.error("output files missing")
        return 1

    # Проверка минимального размера (анти-пустой-результат)
    if stats.whitelist_count < cfg.safety.min_configs_whitelist:
        log.error(
            "whitelist count %d < min %d — refusing to overwrite",
            stats.whitelist_count,
            cfg.safety.min_configs_whitelist,
        )
        return 1

    # Сохранение статистики
    stats_path = Path(args.stats_output)
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(
        json.dumps(stats.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.info("done. whitelist=%d, wifi=%d", stats.whitelist_count, stats.wifi_count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
