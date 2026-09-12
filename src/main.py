"""meeyota-vpn — агрегатор публичных VPN-конфигураций.

Точка входа:  python -m src.main [опции]

Этапные этапы:
    1. скачивание файлов-источников (retry, timeout, ETag-кэш, API-fallback);
    2. парсинг и нормализация URI (vless, vmess, trojan, ss, ssr, hy2, tuic, socks5);
    3. дедупликация;
    4. проверки для «VPN Wi-fi» (опция --checks): реальное соединение через
       sing-box + геолокация внешнего IPv4/IPv6, строгой отсев RU/конфликтов;
    5. генерация двух подписок в output/ + data/ (stats, configs, результаты);
    6. защита от обнуления: при аномально малом списке подписки не перезаписываются.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checks.connectivity import singbox_available
from .checks.verifier import CheckResults, VERDICT_OK, verify
from .collectors import Collector, SourceError
from .config import ConfigError, load_settings
from .deduplicator import dedup, sort_for_export
from .exporter import (
    WHITELIST_FILE,
    WIFI_FILE,
    count_uris,
    render_incy_links,
    update_readme_links,
    wipeout_ok,
    write_import_link_file,
    write_incy_links_file,
    write_outputs,
)
from .parsers import parse_text

log = logging.getLogger("meeyota")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="meeyota-vpn",
        description="Агрегатор публичных VPN-конфигураций (GitHub → подписки Incy/v2rayN)",
    )
    p.add_argument("--config", default="sources.yaml", help="путь к sources.yaml (по умолчанию ./sources.yaml)")
    p.add_argument("--checks", action="store_true", help="выполнять проверки соединения и геолокации (нужен sing-box)")
    p.add_argument("--workers", type=int, default=None, help="число параллельных проверок (по умолчанию из sources.yaml)")
    p.add_argument("--check-minutes", type=float, default=None, help="бюджет времени на проверки, минут")
    p.add_argument("--singbox", default=None, help="путь к бинарнику sing-box (или env SINGBOX_BIN)")
    p.add_argument("--import-link", metavar="FILE", default=None,
                   help="сформировать файл с одноразовыми ссылками incy://import/{base64}")
    p.add_argument("--verbose", action="store_true", help="подробный лог")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)

    config_path = Path(args.config)
    root = config_path.resolve().parent

    try:
        settings = load_settings(config_path)
    except ConfigError as e:
        log.error("конфигурация: %s", e)
        return 1

    # Переопределение данных Pages переменными окружения (CI-friendly)
    if os.environ.get("PAGES_USERNAME"):
        settings.pages_username = os.environ["PAGES_USERNAME"]
    if os.environ.get("PAGES_REPOSITORY"):
        settings.pages_repository = os.environ["PAGES_REPOSITORY"]

    data_dir = root / settings.data_dir
    output_dir = root / "output"
    data_dir.mkdir(parents=True, exist_ok=True)

    log.info("=== meeyota-vpn: запуск (%s) ===", _iso_now())
    log.info("источников: %d", len([s for s in settings.sources if s.enabled]))

    # ------------------------------------------------------------------
    # 1) Сборка источников
    # ------------------------------------------------------------------
    collector = Collector(settings, root=root)
    all_configs: list[Any] = []
    source_stats: list[dict[str, Any]] = []
    found = invalid = 0

    for src in settings.sources:
        if not src.enabled:
            log.info("источник %s: отключён, пропускаю", src.id)
            continue
        stat: dict[str, Any] = {
            "id": src.id,
            "name": src.name,
            "type": src.type,
            "status": "ok",
            "error": None,
            "files": [],
            "configs": 0,
            "invalid": 0,
        }
        try:
            for fref in src.files:
                if src.type == "github":
                    text = collector.fetch_github(src.repo, src.branch, fref.path, fref.max_size_mb)
                else:
                    text = collector.fetch_url(fref.path, fref.max_size_mb)
                cfgs, inv = parse_text(text, src.id)
                all_configs.extend(cfgs)
                found += len(cfgs)
                invalid += inv
                stat["configs"] += len(cfgs)
                stat["invalid"] += inv
                stat["files"].append(
                    {"path": fref.path, "lines": len(text.splitlines()), "configs": len(cfgs), "invalid": inv}
                )
                log.info(
                    "  %s: %s — строк: %d, валидных: %d, битых: %d",
                    src.id, fref.path, len(text.splitlines()), len(cfgs), inv,
                )
        except SourceError as e:
            stat["status"] = "error"
            stat["error"] = str(e)
            log.error("источник %s НЕДОСТУПЕН: %s", src.id, e)
        source_stats.append(stat)

    ok_sources = sum(1 for s in source_stats if s["status"] == "ok")
    log.info("скачано источников: %d/%d; найдено URI: %d; битых строк: %d",
             ok_sources, len(source_stats), found, invalid)

    # ------------------------------------------------------------------
    # 2) Дедупликация
    # ------------------------------------------------------------------
    unique, duplicates = dedup(all_configs)
    unique = sort_for_export(unique)
    log.info("уникальных конфигов: %d (дубликатов удалено: %d)", len(unique), duplicates)

    # ------------------------------------------------------------------
    # 3) Проверки для подписки «VPN Wi-fi meeyota»
    # ------------------------------------------------------------------
    results_path = data_dir / "check_results.json"
    results = CheckResults.load(results_path)
    check_stats: dict[str, Any] | None = None

    if args.checks:
        singbox = singbox_available(args.singbox)
        if not singbox:
            log.warning("--checks: sing-box не найден (установите его или задайте SINGBOX_BIN) — проверки пропущены")
        check_stats = verify(
            unique,
            settings,
            results,
            singbox,
            workers=args.workers,
            minutes=args.check_minutes,
        )
        results.save(results_path)
        log.info(
            "проверки: серверов %d (в очереди %d, из кэша %d), проверено %d, "
            "ошибок %d, вердикты %s",
            check_stats.get("total_servers", 0), check_stats.get("due", 0),
            check_stats.get("cached", 0), check_stats.get("checked", 0),
            check_stats.get("errors", 0), check_stats.get("verdicts", {}),
        )

    # применяем сохранённые результаты к конфигам
    for c in unique:
        r = results.configs.get(c.hash)
        if r:
            c.last_check = r.get("last_check")
            c.country = r.get("country")
            c.ip = r.get("ip")
            c.verdict = r.get("verdict")

    wifi = [c for c in unique if c.verdict == VERDICT_OK]
    log.info("подписка whitelist: %d; подписка wifi (проверено вне РФ): %d", len(unique), len(wifi))

    # ------------------------------------------------------------------
    # 4) Защита от обнуления + экспорт
    # ------------------------------------------------------------------
    prev_whitelist = count_uris(output_dir / WHITELIST_FILE)
    ok, reason = wipeout_ok(prev_whitelist, len(unique), settings.min_configs, settings.max_drop_ratio)
    if not ok:
        log.critical(
            "ПОДПИСКА НЕ ОБНОВЛЯЕТСЯ (защита от обнуления): %s. "
            "Прежний файл сохранён.", reason,
        )
        _write_stats(root, data_dir, source_stats, found, invalid, len(unique), duplicates,
                     len(unique), len(wifi), check_stats, aborted=reason)
        return 2

    paths = write_outputs(output_dir, unique, wifi, settings, results.configs)
    _write_stats(root, data_dir, source_stats, found, invalid, len(unique), duplicates,
                 len(unique), len(wifi), check_stats)
    _write_configs_json(data_dir, unique)

    # Incy-ссылки: README (блок между маркерами) + data/incy-links.txt
    readme = root / "README.md"
    if readme.exists():
        if update_readme_links(readme, render_incy_links(settings)):
            log.info("README.md: блок Incy-ссылок обновлён")
    write_incy_links_file(data_dir / "incy-links.txt", settings)

    if args.import_link:
        write_import_link_file(Path(args.import_link), output_dir)
        log.info("одноразовые incy://import-ссылки: %s", args.import_link)

    log.info("=== готово: %s (%d), %s (%d) ===",
             paths["whitelist"].name, len(unique), paths["wifi"].name, len(wifi))
    return 0


# ---------------------------------------------------------------------------
# Хранение данных
# ---------------------------------------------------------------------------

def _write_configs_json(data_dir: Path, configs: list[Any]) -> None:
    payload = [c.to_dict() for c in configs]
    path = data_dir / "configs.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def _write_stats(
    root: Path,
    data_dir: Path,
    source_stats: list[dict[str, Any]],
    found: int,
    invalid: int,
    unique_count: int,
    duplicates: int,
    whitelist_count: int,
    wifi_count: int,
    check_stats: dict[str, Any] | None,
    aborted: str | None = None,
) -> None:
    stats = {
        "generated_at": _iso_now(),
        "aborted": aborted,
        "sources": source_stats,
        "found": found,
        "invalid": invalid,
        "unique": unique_count,
        "duplicates": duplicates,
        "whitelist": whitelist_count,
        "wifi": wifi_count,
        "checks": check_stats,
    }
    path = data_dir / "stats.json"
    path.write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    log.info(
        "статистика: найдено=%d валидных=%d битых=%d уникальных=%d дубликатов=%d "
        "whitelist=%d wifi=%d",
        found, found - invalid, invalid, unique_count, duplicates, whitelist_count, wifi_count,
    )


if __name__ == "__main__":
    sys.exit(main())
