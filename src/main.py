"""meeyota-vpn: агрегатор публичных VPN-конфигураций из GitHub-репозиториев.

Запуск:  python -m src.main [опции]
Пайплайн:  sources.yaml -> collect (retry/cache) -> parse -> dedupe
           -> checks (внешний IP + геолокация через Xray) -> export (2 подписки) -> README.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests

from .checks.checker import (CheckResult, load_checks_cache, run_checks,
                             save_checks_cache, wifi_eligible)
from .checks.xray import ensure_xray
from .collectors.http_client import HttpClient
from .collectors.source import collect_source
from .config import Settings, load_sources
from .deduplicator import dedupe
from .exporter import export, incy_add_links, incy_import_link
from .models.config import VpnConfig
from .parsers.subscription import extract_uris
from .parsers.uri import ParseError, parse_uri

log = logging.getLogger("meeyota")


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def _load_prev_configs(data_dir: Path) -> List[VpnConfig]:
    """Последнее хорошее состояние (data/configs.json) — фолбэк для упавших источников."""
    p = data_dir / "configs.json"
    if not p.is_file():
        return []
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        out: List[VpnConfig] = []
        for d in raw:
            c = VpnConfig(
                protocol=d.get("protocol", ""),
                address=d.get("address", ""),
                port=int(d.get("port") or 0),
                name=d.get("name", ""),
                source=d.get("source", ""),
                raw=d.get("raw", ""),
            )
            out.append(c)
        return out
    except (json.JSONDecodeError, OSError, ValueError, TypeError) as e:
        log.warning("configs.json не читается: %s", e)
        return []


def collect_all(settings: Settings) -> tuple[List[dict], dict]:
    """Скачивает все включённые источники. -> (источники-резулты, stats-фрагмент)."""
    sources = load_sources(Path(settings.sources_path))
    client = HttpClient(
        user_agent=f"meeyota-vpn-aggregator/1.0 (repo {settings.repository or 'local'})")
    cache_dir = Path(settings.data_dir) / "cache"
    results: List[dict] = []
    stats = {"sources_total": 0, "sources_enabled": 0, "sources_ok": 0,
             "sources_failed": 0, "sources_from_cache": 0}
    for spec in sources:
        if not spec.enabled:
            log.info("%s: отключён (enabled: false), пропускаем", spec.id)
            continue
        stats["sources_enabled"] += 1
        res = collect_source(spec, client, cache_dir)
        results.append({"spec": spec, "result": res})
        if res.ok:
            stats["sources_ok"] += 1
            if res.from_cache:
                stats["sources_from_cache"] += 1
        else:
            stats["sources_failed"] += 1
    return results, stats


def parse_all(results: List[dict]) -> tuple[List[VpnConfig], dict]:
    """URI -> VpnConfig. Битые отбрасываются, оригинальный URI сохраняется (raw)."""
    stats = {"lines": 0, "uris": 0, "parsed": 0, "invalid": 0, "invalid_examples": []}
    configs: List[VpnConfig] = []
    for item in results:
        spec, res = item["spec"], item["result"]
        if not res.ok or not res.text:
            continue
        uris = extract_uris(res.text)
        stats["uris"] += len(uris)
        for u in uris:
            stats["lines"] += 1
            try:
                cfg = parse_uri(u)
            except ParseError as e:
                stats["invalid"] += 1
                if len(stats["invalid_examples"]) < 10:
                    stats["invalid_examples"].append(f"{u[:80]} :: {e}")
                continue
            cfg.source = f"{spec.name} ({spec.id})"
            configs.append(cfg)
            stats["parsed"] += 1
    return configs, stats


def merge_failed_sources(configs: List[VpnConfig], results: List[dict],
                         prev: List[VpnConfig]) -> tuple[List[VpnConfig], int]:
    """Для источников, которые не отдалось скачать и нет кэша — берём предыдущее состояние.

    Это вторая линия защиты от обнуления: подписка не теряется из-за одного упавшего URL."""
    failed_ids = {item["spec"].id for item in results
                  if not item["result"].ok}
    if not failed_ids or not prev:
        return configs, 0
    # имя источника в configs: "name (id)"
    have = {c.source for c in configs}
    added = 0
    for old in prev:
        for fid in failed_ids:
            if old.source.endswith(f"({fid})") and old.source not in have and old.raw:
                configs.append(old)
                have.add(old.source)
                added += 1
    if added:
        log.warning("восстановлено конфигураций из прошлого состояния (источники недоступны): %d", added)
    return configs, added


def build_wifi_list(whitelist: List[VpnConfig],
                    checks: Dict[str, CheckResult],
                    settings: Settings) -> tuple[List[VpnConfig], dict]:
    now = time.time()
    wifi: List[VpnConfig] = []
    stats = {"included": 0, "ex_ru4": 0, "ex_ru6": 0, "ex_conflict": 0,
             "ex_unknown": 0, "ex_not_checked": 0, "ex_stale": 0,
             "ex_check_failed": 0}
    for cfg in whitelist:
        r = checks.get(cfg.fingerprint)
        ok, reason = wifi_eligible(r, settings.check_ttl_hours, now)
        if ok:
            wifi.append(cfg)
            stats["included"] += 1
            continue
        # классификация причины отсева (порядок соответствует wifi_eligible)
        if r is None:
            stats["ex_not_checked"] += 1
        elif not r.ok:
            stats["ex_check_failed"] += 1
        elif "устарела" in reason or "нет даты" in reason:
            stats["ex_stale"] += 1
        elif not r.cc4:
            stats["ex_unknown"] += 1          # IPv4 не получен или страна не определена
        elif r.cc4 == "RU":
            stats["ex_ru4"] += 1
        elif r.ip6 and not r.cc6:
            stats["ex_unknown"] += 1          # страна IPv6 не определена
        elif r.ip6 and r.cc6 == "RU":
            stats["ex_ru6"] += 1
        elif r.ip6 and r.cc6 != r.cc4:
            stats["ex_conflict"] += 1
        else:
            stats["ex_check_failed"] += 1
    return wifi, stats


def run_pipeline(settings: Settings) -> int:
    t_start = time.time()
    _setup_logging(verbose=settings.extra.get("verbose", False))
    data_dir = Path(settings.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    log.info("=== meeyota-vpn: старт пайплайна ===")
    try:
        sources = load_sources(Path(settings.sources_path))
    except (ValueError, OSError) as e:
        log.error("sources.yaml: %s", e)
        return 2

    # 1) COLLECT
    results, s_sources = collect_all(settings)
    ok_sources = [i for i in results if i["result"].ok]
    if not ok_sources:
        log.critical("ВСЕ источники недоступны и кэш пуст — подписки НЕ трогаем")
        return 2

    # 2) PARSE
    configs, s_parse = parse_all(results)
    for ex in s_parse["invalid_examples"]:
        log.debug("битый: %s", ex)

    # 3) фолбэк для упавших источников + DEDUPE
    prev = _load_prev_configs(data_dir)
    configs, restored = merge_failed_sources(configs, results, prev)
    deduped = dedupe(configs)
    whitelist: List[VpnConfig] = deduped.unique
    log.info("найденных URI: %d, валидных: %d, битых: %d, дубликатов: %d, уникальных: %d",
             s_parse["uris"], s_parse["parsed"], s_parse["invalid"],
             deduped.duplicates, len(whitelist))

    # 4) CHECKS (внешний IP + геолокация)
    checks: Dict[str, CheckResult] = load_checks_cache(data_dir / "checks.json")
    checks_ran = False
    xray_bin = None
    if not settings.skip_checks:
        session = requests.Session()
        xray_bin = ensure_xray(Path(settings.xray_bin_dir), session, log)
        if xray_bin is None:
            log.error("Xray недоступен — проверки пропущены (wifi-подписка сохранится прежней)")
        else:
            # приоритет: fingerprint'ы, уже состоящие в текущей wifi-подписке
            current_wifi = Path(settings.output_dir) / settings.wifi_file
            prioritize: Set[str] = set()
            if current_wifi.is_file():
                for line in current_wifi.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        prioritize.add(parse_uri(line).fingerprint)
                    except ParseError:
                        pass
            before = len(checks)
            checks = run_checks(
                whitelist, xray_bin, checks,
                ttl_hours=settings.check_ttl_hours,
                max_checks=settings.max_checks,
                workers=settings.workers,
                recheck_all=settings.recheck_all,
                per_request_timeout=15.0,
                overall_timeout=settings.check_timeout_s,
                prioritize=prioritize)
            checks_ran = len(checks) > before
            save_checks_cache(data_dir / "checks.json", checks)

    checks_ok = sum(1 for r in checks.values() if r.ok)

    # 5) WIFI-ФИЛЬТР
    wifi, s_wifi = build_wifi_list(whitelist, checks, settings)
    log.info("wifi: включено %d; RU-v4 %d, RU-v6 %d, противоречия %d, "
             "неопределённые %d, не проверено %d, устаревшие %d, проверка не пройдена %d",
             s_wifi["included"], s_wifi["ex_ru4"], s_wifi["ex_ru6"], s_wifi["ex_conflict"],
             s_wifi["ex_unknown"], s_wifi["ex_not_checked"], s_wifi["ex_stale"],
             s_wifi["ex_check_failed"])

    # 6) EXPORT (guard от обнуления + README incy-ссылки)
    stats = {
        "started_at": t_start,
        "duration_s": round(time.time() - t_start, 1),
        "sources": s_sources,
        "parse": s_parse,
        "restored_from_prev": restored,
        "duplicates": deduped.duplicates,
        "by_protocol": deduped.by_protocol,
        "unique": len(whitelist),
        "checks": {
            "cached_total": len(checks),
            "ran_this_run": checks_ran,
            "ok": checks_ok,
        },
        "wifi": s_wifi,
        "geo_cache_ips": None,
    }
    exp = export(settings, whitelist, wifi, checks,
                 checks_ran=checks_ran, checks_ok=checks_ok, stats=stats)
    stats["export"] = {
        "whitelist_written": exp.whitelist_written,
        "whitelist_count": exp.whitelist_count,
        "wifi_written": exp.wifi_written,
        "wifi_count": exp.wifi_count,
        "aborted": exp.aborted,
    }
    if not settings.dry_run:
        (data_dir / "stats.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=1, default=str), encoding="utf-8")

    # 7) INCY-ссылки (вывод)
    links = incy_add_links(settings)
    log.info("=== готово за %.1fs ===", stats["duration_s"])
    log.info("VPN whitelist meeyota: %s", links["whitelist"])
    log.info("VPN Wi-fi meeyota:     %s", links["wifi"])
    print(f"\nIncy whitelist: {links['whitelist']}")
    print(f"Incy wifi:      {links['wifi']}")

    if exp.aborted:
        fatal = [a for a in exp.aborted if a.startswith("whitelist:")]
        for a in exp.aborted:
            log.critical("GUARD: %s", a)
        if fatal:
            # похоже, сбились источники/парсер — вообще ничего не коммитим
            log.critical("whitelist-подписка НЕ обновлена — запуск считается ошибочным")
            return 1
        # затронуто только wifi (напр., xray недоступен): whitelist обновляется,
        # старый wifi-список сохраняется
        log.warning("продолжаем: затронута только wifi-подписка (старая сохранена)")
    return 0


# --------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="meeyota-vpn",
        description="Агрегатор публичных VPN-конфигураций (GitHub -> 2 подписки).")
    p.add_argument("--sources", default="sources.yaml", help="путь к sources.yaml")
    p.add_argument("--data-dir", default="data")
    p.add_argument("--output-dir", default="output")
    p.add_argument("--readme", default="README.md")
    p.add_argument("--skip-checks", action="store_true",
                   help="не проверять внешний IP (whitelist-подписка всё равно обновится)")
    p.add_argument("--recheck-all", action="store_true", help="перепроверить всё, несмотря на кэш")
    p.add_argument("--max-checks", type=int, default=400, help="лимит новых проверок за запуск")
    p.add_argument("--workers", type=int, default=5, help="параллельных xray-зондов")
    p.add_argument("--check-ttl-hours", type=float, default=24.0,
                   help="свежесть проверки для wifi-подписки (часы)")
    p.add_argument("--check-timeout", type=float, default=45.0, help="общий таймаут проверки, сек")
    p.add_argument("--username", default="", help="GitHub username для incy://add ссылок")
    p.add_argument("--repository", default="", help="имя репозитория для incy://add ссылок")
    p.add_argument("--dry-run", action="store_true", help="ничего не записывать")
    p.add_argument("--incy-import", action="store_true",
                   help="после генерации напечатать incy://import/{base64} снапшот")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings(
        sources_path=Path(args.sources),
        data_dir=Path(args.data_dir),
        output_dir=Path(args.output_dir),
        readme_path=Path(args.readme),
        skip_checks=args.skip_checks,
        recheck_all=args.recheck_all,
        max_checks=args.max_checks,
        workers=args.workers,
        check_ttl_hours=args.check_ttl_hours,
        check_timeout_s=args.check_timeout,
        username=args.username,
        repository=args.repository,
        dry_run=args.dry_run,
        extra={"verbose": args.verbose},
    )
    rc = run_pipeline(settings)
    if args.incy_import and rc == 0:
        prev = _load_prev_configs(settings.data_dir)
        if prev:
            print(incy_import_link(prev))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
