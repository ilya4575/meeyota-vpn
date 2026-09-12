"""Проверка конфигураций: внешний IP + геолокация, политика для «VPN Wi-fi meeyota»."""
from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

import requests

from ..models.config import VpnConfig
from . import geo, xray

log = logging.getLogger("meeyota.checks")


@dataclass
class CheckResult:
    fingerprint: str
    ok: bool
    ip4: Optional[str] = None
    ip6: Optional[str] = None
    cc4: Optional[str] = None
    cc6: Optional[str] = None
    provider4: Optional[str] = None
    provider6: Optional[str] = None
    error: str = ""
    checked_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "CheckResult":
        known = {f for f in CheckResult.__dataclass_fields__}
        return CheckResult(**{k: v for k, v in d.items() if k in known})


# ------------------------------------------------------------------ политика
def wifi_eligible(r: Optional[CheckResult], ttl_hours: float,
                  now: Optional[float] = None) -> Tuple[bool, str]:
    """Строгие правила подписки «VPN Wi-fi meeyota»:

    - проверка проведена и свежая (checked_at в пределах ttl);
    - получен IPv4, страна определена и != RU;
    - если получен IPv6: страна определена, != RU и == стране IPv4 (иначе — «противоречие»);
    - IPv4/IPv6 несовместимы по стране -> конфигурация не подходит;
    - геолокация неопределённа -> не подходит (строго).
    """
    now = now if now is not None else time.time()
    if r is None:
        return False, "не проверен"
    if not r.ok:
        return False, f"проверка не пройдена: {r.error or 'unknown'}"
    if not r.checked_at:
        return False, "нет даты проверки"
    try:
        checked = time.mktime(time.strptime(r.checked_at[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return False, "битая дата проверки"
    if now - checked > ttl_hours * 3600:
        return False, "проверка устарела"
    if not r.ip4:
        return False, "нет внешнего IPv4"
    if not r.cc4:
        return False, "страна IPv4 не определена"
    if r.cc4 == "RU":
        return False, "IPv4: RU"
    if r.ip6:
        if not r.cc6:
            return False, "страна IPv6 не определена"
        if r.cc6 == "RU":
            return False, "IPv6: RU"
        if r.cc6 != r.cc4:
            return False, f"противоречие IPv4/IPv6: {r.cc4}/{r.cc6}"
    return True, "ok"


# --------------------------------------------------------------- кэш проверок
def load_checks_cache(path: Path) -> Dict[str, CheckResult]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return {k: CheckResult.from_dict(v) for k, v in raw.items()}
    except (json.JSONDecodeError, OSError, TypeError) as e:
        log.warning("checks.json повреждён, начинаю заново: %s", e)
        return {}


def save_checks_cache(path: Path, cache: Dict[str, CheckResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({k: v.to_dict() for k, v in cache.items()},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(path)


# ------------------------------------------------------------------ запуск
def _needs_check(cfg: VpnConfig, cache: Dict[str, CheckResult],
                 ttl_hours: float, recheck_all: bool, now: float) -> bool:
    if not cfg.checkable:
        return False
    if recheck_all:
        return True
    r = cache.get(cfg.fingerprint)
    if r is None:
        return True
    if not r.ok and r.error.startswith("не проверяем"):
        return False  # mtproto/tuic и т.п. — не тратим время
    try:
        checked = time.mktime(time.strptime(r.checked_at[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, AttributeError):
        return True
    return now - checked > ttl_hours * 3600


def run_checks(configs: List[VpnConfig],
               xray_bin: Optional[Path],
               cache: Dict[str, CheckResult],
               *,
               ttl_hours: float = 24.0,
               max_checks: int = 400,
               workers: int = 5,
               recheck_all: bool = False,
               per_request_timeout: float = 15.0,
               overall_timeout: float = 45.0,
               prioritize: Optional[Set[str]] = None,
               work_dir: Optional[Path] = None,
               ) -> Dict[str, CheckResult]:
    """Запускает недостающие проверки. prioritize — fingerprint'ы, которые проверить первыми
    (уже состоящие в wifi-подписке). Возвращает обновлённый кэш."""
    now = time.time()
    due = [c for c in configs if _needs_check(c, cache, ttl_hours, recheck_all, now)]
    if prioritize:
        due.sort(key=lambda c: 0 if c.fingerprint in prioritize else 1)
    if len(due) > max_checks:
        log.info("проверок нужно %d, лимит за запуск %d — проверяем приоритетные",
                 len(due), max_checks)
        due = due[:max_checks]

    if not due:
        log.info("новых проверок не требуется (кэш в пределах TTL)")
        return cache

    if xray_bin is None:
        log.error("бинарник Xray недоступен — проверки внешнего IP НЕ выполнены; "
                  "wifi-подписка не будет обновлена (защита от обнуления)")
        return cache

    geo_cache = geo.GeoCache()
    http = requests.Session()
    http.headers.update({"User-Agent": "meeyota-vpn-aggregator/1.0"})
    work_dir = Path(work_dir) if work_dir else Path("data") / "xray-tmp"

    done = 0
    total = len(due)
    log.info("запускаю проверку %d конфигураций (workers=%d) ...", total, workers)

    def _work(cfg: VpnConfig) -> CheckResult:
        t0 = time.time()
        ip4, ip6, err = xray.probe_config(
            xray_bin, cfg, work_dir, http,
            per_request_timeout=per_request_timeout,
            overall_timeout=overall_timeout)
        res = CheckResult(fingerprint=cfg.fingerprint, ok=False,
                          checked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        if err:
            res.error = err
            return res
        res.ip4, res.ip6 = ip4, ip6
        if ip4:
            res.cc4, res.provider4 = geo.geolocate(http, ip4, geo_cache)
        if ip6:
            res.cc6, res.provider6 = geo.geolocate(http, ip6, geo_cache)
        res.ok = True
        res.error = ""
        log.info("check %s: ip4=%s(%s) ip6=%s(%s) %.1fs",
                 cfg.fingerprint[:60], res.ip4, res.cc4, res.ip6, res.cc6, time.time() - t0)
        return res

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_work, c): c for c in due}
        for fut in as_completed(futures):
            cfg = futures[fut]
            try:
                res = fut.result()
            except Exception as e:  # noqa: BLE001
                res = CheckResult(fingerprint=cfg.fingerprint, ok=False,
                                  error=f"unexpected: {e}",
                                  checked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            cache[res.fingerprint] = res
            done += 1
            if done % 25 == 0 or done == total:
                log.info("проверено %d/%d", done, total)
    return cache
