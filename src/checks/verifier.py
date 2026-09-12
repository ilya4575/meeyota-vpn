"""Оркестрация проверок для подписки «VPN Wi-fi meeyota».

Правила включения в подписку (строгие):
    1. устанавливается реальное соединение с конфигурацией (sing-box);
    2. определяется фактический внешний IPv4 (и, если есть, IPv6);
    3. страна каждого IP определяется через геолокационные API;
    4. если IPv4 или IPv6 определяется как RU — конфиг НЕ включается;
    5. если IPv4 и IPv6 дают РАЗНЫЕ страны — конфликт, конфиг НЕ включается;
    6. если страна не определена (оба API молчат) — НЕ включается
       (нет подтверждения «вне РФ»);
    7. дата последней проверки и результат сохраняются
       (data/check_results.json и в заголовках строк подписки).

Оптимизация: все конфигурации одного сервера (адрес:порт) имеют один
выходной IP, поэтому проверка выполняется один раз на сервер, а результат
применяется ко всем его конфигурациям.

Кэширование: результаты серверов живут ``check_ttl_days`` дней;
остальные серверы проверяются в пределах бюджета времени
(``check_minutes``) — остаток дойдёт до проверки в следующих запусках.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from typing import Any

from ..models.config import VpnConfig
from .connectivity import probe_config
from .geolocation import GeoLookup

log = logging.getLogger(__name__)

VERDICT_OK = "ok"          # вне РФ, IPv4/IPv6 согласованы
VERDICT_RU = "ru"          # обнаружен выход в РФ
VERDICT_CONFLICT = "conflict"  # IPv4 и IPv6 дают разные страны
VERDICT_ERROR = "error"    # соединение не установлено / страна не определена

# порядок попыток внутри одного сервера: сначала самые «надёжные» протоколы
PROTO_PRIORITY = {
    "vless": 0,
    "trojan": 1,
    "ss": 2,
    "hysteria2": 3,
    "vmess": 4,
    "tuic": 5,
    "hysteria": 6,
    "socks5": 7,
}
MAX_ATTEMPTS_PER_SERVER = 3


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value: str) -> float:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return 0.0


@dataclass
class CheckResults:
    """Хранилище результатов проверок (JSON, коммитится в репозиторий)."""

    groups: dict[str, dict[str, Any]] = field(default_factory=dict)    # "addr:port" -> результат
    configs: dict[str, dict[str, Any]] = field(default_factory=dict)   # hash -> результат

    @classmethod
    def load(cls, path: Path) -> "CheckResults":
        res = cls()
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                res.groups = {k: v for k, v in (data.get("groups") or {}).items() if isinstance(v, dict)}
                res.configs = {k: v for k, v in (data.get("configs") or {}).items() if isinstance(v, dict)}
        except (OSError, ValueError):
            pass
        return res

    def save(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"version": 1, "groups": self.groups, "configs": self.configs}
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, path)
        except OSError as e:
            log.warning("не удалось сохранить результаты проверок: %s", e)


def group_configs(configs: list[VpnConfig]) -> dict[str, list[VpnConfig]]:
    groups: dict[str, list[VpnConfig]] = {}
    for c in configs:
        groups.setdefault(c.server_key, []).append(c)
    return groups


def _judge(
    ip4: str | None, ip6: str | None, c4: str | None, c6: str | None
) -> tuple[str, str | None, str | None, str]:
    """Строгое решение по результатам проверки одного сервера."""
    if ip4 is None and ip6 is None:
        return VERDICT_ERROR, None, None, "соединение не установлено"
    if c4 == "RU" or c6 == "RU":
        return VERDICT_RU, c4 or c6, ip4 or ip6, "внешний IP определяется как РФ"
    if c4 is None and c6 is None:
        return VERDICT_ERROR, None, ip4 or ip6, "геолокация не определила страну"
    if c4 and c6 and c4 != c6:
        return VERDICT_CONFLICT, None, None, f"конфликт стран: IPv4={c4}, IPv6={c6}"
    return VERDICT_OK, c4 or c6, ip4 or ip6, ""


def verify(
    configs: list[VpnConfig],
    settings: Any,
    results: CheckResults,
    singbox_bin: str | None,
    workers: int | None = None,
    minutes: float | None = None,
) -> dict[str, Any]:
    """Проверяет серверы конфигов (с кэшем и бюджетом времени).

    :return: статистика: {due, cached, checked, verdicts: {...}, errors, skipped}
    """
    workers = int(workers or settings.check_workers)
    minutes = float(minutes if minutes is not None else settings.check_minutes)
    ttl = float(settings.check_ttl_days) * 86400
    now = time.time()

    groups = group_configs(configs)
    due: list[tuple[str, list[VpnConfig]]] = []
    for key, gcfgs in groups.items():
        g = results.groups.get(key)
        if g and (now - _parse_iso(str(g.get("checked_at", "")))) < ttl:
            continue  # свежий кэш
        due.append((key, gcfgs))

    # сначала серверы с большим числом конфигов — равномернее покрываем список
    due.sort(key=lambda kv: -len(kv[1]))
    deadline = now + minutes * 60

    stats: dict[str, Any] = {
        "total_servers": len(groups),
        "due": len(due),
        "cached": len(groups) - len(due),
        "checked": 0,
        "skipped": 0,
        "errors": 0,
        "verdicts": {VERDICT_OK: 0, VERDICT_RU: 0, VERDICT_CONFLICT: 0, VERDICT_ERROR: 0},
    }

    if not singbox_bin:
        log.warning("sing-box не найден — новые проверки пропущены (используется кэш)")
        stats["skipped"] = len(due)
        stats["no_singbox"] = True
        return stats

    geo_cache_path = Path(settings.data_dir) / "geo_cache.json"
    geo = GeoLookup(
        cache_path=geo_cache_path,
        ttl_days=settings.geo_ttl_days,
        max_entries=settings.geo_cache_max,
    )

    q: Queue[tuple[str, list[VpnConfig]] | None] = Queue()
    for item in due:
        q.put(item)

    lock = threading.Lock()
    base_port = 18100

    def worker(worker_idx: int) -> None:
        port = base_port + (worker_idx % 48) * 10
        while True:
            item = q.get()
            try:
                if item is None:
                    return
                key, gcfgs = item
                if time.time() > deadline:
                    stats["skipped"] += 1
                    continue
                c4 = c6 = None
                ip4 = ip6 = None
                detail = ""
                candidates = sorted(
                    gcfgs,
                    key=lambda c: (PROTO_PRIORITY.get(c.protocol, 9), c.hash),
                )
                for cand in candidates[:MAX_ATTEMPTS_PER_SERVER]:
                    ip4, ip6, detail = probe_config(cand, singbox_bin, port, timeout=25)
                    if ip4 or ip6:
                        break
                if ip4 is None and ip6 is None:
                    verdict, country, egress, _ = _judge(None, None, None, None)
                    detail = f"соединение не установлено: {detail}" if detail else "соединение не установлено"
                else:
                    if ip4:
                        c4 = geo.country(ip4)
                    if ip6:
                        c6 = geo.country(ip6)
                    verdict, country, egress, detail = _judge(ip4, ip6, c4, c6)
                with lock:
                    results.groups[key] = {
                        "checked_at": _now_iso(),
                        "ip4": ip4,
                        "ip6": ip6,
                        "ip4_country": c4,
                        "ip6_country": c6,
                        "country": country,
                        "ip": egress,
                        "verdict": verdict,
                        "detail": detail,
                    }
                    stamp = _now_iso()
                    for c in gcfgs:
                        results.configs[c.hash] = {
                            "last_check": stamp,
                            "ip": egress,
                            "country": country,
                            "verdict": verdict,
                        }
                    stats["checked"] += 1
                    stats["verdicts"][verdict] = stats["verdicts"].get(verdict, 0) + 1
                log.info(
                    "server %s: %s (ip4=%s/%s ip6=%s/%s)%s",
                    key, verdict, ip4, c4, ip6, c6,
                    f" — {detail}" if detail else "",
                )
            except Exception as e:  # noqa: BLE001 — не роняем весь батч
                log.exception("ошибка проверки сервера: %s", e)
                with lock:
                    stats["errors"] += 1
            finally:
                q.task_done()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    for _ in range(workers):
        q.put(None)
    for t in threads:
        t.join(timeout=minutes * 60 + 300)

    _cap_results(results, settings)
    geo.save()
    return stats


def _cap_results(results: CheckResults, settings: Any) -> None:
    """Ограничиваем размер хранилища результатов (самые старые — выбрасываются)."""
    max_groups = int(settings.results_max_groups)
    if len(results.groups) > max_groups:
        items = sorted(results.groups.items(), key=lambda kv: _parse_iso(str(kv[1].get("checked_at", ""))))
        for key, _ in items[: len(results.groups) - max_groups]:
            results.groups.pop(key, None)
    max_configs = int(settings.results_max_configs)
    if len(results.configs) > max_configs:
        items = sorted(results.configs.items(), key=lambda kv: _parse_iso(str(kv[1].get("last_check", ""))))
        for key, _ in items[: len(results.configs) - max_configs]:
            results.configs.pop(key, None)


def check_stats_dict(stats: dict[str, Any]) -> dict[str, Any]:
    """Нормализованная статистика для data/stats.json."""
    return {k: v for k, v in stats.items()}
