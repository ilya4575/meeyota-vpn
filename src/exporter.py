"""Экспорт: две подписки, JSON-состояние, Incy-ссылки, обновление README, guard от обнуления."""
from __future__ import annotations

import base64
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .checks.checker import CheckResult
from .config import Settings
from .models.config import VpnConfig

log = logging.getLogger("meeyota.export")

INCY_BEGIN = "<!-- meeyota:incy:begin -->"
INCY_END = "<!-- meeyota:incy:end -->"


@dataclass
class ExportResult:
    whitelist_written: bool = False
    wifi_written: bool = False
    aborted: List[str] = field(default_factory=list)
    whitelist_count: int = 0
    wifi_count: int = 0


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def _write_lines(path: Path, lines: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tmp.replace(path)


# ------------------------------------------------------------------ incy links
def pages_base_url(settings: Settings) -> str:
    """https://USERNAME.github.io/REPOSITORY/ — реальные значения из git remote/env,
    иначе плейсхолдеры (не подставляем выдуманный username)."""
    user, repo = settings.username, settings.repository
    if not (user and repo):
        try:
            out = subprocess.check_output(
                ["git", "remote", "get-url", "origin"],
                stderr=subprocess.DEVNULL, timeout=5).decode().strip()
            m = re.search(r"github\.com[/:]([^/]+)/([^/.]+)", out)
            if m:
                user, repo = user or m.group(1), repo or m.group(2)
        except (OSError, subprocess.SubprocessError):
            pass
    user = user or "USERNAME"
    repo = repo or "REPOSITORY"
    return f"https://{user.lower()}.github.io/{repo}/"


def incy_add_links(settings: Settings) -> Dict[str, str]:
    base = pages_base_url(settings)
    return {
        "whitelist": f"incy://add/{base}{settings.whitelist_file}",
        "wifi": f"incy://add/{base}{settings.wifi_file}",
    }


def incy_import_link(configs: List[VpnConfig]) -> str:
    """Вариант импорта «напрямую»: incy://import/{base64(json-массив конфигов)}.

    Основной способ — incy://add/{url} (подписка обновляется на GitHub Pages);
    import — запасной, фиксирует снапшот на момент генерации.
    """
    payload = [c.to_record() for c in configs]
    blob = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return "incy://import/" + base64.b64encode(blob).decode("ascii")


def update_readme_links(readme_path: Path, settings: Settings) -> bool:
    """Вставляет/обновляет блок с Incy-ссылками в README между маркерами."""
    if not readme_path.is_file():
        return False
    links = incy_add_links(settings)
    base = pages_base_url(settings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    block = f"""{INCY_BEGIN}
## 🔗 Ссылки для Incy (автогенерация — не редактировать вручную)

> Обновлено: {now} · ссылки пересобираются при каждом запуске генератора.

**Основной способ — подписка (incy://add).** Клиент сам обновляет список с GitHub Pages,
повторный импорт не нужен:

- **VPN whitelist meeyota** — весь агрегированный список:
  `{links["whitelist"]}`
- **VPN Wi-fi meeyota** — только проверенные конфигурации с внешним IP за пределами РФ:
  `{links["wifi"]}`

Прямые URL подписок (работают в любом клиенте с поддержкой подписок):

- `{base}{settings.whitelist_file}`
- `{base}{settings.wifi_file}`

<sub>Запасной способ `incy://import/{{base64}}` — одноразовый импорт снапшота;
генерируется командой `python -m src.main --incy-import`. Приоритет — у `incy://add`.</sub>
{INCY_END}"""
    text = readme_path.read_text(encoding="utf-8")
    if INCY_BEGIN in text and INCY_END in text:
        new = re.sub(re.escape(INCY_BEGIN) + r".*?" + re.escape(INCY_END),
                     block.replace("\\", "\\\\"), text, flags=re.S)
    else:
        new = text.rstrip() + "\n\n" + block + "\n"
    if new == text:
        return False
    readme_path.write_text(new, encoding="utf-8")
    return True


# ------------------------------------------------------------------- guard
def _guard_aborts(settings: Settings, wl_new: int, wifi_new: int,
                  checks_ran: bool, checks_ok: int) -> List[str]:
    """Защита от полного обнуления подписки при временной ошибке."""
    aborts: List[str] = []
    out = Path(settings.output_dir)
    prev_wl = _count_lines(out / settings.whitelist_file)
    prev_wifi = _count_lines(out / settings.wifi_file)

    if prev_wl >= settings.min_keep_abs:
        threshold = max(settings.min_keep_abs, int(prev_wl * settings.min_keep_ratio))
        if wl_new < threshold:
            aborts.append(
                f"whitelist: новый размер {wl_new} < {threshold} (было {prev_wl}) — "
                f"видимо, сбой источников; старые подписки сохраняются")

    if prev_wifi > 0 and wifi_new == 0:
        if not checks_ran:
            aborts.append(
                f"wifi: проверки не выполнялись, а список был бы пуст "
                f"(было {prev_wifi}) — сохраняем старые")
        elif checks_ok == 0:
            aborts.append(
                f"wifi: ни одна проверка не прошла успешно (было {prev_wifi}) — "
                f"возможна временная проблема; сохраняем старые")
    return aborts


# ------------------------------------------------------------------- export
def export(settings: Settings,
           whitelist: List[VpnConfig],
           wifi: List[VpnConfig],
           checks: Dict[str, CheckResult],
           *,
           checks_ran: bool,
           checks_ok: int,
           stats: Dict) -> ExportResult:
    out_dir = Path(settings.output_dir)
    data_dir = Path(settings.data_dir)
    res = ExportResult(whitelist_count=len(whitelist), wifi_count=len(wifi))

    # 1) данные (state) — всегда обновляем, если не dry-run
    if not settings.dry_run:
        data_dir.mkdir(parents=True, exist_ok=True)
        # подтягиваем last_check/country/ip в записи
        for cfg in whitelist:
            r = checks.get(cfg.fingerprint)
            if r and r.ok:
                cfg.last_check = r.checked_at
                cfg.country = r.cc4
                cfg.ip = r.ip4
        (data_dir / "configs.json").write_text(
            json.dumps([c.to_record() for c in whitelist], ensure_ascii=False, indent=1),
            encoding="utf-8")
        (data_dir / "checks.json").write_text(
            json.dumps({k: v.to_dict() for k, v in checks.items()},
                       ensure_ascii=False, indent=1),
            encoding="utf-8")
        stats["data_saved_at"] = datetime.now(timezone.utc).isoformat()

    # 2) guard от обнуления
    aborts = _guard_aborts(settings, len(whitelist), len(wifi), checks_ran, checks_ok)
    res.aborted = aborts
    for a in aborts:
        log.critical("GUARD: %s", a)

    # 3) подписки
    if not settings.dry_run:
        if "whitelist:" not in " ".join(aborts):
            _write_lines(out_dir / settings.whitelist_file, [c.raw for c in whitelist])
            res.whitelist_written = True
        else:
            log.warning("whitelist НЕ перезаписан (guard)")
        wifi_aborted = "wifi:" in " ".join(aborts)
        if not wifi_aborted and wifi:
            _write_lines(out_dir / settings.wifi_file, [c.raw for c in wifi])
            res.wifi_written = True
        elif not wifi_aborted and not wifi:
            # первый запуск и проверок ещё нет — пишем пустой файл, чтобы URL существовал
            _write_lines(out_dir / settings.wifi_file, [])
            res.wifi_written = True
            log.warning("wifi-подписка пуста (проверок ещё не было/все отфильтрованы)")
        else:
            log.warning("wifi НЕ перезаписан (guard)")

    # 4) incy-ссылки в README
    res_readme = update_readme_links(Path(settings.readme_path), settings)
    stats["readme_links_updated"] = res_readme
    return res
