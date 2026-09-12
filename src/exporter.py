"""Формирование файлов подписок, статистики и Incy-ссылок."""

from __future__ import annotations

import base64
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models.config import VpnConfig

log = logging.getLogger(__name__)

WHITELIST_FILE = "vpn-whitelist-meeyota.txt"
WIFI_FILE = "vpn-wifi-meeyota.txt"

INCY_BEGIN = "<!-- INCY-LINKS:BEGIN (автоматически генерируется — не редактировать) -->"
INCY_END = "<!-- INCY-LINKS:END -->"

URI_LINE_RE = re.compile(r"^(vless|vmess|trojan|ss|ssr|hysteria2?|hy2?|tuic|socks5)://", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def pages_base_url(settings: Any) -> str:
    return f"https://{settings.pages_username}.github.io/{settings.pages_repository}"


def incy_add(url: str) -> str:
    return f"incy://add/{url}"


def incy_import(payload: str) -> str:
    return "incy://import/" + base64.b64encode(payload.encode("utf-8")).decode("ascii")


def count_uris(path: Path) -> int:
    """Число URI-строк в существующем файле подписки (для защиты от обнуления)."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if URI_LINE_RE.match(line.strip()))


def wipeout_ok(
    prev_count: int,
    new_count: int,
    min_configs: int,
    max_drop_ratio: float,
) -> tuple[bool, str]:
    """Защита от полного обнуления подписки при временной ошибке источников."""
    if new_count < min_configs:
        return False, f"найдено только {new_count} конфигов (минимум {min_configs})"
    if prev_count >= min_configs and new_count < prev_count * (1.0 - max_drop_ratio):
        return False, (
            f"список сократился с {prev_count} до {new_count} "
            f"(больше, чем на {int(max_drop_ratio * 100)}%) — вероятно, сбой источников"
        )
    return True, ""


def render_subscription(
    configs: list[VpnConfig],
    title: str,
    settings: Any,
    checked: dict[str, dict[str, Any]] | None = None,
    announce: str | None = None,
) -> str:
    """Собирает текст подписки (заголовок v2rayN + URI-строки)."""
    now = _now().strftime("%Y-%m-%d / %H:%M (UTC)")
    page = pages_base_url(settings)
    support = f"https://github.com/{settings.pages_username}/{settings.pages_repository}"
    protocols: dict[str, int] = {}
    for c in configs:
        protocols[c.protocol] = protocols.get(c.protocol, 0) + 1
    protos = ", ".join(f"{k}={v}" for k, v in sorted(protocols.items()))

    lines: list[str] = []
    lines.append(f"#profile-title: {title}")
    lines.append(f"#profile-update-interval: {settings.update_interval_hours}")
    lines.append(f"#profile-web-page-url: {page}")
    lines.append(f"#support-url: {support}")
    if announce:
        lines.append(f"#announce: {announce}")
    lines.append(f"# Date/Time: {now}")
    lines.append(f"# Количество: {len(configs)}")
    if protos:
        lines.append(f"# Протоколы: {protos}")
    lines.append("")

    for c in configs:
        if checked is not None:
            r = checked.get(c.hash)
            if r:
                lines.append(
                    f"# checked: {r.get('last_check')} | country: {r.get('country') or 'n/a'} "
                    f"| ip: {r.get('ip') or 'n/a'}"
                )
        lines.append(c.raw)
    return "\n".join(lines) + "\n"


def render_incy_links(settings: Any) -> str:
    """Блок ссылок incy://add/... для README и data/incy-links.txt."""
    page = pages_base_url(settings)
    return (
        "## 🔗 Ссылки для импорта в Incy\n"
        "\n"
        "Основной (приоритетный) способ — `incy://add/{url}`: клиент сам обновляет\n"
        "подписку на стороне GitHub Pages, повторный импорт не нужен.\n"
        "\n"
        f"**VPN whitelist meeyota** — {WHITELIST_FILE}\n"
        "\n"
        f"`{incy_add(page + '/' + WHITELIST_FILE)}`\n"
        "\n"
        f"**VPN Wi-fi meeyota** — {WIFI_FILE}\n"
        "\n"
        f"`{incy_add(page + '/' + WIFI_FILE)}`\n"
        "\n"
        "Одноразовый импорт содержимого (`incy://import/{base64}`) формируется\n"
        "опционально командой `python -m src.main --import-link data/incy-import-links.txt`\n"
        "(используется, когда `incy://add/{url}` недоступен).\n"
    )


def update_readme_links(readme_path: Path, block_text: str) -> bool:
    """Заменяет блок между маркерами INCY-LINKS. Возвращает True, если файл изменился."""
    block = f"{INCY_BEGIN}\n\n{block_text.strip()}\n\n{INCY_END}"
    try:
        text = Path(readme_path).read_text(encoding="utf-8")
    except OSError:
        return False
    pattern = re.compile(
        re.escape(INCY_BEGIN) + r".*?" + re.escape(INCY_END),
        re.DOTALL,
    )
    if pattern.search(text):
        new_text = pattern.sub(block.replace("\\", "\\\\"), text)
    else:
        new_text = text.rstrip() + "\n\n" + block + "\n"
    if new_text == text:
        return False
    Path(readme_path).write_text(new_text, encoding="utf-8")
    return True


def write_outputs(
    output_dir: Path,
    whitelist: list[VpnConfig],
    wifi: list[VpnConfig],
    settings: Any,
    check_results: dict[str, dict[str, Any]],
) -> dict[str, Path]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    wl_path = out / WHITELIST_FILE
    wf_path = out / WIFI_FILE

    announce_wl = (
        f"{len(whitelist)} конфигов · агрегация публичных источников · автообновление GitHub Actions"
    )
    wl = render_subscription(
        whitelist, "VPN Whitelist meeyota", settings, checked=None, announce=announce_wl
    )
    checked_map = {c.hash: check_results.get(c.hash, {}) for c in wifi}
    announce_wf = (
        f"{len(wifi)} проверенных серверов · внешний IP вне РФ (IPv4/IPv6) · "
        f"обновляется каждые {settings.update_interval_hours} ч"
    )
    wf = render_subscription(
        wifi, "VPN Wi-fi meeyota", settings, checked=checked_map, announce=announce_wf
    )
    wl_path.write_text(wl, encoding="utf-8")
    wf_path.write_text(wf, encoding="utf-8")
    return {"whitelist": wl_path, "wifi": wf_path}


def write_incy_links_file(path: Path, settings: Any) -> None:
    Path(path).write_text(render_incy_links(settings), encoding="utf-8")


def write_import_link_file(path: Path, output_dir: Path) -> None:
    """Файл с одноразовыми ссылками incy://import/{base64} (НЕ коммитится)."""
    lines = [
        "# Одноразовые ссылки импорта (содержимое подписок в base64).",
        "# Основной способ — incy://add/... (автоматическое обновление);",
        "# incy://import/... используется при необходимости. Ссылки актуальны",
        "# только для текущей версии файлов и не коммитятся в репозиторий.",
        "",
    ]
    for fname in (WHITELIST_FILE, WIFI_FILE):
        f = Path(output_dir) / fname
        try:
            payload = f.read_text(encoding="utf-8")
        except OSError:
            continue
        lines.append(f"{fname}:")
        lines.append(incy_import(payload))
        lines.append("")
    Path(path).write_text("\n".join(lines), encoding="utf-8")
