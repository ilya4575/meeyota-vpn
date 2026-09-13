"""
Симулятор импорта Incy: проверяет, как именно Incy отобразит содержимое подписки.

Поведение Incy (по официальной документации):
  - Если body — JSON-массив, каждый элемент = отдельный сервер.
  - Если body — JSON-объект с inbounds+outbounds = один full config = ОДИН сервер.
  - Если body — plain-text/base64 список URI = каждый URI = отдельный сервер.

Этот скрипт НЕ запускает реальный Incy (невозможно в CI), но точно моделирует
поведение парсера Incy по правилам из официальной документации.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


def simulate_incy_import(body: bytes) -> list[dict]:
    """
    Возвращает список «серверов», которые Incy создаст при импорте данного body.
    Каждый элемент содержит:
      - type: 'full_xray_config' | 'single_uri' | 'unknown'
      - name: имя сервера (как Incy его покажет)
      - details: дополнительная информация
    """
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []

    # === Try full Xray JSON ===
    parsed_json: object | None = None
    try:
        parsed_json = json.loads(text)
    except json.JSONDecodeError:
        # try base64
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="replace").strip()
            parsed_json = json.loads(decoded)
        except Exception:
            parsed_json = None

    servers: list[dict] = []

    if isinstance(parsed_json, list):
        # JSON ARRAY → каждый элемент = отдельный сервер
        for i, item in enumerate(parsed_json):
            if isinstance(item, dict) and "outbounds" in item and "inbounds" in item:
                name = _extract_full_config_name(item)
                servers.append(
                    {
                        "type": "full_xray_config",
                        "name": name,
                        "details": {"index": i, "outbounds_count": len(item.get("outbounds", []))},
                    }
                )
            else:
                servers.append(
                    {
                        "type": "unknown_json_array_item",
                        "name": f"<item #{i}>",
                        "details": {"index": i, "keys": list(item.keys()) if isinstance(item, dict) else None},
                    }
                )

    elif isinstance(parsed_json, dict):
        # JSON OBJECT → один full config (если есть inbounds+outbounds)
        if "outbounds" in parsed_json and "inbounds" in parsed_json:
            name = _extract_full_config_name(parsed_json)
            servers.append(
                {
                    "type": "full_xray_config",
                    "name": name,
                    "details": {
                        "outbounds_count": len(parsed_json.get("outbounds", [])),
                        "balancers": parsed_json.get("routing", {}).get("balancers", []),
                        "has_burst_observatory": "burstObservatory" in parsed_json,
                    },
                }
            )
        else:
            servers.append({"type": "unknown_json_object", "name": "<json>", "details": {"keys": list(parsed_json.keys())}})

    else:
        # Plain text → каждая непустая строка = отдельный сервер
        for i, line in enumerate(text.splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "://" in line:
                # extract name from #fragment
                name = line.split("#", 1)[1] if "#" in line else line[:50]
                servers.append({"type": "single_uri", "name": name, "details": {"scheme": line.split("://", 1)[0]}})

    return servers


def _extract_full_config_name(cfg: dict) -> str:
    """Точно так же, как это делает Incy: имя = тег первого proxy-outbound."""
    for ob in cfg.get("outbounds", []):
        proto = ob.get("protocol")
        if proto in ("freedom", "blackhole"):
            continue
        tag = ob.get("tag")
        if tag:
            return tag
    return "<unnamed>"


def validate_import_result(
    json_path: Path,
    expected_server_count: int,
    expected_names: list[str],
) -> None:
    print(f"\n=== Simulating Incy import of {json_path} ===\n")

    body = json_path.read_bytes()
    servers = simulate_incy_import(body)

    print(f"Incy would create {len(servers)} server(s) from this body:\n")
    for i, s in enumerate(servers):
        print(f"  [{i}] type={s['type']!r}, name={s['name']!r}")
        print(f"      details={s['details']}")

    print()
    actual_names = [s["name"] for s in servers]

    if len(servers) != expected_server_count:
        print(
            f"❌ FAIL: expected {expected_server_count} server(s), got {len(servers)}. "
            f"This means the body would import as multiple servers, which is exactly what we DON'T want."
        )
        sys.exit(1)

    print(f"✅ Exactly {expected_server_count} server(s) — matches expectation")

    for name in expected_names:
        if name not in actual_names:
            print(f"❌ FAIL: expected name {name!r} not found among server names: {actual_names}")
            sys.exit(1)

    print(f"✅ Server name(s) match: {actual_names}")

    # Critical: ensure no internal proxy-* names leaked as server names
    leaked = [n for n in actual_names if n.startswith("proxy-")]
    if leaked:
        print(f"❌ FAIL: internal proxy-* names leaked as server names: {leaked}")
        sys.exit(1)

    print(f"✅ No internal proxy-* names leaked as server names")


def main() -> None:
    if len(sys.argv) != 4:
        print(
            "Usage: simulate_incy_import.py <json-file> <expected-count> <expected-name>"
        )
        sys.exit(2)

    json_path = Path(sys.argv[1])
    expected_count = int(sys.argv[2])
    expected_name = sys.argv[3]

    if not json_path.is_file():
        print(f"❌ file not found: {json_path}")
        sys.exit(1)

    validate_import_result(json_path, expected_count, [expected_name])


if __name__ == "__main__":
    main()
