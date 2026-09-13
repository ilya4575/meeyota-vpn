"""
Валидатор структуры full Xray JSON для Incy.

Проверяет, что итоговая подписка соответствует требованиям:
- ровно ОДИН JSON-объект (не массив) → Incy отображает как ОДИН сервер;
- содержит inbounds + outbounds → детектируется как full config;
- первый proxy-outbound имеет имя, равное ожидаемому имени профиля;
- balancer использует prefix-match для включения всех proxy-* outbounds;
- burstObservatory ссылается на те же теги;
- fallbackTag задан (иначе Xray-core падает на первый outbound);
- нет outbounds, которые НЕ входят в balancer.selector и НЕ direct/block.

Использование:
    python tests/validate_incy_profile.py path/to/profile.json "Expected Profile Name"
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_PROTOCOLS_DIRECT = {"freedom"}
REQUIRED_PROTOCOLS_BLOCK = {"blackhole"}
ALLOWED_SYSTEM_TAGS = {"direct", "block"}


def fail(msg: str) -> None:
    print(f"❌ FAIL: {msg}")
    sys.exit(1)


def ok(msg: str) -> None:
    print(f"✅ {msg}")


def validate_profile(json_path: Path, expected_name: str) -> None:
    print(f"\n=== Validating {json_path} for profile '{expected_name}' ===\n")

    try:
        cfg = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        fail(f"invalid JSON: {e}")

    # === Top-level structure ===
    if not isinstance(cfg, dict):
        fail("top-level must be a JSON OBJECT (not array) — arrays are imported as multiple servers")

    ok("top-level is a JSON object (not array)")

    if "inbounds" not in cfg or "outbounds" not in cfg:
        fail("missing 'inbounds' or 'outbounds' — Incy will not detect this as a full config")

    ok("has 'inbounds' AND 'outbounds' (detected as full Xray config)")

    if not isinstance(cfg["inbounds"], list) or not cfg["inbounds"]:
        fail("'inbounds' must be a non-empty array")
    if not isinstance(cfg["outbounds"], list) or not cfg["outbounds"]:
        fail("'outbounds' must be a non-empty array")

    # === Outbounds ===
    outbounds = cfg["outbounds"]
    proxy_tags: list[str] = []
    system_tags: list[str] = []
    first_proxy_tag: str | None = None

    for i, ob in enumerate(outbounds):
        if "tag" not in ob:
            fail(f"outbound #{i} has no 'tag'")
        if "protocol" not in ob:
            fail(f"outbound #{i} ({ob.get('tag')}) has no 'protocol'")
        tag = ob["tag"]
        proto = ob["protocol"]
        if proto in REQUIRED_PROTOCOLS_DIRECT or tag in ALLOWED_SYSTEM_TAGS and proto == "freedom":
            system_tags.append(tag)
            continue
        if proto in REQUIRED_PROTOCOLS_BLOCK:
            system_tags.append(tag)
            continue
        proxy_tags.append(tag)
        if first_proxy_tag is None:
            first_proxy_tag = tag

    if not proxy_tags:
        fail("no proxy outbounds (vless/vmess/trojan/ss/hy2) found")

    ok(f"found {len(proxy_tags)} proxy outbounds and {len(system_tags)} system outbounds")

    # === Expected name is the tag of the first proxy outbound ===
    if first_proxy_tag != expected_name:
        fail(
            f"first proxy outbound tag is '{first_proxy_tag}', "
            f"but expected profile name is '{expected_name}'. "
            f"Incy will display the tag of the first proxy-outbound as the server name."
        )
    ok(f"first proxy outbound tag = '{expected_name}' (Incy will show this as the server name)")

    # === Routing / balancer ===
    routing = cfg.get("routing")
    if not routing:
        fail("missing 'routing' — balancer won't work")
    balancers = routing.get("balancers")
    if not balancers:
        fail("routing.balancers is empty — no automatic selection")
    if not isinstance(balancers, list) or len(balancers) != 1:
        fail(f"expected exactly 1 balancer, found {len(balancers) if isinstance(balancers, list) else 'non-list'}")
    balancer = balancers[0]

    ok(f"found exactly 1 balancer (tag={balancer.get('tag')!r})")

    if balancer.get("fallbackTag") not in ALLOWED_SYSTEM_TAGS and balancer.get("fallbackTag") not in proxy_tags:
        fail(
            f"balancer.fallbackTag={balancer.get('fallbackTag')!r} must reference an existing "
            f"system outbound (direct/block) or a proxy outbound to avoid silent failure"
        )
    ok(f"balancer.fallbackTag = {balancer.get('fallbackTag')!r} (no silent failure)")

    strategy = balancer.get("strategy", {})
    strat_type = strategy.get("type")
    if strat_type not in {"leastPing", "leastLoad", "roundRobin", "random"}:
        fail(f"balancer.strategy.type={strat_type!r} not in known set")
    ok(f"balancer.strategy.type = {strat_type!r}")

    # === Verify every proxy outbound is covered by balancer selector ===
    # Xray balancer selector works as prefix-match. Verify all proxy_tags are matched.
    selectors: list[str] = balancer.get("selector", [])
    if not selectors:
        fail("balancer.selector is empty")

    unmatched: list[str] = []
    for tag in proxy_tags:
        if not any(tag.startswith(s) or tag == s for s in selectors):
            unmatched.append(tag)
    if unmatched:
        fail(
            f"these proxy outbounds are NOT covered by balancer.selector={selectors!r}: "
            f"{unmatched}. They will be orphaned (not load-balanced)."
        )
    ok(f"all {len(proxy_tags)} proxy outbounds are covered by balancer.selector={selectors!r}")

    # === burstObservatory ===
    if "burstObservatory" not in cfg and "observatory" not in cfg:
        fail("missing 'burstObservatory' or 'observatory' — leastPing/leastLoad will not have data to choose from")
    obs = cfg.get("burstObservatory") or cfg.get("observatory")
    obs_subj = obs.get("subjectSelector", []) if isinstance(obs, dict) else []
    if not obs_subj:
        fail("observatory/burstObservatory.subjectSelector is empty")
    obs_unmatched = [t for t in proxy_tags if not any(t.startswith(s) or t == s for s in obs_subj)]
    if obs_unmatched:
        fail(
            f"these proxy outbounds are NOT covered by observatory.subjectSelector={obs_subj!r}: "
            f"{obs_unmatched}. Their health will not be monitored."
        )
    ok(
        f"all {len(proxy_tags)} proxy outbounds are covered by "
        f"{'burstObservatory' if 'burstObservatory' in cfg else 'observatory'}.subjectSelector={obs_subj!r}"
    )

    # === Rules must route traffic through balancer ===
    rules = routing.get("rules", [])
    if not rules:
        fail("routing.rules is empty — traffic won't be routed to balancer")

    balancer_tag = balancer.get("tag")
    rule_uses_balancer = any(r.get("balancerTag") == balancer_tag for r in rules if isinstance(r, dict))
    if not rule_uses_balancer:
        fail(f"no routing rule references balancerTag={balancer_tag!r} — traffic will not go through balancer")
    ok(f"at least one routing rule references balancerTag={balancer_tag!r}")

    # === DNS ===
    if "dns" in cfg and cfg["dns"].get("servers"):
        ok(f"dns.servers configured: {cfg['dns']['servers']}")
    else:
        print("⚠️  WARN: dns.servers is empty — Incy may inject its own (which is OK)")

    # === stats (Incy auto-adds if burstObservatory exists, but we set it explicitly) ===
    if "stats" in cfg:
        ok("'stats' object present")

    print(f"\n✅ {json_path.name} is structurally valid for Incy as a SINGLE full Xray config profile\n")


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: validate_incy_profile.py <json-file> <expected-profile-name>")
        sys.exit(2)

    json_path = Path(sys.argv[1])
    expected_name = sys.argv[2]

    if not json_path.is_file():
        fail(f"file not found: {json_path}")

    validate_profile(json_path, expected_name)


if __name__ == "__main__":
    main()
