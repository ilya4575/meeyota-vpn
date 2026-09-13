"""Генерация full Xray JSON для Incy.

Ключевая идея: ОДИН JSON-объект → Incy показывает как ОДИН сервер в UI.
Имя сервера берётся из тега ПЕРВОГО proxy-outbound (документация Incy).
Все остальные outbounds имеют теги proxy-1, proxy-2, … и НЕ отображаются.

Balancer и burstObservatory используют prefix-match для включения
всех proxy-* outbounds в пул автоселекта.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.config import VpnConfig


# Балансировщик использует стратегию leastLoad + burstObservatory.
# Это документированная комбинация (https://github.com/XTLS/Xray-core/discussions/3138).
DEFAULT_BALANCER_TAG = "meeyota-auto"

DEFAULT_BURST_OBSERVATORY = {
    "destination": "http://www.google.com/generate_204",
    "connectivity": "http://www.google.com/generate_204",
    "interval": "30s",
    "sampling": 2,
    "timeout": "5s",
}


def _vnext_outbound(cfg: VpnConfig) -> dict[str, Any]:
    """VLESS → Xray outbound."""
    ob: dict[str, Any] = {
        "tag": cfg.params.get("__tag__", "proxy"),
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": cfg.host,
                    "port": cfg.port,
                    "users": [
                        {
                            "id": cfg.protocol_data["uuid"],
                            "encryption": cfg.params.get("encryption", "none"),
                        }
                    ],
                }
            ]
        },
    }
    if flow := cfg.params.get("flow"):
        ob["settings"]["vnext"][0]["users"][0]["flow"] = flow
    _apply_stream_settings(ob, cfg)
    return ob


def _vmess_outbound(cfg: VpnConfig) -> dict[str, Any]:
    ob: dict[str, Any] = {
        "tag": cfg.params.get("__tag__", "proxy"),
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": cfg.host,
                    "port": cfg.port,
                    "users": [
                        {
                            "id": cfg.protocol_data["uuid"],
                            "alterId": int(cfg.protocol_data.get("alterId", 0) or 0),
                            "security": cfg.params.get("encryption", "auto"),
                        }
                    ],
                }
            ]
        },
    }
    _apply_stream_settings(ob, cfg)
    return ob


def _trojan_outbound(cfg: VpnConfig) -> dict[str, Any]:
    ob: dict[str, Any] = {
        "tag": cfg.params.get("__tag__", "proxy"),
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": cfg.host,
                    "port": cfg.port,
                    "password": cfg.protocol_data["password"],
                }
            ]
        },
    }
    _apply_stream_settings(ob, cfg)
    return ob


def _ss_outbound(cfg: VpnConfig) -> dict[str, Any]:
    ob: dict[str, Any] = {
        "tag": cfg.params.get("__tag__", "proxy"),
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": cfg.host,
                    "port": cfg.port,
                    "method": cfg.protocol_data["method"],
                    "password": cfg.protocol_data.get("password", ""),
                }
            ]
        },
    }
    _apply_stream_settings(ob, cfg)
    return ob


def _hy2_outbound(cfg: VpnConfig) -> dict[str, Any]:
    ob: dict[str, Any] = {
        "tag": cfg.params.get("__tag__", "proxy"),
        "protocol": "hysteria2",
        "settings": {
            "servers": [
                {
                    "address": cfg.host,
                    "port": cfg.port,
                    "password": cfg.protocol_data["password"],
                }
            ]
        },
    }
    _apply_stream_settings(ob, cfg)
    return ob


def _apply_stream_settings(ob: dict, cfg: VpnConfig) -> None:
    """Применяет transport / security из params к outbound'у."""
    security = cfg.params.get("security", "")
    network = cfg.params.get("type", "tcp")

    stream: dict[str, Any] = {"network": network or "tcp"}
    if security in ("tls", "reality"):
        stream["security"] = security
        tls: dict[str, Any] = {}
        sni = cfg.params.get("sni") or cfg.params.get("host")
        if sni:
            tls["serverName"] = sni
        if cfg.params.get("alpn"):
            tls["alpn"] = cfg.params.get("alpn").split(",")
        if cfg.params.get("allowInsecure") in ("1", "true", "yes"):
            tls["allowInsecure"] = True
        elif cfg.params.get("allowInsecure") in ("0", "false", "no"):
            tls["allowInsecure"] = False
        if cfg.params.get("fp"):
            tls["fingerprint"] = cfg.params.get("fp")
        if security == "reality":
            reality: dict[str, Any] = {}
            if pbk := cfg.params.get("pbk"):
                reality["publicKey"] = pbk
            if sid := cfg.params.get("sid"):
                reality["shortId"] = sid
            if cfg.params.get("spx"):
                reality["spiderX"] = cfg.params.get("spx")
            if reality:
                tls["realitySettings"] = reality
        if tls:
            stream["security"] = security
            stream[f"{security}Settings"] = tls
    elif security == "" or security == "none":
        stream["security"] = "none"

    # ws / grpc / xhttp
    if network == "ws":
        ws: dict[str, Any] = {}
        if path := cfg.params.get("path"):
            ws["path"] = path
        if host_h := cfg.params.get("host"):
            ws["headers"] = {"Host": host_h}
        if ws:
            stream["wsSettings"] = ws
    elif network == "grpc":
        grpc: dict[str, Any] = {}
        if sn := cfg.params.get("serviceName"):
            grpc["serviceName"] = sn
        if mode := cfg.params.get("mode"):
            grpc["mode"] = mode
        if grpc:
            stream["grpcSettings"] = grpc
    elif network == "xhttp":
        xh: dict[str, Any] = {}
        if path := cfg.params.get("path"):
            xh["path"] = path
        if mode := cfg.params.get("mode"):
            xh["mode"] = mode
        if xh:
            stream["xhttpSettings"] = xh

    ob["streamSettings"] = stream


def _vpn_config_to_outbound(cfg: VpnConfig, tag: str) -> dict[str, Any] | None:
    cfg.params["__tag__"] = tag
    try:
        if cfg.scheme == "vless":
            return _vnext_outbound(cfg)
        if cfg.scheme == "vmess":
            return _vmess_outbound(cfg)
        if cfg.scheme == "trojan":
            return _trojan_outbound(cfg)
        if cfg.scheme == "ss":
            return _ss_outbound(cfg)
        if cfg.scheme == "hysteria2":
            return _hy2_outbound(cfg)
    except (KeyError, ValueError):
        return None
    return None


def build_full_xray_config(
    configs: list,
    profile_name: str,
    burst_interval: str = "30s",
) -> dict[str, Any]:
    """Собирает full Xray JSON: один объект с inbounds+outbounds+balancer+observatory.

    Args:
        configs: список VpnConfig (уже валидных и нормализованных)
        profile_name: имя профиля (попадёт в tag первого outbound'а)
        burst_interval: интервал burstObservatory (для wifi — 60s, для whitelist — 30s)

    Returns:
        dict — JSON-сериализуемый full Xray config
    """
    outbounds: list[dict] = []
    proxy_tags: list[str] = []

    # Первый outbound — с тегом = profile_name (это имя, которое Incy покажет)
    if configs:
        first = configs[0]
        ob = _vpn_config_to_outbound(first, profile_name)
        if ob is not None:
            outbounds.append(ob)
            proxy_tags.append(profile_name)

    # Остальные — proxy-1, proxy-2, …, proxy-N
    for i, cfg in enumerate(configs[1:], start=1):
        tag = f"proxy-{i}"
        ob = _vpn_config_to_outbound(cfg, tag)
        if ob is not None:
            outbounds.append(ob)
            proxy_tags.append(tag)

    # Системные outbounds
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    # Если профиль пустой — всё равно добавим минимальную валидную структуру,
    # чтобы Xray не падал. Incy покажет один сервер, но он будет нерабочим.
    # (вызывающий код должен предотвратить эту ситуацию через safety-checks)

    # Balancer: префиксный матч для всех proxy-* + profile_name
    selectors = [profile_name, "proxy-"]

    burst_obs = dict(DEFAULT_BURST_OBSERVATORY)
    burst_obs["interval"] = burst_interval

    return {
        "log": {"loglevel": "warning"},
        "dns": {
            "servers": [
                "https://1.1.1.1/dns-query",
                "https://8.8.8.8/dns-query",
            ],
            "queryStrategy": "UseIP",
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],
        "outbounds": outbounds,
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "domainMatcher": "hybrid",
            "rules": [
                # DNS-серверы напрямую (предотвращает цикл с observatory)
                {
                    "type": "field",
                    "ip": ["1.1.1.1", "8.8.8.8"],
                    "outboundTag": "direct",
                },
                # Весь остальной трафик → через balancer (автоселект)
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": DEFAULT_BALANCER_TAG,
                },
            ],
            "balancers": [
                {
                    "tag": DEFAULT_BALANCER_TAG,
                    "selector": selectors,
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "expected": 2,
                            "maxRTT": "1s",
                            "tolerance": 0.01,
                            "baselines": ["300ms", "1s"],
                        },
                    },
                    "fallbackTag": "direct",
                }
            ],
        },
        "burstObservatory": {
            "subjectSelector": selectors,
            "pingConfig": burst_obs,
        },
        "stats": {},
        "policy": {
            "levels": [
                {
                    "handshake": 2,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                }
            ]
        },
    }


def render_json(cfg: dict, indent: int = 2) -> bytes:
    return json.dumps(cfg, indent=indent, ensure_ascii=False).encode("utf-8")
