"""Реальная проверка соединения: sing-box как локальный микс-прокси.

Алгоритм:
    1. по нормализованной конфигурации собирается клиентский конфиг sing-box
       (outbound протокола + mixed-inbound на 127.0.0.1);
    2. запускается ``sing-box run -c client.json``;
    3. через прокси ``curl -4`` / ``curl -6`` запрашивается внешний IP;
    4. процесс завершается.

Возвращаемый результат: (ip4, ip6, detail) — где часть полей может быть None
(нет IPv4-выхода / нет IPv6-выхода).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from ..models.config import VpnConfig
from ..parsers.uri import NON_SINGBOX_TRANSPORTS

log = logging.getLogger(__name__)

class UnsupportedProtocol(Exception):
    """Протокол нельзя проверить через sing-box."""


# Сервисы определения внешнего IP (проверяем через прокси)
EGRESS_V4_URLS = [
    "https://api.ipify.org?format=json",
    "https://api.my-ip.io/v2/ip.txt",
]
EGRESS_V6_URLS = [
    "https://api6.ipify.org?format=json",
    "https://api.my-ip.io/v2/ip.txt",
]

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------------------
# Сборка конфига sing-box
# ---------------------------------------------------------------------------

def _transport(p: dict[str, Any]) -> dict[str, Any] | None:
    t = (p.get("type") or p.get("net") or "tcp").lower()
    if t == "ws":
        tr: dict[str, Any] = {"type": "websocket"}
        if p.get("path"):
            tr["path"] = p["path"]
        if p.get("host"):
            tr["headers"] = {"Host": p["host"]}
        return tr
    if t == "grpc":
        return {
            "type": "grpc",
            "service_name": p.get("serviceName") or p.get("path") or "",
        }
    if t in ("http", "h2"):
        tr = {"type": "http"}
        if t == "h2":
            hosts = [h for h in (p.get("host"), p.get("sni")) if h]
            if hosts:
                tr["host"] = hosts
        else:
            if p.get("path"):
                tr["path"] = p["path"]
            if p.get("host"):
                tr["headers"] = {"Host": p["host"]}
        return tr
    return None


def _tls(p: dict[str, Any], cfg: VpnConfig, default_server_name: str | None = None) -> dict[str, Any]:
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": p.get("sni") or default_server_name or cfg.address,
        "insecure": bool(p.get("insecure")),
    }
    fp = (p.get("fp") or "").lower()
    if fp and fp not in ("unsafe", "random"):
        tls["fingerprint"] = fp
    if p.get("alpn"):
        tls["alpn"] = list(p["alpn"])
    if p.get("security") == "reality":
        tls["reality"] = {
            "enabled": True,
            "public_key": p.get("pbk") or "",
            "short_id": p.get("sid") or "",
        }
    return tls


def build_singbox_outbound(cfg: VpnConfig) -> dict[str, Any]:
    """Outbound sing-box (v1.x, плоская схема server/server_port)."""
    p = cfg.params
    proto = cfg.protocol

    # xhttp / httpupgrade поддерживаются xray/v2rayN/Incy, но не sing-box —
    # конфиг остаётся в whitelist, но проверить его для Wi-fi нечем.
    transport = (p.get("type") or p.get("net") or "tcp").lower()
    if transport in NON_SINGBOX_TRANSPORTS:
        raise UnsupportedProtocol(f"транспорт {transport} не поддерживается sing-box")

    if proto == "vless":
        out: dict[str, Any] = {
            "type": "vless",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "uuid": p.get("uuid", ""),
        }
        if p.get("flow"):
            out["flow"] = p["flow"]
        if p.get("security") in ("tls", "reality"):
            out["tls"] = _tls(p, cfg)
        tr = _transport(p)
        if tr:
            out["transport"] = tr
        return out

    if proto == "vmess":
        out = {
            "type": "vmess",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "uuid": p.get("uuid", ""),
            "alter_id": int(p.get("aid") or 0),
            "security": p.get("scy") or "auto",
        }
        if p.get("tls"):
            out["tls"] = _tls(p, cfg)
        tr = _transport(p)
        if tr:
            out["transport"] = tr
        return out

    if proto == "trojan":
        out = {
            "type": "trojan",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "password": p.get("password", ""),
        }
        out["tls"] = _tls(p, cfg)
        tr = _transport(p)
        if tr:
            out["transport"] = tr
        return out

    if proto == "ss":
        return {
            "type": "shadowsocks",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "method": p.get("method", "aes-256-gcm"),
            "password": p.get("password", ""),
        }

    if proto == "hysteria2":
        out = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
        }
        if p.get("password"):
            out["password"] = p["password"]
        if p.get("auth"):
            out["authentication"] = p["auth"]
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": p.get("sni") or cfg.address,
            "insecure": bool(p.get("insecure")),
        }
        if p.get("pinsha256"):
            tls["pins"] = [p["pinsha256"]]
        out["tls"] = tls
        return out

    if proto == "tuic":
        out = {
            "type": "tuic",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "uuid": p.get("uuid", ""),
            "congestion_control": p.get("congestion_control") or "bbr",
            "zero_rtt_handshake": True,
        }
        if p.get("password"):
            out["password"] = p["password"]
        tls = {
            "enabled": True,
            "server_name": p.get("sni") or cfg.address,
            "insecure": bool(p.get("insecure")),
        }
        if p.get("alpn"):
            tls["alpn"] = list(p["alpn"])
        out["tls"] = tls
        return out

    if proto == "socks5":
        out = {
            "type": "socks",
            "tag": "proxy",
            "server": cfg.address,
            "server_port": cfg.port,
            "version": "5",
        }
        if p.get("username"):
            out["username"] = p["username"]
        if p.get("password"):
            out["password"] = p["password"]
        return out

    raise UnsupportedProtocol(f"sing-box не поддерживает проверку протокола: {proto}")


def build_singbox_config(cfg: VpnConfig, mixed_port: int) -> dict[str, Any]:
    """Полный клиентский конфиг sing-box: mixed-inbound + outbound."""
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": int(mixed_port),
            }
        ],
        "outbounds": [
            build_singbox_outbound(cfg),
            {"type": "direct", "tag": "direct"},
        ],
    }


def singbox_available(singbox_bin: str | None = None) -> str | None:
    """Путь к бинарнику sing-box или None."""
    candidate = singbox_bin or os.environ.get("SINGBOX_BIN") or shutil.which("sing-box")
    if candidate and Path(candidate).exists():
        return candidate
    return None


# ---------------------------------------------------------------------------
# Пропуск трафика
# ---------------------------------------------------------------------------

def _wait_port(host: str, port: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def _terminate(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except (subprocess.SubprocessError, OSError):
        try:
            proc.kill()
        except OSError:
            pass
    try:
        if proc.stderr is not None:
            proc.stderr.close()
    except OSError:
        pass


def _extract_ip(response: str, family: str) -> str | None:
    text = (response or "").strip()
    try:
        d = json.loads(text)
        if isinstance(d, dict) and d.get("ip"):
            ip = str(d["ip"])
            if _family_ok(ip, family):
                return ip
    except ValueError:
        pass
    if family == "4":
        m = _IPV4_RE.search(text)
        return m.group(0) if m else None
    m = re.search(r"\b[0-9a-f:]{2,45}\b", text, re.IGNORECASE)
    if m and ":" in m.group(0) and _family_ok(m.group(0), family):
        return m.group(0)
    return None


def _family_ok(ip: str, family: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.version == 4) if family == "4" else (a.version == 6)


def _curl_egress(family: str, urls: list[str], port: int, max_time: int = 12) -> str | None:
    flag = "-4" if family == "4" else "-6"
    for url in urls:
        try:
            r = subprocess.run(
                [
                    "curl", flag, "-sS",
                    "-x", f"http://127.0.0.1:{port}",
                    "--max-time", str(max_time),
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=max_time + 5,
            )
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            continue
        if r.returncode != 0:
            continue
        ip = _extract_ip(r.stdout, family)
        if ip:
            return ip
    return None


def probe_config(
    cfg: VpnConfig,
    singbox_bin: str | None,
    mixed_port: int,
    timeout: int = 25,
) -> tuple[str | None, str | None, str]:
    """Подключается к серверу и определяет внешний IPv4/IPv6.

    :return: (ip4, ip6, detail)
    """
    if not singbox_bin:
        return None, None, "sing-box не найден"
    try:
        build_singbox_outbound(cfg)
    except UnsupportedProtocol as e:
        return None, None, str(e)

    client = build_singbox_config(cfg, mixed_port)
    with tempfile.TemporaryDirectory(prefix="meeyota-sb-") as td:
        cfg_path = os.path.join(td, "client.json")
        Path(cfg_path).write_text(json.dumps(client), encoding="utf-8")
        try:
            proc = subprocess.Popen(
                [singbox_bin, "run", "-c", cfg_path, "--log-level", "warn"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.SubprocessError) as e:
            return None, None, f"не удалось запустить sing-box: {e}"
        try:
            if not _wait_port("127.0.0.1", mixed_port, timeout=5):
                err = b""
                if proc.stderr is not None:
                    err = proc.stderr.read(500)
                    proc.stderr.close()
                return None, None, f"sing-box не запустился: {err.decode('utf-8', 'replace')[:300]}"
            max_time = max(8, min(15, timeout // 2))
            ip4 = _curl_egress("4", EGRESS_V4_URLS, mixed_port, max_time=max_time)
            ip6 = _curl_egress("6", EGRESS_V6_URLS, mixed_port, max_time=max_time)
        finally:
            _terminate(proc)

    if ip4 is None and ip6 is None:
        return None, None, "нет внешнего выхода (IPv4/IPv6 не получены)"
    return ip4, ip6, ""
