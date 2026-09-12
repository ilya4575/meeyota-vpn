"""Работа с Xray-core: загрузка бинарника, сборка proxy-конфига, зонд внешнего IP.

Схема проверки одного конфига:
1. собрать xray-конфиг: inbound HTTP-прокси на 127.0.0.1:<порт> + outbound из конфига;
2. запустить xray (без fallback на direct — если VPN мёртв, запрос просто не пройдёт);
3. через локальный прокси GET https://api4.ipify.org (внешний IPv4) и https://api6.ipify.org (IPv6);
4. завершить xray.
"""
from __future__ import annotations

import json
import logging
import os
import random
import socket
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from ..models.config import VpnConfig

log = logging.getLogger("meeyota.xray")

XRAY_REPO = "XTLS/Xray-core"
# актуальные релизы (запасные, если latest недоступен)
FALLBACK_VERSIONS = ["v26.9.9", "v26.7.28", "v26.6.27", "v26.5.9", "v26.4.25"]

IP4_URL = "https://api4.ipify.org"
IP6_URL = "https://api6.ipify.org"
IP_FALLBACKS_V4 = ["https://api4.ipify.org", "https://ipv4.icanhazip.com"]
IP_FALLBACKS_V6 = ["https://api6.ipify.org", "https://ipv6.icanhazip.com"]


class XrayError(Exception):
    pass


def _asset_url(version: str) -> str:
    return f"https://github.com/{XRAY_REPO}/releases/download/{version}/Xray-linux-64.zip"


def resolve_latest_version(session: requests.Session) -> Optional[str]:
    try:
        r = session.get(f"https://api.github.com/repos/{XRAY_REPO}/releases/latest",
                        timeout=15)
        tag = r.json().get("tag_name")
        if tag and tag.startswith("v"):
            return tag
    except (requests.RequestException, ValueError) as e:
        log.warning("не удалось получить latest Xray: %s", e)
    return None


def ensure_xray(bin_dir: Path, session: requests.Session,
                logger: Optional[logging.Logger] = None) -> Optional[Path]:
    """Возвращает путь к бинарнику xray или None (если скачать не удалось)."""
    logger = logger or log
    bin_dir = Path(bin_dir)
    binary = bin_dir / "xray" / "xray"
    if binary.is_file() and os.access(binary, os.X_OK):
        return binary

    versions: list = []
    latest = resolve_latest_version(session)
    if latest:
        versions.append(latest)
    versions.extend(v for v in FALLBACK_VERSIONS if v not in versions)

    for ver in versions:
        url = _asset_url(ver)
        try:
            logger.info("скачиваю Xray %s ...", ver)
            r = session.get(url, timeout=120, stream=True)
            if r.status_code != 200:
                raise XrayError(f"HTTP {r.status_code}")
            tmp_zip = bin_dir / f"xray-{ver}.zip"
            bin_dir.mkdir(parents=True, exist_ok=True)
            with open(tmp_zip, "wb") as f:
                for chunk in r.iter_content(1 << 16):
                    f.write(chunk)
            with zipfile.ZipFile(tmp_zip) as z:
                names = [n for n in z.namelist() if n.endswith("xray") and "geoip" not in n]
                if not names:
                    raise XrayError("в архиве нет бинарника xray")
                z.extract(names[0], bin_dir)
            # файл внутри: Xray-linux-64/xray
            for cand in bin_dir.glob(f"**/xray"):
                if cand.is_file() and cand.name == "xray":
                    os.chmod(cand, 0o755)
                    target = bin_dir / "xray"
                    target.mkdir(parents=True, exist_ok=True)
                    if cand.resolve() != (target / "xray").resolve():
                        import shutil
                        shutil.move(str(cand), target / "xray")
                    tmp_zip.unlink(missing_ok=True)
                    logger.info("Xray %s установлен: %s", ver, target / "xray")
                    return target / "xray"
            raise XrayError("xray не найден после распаковки")
        except (XrayError, requests.RequestException, OSError, zipfile.BadZipFile) as e:
            logger.warning("Xray %s: %s", ver, e)
            continue
    return None


def pick_local_port() -> int:
    return random.randint(20000, 39999)


def build_proxy_config(outbound: Dict[str, Any], local_port: int) -> Dict[str, Any]:
    """xray-конфиг: локальный HTTP-прокси -> один VPN-outbound (без fallback)."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": local_port,
            "settings": {"allowTransparent": False},
        }],
        "outbounds": [outbound, {"protocol": "blackhole", "tag": "block"}],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


def _wait_port(port: int, timeout: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def _get_ip(session: requests.Session, urls: list, port: int,
            timeout: float) -> Optional[str]:
    proxies = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    for url in urls:
        try:
            r = session.get(url, proxies=proxies, timeout=timeout)
            ip = r.text.strip()
            if ip.count(".") == 3 or ":" in ip:  # вменяемый IP
                import ipaddress
                ipaddress.ip_address(ip)
                return ip
        except (requests.RequestException, ValueError, OSError):
            continue
    return None


def probe_config(xray_bin: Path, cfg: VpnConfig, work_dir: Path,
                 session: requests.Session, per_request_timeout: float = 15.0,
                 overall_timeout: float = 45.0) -> Tuple[Optional[str], Optional[str], str]:
    """-> (ip4, ip6, error). error='' при успехе."""
    outbound = cfg.to_xray_outbound()
    if outbound is None:
        return None, None, f"не проверяем: {cfg.check_reason or cfg.protocol}"

    port = pick_local_port()
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = work_dir / f"probe-{cfg.fingerprint.replace('|', '_')[:80]}.json"
    log_path = work_dir / f"probe-{cfg.fingerprint.replace('|', '_')[:80]}.log"

    proc: Optional[subprocess.Popen] = None
    try:
        cfg_path.write_text(json.dumps(build_proxy_config(outbound, port)), encoding="utf-8")
        proc = subprocess.Popen(
            [str(xray_bin), "run", "-c", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=open(log_path, "wb"),
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        if not _wait_port(port):
            return None, None, "xray не поднял локальный порт"

        t0 = time.time()
        ip4 = _get_ip(session, IP_FALLBACKS_V4, port, per_request_timeout)
        if time.time() - t0 > overall_timeout:
            return ip4, None, "превышено общее время проверки (ip4)"
        ip6 = _get_ip(session, IP_FALLBACKS_V6, port, per_request_timeout)
        if ip4 is None and ip6 is None:
            return None, None, "не удалось получить внешний IP через прокси"
        if ip4 is None:
            return None, ip6, "нет IPv4-выхода (есть только IPv6)"
        return ip4, ip6, ""
    except Exception as e:  # noqa: BLE001
        return None, None, f"ошибка зонда: {e}"
    finally:
        if proc is not None:
            try:
                import signal
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=4)
            except (ProcessLookupError, OSError, subprocess.TimeoutExpired):
                try:
                    proc.kill()
                except OSError:
                    pass
        try:
            cfg_path.unlink(missing_ok=True)
        except OSError:
            pass
