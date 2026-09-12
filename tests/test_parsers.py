"""Тесты парсера URI: все протоколы + битые строки + base64-контейнеры."""

import base64

import pytest

from src.parsers import ParseError, parse_text, parse_uri
from src.parsers.uri import decode_b64, looks_like_b64_blob

from .conftest import (
    BROKEN_LINES,
    GOOD_LINES,
    HY2_HEX_PASSWORD,
    HY2_SNI,
    HY2_UUID,
    SOCKS5_AUTH,
    SOCKS5_PLAIN,
    SS_LEGACY_NO_PADDING,
    SS_LEGACY_PADDed,
    SS_NEW,
    TROJAN_WS,
    VLESS_GRPC_TRAILING_SLASH,
    VLESS_HTML_ENTITIES,
    VLESS_REALITY_HIZTIN,
    VLESS_REALITY_TCP,
    VLESS_WS_NONE,
    VMESS_STRING_PORT,
    VMESS_TCP,
)


# ---------------------------------------------------------------------------
# VLESS
# ---------------------------------------------------------------------------

def test_vless_reality_tcp():
    c = parse_uri(VLESS_REALITY_TCP, "src")
    assert c.protocol == "vless"
    assert c.address == "47.88.107.209"
    assert c.port == 443
    assert c.params["security"] == "reality"
    assert c.params["flow"] == "xtls-rprx-vision"
    assert c.params["pbk"].startswith("uxMpQ2V3")
    assert c.params["sid"] == "1b2c3d4e5f607182"
    assert c.params["sni"] == "www.cloudflare.com"
    assert c.name == ".test-reality"
    assert c.hash and len(c.hash) == 64
    assert c.raw == VLESS_REALITY_TCP


def test_vless_reality_hiztin():
    c = parse_uri(VLESS_REALITY_HIZTIN, "src")
    assert c.port == 40443
    assert c.params["security"] == "reality"
    assert c.params["fp"] == "chrome"
    assert c.params["sid"] == "c84f"
    assert c.name.startswith("🇳🇱")


def test_vless_ws_none():
    c = parse_uri(VLESS_WS_NONE, "src")
    assert c.params["type"] == "ws"
    assert c.params["host"] == "long-smoke-b6cb.290-cd1.workers.dev"
    assert c.params["path"] == "/pyip=ProxyIP.US.CMLiussss.net"


def test_vless_grpc_trailing_slash_port():
    c = parse_uri(VLESS_GRPC_TRAILING_SLASH, "src")
    assert c.port == 8880
    assert c.params["type"] == "grpc"
    assert c.params["flow"] == ""  # пустой flow очищается


def test_vless_html_entities():
    """Источники с HTML-заэкранированными &amp; должны парситься корректно."""
    c = parse_uri(VLESS_HTML_ENTITIES, "src")
    assert c.params["security"] == "tls"
    assert c.params["alpn"] == ["h2", "http/1.1"]
    assert c.params["type"] == "tcp"
    assert c.params["fp"] == "chrome"
    assert c.params["insecure"] is False


def test_vless_bad_uuid():
    with pytest.raises(ParseError):
        parse_uri("vless://not-a-uuid@example.com:443", "src")


def test_vless_reality_without_pbk():
    with pytest.raises(ParseError):
        parse_uri("vless://17c1b548-97db-4b58-a410-cab03d1f09c4@example.com:443?security=reality", "src")


def test_vless_bad_port():
    with pytest.raises(ParseError):
        parse_uri("vless://17c1b548-97db-4b58-a410-cab03d1f09c4@example.com:99999", "src")


# ---------------------------------------------------------------------------
# VMess
# ---------------------------------------------------------------------------

def test_vmess_tcp():
    c = parse_uri(VMESS_TCP, "src")
    assert c.protocol == "vmess"
    assert c.address == "129.146.143.80"
    assert c.port == 48111
    assert c.params["uuid"] == "d4603cc2-e0ee-4651-83f5-1db5b7168177"
    assert c.params["aid"] == 0
    assert c.params["net"] == "tcp"
    assert c.params["tls"] is False


def test_vmess_string_port():
    c = parse_uri(VMESS_STRING_PORT, "src")
    assert c.port == 443
    assert c.params["uuid"] == "b65a2d69-5634-42a2-e4be-54e8a6176900"


def test_vmess_bad_payload():
    with pytest.raises(ParseError):
        parse_uri("vmess://!!!not-base64!!!", "src")


# ---------------------------------------------------------------------------
# Shadowsocks
# ---------------------------------------------------------------------------

def test_ss_new_form():
    c = parse_uri(SS_NEW, "src")
    assert c.protocol == "ss"
    assert c.address == "82.38.31.200"
    assert c.port == 8080
    assert c.params["method"] == "chacha20-ietf-poly1305"
    assert c.params["password"] == "k1dBOmOB4oqi7Ump37a1bQ"


def test_ss_legacy_padded():
    c = parse_uri(SS_LEGACY_PADDed, "src")
    assert c.address == "166.88.130.218"
    assert c.port == 30111
    assert c.params["method"] == "aes-256-gcm"
    assert c.params["password"] == "fbcec76953a2d173"


def test_ss_legacy_no_padding():
    c = parse_uri(SS_LEGACY_NO_PADDING, "src")
    assert c.address == "51.79.85.185"
    assert c.port == 8118
    assert c.params["method"] == "aes-256-gcm"


def test_ss_bad_payload():
    with pytest.raises(ParseError):
        parse_uri("ss://zzzz", "src")


# ---------------------------------------------------------------------------
# Trojan / Hysteria2 / SOCKS5
# ---------------------------------------------------------------------------

def test_trojan_ws():
    c = parse_uri(TROJAN_WS, "src")
    assert c.protocol == "trojan"
    assert c.address == "www.ignitelimit.com"
    assert c.port == 443
    assert c.params["password"] == "humanity"
    assert c.params["type"] == "ws"
    assert c.params["path"] == "/assignment"


def test_trojan_empty_password():
    with pytest.raises(ParseError):
        parse_uri("trojan://@example.com:443", "src")


def test_hysteria2_variants():
    c1 = parse_uri(HY2_UUID, "src")
    assert c1.protocol == "hysteria2"
    assert c1.params["password"] == "f317b5d6-d399-4d3d-a051-89d674ae953c"
    c2 = parse_uri(HY2_HEX_PASSWORD, "src")
    assert c2.params["password"] == "b0917015b656b3dd2286b5633af0c5c1"
    c3 = parse_uri(HY2_SNI, "src")
    assert c3.params["sni"] == "uk.shamanapp.online"


def test_socks5():
    c = parse_uri(SOCKS5_PLAIN, "src")
    assert c.protocol == "socks5"
    assert c.address == "45.144.54.40"
    c2 = parse_uri(SOCKS5_AUTH, "src")
    assert c2.params["username"] == "user"
    assert c2.params["password"] == "secret"


# ---------------------------------------------------------------------------
# parse_text: комментарии, битые строки, base64
# ---------------------------------------------------------------------------

def test_parse_text_counts():
    text = "\n".join(GOOD_LINES + ["#profile-title: header", ""] + BROKEN_LINES)
    configs, invalid = parse_text(text, "src")
    assert len(configs) == len(GOOD_LINES)
    # пустые строки и комментарии пропускаются, не считаются битыми
    assert invalid == len(BROKEN_LINES) - 3


def test_parse_text_b64_blob():
    """Файл целиком в base64 должен декодироваться автоматически."""
    payload = "\n".join(GOOD_LINES)
    blob = base64.b64encode(payload.encode()).decode()
    configs, invalid = parse_text(blob, "src")
    assert len(configs) == len(GOOD_LINES)
    assert invalid == 0


def test_parse_text_b64_lines():
    """Отдельные строки в base64 должны декодироваться построчно."""
    lines = []
    for uri in GOOD_LINES:
        lines.append(base64.b64encode(uri.encode()).decode())
    configs, invalid = parse_text("\n".join(lines), "src")
    assert len(configs) == len(GOOD_LINES)


def test_looks_like_b64_blob():
    payload = "\n".join(GOOD_LINES)
    assert looks_like_b64_blob(base64.b64encode(payload.encode()).decode())
    assert not looks_like_b64_blob(payload)
    assert not looks_like_b64_blob("short")


def test_hash_stability_and_sensitivity():
    """Одинаковые конфиги (разные имена) дают один хеш; другая cred — другой."""
    a = parse_uri(VLESS_REALITY_TCP, "s1")
    b = parse_uri(VLESS_REALITY_TCP.replace("#.test-reality", "#other name"), "s2")
    assert a.hash == b.hash
    c = parse_uri(VLESS_REALITY_TCP.replace("47.88.107.209", "47.88.107.210"), "s3")
    assert a.hash != c.hash


def test_decode_b64_variants():
    data = "abc+def/ghi="
    assert decode_b64(data) == base64.b64decode(data)
    # строка без padding тоже декодируется
    assert decode_b64("YWJj") == b"abc"
    # строка с невозможной длиной: decode_b64 честно падает, парсер это перехватывает
    with pytest.raises(Exception):
        decode_b64("abcde")
