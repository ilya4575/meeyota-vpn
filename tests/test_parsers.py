"""Тесты парсеров на реальных (обезличенных по образцу) строках из подписок."""
import pytest

from src.parsers.uri import ParseError, parse_uri
from src.parsers.subscription import extract_uris, _try_decode_base64
from src.models.config import VpnConfig


# ------------------------------------------------------------------ vless
def test_vless_reality_tcp():
    raw = ("vless://17c1b548-97db-4b58-a410-cab03d1f09c4@47.88.107.209:443"
           "?type=tcp&security=reality&flow=xtls-rprx-vision"
           "&pbk=uxMpQ2V3K2VvD0FKyH0hGRxTIshiwssgK7eM-RpBLB8&sid=1b2c3d4e5f607182"
           "&sni=www.cloudflare.com&fp=chrome#test")
    c = parse_uri(raw)
    assert c.protocol == "vless"
    assert c.uuid == "17c1b548-97db-4b58-a410-cab03d1f09c4"
    assert c.address == "47.88.107.209" and c.port == 443
    assert c.security == "reality" and c.network == "tcp"
    assert c.flow == "xtls-rprx-vision" and c.pbk.startswith("uxMp")
    assert c.sni == "www.cloudflare.com" and c.name == "test"
    assert c.checkable


def test_vless_ws_no_security():
    c = parse_uri("vless://e5cc16a6-ea42-46b2-82ae-ad2157e1641b@172.64.150.28:2082"
                  "?path=%2Ffp&security=&encryption=none&host=hhlfy.example.com&type=ws#x")
    assert c.network == "ws" and c.security == "none"
    assert c.path == "/fp" and c.host == "hhlfy.example.com"


def test_vless_grpc_reality():
    c = parse_uri("vless://2f35965a-1a7e-4643-855d-ebdbbf1f7e90@bg2.example.com:443"
                  "?mode=gun&security=reality&encryption=none&pbk=XBfCioniAKXgKYBUVnvBX"
                  "&fp=chrome&type=grpc&serviceName=home.v1.ApiService&sni=bg2.example.com#n")
    assert c.network == "grpc" and c.service_name == "home.v1.ApiService"


def test_vless_xhttp_spx():
    c = parse_uri("vless://682300d9-74d0-4dae-431a-8a8a36b33495@103.75.119.11:443"
                  "?encryption=none&flow=xtls-rprx-vision&type=xhttp&mode=stream-one"
                  "&host=sberbank.ru&path=%2Fapi%2Fv1%2Fc8dd02d6&security=reality"
                  "&fp=chrome&pbk=OvlkCDO6YdWR0ec3kVHW-Ul7I9TuEmJVfxXdaZiy5Ug"
                  "&sni=sberbank.ru&sid=2cbe511ff1f9200b#x")
    assert c.network == "http" and c.path == "/api/v1/c8dd02d6"


def test_vless_amp_escape():
    # в реальных подписках встречается '&amp;'
    c = parse_uri("vless://0b39a009-2a2a-4035-ba87-cc82894f8e21@connect3.example.ir:8444"
                  "?security=tls&amp;alpn=h2%2Chttp%2F1.1&amp;encryption=none&amp;fp=chrome"
                  "&amp;type=tcp&amp;allowInsecure=0#x")
    assert c.security == "tls" and c.network == "tcp" and c.fp == "chrome"
    assert c.alpn == ["h2", "http/1.1"]


def test_vless_broken_uuid_rejected():
    with pytest.raises(ParseError):
        parse_uri("vless://not-a-uuid@1.2.3.4:443?type=tcp#x")


def test_vless_broken_sni_rejected():
    # sni=%2FTELEGRAM_TM(...)%2CTELEGRAM... — мусор из телеграм-ссылок
    with pytest.raises(ParseError):
        parse_uri("vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@66.90.104.42:2083"
                  "?mode=gun&security=none&encryption=none&type=grpc&serviceName=vless"
                  "&sni=%2FTELEGRAM_TM%28%40ABC%29%2CTELEGRAM_TM%28%40ABC%29#x")


def test_vless_reality_without_pbk_uncheckable():
    c = parse_uri("vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@66.90.104.42:2083"
                  "?security=reality&type=grpc&serviceName=vless#x")
    assert c.checkable is False


def test_vless_flow_without_tls_uncheckable():
    c = parse_uri("vless://1d39f715-2740-4d99-bc3b-197cc48dcee7@1.2.3.4:443"
                  "?flow=xtls-rprx-vision&security=none&type=tcp#x")
    assert c.checkable is False


# ------------------------------------------------------------------ vmess
def test_vmess_base64_json():
    import base64, json
    payload = json.dumps({
        "add": "23.162.200.198", "id": "f8c8dc3d-0d37-46b0-8b34-a7232882fcfe",
        "port": "18000", "scy": "auto", "v": "2", "net": "raw", "type": "none",
        "tls": "none", "ps": "Test Node"
    }).encode()
    raw = "vmess://" + base64.b64encode(payload).decode()
    c = parse_uri(raw)
    assert c.protocol == "vmess"
    assert c.address == "23.162.200.198" and c.port == 18000
    assert c.uuid == "f8c8dc3d-0d37-46b0-8b34-a7232882fcfe"
    assert c.network == "tcp" and c.security == "none"
    assert c.name == "Test Node"


def test_vmess_ws_tls():
    import base64, json
    payload = json.dumps({
        "v": "2", "ps": "ws", "add": "example.com", "port": "443",
        "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "aid": "0", "scy": "auto",
        "net": "ws", "type": "none", "host": "example.com", "path": "/abc",
        "tls": "tls", "sni": "example.com"
    }).encode()
    c = parse_uri("vmess://" + base64.b64encode(payload).decode())
    assert c.network == "ws" and c.security == "tls"
    assert c.path == "/abc" and c.sni == "example.com"


def test_vmess_broken():
    with pytest.raises(ParseError):
        parse_uri("vmess://!!!not-base64!!!")


# ------------------------------------------------------------------ trojan
def test_trojan_ws():
    c = parse_uri("trojan://humanity@104.21.46.3:443?security=tls&sni=www.example.com"
                  "&fp=chrome&type=ws&path=%2Fassignment#x")
    assert c.protocol == "trojan" and c.password == "humanity"
    assert c.network == "ws" and c.path == "/assignment"


def test_trojan_reality():
    c = parse_uri("trojan://BbNnpOgc1j9WOaWoslbSyeob1r47IRHV@jgzt1997.example.ir:1080"
                  "?type=raw&headerType=none&security=reality&fp=chrome"
                  "&pbk=1ZO9Cjhs1IFAU6nZATRhOuD3kq6J-1dZadfEfX734zc"
                  "&sni=maps.google.com&sid=0d12eb289946de9b#x")
    assert c.security == "reality" and c.checkable


# ------------------------------------------------------------------ shadowsocks
def test_ss_sip002():
    import base64
    mp = base64.b64encode(b"chacha20-ietf-poly1305:k1dBOmOB4oqi7Ump37a1bQ").decode()
    c = parse_uri(f"ss://{mp}@82.38.31.200:8080#node-1")
    assert c.protocol == "shadowsocks"
    assert c.method == "chacha20-ietf-poly1305"
    assert c.address == "82.38.31.200" and c.port == 8080
    assert c.name == "node-1"


def test_ss_legacy():
    import base64
    blob = base64.b64encode(b"aes-256-gcm:pass@121.46.230.139:65443").decode()
    c = parse_uri(f"ss://{blob}#legacy")
    assert c.method == "aes-256-gcm" and c.password == "pass"
    assert c.address == "121.46.230.139" and c.port == 65443


def test_ss_bad_method_rejected():
    import base64
    mp = base64.b64encode(b"unknown-cipher:pass").decode()
    with pytest.raises(ParseError):
        parse_uri(f"ss://{mp}@1.2.3.4:8080")


# ------------------------------------------------------------------ hysteria2
def test_hysteria2():
    c = parse_uri("hysteria2://H7mP2xY9kJ4nQ8wR5tF6vB3z@vpn-au-002.example.world:443/"
                  "?insecure=1&sni=css.example.com#AU")
    assert c.protocol == "hysteria2"
    assert c.password == "H7mP2xY9kJ4nQ8wR5tF6vB3z"
    assert c.port == 443 and c.sni == "css.example.com"
    assert c.checkable


def test_hy2_short_scheme_empty_query():
    c = parse_uri("hy2://b0917015b656b3dd2286b5633af0c5c1@31.57.248.176:50160?#HK")
    assert c.protocol == "hysteria2" and c.port == 50160
    assert c.checkable


# ------------------------------------------------------------------ other
def test_mtproto_tme_link():
    c = parse_uri("https://t.me/proxy?server=dokhtar.example.co.uk&port=8443&secret=EERighJJvXrF")
    assert c.protocol == "mtproto"
    assert c.address == "dokhtar.example.co.uk" and c.port == 8443
    assert c.checkable is False


def test_socks5():
    c = parse_uri("socks5://user:pass@1.2.3.4:1080")
    assert c.protocol == "socks5" and c.port == 1080


def test_http_proxy_like_webpage_rejected():
    with pytest.raises(ParseError):
        parse_uri("https://example.com/some/path/page")


# ------------------------------------------------------------------ subscription
def test_extract_uris_plain_with_comments():
    text = "# profile-title: Test\n\nvless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443#n1\n"
    out = extract_uris(text)
    assert len(out) == 1 and out[0].startswith("vless://")


def test_extract_uris_base64_block():
    import base64
    inner = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443\n"
             "vless://bbbbbbbb-cccc-dddd-eeee-ffffffffffff@5.6.7.8:8443\n")
    blob = base64.b64encode(inner.encode()).decode()
    out = extract_uris(blob)
    assert len(out) == 2


def test_extract_uris_plain_not_mistaken_for_b64():
    text = ("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?security=none&type=tcp#n\n"
            "vless://bbbbbbbb-cccc-dddd-eeee-ffffffffffff@5.6.7.8:8080#m\n")
    out = extract_uris(text)
    assert len(out) == 2  # ':' в URI не даёт b64-совпадения


def test_try_decode_base64_roundtrip():
    import base64
    inner = "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:pw").decode() + "@1.2.3.4:8388"
    blob = base64.b64encode(inner.encode()).decode()
    dec = _try_decode_base64(blob)
    assert dec == inner
