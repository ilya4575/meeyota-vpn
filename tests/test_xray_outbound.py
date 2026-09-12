"""Тесты генерации xray-конфига (JSON outbound)."""
import json

from src.models.config import VpnConfig
from src.parsers.uri import parse_uri
from src.checks.xray import build_proxy_config


def _outbound(cfg: VpnConfig):
    out = cfg.to_xray_outbound()
    assert out is not None
    return out


def test_vless_reality_outbound():
    c = parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443"
                  "?security=reality&pbk=ABCD1234&sid=0e&sni=example.com&fp=chrome"
                  "&type=tcp&flow=xtls-rprx-vision#x")
    out = _outbound(c)
    assert out["protocol"] == "vless"
    vn = out["settings"]["vnext"][0]
    assert vn["address"] == "1.2.3.4" and vn["port"] == 443
    assert vn["users"][0]["flow"] == "xtls-rprx-vision"
    st = out["streamSettings"]
    assert st["security"] == "reality"
    r = st["realitySettings"]
    assert r["publicKey"] == "ABCD1234" and r["serverName"] == "example.com"
    assert r["fingerprint"] == "chrome"
    # валидный JSON, сериализуемый
    json.dumps(out)


def test_vless_ws_outbound():
    c = parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@5.6.7.8:443"
                  "?security=tls&type=ws&path=%2Fvless&host=h.example.com&sni=s.example.com#x")
    out = _outbound(c)
    st = out["streamSettings"]
    assert st["network"] == "ws"
    assert st["security"] == "tls"
    assert st["wsSettings"]["path"] == "/vless"
    assert st["wsSettings"]["headers"]["Host"] == "h.example.com"
    assert st["tlsSettings"]["serverName"] == "s.example.com"


def test_vmess_outbound():
    # валидный vmess (base64 json), aid=0
    c = parse_uri("vmess://" +
                  "eyJ2IjoiMiIsInBzIjoicmF3IHRlc3QiLCJhZGQiOiIxLjEuMS4xIiwicG9ydCI6IjIwODYi"
                  "LCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAi"
                  "LCJzY3kiOiJhdXRvIiwibmV0IjoicmF3IiwidHlwZSI6Im5vbmUiLCJ0bHMiOiJub25lIn0=")
    out = _outbound(c)
    assert out["protocol"] == "vmess"
    vn = out["settings"]["vnext"][0]
    assert vn["users"][0]["id"] == "00000000-0000-0000-0000-000000000001"
    assert vn["users"][0]["security"] == "auto"


def test_trojan_outbound():
    c = parse_uri("trojan://pw@7.7.7.7:443?security=tls&sni=c.example.com&type=ws&path=/y#t")
    out = _outbound(c)
    assert out["protocol"] == "trojan"
    assert out["settings"]["servers"][0]["password"] == "pw"


def test_shadowsocks_outbound():
    c = parse_uri("ss://" + "YWVzLTI1Ni1nY206cGFzcw==" + "@9.9.9.9:8388#s")
    out = _outbound(c)
    assert out["protocol"] == "shadowsocks"
    srv = out["settings"]["servers"][0]
    assert srv["method"] == "aes-256-gcm" and srv["password"] == "pass"


def test_hysteria2_outbound():
    c = parse_uri("hysteria2://pw123@8.8.8.8:443?sni=h.example.com#h")
    out = _outbound(c)
    assert out["protocol"] == "hysteria2"
    assert out["streamSettings"]["tlsSettings"]["serverName"] == "h.example.com"


def test_uncheckable_returns_none():
    c = parse_uri("https://t.me/proxy?server=x.example&port=443&secret=abc")
    assert c.to_xray_outbound() is None
    c2 = parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.1.1.1:443?security=reality&type=grpc#no-service-name")
    assert c2.to_xray_outbound() is None


def test_proxy_config_shape():
    c = parse_uri("vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@1.2.3.4:443?security=none&type=tcp#x")
    cfg = build_proxy_config(c.to_xray_outbound(), 31337)
    assert cfg["inbounds"][0]["listen"] == "127.0.0.1"
    assert cfg["inbounds"][0]["port"] == 31337
    # fallback на direct НЕ должен быть — иначе проверка даст IP раннера
    assert not any(o.get("protocol") == "freedom" for o in cfg["outbounds"])
