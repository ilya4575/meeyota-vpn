"""Тесты парсера URI."""

from src.parsers.uri import parse_uri, parse_text, ParseError


def test_vless_reality():
    cfg = parse_uri(
        "vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@example.com:443"
        "?security=reality&pbk=XYZ&sid=abcd&sni=cf.com&fp=chrome&type=tcp&flow=xtls-rprx-vision#MyServer"
    )
    assert cfg.scheme == "vless"
    assert cfg.host == "example.com"
    assert cfg.port == 443
    assert cfg.protocol_data["uuid"] == "cd3bb7d9-7df3-4644-ac05-c260990ac277"
    assert cfg.params["security"] == "reality"
    assert cfg.params["pbk"] == "XYZ"
    assert cfg.params["fp"] == "chrome"
    assert cfg.name == "MyServer"
    print("✓ test_vless_reality")


def test_vless_with_fragment_url_encoded():
    cfg = parse_uri(
        "vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@server.com:443?security=tls&type=tcp#%F0%9F%87%BA%F0%9F%87%B3"
    )
    assert cfg.name == "🇺🇳" or "🇺🇳" in cfg.name
    print("✓ test_vless_with_fragment_url_encoded")


def test_vless_amp_entity():
    cfg = parse_uri(
        "vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@server.com:443?security=tls&amp;type=tcp#Name"
    )
    assert cfg.params["security"] == "tls"
    assert cfg.params["type"] == "tcp"
    print("✓ test_vless_amp_entity")


def test_vless_bad_uuid():
    try:
        parse_uri("vless://not-a-uuid@server.com:443#Name")
        raise AssertionError("expected ParseError")
    except ParseError as e:
        assert "uuid" in str(e).lower()
    print("✓ test_vless_bad_uuid")


def test_trojan_basic():
    cfg = parse_uri(
        "trojan://password123@example.com:443?security=tls&sni=example.com&type=tcp#TrojanServer"
    )
    assert cfg.scheme == "trojan"
    assert cfg.protocol_data["password"] == "password123"
    assert cfg.host == "example.com"
    print("✓ test_trojan_basic")


def test_ss_sip002():
    cfg = parse_uri(
        "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@example.com:8388#SSName"
    )
    assert cfg.scheme == "ss"
    assert cfg.protocol_data["method"] == "aes-256-gcm"
    assert cfg.protocol_data["password"] == "password"
    assert cfg.host == "example.com"
    assert cfg.port == 8388
    print("✓ test_ss_sip002")


def test_hy2():
    cfg = parse_uri(
        "hysteria2://authpass@example.com:443?sni=cf.com#Hy2Server"
    )
    assert cfg.scheme == "hysteria2"
    assert cfg.protocol_data["password"] == "authpass"
    print("✓ test_hy2")


def test_skipped_schemes():
    for s in ("ssr://foo", "tuic://bar", "hysteria://baz"):
        try:
            parse_uri(s)
            raise AssertionError(f"expected ParseError for {s}")
        except ParseError as e:
            assert "skipped" in str(e).lower() or "recognized" in str(e).lower()
    print("✓ test_skipped_schemes")


def test_ipv6_host():
    cfg = parse_uri(
        "vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@[2001:db8::1]:443?security=tls&type=tcp#IPv6"
    )
    assert cfg.host == "2001:db8::1"
    print("✓ test_ipv6_host")


def test_parse_text_mixed():
    text = """
# comment line
vless://cd3bb7d9-7df3-4644-ac05-c260990ac277@server1.com:443?security=tls&type=tcp#S1
not a valid line
trojan://pass@server2.com:443?security=tls&type=tcp#S2
"""
    parsed, errors = parse_text(text, source_id="test")
    assert len(parsed) == 2
    assert len(errors) == 1
    assert parsed[0].scheme == "vless"
    assert parsed[1].scheme == "trojan"
    print("✓ test_parse_text_mixed")


if __name__ == "__main__":
    test_vless_reality()
    test_vless_with_fragment_url_encoded()
    test_vless_amp_entity()
    test_vless_bad_uuid()
    test_trojan_basic()
    test_ss_sip002()
    test_hy2()
    test_skipped_schemes()
    test_ipv6_host()
    test_parse_text_mixed()
    print("\nAll parser tests passed.")
