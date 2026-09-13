"""Тесты нормализатора и дедупликатора."""

from src.models.config import VpnConfig
from src.normaliser import normalise
from src.deduplicator import deduplicate


def _make_cfg(**kwargs):
    return VpnConfig(
        scheme="vless",
        raw="vless://abc@server.com:443?security=tls&type=tcp#Name",
        host=kwargs.get("host", "server.com"),
        port=kwargs.get("port", 443),
        params=kwargs.get("params", {"security": "TLS", "type": "TCP"}),
        fragment=kwargs.get("fragment", "Name"),
        name=kwargs.get("name", "Name"),
        protocol_data=kwargs.get("protocol_data", {"uuid": "abc"}),
    )


def test_normalise_lowercases_params():
    c = _make_cfg(params={"security": "TLS", "type": "TCP", "fp": "chrome"})
    n = normalise(c)
    assert n.params["security"] == "tls"
    assert n.params["type"] == "tcp"
    assert n.params["fp"] == "chrome"
    print("✓ test_normalise_lowercases_params")


def test_normalise_lowercases_host():
    c = _make_cfg(host="SERVER.COM")
    n = normalise(c)
    assert n.host == "server.com"
    print("✓ test_normalise_lowercases_host")


def test_dedup_identical():
    a = _make_cfg()
    b = _make_cfg()
    unique, dropped = deduplicate([a, b])
    assert len(unique) == 1
    assert dropped == 1
    print("✓ test_dedup_identical")


def test_dedup_different_hosts():
    a = _make_cfg(host="a.com")
    b = _make_cfg(host="b.com")
    unique, dropped = deduplicate([a, b])
    assert len(unique) == 2
    assert dropped == 0
    print("✓ test_dedup_different_hosts")


def test_dedup_different_sn():
    a = _make_cfg(params={"security": "tls", "type": "tcp", "sni": "a.com"})
    b = _make_cfg(params={"security": "tls", "type": "tcp", "sni": "b.com"})
    unique, dropped = deduplicate([a, b])
    assert len(unique) == 2
    print("✓ test_dedup_different_sn")


if __name__ == "__main__":
    test_normalise_lowercases_params()
    test_normalise_lowercases_host()
    test_dedup_identical()
    test_dedup_different_hosts()
    test_dedup_different_sn()
    print("\nAll normaliser/dedup tests passed.")
