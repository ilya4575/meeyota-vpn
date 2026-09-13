"""Тесты валидатора."""

from src.models.config import VpnConfig
from src.validator import validate_all, ValidationError


def _make(**kwargs):
    defaults = dict(
        scheme="vless",
        raw="",
        host="server.com",
        port=443,
        params={"security": "tls", "type": "tcp"},
        fragment="Name",
        name="Name",
        protocol_data={"uuid": "cd3bb7d9-7df3-4644-ac05-c260990ac277"},
    )
    defaults.update(kwargs)
    return VpnConfig(**defaults)


def test_valid():
    valid, errors = validate_all([_make()])
    assert len(valid) == 1
    assert len(errors) == 0
    print("✓ test_valid")


def test_bad_host():
    valid, errors = validate_all([_make(host="")])
    assert len(errors) == 1
    assert "host" in str(errors[0][1]).lower()
    print("✓ test_bad_host")


def test_bad_port():
    valid, errors = validate_all([_make(port=0)])
    assert len(errors) == 1
    assert "port" in str(errors[0][1]).lower()
    print("✓ test_bad_port")


def test_missing_uuid():
    valid, errors = validate_all([_make(protocol_data={"uuid": ""})])
    assert len(errors) == 1
    print("✓ test_missing_uuid")


def test_ipv4_host():
    valid, errors = validate_all([_make(host="1.2.3.4")])
    assert len(errors) == 0
    print("✓ test_ipv4_host")


def test_ipv6_host():
    valid, errors = validate_all([_make(host="2001:db8::1")])
    assert len(errors) == 0
    print("✓ test_ipv6_host")


if __name__ == "__main__":
    test_valid()
    test_bad_host()
    test_bad_port()
    test_missing_uuid()
    test_ipv4_host()
    test_ipv6_host()
    print("\nAll validator tests passed.")
