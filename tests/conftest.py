"""Общие фикстуры тестов: реальные строки из публичных источников."""

import base64
import json

VLESS_REALITY_TCP = (
    "vless://17c1b548-97db-4b58-a410-cab03d1f09c4@47.88.107.209:443"
    "?type=tcp&security=reality&flow=xtls-rprx-vision"
    "&pbk=uxMpQ2V3K2VvD0FKyH0hGRxTIshiwssgK7eM-RpBLB8&sid=1b2c3d4e5f607182"
    "&sni=www.cloudflare.com&fp=chrome#.test-reality"
)

VLESS_REALITY_HIZTIN = (
    "vless://4bf5a71c-d726-4585-b095-7396675706d5@72.56.81.165:40443"
    "?flow=xtls-rprx-vision&fp=chrome&host=%2F%3Fbia_telegram-tgrvpn"
    "&pbk=D_ks4Yyk4-osnWBxCFvd0_UEgohUXvR2zJoWQg1CACU&security=reality&sid=c84f"
    "&sni=deepl.com&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20%5BVL%5D%20test"
)

VLESS_WS_NONE = (
    "vless://da5ff974-c135-4b57-a0ff-53dd2502e71e@104.21.23.72:8880"
    "?security=none&type=ws&host=long-smoke-b6cb.290-cd1.workers.dev"
    "&path=/pyip=ProxyIP.US.CMLiussss.net#%5BOpenRay%5D%20CA-28959"
)

VLESS_GRPC_TRAILING_SLASH = (
    "vless://df0680ca-e43c-498d-ed86-8e196eedd012@185.153.183.211:8880/"
    "?type=grpc&encryption=none&flow=#grpc-test"
)

VLESS_HTML_ENTITIES = (
    "vless://0b39a009-2a2a-4035-ba87-cc82894f8e21@connect3.nyxserver.ir:8444"
    "?security=tls&amp;alpn=h2%2Chttp%2F1.1&amp;encryption=none&amp;insecure=0"
    "&amp;headerType=none&amp;fp=chrome&amp;type=tcp&amp;allowInsecure=0#entity-test"
)

# VMess-фикстуры (как в hiztin/VLESS-PO-GRIBI: base64(JSON), реальные данные)
_VMESS1 = json.dumps(
    {
        "add": "129.146.143.80", "aid": 0, "id": "d4603cc2-e0ee-4651-83f5-1db5b7168177",
        "net": "tcp", "port": 48111, "ps": "t.me/rjsxrd", "scy": "auto",
        "tls": "", "type": "none", "v": "2",
    },
    separators=(",", ":"),
)
VMESS_TCP = "vmess://" + base64.b64encode(_VMESS1.encode()).decode() + "#%20t.me%2Frjsxrd"

_VMESS2 = json.dumps(
    {
        "v": "2", "add": "165.140.216.142", "port": "443",
        "id": "b65a2d69-5634-42a2-e4be-54e8a6176900", "aid": "0",
        "scy": "auto", "net": "tcp", "type": "", "tls": "", "ps": "test",
    }
)
VMESS_STRING_PORT = "vmess://" + base64.b64encode(_VMESS2.encode()).decode()

SS_NEW = (
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTprMWRCT21PQjRvcWk3VW1wMzdhMWJR"
    "@82.38.31.200:8080#%F0%9F%87%B3%F0%9F%87%B1%20%5BSS%5D%20test"
)

SS_LEGACY_PADDed = (
    "ss://YWVzLTI1Ni1nY206ZmJjZWM3Njk1M2EyZDE3M0AxNjYuODguMTMwLjIxODozMDExMQ=="
    "#%5BOpenRay%5D%20CA-29446"
)

SS_LEGACY_NO_PADDING = (
    "ss://YWVzLTI1Ni1nY206Y2RCSURWNDJEQ3duZklOQDUxLjc5Ljg1LjE4NTo4MTE4"
    "#%5BOpenRay%5D%20CA-29044"
)

TROJAN_WS = (
    "trojan://humanity@www.ignitelimit.com:443?security=tls&type=ws&path=%2F"
    "assignment#CA-test-1"
)

HY2_UUID = "hysteria2://f317b5d6-d399-4d3d-a051-89d674ae953c@msk.frkn.org:443?security=tls#RU-test"
HY2_HEX_PASSWORD = "hy2://b0917015b656b3dd2286b5633af0c5c1@31.57.248.176:50160#HK-test"
HY2_SNI = "hysteria2://b3a11068-1a7e-4643-85de-7c82cce46943@82.38.171.81:10451?sni=uk.shamanapp.online#GB-test"

SOCKS5_PLAIN = "socks5://45.144.54.40:1080"
SOCKS5_AUTH = "socks5://user:secret@203.0.113.7:1080"

BROKEN_LINES = [
    "",
    "   ",
    "#profile-title: comment",
    "vless://not-a-uuid@example.com:443",
    "vless://17c1b548-97db-4b58-a410-cab03d1f09c4@example.com:99999",
    "vless://17c1b548-97db-4b58-a410-cab03d1f09c4@example.com?security=reality",
    "vmess://!!!not-base64!!!",
    "ss://zzzz",
    "foobar://example.com:443",
    "https://example.com/not-a-vpn",
    "vless://",
    "trojan://@example.com:443",
]

GOOD_LINES = [
    VLESS_REALITY_TCP,
    VLESS_WS_NONE,
    VMESS_TCP,
    SS_NEW,
    TROJAN_WS,
    HY2_UUID,
    SOCKS5_PLAIN,
]
