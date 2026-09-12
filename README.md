# meeyota-vpn

Агрегатор публичных VPN-конфигураций из GitHub-репозиториев: скачивает, нормализует,
дедуплицирует, отбрасывает битые, проверяет внешний IP (геолокация) и публикует
**две готовые подписки** через GitHub Pages. Полностью без VPS, Docker и БД —
весь «сервер» — это GitHub Actions + GitHub Pages.

## 📡 Подписки

| Подписка | Файл | Состав |
|---|---|---|
| **VPN whitelist meeyota** | `vpn-whitelist-meeyota.txt` | Все валидные, дедуплицированные конфигурации из всех источников (vless, vmess, trojan, shadowsocks, hysteria2, socks5, http, mtproto, tuic) |
| **VPN Wi-fi meeyota** | `vpn-wifi-meeyota.txt` | Подмножество, для которого **актуальной проверкой** подтверждено: соединение работает, внешний IPv4 **за пределами РФ** (IPv6 — если присутствует — из той же страны; противоречие IPv4/IPv6 или RU → отсев) |

Правила группировки whitelist: конфигурации группируются по протоколу и
сохраняют порядок источников из `sources.yaml` (первый источник — выше приоритет).

### ⚠️ Честное предупреждение про геолокацию

Мы **не даём абсолютной гарантии** страны внешнего IP: публичные IP-базы
(ipwho.is, ip-api.com, ipinfo.io) могут ошибаться и обновляются с задержкой.
Формулировка подписки «за пределами РФ» означает: «по данным актуальной
проверки через геолокационные API, IP не определён как RU». Конфигурации,
по которым geolocate вернул неопределённую страну, **не включаются** —
только строго подтверждённые. Дата последней проверки и результат хранятся
в `data/checks.json` и у каждой записи (`last_check`, `country`, `ip`).

## 🔗 Ссылки для Incy

Основной способ импорта — **`incy://add/{url}`**: клиент сам обновляет список
с GitHub Pages, повторный импорт не нужен (подписка обновляется на стороне GitHub).

Пока репозиторий не задеплоен, вставьте свои значения `USERNAME`/`REPOSITORY`
(или запустите генератор — блок ниже обновится автоматически после первого
запуска/публичного CI-прогона):

- VPN whitelist meeyota:
  `incy://add/https://USERNAME.github.io/REPOSITORY/vpn-whitelist-meeyota.txt`
- VPN Wi-fi meeyota:
  `incy://add/https://USERNAME.github.io/REPOSITORY/vpn-wifi-meeyota.txt`

Прямые URL подписок (для любых клиентов с поддержкой подписок):

- `https://USERNAME.github.io/REPOSITORY/vpn-whitelist-meeyota.txt`
- `https://USERNAME.github.io/REPOSITORY/vpn-wifi-meeyota.txt`

Запасной способ — **`incy://import/{base64}`** (одноразовый импорт снапшота):
генерируется командой `python -m src.main --incy-import` после сборки.
Приоритет — у `incy://add`: subscription обновляется без повторного импорта.

<!-- meeyota:incy:begin -->
_Ссылки будут автоматически обновлены при следующем запуске генератора._
<!-- meeyota:incy:end -->

## 🏗 Как это работает

```
sources.yaml (источники)
   │  collect: retry + timeout + max_bytes + кэш (фолбэк при сбое)
   ▼
parse:  vless / vmess / trojan / ss / hy2 / socks5 / http / tuic / mtproto
        base64-подписки, комментарии, '&amp;', склеенные URI, битый SNI
   ▼
dedupe: fingerprint = сервер + порт + учётные данные + транспорт
   ▼
checks (Xray-core как локальный прокси):
        1. собрать xray-конфиг (inbound HTTP-прокси -> outbound из конфига,
           БЕЗ fallback на direct — мёртвый VPN не выдаст IP раннера)
        2. GET https://api4.ipify.org  -> внешний IPv4
           GET https://api6.ipify.org  -> внешний IPv6 (если есть)
        3. геолокация: ipwho.is -> ip-api.com -> ipinfo.io
        4. политика: RU / противоречие IPv4-IPv6 / неопределённая страна -> отсев
   ▼
export:  output/vpn-whitelist-meeyota.txt   (все)
         output/vpn-wifi-meeyota.txt        (только прошедшие проверку)
         data/configs.json, data/checks.json, data/stats.json
         README.md (автоматический блок со ссылками)
   ▼
GitHub Actions: коммит только если изменилось -> GitHub Pages (output/)
```

### Защита от обнуления подписки

1. **Кэш источника** (`data/cache/`, не коммитится): если live-fetch упал,
   используется последний успешный fetch (до `cache_ttl_days`).
2. **Предыдущее состояние** (`data/configs.json`, коммитится): для источника,
   который недоступен и в кэше нет, берутся его конфиги из прошлого прогона.
3. **Guard**: если новый whitelist < 30% прежнего (и минимум 10 строк) —
   пайплайн считает запуск ошибочным, старые подписки не трогаются,
   коммит и деплой не выполняются.
4. **Wifi-guard**: если wifi-подписка стала бы пустой, а проверки не
   выполнялись/не прошли ни по одной — старый список сохраняется.

### Конфигурация

Каждая конфигурация в `data/configs.json` хранится в схеме:

```json
{
  "protocol": "vless",
  "address": "1.2.3.4",
  "port": 443,
  "name": "🇩🇪 Германия",
  "source": "FLAT447/v2ray-lists · WHITE_FULL (flat447-white-full)",
  "raw": "vless://... (оригинальный URI сохраняется как есть)",
  "hash": "sha256(raw)",
  "last_check": "2026-09-12T14:03:22Z",
  "country": "DE",
  "ip": "185.240.194.1",
  "fingerprint": "vless|1.2.3.4:443|uuid|tcp|xtls-rprx-vision|sni"
}
```

## 📂 Дерево проекта

```
meeyota-vpn/
├── .github/
│   └── workflows/
│       └── update.yml          # CI: tests + build + commit + GitHub Pages
├── src/
│   ├── main.py                 # CLI и пайплайн
│   ├── config.py               # sources.yaml + настройки
│   ├── collectors/
│   │   ├── http_client.py      # fetch: retry/timeout/max_bytes, file://
│   │   └── source.py           # collect + кэш-фолбэк
│   ├── parsers/
│   │   ├── uri.py              # vless/vmess/trojan/ss/hy2/socks5/http/tuic/mtproto
│   │   └── subscription.py     # текст подписки -> URI (base64, комментарии)
│   ├── models/
│   │   └── config.py           # VpnConfig, fingerprint, xray-outbound
│   ├── checks/
│   │   ├── geo.py              # ipwho.is -> ip-api.com -> ipinfo.io
│   │   ├── xray.py             # загрузка Xray-core, зонд внешнего IP
│   │   └── checker.py          # оркестрация проверок, wifi-политика
│   ├── deduplicator.py
│   └── exporter.py             # подписки, guard, Incy-ссылки, README
├── data/                        # configs.json, checks.json, stats.json (коммитятся)
│   ├── bin/                     # xray (не коммитится)
│   └── cache/                   # кэш источников (не коммитится)
├── output/                      # vpn-whitelist-meeyota.txt, vpn-wifi-meeyota.txt
├── tests/                       # 59 оффлайн-тестов (парсеры, дедуп, политика, E2E)
├── sources.yaml                 # источники — добавляются БЕЗ изменения кода
├── requirements.txt
└── README.md
```

## 🚀 Запуск

### 1. На GitHub (рекомендуется)

1. Запушьте репозиторий на GitHub (username/имя — ваши, реальные).
2. **Settings → Pages → Build and deploy → Source: «GitHub Actions»**.
3. Workflow `.github/workflows/update.yml`:
   - запускается **вручную** (Actions → «Update meeyota subscriptions» → Run workflow);
   - автоматически **по расписанию** (каждые 4 часа) и при изменении `sources.yaml`;
   - скачивает свежие данные из всех источников (ошибка одного источника не
     роняет цикл — кэш/фолбэк),
   - выполняет проверки внешнего IP (лимит за прогон — переменная `MAX_CHECKS`),
   - коммитит изменения **только если файлы изменились**,
   - деплоит `output/` на GitHub Pages.
4. Опциональные переменные репозитория (Settings → Secrets and variables →
   Actions → Variables): `MAX_CHECKS` (по умолчанию 400), `WORKERS` (5),
   `CHECK_TTL_HOURS` (24).
5. После деплоя ссылки:
   `https://{username}.github.io/{repo}/vpn-whitelist-meeyota.txt` и т.д.
   Блок со ссылками в README обновится автоматически при следующем прогоне.

> Первый прогон может занять до ~50 минут: скачиваются ~30 МБ подписок,
> затем до `MAX_CHECKS` конфигураций проверяются по 5 параллельно.
> Далее, благодаря кэшу проверок (TTL 24 ч), прогоны короче.

### 2. Локально

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# полный цикл (нужен интернет: GitHub + ipify + geo-API):
python -m src.main

# только сборка, без проверок внешнего IP:
python -m src.main --skip-checks

# принудительно перепроверить всё, 8 зондов, лимит 200:
python -m src.main --recheck-all --max-checks 200 --workers 8

# напечатать incy://import/{base64} снапшот после сборки:
python -m src.main --skip-checks --incy-import

# тесты:
pytest -q
```

Полезные флаги: `--data-dir`, `--output-dir`, `--readme`, `--username`,
`--repository` (для ссылок), `--dry-run` (ничего не записывать),
`--check-ttl-hours` (свежесть проверок), `--check-timeout`.

Результаты: `output/vpn-whitelist-meeyota.txt`, `output/vpn-wifi-meeyota.txt`,
`data/stats.json` (найдено/валидных/битых/дубликатов/уникальных/проверено/
отфильтровано по причинам), а в конце пайплайн печатает обе Incy-ссылки.

## ➕ Как добавить новый источник

Ничего в Python менять не нужно — добавьте блок в `sources.yaml`:

```yaml
sources:
  - id: my-source            # уникальный id (латиница, без пробелов)
    name: MyRepo · sub.txt   # человекочитаемое имя (попадёт в configs.json)
    url: https://raw.githubusercontent.com/owner/repo/main/sub.txt
    enabled: true            # false — временно отключить без удаления
    # опционально (переопределяют defaults):
    # timeout: 30
    # retries: 3
    # retry_delay: 5
    # max_bytes: 25000000    # ограничение размера файла
    # note: "откуда/почему"
```

Поддерживаются файлы: plain URI по строке (комментарии `#` пропускаются),
целое содержимое в base64, URI, склеенные без разделителей.
Прямой URL любого хоста (raw.githubusercontent, свои зеркала и т.п.).
После коммита `sources.yaml` workflow пересоберёт подписки (также — по расписанию).

## 📊 Текущие источники (проверены по актуальной структуре, 2026-09-12)

| Репозиторий | Файлы |
|---|---|
| FLAT447/v2ray-lists | `WHITE_FULL.txt`, `BLACK_FULL.txt`, `BASE64/WHITE_FULL.txt`, `blacklist.txt` (MTProxy) |
| hiztin/VLESS-PO-GRIBI | `deploy/sub.txt`, `deploy/sub_base64.txt` |
| AvenCores/goida-vpn-configs | `githubmirror/1.txt` … `githubmirror/26.txt` (2.txt — с ограничением 8 МБ) |
| igareck/vpn-configs-for-russia | 8 файлов в корне: `BLACK_*`, `WHITE-*`, `Vless-Reality-White-Lists-Rus-Mobile.txt` |
| whoahaow/rjsxrd | `githubmirror/bypass/bypass-all.txt`, `githubmirror/bypass-unsecure/bypass-unsecure-all.txt` |

## 🧪 Проверка внешнего IP: детали

- Xray-core скачивается автоматически (latest release → запасные версии) в
  `data/bin/` и используется как одноразовый локальный прокси:
  inbound HTTP-прокси на `127.0.0.1:<случайный порт>` + единственный outbound
  из конфигурации. **Fallback на direct отсутствует** — если VPN мёртв,
  запрос не пройдёт (а не «сработает» IP самого раннера).
- IPv4: `https://api4.ipify.org` (запасной `ipv4.icanhazip.com`);
  IPv6: `https://api6.ipify.org` (запасной `ipv6.icanhazip.com`).
- Геолокация: `ipwho.is` → `ip-api.com` → `ipinfo.io` (все без ключей).
- Политика `VPN Wi-fi meeyota`: IPv4 получен и страна определена и ≠ RU;
  если IPv6 получен — его страна определена, ≠ RU и **равна** стране IPv4
  (иначе «противоречие» → отсев). Неопределённая страна → отсев.
  Проверка старше `CHECK_TTL_HOURS` → отсев до перепроверки.
- MTProto/TUIC и конфиги с неподдерживаемым транспортом попадают в whitelist,
  но в wifi — нет (их не проверить через xray).

## ⚖️ Дисклеймер

Проект агрегирует **публичные** конфигурации из открытых репозиториев в
исследовательских целях. Использование бесплатных публичных VPN-серверов может
нарушать правила их провайдеров; работоспособность и юридическая чистота
отдельных серверов не гарантируются. Авторы не несут ответственности за
результаты использования. Не публикуйте чужие закрытые ключи/токены.
