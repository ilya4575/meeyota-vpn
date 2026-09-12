# meeyota-vpn

Агрегатор публичных VPN-конфигураций из GitHub-репозиториев. Собирает,
нормализует и дедуплицирует конфигурации, затем публикует **две** подписки
через GitHub Pages:

* **VPN whitelist meeyota** — объединённый белый список всех валидных
  конфигураций из всех источников;
* **VPN Wi-fi meeyota** — строгий подмножество: только серверы, чей
  **фактический внешний IP (IPv4 и IPv6) не определяется как Российская
  Федерация** (проверка реальным соединением + геолокация).

Вся инфраструктура — GitHub Actions + GitHub Pages. **Без VPS, без Docker,
без базы данных.**

<!-- INCY-LINKS:BEGIN (автоматически генерируется — не редактировать) -->

## 🔗 Ссылки для импорта в Incy

Основной (приоритетный) способ — `incy://add/{url}`: клиент сам обновляет
подписку на стороне GitHub Pages, повторный импорт не нужен.

**VPN whitelist meeyota** — vpn-whitelist-meeyota.txt

`incy://add/https://ilya4575.github.io/meeyota-vpn/vpn-whitelist-meeyota.txt`

**VPN Wi-fi meeyota** — vpn-wifi-meeyota.txt

`incy://add/https://ilya4575.github.io/meeyota-vpn/vpn-wifi-meeyota.txt`

Одноразовый импорт содержимого (`incy://import/{base64}`) формируется
опционально командой `python -m src.main --import-link data/incy-import-links.txt`
(используется, когда `incy://add/{url}` недоступен).

<!-- INCY-LINKS:END -->

> ⚠️ Ссылки выше актуальны для репозитория `ilya4575/meeyota-vpn`. При
> переносе проекта в другой репозиторий измените секцию `pages` в
> `sources.yaml` — блок обновится автоматически при следующем запуске.
> До первого запуска workflow блок будет содержать `USERNAME`/`REPOSITORY`.

---

## Как это работает

```
GitHub Actions (каждые 6 ч / вручную)
  │
  ├─ 1. Скачивание файлов источников
  │      (retry, timeout, ETag-кэш, лимит размера, GitHub API как fallback)
  ├─ 2. Парсинг и нормализация URI
  │      (VLESS, VMess, Trojan, Shadowsocks, SSR, Hysteria/Hysteria2, TUIC,
  │       SOCKS5; base64-файлы и &amp;-сущности обрабатываются)
  ├─ 3. Дедупликация (канонический хеш: сервер+порт+креды+транспорт)
  ├─ 4. Проверки для «VPN Wi-fi» (sing-box):
  │      реальное соединение → внешний IPv4 (+IPv6, если есть) →
  │      геолокация (ipwho.is, fallback ip-api.com) → строгий вердикт
  ├─ 5. Экспорт output/*.txt + data/*.json
  │      (защита от обнуления: при аномальном падении списка подписки
  │       НЕ перезаписываются)
  ├─ 6. Коммит ТОЛЬКО если файлы изменились
  └─ 7. Публикация output/ на GitHub Pages
```

### Правила подписки «VPN Wi-fi meeyota» (строгие)

1. устанавливается реальное соединение с конфигурацией (sing-box,
   mixed-proxy на 127.0.0.1, прогонка трафика через прокси);
2. определяется фактический внешний **IPv4**;
3. при наличии выхода в IPv6 определяется и **IPv6**;
4. страна каждого IP определяется через геолокационный API
   (основной — `ipwho.is`, запасной — `ip-api.com`);
5. если IPv4 **или** IPv6 определяется как `RU` — конфигурация **не
   включается**;
6. если IPv4 и IPv6 дают **разные** страны — конфликт, конфигурация
   **не включается**;
7. если страна не определяется (оба API молчат) — **не включается**
   (нет подтверждения «вне РФ»);
8. дата последней проверки (`last_check`) и результат (`country`, `ip`,
   `verdict`) сохраняются в `data/check_results.json`,
   `data/configs.json` и в комментариях над каждой строкой подписки.

> **О геолокации.** Абсолютной гарантии нет: IP-базы могут ошибаться и
> обновляются с задержкой. Поэтому используется максимально строгий отсев —
> в подписку попадает только то, что при актуальной проверке явно
> определено как вне РФ, а любые сомнения (конфликт, неизвестная страна,
> сбой) исключают конфигурацию. Результаты кэшируются 3 дня
> (`checks.ttl_days`), повторные проверки — по расписанию.

---

## Источники

Фактические файлы выбраны по актуальной структуре репозиториев
(проверено через GitHub API):

| Источник | Файлы | Протоколы |
|---|---|---|
| [FLAT447/v2ray-lists](https://github.com/FLAT447/v2ray-lists) | `WHITE_FULL.txt`, `BLACK_FULL.txt` | vless, ss, hysteria2 |
| [hiztin/VLESS-PO-GRIBI](https://github.com/hiztin/VLESS-PO-GRIBI) | `deploy/sub.txt` (объединённая) | vless, ss, vmess |
| [AvenCores/goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs) | `githubmirror/{1,6,22,23,24,25}.txt` (рекомендованные в README; 2.txt≈100 МБ и 21.txt≈20 МБ намеренно не включены) | vless, vmess, trojan, ss, hy2, socks5 |
| [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) | `BLACK_VLESS_RUS.txt`, `BLACK_SS+All_RUS.txt`, `BLACK_VLESS_RUS_mobile.txt`, `BLACK_SS_WEAK_DPI_RUS.txt`, `Vless-Reality-White-Lists-Rus-Mobile.txt` | vless, vmess, hy2, trojan |
| [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd) | `githubmirror/bypass/bypass-all.txt` | vless, ss, trojan, vmess |

Управление источниками — только через [`sources.yaml`](sources.yaml),
код менять не нужно (см. ниже).

---

## Структура проекта

```
meeyota-vpn/
├── .github/
│   └── workflows/
│       └── update.yml          # сборка + проверки + Pages
├── src/
│   ├── collectors/
│   │   └── github.py           # raw + API-fallback, retry, ETag-кэш, лимит размера
│   ├── parsers/
│   │   └── uri.py              # vless/vmess/trojan/ss/ssr/hy2/tuic/socks5, base64, &amp;
│   ├── models/
│   │   └── config.py           # VpnConfig + канонический хеш
│   ├── checks/
│   │   ├── connectivity.py     # sing-box: конфиг, запуск, внешний IPv4/IPv6
│   │   ├── geolocation.py      # ipwho.is + ip-api.com, кэш
│   │   └── verifier.py         # оркестрация: кэш, бюджет времени, вердикты
│   ├── deduplicator.py
│   ├── exporter.py             # подписки, Incy-ссылки, защита от обнуления
│   ├── config.py               # sources.yaml → Settings
│   └── main.py                 # точка входа
├── data/                        # кэш, результаты проверок, stats.json, configs.json
├── output/
│   ├── vpn-whitelist-meeyota.txt
│   └── vpn-wifi-meeyota.txt
├── tests/                       # 67 тестов (pytest)
├── sources.yaml
├── requirements.txt
└── run_local.sh
```

---

## Локальный запуск

```bash
./run_local.sh                  # venv + зависимости + агрегация (без проверок)
# или вручную:
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m src.main --verbose
```

С проверками соединения (нужен [sing-box](https://github.com/SagerNet/sing-box)
в PATH или `SINGBOX_BIN=/path/to/sing-box`):

```bash
SINGBOX_BIN=/usr/local/bin/sing-box python -m src.main --checks --workers 8 --check-minutes 60
```

Одноразовые ссылки `incy://import/{base64}`:

```bash
python -m src.main --import-link data/incy-import-links.txt
```

Тесты:

```bash
pytest tests/ -q
```

> Примечание: в средах, где `requests` не доверяет системным CA
> (прокси/MITM), задайте `REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt`.

---

## Как добавить новый источник

Отредактируйте `sources.yaml` (код не меняется):

```yaml
sources:
  # ... существующие ...

  # GitHub-репозиторий:
  - id: my-new-source            # уникальный id
    name: "owner/repo"
    type: github
    repo: owner/repo
    branch: main
    files:
      - path: subscriptions/all.txt
        max_size_mb: 10          # опционально: лимит на файл

  # Произвольный HTTPS-URL (подписка, которую отдаёт любой сервер):
  - id: my-raw-url
    type: url
    files:
      - https://example.com/subscription.txt
```

Правила:

* `id` — уникальный, без пробелов (попадает в статистику и `configs.json`);
* `files` — список путей (относительно корня репозитория) или URL;
* файл может быть raw-URI, base64-блоком или base64-строками —
  определяется автоматически;
* `enabled: false` временно отключает источник;
* после коммита `sources.yaml` следующий запуск (автоматически по push или
  вручную) подхватит новый источник.

---

## GitHub Actions

Workflow [`.github/workflows/update.yml`](.github/workflows/update.yml):

* **вручную**: Actions → *Update VPN subscriptions* → *Run workflow*;
* **автоматически**: расписание `0 */6 * * *` (каждые 6 часов);
* при push в `main`, затронувшем `sources.yaml`, `src/**` или сам workflow;
* установка sing-box для проверок;
* обработка ошибок отдельных источников (один мёртвый источник не роняет
  запуск), retry/timeout на уровне HTTP;
* дедупликация, проверки, генерация двух подписок;
* **коммит только если файлы действительно изменились**;
* деплой `output/` на GitHub Pages (артефакт → `actions/deploy-pages`).

Защита от обнуления: если количество валидных конфигов упало ниже
`safety.min_configs` или потеряно более чем `safety.max_drop_ratio` от
прежнего списка — подписки **не перезаписываются**, запуск завершается с
кодом 2, старый файл и страница остаются на месте.

---

## GitHub Pages

Публикуется каталог `output/` в корень сайта. После публикации должны
существовать:

```
https://USERNAME.github.io/REPOSITORY/vpn-whitelist-meeyota.txt
https://USERNAME.github.io/REPOSITORY/vpn-wifi-meeyota.txt
```

Для этого репозитория:

```
https://ilya4575.github.io/meeyota-vpn/vpn-whitelist-meeyota.txt
https://ilya4575.github.io/meeyota-vpn/vpn-wifi-meeyota.txt
```

### Одноразовая настройка (делает владелец репозитория)

1. Откройте **Settings → Pages**;
2. в блоке **Build and deployment**:
   * **Source** → выберите **GitHub Actions**;
3. сохраните.

> Альтернатива — API: `gh api -X PUT /repos/USERNAME/REPOSITORY/pages -f build_type=workflow`
> (нужен токен владельца, а не GitHub App).

После этого каждый успешный запуск workflow сам обновит сайт. URL из
секции `pages` в `sources.yaml` автоматически подставляются в блок Incy-ссылок
README и в `data/incy-links.txt`.

---

## Данные и статистика

| Файл | Что хранит |
|---|---|
| `data/stats.json` | счётчики: найдено / валидных / битых / уникальных / дубликатов / whitelist / wifi + статус каждого источника + статистика проверок |
| `data/configs.json` | все уникальные конфиги: `protocol, address, port, name, source, raw, hash, last_check, country, ip` |
| `data/check_results.json` | результаты проверок по серверам (verdict, ip4/ip6, страны, дата) и по хешам конфигов |
| `data/geo_cache.json` | кэш «IP → страна» (до `checks.geo_cache_max` записей) |
| `data/incy-links.txt` | готовые `incy://add/...` ссылки |
| `data/cache/` | кэш скачанных файлов и ETag (не коммитится) |

---

## Ограничения

* Публичные бесплатные конфигурации — доверять им нельзя: это чужие серверы,
  работа и приватность не гарантируются.
* Транспорт `xhttp`/`httpupgrade` поддерживается xray/v2rayN/Incy, но не
  sing-box — такие конфиги попадают в whitelist, но для Wi-fi-подписки не
  проверяются (вердикт `error`).
* Wi-fi-подписка растёт по мере проверок: за один запуск проверяется
  бюджет `checks.minutes` минут работы, остальные серверы дойдут до
  проверки в следующих запусках (результаты кэшируются).
* Геолокация — вероятностная; см. дисклеймер выше.
* История коммитов `output/` и `data/` со временем разрастает репозиторий;
  при необходимости его можно очистить (история подписок не критична).
