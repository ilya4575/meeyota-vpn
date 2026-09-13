# meeyota-vpn

Агрегатор публичных VPN-конфигураций из GitHub-репозиториев.

Собирает, нормализует, дедуплицирует и проверяет конфигурации, затем
публикует **ровно два профиля** через GitHub Pages:

| Профиль | Назначение |
|---|---|
| **VPN whitelist meeyota** | Объединённая подборка всех валидных конфигураций из всех источников |
| **VPN Wi-fi meeyota** | Подмножество для Wi-Fi-сетей (только проверенные non-RU IP-узлы) |

Каждый профиль — это **один full Xray JSON** для клиента **Incy**.
Incy показывает его как **один сервер** в UI, а выбор рабочего узла
происходит автоматически через Xray-core (`burstObservatory` +
`routing.balancers` со стратегией `leastLoad`).

Никаких 12 000 отдельных серверов. Никакого ручного перебора.

---

## Результат после импорта в Incy

```
Подписка
├── VPN whitelist meeyota       ← 1 запись
└── VPN Wi-fi meeyota           ← 1 запись
```

Внутри каждой записи — пул из N собранных конфигураций (`proxy-1`,
`proxy-2`, …, `proxy-N`), и Xray-core автоматически выбирает лучший из
них через balancer.

---

## Источники

Берём публичные GitHub-репозитории (декларативно, через `sources.yaml`):

| Источник | Файлы | Протоколы |
|---|---|---|
| [`FLAT447/v2ray-lists`](https://github.com/FLAT447/v2ray-lists) | `WHITE_FULL.txt`, `BLACK_FULL.txt` | vless, ss, trojan, hysteria2 |
| [`hiztin/VLESS-PO-GRIBI`](https://github.com/hiztin/VLESS-PO-GRIBI) | `deploy/subscriptions/1.txt` | vless (Reality/grpc/xhttp) |
| [`AvenCores/goida-vpn-configs`](https://github.com/AvenCores/goida-vpn-configs) | `githubmirror/1.txt`, `githubmirror/7.txt` | vless, trojan, vmess, ss |

> **О goida:** README этого репозитория содержит «обход блокировок».
> Мы используем его **только как технический склад URI**; никакой
> RU-специфичной логики (CIDR/SNI/whitelist-bypass) в наши подписки
> **не передаётся**. Семантика **нашего** проекта — агрегатор
> плюс автоматический выбор, а не обход чего-либо.
>
> **О igareck/vpn-configs-for-russia:** этот источник **намеренно
> не используется** — его декларируемая цель («whitelist bypass»)
> противоречит цели нашего проекта.

---

## Поддерживаемые протоколы

Парсер распознаёт следующие URI-схемы:

* `vless://` (Reality, TLS, ws, grpc, xhttp, vision-flow)
* `vmess://` (legacy JSON-base64)
* `trojan://`
* `ss://` (SIP002 + legacy base64)
* `hysteria2://` / `hy2://`

Схемы `ssr://`, `tuic://`, `hysteria://` (v1) — Incy их распознаёт, но
**не парсит** (документация Incy). Мы их пропускаем с предупреждением.

---

## Как импортировать в Incy

URL после публикации:

```
https://<username>.github.io/meeyota-vpn/vpn-whitelist-meeyota.json
https://<username>.github.io/meeyota-vpn/vpn-wifi-meeyota.json
```

В Incy:

1. Откройте приложение → Subscriptions → **+** → **Add from URL**.
2. Вставьте `https://...vpn-whitelist-meeyota.json` → подтвердите.
3. Повторите для `vpn-wifi-meeyota.json`.
4. Подписка обновится автоматически (раз в 6 часов, см. workflow).

Deep link (iOS/Android — откроет Incy напрямую):

```
incy://add/https://<username>.github.io/meeyota-vpn/vpn-whitelist-meeyota.json
incy://add/https://<username>.github.io/meeyota-vpn/vpn-wifi-meeyota.json
```

Зашифрованный вариант (crypt1) — генерируется официальным
[`@incy/link-encoder`](https://github.com/INCY-DEV/incy-link-encoder).
Полезно для QR-кодов: URL подписки скрыт от посторонних глаз.

---

## Как устроен автоматический выбор узла

Incy нативно поддерживает **full Xray JSON** — полный конфиг Xray-core,
который передаётся движку почти без изменений. В таком конфиге мы
объявляем:

1. **Все собранные URI** как `outbounds` с тегами `proxy-1`, `proxy-2`, …
   плюс один с тегом, **совпадающим с именем профиля** (см. ниже — почему).
2. **Balancer** с селектором, который prefix-match'ит все `proxy-*`
   outbounds + тег профиля, стратегия `leastLoad` (выбирает наименее
   загруженный узел по данным observatory).
3. **`burstObservatory`** с тем же `subjectSelector` — раз в 30 секунд
   (whitelist) или 60 секунд (wifi) делает 2 ping-замера на
   `http://www.google.com/generate_204` через каждый узел.
4. **`fallbackTag: "direct"`** — если все узлы мёртвые, трафик идёт
   напрямую (это требование Xray-core чтобы избежать «всё упало»).
5. **DNS** через Cloudflare/Google DoH, и правило
   `routing.rules: { ip: ["1.1.1.1","8.8.8.8"], outboundTag: "direct" }`
   чтобы DNS-разрешение для проверок не шло через balancer (петля).

В UI Incy показывает это как **одну запись**, потому что Incy
документирует:

> **Full configurations are displayed as a single server in the list.**
> The server name is taken from the first proxy-outbound.

Имя первого outbound'а мы ставим равным имени профиля (`VPN whitelist
meeyota` или `VPN Wi-fi meeyota`) — это **единственный** документированный
Incy способ показать имя для full Xray JSON. `meta.serverDescription`
внутри JSON — это **описание** (подпись под именем, max 30 символов), а
не само имя. `profile-title` в HTTP-заголовках/теле подписки — это имя
**подписки**, а не имя сервера внутри неё.

---

## Как формируется VPN Wi-fi meeyota

Из всего пула валидных конфигураций Wi-Fi подписка берёт подмножество:

1. Узел должен иметь IP-адрес (доменные — пропускаются, т. к. для их
   проверки нужен DNS-резолв, который в CI небезопасен).
2. Внешний IP запрашивается через `ipwho.is` (основной) или
   `ip-api.com` (fallback).
3. Если страна — `RU` или не определена — узел **исключается**.
4. Результат кэшируется в `data/check_results.json` с TTL 3 дня.

**Известные ограничения** (документируем честно):

* Проверка делается из GitHub Actions runner'а (США). Узел, отлично
  работающий с домашнего Wi-Fi, может быть недоступен из CI и наоборот.
  Это — цена отказа от VPS.
* Гео-IP базы могут ошибаться. Поэтому применён строгий «нет
  подтверждения ≠ вне РФ» подход.

---

## GitHub Actions

* Расписание: каждые 6 часов (`cron: "0 */6 * * *"`) + ручной запуск
  (`workflow_dispatch`).
* Pipeline:
  1. Скачать файлы источников (`retry`, `timeout`, `ETag`-кэш,
     GitHub API fallback при недоступности raw).
  2. Распарсить → нормализовать → дедуплицировать → валидировать.
  3. Сгенерировать два full Xray JSON в `output/`.
  4. Структурно валидировать итог.
  5. Задеплоить `output/` на GitHub Pages через `actions/deploy-pages@v4`.
  6. Сохранить `data/stats.json` (через git commit, если изменился).

**Защита от пустого результата:** если новый whitelist содержит
меньше `safety.min_configs_whitelist` (по умолчанию 50) конфигов —
workflow завершается с ошибкой и `output/` **не перезаписывается**.

---

## Разработка

```bash
# Установить зависимости
pip install -r requirements.txt

# Прогнать все тесты
PYTHONPATH=. python3 tests/test_parsers.py
PYTHONPATH=. python3 tests/test_normaliser.py
PYTHONPATH=. python3 tests/test_validator.py
PYTHONPATH=. python3 tests/test_emitter.py
PYTHONPATH=. python3 tests/test_incy_import.py
PYTHONPATH=. python3 tests/test_scale.py
PYTHONPATH=. python3 tests/test_collector.py
PYTHONPATH=. python3 tests/test_pipeline.py

# Или одной командой:
for t in tests/test_*.py; do PYTHONPATH=. python3 "$t" || exit 1; done

# Локальный запуск пайплайна (нужен GITHUB_TOKEN для rate-limit)
export GITHUB_TOKEN=...
./run_local.sh
```

### Структура

```
src/
├── collectors/github.py     # скачивание raw + ETag-кэш + API fallback
├── parsers/uri.py           # vless/vmess/trojan/ss/hy2
├── models/config.py         # VpnConfig + canonical hash
├── normaliser.py            # lower-case параметров, host, fragment
├── deduplicator.py          # по canonical hash
├── validator.py             # структурные проверки
├── emitter/xray.py          # генерация full Xray JSON
├── checks/                  # Wi-Fi фильтрация (геолокация IP)
└── main.py                  # entry point
tests/
├── test_parsers.py
├── test_normaliser.py
├── test_validator.py
├── test_emitter.py
├── test_incy_import.py      # симуляция импорта Incy
├── test_scale.py            # проверка масштабирования
├── test_collector.py        # с моком requests
├── test_pipeline.py         # smoke-test pipeline с моком коллектора
├── simulate_incy_import.py  # точно моделирует поведение Incy-парсера
└── validate_incy_profile.py # структурная валидация JSON
docs/
├── ARCHITECTURE-DRAFT.md    # первоначальный архитектурный черновик
├── TEST-JSON-EXAMPLE.json   # первый тестовый JSON (3 outbounds)
├── SMOKE-TEST-whitelist.json # минимальный smoke-test whitelist
└── SMOKE-TEST-wifi.json     # минимальный smoke-test wifi
```

---

## Что проверено автоматически, а что — нет

| Проверка | Как проверено | Статус |
|---|---|---|
| Один JSON → один сервер в Incy | Симулятор `tests/simulate_incy_import.py` моделирует поведение Incy-парсера по официальной документации | ✅ автоматически |
| Структура JSON (balancer, observatory, fallbackTag, DNS, правила) | `tests/validate_incy_profile.py` — структурный валидатор | ✅ автоматически |
| Масштабирование до 1000+ outbounds | `tests/test_scale.py` — генерит 1000/2000 outbounds и проверяет | ✅ автоматически |
| Имя сервера берётся из `outbounds[0].tag` | Тест `test_emit_first_outbound_matches_profile_name` | ✅ автоматически |
| Xray-core принимает JSON без ошибок | **Не проверено** — в этом окружении xray-core недоступен | ⚠️ требует ручного теста в Incy |
| Автовыбор реально работает в Incy | **Не проверено** — Incy нельзя запустить в CI | ⚠️ требует ручного теста |
| Incy отображает 2 записи после импорта обеих подписок | **Не проверено** — Incy нельзя запустить в CI | ⚠️ требует ручного теста |

### Что нужно проверить вручную после первого деплоя

1. Открыть Incy → импортировать обе ссылки.
2. Убедиться, что в списке **ровно 2 сервера** с именами `VPN whitelist
   meeyota` и `VPN Wi-fi meeyota`.
3. Включить `VPN whitelist meeyota` → проверить, что трафик идёт
   (значит Xray-core поднял конфиг и balancer работает).
4. Подождать 30 секунд, переподключиться — должен выбраться другой
   узел (значит burstObservatory обновляет данные).

---

## Известные ограничения

1. **Incy берёт имя full Xray config только из тега первого outbound'а.**
   Других штатных способов (по документации Incy) нет. Это значит, что
   имя профиля живёт внутри `outbounds[0].tag`. Это требование
   клиента, а не наш выбор.
2. **GitHub Actions runner в США.** Wi-Fi-проверка может false-positive
   / false-negative относительно пользовательской сети.
3. **GitHub Pages не позволяет задать HTTP-заголовки** произвольно.
   Метаданные подписки (`#profile-title:` и т. п.) мы кладём **в тело**
   JSON-файла как Incy-комментарии. JSON-парсер их игнорирует, Incy —
   документированный fallback.
4. **Без VPS мы не делаем real-network-проверки тысяч URI** —
   Wi-Fi-фильтрация идёт с TTL-кэшем 3 дня.

---

## Лицензия

MIT (или другая по вашему выбору — добавьте файл `LICENSE`).
