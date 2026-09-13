# meeyota-vpn — анализ задачи и предложение архитектуры

> Документ-черновик. **Код не пишется до подтверждения пользователем.**
> Дата проверки источников: 2026-09-13 (UTC).

---

## 1. Анализ требований

Проект — обычный агрегатор и менеджер публичных VPN-конфигураций:

* берёт URI-конфиги из публичных GitHub-источников;
* парсит → нормализует → дедуплицирует → валидирует;
* выдаёт **две подписки** (whitelist и Wi-Fi) в формате, который
  Incy (iOS/Android/Desktop VPN-клиент на Xray-core) умеет импортировать
  и **сам выбирает рабочий узел** без ручного перебора тысяч серверов;
* обновляется по расписанию через GitHub Actions;
* публикуется через GitHub Pages;
* защищён от падения источника, от пустого результата, от выхода за
  лимиты Actions.

**Чего проект НЕ делает** (по требованию пользователя):

* не нацелен на обход конкретных государственных/корпоративных
  ограничений или блокировок (никакой «обход DPI / CIDR / SNI / белых
  списков» как *цели*);
* не требует VPS, БД, Docker.

---

## 2. Проверка источников (актуальное состояние на 2026-09-13)

Проверено через GitHub API (`/repos/{owner}/{repo}/contents/`) и
скачиванием файлов с `raw.githubusercontent.com`.

### 2.1. `igareck/vpn-configs-for-russia`

* README явно описывает проект как «обход белых списков / whitelist bypass»,
  что **противоречит требованию пользователя** «не добавлять функциональность
  для обхода конкретных государственных/корпоративных блокировок».
* Файлы в корне — это сортированные подписки: `BLACK_VLESS_RUS.txt`,
  `BLACK_SS+All_RUS.txt`, `BLACK_SS_WEAK_DPI_RUS.txt`, `BLACK_VLESS_RUS_mobile.txt`,
  `WHITE-CIDR-RU-all.txt`, `WHITE-CIDR-RU-checked.txt`, `WHITE-SNI-RU-all.txt`,
  `Vless-Reality-White-Lists-Rus-Mobile.txt`. Метки `[BL]`, `[WL]`, `[*CIDR]`,
  `[VK]`, `[Я]` и т. п. — это и есть признаки узкой целевой аудитории
  (только RU).
* Папки: `Export/`, `QR-codes/`, `TOR-BRIDGES/`.

**Решение:** источник **отбрасываем целиком**. Технически подписки валидны
и парсятся, но семантика всего репозитория противоречит пункту «Важное
ограничение» требований. Если пользователь хочет его оставить, нужно
явное подтверждение — иначе это будет нарушением исходных требований.

### 2.2. `FLAT447/v2ray-lists` — берём

* Корневые TXT-подписки (не зависят от RU-тематики, генерируются
  ботом `v2ray-collector-bot`):
  * `WHITE_FULL.txt`, `WHITE_LITE.txt` — белый список;
  * `BLACK_FULL.txt`, `BLACK_LTE.txt` — расширенный список;
  * `whitelist.txt`, `blacklist.txt` — служебные.
* Папки `BASE64/` и `CLASH/` содержат альтернативные представления
  тех же данных.
* В файлах встречаются URI с телом-метаданными Incy:
  `#announce:`, `#profile-web-page-url:`, `#profile-title:`,
  `#support-url:`, `#profile-update-interval: 1`.
* Протоколы в файлах: `vless://`, `trojan://`, `ss://`, `hy2://` /
  `hysteria2://`. Hysteria1 (`hysteria://`) и TUIC в актуальных файлах
  практически не встречаются — поддерживать их парсер ради гипотетики
  не будем.

### 2.3. `hiztin/VLESS-PO-GRIBI` — берём

* Папка `deploy/subscriptions/` содержит пронумерованные подписки
  `1.txt` … `25.txt`, каждая — результат сбора из конкретного
  upstream-источника (по словам README).
* Преимущественно `vless://` (Reality + Vision + grpc + xhttp), есть
  также `ss://`.
* README упоминает, что «SS могут сейчас не работать из-за их
  замедления» — это намёк на то, что источник **знает про ограничения**,
  но собирает валидные на момент сбора URI. Технически для агрегатора
  это нормально: мы фильтруем битые URI на этапе валидации.
* Объединённой подписки `deploy/sub.txt` сейчас **нет** (README
  упоминает её как историческую); актуальные файлы — только
  `deploy/subscriptions/N.txt`. Будем брать `1.txt` как
  представительный срез (если упадёт — расширим набор).
* Сам README говорит: «ежедневно обновляемая коллекция рабочих
  VPN-серверов». Семантика проекта — агрегатор, не «обход блокировок».
  Годится.

### 2.4. `AvenCores/goida-vpn-configs` — берём частично

* Папка `githubmirror/` содержит 26 файлов-зеркал `1.txt` … `26.txt`
  upstream-источников (см. таблицу из README).
* Это **самый большой и разнообразный** источник: vless, trojan, vmess,
  ss. Есть `vmess://` (нужен парсер).
* Но README прямо говорит «для быстрого обхода блокировок» и описывает
  проект как «whitelist bypass». Это **та же проблема**, что и у
  igareck.

**Решение:** включаем файлы **только как технический источник URI**.
Никакой маршрутизации, никаких CIDR/SNI-списков, никаких
RU-специфичных пометок мы в итоговые подписки не транслируем. Семантика
**нашего** проекта остаётся «агрегатор + автоселект»; репозиторий
воспринимается только как пассивное хранилище URI.

> **Нужно подтверждение пользователя.** Если «Важное ограничение»
> трактуется как «не использовать источники, чья декларируемая цель —
> обход блокировок», то goida тоже надо отбросить. Здесь я исхожу из
> более узкой трактовки: ограничение относится к тому, что **наш
> проект** не добавляет такой функциональности; источники остаются
> просто сырыми URI. Прошу уточнить.

---

## 3. Incy — что поддерживается и как сделать автоселект

Документация: <https://incy.gitbook.io/docs/docs-en/subscription-format>
и <https://incy.gitbook.io/docs/docs-en/full-xray-config>.
Проверено 2026-09-13.

### 3.1. Форматы тела подписки

Incy понимает **5 форматов** тела подписки:

1. **Base64-ссылки** (одна строка — это base64 от многострочного списка URI);
2. **Plain-text ссылки** (URI по одной на строку);
3. **JSON — массив полных Xray-конфигов**;
4. **JSON — единый полный Xray-конфиг**;
5. **Смешанный** (URI + служебные строки `://autorouting/...`,
   `://routing/...`, `#announce:`, `#profile-title:` и т. п.).

### 3.2. Поддерживаемые URI-схемы

Парсятся и становятся «серверами»: `vless://`, `vmess://`, `trojan://`,
`ss://`, `hysteria2://`/`hy2://`, `socks://`/`socks5://`, `http://`,
`wireguard://`/`wg://`, `amneziawg://`/`awg://`.

Распознаются, **но НЕ парсятся** (скипаются клиентом): `ssr://`,
`tuic://`, `hysteria://` (v1).

### 3.3. Служебные строки в теле подписки (метаданные)

`#profile-title: …`, `#profile-description: …`,
`#profile-update-interval: N`, `#announce: …`, `#announce-url: …`,
`#support-url: …`, `#support-email: …`, `#profile-web-page-url: …`,
`#hide-url: …`, `://autorouting/onadd/{url|base64}`,
`://autorouting/add/…`, `://routing/onadd/…`, `://routing/add/…`,
`://routing/{base64}`.

### 3.4. HTTP-заголовки ответа (через `actions/upload-pages-artifact`
или `_headers`-файл Pages)

Incy понимает заголовки `profile-title`, `profile-update-interval`,
`subscription-userinfo`, `profile-web-page-url`, `homepage`, `announce`,
`announce-url`, `autorouting`, `routing`, `support-url`, `support-email`,
`hide-url`, `sort-order`, и группу «per-app-proxy-*» / «fragmentation-*»
/ «noises-*» / «server-address-resolve-*».

Для GitHub Pages заголовки **нельзя задать произвольно** — Pages
разрешает только фиксированный набор (`Content-Type`, кэш и т. п.).
Поэтому метаданные **кодируются в тело подписки** (`#profile-title:` и
т. д.) — Incy при отсутствии заголовка использует body-параметры как
fallback. Это уже подтверждено документацией Incy и тем, как работают
FLAT447 и hiztin.

### 3.5. Автоселект (главное)

Incy **не имеет** собственного механизма `selector`/`url-test`/`fallback`
в духе Clash. Вместо этого он принимает **полный Xray JSON-конфиг**,
в котором есть `burstObservatory` + `routing.balancers` со стратегией
`leastPing`/`leastLoad`. Сам Xray-core тогда автоматически выбирает
самый быстрый живой outbound.

Это документировано на странице
<https://incy.gitbook.io/docs/docs-en/full-xray-config>:

* Incy принимает JSON-объект с полями `inbounds` И `outbounds`
  (любой такой JSON считается «full config»);
* App на старте применяет `patchFullConfigInbounds` (заменяет listen
  на 127.0.0.1, добавляет socks/mixed inbound на 10808, http на 10809,
  добавляет routing rule для DNS-серверов чтобы не было петли);
* Поддерживаются `observatory` (leastPing), `burstObservatory`
  (leastLoad), `routing.balancers[].strategy.type = leastPing | leastLoad`;
* В UI такая подписка отображается **одной записью** («Auto»), имя
  берётся из первого outbound; внутри неё xray-core сам переключается
  между outbounds.

> **Вывод для архитектуры:** автоселект реализуется через генерацию
> **одного full Xray JSON-конфига** с outbounds = все валидные URI,
> balancer = leastPing, burstObservatory на их subjectSelector.
> Пользователь добавляет подписку в Incy, клиент сам выбирает узел.

Для подписки с **меньшим** количеством узлов (например, «Wi-Fi» —
где их и так мало после фильтрации) full Xray JSON даёт максимальную
гибкость; для «whitelist» (сотни/тысячи URI) full Xray JSON будет
тяжёлым. Поэтому:

* **vpn-whitelist-meeyota** — full Xray JSON (один «Auto»-узел
  с автоселектом через burstObservatory + balancer leastPing);
* **vpn-wifi-meeyota** — full Xray JSON (тот же подход).

В обоих случаях пользователь видит одну запись «VPN whitelist meeyota» /
«VPN Wi-fi meeyota» и нажимает «Подключиться» — клиент сам выбирает
лучший узел.

> **Альтернатива (plain-text fallback).** Дополнительно рядом кладём
> те же URI **plain-text** (`vpn-whitelist-meeyota.txt` /
> `vpn-wifi-meeyota.txt`) и **base64-обёртку** для клиентов, которые
> ожидают именно base64. Это упрощает ручную отладку, но не нужно для
> основного сценария.

### 3.6. Deep links

Подтверждённые форматы:

* `incy://import/{data}` — авто-детект (URL подписки, server-URI,
  несколько URI, сырой WireGuard `.conf`);
* `incy://add/{url}` — добавить подписку;
* `incy://crypt1/{base64url-payload}` — зашифрованная версия `add/`,
  payload — компактный JSON `{ "url": "...", "v": 1, "n": "..." }`.

README должен показывать пользователю **обычный `https://…` URL**
подписки (добавляется кнопкой «Добавить по ссылке» / share-sheet /
QR). `incy://add/` опционально показываем как более короткий
вариант для мобильных.

---

## 4. Поддерживаемые протоколы

Реально встречаются в источниках: `vless://`, `vmess://`, `trojan://`,
`ss://`, `hysteria2://`/`hy2://`. Все остальные (`tuic://`, `ssr://`,
`hysteria://`, `wireguard://`, `amneziawg://`, `socks5://`,
`http://`) Incy или не парсит, или не встречается в выбранных
источниках — **парсер делаем только под то, что реально есть**.

---

## 5. Два результата: формирование

### 5.1. Общий пайплайн (один на оба результата)

```
GitHub Actions (cron + workflow_dispatch)
        │
        ▼
[collect]  скачать файлы источников (retry, timeout, ETag-кэш,
            лимит размера, GitHub API как fallback)
        │   per-source: количество скачанных URI
        ▼
[parse]    распарсить URI → список VpnConfig(scheme, raw, host,
            port, params, fingerprint, name)
        │   per-scheme: сколько распарсилось
        ▼
[normalise] нормализовать: query-сортировка, &amp; → &, пустые
            параметры, приведение fp/flow/sid/alpn/type к нижнему
            регистру, IPv6 в скобках
        ▼
[dedup]    канонический ключ = (scheme, host, port, transport,
            security, sorted-parity-of-critical-params)
        │   статистика: сколько уникальных
        ▼
[validate]  структурная валидация: UUID для vless/vmess, пароль для
            trojan, ss-method, корректный port 1..65535, host не пустой,
            нет null-байтов и т. п.
        │   статистика: сколько прошло / сколько отсеяно и почему
        ▼
[cap]      ограничить до max_configs (настраивается, дефолт 5000)
            чтобы full Xray JSON оставался разумного размера
        ▼
[checks]   для Wi-Fi: реальное соединение (sing-box) → внешний IP →
            геолокация → отсев RU и «неопределено» (опционально —
            см. § 6)
        │
        ▼
[emit]     сгенерировать:
            - vpn-whitelist-meeyota.json (full Xray config)
            - vpn-whitelist-meeyota.txt (plain-text fallback)
            - vpn-wifi-meeyota.json  (full Xray config)
            - vpn-wifi-meeyota.txt   (plain-text fallback)
            - stats.json (для README-бейджей)
        │
        ▼
[safety]   если результат пуст или < min_configs — НЕ перезаписывать,
            аварийно завершить workflow с ненулевым кодом
        │
        ▼
[commit]   git diff; коммит только при реальном изменении
        │
        ▼
[pages]    deploy output/ на GitHub Pages
```

### 5.2. VPN whitelist meeyota

* Источники: FLAT447/v2ray-lists (`WHITE_FULL.txt`, `BLACK_FULL.txt`),
  hiztin/VLESS-PO-GRIBI (`deploy/subscriptions/1.txt`), goida
  (`githubmirror/1.txt`).
* Никакой дополнительной фильтрации по IP/стране.
* Результат — full Xray JSON с outbounds = все валидные URI после
  дедупликации + balancer `leastPing` + `burstObservatory` (sampling=2,
  interval=30s, timeout=5s, destination `http://www.google.com/generate_204`).

### 5.3. VPN Wi-fi meeyota

Критерий попадания — программно проверяемый и задокументированный:

1. URI прошёл парсинг + нормализацию + структурную валидацию;
2. Узел **доступен** — реально установленное соединение через
   sing-box / xray-core (mixed-proxy на 127.0.0.1, прогон одного
   HTTP-запроса к `http://www.google.com/generate_204` через прокси);
3. Внешний IPv4, полученный через прокси, **не равен** RU
   (геолокация: основной `ipwho.is`, fallback `ip-api.com`);
4. Если есть IPv6 — он тоже проверен и не RU;
5. Если IPv4 и IPv6 дают разные страны — узел отбрасывается (конфликт);
6. Если страна не определяется (оба API молчат) — отбрасывается
   (нет подтверждения «вне РФ»).

**Техническая реализуемость.** Все шаги выполнимы стандартными
инструментами:

* sing-box или xray-core запускается как подпроцесс на время проверки;
* для каждого URI поднимается inbound+outbound, делается HTTP-запрос
  через `127.0.0.1:10809`, парсится `cf-connecting-ip` / `x-forwarded-for`
  / прямой IP-ответ;
* IP отправляется в `https://ipwho.is/{ip}` (формат JSON, поле `country_code`);
* при ошибке — `http://ip-api.com/json/{ip}?fields=countryCode` (формат JSON,
  поле `countryCode`).

**Ограничения честно:**

* Проверка делается **из инфраструктуры GitHub Actions** (us-east-1 и
  подобные). Узел, который отлично работает с домашнего Wi-Fi, может
  быть недоступен из Actions и наоборот. Это **известное** ограничение —
  никакой VPS для проверки мы не используем.
* Гео-IP базы могут ошибаться. Поэтому принят строгий «нет подтверждения
  ≠ вне РФ» подход.
* Время проверки тысяч URI при ограниченном GitHub Actions-бюджете —
  дорого. Поэтому Wi-Fi подписка ограничена до ~600–1000 URI
  (конфигурируемо), причём проверки идут пачками с TTL (3 дня) и
  persistent cache в `data/check_results.json`.

### 5.4. Альтернатива — критерий Wi-Fi без сетевых проверок

Если пользователь хочет избежать сетевых проверок (экономия CPU и
времени Actions, без зависимости от sing-box в CI), можно реализовать
**более простой** критерий:

* узел прошёл парсинг/нормализацию/дедупликацию;
* узел **не имеет** в имени/параметрах признаков RU-локации
  (эвристика по тексту `#`-фрагмента: не содержит «RU», «Россия»,
  «Москва», «СПб», «🇷🇺», «Russia», «Moscow», «Rus», «Ru-» и т. п.);
* узел использует только TLS/Reality transport (отбраковываем
  `security=none` через CDN-workers, которые часто RU).

Эта эвристика **надёжно не отделяет** «работает за пределами RU» от
RU-узла — это очевидное ограничение. Поэтому по умолчанию включаю
**полную** проверку через sing-box + геолокацию, а эвристику — как
fallback если sing-box не соберётся на runner'е.

---

## 6. Структура файлов

```
meeyota-vpn/
├── .github/
│   └── workflows/
│       ├── update.yml              # основной cron + workflow_dispatch
│       └── pages.yml               # деплой на GitHub Pages
├── docs/
│   ├── ARCHITECTURE-DRAFT.md       # ← этот документ
│   └── sources-freshness.md        # журнал проверки источников
├── src/
│   ├── __init__.py
│   ├── main.py                     # CLI entry point
│   ├── config.py                   # загрузка sources.yaml + dataclass'ы
│   ├── collectors/
│   │   ├── __init__.py
│   │   └── github.py               # скачивание raw + ETag + retry + API fallback
│   ├── parsers/
│   │   ├── __init__.py
│   │   ├── uri.py                  # парсер vless/vmess/trojan/ss/hy2
│   │   └── text.py                 # разбивка файла → список URI
│   ├── models/
│   │   ├── __init__.py
│   │   └── config.py               # VpnConfig dataclass + canonical hash
│   ├── normaliser.py               # query-сортировка, &amp;, fp lower, …
│   ├── deduplicator.py             # по canonical hash
│   ├── validator.py                # структурные проверки
│   ├── emitter/
│   │   ├── __init__.py
│   │   ├── xray.py                 # full Xray JSON с balancer+observatory
│   │   ├── plaintext.py            # одна URI на строку + body-метаданные
│   │   └── base64wrap.py           # base64-обёртка (для старых клиентов)
│   ├── checks/                     # только для Wi-Fi подписки
│   │   ├── __init__.py
│   │   ├── connectivity.py         # sing-box subprocess + HTTP через прокси
│   │   ├── geolocation.py          # ipwho.is / ip-api.com
│   │   └── verifier.py             # оркестратор + persistent cache
│   ├── stats.py                    # сбор и сериализация статистики
│   └── safety.py                   # проверки min_configs / max_drop_ratio
├── tests/
│   ├── conftest.py
│   ├── test_parsers.py
│   ├── test_normaliser.py
│   ├── test_deduplicator.py
│   ├── test_validator.py
│   ├── test_emitter_xray.py
│   ├── test_emitter_plaintext.py
│   ├── test_safety.py
│   └── test_collector_unavailable.py
├── output/                         # публикуется на GitHub Pages
│   ├── vpn-whitelist-meeyota.json
│   ├── vpn-whitelist-meeyota.txt
│   ├── vpn-wifi-meeyota.json
│   └── vpn-wifi-meeyota.txt
├── data/                           # кэш/промежуточное (в .gitignore)
│   ├── cache/
│   ├── check_results.json
│   ├── configs.json
│   └── stats.json
├── sources.yaml                    # декларативный список источников
├── .gitignore
├── README.md
├── requirements.txt
├── run_local.sh                    # ручной запуск пайплайна локально
└── LICENSE
```

---

## 7. Автоматический выбор узла — отдельное объяснение

### 7.1. Что делаем

Для обеих подписок (`whitelist`, `wifi`) эмиттер `xray.py` генерирует
**один full Xray JSON-конфиг**. Внутри:

* `outbounds[]` — каждый валидный URI превращается в outbound с тегом
  `proxy-N`. Параллельно добавляются два системных outbound'а:
  `direct` (freedom) и `block` (blackhole).
* `inbounds[]` — стандартные, на 127.0.0.1:10808 (mixed) и
  :10809 (http). Incy на старте **автоматически** перепишет `listen` на
  127.0.0.1 и добавит нужные inbound'ы, если их нет; но мы задаём их
  сами, чтобы не зависеть от патчера.
* `routing.balancers[]` — один balancer с `tag: meeyota`, `selector` —
  все `proxy-N`, `strategy.type = "leastPing"`. Дополнительно
  `fallbackTag = "direct"` — если по какой-то причине все outbounds
  померяют, трафик пойдёт напрямую (это требование Xray, чтобы не было
  «всё умерло»).
* `burstObservatory` (есть и в Wi-Fi, и в whitelist, но с разными
  параметрами по нагрузке) — следит за latency всех outbounds:
  * `subjectSelector = [proxy-1, …, proxy-N]`;
  * `pingConfig.destination = "http://www.google.com/generate_204"`;
  * `pingConfig.connectivity = "http://www.google.com/generate_204"`;
  * `pingConfig.interval = "30s"` для whitelist (много узлов — реже
    дёргаем), `"60s"` для Wi-Fi;
  * `pingConfig.sampling = 2`, `pingConfig.timeout = "5s"`.
* `routing.rules[]` — пусто или минимальное (Incy добавит свои для
  DNS, чтобы не было петли).
* `dns.servers = ["8.8.8.8", "1.1.1.1"]` — DNS для проверок
  Observatory.

### 7.2. Что НЕ делаем

* Не запускаем sing-box / xray-core **сами** для проверок тысяч
  серверов перед генерацией — это съело бы весь бюджет Actions.
* Не делаем health-check на каждый URI: Incy + Xray-core делают это
  сами в рантайме, постоянно и эффективно. Наша задача — дать ему
  валидный список outbounds.
* Не пытаемся реализовать `selector`/`url-test` через какие-то хитрые
  обёртки — Incy это не поддерживает; правильный путь — full Xray
  JSON с balancer.

### 7.3. Стоимость по ресурсам

* `output/vpn-whitelist-meeyota.json` при 1000–5000 outbounds —
  ~150 КБ – 1 МБ. Это нормальный размер для подписки, Incy его
  принимает без проблем.
* `output/vpn-wifi-meeyota.json` после фильтрации — 50–500 outbounds,
  ~10–100 КБ.
* Полный пайплайн на Actions: ~2–4 минуты без Wi-Fi-проверок,
  ~10–20 минут с проверками.

---

## 8. Надёжность — конкретные механизмы

| Требование | Реализация |
|---|---|
| timeout | `requests` / `urllib` с `timeout = settings.timeout` (30 с по умолчанию) |
| retry | exponential backoff, `settings.retries = 3`, `settings.backoff = 2.0` |
| недоступный источник | собираем per-source статус, не валим весь pipeline; лог + warning |
| некорректный URI | validator + skip + статистика причин |
| защита от пустого результата | `safety.min_configs = 50` (whitelist), 5 (wifi); не коммитим, fail workflow |
| ограничение размера файла | `max_file_size_mb = 25` per-file + общий лимит |
| ограничение итогового числа | `safety.max_configs` (cap на количество outbounds) |
| дедупликация | canonical hash по (scheme, host, port, transport, security, sorted params) |
| логирование | structured logs в stdout (`source=X count=Y after_parse=Z …`) |
| коммит только при изменениях | `git diff --quiet || git add … && git commit` |
| idempotency workflow | concurrency group, cancel-in-progress=false (чтобы не терять данные) |

---

## 9. GitHub Actions — расписание

* `cron: "0 */6 * * *"` — каждые 6 часов.
* `workflow_dispatch` — ручной запуск с опциональным input «только
  whitelist / только wifi / без проверок».
* Concurrency group: `update-${{ github.ref }}` без cancel.
* Отдельный workflow `pages.yml` деплоит `output/` через
  `actions/deploy-pages` (Pages v2 API). Не используем сторонний
  `peaceiris/actions-gh-pages`.

---

## 10. Тесты — минимум

| Тест | Что проверяет |
|---|---|
| `test_parsers.py` | корректный парсинг vless/vmess/trojan/ss/hy2; ошибки на битых URI |
| `test_normaliser.py` | `&amp;` → `&`, fp-case, query-сортировка, IPv6 |
| `test_deduplicator.py` | одинаковые URI → один; разные sni/fp → разные |
| `test_validator.py` | структурные ошибки (пустой host, port вне диапазона, битый UUID) |
| `test_emitter_xray.py` | структура full Xray JSON: есть inbounds+outbounds, balancer ссылается на теги, burstObservatory ссылается на теги |
| `test_emitter_plaintext.py` | URI по одному на строку, метаданные в `#`-строках |
| `test_safety.py` | пустой результат → raise, drop > 50% → raise |
| `test_collector_unavailable.py` | один из двух источников 5xx → pipeline всё равно работает |

---

## 11. README — что войдёт

* Что делает проект (агрегатор + автоселект через Xray balancer).
* Откуда данные (таблица источников с ссылками на GitHub).
* Какие протоколы (vless, vmess, trojan, ss, hysteria2).
* Как запускается обновление (cron, workflow_dispatch).
* Где два результата и как импортировать в Incy:
  * HTTPS-URL подписки (кнопка «Add subscription»);
  * `incy://add/{url}` — опционально;
  * `incy://crypt1/{base64url}` — опционально для приватности ссылки.
* Как импортировать в другие клиенты (v2rayNG, Hiddify, Nekoray и т. п.).
* Ограничения: зависимость от источников, отсутствие гарантий
  доступности/анонимности, **проект не нацелен на обход
  государственных/корпоративных блокировок**.

---

## 12. Потенциальные технические ограничения (честно)

1. **Incy автоселект требует full Xray JSON.** Если пользователь
   использует не Incy, а клиент без поддержки full Xray JSON
   (v2rayNG в режиме одиночных URI, например), он увидит одну
   запись без возможности выбрать узел. Поэтому рядом кладём
   plain-text/base64-варианты.

2. **GitHub Actions runners находятся в облаке** — IP exit'ов не
   совпадает с пользовательскими. Это означает:
   * Wi-Fi-проверка может отсеять серверы, которые у пользователя
     дома отлично работают.
   * Wi-Fi-проверка может пропустить серверы, которые у пользователя
     не работают (но работают из Actions).

3. **Без VPS мы не можем сделать «настоящие» сетевые проверки
   тысяч URI.** Wi-Fi-проверка поэтому работает по TTL-кэшу
   (3 дня), чтобы за несколько запусков покрыть как можно больше.

4. **GitHub Pages не позволяет задать произвольные HTTP-заголовки.**
   Все метаданные Incy идут **в теле** подписки (`#profile-title:` и
   т. д.). Это работает (Incy это документирует как fallback), но
   `Content-Type` мы не контролируем — Incy всё равно распознаёт
   plain-text и base64.

5. **Бюджет GitHub Actions** — 2000 минут/месяц на free-tier. Наш
   pipeline использует ~3 минуты на запуск × 4 запуска/день × 30 дней
   ≈ 360 минут/месяц. Если добавим Wi-Fi-проверки по 1000 URI × 4
   раза в день — это ещё ~600 минут/месяц. Впритык, но влезает.

6. **`igareck/vpn-configs-for-russia` отбрасываем** (см. § 2.1) —
   иначе нарушаем требование «не добавлять функциональность для обхода
   конкретных государственных/корпоративных ограничений». Нужно
   подтверждение пользователя по этому решению.

7. **`AvenCores/goida-vpn-configs`** — формально README описывает
   проект как «обход блокировок». Использовать только как пассивное
   хранилище URI (без передачи его семантики). Нужно подтверждение
   пользователя.

8. **Incy не поддерживает `selector`/`url-test`/`fallback` как
   отдельные сущности в подписке.** Только через full Xray JSON.
   Это документировано выше и в источниках Incy.

---

## 13. Что я хочу подтвердить от пользователя

1. **Источник `igareck/vpn-configs-for-russia` отбрасываем** — он
   целиком про «обход белых списков», что прямо запрещено
   требованиями. Согласны?

2. **Источник `AvenCores/goida-vpn-configs`** — README содержит
   «для быстрого обхода блокировок». Использовать только как
   технический склад URI (без передачи его семантики в наши
   подписки). Согласны?

3. **Wi-Fi-критерий** — делаем по полной схеме (sing-box +
   геолокация + строгий отсев)? Это требует ~10–20 минут на запуск
   и съедает часть бюджета Actions. Альтернатива — эвристика без
   сетевых проверок, которая **ненадёжна** (явно указываем это в
   README).

4. **Автоселект через full Xray JSON** — согласны с этим подходом?
   Альтернатива — plain-text список (пользователь сам выбирает
   узел или ставит в клиенте `auto` через его локальные средства).

5. **Расписание обновления — каждые 6 часов** (4 раза в день). Нужно
   чаще/реже?

6. **Глубина сетевых проверок для Wi-Fi** — максимум 1000 URI за
   запуск, кэш 3 дня, ~10–20 минут. Приемлемо?

После подтверждения этих шести пунктов приступаю к реализации.
