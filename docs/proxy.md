# Клиенты прокси (steer-proxy)

Этот документ описывает модуль `steer-proxy` — клиенты протоколов trojan, shadowsocks, socks, http и
vmess. Модуль есть только в пакете `steer-proxy`; в мета-пакет `steer-extended` он не входит, как и
`steer-hysteria2`.

Зачем он нужен: коннектор sing-box (steer-box-connector) даёт немодифицированным роутерам podkop и
forkop работать поверх steer. Он переводит конфиг sing-box в спеку steer v2, а каждый прокси-outbound
становится выходом `kind: tunnel` с одним из этих протоколов; узел берётся из файла подписки (одна
share-ссылка на файл), который пишет коннектор.

Клиент поднимает TUN-устройство и несёт через него TCP и, где протокол это умеет, UDP. Дальше
устройство ничем не отличается от `wg0` для остальной части движка: метки, таблицы, каналы и failover
работают с ним так же. Строение общее с клиентами VLESS и hysteria2 — [docs/vless.md](vless.md),
[docs/hysteria2.md](hysteria2.md) и раздел «Туннели» в [docs/architecture.md](architecture.md): тот же
стек туннеля (`src/tunnel`) и, у протоколов поверх потока, тот же транспорт с TLS/Reality
(`src/proto/transport`).

## Что поддерживается

| Протокол | Транспорт и безопасность | TCP | UDP |
|---|---|---|---|
| `trojan` | tcp, grpc, xhttp, ws, httpupgrade; tls или reality (как у vless) | да | да (в потоке) |
| `shadowsocks` | голый tcp (шифрует сам протокол) | да | да, кроме 2022 |
| `socks` | голый tcp | да | socks5 (ASSOCIATE), не socks4 |
| `http` | tcp или tls (CONNECT) | да | нет |
| `vmess` | tcp, grpc, xhttp, ws, httpupgrade; tls (как у vless) | да | да (в потоке) |

- **trojan**: пароль на проводе — `SHA-224(пароль)` в hex; адрес назначения — SOCKS5. UDP — пакеты
  `[адрес][длина][CRLF][данные]` в потоке. Поддержаны те же транспорты и безопасность, что у VLESS
  (reality в том числе), так как слой транспорта общий.
- **shadowsocks**: AEAD-шифры `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` (ключ из пароля —
  EVP_BytesToKey на MD5, подключ сессии — HKDF-SHA1); SIP022 `2022-blake3-aes-128-gcm`,
  `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`, включая многопользовательский
  `iPSK:uPSK` (EIH на один уровень реле); `none`/`plain` без шифрования. PSK у 2022 — base64 (16 или 32
  байта).
- **socks**: socks5 с авторизацией имя/пароль и без; socks4 и socks4a. У socks5 работает UDP
  ASSOCIATE (управляющее TCP-соединение плюс сокет к ретранслятору).
- **http**: прокси HTTP CONNECT, по желанию поверх TLS (`https://`), с базовой авторизацией
  (`user:pass@`).
- **vmess**: AEAD-заголовок (alterId 0), шифр тела `aes-128-gcm` или `chacha20-poly1305` (`auto` —
  aes-128-gcm); те же транспорты, что у VLESS.

**ICMP не пересылается**: всё, что не TCP и не UDP, получает ICMP «порт недостижим», как у VLESS.

## Что НЕ поддерживается и почему

- **shadowsocks 2022 UDP**: формат UDP у 2022 иной (сессии, счётчик пакетов, заголовок под AES-ECB и
  XChaCha для chacha-варианта) и существенно сложнее потокового. TCP у таких узлов работает; UDP
  такого узла отклоняется с причиной в журнале, датаграммы через него не идут.
- **socks4/4a UDP**: socks4 не знает UDP вовсе — датаграммы отклоняются.
- **http CONNECT UDP**: у CONNECT нет UDP — датаграммы отклоняются.
- **vmess security `none` и `zero`**: тело без AEAD; podkop и коннектор их не выдают, а без шифра тела
  у vmess нет и проверки. Такой узел пропускается с причиной.
- **vmess alterId ≠ 0**: старый формат заголовка (MD5) снят в самом vmess; поддержан только AEAD
  (alterId 0).
- **shadowsocks `?plugin=`**: обфускаторы ss (v2ray-plugin, obfs) — отдельная связка, которой нет;
  узел с `plugin=` пропускается с причиной, а не идёт на сервер, который плагина ждёт.

## Форматы узла (share-ссылки)

Подписка — список share-ссылок по строкам, тот же список в base64. Чужие ссылки считаются (в
`foreign`) и не мешают; узлы наших протоколов, которые клиент не потянет, получают причину пропуска
(`proxy-nodes`, поле `skipped_reasons`).

### trojan

```
trojan://пароль@хост:порт?security=tls&sni=&type=&path=&host=&…#имя
```

Та же форма и те же параметры транспорта, что у `vless://` ([docs/vless.md](vless.md)): `type` (tcp,
grpc, xhttp, ws, httpupgrade), `security` (tls, reality: `pbk`, `sid`), `sni`, `fp`, `path`, `host`,
`serviceName`, `pcs`/`vcn` (проверка сертификата), `allowInsecure`. Пароль — весь userinfo до `@`, с
процентным кодированием. trojan без TLS не бывает.

### shadowsocks (SIP002)

```
ss://base64url(метод:пароль)@хост:порт#имя
ss://метод:пароль@хост:порт#имя            (userinfo процентно, без base64)
```

Для 2022 пароль — base64 PSK (`ss://2022-blake3-aes-128-gcm:<base64-16-байт>@…`), многопользовательский
— `iPSK:uPSK` (`…:<base64>:<base64>@…`). Параметр `?plugin=` отвергается с причиной.

### socks

```
socks5://[user:pass@]хост:порт#имя
socks://хост:порт          (= socks5)
socks4://хост:порт#имя
socks4a://хост:порт#имя
```

У socks4 пароля нет (ссылка с паролем пропускается).

### http

```
http://[user:pass@]хост:порт#имя
https://[user:pass@]хост:порт?sni=#имя     (CONNECT поверх TLS)
```

### vmess (v2rayN)

```
vmess://base64(JSON)
```

JSON v2rayN: `add`, `port`, `id`, `aid` (только 0), `scy` (auto, aes-128-gcm, chacha20-poly1305),
`net` (tcp, ws, grpc, httpupgrade; `h2` читается как xhttp), `type`, `host`, `path`, `tls`, `sni`,
`fp`, `alpn`, `ps` (имя).

## Выход в спеке

```yaml
outputs:
  nl:  { kind: tunnel, protocol: trojan,      subscription: sub/nl, nodes: [0, 2], over: wg0 }
  ss:  { kind: tunnel, protocol: shadowsocks, subscription: sub/ss }
  vm:  { kind: tunnel, protocol: vmess,       subscription: sub/vm, insecure: true }
```

Ключи те же, что у VLESS: `subscription`, `nodes` (номера пригодных узлов; пусто — первый
отвечающий), `device`, `over`. Ключа `transport` у прокси нет — транспорт берётся из ссылки узла.
`insecure` есть только у протоколов с TLS (trojan, vmess, http) — у ss и socks его нет. Без пакета
`steer-proxy` спека отвергается словами «kind … требует пакет steer-proxy».

## Подъём, перебор узлов, слежка

`steer proxy <выход>` читает спеку и подписку, берёт кандидатов (`nodes` либо все пригодные) и
проверяет их по порядку: рукопожатие и запрос через узел к 1.1.1.1:80, срок — 8 секунд на узел.
Первый отвечающий — узел выхода. Затем поднимается устройство, демону уходит `up` с именем устройства
(маршрут ставит демон), заводится слежка. Под демоном клиент сам говорит, жив ли узел (как у VLESS):
проба раз в минуту, после двух неудач подряд — `down` с причиной, круг проб, при переключении —
перезапуск процесса.

Команды: `steer proxy-nodes <выход|/файл>` — узлы подписки JSON-ом; `steer proxy-probe <выход|/файл>
[--node N] [--timeout С]` — проверка узлов с задержкой и причиной отказа.

## status и diag

В `steer status` у выхода — `nodes` и объект `proxy` (пока клиент жив): `node`, `protocol`, `up`.
`steer diag` проверяет, что клиент запущен и соединение поднято.

## Ограничения

- Адрес назначения — IPv4 клиента; имён клиент не передаёт (сервер видит адрес).
- Смена узла на ходу невозможна: при потере узла процесс перезапускается целиком.
- Телефонная сборка (профиль android) модуля не содержит — как и `steer-hysteria2`.
