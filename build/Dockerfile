# Кросс-компилятор для steer: musl-статика под все архитектуры OpenWrt плюс исходники
# wolfSSL для расширенной части (VLESS/Reality, xsteer, мост tgws).
#
# Почему zig, а не набор тулчейнов: движку нужен статический musl-бинарник, и Debian'ов
# cross-gcc здесь не годится дважды — статический glibc это ~800 КБ на 35 КБ программы
# при 7 МБ флеша, а его mipsel-цель собрана под HARD FLOAT, тогда как OpenWrt mipsel_24kc
# работает на soft-float: такой бинарник умирает с SIGILL на Mi Router 4C, то есть пакет
# ставится, а демон не может запуститься ни разу. Один zig на 45 МБ покрывает все ISA.
#
# Почему wolfSSL ИСХОДНИКАМИ, а не пакетом libwolfssl OpenWrt:
#
# Reality, TLS 1.3 и xsteer — это X25519, HKDF, ChaCha20-Poly1305 и AES-GCM. Писать это самому
# было бы худшим решением в проекте: ошибка в криптографии не ломается заметно, она тихо
# перестаёт защищать. Пакет libwolfssl в OpenWrt есть, но собран без QUIC (включить его опцией
# меню нельзя), а его SONAME несёт хеш опций (libwolfssl.so.5.9.1.e624513f) и меняется с каждым
# обновлением — бинарник, слинкованный с ним, ломается (docs/architecture.md, «1.10 — решения
# владельца»). Поэтому исходники едут в образ и компилируются тем же zig, что и остальное, со
# своими опциями (build/wolfssl/user_settings.h): у бинарника СВОЯ wolfSSL, и что именно оказалось
# на роутере, его не касается вовсе. Пакетом libsteer-wolfssl (.so) эта же сборка станет на шаге 4.
#
# Прежде здесь лежала mbedtls 3.6.2; она снята целиком (решение владельца 2026-09-28: QUIC в ней нет,
# второго криптостека на флеше владелец не хочет). Образ с ней — прежний тег steer-builder:mbedtls,
# этот — steer-builder:wolfssl (build.sh, STEER_BUILDER_IMAGE).
FROM alpine:3.20

ARG ZIG_VERSION=0.13.0
ARG ZIG_SHA256=d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea

RUN apk add --no-cache curl xz \
 && curl -fsSL -o /tmp/zig.tar.xz \
      "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && mkdir -p /opt && tar xf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm /tmp/zig.tar.xz \
 && zig version

# ВЕРСИЯ wolfSSL И ЕЁ СУММА ЗАПИСАНЫ НЕ ЗДЕСЬ, а в build/wolfssl/fetch.sh — одном месте на все
# сборки (образ, стенды на хосте, проверку под телефон): образ копирует скрипт и зовёт его. Скрипт
# сверяет sha256 тарбола и отказывается распаковывать несошедшийся (I-033: прежде тарбол mbedtls
# распаковывался тем, что отдал сервер). Сменить версию — правка двух строк в fetch.sh; образ
# пересоберётся сам, потому что копия скрипта — слой образа.
#
# Только исходники: собирать их будет вызывающий (build/wolfssl/build.sh), под нужную цель. Готовых
# .a в образе нет намеренно — иначе пришлось бы держать по копии на каждую из девяти архитектур и
# следить, чтобы они не разъехались с опциями в дереве.
COPY wolfssl/fetch.sh /opt/steer-wolfssl-fetch.sh
RUN sh /opt/steer-wolfssl-fetch.sh /opt/wolfssl \
 && ls /opt/wolfssl/wolfssl/wolfcrypt/settings.h

ENV WOLFSSL_DIR=/opt/wolfssl
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/zig"]
