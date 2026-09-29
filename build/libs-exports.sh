#!/bin/sh
# Списки экспорта разделяемых библиотек (шаг 4 выпуска 1.10): что libsteer.so отдаёт steerd и
# модулям, а libsteer-wolfssl.so — libsteer.
#
#     sh build/libs-exports.sh gen     переписать build/libsteer.map и build/wolfssl/libsteer-wolfssl.map
#     sh build/libs-exports.sh check   сверить файлы с кодом (выход 1 — расходятся)
#
# ЗАЧЕМ СПИСКИ, А НЕ «ВСЁ ВИДИМОЕ». Без version-script библиотека отдаёт наружу каждый глобальный
# символ — модель, YAML, всё, что не static, — и любой из них становится ABI, который потом
# приходится помнить. С -fvisibility=hidden и списком наружу торчит ровно то, что кто-то снаружи
# (steerd, модуль) действительно зовёт. Список — не ручной: он вычисляется как пересечение
# неопределённых символов потребителей (steerd и всех модулей) с определёнными в libsteer, так что
# ни забыть нужный, ни оставить лишний нельзя — `check` падает, если файл разошёлся с кодом.
# Забытый символ ловит и сама сборка (-Wl,-z,defs у библиотеки; у потребителя — неопределённая
# ссылка), но `check` показывает разницу словами, а не строкой линковщика.
#
# СИМВОЛЫ НЕ ЗАВИСЯТ ОТ АРХИТЕКТУРЫ, поэтому считаются один раз на хосте (nm образа сборщика нет:
# там только zig) и лежат в дереве; кросс-сборка (build/build-libs.sh) их только читает.
#
# Нужны исходники wolfSSL (слой scrypto.c включает её заголовки): STEER_WOLFSSL или
# $BUILD/wolfssl-host/src (их кладёт tests/ext-test.sh).
set -eu
MODE="${1:-check}"
BUILD="${BUILD:-build}"
CC="${CC:-cc}"
. build/sources.sh
STEER_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
THIRD_DEFS="$(profile_var THIRD_DEFS)"
WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
[ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || {
    echo "libs-exports: нет исходников wolfSSL ($WSRC) — STEER_WOLFSSL=/путь" >&2; exit 2; }
W="$BUILD/libs-exports"
rm -rf "$W"
mkdir -p "$W/lib" "$W/app"
F="-O0 -w -fPIC -DSTEER_LIBSTEER -DWOLFSSL_USER_SETTINGS -Ibuild/wolfssl -I$WSRC $STEER_INC $THIRD_DEFS"
CRYPTO="$(profile_var CRYPTO_SRC)"
comp() {  # ДЕЛО КАТАЛОГ ФАЙЛЫ…
    d="$1"; shift
    printf '%s\n' "$@" | OD="$d" CCF="$F" xargs -P "$(nproc 2>/dev/null || echo 4)" -I{} \
        sh -c '$CC $CCF -c "$1" -o "$OD/$(echo "$1" | tr / _).o"' _ {}
}
export CC
comp "$W/lib" $(profile_var PROFILE_libsteer)
{
    for p in PROFILE_steerd PROFILE_mod_vless PROFILE_mod_xsteer PROFILE_mod_obfs PROFILE_mod_tgws; do
        profile_var "$p"
    done
} | tr ' ' '\n' | sort -u | grep -v '^$' > "$W/app.lst"
comp "$W/app" $(cat "$W/app.lst")

nm -g --defined-only "$W"/lib/*.o | awk 'NF==3 {print $3}' | sort -u > "$W/defs"
nm -u "$W"/app/*.o | awk '$1=="U" {print $2}' | sort -u > "$W/undef"
comm -12 "$W/defs" "$W/undef" > "$W/need"
# Все, что определено в libsteer, а снаружи не зовётся, остаётся скрытым.
nm -u "$W/lib/$(echo "$CRYPTO" | tr / _).o" \
    | awk '$1=="U" && ($2 ~ /^(wc_|wolfSSL_|wolfCrypt_)/) {print $2}' | sort -u > "$W/wneed"

emit_libsteer() {
    echo "/* Экспорт libsteer.so — ЭТОТ ФАЙЛ ПОРОЖДАЕТ build/libs-exports.sh (gen), руками не правится."
    echo " * Символы, которые steerd и модули (steer-vless, steer-xsteer, steer-obfs, steer-tgws) берут"
    echo " * из библиотеки; остальное скрыто (-fvisibility=hidden + local: *). Проверка: check. */"
    echo "LIBSTEER_1 {"
    echo "  global:"
    sed 's/$/;/; s/^/    /' "$W/need"
    echo "  local:"
    echo "    *;"
    echo "};"
}
emit_wolfssl() {
    echo "/* Экспорт libsteer-wolfssl.so — ЭТОТ ФАЙЛ ПОРОЖДАЕТ build/libs-exports.sh (gen), руками не правится."
    echo " * Символы wolfSSL, которые зовёт слой src/lib/scrypto.c, и отпечаток сборки steer_wolfssl_abi"
    echo " * (build/wolfssl/abi.c). Остальное скрыто: наружу торчит не библиотека, а нужное. Когда"
    echo " * появится потребитель QUIC (ngtcp2, шаг 7), его символы добавятся тем же способом. */"
    echo "{"
    echo "  global:"
    echo "    steer_wolfssl_abi;"
    sed 's/$/;/; s/^/    /' "$W/wneed"
    echo "  local:"
    echo "    *;"
    echo "};"
}
emit_libsteer > "$W/libsteer.map"
emit_wolfssl > "$W/libsteer-wolfssl.map"

case "$MODE" in
gen)
    cp "$W/libsteer.map" build/libsteer.map
    cp "$W/libsteer-wolfssl.map" build/wolfssl/libsteer-wolfssl.map
    echo "libs-exports: libsteer.map — $(wc -l < "$W/need") символов, libsteer-wolfssl.map — $(wc -l < "$W/wneed")"
    ;;
check)
    bad=0
    for pair in libsteer.map:build/libsteer.map libsteer-wolfssl.map:build/wolfssl/libsteer-wolfssl.map; do
        gen="$W/${pair%%:*}"; have="${pair#*:}"
        if ! diff -u "$have" "$gen" > "$W/diff" 2>&1; then
            echo "libs-exports: $have разошёлся с кодом (sh build/libs-exports.sh gen):"
            sed 's/^/    /' "$W/diff" | head -30
            bad=1
        fi
    done
    [ "$bad" = 0 ] || exit 1
    echo "libs-exports: списки экспорта сходятся с кодом"
    ;;
*) echo "libs-exports: gen или check" >&2; exit 2 ;;
esac
