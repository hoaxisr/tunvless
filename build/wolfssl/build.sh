#!/bin/sh
# Build wolfSSL from source into a static archive — one recipe for every target.
#
#     sh build/wolfssl/build.sh <wolfSSL sources> <output .a> [asm|noasm]
#
# Compiler and flags come from the environment: CC (default cc), CFLAGS (target, optimization),
# AR (default ar). STEER_WOLFSSL_DEFS adds library options that are not in user_settings.h: only
# the crypto tests use it (certificate issuing and a TLS server for the peer side, see the
# Makefile); tunvless builds never do.
#
# Next to the archive goes <output>.cflags — exactly the flags src/lib/scrypto.c must be compiled
# with against this archive (defines and -I). Not "roughly the same": STEER_WOLFSSL_ASM changes the
# layout of Aes (the AES-NI fields), and scrypto.c compiled without it next to a library built with
# it would write past the fields. So callers read the flags from the file instead of deriving them.
#
# WHY A RECIPE AND NOT configure. Cross builds (the Entware SDK, any CC=...) get one list of .c
# files, -DWOLFSSL_USER_SETTINGS and one options header (build/wolfssl/user_settings.h — the
# reasons for each option are there) — wolfSSL's own way for embedded builds — instead of
# autotools probing a foreign compiler.
#
# THE FILE LIST IS EXPLICIT, not "everything in wolfcrypt/src": more than a hundred files of which a
# third are needed. A forgotten one shows at once as an undefined reference at link time.
#
# A FILE THAT FAILS TO COMPILE IS NOT HIDDEN: its errors are printed and the build stops.
set -eu

SRC="${1:?нужен каталог исходников wolfSSL}"
OUT="${2:-}"
[ "$SRC" = list ] || [ -n "$OUT" ] || { echo "wolfssl: нужен путь выходного архива" >&2; exit 2; }
ASM="${3:-asm}"
CC="${CC:-cc}"
AR="${AR:-ar}"
CFLAGS="${CFLAGS:--O2}"
HERE=$(cd "$(dirname "$0")" && pwd)

# The list is a function, so that `build.sh list` can print it.
wolfssl_c_files() {
    for f in internal keys ssl tls tls13 wolfio; do echo "src/$f.c"; done
    # ge_operations.c — групповая математика Ed25519: X25519 берёт её для открытого ключа там, где
    # у кривой свой ассемблер (aarch64, CURVED25519_ASM_64BIT); на остальных целях файл пуст.
    for f in aes asn chacha chacha20_poly1305 coding cpuid curve25519 ecc error fe_operations \
             ge_operations hash hmac kdf logging md5 memory poly1305 random rsa sha sha256 sha3 sha512 \
             sp_int wc_encrypt wc_mldsa wc_mlkem wc_mlkem_poly wc_port wolfmath; do
        echo "wolfcrypt/src/$f.c"
    done
    # Встроенный ассемблер aarch64 (WOLFSSL_ARMASM_INLINE в user_settings.h). Файлы в каждом
    # списке, а не только у aarch64: вне его они компилируются в пустоту (#ifdef __aarch64__
    # внутри), и список остаётся одним на все цели.
    for f in aes-asm_c chacha-asm_c poly1305-asm_c sha256-asm_c sha512-asm_c curve25519_c sha3-asm_c; do
        echo "wolfcrypt/src/port/arm/armv8-$f.c"
    done
}
[ "$SRC" = list ] && { wolfssl_c_files; exit 0; }
[ -f "$SRC/wolfssl/wolfcrypt/settings.h" ] || {
    echo "wolfssl: в $SRC нет исходников wolfSSL (wolfssl/wolfcrypt/settings.h)" >&2; exit 2; }
# Пути — абсолютные: они уходят в <выход>.cflags, а читают его из другого рабочего каталога.
SRC=$(cd "$SRC" && pwd)
mkdir -p "$(dirname "$OUT")"

TRIPLE=$($CC -dumpmachine 2>/dev/null || echo unknown)
ASMFILES=
ASMDEF=
case "$ASM:$TRIPLE" in
    asm:x86_64-*)
        ASMDEF=-DSTEER_WOLFSSL_ASM
        for f in aes_x86_64_asm aes_gcm_asm; do
            ASMFILES="$ASMFILES wolfcrypt/src/$f.S"
        done ;;
esac

DEFS="-DWOLFSSL_USER_SETTINGS $ASMDEF ${STEER_WOLFSSL_DEFS:-}"
OBJ="$OUT.obj"
# Отпечаток сборки: опции, флаги, компилятор. Архив с тем же отпечатком не пересобирается, а любая
# правка user_settings.h или флагов пересобирает его.
STAMP="$(cat "$HERE/user_settings.h" "$0"; echo "$CC|$CFLAGS|$DEFS|$TRIPLE")"
if [ -f "$OUT" ] && [ -f "$OUT.stamp" ] && [ "$(cat "$OUT.stamp")" = "$STAMP" ]; then
    exit 0
fi
rm -rf "$OBJ"
mkdir -p "$OBJ"

failed=
for f in $(wolfssl_c_files) $ASMFILES; do
    o="$OBJ/$(echo "$f" | tr '/' '_').o"
    extra=
    # Интринсики AES-NI в aes.c (AES_set_decrypt_key) требуют -maes у компилятора. Ключ — ОДНОМУ
    # файлу: команды AES компилятор сам не выпускает никогда, а весь путь AES-NI в aes.c стоит за
    # проверкой CPUID (Check_CPU_support_AES), так что бинарник по-прежнему запускается там, где
    # AES-NI нет. SSE4.1 не даётся нарочно: её команды компилятор ВЫПУСКАЕТ сам, векторизуя
    # обычный код, и тогда файл упал бы на процессоре без неё.
    [ -n "$ASMDEF" ] && [ "$f" = wolfcrypt/src/aes.c ] && extra=-maes
    # shellcheck disable=SC2086
    if ! $CC $CFLAGS $extra $DEFS -I"$HERE" -I"$SRC" \
            -c "$SRC/$f" -o "$o" 2>"$o.err"; then
        failed="$failed $f"
        echo "wolfssl: сборка файла $f не удалась ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    elif [ -s "$o.err" ]; then
        # Предупреждения не прячутся: сборка движка идёт без них, и у библиотеки их тоже быть
        # не должно — новое предупреждение после обновления wolfSSL видно здесь, а не в релизе.
        echo "wolfssl: предупреждения в $f ($TRIPLE):" >&2
        sed 's/^/    /' "$o.err" >&2
    fi
    rm -f "$o.err"
done
[ -z "$failed" ] || { echo "wolfssl: сборка не удалась у файлов:$failed" >&2; exit 1; }

rm -f "$OUT"
# shellcheck disable=SC2086
$AR rcs "$OUT" "$OBJ"/*.o
printf '%s\n' "$DEFS -I$HERE -I$SRC" > "$OUT.cflags"
printf '%s' "$STAMP" > "$OUT.stamp"
rm -rf "$OBJ"
