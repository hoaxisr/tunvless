#!/bin/sh
# Разделяемая раскладка роутера на хосте (шаг 4 выпуска 1.10, build/build-libs.sh): собирается то же,
# что кладёт в пакеты build.sh, — libsteer-wolfssl.so, libsteer.so, steerd и четыре модуля, —
# только хостовым компилятором, и проверяется как устроенное целое:
#
#   • списки экспорта (build/libsteer.map, build/wolfssl/libsteer-wolfssl.map) сходятся с кодом, а
#     в .dynsym библиотек лежит ровно то, что в списках, — никаких yaml_*, wolfSSL_* и прочего;
#   • SONAME по версии движка, у модулей единственный NEEDED из наших — libsteer.so.<версия>, у
#     libsteer — libsteer-wolfssl.so.<версия wolfSSL>; в модуле нет ни failover.c, ни модели;
#   • команды модулей через steerd: без модуля — отказ со словами «нужен пакет steer-vless» и
#     контрактной подстрокой steer-extended, с модулем — steerd запускает его и отвечает ровно
#     тем же (вывод и код выхода), что сам модуль;
#   • hello: первое сообщение модуля в линию событий — версия его сборки;
#   • ABI между библиотеками: libsteer при загрузке сверяет отпечаток libsteer-wolfssl.so, и
#     библиотека другой сборки — отказ со строкой, а не порча памяти;
#   • снимок генератора динамическим steerd (139 снимков) — ядро в раскладке пакета ведёт себя
#     так же, как статическое.
#
# wolfSSL — те же исходники, что у tests/ext-test.sh (STEER_WOLFSSL или $BUILD/wolfssl-host/src);
# нет их — громкий пропуск, как там. Зовёт этот стенд tests/ext-test.sh в конце и `make libs-test`.
set -u
BUILD=${BUILD:-build}
CC=${CC:-cc}
WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
if [ ! -f "$WSRC/wolfssl/wolfcrypt/settings.h" ]; then
    echo "libs-test: исходников wolfSSL нет ($WSRC) — ПРОПУСК (это не падение)."
    exit 0
fi
# ngtcp2 с патчем — тем же деревом, что у ext-test (STEER_NGTCP2 или $BUILD/ngtcp2-host/src); не
# нашлось — пробуем скачать, как ext-test, и без него libsteer не собрать: тот же громкий пропуск.
NSRC="${STEER_NGTCP2:-$BUILD/ngtcp2-host/src}"
if [ ! -f "$NSRC/lib/ngtcp2_brutal.c" ] && [ -z "${STEER_NGTCP2:-}" ]; then
    sh build/ngtcp2/fetch.sh "$NSRC" >/dev/null 2>&1
fi
if [ ! -f "$NSRC/lib/ngtcp2_brutal.c" ]; then
    echo "libs-test: исходников ngtcp2 нет ($NSRC) — ПРОПУСК (это не падение)."
    exit 0
fi
VER="$(cat VERSION)"
WVER="$(sh build/wolfssl/fetch.sh version)"
L="$BUILD/libs-host"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}

echo "libs-test: собираю раскладку в $L ..."
mkdir -p "$BUILD"
rm -rf "$L"
# В образе сборщика компилятор — zig: у его драйвера свои ограничения на флаги компоновщика
# (ZIG=1 в build/build-libs.sh).
case "$CC" in zig*) ZIG=1; AR="zig ar"; export ZIG AR ;; esac
if ! CC="$CC" LIBS="-lpthread -ldl -lm" WOLFSSL_DIR="$WSRC" NGTCP2_DIR="$NSRC" JOBS="$(nproc 2>/dev/null || echo 4)" \
        sh build/build-libs.sh "$L" "$VER" "libs-test" > "$L.log" 2>&1; then
    echo "libs-test: сборка не удалась:"; grep -m10 -i "error\|undefined" "$L.log"
    exit 1
fi
LD_LIBRARY_PATH="$L"; export LD_LIBRARY_PATH
SO="$L/libsteer.so.$VER"; WSO="$L/libsteer-wolfssl.so.$WVER"

# ---- списки экспорта и таблица символов -----------------------------------------------------
if command -v nm >/dev/null 2>&1; then
    STEER_WOLFSSL="$WSRC" STEER_NGTCP2="$NSRC" BUILD="$BUILD" CC="$CC" sh build/libs-exports.sh check > "$L.exp" 2>&1
    check "списки экспорта сходятся с кодом" "0" "$?"
    want="$(sed -n 's/^ *\([A-Za-z_0-9]*\);$/\1/p' build/libsteer.map | sort)"
    # nm -D печатает версию символа (имя@@LIBSTEER_1) — её отрезаем.
    have="$(nm -D --defined-only "$SO" | awk '$2 ~ /^[TDBRVW]$/ {sub(/@.*/, "", $3); print $3}' | sort)"
    check "в .dynsym libsteer — ровно список build/libsteer.map" "$want" "$have"
    check "  и в нём нет ни libyaml, ни wolfSSL" "0" \
        "$(printf '%s\n' "$have" | grep -c '^yaml_\|^wc_\|^wolfSSL_')"
    wwant="$(sed -n 's/^ *\([A-Za-z_0-9]*\);$/\1/p' build/wolfssl/libsteer-wolfssl.map | sort)"
    whave="$(nm -D --defined-only "$WSO" | awk '$2 ~ /^[TDBRVW]$/ {sub(/@.*/, "", $3); print $3}' | sort)"
    check "в .dynsym libsteer-wolfssl — ровно список её карты" "$wwant" "$whave"
    for m in steer-vless steer-xsteer steer-obfs steer-tgws; do
        check "$m: в модуле нет failover.c (маршрут ставит демон)" "0" \
            "$(nm "$L/$m" 2>/dev/null | grep -c ' bind_device$\| table_bind$')"
        check "$m: в модуле нет разбора спеки (модель — в libsteer)" "0" \
            "$(nm "$L/$m" 2>/dev/null | grep -c ' load_spec$\| v2_parse')"
    done
else
    echo "libs-test: nm нет — таблицы символов не проверены (ПРОПУСК этих проверок)"
fi
if command -v readelf >/dev/null 2>&1; then
    check "SONAME libsteer — по версии движка" "libsteer.so.$VER" \
        "$(readelf -d "$SO" | sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
    check "SONAME libsteer-wolfssl — по версии wolfSSL" "libsteer-wolfssl.so.$WVER" \
        "$(readelf -d "$WSO" | sed -n 's/.*Library soname: \[\(.*\)\]/\1/p')"
    check "libsteer зависит от libsteer-wolfssl" "libsteer-wolfssl.so.$WVER" \
        "$(readelf -d "$SO" | sed -n 's/.*Shared library: \[\(libsteer[^]]*\)\]/\1/p')"
    for m in steer-vless steer-xsteer steer-obfs steer-tgws steerd; do
        check "$m: из нашего только libsteer.so.$VER" "libsteer.so.$VER" \
            "$(readelf -d "$L/$m" | sed -n 's/.*Shared library: \[\(libsteer[^]]*\)\]/\1/p')"
    done
fi

# ---- команды модулей через steerd ----------------------------------------------------------
empty="$L/nomods"
mkdir -p "$empty"
out="$(STEER_MODULE_DIR="$empty" "$L/steerd" vless '' 2>&1)"; rc=$?
check "без модуля: steerd vless — код 2" "2" "$rc"
check "  отказ называет пакет модуля" "1" "$(printf '%s' "$out" | grep -c 'steer-vless')"
check "  и контрактную подстроку steer-extended (splify2)" "1" "$(printf '%s' "$out" | grep -c 'steer-extended')"
for c in "vless-nodes v" "sub-fetch http://x --out /dev/null" "tls-probe x" "xsteer x" "xsteer-key" \
         "tgws x" "tgws-probe" "obfs x"; do
    o="$(STEER_MODULE_DIR="$empty" "$L/steerd" $c 2>&1)"; r=$?
    check "без модуля: steerd $c — код 2 и «нужен пакет»" "2 1" \
        "$r $(printf '%s' "$o" | grep -c 'нужен пакет steer-')"
done
# С модулем: steerd передаёт командную строку модулю, ответ тот же байт в байт.
cp "$L/steer-vless" "$empty/steer-vless"
a="$(STEER_MODULE_DIR="$empty" "$L/steerd" vless-nodes nosuch --spec /nonexistent 2>&1; echo "rc=$?")"
b="$("$L/steer-vless" vless-nodes nosuch --spec /nonexistent 2>&1; echo "rc=$?")"
check "с модулем: steerd vless-nodes отвечает как сам модуль (вывод и код)" "$b" "$a"
check "  и это не отказ «нужен пакет»" "0" "$(printf '%s' "$a" | grep -c 'нужен пакет')"

# ---- hello ------------------------------------------------------------------------------------
h="$(STEER_EVENT_FD=3 "$L/steer-vless" vless x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "первое сообщение модуля — hello с версией его сборки" \
    "{\"ev\":\"hello\",\"ver\":\"$VER\",\"mod\":\"vless\"}" "$h"
h="$(STEER_EVENT_FD=3 "$L/steer-obfs" obfs x --spec /nonexistent 3>&1 >/dev/null 2>&1 | head -1)"
check "  и у steer-obfs" "{\"ev\":\"hello\",\"ver\":\"$VER\",\"mod\":\"obfs\"}" "$h"
out="$("$L/steer-obfs" vless x 2>&1)"
check "модуль чужой команды не берёт" "steer-obfs: команда vless — не этого модуля" "$out"

# ---- ABI между библиотеками ---------------------------------------------------------------------
# Подложная libsteer-wolfssl.so с чужим отпечатком: то же имя (SONAME) и те же символы (иначе
# загрузчик отказал бы раньше, не дойдя до сверки), но steer_wolfssl_abi другой — так выглядела бы
# библиотека иной сборки (иные опции — иные размеры структур). Собирается из того же архива wolfSSL.
bad="$L/badabi"
mkdir -p "$bad"
cp "$L"/libsteer.so.* "$bad/"
cat > "$bad/abi.c" <<'EOF'
__attribute__((visibility("default")))
const unsigned long steer_wolfssl_abi[11] = { 0x05009004, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
EOF
WLIB="$(ls "$L"/wolfssl-pic/*/libwolfssl.a | head -1)"
$CC -shared -fPIC -o "$bad/libsteer-wolfssl.so.$WVER" "$bad/abi.c" \
    -Wl,--whole-archive "$WLIB" -Wl,--no-whole-archive -Wl,-soname,"libsteer-wolfssl.so.$WVER" \
    -Wl,--version-script=build/wolfssl/libsteer-wolfssl.map -Wl,--gc-sections \
    -lpthread -lm > "$bad/build.log" 2>&1
o="$(LD_LIBRARY_PATH="$bad" "$L/steer-vless" vless x --spec /nonexistent 2>&1)"; r=$?
check "libsteer-wolfssl другой сборки: процесс не стартует, код 3" "3" "$r"
check "  и строка называет причину и лечение" "1" \
    "$(printf '%s' "$o" | grep -c 'другой сборки.*обновите пакеты libsteer и libsteer-wolfssl вместе')"
# Настоящая библиотека — проходит (модуль отвечает своим отказом про спеку, а не про библиотеку).
o="$("$L/steer-vless" vless x --spec /nonexistent 2>&1)"
check "настоящая libsteer-wolfssl: сверка молчит" "0" "$(printf '%s' "$o" | grep -c 'другой сборки')"

# ---- QUIC в раскладке пакета (шаг 7) ---------------------------------------------------------------
# Клиент замера (tests/qcbench.c — он же «потребитель», чьи символы дали qc_* в списке экспорта)
# линкуется с настоящей libsteer.so и ходит через настоящую libsteer-wolfssl.so, то есть на ту
# wolfSSL, что поедет в пакет — без сервера TLS, с QUIC и AES-ECB. Сервер — build/qcserver из
# ext-test (собран на статической wolfSSL стенда, с сервером TLS): две разные сборки wolfSSL по
# разные стороны провода — как в жизни.
if [ -x "$BUILD/qcserver" ]; then
    $CC -O2 -w -Isrc/proto/quic -Itests -o "$L/qcbench" tests/qcbench.c "$SO" -Wl,-rpath,"$L" -lpthread
    check "стенд-потребитель QUIC слинковался с libsteer.so" "0" "$?"
    for mode in "cubic" "brutal 6250000"; do
        "$BUILD/qcserver" --port 0 --idle 15 > "$L/qcsrv.out" 2>/dev/null &
        spid=$!
        n=0
        while ! grep -q '^listening' "$L/qcsrv.out" 2>/dev/null && [ "$n" -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
        port="$(sed -n 's/^listening //p' "$L/qcsrv.out")"
        o="$("$L/qcbench" 127.0.0.1 "${port:-1}" 1 $mode 2>&1)"
        check "QUIC через libsteer.so и libsteer-wolfssl.so ($mode): рукопожатие и передача, сервер ответил" "1" \
            "$(printf '%s' "$o" | grep -c 'replied=1')"
        kill "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
    done
else
    echo "libs-test: нет $BUILD/qcserver (его собирает make ext-test) — QUIC через раскладку пакета пропущен"
fi

# ---- снимок генератора динамическим steerd ---------------------------------------------------------
# Клиент, steerd и библиотеки — в отдельном каталоге БЕЗ модулей (клиент берёт движок рядом с
# собой, а модули ищутся рядом с движком): это пакет ядра без модулей, то есть та же база, что у
# статического build/steerd, и снимок обязан совпасть до байта. Переменную STEER_MODULE_DIR для
# этого не ставим — снимок записывает в заголовок все STEER_*, и она разошлась бы с эталоном.
if [ -x "$BUILD/steer" ] && [ -x "$BUILD/steer-android" ] && [ -x "$BUILD/tgwssim" ]; then
    core="$L/core"
    mkdir -p "$core"
    cp "$L/steerd" "$L"/libsteer.so.* "$L"/libsteer-wolfssl.so.* "$core/"
    cp "$BUILD/steer" "$core/steer"
    # env -u: STEER_WOLFSSL (путь к исходникам библиотеки) — тоже STEER_*, и снимок записал бы его.
    o="$(env -u STEER_WOLFSSL -u STEER_NGTCP2 LD_LIBRARY_PATH="$core" STEER="$core/steer" sh tests/snapshot.sh 2>&1 | tail -1)"
    check "снимок генератора динамическим steerd: совпал" "1" "$(printf '%s' "$o" | grep -c 'снимков совпали')"
else
    echo "libs-test: нет build/steer, steer-android или tgwssim — снимок динамическим steerd пропущен (make)"
fi

printf '\n%d проверок пройдено' "$pass"
if [ "$fail" -gt 0 ]; then printf ', %d ПРОВАЛЕНО\n' "$fail"; exit 1; fi
printf '\nвсе проверки прошли\n'
