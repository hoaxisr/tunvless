#!/bin/sh
# Прогон стендов расширенной части, которым нужна НАСТОЯЩАЯ криптобиблиотека (wolfSSL за слоем
# src/lib/scrypto.h), а не подменённые функции, как в `make test`:
#
#   tests/scryptomatch.c — слой примитивов против известных векторов (RFC, NIST) и цепочка X.509
#                        с подписями, выпущенными OpenSSL (tests/scrypto-pki.h);
#   tests/hellofreeze.c — ClientHello байт в байт против заморозки (tests/chello-frozen.h):
#                        сборщик Hello зовёт X25519 слоя, и отпечаток не должен сдвинуться ни на бит;
#   tests/xsepochmatch.c — ратчет эпох xsteer против векторов реализации на Go;
#   tests/xsloop.c     — рукопожатие Noise IK целиком: сборка ClientHello, ответ хаба,
#                        подтверждение, отказ по аутентификации, затирание состояния.
#   tests/spokematch.c — освобождение транспортных ключей при неудачном рукопожатии;
#                        собирается под AddressSanitizer (I-067).
#   tests/vlessmatch.c — ветви отказа vless_connect: код возврата, дескрипторы и куча на
#                        каждом «нет», под AddressSanitizer (R-114), и серверная половина
#                        TLS 1.3 со своей цепочкой X.509 для security=tls (R-118).
#   tests/androidroots.c — склейка каталога корней Android в хранилище для certverify.
#   tests/hubmatch.c   — арифметика записи в хабе: правило набора кадров в пачку против
#                        объявленной строки воркера (I-070).
#   tests/devupmatch.c — подъём устройства туннеля: каждый отказ `ip` обязан быть назван (I-114).
#   tests/probe.sh     — активное зондирование хаба настоящим openssl s_client (нужен root).
#
# В обычный `make test` они НЕ входят: там библиотеки нет по построению (R-014, см. ext-syntax в
# Makefile), а роутерная сборка расширенной части идёт только docker'ом через build.sh. Из-за
# этого xsloop и spokematch до запуска 42 не прогонялись НИ РАЗУ — и первый же прогон дал I-066
# и I-067. Эта цель закрывает разрыв: проверяемость расширенной части хоть где-то, кроме
# релизной сборки (R-058).
#
# БИБЛИОТЕКА — ТА ЖЕ, ЧТО В ДВИЖКЕ. wolfSSL собирается здесь из исходников той же версии
# (build/wolfssl/fetch.sh: версия и sha256 записаны там) и с теми же опциями
# (build/wolfssl/user_settings.h), что у роутерной сборки, — тем же рецептом build/wolfssl/build.sh.
# Прежде стенды шли на той mbedtls, что стояла у человека (2.28 системная против 3.6 в релизе), и
# «зелёное здесь» не значило «зелёное в релизе» (R-058). Теперь версия одна по построению.
# Единственная добавка — WOLFSSL_CERT_GEN (и WOLFSSL_CERT_EXT): выпуск сертификатов нужен стендам
# security=tls (tests/certgen.c), а движку — нет; раскладку того, что зовёт движок, ключи не меняют.
#
# Исходники: STEER_WOLFSSL — каталог готовых исходников; иначе они скачиваются в $BUILD/wolfssl-host
# со сверкой суммы. Не нашлись и не скачались — ГРОМКИЙ пропуск (echo + выход 0), а не падение и
# не молчание: молчаливый пропуск читается как «прошло», ровно как пропущенный ui-harness в splify2.
#
# В РЕЛИЗЕ этот же файл зовётся ВНУТРИ образа сборщика: обвязка — build/ext-test-image.sh, шаг — в
# .github/workflows/release.yml (R-063). Оттуда приходят STEER_WOLFSSL (исходники в образе) и
# CC="zig cc".
set -e

CC=${CC:-cc}
# -I на все каталоги слоёв — из того же манифеста, что у сборки (build/sources.mk).
. build/sources.sh
STEER_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
# И определения стороннего кода ядра (libyaml: -DHAVE_CONFIG_H) — их ждёт каждая сборка, в которую
# входит CORE_SRC (серверный бинарник ниже); остальным стендам ключ ничего не значит.
STEER_INC="$STEER_INC $(profile_var THIRD_DEFS)"
# Разбор спеки спрашивает вид у реестра (src/kinds/kind.c), поэтому стенды, компонующие парсер,
# берут и виды выхода — из того же манифеста. Без awg.c: ему нужен lib/run.c, а стенды подменяют
# run_quiet сами, и вида awg им не нужно (реестр оставит на его месте запись отказа).
KINDS_SRC="$(for f in $(profile_var KINDS_BASE_SRC) $(profile_var KINDS_EXT_SRC); do
    [ "$f" = src/kinds/awg.c ] || printf '%s ' "$f"; done)"
# Модель — тоже из манифеста, вместе с платформой (src/platform): её спрашивают и разбор, и пути.
MODEL_SRC="$(profile_var MODEL_SRC)"
BUILD=${BUILD:-build}
mkdir -p "$BUILD"

# ---- wolfSSL: исходники и сборка ----------------------------------------------------------------
WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
if [ ! -f "$WSRC/wolfssl/wolfcrypt/settings.h" ]; then
	if [ -n "${STEER_WOLFSSL:-}" ] || ! sh build/wolfssl/fetch.sh "$WSRC"; then
		echo "ext-test: исходников wolfSSL нет ($WSRC) — ПРОПУСК (это не падение)."
		echo "ext-test:   STEER_WOLFSSL=/путь к распакованному выпуску, либо сеть для"
		echo "ext-test:   build/wolfssl/fetch.sh (версия и сумма записаны там)."
		echo "ext-test: под этими стендами лежат I-066 и I-067 — без прогона они не видны."
		exit 0
	fi
fi
WVER=$(sh build/wolfssl/fetch.sh version)
# Архив — на компилятор: gcc хоста и zig в образе дают разные объекты, и один архив на обоих
# собирался бы заново на каждом переключении.
CCTAG=$(printf '%s' "$CC" | tr -c 'a-zA-Z0-9' '_')
WLIB="$BUILD/wolfssl-host/libwolfssl-$CCTAG.a"
case "$CC" in zig*) WAR="zig ar" ;; *) WAR="${AR:-ar}" ;; esac
echo "ext-test: wolfSSL $WVER, опции build/wolfssl/user_settings.h (+ выпуск сертификатов для стендов)"
CC="$CC" AR="$WAR" CFLAGS="-O2 -g" STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" \
	sh build/wolfssl/build.sh "$WSRC" "$WLIB" asm
WCFLAGS=$(cat "$WLIB.cflags")

# Слой и выпуск сертификатов — отдельными объектами, со своими ключами: заголовки wolfSSL видят
# только они, как в движке (остальные файлы собираются без -I на библиотеку).
# shellcheck disable=SC2086
$CC -O2 -g -w $STEER_INC $WCFLAGS -c src/lib/scrypto.c -o "$BUILD/wolfssl-host/scrypto-$CCTAG.o"
# shellcheck disable=SC2086
$CC -O2 -g -w $STEER_INC $WCFLAGS -c tests/certgen.c -o "$BUILD/wolfssl-host/certgen-$CCTAG.o"
CRYPTO="$BUILD/wolfssl-host/scrypto-$CCTAG.o $WLIB"
CERTGEN="$BUILD/wolfssl-host/certgen-$CCTAG.o"

# ---- векторы слоя и заморозка Hello ------------------------------------------------------------
echo "ext-test: собираю и прогоняю scryptomatch..."
$CC -O2 -g -w $STEER_INC -Itests -o "$BUILD/scryptomatch" tests/scryptomatch.c $CRYPTO -lpthread
"$BUILD/scryptomatch"

echo "ext-test: собираю и прогоняю hellofreeze..."
$CC -O2 -w $STEER_INC -o "$BUILD/hellofreeze" tests/hellofreeze.c $CRYPTO -lpthread
"$BUILD/hellofreeze"

echo "ext-test: собираю и прогоняю xsepochmatch..."
$CC -O2 -w $STEER_INC -o "$BUILD/xsepochmatch" tests/xsepochmatch.c src/proto/xsteer/xsepoch.c \
	src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/h2.c \
	$CRYPTO -lpthread
"$BUILD/xsepochmatch"

# xsloop — рукопожатие целиком.
echo "ext-test: собираю и прогоняю xsloop..."
$CC -O2 -w $STEER_INC -o "$BUILD/xsloop" tests/xsloop.c \
	src/proto/xsteer/xshake.c src/proto/tls/chello.c src/proto/xsteer/xswire.c src/proto/tls/reality.c \
	src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/h2.c $CRYPTO -lpthread
"$BUILD/xsloop"

# spokematch — освобождение ключей при неудаче, под AddressSanitizer.
#
# Доступен ли санитайзер — проверяется ПРОБОЙ, а не догадкой по имени компилятора. В образе
# сборщика (zig cc, musl) рантайма ASan нет вовсе, а на musl нет и LeakSanitizer — то есть ровно
# того, на чём стоит этот стенд (I-067, утечка контекста шифра). Собрать там без санитайзера
# МОЛЧА значило бы получить зелёный стенд, который больше не проверяет то, ради чего написан,
# — поэтому пропуск громкий, как и пропуск по ненайденной библиотеке.
#
# ПРОБ ДВЕ, И ВТОРАЯ ПОЯВИЛАСЬ ПОТОМУ, ЧТО ПЕРВОЙ НЕ ХВАТАЛО (I-232). Первая ничего не теряет
# и обязана пройти: так видно, что рантайм есть и программа с ним ЗАПУСКАЕТСЯ. Вторая теряет
# 64 байта нарочно и обязана ПРОВАЛИТЬСЯ: так видно, что утечки ищутся. Без второй проба
# отвечала на вопрос «есть ли рантайм», а комментарий над ней обещал ответ и про отсутствие
# LeakSanitizer — обещание, которого код не исполнял: программа без утечки проходит и там, где
# утечек не ищут вовсе. Проверено: `ASAN_OPTIONS=detect_leaks=0 ./build/spokematch` печатал
# «все проверки прошли», то есть барьер под I-067 снимался переменной окружения молча.
ASAN="-fsanitize=address"
probe="$BUILD/asan-probe"
printf '#include <stdlib.h>\nint main(void){char*p=malloc(16);p[0]=1;free(p);return 0;}\n' \
	> "$probe.c"
printf '#include <stdlib.h>\nint main(void){char*p=malloc(64);p[0]=1;return 0;}\n' \
	> "$probe-leak.c"
asan_why=""
if ! $CC -O0 $ASAN -o "$probe" "$probe.c" >/dev/null 2>&1 || ! "$probe" >/dev/null 2>&1; then
	asan_why="рантайма нет либо программа с ним не запускается"
elif ! $CC -O0 $ASAN -o "$probe-leak" "$probe-leak.c" >/dev/null 2>&1; then
	asan_why="проба на утечку не собралась"
elif "$probe-leak" >/dev/null 2>&1; then
	# Вышла с нулём, потеряв 64 байта: рантайм есть, а утечек он не ищет.
	asan_why="утечки не ищутся (нет LeakSanitizer, как на musl, либо detect_leaks=0)"
fi
if [ -n "$asan_why" ]; then
	echo "ext-test: ВНИМАНИЕ — AddressSanitizer здесь не годится: $asan_why."
	echo "ext-test:            spokematch и vlessmatch собираются БЕЗ него: проверки в них"
	echo "ext-test:            прогонятся, утечки (I-067, R-114) — НЕТ."
	ASAN=""
fi
rm -f "$probe" "$probe.c" "$probe-leak" "$probe-leak.c"

echo "ext-test: собираю и прогоняю spokematch (ASan: ${ASAN:-нет})..."
# xslink.c в списке ОБЯЗАТЕЛЕН: командная строка клиента принимает и ссылку xs://, и файл
# одним xs_conf_load_any, и живёт эта функция там. Без неё сборка стенда падает на компоновке,
# то есть весь ext-test не доходит даже до первой проверки — а именно в нём и живёт ASan.
# src/lib/ctlcall.c — там же и по той же причине: xsclient.c зовёт сокет управления демона
# (ctlcall_socket и ctlcall_forward в cmd_xsteer_peers), и без файла стенд не компоновался — до
# шага 1 выпуска 1.10 ext-test был из-за этого красным ещё до первой проверки.
$CC -O1 -g -w $STEER_INC $ASAN -o "$BUILD/spokematch" \
	tests/spokematch.c \
	src/proto/xsteer/xsconn.c src/proto/xsteer/xswire.c src/proto/xsteer/xsepoch.c src/proto/xsteer/xsroute.c \
	src/proto/xsteer/xsconf.c src/proto/xsteer/xslink.c src/proto/xsteer/xsstream.c src/proto/xsteer/xshake.c src/proto/tls/chello.c \
	src/proto/tls/reality.c src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/h2.c src/tunnel/tun.c src/proto/obfs/obfs.c \
	src/lib/jsonw.c src/lib/evline.c src/lib/ctlcall.c \
	$MODEL_SRC $KINDS_SRC $CRYPTO -lpthread
"$BUILD/spokematch"

# vlessmatch — ветви отказа vless_connect, под тем же AddressSanitizer.
#
# ASAN здесь уже определён пробой выше: второй экземпляр этой пробы разошёлся бы с первым. Если
# санитайзера нет, стенд об этом ГОВОРИТ САМ (последние строки его вывода) — проверки кодов
# возврата и дескрипторов прогонятся, куча нет.
#
# Список исходников повторяет devupmatch без client.c: сам client.c стенд ВКЛЮЧАЕТ (шов
# установления TCP статический, см. заголовок стенда), и вторая его копия при компоновке
# дала бы дубли символов. Выпуск сертификатов (R-118) — tests/certgen.c, он есть всегда, поэтому
# STEER_HAVE_X509WRITE задаётся безусловно (прежде — пробой mbedtls на MBEDTLS_X509_CRT_WRITE_C).
echo "ext-test: собираю и прогоняю vlessmatch (ASan: ${ASAN:-нет})..."
$CC -O1 -g -w $STEER_INC -Itests $ASAN -DSTEER_HAVE_X509WRITE -o "$BUILD/vlessmatch" tests/vlessmatch.c \
	src/proto/vless/vless_proto.c src/proto/vless/vision.c src/proto/tls/tls13.c src/proto/tls/certverify.c \
	src/proto/tls/reality.c src/proto/tls/h2.c src/tunnel/tun.c src/tunnel/rtx.c src/proto/vless/sub.c \
	$MODEL_SRC $KINDS_SRC $CERTGEN $CRYPTO -lpthread
"$BUILD/vlessmatch"

# androidroots — склейка каталога корней Android в файл для certverify (cert_roots в
# client.c на платформе с системным хранилищем корней). Платформа — телефон (умолчание сборки),
# каталоги хранилища — свои, во временном месте (ключ STEER_ANDROID_CA_DIRS читает
# src/platform/android.c): стенд не трогает ни /data, ни /apex.
echo "ext-test: собираю и прогоняю androidroots..."
$CC -O1 -g -w $STEER_INC -Itests -DSTEER_HAVE_X509WRITE -DSTEER_DEFAULT_PLATFORM=android \
	'-DSTEER_ANDROID_CA_DIRS="/tmp/steer-androidroots/nope","/tmp/steer-androidroots/empty","/tmp/steer-androidroots/cacerts"' \
	-o "$BUILD/androidroots" tests/androidroots.c \
	src/proto/vless/vless_proto.c src/proto/vless/vision.c src/proto/tls/tls13.c src/proto/tls/certverify.c \
	src/proto/tls/reality.c src/proto/tls/h2.c src/tunnel/tun.c src/tunnel/rtx.c src/proto/vless/sub.c \
	$MODEL_SRC $KINDS_SRC $CERTGEN $CRYPTO -lpthread
"$BUILD/androidroots"

# hubmatch — согласие правила набора пачки с размером строки воркера.
echo "ext-test: собираю и прогоняю hubmatch..."
$CC -O2 -w $STEER_INC -o "$BUILD/hubmatch" tests/hubmatch.c \
	src/proto/xsteer/xsconn.c src/proto/xsteer/xswire.c src/proto/xsteer/xsepoch.c src/proto/xsteer/xsroute.c \
	src/proto/xsteer/xsconf.c src/proto/xsteer/xslink.c src/proto/xsteer/xsstream.c src/proto/xsteer/xshake.c src/proto/tls/chello.c \
	src/proto/tls/reality.c src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/h2.c src/tunnel/tun.c src/proto/obfs/obfs.c \
	src/lib/jsonw.c src/lib/evline.c \
	$MODEL_SRC $KINDS_SRC $CRYPTO -lpthread
"$BUILD/hubmatch"

# devupmatch — подъём устройства туннеля называет свои отказы (I-114).
echo "ext-test: собираю и прогоняю devupmatch..."
$CC -O2 -w $STEER_INC -o "$BUILD/devupmatch" tests/devupmatch.c \
	src/proto/vless/client.c src/proto/vless/vless_proto.c src/proto/vless/vision.c src/proto/tls/tls13.c src/proto/tls/certverify.c \
	src/proto/tls/reality.c src/proto/tls/h2.c src/tunnel/tun.c src/tunnel/rtx.c src/proto/vless/sub.c src/lib/jsonw.c src/lib/evline.c \
	$MODEL_SRC $KINDS_SRC $CRYPTO -lpthread
"$BUILD/devupmatch"

# probe — активное зондирование настоящим openssl s_client. Здесь, а не отдельной целью
# Makefile: библиотека уже собрана выше, а второй экземпляр её сборки разошёлся бы с первым.
# Стенд требует root и сетевых пространств и без них ГРОМКО пропускается, поэтому в ext-test он
# безопасен.
#
# Бинарник СЕРВЕРНЫЙ (профиль server): хаб живёт только в нём, у роутерной сборки подкоманда
# xsteer-hub — штатная заглушка «ставится из архива steer-hub». Список исходников — профиль
# server манифеста, тот же, что у build/build-ext.sh, без слоя примитивов: его объект собран
# выше со своими ключами (профиль перечисляет src/lib/scrypto.c, а заголовки wolfSSL нужны только
# ему).
#
# РАЗОШЛИСЬ ОДНАЖДЫ И ЗДЕСЬ. `src/tools/srs.c` появился в движке 5 сентября, в прежний
# переписанный руками список его не внесли, и с того дня `make ext-test` не собирался вовсе — падал
# на `undefined reference to srs_dump`. Урок ровно про это: барьер, который нужно ЗАПУСТИТЬ
# РУКАМИ, не барьер, а список, переписанный руками, — второй список.
echo "ext-test: собираю серверный бинарник для стенда зондирования..."
SERVER_SRC="$(for f in $(profile_src server); do
    [ "$f" = "$(profile_var CRYPTO_SRC)" ] || printf '%s ' "$f"; done)"
# shellcheck disable=SC2086
$CC -O1 -w $STEER_INC -o "$BUILD/steer-hub-native" $SERVER_SRC $CRYPTO -lpthread
echo "ext-test: прогоняю probe (зондирование порта хаба)..."
BUILD="$BUILD" sh tests/probe.sh

echo "ext-test: все стенды прошли на wolfSSL $WVER"
