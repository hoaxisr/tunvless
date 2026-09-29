#!/bin/sh
# Замер: Brutal против CUBIC на канале с потерями и задержкой (шаг 7 выпуска 1.10).
#
#     sh tests/qcbench.sh                                 умолчания ниже
#     SECS=10 DELAY=25ms LOSS=5% BPS=6250000 sh tests/qcbench.sh
#     sh tests/qcbench.sh check                           для ext-test: коротко, тихо, с проверкой
#
# СТЕНД. Два сетевых пространства имён, между ними veth, на обоих концах netem (задержка и потери
# на выходе, то есть в обе стороны — теряются и подтверждения). Сервер (tests/qcserver.c) в одном,
# клиент (tests/qcbench.c) в другом: не loopback, а настоящее ядерное соединение с очередью, — и, что
# важно для соседних прогонов на той же машине, netem НЕ на общем интерфейсе lo: qdisc висит на
# паре veth, которую видит только этот скрипт. Пространства и пара удаляются при любом выходе.
#
# Что меряется. Клиент льёт данные в один поток SECS секунд; сервер считает принятые байты и
# печатает скорость (goodput — то, что дошло и было принято приложением). CUBIC режет окно на каждую
# потерю и на канале с 5% потерь и RTT 40 мс проседает до нескольких мегабит; Brutal держит заданное
# BPS (БАЙТ/с) и поправляет отправку на потери.
#
# Нужно: root, ip(8) с netns, tc(8) с netem, собранные build/qcserver и build/qcbench (tests/ext-test.sh
# собирает их вместе с остальным). Нет чего-то — пропуск с причиной, не падение.
set -u
BUILD=${BUILD:-build}
SECS=${SECS:-8}
DELAY=${DELAY:-20ms}
LOSS=${LOSS:-5%}
BPS=${BPS:-6250000}
MODE=${1:-report}
[ "$MODE" = check ] && SECS=${SECS_CHECK:-4}

skip() { echo "qcbench: ПРОПУСК — $1"; exit 0; }
[ "$(id -u)" = 0 ] || skip "нужен root (ip netns)"
command -v ip >/dev/null 2>&1 || skip "нет ip(8)"
command -v tc >/dev/null 2>&1 || skip "нет tc(8)"
[ -x "$BUILD/qcserver" ] && [ -x "$BUILD/qcbench" ] || skip "нет $BUILD/qcserver и $BUILD/qcbench (make ext-test)"

ID=$$
NS_S=qcb-s-$ID
NS_C=qcb-c-$ID
LOG=$(mktemp -d)
cleanup() {
    [ -n "${SPID:-}" ] && kill "$SPID" 2>/dev/null
    ip netns del "$NS_S" 2>/dev/null
    ip netns del "$NS_C" 2>/dev/null
    # KEEP=1 — оставить журналы сервера и клиента (разбор отказа): путь напечатан ниже.
    if [ -n "${KEEP:-}" ]; then echo "qcbench: журналы в $LOG"; else rm -rf "$LOG"; fi
}
trap cleanup EXIT INT TERM

ip netns add "$NS_S" 2>/dev/null && ip netns add "$NS_C" 2>/dev/null || skip "не создать пространство имён"
V1=qcs$ID
V2=qcc$ID
ip link add "$V1" type veth peer name "$V2" 2>/dev/null || skip "не создать veth"
ip link set "$V1" netns "$NS_S"
ip link set "$V2" netns "$NS_C"
ip -n "$NS_S" addr add 10.77.0.1/24 dev "$V1"
ip -n "$NS_C" addr add 10.77.0.2/24 dev "$V2"
ip -n "$NS_S" link set "$V1" up
ip -n "$NS_C" link set "$V2" up
ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set lo up
for pair in "$NS_S:$V1" "$NS_C:$V2"; do
    ip netns exec "${pair%%:*}" tc qdisc add dev "${pair#*:}" root netem delay "$DELAY" loss "$LOSS" limit 20000 2>/dev/null \
        || skip "нет netem в ядре (tc qdisc add ... netem)"
done
# Буферы сокета: пачка Brutal и окно — десятки мегабайт в полёте; потолок ядра иначе режет замер.
ip netns exec "$NS_S" sysctl -qw net.core.rmem_max=8388608 net.core.wmem_max=8388608 2>/dev/null

run_one() {  # ИМЯ АРГУМЕНТЫ-КЛИЕНТА…
    name=$1; shift
    ip netns exec "$NS_S" "$BUILD/qcserver" --bind 10.77.0.1 --port 4433 --idle 20 > "$LOG/srv.$name" 2>/dev/null &
    SPID=$!
    n=0
    while ! grep -q '^listening' "$LOG/srv.$name" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
    ip netns exec "$NS_C" "$BUILD/qcbench" 10.77.0.1 4433 "$SECS" "$@" > "$LOG/cli.$name" 2>"$LOG/cli.$name.err"
    wait "$SPID" 2>/dev/null
    SPID=
    mbit=$(sed -n 's/^total .*mbit=\([0-9.]*\)$/\1/p' "$LOG/srv.$name")
    echo "${mbit:-0}"
}

[ "$MODE" = check ] || echo "qcbench: RTT ${DELAY}x2, потери ${LOSS} в каждую сторону, ${SECS} с, Brutal ${BPS} байт/с ($((BPS * 8 / 1000000)) Мбит/с)"
cubic=$(run_one cubic cubic)
brutal=$(run_one brutal brutal "$BPS")
target=$((BPS * 8 / 1000000))
if [ "$MODE" != check ]; then
    echo "  CUBIC    goodput ${cubic} Мбит/с   ($(sed 's/^client //' "$LOG/cli.cubic"))"
    echo "  Brutal   goodput ${brutal} Мбит/с   ($(sed 's/^client //' "$LOG/cli.brutal"))  цель ${target} Мбит/с"
    exit 0
fi
# Проверка для ext-test: Brutal держит заданное (не ниже 60% цели — часть уходит на потери и разгон
# за короткий прогон), и заметно быстрее CUBIC на том же канале.
ok=$(awk -v b="$brutal" -v c="$cubic" -v t="$target" 'BEGIN { print (b >= 0.6 * t && b >= 2 * c) ? 1 : 0 }')
echo "qcbench: CUBIC ${cubic} Мбит/с, Brutal ${brutal} Мбит/с (цель ${target}): $([ "$ok" = 1 ] && echo ok || echo ПРОВАЛ)"
[ "$ok" = 1 ]
