#!/bin/sh
# Окно приёма стека TUN с настоящим клиентом ядра Linux: масштаб окна (RFC 7323) обязан быть согласован,
# а выгрузка через туннель при задержке в LAN — не упираться в 64 КБ на круг.
#
# ЧТО НАШЛИ. Стек туннеля объявлял клиенту окно 65535 без масштаба (OUR_WSCALE 0 в stack.c): клиент не
# вправе иметь в пути больше 64 КБ на соединение, а скорость соединения — это окно, делённое на круг.
# Замер (узел — Xray, клиент — ядро Linux, netem по 3 мс в каждую сторону): выгрузка одним потоком 83 Мбит/с
# при потолке 65535 байт / 6,1 мс = 86, с масштабом — около 1,4 Гбит/с; в настоящей сети с Wi-Fi (круг 2-5 мс)
# прежний потолок — 100-250 Мбит/с на соединение, сколько бы ни давали узел и процессор. Без задержки (veth,
# круг в доли миллисекунды) окно скорость выгрузки не ограничивало: её держит узел.
#
# ЧТО ПРОВЕРЯЕТ СТЕНД. Модуль steer-vless (прямой запуск, без демона: маршрут на цель — в TUN, как у
# tests/run-tunnel.sh) принимает выгрузку настоящего клиента ядра, между клиентом и роутером — netem в
# обе стороны (круг 6 мс), узел — приёмник без шифрования (tests/sigpipe-node.py, порт 82). Дважды:
#   * по умолчанию — клиент видит в `ss -ti` масштаб окна роутера (wscale:<наш>,<его>), объявленное окно
#     (snd_wnd) выше 64 КБ, и выгрузка быстрее потолка «64 КБ на круг» больше чем втрое;
#   * с STEER_TUN_RCVWND=0 (прежнее поведение одной переменной) — масштаба нет (wscale:0), окно не выше
#     65535, скорость не выше потолка «64 КБ на круг» с запасом на разброс замера.
# Клиент без опции масштаба в SYN (net.ipv4.tcp_window_scaling=0 в его пространстве) — третий прогон: масштаба
# нет, окно 65535, выгрузка идёт и не рвётся. Что опции в SYN-ACK на такой SYN нет, проверяет tunnelmatch
# (клиент её всё равно проигнорировал бы, и в ss этого не видно).
#
# Нужны root, unshare -nm, ip, tc (netem), ss, nsenter и python3 — иначе пропуск, а не падение.
# LIBS — раскладка libs (tests/libs-test.sh, build/libs-host).
set -u
LIBS="$(cd "${LIBS:-build/libs-host}" 2>/dev/null && pwd)"
skip() { echo "rcvwnd: $1 — пропуск"; exit 0; }
[ -x "$LIBS/steerd" ] && [ -x "$LIBS/steer-vless" ] || skip "нет раскладки libs ($LIBS, tests/libs-test.sh)"
HERE="$(cd "$(dirname "$0")" && pwd)"
LD_LIBRARY_PATH="$LIBS"; export LD_LIBRARY_PATH
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "ok   $1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
for t in ip tc ss python3 nsenter unshare awk; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${RCVWND_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    RCVWND_INNER=1 exec unshare -nm sh "$0" "$@"
fi
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "свой /sys не смонтировать"
ip link set lo up
ip link add nemprobe type dummy 2>/dev/null && tc qdisc add dev nemprobe root netem delay 1ms 2>/dev/null \
    || skip "netem недоступен (sch_netem)"
ip link del nemprobe
sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0

UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
TARGET=203.0.113.7
SECS="${RCVWND_SECS:-4}"
DELAY="${RCVWND_DELAY:-3}"       # мс в каждую сторону: круг вдвое больше
tmp="$(mktemp -d)"
mkdir -p "$tmp/st"
CPID="" NP="" MP="" CL=""
cleanup() {
    kill $CL $MP $NP $CPID 2>/dev/null
    if [ "$fail" != 0 ]; then
        echo "--- журнал модуля (хвост)"; tail -n 12 "$tmp/mod.log" 2>/dev/null
    fi
    if [ "${RCVWND_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть: роутер (это пространство), клиент за veth, узел на dummy роутера ---------------------------
unshare -n sleep 1800 & CPID=$!
sleep 0.3
C() { nsenter -t "$CPID" -n "$@"; }
ip link add p0 type veth peer name c0
ip link set c0 netns "$CPID"
ip addr add 10.78.1.1/24 dev p0
ip link set p0 up
C ip link set lo up
C ip addr add 10.78.1.2/24 dev c0
C ip link set c0 up
C ip route add default via 10.78.1.1
ip link add node0 type dummy
ip addr add 10.78.0.1/32 dev node0
ip link set node0 up
# Круг в LAN: задержка в каждую сторону (исходящее клиента и исходящее роутера клиенту). limit — с запасом:
# netem держит в очереди всё, что «в полёте» по задержке, и со штатным 1000 пакетов терял бы сам.
C tc qdisc add dev c0 root netem delay "${DELAY}ms" limit 100000
tc qdisc add dev p0 root netem delay "${DELAY}ms" limit 100000

python3 "$HERE/sigpipe-node.py" --bind 10.78.0.1 --port 10444 --uuid "$UUID" >"$tmp/node.out" 2>"$tmp/node.err" & NP=$!
wait_for 'grep -q ready "$tmp/node.out"' 10
printf 'vless://%s@10.78.0.1:10444?security=none&type=tcp#node\n' "$UUID" > "$tmp/sub.txt"
cat > "$tmp/spec.json" <<EOF
{"schema":1,
 "outputs":{"vl":{"name":"vl","kind":"vless","sub_file":"$tmp/sub.txt","node":0}},
 "channels":[]}
EOF

# Клиент: выгрузка на порт 82 узла (приёмник, который не закрывается) SECS секунд; соединение держится
# открытым, пока стенд не снимет ss.
cat > "$tmp/up.py" <<'PY'
import socket, sys, time
target, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket()
s.settimeout(10)
s.connect((target, 82))
blob = b"\xa5" * (1 << 20)
end = time.time() + secs
try:
    while time.time() < end:
        s.send(blob)
except OSError as e:
    print("клиент: запись оборвалась:", e, flush=True)
print("клиент: послал", flush=True)
time.sleep(30)
PY

# Один прогон: модуль (env — «К=З» или пусто), выгрузка, ss клиента в середине и в конце. Печатает в $tmp/run.*
run() {
    name="$1"; shift
    env "$@" "$LIBS/steerd" vless vl --spec "$tmp/spec.json" --state-dir "$tmp/st" >"$tmp/mod.log" 2>&1 &
    MP=$!
    wait_for 'ip link show vl >/dev/null 2>&1' 20
    wait_for 'grep -q "запасных сессий" "$tmp/mod.log"' 20
    ip route replace "$TARGET/32" dev vl
    # nsenter напрямую, а не функцией C: у функции $! — подоболочка, и kill её не убил бы сам python.
    nsenter -t "$CPID" -n python3 "$tmp/up.py" "$TARGET" "$SECS" >"$tmp/cl.$name" 2>&1 & CL=$!
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.mid.$name" 2>&1
    sleep "$(awk -v s="$SECS" 'BEGIN { print s / 2 + 0.5 }')"
    C ss -tin dst "$TARGET" > "$tmp/ss.end.$name" 2>&1
    kill $CL 2>/dev/null; wait $CL 2>/dev/null; CL=""
    kill $MP 2>/dev/null; wait $MP 2>/dev/null; MP=""
    ip link del vl 2>/dev/null
    sleep 1
}
# Поле ss: tok<имя>:<значение> из строки с данными соединения.
field() { tr ' ' '\n' < "$1" | sed -n "s/^$2://p" | head -n 1; }
# Мбит/с по bytes_acked клиента за срок выгрузки.
mbit() { awk -v b="$(field "$1" bytes_acked)" -v s="$SECS" 'BEGIN { printf "%d", b * 8 / s / 1e6 }'; }
# Потолок «окно 64 КБ на круг» в Мбит/с: 65535 байт на (круг + то, что стоит сам модуль — берём один пакет).
CEIL="$(awk -v d="$DELAY" 'BEGIN { printf "%d", 65535 * 8 / (2 * d / 1000) / 1e6 }')"

run scaled STEER_X=1
run legacy STEER_TUN_RCVWND=0
C sysctl -qw net.ipv4.tcp_window_scaling=0
run nows STEER_X=1
C sysctl -qw net.ipv4.tcp_window_scaling=1

echo "  круг ${DELAY}x2 мс; потолок «64 КБ на круг» — $CEIL Мбит/с"
for v in scaled legacy nows; do
    echo "  $v: $(mbit "$tmp/ss.end.$v") Мбит/с, snd_wnd $(field "$tmp/ss.mid.$v" snd_wnd), wscale $(field "$tmp/ss.mid.$v" wscale), rtt $(field "$tmp/ss.mid.$v" rtt)"
done

check "в журнале модуля — окно приёма и множитель, не нулевой" "1" \
    "$(sed -n 's/.*окно приёма клиентов: до [0-9]* КБ, масштаб \([0-9]*\).*/\1/p' "$tmp/mod.log" | head -n 1 | grep -c '^[1-9]')"
# Масштаб — по ss клиента: wscale:<масштаб роутера>,<его собственный>.
check "по умолчанию клиент видит масштаб окна роутера (wscale:N,... с N > 0)" "1" \
    "$([ "$(field "$tmp/ss.mid.scaled" wscale | cut -d, -f1)" -gt 0 ] 2>/dev/null && echo 1 || echo 0)"
check "  и окно выше 64 КБ (snd_wnd)" "1" "$([ "$(field "$tmp/ss.mid.scaled" snd_wnd)" -gt 65535 ] 2>/dev/null && echo 1 || echo 0)"
check "  и выгрузка быстрее потолка «64 КБ на круг» больше чем втрое" "1" \
    "$([ "$(mbit "$tmp/ss.end.scaled")" -gt $((CEIL * 3)) ] && echo 1 || echo 0)"
check "STEER_TUN_RCVWND=0: масштаба нет (wscale:0,...)" "0" "$(field "$tmp/ss.mid.legacy" wscale | cut -d, -f1)"
check "  окно не выше 65535" "1" "$([ "$(field "$tmp/ss.mid.legacy" snd_wnd)" -le 65535 ] 2>/dev/null && echo 1 || echo 0)"
check "  скорость не выше потолка с запасом на разброс (в полтора раза)" "1" \
    "$([ "$(mbit "$tmp/ss.end.legacy")" -le $((CEIL * 3 / 2)) ] && echo 1 || echo 0)"
check "клиент без масштаба окна: выгрузка идёт, окно 65535, масштаба нет" "1" \
    "$([ "$(mbit "$tmp/ss.end.nows")" -gt 10 ] && [ "$(field "$tmp/ss.mid.nows" snd_wnd)" -le 65535 ] && [ -z "$(field "$tmp/ss.mid.nows" wscale)" ] && echo 1 || echo 0)"

echo "rcvwnd: $pass ok, $fail fail"
[ "$fail" = 0 ]
