#!/bin/sh
# Группы выходов спеки v2 в демоне с настоящими nft и ip (docs/architecture.md, «4в», шаг 3).
#
# Сеть стенда: наше пространство (демон `steerd daemon --watch --apply`), клиент за устройством
# lanx (192.168.7.2) и ответчик за двумя парами veth — sw1 (член a) и sw2 (член b). На ответчике:
# 1.1.1.1 и 8.8.8.8 — цели проб сторожа, 10.2.0.1:8080 — HTTP-ответчик generate_204 (считает
# запросы по пути и отвечает, с какого адреса пришёл запрос: 10.9.1.1 — через a, 10.9.2.1 —
# через b) и эхо TCP на 10.2.0.1:9000 для долгого соединения. Задержка члена — tc netem на
# стороне ответчика.
#
# Что проверяется.
#  1. manual: `steer select man b` переключает таблицу группы на устройство b без apply (набор
#     правил в ядре не пересоздаётся), подписчику — switched с by: select и member; status — select
#     и selected; выбор переживает перезапуск демона (файл select); select мёртвого члена — отказ
#     группы по on_fail (blackhole), а не другой член; отказы команды (не член, не manual).
#  2. latency = urltest: через двух членов с разной задержкой выбирается быстрый, хотя он второй
#     по порядку; запрос идёт именно через члена (ответчик видит адрес его устройства); гистерезис:
#     выигрыш меньше tolerance — остаётся на текущем; больше — уходит.
#  3. balance: новые соединения клиента расходятся по обоим членам; упавший член выпадает из карты
#     (карта в ядре — только цепочка живого, событие balance), новые идут на живого; установленное
#     соединение не перескакивает ни при уходе, ни при возврате другого члена.
#  4. idle_timeout: без трафика через группу ни одного запроса проверки; трафик пошёл — замер есть.
#
# Нужны root, unshare, nsenter, nft, ip, tc и python3; без них — пропуск.
set -u
BIN="${STEER:-./build/steer}"
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[ -x "$BIN" ] || { echo "not built: $BIN (make)"; exit 2; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
wait_for() {
    i=0
    while [ $i -lt $(($2 * 10)) ]; do eval "$1" && return 0; sleep 0.1; i=$((i + 1)); done
    return 1
}
skip() { echo "groupsmatch: $1 — пропуск"; exit 0; }
for t in nft ip tc python3 nsenter unshare; do command -v $t >/dev/null 2>&1 || skip "$t нет"; done
if [ "${GROUPS_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    GROUPS_INNER=1 STEER="$BIN" exec unshare -n sh "$0" "$@"
fi
ip link set lo up
nft add table inet groupsmatch_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet groupsmatch_probe
unshare -m sh -c 'mount -t sysfs sysfs /sys' 2>/dev/null || skip "свой /sys не смонтировать"
tc qdisc add dev lo root netem delay 1ms 2>/dev/null && tc qdisc del dev lo root 2>/dev/null ||
    skip "tc netem недоступен"
sysctl -qw net.ipv4.ip_forward=1

tmp="$(mktemp -d)"
mkdir -p "$tmp/st" "$tmp/bin"
D="" SUB="" RPID="" CPID="" HP="" EP="" LP=""
cleanup() {
    kill $SUB $HP $EP $LP $RPID $CPID 2>/dev/null
    [ -n "$D" ] && kill "$D" 2>/dev/null
    # Провал — журнал демона в вывод стенда; GROUPS_KEEP=1 оставляет каталог стенда.
    [ "$fail" != 0 ] && [ -f "$tmp/d.err" ] && { echo "--- журнал демона (хвост)"; tail -n 40 "$tmp/d.err"; }
    if [ "${GROUPS_KEEP:-}" = 1 ]; then echo "каталог стенда: $tmp"; elif [ -n "$tmp" ]; then rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM

# ---- сеть ----
unshare -n sleep 900 & RPID=$!
unshare -n sleep 900 & CPID=$!
sleep 0.3
R() { nsenter -t "$RPID" -n "$@"; }
C() { nsenter -t "$CPID" -n "$@"; }
R ip link set lo up
R ip addr add 1.1.1.1/32 dev lo; R ip addr add 8.8.8.8/32 dev lo; R ip addr add 10.2.0.1/32 dev lo
for k in 1 2; do
    ip link add sw$k type veth peer name sw${k}p
    ip link set sw${k}p netns "$RPID"
    R ip link set sw${k}p up; R ip addr add 10.9.$k.2/24 dev sw${k}p
    ip link set sw$k addrgenmode none 2>/dev/null
    ip link set sw$k up; ip addr add 10.9.$k.1/24 dev sw$k
done
ip link add lanx type veth peer name lanxp
ip link set lanxp netns "$CPID"
ip link set lanx up; ip addr add 192.168.7.1/24 dev lanx
C ip link set lo up; C ip link set lanxp up; C ip addr add 192.168.7.2/24 dev lanxp
C ip route add default via 192.168.7.1
# Как у роутера — маршрут по умолчанию в WAN (здесь пустое устройство). Ответ на замер через члена
# приходит с его устройства без метки, и проверка обратного пути (rp_filter=2, loose) ищет маршрут к
# адресу ответчика в main: без маршрута по умолчанию ответ был бы выброшен.
ip link add wan0 type dummy; ip link set wan0 up; ip addr add 203.0.113.1/24 dev wan0
ip route add default via 203.0.113.254 dev wan0
# Masquerade — дело фаервола, а не движка: здесь своей таблицей, чтобы ответчик отвечал в ту же пару.
nft -f - <<'EOF'
table ip groupsmatch_nat {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname { "sw1", "sw2" } masquerade
    }
}
EOF
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifdown"
printf '#!/bin/sh\nexit 1\n' > "$tmp/bin/ifup"
chmod +x "$tmp/bin/ifdown" "$tmp/bin/ifup"
PATH="$tmp/bin:$PATH"
export PATH

# HTTP-ответчик: 204 на /generate_204 и /idle_204, журнал «путь адрес» по строке; /who — адрес.
cat > "$tmp/http.py" <<'PY'
import socket, sys, threading
log = open(sys.argv[1], 'a', buffering=1)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.2.0.1', 8080)); s.listen(64)
def serve(c, a):
    try:
        d = b''
        while b'\r\n\r\n' not in d:
            x = c.recv(4096)
            if not x: return
            d += x
        path = d.split(b' ')[1].decode()
        log.write('%s %s\n' % (path, a[0]))
        if path == '/who':
            body = a[0].encode()
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
        else:
            c.sendall(b'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n')
    finally:
        c.close()
while True:
    c, a = s.accept()
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
PY
# Эхо: на каждую строку отвечает адресом собеседника (через какого члена пришло соединение).
cat > "$tmp/echo.py" <<'PY'
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.2.0.1', 9000)); s.listen(16)
def serve(c, a):
    f = c.makefile('rwb', buffering=0)
    for line in f:
        f.write(a[0].encode() + b'\n')
while True:
    c, a = s.accept()
    threading.Thread(target=serve, args=(c, a), daemon=True).start()
PY
# Долгое соединение клиента: пишет строку по сигналу (файл-триггер), ответ — в журнал.
cat > "$tmp/long.py" <<'PY'
import socket, sys, time, os
s = socket.create_connection(('10.2.0.1', 9000), timeout=5)
f = s.makefile('rwb', buffering=0)
out = open(sys.argv[1], 'a', buffering=1)
n = 0
while True:
    if os.path.exists(sys.argv[2] + '.%d' % n):
        f.write(b'x\n')
        out.write('%d %s\n' % (n, f.readline().decode().strip()))
        n += 1
    time.sleep(0.05)
PY
: > "$tmp/http.log"
# nsenter напрямую, а не функцией R: у функции в фоне $! — подоболочка, и kill её не снял бы сервер.
nsenter -t "$RPID" -n python3 "$tmp/http.py" "$tmp/http.log" >"$tmp/http.err" 2>&1 & HP=$!
nsenter -t "$RPID" -n python3 "$tmp/echo.py" >"$tmp/echo.err" 2>&1 & EP=$!
sleep 0.5

cat > "$tmp/j.py" <<'PY'
import json, sys
d = json.loads(sys.stdin.read())
for k in sys.argv[1].split('.'):
    if isinstance(d, dict): d = d.get(k)
    elif isinstance(d, list) and k.isdigit(): d = d[int(k)] if int(k) < len(d) else None
    else: d = None
if isinstance(d, list): print(','.join(str(x) for x in d))
elif isinstance(d, dict): print(','.join('%s=%s' % kv for kv in sorted(d.items())))
else: print('-' if d is None else d)
PY
j() { python3 "$tmp/j.py" "$1"; }

printf '10.2.0.0/24\n' > "$tmp/bal.lst"
printf '10.3.0.0/24\n' > "$tmp/idl.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lanx] }
lists:
  lb: { prefixes_file: $tmp/bal.lst }
  li: { prefixes_file: $tmp/idl.lst }
outputs:
  a:   { kind: interface, device: sw1 }
  b:   { kind: interface, device: sw2 }
  man: { kind: group, pick: manual, members: [a, b], default: a }
  lat: { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/generate_204", tolerance: 60, idle_timeout: 0 }
  idl: { kind: group, pick: latency, members: [b, a], url: "http://10.2.0.1:8080/idle_204", idle_timeout: 3600 }
  bal: { kind: group, pick: balance, members: [a, b] }
rules:
  - { name: bal, to: [lb], out: bal }
  - { name: idl, to: [li], out: idl }
EOF
S="--spec $tmp/spec.yaml --state-dir $tmp/st"
STEER_SOCKET="$tmp/steer.sock"
export STEER_SOCKET
c() { "$BIN" "$@" $S; }
start_daemon() {
    unshare -m sh -c "mount -t sysfs sysfs /sys && exec \"$BIN\" daemon --watch --watch-period 3 --apply \
        --socket \"$tmp/steer.sock\" $S" >>"$tmp/d.out" 2>>"$tmp/d.err" &
    D=$!
    wait_for '[ -S "$tmp/steer.sock" ] && [ "$(grep -c "watch: первый проход" "$tmp/d.err")" -gt "$starts" ]' 15
    starts=$((starts + 1))
    # Подписчик — заново у каждого экземпляра демона (соединение уходит вместе с прежним).
    [ -n "$SUB" ] && kill "$SUB" 2>/dev/null
    : > "$tmp/sub.out"
    "$BIN" subscribe $S > "$tmp/sub.out" 2>&1 &
    SUB=$!
    wait_for 'grep -q "\"cmd\":\"subscribe\"" "$tmp/sub.out"' 5
}
starts=0
stop_daemon() { kill "$D" 2>/dev/null; wait "$D" 2>/dev/null; D=""; rm -f "$tmp/steer.sock"; }
reg() { awk -v o="$1" '$1 == o { print $'"$2"' }' "$tmp/st/registry"; }
tdev() { ip route show table "$(reg "$1" 3)" | awk '$1 == "default" && $2 == "dev" { print $3 }' | head -n 1; }
tbh() { ip route show table "$(reg "$1" 3)" | grep -c '^blackhole default *$'; }
troutes() { ip route show table "$(reg "$1" 3)" | tr '\n' ';'; }
# status — только от демона (движок подменён отказом): память сторожа — у него.
st() { STEER_ENGINE=/bin/false "$BIN" status $S | j "$1"; }

start_daemon
wait_for '[ "$(tdev man)" = sw1 ]' 10
check "manual: до первой команды — default (a, sw1)" "sw1" "$(tdev man)"
wait_for '[ "$(st outputs.man.group.selected)" = a ]' 20
check "  status: pick, select, selected" "manual a a" \
    "$(st outputs.man.group.pick) $(st outputs.man.group.select) $(st outputs.man.group.selected)"

# ---- 1. manual ----
h0="$(nft -a list chain inet steer prerouting_mark | grep -o 'handle [0-9]*' | tr '\n' ' ')"
out="$(c select man b 2>&1)"; rc=$?
check "select man b: код 0 и ответ" "0 1" "$rc $(echo "$out" | grep -c 'выбран b (sw2)')"
check "  таблица группы — на устройство b сразу" "sw2" "$(tdev man)"
check "  без apply: правила в ядре те же (номера правил не сменились)" "$h0" \
    "$(nft -a list chain inet steer prerouting_mark | grep -o 'handle [0-9]*' | tr '\n' ' ')"
wait_for 'grep -q "\"by\":\"select\"" "$tmp/sub.out"' 3
check "  подписчику — switched by: select с членом" \
    '{"v":1,"ev":"switched","out":"man","from":"sw1","to":"sw2","why":"select","member":"b","by":"select"}' \
    "$(grep '"ev":"switched"' "$tmp/sub.out" | grep '"by":"select"' | head -n 1)"
check "  status: select b, selected b" "b b" "$(st outputs.man.group.select) $(st outputs.man.group.selected)"
check "  выбор — в файле select рядом с реестром" "man b" "$(cat "$tmp/st/select")"
sleep 7
check "  проход сторожа выбор не отменяет" "sw2" "$(tdev man)"
out="$(c select man nope 2>&1)"; rc=$?
check "select не члена — отказ 2" "2 1" "$rc $(echo "$out" | grep -c 'не член группы man')"
out="$(c select lat a 2>&1)"; rc=$?
check "select у группы не manual — отказ 2" "2 1" "$rc $(echo "$out" | grep -c 'pick: latency')"

stop_daemon
check "перезапуск: таблица осталась на b" "sw2" "$(tdev man)"
start_daemon
sleep 1
check "  после перезапуска демона выбор тот же (status select и таблица)" "b sw2" \
    "$(st outputs.man.group.select) $(tdev man)"

ip link set sw2 down
wait_for '[ "$(tbh man)" = 1 ]' 40
check "выбранный член упал — группа по on_fail (drop: blackhole), не на a" "1 " \
    "$(tbh man) $(tdev man)$([ "$(tbh man)" = 1 ] || troutes man)"
wait_for 'grep "\"ev\":\"failed\"" "$tmp/sub.out" | grep -q "\"out\":\"man\""' 10
check "  подписчику — failed группы" "1" "$(grep '"ev":"failed"' "$tmp/sub.out" | grep -c '"out":"man"')"
check "  status: selected null, select по-прежнему b" "- b" \
    "$(st outputs.man.group.selected) $(st outputs.man.group.select)"
ip link set sw2 up
wait_for '[ "$(tdev man)" = sw2 ]' 30
check "член поднялся — группа снова на нём" "sw2" "$(tdev man)"

# ---- 2. latency = urltest ----
# b (первый по порядку) медленный: 200 мс на стороне ответчика; a — быстрый.
R tc qdisc add dev sw2p root netem delay 200ms
stop_daemon
start_daemon
# Замеры живут в памяти демона: после перезапуска их нет, пока первый проход не измерит обоих.
wait_for '[ "$(st outputs.lat.group.latency | tr "," "\n" | grep -c "^[ab]=")" = 2 ]' 20
check "latency: быстрый член выбран, хотя он второй по порядку" "sw1 a" "$(tdev lat) $(st outputs.lat.group.selected)"
lat_b="$(st outputs.lat.group.latency | tr ',' '\n' | awk -F= '$1 == "b" { print $2 }')"
lat_a="$(st outputs.lat.group.latency | tr ',' '\n' | awk -F= '$1 == "a" { print $2 }')"
check "  status: замеры обоих, b медленнее a на задержку netem" "yes" \
    "$([ -n "$lat_a" ] && [ -n "$lat_b" ] && [ "$lat_b" -ge 190 ] && [ "$lat_a" -lt 150 ] && echo yes || echo "a=$lat_a b=$lat_b")"
check "  запрос шёл через каждого члена (ответчик видел оба адреса)" "2" \
    "$(grep '^/generate_204 ' "$tmp/http.log" | awk '{ print $2 }' | sort -u | grep -c '^10\.9\.[12]\.1$')"
# Гистерезис: теперь b быстрее, но меньше чем на tolerance 60 мс — остаёмся на a. Задержка netem
# на стороне ответчика ложится в замер дважды (SYN-ACK и ответ): 15 мс — около 30 мс разницы.
R tc qdisc del dev sw2p root
R tc qdisc add dev sw1p root netem delay 15ms
stop_daemon      # замеры живут в памяти демона: перезапуск — свежий замер на первом проходе
start_daemon
wait_for '[ -n "$(st outputs.lat.group.latency | grep "a=")" ]' 15
check "  гистерезис: выигрыш b меньше допуска — остаётся a" "sw1" \
    "$(tdev lat)$([ "$(tdev lat)" = sw1 ] || st outputs.lat.group.latency)"
R tc qdisc change dev sw1p root netem delay 250ms
stop_daemon
start_daemon
wait_for '[ "$(tdev lat)" = sw2 ]' 15
check "  выигрыш больше допуска — уходит на b" "sw2 b" "$(tdev lat) $(st outputs.lat.group.selected)"
R tc qdisc del dev sw1p root

# ---- 4. idle_timeout ----
check "idle_timeout: без трафика через группу — ни одного запроса проверки" "0" \
    "$(grep -c '^/idle_204 ' "$tmp/http.log")"
# Трафик — после того как сторож хотя бы раз прошёл группу (первая встреча берёт отсчёт), и
# пачками, пока замер не появится.
sleep 5
for k in $(seq 1 15); do
    C python3 -c 'import socket
for i in range(5):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x", ("10.3.0.1", 9))' 2>/dev/null
    [ "$(grep -c '^/idle_204 ' "$tmp/http.log")" -ge 1 ] && break
    sleep 2
done
check "  трафик пошёл — замер сделан" "yes" \
    "$([ "$(grep -c '^/idle_204 ' "$tmp/http.log")" -ge 1 ] && echo yes || echo no)"

# ---- 3. balance ----
who() { C python3 -c 'import socket
s = socket.create_connection(("10.2.0.1", 8080), timeout=3)
s.sendall(b"GET /who HTTP/1.1\r\nHost: x\r\n\r\n")
d = b""
while True:
    x = s.recv(4096)
    if not x: break
    d += x
print(d.split(b"\r\n\r\n", 1)[1].decode())' 2>/dev/null; }
n1=0 n2=0
for i in $(seq 1 40); do
    case "$(who)" in 10.9.1.1) n1=$((n1 + 1)) ;; 10.9.2.1) n2=$((n2 + 1)) ;; esac
done
check "balance: соединения расходятся по обоим членам (40 соединений)" "yes" \
    "$([ $n1 -ge 5 ] && [ $n2 -ge 5 ] && [ $((n1 + n2)) = 40 ] && echo yes || echo "a=$n1 b=$n2")"
check "  status: живые — оба, веса" "a,b 1,1" "$(st outputs.bal.group.alive) $(st outputs.bal.group.weights)"
# Долгое соединение — на каком оно члене, скажет эхо.
nsenter -t "$CPID" -n python3 "$tmp/long.py" "$tmp/long.log" "$tmp/go" >"$tmp/long.err" 2>&1 & LP=$!
sleep 0.5
touch "$tmp/go.0"
wait_for '[ -s "$tmp/long.log" ]' 5
first="$(awk '$1 == 0 { print $2 }' "$tmp/long.log")"
case "$first" in 10.9.1.1) keep=sw1 other=sw2 om=b km=a ;; *) keep=sw2 other=sw1 om=a km=b ;; esac
map_targets() { nft list map inet steer "balmap_$(reg bal 3)" | grep -o 'goto mark_[0-9]*' | sort -u | tr '\n' ' '; }
ip link set "$other" down
wait_for '[ "$(map_targets)" = "goto mark_$(reg "$km" 3) " ]' 30
check "упал член $om — карта только с живым" "goto mark_$(reg "$km" 3) " "$(map_targets)"
check "  подписчику — balance с живыми" "{\"v\":1,\"ev\":\"balance\",\"out\":\"bal\",\"alive\":[\"$km\"]}" \
    "$(grep '"ev":"balance"' "$tmp/sub.out" | tail -n 1)"
touch "$tmp/go.1"
wait_for '[ "$(awk "\$1 == 1" "$tmp/long.log")" ]' 5
check "  установленное соединение на своём члене" "$first" "$(awk '$1 == 1 { print $2 }' "$tmp/long.log")"
m=0
for i in $(seq 1 10); do [ "$(who)" = "$first" ] && m=$((m + 1)); done
check "  новые соединения — все на живого" "10" "$m"
ip link set "$other" up
wait_for '[ "$(map_targets | wc -w)" = 4 ]' 30
check "член вернулся — карта снова на обоих" "4" "$(map_targets | wc -w)"
touch "$tmp/go.2"
wait_for '[ "$(awk "\$1 == 2" "$tmp/long.log")" ]' 5
check "  установленное соединение не перескочило на вернувшийся" "$first" "$(awk '$1 == 2 { print $2 }' "$tmp/long.log")"
kill $LP 2>/dev/null

stop_daemon
echo "groupsmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
