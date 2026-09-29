#!/bin/sh
# Апстримы резолвера с настоящим TLS: DoT и DoH через выход, bootstrap, кэш, лежащий выход.
# Устройство проверяемого — src/dnsd/dup.h; спека — docs/spec-v2.md, раздел `dns`.
#
# Сеть — два пространства. Роутер (сам стенд): wan0 (10.0.1.1) — «провайдер», tun0 (10.0.2.1) —
# устройство выхода `vpn` (kind=interface), у него своя таблица и ip rule по метке, и правила
# nft — настоящие, из `steerd apply`, вместе со стражем postrouting_guard. Сервер S (пространство
# за ними): один адрес 192.0.2.53 на lo, доступный и по wan1, и по tun1; на нём tests/dnsup-server.py —
# обычный DNS, DoT, DoH, каждый вопрос в журнале с адресом клиента. По адресу клиента видно путь:
# 10.0.2.1 — через выход, 10.0.1.1 — напрямую (мимо выхода, «в WAN»).
#
# Что проверяется.
#  1. Имя правила с dns.upstreams.<имя>.out: vpn спрашивается по DoT и по DoH, вопрос приходит с
#     туннельного адреса, пакеты идут через tun0 (счётчик устройства растёт), в WAN ничего.
#  2. Имя сервера разрешается bootstrap-сервером (обычный DNS, тоже через выход), а не системным
#     резолвером: в пространстве нет ни одного другого DNS, и `dns.test` больше нигде не найдётся.
#  3. Апстрим без выхода (direct) — вопрос приходит с адреса WAN.
#  4. Кэш: второй вопрос того же имени не доходит до сервера; ответ клиенту по-прежнему
#     поддельный адрес (fake-IP строгий) — и элемент карты ядра стоит.
#  5. Выход лёг (tun0 вниз): ни одного вопроса из WAN, клиенту SERVFAIL; вернулся — работает.
#  6. Сервер перезапущен (соединения мертвы) — следующий вопрос идёт на новом; DoH с ответом кусками
#     (Transfer-Encoding: chunked).
#  7. Имя вне правил идёт прежним путём (заглушка на петле), а не на апстрим правил.
#  8. bootstrap не отвечает, адресов в спеке нет — SERVFAIL за срок, а не зависание; адреса в спеке
#     (`ips`) — bootstrap не нужен вовсе.
#  9. `steer dns-log`: апстримы, их состояние, счётчики, кэш.
#  Замер задержек (DNSUP_BENCH=1): холодное соединение и тёплое, UDP/DoT/DoH.
#
# Нужны root, unshare, nsenter, ip, nft, openssl, python3 и исходники wolfSSL (STEER_WOLFSSL или
# $BUILD/wolfssl-host/src, как у tests/ext-test.sh): TLS в резолвере — из библиотеки движка. Чего-то
# нет — стенд пропускается вслух, с кодом 0.
set -u
BUILD=${BUILD:-build}
skip() { echo "dnsup: $1 — пропускаю"; exit 0; }
for t in ip nft unshare nsenter openssl python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
if [ "${DNSUP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    WSRC="${STEER_WOLFSSL:-$BUILD/wolfssl-host/src}"
    [ -f "$WSRC/wolfssl/wolfcrypt/settings.h" ] || skip "исходников wolfSSL нет ($WSRC)"
    # ---- сборка: движок с TLS для проверки (то же, что кладёт в пакет libsteer, но одним файлом) ----
    CC=${CC:-cc}
    . build/sources.sh
    INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done) $(profile_var THIRD_DEFS)"
    CCTAG=$(printf '%s' "$CC" | tr -c 'a-zA-Z0-9' '_')
    WLIB="$BUILD/wolfssl-host/libwolfssl-$CCTAG.a"
    mkdir -p "$BUILD/wolfssl-host" "$BUILD/dnsup"
    if [ ! -f "$WLIB" ]; then
        CC="$CC" AR="${AR:-ar}" CFLAGS="-O2 -g" STEER_WOLFSSL_DEFS="-DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT" \
            sh build/wolfssl/build.sh "$WSRC" "$WLIB" asm >/dev/null || skip "wolfSSL не собрался"
    fi
    WCF=$(cat "$WLIB.cflags")
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC $WCF -c src/lib/scrypto.c -o "$BUILD/dnsup/scrypto.o" || skip "scrypto не собрался"
    # shellcheck disable=SC2086
    $CC -O2 -g -w $INC -DSTEER_VERSION='"dnsup"' -o "$BUILD/dnsup/steer" $(profile_var CORE_SRC) \
        src/proto/tls/tls13.c src/proto/tls/certverify.c src/proto/tls/reality.c src/proto/tls/chello.c \
        src/proto/tls/h2.c src/proto/tls/roots.c "$BUILD/dnsup/scrypto.o" "$WLIB" -lpthread -lm ||
        skip "движок с TLS не собрался"
    DNSUP_INNER=1 DNSUP_BIN="$(cd "$BUILD/dnsup" && pwd)/steer" DNSUP_SRV="$(cd tests && pwd)/dnsup-server.py" \
        exec unshare -nm sh "$0" "$@"
fi
BIN="$DNSUP_BIN"
mount --make-rprivate / 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null || skip "не смонтировать sysfs в своём пространстве"
ip link set lo up

tmp="$(mktemp -d)"
S="--state-dir $tmp/st"
cleanup() {
    kill $(cat "$tmp"/*.pid 2>/dev/null) ${SPID:-0} ${STUB:-0} 2>/dev/null
    pkill -f "dnsup-server.py 192.0.2.53 $tmp" 2>/dev/null
    pkill -f "$tmp/" 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup EXIT

pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

# ---- сеть --------------------------------------------------------------------------------------
unshare -n sh -c 'echo $$ > '"$tmp"'/srv.ns; exec sleep 3600' & SPID=$!
n=0; while [ ! -s "$tmp/srv.ns" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
NS="$(cat "$tmp/srv.ns")"
inS() { nsenter -t "$NS" -n "$@"; }
ip link add wan0 type veth peer name wan1 netns "$NS" || skip "veth недоступен"
ip link add tun0 type veth peer name tun1 netns "$NS"
ip addr add 10.0.1.1/24 dev wan0; ip addr add 10.0.2.1/24 dev tun0
ip link set wan0 up; ip link set tun0 up
inS ip link set lo up
inS ip addr add 10.0.1.2/24 dev wan1; inS ip addr add 10.0.2.2/24 dev tun1
inS ip link set wan1 up; inS ip link set tun1 up
inS ip addr add 192.0.2.53/32 dev lo
ip route add default via 10.0.1.2 dev wan0
sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
inS sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
nft add table inet steer_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet steer_probe

# ---- сертификаты и сервер ----------------------------------------------------------------------
c="$tmp/pki"; mkdir -p "$c"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/ca.key" \
    -out "$c/ca.pem" -days 3 -subj "/CN=dnsup-test-ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/srv.key" \
    -out "$c/srv.csr" -subj "/CN=dns.test" >/dev/null 2>&1
printf 'subjectAltName=DNS:dns.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$c/ext"
openssl x509 -req -in "$c/srv.csr" -CA "$c/ca.pem" -CAkey "$c/ca.key" -CAcreateserial -out "$c/srv.pem" \
    -days 3 -extfile "$c/ext" >/dev/null 2>&1
LOG="$tmp/srv.log"; : > "$LOG"
srv_start() {   # аргументы сервера
    inS python3 "$DNSUP_SRV" 192.0.2.53 "$LOG" "$c/srv.pem" "$c/srv.key" --zone svc.test=203.0.113.7 \
        --zone dns.test=192.0.2.53 --zone plain.test=203.0.113.9 --ttl 300 "$@" > "$tmp/srv.out" 2>&1 &
    echo $! > "$tmp/srv.pid"
    n=0; while ! grep -q ready "$tmp/srv.out" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
}
srv_start

# ---- заглушка на петле: «dnsmasq» для имён вне правил ---------------------------------------------
cat > "$tmp/stub.py" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(2048)
    e = 12
    while d[e]: e += 1 + d[e]
    e += 5
    open(sys.argv[2], "a").write("stub\n")
    s.sendto(d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x01\x00\x00\x00\x00" + d[12:e] +
             b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([198, 51, 100, 77]), a)
PY
STUBLOG="$tmp/stub.log"; : > "$STUBLOG"
python3 "$tmp/stub.py" 15353 "$STUBLOG" & STUB=$!

# ---- клиент ------------------------------------------------------------------------------------
cat > "$tmp/ask.py" <<'PY'
import socket, struct, sys, time
port, name = int(sys.argv[1]), sys.argv[2]
qt = int(sys.argv[3]) if len(sys.argv) > 3 else 1
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', qt, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(6)
t = time.time()
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
ms = (time.time() - t) * 1000
rc = d[3] & 0x0f
if len(sys.argv) > 4: print("%.1f" % ms); sys.exit()
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(".".join(str(b) for b in d[-4:]))
PY
LPORT=15310
ask() { python3 "$tmp/ask.py" "$LPORT" "$@"; }
cnt() { grep -c "$1" "$LOG"; }     # число строк журнала сервера

# ---- спека --------------------------------------------------------------------------------------
mkdir -p "$tmp/st"
for l in dot doh dohd udp; do printf '%s.svc.test\n' "$l" > "$tmp/$l.lst"; done
printf 'plain.svc.test\n' > "$tmp/plain.lst"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  ldot:  { domains_file: $tmp/dot.lst }
  ldoh:  { domains_file: $tmp/doh.lst }
  ldohd: { domains_file: $tmp/dohd.lst }
  ludp:  { domains_file: $tmp/udp.lst }
outputs:
  direct: { kind: direct }
  vpn: { kind: interface, device: tun0 }
dns:
  cache: 64
  bootstrap: [192.0.2.53]
  upstreams:
    dot:  { url: tls://dns.test, out: vpn }
    doh:  { url: https://dns.test/dns-query, out: vpn }
    dohd: { url: https://dns.test:8443/dns-query }
    udp:  { url: udp://192.0.2.53, out: vpn }
rules:
  - { name: rdot,  to: [ldot],  out: vpn, dns: dot }
  - { name: rdoh,  to: [ldoh],  out: vpn, dns: doh }
  - { name: rdohd, to: [ldohd], out: vpn, dns: dohd }
  - { name: rudp,  to: [ludp],  out: vpn, dns: udp }
EOF
"$BIN" apply --spec "$tmp/spec.yaml" $S >"$tmp/apply.out" 2>&1 || { echo "FAIL apply:"; cat "$tmp/apply.out"; exit 1; }
"$BIN" daemon --supervise --socket "$tmp/s.sock" --spec "$tmp/spec.yaml" $S \
    --dnsd-flag --listen-port --dnsd-flag "$LPORT" --dnsd-flag --upstream-port --dnsd-flag 15353 \
    --dnsd-flag --ca-file --dnsd-flag "$c/ca.pem" 2>"$tmp/d.err" &
echo $! > "$tmp/d.pid"
n=0; while [ ! -S "$tmp/s.sock" ] && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
n=0; while ! grep -q 'слушает\|listening on' "$tmp/d.err" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
sleep 0.5
TUNTX() { cat /sys/class/net/tun0/statistics/tx_packets; }
WANTX() { cat /sys/class/net/wan0/statistics/tx_packets; }
fake() { case "$1" in 198.18.*) echo fake ;; *) echo "$1" ;; esac; }

# ---- 1-2. DoT и DoH через выход, bootstrap ------------------------------------------------------
t0=$(TUNTX); w0=$(WANTX)
check "DoT: клиенту поддельный адрес" fake "$(fake "$(ask a.dot.svc.test)")"
check "DoT: вопрос пришёл по dot с адреса туннеля" "1" "$(grep -c '^dot 10.0.2.1 a.dot.svc.test' "$LOG")"
check "DoH: клиенту поддельный адрес" fake "$(fake "$(ask a.doh.svc.test)")"
check "DoH: вопрос пришёл по doh с адреса туннеля" "1" "$(grep -c '^doh 10.0.2.1 a.doh.svc.test' "$LOG")"
check "bootstrap: имя сервера спрошено обычным DNS через выход" "1" \
    "$([ "$(grep -c '^udp 10.0.2.1 dns.test' "$LOG")" -ge 1 ] && echo 1 || echo 0)"
check "ни одного вопроса с адреса WAN к DoT/DoH через выход" "0" "$(grep -c '^\(dot\|doh\) 10.0.1.1 ' "$LOG")"
check "через tun0 прошли пакеты" "1" "$([ "$(TUNTX)" -gt "$t0" ] && echo 1 || echo 0)"
check "UDP через выход: с адреса туннеля" "fake" "$(fake "$(ask a.udp.svc.test)")"
check "  вопрос пришёл по udp с адреса туннеля" "1" "$(grep -c '^udp 10.0.2.1 a.udp.svc.test' "$LOG")"

# ---- 3. без выхода ------------------------------------------------------------------------------
check "DoH без выхода: ответ" fake "$(fake "$(ask a.dohd.svc.test)")"
check "  вопрос пришёл с адреса WAN" "1" "$(grep -c '^doh 10.0.1.1 a.dohd.svc.test' "$LOG")"

# ---- 4. кэш и строгий fake-IP -------------------------------------------------------------------
n0=$(cnt 'b.dot.svc.test')
f1="$(ask b.dot.svc.test)"; sleep 0.3
f2="$(ask b.dot.svc.test)"
check "кэш: клиенту поддельный адрес оба раза, один и тот же" "$f1" "$f2"
sleep 61   # быстрый путь fake-IP ходит наверх не чаще раза в минуту; следующий вопрос идёт через кэш
f3="$(ask b.dot.svc.test)"; sleep 0.3
check "кэш: до сервера дошёл один вопрос из трёх" "1" "$(($(cnt 'b.dot.svc.test') - n0))"
check "fake-IP: элемент карты ядра стоит" "203.0.113.7" \
    "$(nft get element inet steer fakeip "{ $f1 }" 2>/dev/null | sed -n 's/.*elements = { [0-9.]* : \([0-9.]*\).*/\1/p')"

# ---- 5. выход лёг -------------------------------------------------------------------------------
ip link set tun0 down
sleep 0.5
wl=$(wc -l < "$LOG")
r="$(ask c.dot.svc.test)"
r2="$(ask c.doh.svc.test)"
r3="$(ask c.udp.svc.test)"
sleep 0.3
check "выход лёг: клиенту не адрес (DoT, DoH, UDP)" "3" \
    "$(for x in "$r" "$r2" "$r3"; do [ "$x" = timeout ] || [ "$x" = rcode2 ] && echo 1; done | wc -l | tr -d ' ')"
check "выход лёг: с адреса WAN за это время не пришло ни одного вопроса" "0" \
    "$(tail -n +$((wl + 1)) "$LOG" | grep -c ' 10.0.1.1 ')"
check "в наборе правил есть страж выхода vpn (postrouting_guard)" "1" \
    "$(nft list chain inet steer postrouting_guard 2>/dev/null | grep -c 'steer-guard:vpn')"
ip link set tun0 up; ip addr add 10.0.2.1/24 dev tun0 2>/dev/null
"$BIN" apply --spec "$tmp/spec.yaml" $S >/dev/null 2>&1      # возвращает маршрут таблицы выхода
sleep 5
check "выход вернулся: DoT снова работает" fake "$(fake "$(ask d.dot.svc.test)")"

# ---- 6. сервер перезапущен: соединения мертвы, следующий вопрос идёт на новом; DoH кусками ---------------
kill "$(cat "$tmp/srv.pid")" 2>/dev/null
sleep 0.5
srv_start --chunked
check "сервер перезапущен: DoT ответил на новом соединении" fake "$(fake "$(ask e.dot.svc.test)")"
check "  DoH (ответ кусками) на новом соединении" fake "$(fake "$(ask e.doh.svc.test)")"
check "  DoH ещё раз по тому же соединению" fake "$(fake "$(ask f.doh.svc.test)")"

# ---- 9. dns-log -----------------------------------------------------------------------------------
"$BIN" dns-log $S > "$tmp/dnslog.json" 2>/dev/null
dl() { python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
u = {x["name"]: x for x in d["upstreams"]}
k = sys.argv[2]
if k == "state": print(u["dot"]["state"], u["doh"]["state"], u["dot"]["proto"], u["dot"]["via"], u["dohd"]["via"])
if k == "sent": print(int(u["dot"]["sent"] > 0 and u["doh"]["ok"] > 0))
if k == "cache": print(int(d["cache"]["hits"] >= 1), d["cache"]["max"])
' "$tmp/dnslog.json" "$1"; }
check "dns-log: состояние и путь апстримов" "ready ready dot vpn None" "$(dl state)"
check "dns-log: счётчики" "1" "$(dl sent)"
check "dns-log: кэш" "1 64" "$(dl cache)"

# ---- 7. вне правил ------------------------------------------------------------------------------
sl=$(wc -l < "$STUBLOG")
check "вне правил: ответ заглушки" "198.51.100.77" "$(ask other.example.org)"
check "  вопрос пришёл на заглушку, не на апстрим" "1" "$(($(wc -l < "$STUBLOG") - sl))"

# ---- 8. bootstrap молчит / адреса в спеке -------------------------------------------------------
cat > "$tmp/spec2.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  lb: { domains_file: $tmp/dot.lst }
  li: { domains_file: $tmp/doh.lst }
outputs:
  direct: { kind: direct }
rules:
  - { name: rb, to: [lb], out: direct, dns: { url: "tls://dns.test", bootstrap: [192.0.2.99] } }
  - { name: ri, to: [li], out: direct, dns: { url: "https://dns.test/dns-query", ips: [192.0.2.53] } }
EOF
"$BIN" dnsd --spec "$tmp/spec2.yaml" --state-dir "$tmp/st2" --listen-port 15311 --upstream-port 15353 \
    --ca-file "$c/ca.pem" 2>"$tmp/d2.err" &
echo $! > "$tmp/d2.pid"
sleep 1
LPORT=15311
t0=$(date +%s)
r="$(ask z.dot.svc.test)"
t1=$(date +%s)
check "bootstrap молчит: SERVFAIL или тишина, но не зависание" "1" \
    "$([ "$r" = rcode2 ] || [ "$r" = timeout ] && [ $((t1 - t0)) -le 7 ] && echo 1 || echo 0)"
check "ips в спеке: имя не разрешается, ответ есть" fake "$(fake "$(ask z.doh.svc.test)")"
LPORT=15310

# ---- замер: добавка транспорта к ответу клиенту -----------------------------------------------
# Отдельный резолвер на трёх прямых апстримах (UDP, DoT, DoH), кэша нет, имена каждый раз новые:
# «холодный» — первый вопрос (bootstrap, connect, рукопожатие), «тёплый» — медиана 30 следующих.
if [ "${DNSUP_BENCH:-0}" = 1 ]; then
    for k in u t h; do printf '%s.bench.test\n' "$k" > "$tmp/b$k.lst"; done
    cat > "$tmp/spec3.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
  bu: { domains_file: $tmp/bu.lst }
  bt: { domains_file: $tmp/bt.lst }
  bh: { domains_file: $tmp/bh.lst }
outputs:
  direct: { kind: direct }
rules:
  - { name: ru, to: [bu], out: direct, resolve: realip, dns: { url: "udp://192.0.2.53" } }
  - { name: rt, to: [bt], out: direct, resolve: realip, dns: { url: "tls://dns.test", bootstrap: [192.0.2.53] } }
  - { name: rh, to: [bh], out: direct, resolve: realip, dns: { url: "https://dns.test/dns-query", bootstrap: [192.0.2.53] } }
EOF
    "$BIN" dnsd --spec "$tmp/spec3.yaml" --state-dir "$tmp/st3" --listen-port 15312 --upstream-port 15353 \
        --ca-file "$c/ca.pem" 2>"$tmp/d3.err" &
    echo $! > "$tmp/d3.pid"
    sleep 1
    for k in u t h; do
        cold="$(python3 "$tmp/ask.py" 15312 c0.$k.bench.test 1 ms)"
        ws="$(for i in $(seq 1 30); do python3 "$tmp/ask.py" 15312 w$i.$k.bench.test 1 ms; done | sort -n | sed -n 15p)"
        echo "замер $k: холодный ${cold} мс, тёплый (медиана из 30) ${ws} мс"
    done
fi

echo "dnsup: пройдено $pass, провалено $fail"
[ "$fail" = 0 ]
