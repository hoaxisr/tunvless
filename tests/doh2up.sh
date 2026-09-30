#!/bin/sh
# DoH по HTTP/2 в резолвере: клиент dnsd против сервера, который ведёт себя по пути запроса
# (tests/doh2-server.py): отказ кодом 505 (цифрами и кодом Хаффмана), сброс потока, GOAWAY посреди
# работы, малый предел потоков, заголовки двумя кадрами, молчание. Работа с настоящим сервером
# (dnsproxy на Go) — в tests/doqup.sh; здесь то, чего независимая реализация не сделает нарочно.
#
#     sh tests/doqup.sh   (один раз: собирает $BUILD/doqup/steer — движок с TLS и QUIC)
#     sh tests/doh2up.sh
#
# Не входит в `make test`: нужны root и unshare (свой сетевой мир на петле, ничего на хосте не трогается),
# openssl, python3. Чего-то нет — пропуск вслух, код 0. Бинарник — DOH2UP_BIN.
#
# Что проверяется.
#  1. Обычные вопросы идут по h2 (dns-log: http=h2), сто одновременных — потоками ОДНОГО соединения.
#  2. Ответ 505 — в dns-log «HTTP 505 от сервера» (а не «нет ответа за 4000 мс»), цифрами и кодом Хаффмана.
#  3. RST_STREAM(REFUSED_STREAM): один повтор, дальше отказ с названием кода.
#  4. GOAWAY: вопросы, не принятые сервером (поток за last_stream_id), уходят на новое соединение и
#     получают ответ; соединений становится больше одного.
#  5. SETTINGS_MAX_CONCURRENT_STREAMS = 2: одновременно у сервера не больше двух потоков, все вопросы
#     с ответом.
#  6. Заголовки ответа двумя кадрами (CONTINUATION) и тело двумя DATA.
#  7. Молчащий сервер: отказ за срок, а не зависание.
#  8. Служебные кадры: клиент ответил на PING и подтвердил SETTINGS.
set -u
BUILD=${BUILD:-build}
skip() { echo "doh2up: $1 — пропускаю"; exit 0; }
for t in ip unshare openssl python3; do command -v $t >/dev/null 2>&1 || skip "нет $t"; done
BIN="${DOH2UP_BIN:-$BUILD/doqup/steer}"
[ -x "$BIN" ] || skip "нет $BIN (соберите: sh tests/doqup.sh)"
if [ "${DOH2UP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -nm true 2>/dev/null || skip "unshare -nm недоступен"
    DOH2UP_INNER=1 DOH2UP_BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" \
        DOH2UP_SRV="$(cd tests && pwd)/doh2-server.py" exec unshare -nm sh "$0" "$@"
fi
BIN="$DOH2UP_BIN"
ip link set lo up
tmp="$(mktemp -d)"
cleanup() {
    kill $(cat "$tmp"/*.pid 2>/dev/null) 2>/dev/null
    if [ -n "${KEEP:-}" ]; then echo "doh2up: журналы в $tmp"; else rm -rf "$tmp"; fi
}
trap cleanup EXIT
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); printf 'ok   %s\n' "$1"; else
        fail=$((fail + 1)); printf 'FAIL %s\n  ожидалось: %s\n  получено:  %s\n' "$1" "$2" "$3"
    fi
}

c="$tmp/pki"; mkdir -p "$c"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/ca.key" \
    -out "$c/ca.pem" -days 3 -subj "/CN=doh2up-test-ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$c/srv.key" \
    -out "$c/srv.csr" -subj "/CN=dns.test" >/dev/null 2>&1
printf 'subjectAltName=DNS:dns.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$c/srv.ext"
openssl x509 -req -in "$c/srv.csr" -CA "$c/ca.pem" -CAkey "$c/ca.key" -CAcreateserial -out "$c/srv.pem" \
    -days 3 -extfile "$c/srv.ext" >/dev/null 2>&1

SLOG="$tmp/srv.log"; S2LOG="$tmp/srv2.log"; : > "$SLOG"; : > "$S2LOG"
python3 "$DOH2UP_SRV" 127.0.0.1 8443 "$c/srv.pem" "$c/srv.key" "$SLOG" > "$tmp/srv.out" 2>&1 & echo $! > "$tmp/srv.pid"
python3 "$DOH2UP_SRV" 127.0.0.1 8445 "$c/srv.pem" "$c/srv.key" "$tmp/srv1.log" --h1 > "$tmp/srv1.out" 2>&1 & echo $! > "$tmp/srv1.pid"
python3 "$DOH2UP_SRV" 127.0.0.1 8444 "$c/srv.pem" "$c/srv.key" "$S2LOG" --max 2 > "$tmp/srv2.out" 2>&1 & echo $! > "$tmp/srv2.pid"

# Заглушка на петле для имён вне правил (движок требует, чтобы было к кому идти).
cat > "$tmp/stub.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(2048)
    e = 12
    while d[e]: e += 1 + d[e]
    e += 5
    s.sendto(d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x01\x00\x00\x00\x00" + d[12:e] +
             b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([198, 51, 100, 77]), a)
PY
python3 "$tmp/stub.py" 15353 & echo $! > "$tmp/stub.pid"

cat > "$tmp/ask.py" <<'PY'
import socket, struct, sys
port, name = int(sys.argv[1]), sys.argv[2]
q = struct.pack('>HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)
for l in name.split('.'): q += bytes([len(l)]) + l.encode()
q += b'\x00' + struct.pack('>HH', 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(9)
s.sendto(q, ('127.0.0.1', port))
try:
    d, _ = s.recvfrom(2048)
except socket.timeout:
    print("timeout"); sys.exit()
rc = d[3] & 0x0f
if rc: print("rcode%d" % rc)
elif struct.unpack('>H', d[6:8])[0] == 0: print("empty")
else: print(".".join(str(b) for b in d[-4:]))
PY
LPORT=15320
ask() { python3 "$tmp/ask.py" "$LPORT" "$@"; }
good() { case "$1" in timeout|rcode*|empty) echo bad ;; *) echo ok ;; esac; }

mkdir -p "$tmp/st"
cat > "$tmp/spec.yaml" <<EOF
version: 2
lan: { devices: [lo] }
lists:
EOF
for n in ok h505 h505h rst ga sp m2 sil h1 h1e; do
    printf '%s.svc.test\n' "$n" > "$tmp/$n.lst"
    printf '  l%s: { domains_file: %s/%s.lst }\n' "$n" "$tmp" "$n" >> "$tmp/spec.yaml"
done
cat >> "$tmp/spec.yaml" <<EOF
outputs:
  direct: { kind: direct }
dns:
  cache: 0
  upstreams:
    ok:    { url: "https://dns.test:8443/ok", ips: [127.0.0.1] }
    h505:  { url: "https://dns.test:8443/st505", ips: [127.0.0.1] }
    h505h: { url: "https://dns.test:8443/st505h", ips: [127.0.0.1] }
    rst:   { url: "https://dns.test:8443/rst", ips: [127.0.0.1] }
    ga:    { url: "https://dns.test:8443/goaway", ips: [127.0.0.1] }
    sp:    { url: "https://dns.test:8443/split", ips: [127.0.0.1] }
    m2:    { url: "https://dns.test:8444/max2", ips: [127.0.0.1] }
    sil:   { url: "https://dns.test:8443/silent", ips: [127.0.0.1] }
    h1:    { url: "https://dns.test:8445/ok", ips: [127.0.0.1] }
    h1e:   { url: "https://dns.test:8445/st505", ips: [127.0.0.1] }
rules:
EOF
for n in ok h505 h505h rst ga sp m2 sil h1 h1e; do
    printf '  - { name: r%s, to: [l%s], out: direct, dns: %s }\n' "$n" "$n" "$n" >> "$tmp/spec.yaml"
done
# Правила ядра нужны быстрому пути fake-IP: без них клиенту отвечено SERVFAIL, и ответ апстрима не виден.
"$BIN" apply --spec "$tmp/spec.yaml" --state-dir "$tmp/st" >"$tmp/apply.out" 2>&1 || { echo "FAIL apply:"; cat "$tmp/apply.out"; exit 1; }
"$BIN" dnsd --spec "$tmp/spec.yaml" --state-dir "$tmp/st" --listen-port "$LPORT" --upstream-port 15353 \
    --ca-file "$c/ca.pem" 2>"$tmp/d.err" & echo $! > "$tmp/d.pid"
n=0; while ! grep -q 'слушает\|listening on' "$tmp/d.err" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
sleep 0.5
dnslog() { "$BIN" dns-log --state-dir "$tmp/st" 2>/dev/null > "$tmp/dnslog.json"; python3 -c '
import json, sys
d = json.load(open(sys.argv[1]))
u = {x["name"]: x for x in d["upstreams"]}[sys.argv[2]]
print(u.get(sys.argv[3]))
' "$tmp/dnslog.json" "$1" "$2"; }

# ---- 1. обычные вопросы и мультиплекс ---------------------------------------------------------------
check "h2: вопрос с ответом" ok "$(good "$(ask a.ok.svc.test)")"
check "  dns-log: сервер выбрал h2" h2 "$(dnslog ok http)"
: > "$tmp/par.res"
for i in $(seq 1 100); do ( good "$(ask "p$i.ok.svc.test")" >> "$tmp/par.res" ) & done
n=0; while [ "$(wc -l < "$tmp/par.res")" -lt 100 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
check "  сто одновременных: все с ответом" 100 "$(grep -c '^ok$' "$tmp/par.res")"
check "  на сервере одно соединение" 1 "$(grep -c '^conn ' "$SLOG")"
check "  отказов нет, и на все вопросы ответил сервер, а не быстрый путь" 1 \
    "$([ "$(dnslog ok failed)" = 0 ] && [ "$(dnslog ok ok)" -ge 101 ] && echo 1 || echo 0)"
check "  клиент подтвердил SETTINGS сервера" 1 "$([ "$(grep -c '^settings-ack' "$SLOG")" -ge 1 ] && echo 1 || echo 0)"
check "  клиент ответил на PING" 1 "$([ "$(grep -c '^ping-ack' "$SLOG")" -ge 1 ] && echo 1 || echo 0)"

# ---- 2. код ответа сервера в dns-log -----------------------------------------------------------------
ask a.h505.svc.test >/dev/null; sleep 0.5
check "505 цифрами: код назван в dns-log" "HTTP 505 от сервера" "$(dnslog h505 error)"
ask a.h505h.svc.test >/dev/null; sleep 0.5
check "505 кодом Хаффмана: код назван в dns-log" "HTTP 505 от сервера" "$(dnslog h505h error)"

# ---- 3. сброс потока -----------------------------------------------------------------------------------
ask a.rst.svc.test >/dev/null; sleep 0.5
check "RST_STREAM: код назван в dns-log" "HTTP/2: сервер сбросил поток (REFUSED_STREAM)" "$(dnslog rst error)"
check "  вопрос пришёл на сервер дважды (один повтор)" 2 "$(grep -c '^req /rst ' "$SLOG")"

# ---- 4. GOAWAY -------------------------------------------------------------------------------------------
c0=$(grep -c '^conn ' "$SLOG")
: > "$tmp/ga.res"
for i in $(seq 1 6); do ( good "$(ask "g$i.ga.svc.test")" >> "$tmp/ga.res" ) & done
n=0; while [ "$(wc -l < "$tmp/ga.res")" -lt 6 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
check "GOAWAY: все шесть вопросов с ответом" 6 "$(grep -c '^ok$' "$tmp/ga.res")"
check "  соединений стало больше одного" 1 "$([ $(($(grep -c '^conn ' "$SLOG") - c0)) -ge 2 ] && echo 1 || echo 0)"
check "  отказов нет" 0 "$(dnslog ga failed)"

# ---- 5. предел потоков -------------------------------------------------------------------------------------
# Первый вопрос прогревает соединение: SETTINGS сервера (предел 2) приходит после него, а до этого клиент
# исходит из того, что RFC 9113 (6.5.2) советует поддерживать серверам, — из ста потоков.
good "$(ask w.m2.svc.test)" >/dev/null
: > "$tmp/m2.res"
for i in $(seq 1 10); do ( good "$(ask "m$i.m2.svc.test")" >> "$tmp/m2.res" ) & done
n=0; while [ "$(wc -l < "$tmp/m2.res")" -lt 10 ] && [ $n -lt 150 ]; do sleep 0.1; n=$((n + 1)); done
check "предел потоков 2: все десять вопросов с ответом" 10 "$(grep -c '^ok$' "$tmp/m2.res")"
check "  у сервера разом не больше двух потоков" 2 "$(sed -n 's/^maxconc //p' "$S2LOG" | sort -n | tail -1)"
check "  соединение одно" 1 "$(grep -c '^conn ' "$S2LOG")"

# ---- 6. заголовки и тело кусками -----------------------------------------------------------------------------
check "HEADERS+CONTINUATION и два DATA: ответ" ok "$(good "$(ask a.sp.svc.test)")"

# ---- 7. молчащий сервер ------------------------------------------------------------------------------------------
t0=$(date +%s)
r="$(ask a.sil.svc.test)"
t1=$(date +%s)
check "молчащий сервер: отказ за срок, не зависание" 1 "$([ "$(good "$r")" = bad ] && [ $((t1 - t0)) -le 8 ] && echo 1 || echo 0)"
check "  в dns-log причина (нет ответа)" "нет ответа за 4000 мс" "$(dnslog sil error)"

# ---- 9. сервер, знающий один HTTP/1.1 -------------------------------------------------------------------------
: > "$tmp/h1.res"
good "$(ask w.h1.svc.test)" >/dev/null
for i in $(seq 1 10); do ( good "$(ask "n$i.h1.svc.test")" >> "$tmp/h1.res" ) & done
n=0; while [ "$(wc -l < "$tmp/h1.res")" -lt 10 ] && [ $n -lt 100 ]; do sleep 0.1; n=$((n + 1)); done
check "HTTP/1.1: десять вопросов с ответом (сервер выбрал http/1.1)" 10 "$(grep -c '^ok$' "$tmp/h1.res")"
check "  dns-log: http/1.1" "http/1.1" "$(dnslog h1 http)"
ask a.h1e.svc.test >/dev/null; sleep 0.5
check "  505 на HTTP/1.1: код назван в dns-log, а не «нет ответа»" "HTTP 505 от сервера" "$(dnslog h1e error)"

printf '\nвыполнено проверок: %d, провалено: %d\n' "$((pass + fail))" "$fail"
[ "$fail" = 0 ]
