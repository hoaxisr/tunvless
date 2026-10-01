#!/bin/sh
# Опция EDNS «не пересылать» резолвера (DNSD_OPT_NOFORWARD, src/dnsd/dnsd_int.h).
#
# Её ставит steer-box-connector, когда спрашивает у dnsd имя, которому правила DNS sing-box дают
# fake-IP. Имя вне доменных каналов обязано получить REFUSED сразу и НЕ уйти наверх: путь наверх на
# роутере — dnsmasq, у podkop и forkop он смотрит на 127.0.0.42, то есть обратно в коннектор, и
# вопрос ходил бы по кругу. Без опции — прежний путь наверх; имя в канале с опцией — обычный ответ.
#
# Стенд: dnsd на петле с одним каналом (x.test), апстрим — сервер на python, который считает
# вопросы и отвечает адресом. Root не нужен (наборы nft резолвер без прав просто не наполняет).
set -u
BUILD=${BUILD:-build}
BIN="${STEER_BIN:-$BUILD/steerd}"
command -v python3 >/dev/null 2>&1 || { echo "noforward: нет python3 — пропускаю"; exit 0; }
[ -x "$BIN" ] || { echo "noforward: нет $BIN"; exit 1; }
tmp=$(mktemp -d)
trap 'kill $(cat "$tmp"/*.pid 2>/dev/null) 2>/dev/null; rm -rf "$tmp"' EXIT
UP=$((20000 + $$ % 10000)); LP=$((UP + 1))
printf 'x.test\n' > "$tmp/d.lst"
cat > "$tmp/spec.json" <<EOF
{"version":2,"lists":{"l":{"domains_file":["$tmp/d.lst"]}},"outputs":{"direct":{"kind":"direct"}},
 "rules":[{"name":"r","to":["l"],"out":"direct","resolve":"realip"}]}
EOF
cat > "$tmp/up.py" <<'EOF'
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", int(sys.argv[1])))
n = 0
while True:
    q, a = s.recvfrom(4096)
    n += 1
    open(sys.argv[2], "w").write(str(n))
    # Ответ: вопрос как есть, одна запись A 192.0.2.7.
    qd_end = 12
    while q[qd_end] != 0: qd_end += q[qd_end] + 1
    qd_end += 5
    r = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:qd_end]
    r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x07"
    s.sendto(r, a)
EOF
python3 "$tmp/up.py" "$UP" "$tmp/count" & echo $! > "$tmp/up.pid"
"$BIN" dnsd --spec "$tmp/spec.json" --state-dir "$tmp" --listen-port "$LP" --upstream-port "$UP" \
    >"$tmp/d.out" 2>&1 & echo $! > "$tmp/d.pid"
cat > "$tmp/ask.py" <<'EOF'
import socket, struct, sys, random
name, port, opt = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "1"
q = struct.pack(">HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 1 if opt else 0)
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
if opt: q += b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x04" + struct.pack(">HH", 65001, 0)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ("127.0.0.1", port))
try:
    r = s.recv(4096); print("rcode=%d an=%d" % (r[3] & 15, struct.unpack(">H", r[6:8])[0]))
except socket.timeout:
    print("timeout")
EOF
n=0; while ! grep -q "listening" "$tmp/d.out" 2>/dev/null && [ $n -lt 50 ]; do sleep 0.1; n=$((n + 1)); done
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
count() { cat "$tmp/count" 2>/dev/null || echo 0; }
check "вне каналов с опцией — REFUSED" "rcode=5 an=0" "$(python3 "$tmp/ask.py" other.test "$LP" 1)"
check "вне каналов с опцией — наверх не ушло" "0" "$(count)"
check "вне каналов без опции — ответ сверху" "rcode=0 an=1" "$(python3 "$tmp/ask.py" other.test "$LP" 0)"
check "вне каналов без опции — ушло наверх" "1" "$(count)"
check "в канале с опцией — ответ" "rcode=0 an=1" "$(python3 "$tmp/ask.py" x.test "$LP" 1)"
echo "noforward: $pass прошло, $fail упало"
[ "$fail" = 0 ]
