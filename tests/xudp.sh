#!/bin/sh
# UDP по vision-записи против НАСТОЯЩИХ серверов: Xray-core (XRAY=/путь/к/xray) и sing-box (SINGBOX=/путь/к/sing-box).
#
# Ради чего. У узла с flow=xtls-rprx-vision UDP идёт не командой 2, а Mux.Cool с рамками XUDP поверх потока
# Vision (src/proto/vless/vldial.c, блок XUDP): команду 2 к такой записи не принимает ни Xray-core, ни sing-box.
# Формат рамок сверялся по исходникам обоих серверов, но исходник — не провод: заголовок запроса Mux без порта
# и адреса выяснился только прогоном (sing-box читал лишние байты как начало потока и рвал соединение).
# Этот стенд гоняет провод: клиент — дайлер VLESS (tests/xudpprobe.c), сервер — настоящий, за ним эхо UDP.
#
# Сервер — TLS с самоподписанным листом (openssl), клиент закрепляет его отпечаток (`pcs`): заодно это ещё
# одна проверка закрепления против настоящего сервера. Узел по имени localhost, а не по 127.0.0.1: разбор
# подписки отбрасывает узлы «отвечать некому» (127.0.0.0/8), и стенд обязан идти тем же разбором.
#
# Чего нет — пропуск ГРОМКИЙ (echo + выход 0), как у venc.sh: молчаливый пропуск читается как «прошло».
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/xudpprobe"
[ -x "$PROBE" ] || { echo "xudp: нет $PROBE (собирает make interop)"; exit 2; }
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
	echo "xudp: ПРОПУСК — нужны python3 и openssl. Это не падение."; exit 0; }
HAVE_X=0; HAVE_S=0
[ -n "${XRAY:-}" ] && [ -x "$XRAY" ] && HAVE_X=1
[ -n "${SINGBOX:-}" ] && [ -x "$SINGBOX" ] && HAVE_S=1
if [ $HAVE_X = 0 ] && [ $HAVE_S = 0 ]; then
	echo "xudp: ПРОПУСК — нет серверов (XRAY=/путь/к/xray и/или SINGBOX=/путь/к/sing-box). Это не падение."
	exit 0
fi

W=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT INT TERM

BASE=$((21000 + $$ % 20000))
ECHO=$((BASE + 1)); XP_VIS=$((BASE + 2)); XP_PLAIN=$((BASE + 3)); SB_VIS=$((BASE + 4))
U=00000000-0000-0000-0000-000000000001

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/k.pem" -out "$W/c.pem" \
	-subj "/CN=test.example" -days 2 -addext "subjectAltName=DNS:test.example" 2>/dev/null
PCS=$(openssl x509 -in "$W/c.pem" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')

python3 - "$ECHO" <<'PY' &
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
while True:
    d, a = s.recvfrom(65535)
    s.sendto(b"echo:" + d, a)
PY
PIDS="$PIDS $!"

if [ $HAVE_X = 1 ]; then
	# finalRules allow: freedom по умолчанию не соединяется с loopback и частными адресами.
	cat > "$W/x.json" <<EOF
{"log": {"loglevel": "warning"},
 "inbounds": [
  {"listen": "127.0.0.1", "port": $XP_VIS, "protocol": "vless",
   "settings": {"clients": [{"id": "$U", "flow": "xtls-rprx-vision"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $XP_PLAIN, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}}],
 "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
EOF
	"$XRAY" run -c "$W/x.json" >"$W/x.log" 2>&1 &
	PIDS="$PIDS $!"
	echo "xudp: сервер — $("$XRAY" version 2>/dev/null | head -1)"
fi
if [ $HAVE_S = 1 ]; then
	cat > "$W/s.json" <<EOF
{"log": {"level": "warn"},
 "inbounds": [{"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": $SB_VIS,
   "users": [{"uuid": "$U", "flow": "xtls-rprx-vision"}],
   "tls": {"enabled": true, "server_name": "test.example", "certificate_path": "$W/c.pem", "key_path": "$W/k.pem"}}],
 "outbounds": [{"type": "direct", "tag": "d"}]}
EOF
	"$SINGBOX" run -c "$W/s.json" >"$W/s.log" 2>&1 &
	PIDS="$PIDS $!"
	echo "xudp: сервер — $("$SINGBOX" version 2>/dev/null | head -1)"
fi
sleep 2

FAILS=0
run() { # название порт flow
	name=$1; port=$2; flow=$3
	url="vless://$U@localhost:$port?type=tcp&security=tls&sni=test.example&pcs=$PCS${flow:+&flow=$flow}"
	for mode in single burst; do
		if [ $mode = burst ]; then export BURST=1; else unset BURST || true; fi
		if out=$(timeout 40 "$PROBE" "$url" 127.0.0.1 "$ECHO" 5 2>&1); then
			echo "  ok   $name ($mode)"
		else
			echo "  FAIL $name ($mode)"; echo "$out" | sed 's/^/       /'; FAILS=$((FAILS + 1))
		fi
	done
	unset BURST || true
}
[ $HAVE_X = 1 ] && run "Xray, vision: Mux и XUDP" $XP_VIS xtls-rprx-vision
[ $HAVE_X = 1 ] && run "Xray, без flow: команда 2" $XP_PLAIN ""
[ $HAVE_S = 1 ] && run "sing-box, vision: Mux и XUDP" $SB_VIS xtls-rprx-vision

[ $FAILS = 0 ] && echo "xudp: все проверки прошли" || { echo "xudp: провалов: $FAILS"; exit 1; }
