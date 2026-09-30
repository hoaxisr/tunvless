#!/bin/sh
# ECH (Encrypted Client Hello) против НАСТОЯЩЕГО сервера: Xray-core (XRAY=/путь/к/xray), на crypto/tls из Go.
#
# Что проверяется: клиент (vless_probe из tests/vencprobe.c — то же рукопожатие, что в работе) собирает внешний
# Hello с именем из ECHConfig, а настоящее имя прячет в HPKE-нагрузке; сервер её расшифровывает, подтверждает
# принятие в ServerHello.random, и рукопожатие идёт по внутреннему Hello (транскрипт переключается на него).
# Без этого совпадения ключи не сходятся, поэтому успешное рукопожатие — само доказательство, что расписание
# HPKE, AAD, набивка и подтверждение принятия соответствуют эталону.
#
#   принят:   список Xray (набор HKDF-SHA256 + AES-128-GCM) и свой список с единственным ChaCha20-Poly1305;
#   отказ:    сервер без ECH, чужой ключ — оба дают «сервер не принял ECH» (TLS13_EECH), а не молчаливое
#             рукопожатие с открытым именем; испорченный список и значение «домен+https://…» (запрос из DNS) —
#             узел не годен с названной причиной.
# Успех рукопожатия отличается от отказа по тексту ответа vencprobe; проба VLESS после него зависит от сети у
# сервера (запрос к 1.1.1.1:80) и при её отсутствии заканчивается иначе — это не отказ ECH и не провал стенда.
#
# Чего нет — громкий пропуск (echo + выход 0), как у xudp.sh и venc.sh.
set -eu
cd "$(dirname "$0")/.."
BUILD=${BUILD:-build}
PROBE="$BUILD/vencprobe"
[ -x "$PROBE" ] || { echo "ech: нет $PROBE (собирает tests/ext-test.sh)"; exit 2; }
command -v python3 >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 || {
	echo "ech: ПРОПУСК — нужны python3 и openssl. Это не падение."; exit 0; }
[ -n "${XRAY:-}" ] && [ -x "$XRAY" ] || {
	echo "ech: ПРОПУСК — нет Xray-core (XRAY=/путь/к/xray). Это не падение."; exit 0; }

W=$(mktemp -d)
PIDS=""
cleanup() { for p in $PIDS; do kill "$p" 2>/dev/null || true; done; rm -rf "$W"; }
trap cleanup EXIT INT TERM

BASE=$((23000 + $$ % 20000))
P_ECH=$((BASE + 1)); P_NOECH=$((BASE + 2)); P_CHACHA=$((BASE + 3))
U=00000000-0000-0000-0000-000000000001

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$W/k.pem" -out "$W/c.pem" \
	-subj "/CN=test.example" -days 2 -addext "subjectAltName=DNS:test.example" 2>/dev/null
PCS=$(openssl x509 -in "$W/c.pem" -outform DER | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')

# Список и ключи сервера от самого Xray: «ECH config list:» и «ECH server keys:», значение — строкой ниже.
"$XRAY" tls ech --serverName public.example > "$W/xech.txt" 2>&1
LIST=$(awk '/ECH config list/{getline; print; exit}' "$W/xech.txt")
KEYS=$(awk '/ECH server keys/{getline; print; exit}' "$W/xech.txt")
[ -n "$LIST" ] && [ -n "$KEYS" ] || { echo "ech: xray tls ech не выдал ключи:"; cat "$W/xech.txt"; exit 1; }

# Свой список с единственным набором ChaCha20-Poly1305 (Xray выдаёт все девять): закрытый ключ — openssl,
# запись ключей сервера — [u16 длина ключа][ключ][u16 длина ECHConfig][ECHConfig].
python3 - "$W" > "$W/chacha.txt" <<'PY'
import base64, struct, subprocess, sys
pem = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519"])
priv = subprocess.check_output(["openssl", "pkey", "-outform", "DER"], input=pem)[-32:]
pub = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem)[-32:]
name = b"chacha.example"
body = bytes([9]) + struct.pack(">HH", 0x20, 32) + pub + struct.pack(">H", 4) + struct.pack(">HH", 1, 3)
body += bytes([64, len(name)]) + name + struct.pack(">H", 0)
cfg = struct.pack(">HH", 0xfe0d, len(body)) + body
print(base64.b64encode(struct.pack(">H", len(cfg)) + cfg).decode())
print(base64.b64encode(struct.pack(">H", 32) + priv + struct.pack(">H", len(cfg)) + cfg).decode())
PY
CLIST=$(sed -n 1p "$W/chacha.txt"); CKEYS=$(sed -n 2p "$W/chacha.txt")

cat > "$W/x.json" <<EOF
{"log": {"loglevel": "warning"},
 "inbounds": [
  {"listen": "127.0.0.1", "port": $P_ECH, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"echServerKeys": "$KEYS",
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $P_NOECH, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}},
  {"listen": "127.0.0.1", "port": $P_CHACHA, "protocol": "vless",
   "settings": {"clients": [{"id": "$U"}], "decryption": "none"},
   "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"echServerKeys": "$CKEYS",
     "certificates": [{"certificateFile": "$W/c.pem", "keyFile": "$W/k.pem"}]}}}],
 "outbounds": [{"protocol": "freedom"}]}
EOF
"$XRAY" run -c "$W/x.json" >"$W/x.log" 2>&1 &
PIDS="$PIDS $!"
echo "ech: сервер — $("$XRAY" version 2>/dev/null | head -1)"
sleep 2

urlenc() { printf '%s' "$1" | sed 's/+/%2B/g; s#/#%2F#g; s/=/%3D/g'; }
FAILS=0
# узел — по имени localhost: разбор подписки отбрасывает узлы 127.0.0.0/8 («отвечать некому»).
probe() { # название порт ожидание(принят|отказ|негоден) список
	name=$1; port=$2; want=$3; lst=$4
	out=$("$PROBE" probe "vless://$U@localhost:$port?type=tcp&security=tls&sni=test.example&pcs=$PCS${lst:+&ech=$(urlenc "$lst")}" 1 2>&1 | tr '\n' ' ') || true
	case "$out" in
		*"не принял ECH"*) got=отказ ;;
		*"узел не годен"*) got=негоден ;;
		*"ECH:"*|*"доказал"*|*"испорчен"*|*"закрыт"*) got="ошибка ($out)" ;;
		*) got=принят ;;
	esac
	if [ "$got" = "$want" ]; then echo "  ok   $name"; else echo "  FAIL $name: ожидали $want, получили $got [$out]"; FAILS=$((FAILS + 1)); fi
}
probe "ECH, набор AES-128-GCM (список Xray)" $P_ECH принят "$LIST"
probe "ECH, набор ChaCha20-Poly1305" $P_CHACHA принят "$CLIST"
probe "без ECH к серверу с ECH — обычное рукопожатие" $P_ECH принят ""
probe "ECH к серверу без ECH — отказ, а не рукопожатие с открытым именем" $P_NOECH отказ "$LIST"
probe "ECH с чужим ключом — отказ" $P_CHACHA отказ "$LIST"
probe "испорченный список — узел не годен" $P_ECH негоден "AAAA"
probe "запрос записи из DNS (домен+https://…) — узел не годен" $P_ECH негоден "cloudflare-ech.com+https://1.1.1.1/dns-query"

[ $FAILS = 0 ] && echo "ech: все проверки прошли" || { echo "ech: провалов: $FAILS"; exit 1; }
