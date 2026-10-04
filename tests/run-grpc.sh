#!/bin/sh
# VLESS over gRPC + Reality against a REAL Xray-core: the node probe, and minutes of load both ways.
#
# tests/grpcmatch.c and tests/h2match.c check frames written by hand. What a gRPC server puts in
# one TLS record depends on how grpc-go flushes and on how fast the target answers, and that is
# where h2_read used to drop the data read in the same call as the end of the stream (RST_STREAM
# after the closing HEADERS). Against Xray 26.3.27 that broke three things: the node probe failed
# on a working node (14 of 30 in gun mode, 21 of 30 in multi), the pool declared the node dead and
# reset every connection, and about 20% of short connections lost the end of the response.
#
# Checks (a failure exits 1, the reason on the last line):
#   1. the node probe (tunvless --probe) 30 times in a row: no failure;
#   2. DUR seconds (default 190) of load through the tunnel: two long flows down, two up and short
#      pages at 10 per second; no page truncated or hung, no long flow broken, no direction stalled
#      for 15 seconds;
#   3. the pool checks the node every 10 seconds (--interval 10): its log must not say that the
#      node does not answer, nor that a flow did not open.
# MODES: gRPC modes separated by spaces (gun, multi); default gun.
#
# The sides live in separate network namespaces: the client (tunvless, its device vl and the load)
# in one; Xray, the Reality cover site and the targets in the other, with 1.1.1.1 and 8.8.8.8
# serving HTTP on :80 as the probe's targets.
#
# Needs root, ip netns, python3, openssl and Xray-core: XRAY=<binary> (or xray in PATH). Without Xray
# or root it is skipped loudly (exit 0). TUNVLESS: the binary (default ./out/tunvless). Not part of
# make test or make e2e: it takes minutes.
set -eu
cd "$(dirname "$0")/.."

BIN="${TUNVLESS:-./out/tunvless}"
DUR="${DUR:-190}"
MODES="${MODES:-gun}"
XRAY="${XRAY:-$(command -v xray 2>/dev/null || true)}"

[ "$(id -u)" = 0 ] || { echo "run-grpc: SKIPPED — needs root (ip netns). Not a failure."; exit 0; }
command -v ip >/dev/null 2>&1 || { echo "run-grpc: SKIPPED — no ip. Not a failure."; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "run-grpc: SKIPPED — needs python3. Not a failure."; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "run-grpc: SKIPPED — needs openssl. Not a failure."; exit 0; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "run-grpc: SKIPPED — no Xray-core (XRAY=/path/to/xray). Not a failure."; exit 0; }
[ -x "$BIN" ] || { echo "run-grpc: no binary $BIN (make)"; exit 2; }
BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
ip netns add "grpc-probe-$$" 2>/dev/null || { echo "run-grpc: SKIPPED — ip netns unavailable. Not a failure."; exit 0; }
ip netns delete "grpc-probe-$$"

NSC="grpcc$$"; NSS="grpcs$$"
S_IP=10.93.0.1; C_IP=10.93.0.2; TARGET=203.0.113.9
PORT=18443; MASK=mask.grpc.test; SVC=grpcsvc
UUID=8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124
SID=0123456789abcdef
W="$(mktemp -d)"
PIDS=""
cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    done
    sleep 0.3
    for n in "$NSC" "$NSS"; do
        for p in $(ip netns pids "$n" 2>/dev/null || true); do kill -9 "$p" 2>/dev/null || true; done
        ip netns delete "$n" 2>/dev/null || true
    done
    rm -rf "$W"
}
trap cleanup EXIT INT TERM

bg_in() { ns="$1"; log="$2"; shift 2; ip netns exec "$ns" "$@" > "$log" 2>&1 & PIDS="$PIDS $!"; }

echo "run-grpc: server — $("$XRAY" version 2>/dev/null | head -1)"

ip netns add "$NSC"; ip netns add "$NSS"
ip -n "$NSC" link set lo up; ip -n "$NSS" link set lo up
ip link add grc0 netns "$NSC" type veth peer name grs0 netns "$NSS"
ip -n "$NSC" addr add "$C_IP/24" dev grc0
ip -n "$NSS" addr add "$S_IP/24" dev grs0
ip -n "$NSC" link set grc0 up; ip -n "$NSS" link set grs0 up
for a in "$TARGET" 1.1.1.1 8.8.8.8; do ip -n "$NSS" addr add "$a/32" dev lo; done

"$XRAY" x25519 > "$W/keys.txt" 2>&1
PRIV=$(awk '/^PrivateKey:/ {print $2}' "$W/keys.txt")
PUB=$(awk '/PublicKey/ {print $NF}' "$W/keys.txt")
[ -n "$PRIV" ] && [ -n "$PUB" ] || { echo "run-grpc: xray x25519 gave no keys:"; cat "$W/keys.txt"; exit 1; }
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$W/mask.key" -out "$W/mask.pem" -subj "/CN=$MASK" -addext "subjectAltName=DNS:$MASK" >/dev/null 2>&1

# The Reality cover site: any TLS 1.3 server with h2 in ALPN.
bg_in "$NSS" "$W/mask.log" openssl s_server -accept "$S_IP:8443" -cert "$W/mask.pem" -key "$W/mask.key" \
    -tls1_3 -alpn h2,http/1.1 -www -quiet
# The target, and the targets of the node probe.
bg_in "$NSS" "$W/target.log" python3 tests/grpc-target.py "$TARGET" 8080
bg_in "$NSS" "$W/probe1.log" python3 tests/grpc-target.py 1.1.1.1 80
bg_in "$NSS" "$W/probe2.log" python3 tests/grpc-target.py 8.8.8.8 80
# A counter of SYNs to the node, printed only (skipped without nft).
if command -v nft >/dev/null 2>&1; then
    ip netns exec "$NSS" nft -f - >/dev/null 2>&1 <<NFT || true
table inet grpccnt { chain in { type filter hook input priority -300; policy accept;
    iifname "grs0" tcp dport $PORT tcp flags & (syn | ack) == syn counter comment "syn" } }
NFT
fi

FAIL=0
for MODE in $MODES; do
    MULTI=false; [ "$MODE" = multi ] && MULTI=true
    echo "run-grpc: ==== mode $MODE ===="
    cat > "$W/xray.json" <<JSON
{"log":{"loglevel":"warning","access":"$W/xray-access-$MODE.log"},
 "inbounds":[{"listen":"$S_IP","port":$PORT,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
   "streamSettings":{"network":"grpc","security":"reality",
     "grpcSettings":{"serviceName":"$SVC","multiMode":$MULTI},
     "realitySettings":{"show":false,"dest":"$S_IP:8443","xver":0,"serverNames":["$MASK"],
       "privateKey":"$PRIV","shortIds":["$SID"]}}}],
 "outbounds":[{"protocol":"freedom","tag":"direct"}]}
JSON
    ip netns exec "$NSS" "$XRAY" run -c "$W/xray.json" > "$W/xray-$MODE.log" 2>&1 &
    XPID=$!; PIDS="$PIDS $XPID"
    for _ in $(seq 40); do ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
    ip netns exec "$NSS" ss -ltn 2>/dev/null | grep -q ":$PORT " || { echo "run-grpc: Xray did not start:"; tail -5 "$W/xray-$MODE.log"; exit 1; }

    printf '%s\n' "vless://$UUID@$S_IP:$PORT?encryption=none&type=grpc&serviceName=$SVC&mode=$MODE&security=reality&sni=$MASK&pbk=$PUB&sid=$SID&fp=chrome#grpc-$MODE" > "$W/sub.txt"
    probe() { ip netns exec "$NSC" "$BIN" --probe --timeout 5 "$W/sub.txt" 2>&1 || true; }
    is_ok() { printf '%s' "$1" | awk -F '\t' '$3 == "ok" { f = 1 } END { exit !f }'; }

    # Warm-up: the very first connection to a freshly started Xray with Reality can be slow (and
    # openssl s_server as the cover site even more), so failures are counted only after the first
    # answer, waited for up to a minute. That is the test bed, not the client.
    warm=0
    for _ in $(seq 12); do
        out=$(probe)
        if is_ok "$out"; then warm=1; break; fi
        sleep 1
    done
    [ "$warm" -eq 1 ] || { echo "run-grpc: FAIL — the node did not answer the probe within a minute: $out"; FAIL=1; kill "$XPID" 2>/dev/null || true; continue; }

    # 1. The node probe, 30 times.
    ok=0; bad=0
    for i in $(seq 30); do
        out=$(probe)
        if is_ok "$out"; then ok=$((ok + 1)); else
            bad=$((bad + 1)); LAST="$out"
            echo "run-grpc:   probe $i: $out"
        fi
    done
    echo "run-grpc: node probe: ok $ok, failed $bad"
    if [ "$bad" -ne 0 ]; then
        echo "run-grpc: FAIL — the probe fails on a working node: $LAST"
        FAIL=1; kill "$XPID" 2>/dev/null || true; continue
    fi

    # 2-3. The tunnel and the load. The pool checks the node every 10 s instead of every minute,
    # so a false "dead" (two failures in a row) shows up within the run.
    ip netns exec "$NSC" "$BIN" "$W/sub.txt" -d vl -n 0 --interval 10 > "$W/tun-$MODE.log" 2>&1 &
    SPID=$!; PIDS="$PIDS $SPID"
    for _ in $(seq 60); do ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 && break; sleep 0.25; done
    ip netns exec "$NSC" ip link show vl >/dev/null 2>&1 || {
        echo "run-grpc: FAIL — the tunnel vl did not come up:"; tail -8 "$W/tun-$MODE.log"; FAIL=1
        kill "$SPID" "$XPID" 2>/dev/null || true; continue; }
    ip netns exec "$NSC" ip route replace "$TARGET/32" dev vl
    echo "run-grpc: tunnel up, load for $DUR s (two flows down, two up, 10 pages/s)"

    rc=0
    ip netns exec "$NSC" python3 tests/grpc-load.py --target "$TARGET:8080" --dur "$DUR" \
        --down 2 --up 2 --rate 10 --report 10 || rc=$?

    # The node declared dead (its connections reset) or a flow to it that did not open.
    bad_log=$(grep -E "does not answer|answers again|did not open" "$W/tun-$MODE.log" || true)
    if [ -n "$bad_log" ]; then
        echo "run-grpc: FAIL — the pool declared the node dead, or a flow did not open:"
        printf '%s\n' "$bad_log" | head -5 | sed 's/^/    /'
        rc=1
    fi
    if command -v nft >/dev/null 2>&1; then
        syns=$(ip netns exec "$NSS" nft list chain inet grpccnt in 2>/dev/null | sed -n 's/.*packets \([0-9]*\) .*comment "syn".*/\1/p')
        [ -n "$syns" ] && echo "run-grpc: TCP connections to the node in this mode: $syns"
    fi
    kill "$SPID" 2>/dev/null || true
    sleep 0.5
    ip netns exec "$NSC" ip link delete vl 2>/dev/null || true
    kill "$XPID" 2>/dev/null || true
    sleep 0.5
    if [ "$rc" -ne 0 ]; then FAIL=1; echo "run-grpc: mode $MODE — FAIL"; else echo "run-grpc: mode $MODE — ok"; fi
done

[ "$FAIL" -eq 0 ] && echo "run-grpc: all checks passed" || echo "run-grpc: FAILED"
exit "$FAIL"
