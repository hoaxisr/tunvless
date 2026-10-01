#!/bin/sh
# Переменные окружения, которыми steer-box-connector настраивает свой экземпляр движка рядом с
# podkop и forkop: STEER_MARK_FIELD (поле метки, src/platform/platform.c), STEER_RULE_PREF
# (приоритет ip rule выходов) и STEER_MARK_RESTORE (цепочка prerouting_restore,
# src/compile/generate.c). Проверяется набор правил apply --dry-run: с переменными — новое поле
# и цепочка; без них — прежний набор, байт в байт (то, на чём стоят снимки генератора).
set -u
BUILD=${BUILD:-build}
BIN="${STEER_BIN:-$BUILD/steerd}"
[ -x "$BIN" ] || { echo "boxenv: нет $BIN"; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf 'x.test\n' > "$tmp/d.lst"
printf '1.2.3.0/24\n' > "$tmp/p.lst"
cat > "$tmp/spec.json" <<EOF
{"version":2,"lists":{"l":{"domains_file":["$tmp/d.lst"],"prefixes_file":["$tmp/p.lst"]}},
 "outputs":{"vpn":{"kind":"interface","device":"wg9"}},"rules":[{"name":"r","to":["l"],"out":"vpn"}]}
EOF
gen() { env "$@" "$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st" 2>/dev/null; }
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
plain=$(gen)
check "без переменных — поле по умолчанию" "1" "$(printf '%s\n' "$plain" | grep -c 'mark and 0x0ff00000 == 0x00100000')"
check "без переменных — цепочки restore нет" "0" "$(printf '%s\n' "$plain" | grep -c prerouting_restore)"
check "пустые переменные — набор тот же" "$plain" "$(gen STEER_MARK_FIELD= STEER_MARK_RESTORE=)"
f=$(gen STEER_MARK_FIELD=0x000000ff)
check "поле 0xff — метка выхода 0x01" "1" "$(printf '%s\n' "$f" | grep -c 'mark and 0x000000ff == 0x00000001')"
check "поле 0xff — старого поля нет" "0" "$(printf '%s\n' "$f" | grep -c 0x0ff00000)"
bad=$(env STEER_MARK_FIELD=0x00000f0f "$BIN" apply --dry-run --spec "$tmp/spec.json" --state-dir "$tmp/st" 2>&1)
check "поле не подряд — предупреждение" "1" "$(printf '%s\n' "$bad" | grep -c 'нужна маска из битов подряд')"
check "поле не подряд — поле платформы" "1" "$(printf '%s\n' "$bad" | grep -c 'mark and 0x0ff00000 == 0x00100000')"
r=$(gen STEER_MARK_FIELD=0x000000ff STEER_MARK_RESTORE=1)
check "restore — цепочка на dstnat + 10" "1" "$(printf '%s\n' "$r" | grep -c 'chain prerouting_restore')"
check "restore — только прямое направление, только при пустом поле" "1" \
    "$(printf '%s\n' "$r" | grep -c 'ct direction original meta mark and 0x000000ff == 0 ct mark and 0x000000ff != 0 meta mark set ct mark and 0x400000ff')"
echo "boxenv: $pass прошло, $fail упало"
[ "$fail" = 0 ]
