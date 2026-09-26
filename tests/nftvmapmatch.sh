#!/bin/sh
# Карта вердиктов группы pick: balance по netlink (src/lib/nftvmap.c) против настоящего nft.
#
# Что проверяется (в своём сетевом пространстве, с таблицей inet, картой `type mark : verdict`,
# цепочками a, b, c и правилом `numgen random mod 8 vmap @m`, как у группы balance):
#  1. ключ — порядок хоста: элемент, положенный `nft add element … { 1 : goto a }`, читается
#     как номер 1;
#  2. запись заполняет 8 элементов — nft видит их; чтение возвращает то же;
#  3. замена части элементов (a → b) одной транзакцией — nft видит новое, число прежнее;
#  4. снятие элементов;
#  5. запись с несуществующей цепочкой — отказ, и карта НЕ изменилась (транзакция целиком);
#  6. чтение несуществующей карты — отказ.
# Нужны root, unshare и nft; без них — пропуск. Инструмент: build/nftvmap-tool (собирается здесь,
# если его нет).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="${NFTVMAP_TOOL:-$ROOT/build/nftvmap-tool}"
pass=0 fail=0
check() {
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); else
        fail=$((fail + 1)); printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
    fi
}
skip() { echo "nftvmapmatch: $1 — пропуск"; exit 0; }
if [ ! -x "$TOOL" ]; then
    (cd "$ROOT" && cc $(make -s print-inc) -O2 -Wall -Wextra -o "$TOOL" tests/nftvmap-tool.c \
        src/lib/nftvmap.c) || { echo "nftvmapmatch: инструмент не собрался"; exit 1; }
fi
command -v nft >/dev/null 2>&1 || skip "nft нет"
if [ "${NFTVMAP_INNER:-}" != 1 ]; then
    [ "$(id -u)" = 0 ] || skip "нужен root"
    unshare -n true 2>/dev/null || skip "unshare -n недоступен"
    NFTVMAP_INNER=1 exec unshare -n sh "$0" "$@"
fi
nft add table inet nftvmap_probe 2>/dev/null || skip "nf_tables недоступен"
nft delete table inet nftvmap_probe

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' 'table inet t {' \
    '  map m { type mark : verdict; }' \
    '  chain a { }' '  chain b { }' '  chain c { }' \
    '  chain p { type filter hook prerouting priority 0; numgen random mod 8 vmap @m; }' \
    '}' > "$tmp/t.nft"
nft -f "$tmp/t.nft" || { echo "nftvmapmatch: таблица не встала"; exit 1; }
T() { "$TOOL" "$@"; }
# Элементы карты текстом nft одной строкой: «0x00000000 : goto a, …».
els() { nft list map inet t m | tr '\n\t' '  ' | sed 's/  */ /g' |
        sed -n 's/.*elements = { \([^}]*[^ }]\) *}.*/\1/p'; }

nft add element inet t m '{ 1 : goto a }'
check "ключ nft — номер 1 (порядок хоста)" "1 a|n 1" "$(T read t m 8 | tr '\n' '|' | sed 's/|$//')"
nft flush map inet t m

T write t m 8 0=a 1=b 2=c 3=a 4=b 5=c 6=a 7=b; check "запись 8 элементов: код 0" "0" "$?"
check "  nft видит все восемь" \
    "0x00000000 : goto a, 0x00000001 : goto b, 0x00000002 : goto c, 0x00000003 : goto a, 0x00000004 : goto b, 0x00000005 : goto c, 0x00000006 : goto a, 0x00000007 : goto b" \
    "$(els)"
check "  чтение — то же" "0 a|1 b|2 c|3 a|4 b|5 c|6 a|7 b|n 8" "$(T read t m 8 | tr '\n' '|' | sed 's/|$//')"

T write t m 8 0=b 3=b 6=b; check "замена a → b одной транзакцией: код 0" "0" "$?"
check "  nft видит новое" \
    "0x00000000 : goto b, 0x00000001 : goto b, 0x00000002 : goto c, 0x00000003 : goto b, 0x00000004 : goto b, 0x00000005 : goto c, 0x00000006 : goto b, 0x00000007 : goto b" \
    "$(els)"
check "  число элементов прежнее" "n 8" "$(T read t m 8 | tail -n 1)"

T write t m 8 2= 5=; check "снятие элементов: код 0" "0" "$?"
check "  осталось шесть, без c" "0 b|1 b|3 b|4 b|6 b|7 b|n 6" "$(T read t m 8 | tr '\n' '|' | sed 's/|$//')"

before="$(els)"
T write t m 8 0=a 2=nosuch 2>/dev/null; check "несуществующая цепочка — отказ" "1" "$?"
check "  карта не изменилась (транзакция целиком)" "$before" "$(els)"

T read t nomap 8 >/dev/null 2>&1; check "чтение несуществующей карты — отказ" "1" "$?"
T write t m 8 >/dev/null 2>&1; check "запись без изменений — код 0" "0" "$?"

echo "nftvmapmatch: $pass passed, $fail failed"
[ "$fail" = 0 ]
