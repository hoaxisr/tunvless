#!/bin/sh
# Тестовый набор steer-box-connector: out/steer-box-connector-test-<версия>.tar.gz из уже собранных
# пакетов out/ (сначала ./build.sh). Внутри — install.sh, README.txt и packages/<архитектура>
# с пакетами steer-core, steer-vless, steer-hysteria2, steer-proxy и steer-box-connector в обоих
# форматах. Пакетов из фидов OpenWrt в наборе нет — их ставит менеджер пакетов.
set -e
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(cat VERSION 2>/dev/null)}"
[ -n "$VERSION" ] || { echo "не нашёл VERSION в build.sh" >&2; exit 1; }
PKGS="steer-core steer-vless steer-hysteria2 steer-proxy steer-box-connector"
name="steer-box-connector-test-$VERSION"
stage="build/pkg/$name"
rm -rf "$stage"
mkdir -p "$stage/packages"
arches=""
for f in out/steer-box-connector-"$VERSION"-1_*.apk; do
	[ -f "$f" ] || continue
	a="${f#out/steer-box-connector-$VERSION-1_}"
	a="${a%.apk}"
	ok=1
	for p in $PKGS; do
		for ext in apk ipk; do
			[ -f "out/$p-$VERSION-1_$a.$ext" ] || { echo "  $a: нет $p .$ext — архитектура пропущена" >&2; ok=0; }
		done
	done
	[ "$ok" = 1 ] || continue
	mkdir -p "$stage/packages/$a"
	for p in $PKGS; do cp "out/$p-$VERSION-1_$a.apk" "out/$p-$VERSION-1_$a.ipk" "$stage/packages/$a/"; done
	arches="$arches${arches:+, }$a"
done
[ -n "$arches" ] || { echo "в out/ нет пакетов steer-box-connector $VERSION" >&2; exit 1; }
sed "s/@VERSION@/$VERSION/g" build/box-bundle/install.sh > "$stage/install.sh"
chmod 0755 "$stage/install.sh"
sed "s/@VERSION@/$VERSION/g; s/@ARCHES@/$arches/" build/box-bundle/README.txt > "$stage/README.txt"
(cd "$stage/packages" && find . -type f | sort | xargs sha256sum) > "$stage/SHA256SUMS"
tar -C build/pkg -czf "out/$name.tar.gz" "$name"
echo "out/$name.tar.gz: $(stat -c %s "out/$name.tar.gz") байт; архитектуры: $arches"
