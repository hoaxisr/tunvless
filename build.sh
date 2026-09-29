#!/bin/sh
# Builds one static musl binary per OpenWrt architecture and packages it.
#
# Same zig cross-toolchain splify uses: a static binary means no libc version to
# match against the router's, and one build serves every OpenWrt release for that
# ISA.
set -eu

VERSION="$(cat VERSION 2>/dev/null || echo 0.1.0)"

# В VERSION только цифры и точки. Этой строкой собираются имя файла пакета
# (`steer-extended-26.9-1_<арх>.apk`), версия для apk/opkg и тег релиза — пробелу и буквам там
# места нет ни в одном из трёх мест. Заодно её читает интерфейс splify2 через менеджер пакетов и
# сравнивает с релизами; версия с буквами в этом сравнении оказалась бы несравнимой.
#
# Кодовое имя выпуска («26.9 Andromeda») живёт в ЗАГОЛОВКЕ релиза на GitHub: оттуда его читает
# splify2 и показывает человеку. В имени пакета ему места нет.
#
# Число составляющих НЕ проверяется: «26.9» — такая же законная версия, как «1.2.0», и требовать
# три части значило бы отвергать собственный выпуск.
case "$VERSION" in
    ''|*[!0-9.]*)
        echo "в VERSION только цифры и точки, а там: «$VERSION»" >&2
        echo "кодовое имя выпуска задаётся заголовком релиза на GitHub, а не файлом VERSION" >&2
        exit 1 ;;
esac
# Ревизия сборки: чем этот бинарник отличается от релиза с тем же номером версии. Версия
# между релизами не меняется, поэтому релизный движок и движок из main через два коммита
# после него назывались одним числом, и на стенде два РАЗНЫХ бинарника отчитывались как
# «0.9.6-r1» (R-045/I-054). Печатает её `steer --version`; имена пакетов и версия пакета не
# затронуты намеренно — интерфейс версию берёт от менеджера пакетов.
#
# Считается ЗДЕСЬ, а не внутри docker: в образе нет ни git, ни каталога .git — смонтирован
# только рабочий каталог, — и describe там вернул бы пустоту при любом состоянии дерева.
#
# Без `--dirty`, в отличие от Makefile: релизный workflow сам записывает номер в VERSION
# ПЕРЕД сборкой и коммитит его после (см. .github/workflows/release.yml), поэтому дерево во
# время релизной сборки грязное всегда, и флаг помечал бы «-dirty» каждый релиз — то есть
# перестал бы что-либо значить.
REV="$(git describe --tags --always 2>/dev/null || true)"
[ -n "$REV" ] || REV="неизвестна"
OUT=out
# Свой образ, а не образ сборщика splify: в том нет исходников криптобиблиотеки, и расширенная
# сборка в нём падает на ненайденном заголовке, тогда как базовая проходит. Незаметная поломка:
# `./build.sh` печатает архитектуры, пакеты появляются, и только extended молча отсутствует.
# Тег — по библиотеке: steer-builder:wolfssl (build/Dockerfile); прежний steer-builder:mbedtls
# с mbedtls 3.6.2 этой сборке не годится — в нём нет исходников wolfSSL.
IMAGE="${STEER_BUILDER_IMAGE:-steer-builder:wolfssl}"

# Собрать образ, если его нет. Иначе первая же сборка на чужой машине упирается в
# «Unable to find image», и человек ищет, откуда его взять, — а он описан прямо здесь,
# в build/Dockerfile.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "образ $IMAGE отсутствует — собираю из build/Dockerfile"
    docker build -t "$IMAGE" build/ || { echo "не удалось собрать образ"; exit 1; }
fi

# id:target:mcpu — the ISAs OpenWrt actually ships. Package arch names below map
# several OpenWrt targets onto one ISA build, which is why the two lists differ.
# Два варианта одного движка, как dnsmasq и dnsmasq-full: базовый и с клиентом
# VLESS/Reality. Базовому VLESS не нужен, а весит он вместе с TLS-стеком больше самого
# движка — и на 4C с 6.9 МБ overlay это решает, влезет ли пакет.
#
# Собираются из ОДНИХ исходников: extended это те же файлы плюс src/tunnel, src/proto и wolfSSL.
# Разные бинарники из разного набора файлов означали бы два места, где чинить одну ошибку.
# Списки файлов всех сборок — в build/sources.mk и только там; build/build-ext.sh читает тот же
# манифест сам (он запускается отдельным процессом и отсюда ничего не наследует).
. ./build/sources.sh
BASE_SRC="$(profile_src base)" || exit 2
BASE_INC="$(for d in $(profile_var INC_DIRS); do printf -- '-I%s ' "$d"; done)"
# Определения стороннего кода в ядре (libyaml: -DHAVE_CONFIG_H) — см. THIRD_DEFS в sources.mk.
THIRD_DEFS="$(profile_var THIRD_DEFS)" || exit 2
# Клиент сокета `steer` — второй бинарник пакета (docs/architecture.md, раздел 4а, «Бинарники»):
# движок — steerd, а под именем steer его зовут rpcd splify2, init-скрипт и человек. Клиент один
# на оба пакета (в нём нет ни видов, ни протоколов), собирается один раз на архитектуру.
CLIENT_SRC="$(profile_var CLIENT_SRC)" || exit 2

ISAS="
mipsel_24kc:mipsel-linux-musl:mips32r2+soft_float
mips_24kc:mips-linux-musl:mips32r2+soft_float
aarch64_cortex-a53:aarch64-linux-musl:cortex_a53
aarch64_generic:aarch64-linux-musl:baseline
arm_cortex-a7_neon-vfpv4:arm-linux-musleabihf:cortex_a7
arm_cortex-a9:arm-linux-musleabi:cortex_a9
arm_cortex-a9_neon:arm-linux-musleabihf:cortex_a9+neon
arm_cortex-a9_vfpv3-d16:arm-linux-musleabihf:cortex_a9+vfp3d16
x86_64:x86_64-linux-musl:baseline
"

# ТРИ РАЗНОВИДНОСТИ CORTEX-A9, А НЕ ОДНА, и выбирать из них нельзя: OpenWrt публикует именно
# три, и пакет под чужую роутер не поставит — apk и opkg сверяют архитектуру по имени.
#
#   arm_cortex-a9            без блока с плавающей точкой, отсюда musleabi (мягкая ABI);
#                            так собран bcm53xx — Netgear R7000, Asus RT-AC68U и родня;
#   arm_cortex-a9_neon       NEON и жёсткая ABI: imx6, oxnas, zynq;
#   arm_cortex-a9_vfpv3-d16  VFPv3-D16 и жёсткая ABI: mvebu — Linksys WRT1200/1900,
#                            Turris Omnia.
#
# Мягкость ABI задаёт ТРИПЛЕТ (musleabi против musleabihf), а не ключ -mcpu: `cortex_a9+soft_float`
# zig не принимает вовсе (проверено сборкой), и пытаться выразить её признаком процессора
# значило бы получить пакет с чужой ABI, который встанет и упадёт на первом же вызове.

# Во время отладки собирать все шесть архитектур незачем: это три бинарника на каждую и около
# десяти минут ожидания. STEER_ARCH сужает список до нужной — полная сборка нужна только перед
# выкладкой пакетов.
if [ -n "${STEER_ARCH:-}" ]; then
    ISAS="$(printf '%s\n' "$ISAS" | grep "^${STEER_ARCH}:")"
    [ -n "$ISAS" ] || { echo "неизвестная архитектура: $STEER_ARCH" >&2; exit 1; }
fi

mkdir -p "$OUT" build/pkg

# ---- загрузчик musl для динамических бинарников (steerd, модули) -----------------------------
#
# Статическому бинарнику загрузчик не нужен, динамическому он вшит в файл ПУТЁМ, и путь обязан
# совпасть с тем, что лежит на роутере: musl называет загрузчик по архитектуре и по ABI —
# ld-musl-<арх>[hf|-sf].so.1. Умолчание zig этого не различает (мягкая плавающая точка MIPS и
# hard-float ARM получили бы имя без суффикса), поэтому задаём явно по тройке цели; тот же
# суффикс определяет, какая из трёх сборок Cortex-A9 у нас (musleabi против musleabihf, см. выше).
# RPATH не нужен: библиотеки лежат в /usr/lib, где musl ищет сам.
interp_of() {  # ТРОЙКА MCPU
    case "$1" in
        mipsel-linux-musl*)     echo /lib/ld-musl-mipsel-sf.so.1 ;;
        mips-linux-musl*)       echo /lib/ld-musl-mips-sf.so.1 ;;
        aarch64-linux-musl*)    echo /lib/ld-musl-aarch64.so.1 ;;
        arm-linux-musleabihf*)  echo /lib/ld-musl-armhf.so.1 ;;
        arm-linux-musleabi*)    echo /lib/ld-musl-arm.so.1 ;;
        x86_64-linux-musl*)     echo /lib/ld-musl-x86_64.so.1 ;;
        *) echo "interp_of: неизвестная цель $1 ($2)" >&2; echo /lib/ld-musl-unknown.so.1 ;;
    esac
}

# ---- две упаковки одного пакета: apk и opkg ----------------------------------
#
# OpenWrt перешёл на apk в 24.10, но 23.05 и 22.03 живут на роутерах и будут жить: на
# 4/32 их никто не обновит, а именно там движок и нужнее всего. Собирать пакет только в
# новом формате значит отрезать половину устройств, ради которых он написан.
#
# Оба формата делаются из ОДНОГО дерева файлов ($root / $eroot), а не из двух: разные
# деревья означали бы пакет, который на одном формате работает, а на другом нет, и
# заметить это можно было бы только на роутере. Отличаются они только метаданными.
#
# ipkg-build — родной скрипт OpenWrt, тот же, что собирает пакеты в их SDK. Берётся из
# сети один раз и кладётся в build/ (см. .gitignore): переписывать его своими руками
# значило бы получить .ipk, который opkg принимает не везде, — ровно та ошибка, на
# которой в splify обжигались с po2lmo.
IPKG=build/ipkg-build
if [ ! -x "$IPKG" ]; then
    echo "качаю ipkg-build из OpenWrt"
    # ДВА ИСТОЧНИКА, а не один, и по той же причине, по которой пакеты выкладываются в
    # ветку dist (splify2#15): `raw.githubusercontent.com` у части провайдеров закрыт
    # целиком, а хосты самого GitHub — другая сеть и работают. `api.github.com` с
    # заголовком `Accept: application/vnd.github.raw` отдаёт тот же файл байтами, никуда не
    # перенаправляя. Это машина сборщика, а не роутер, но человек с закрытым доменом не мог
    # собрать пакеты вовсе, и сообщение об этом ничем не отличалось от «сеть отвалилась».
    RAW=https://raw.githubusercontent.com/openwrt/openwrt/master/scripts/ipkg-build
    API='https://api.github.com/repos/openwrt/openwrt/contents/scripts/ipkg-build?ref=master'
    ACCEPT='Accept: application/vnd.github.raw'
    # curl или wget: на машине сборщика бывает любой из двух, а требовать конкретный
    # значит уронить сборку там, где всё для неё есть.
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$RAW" -o "$IPKG" ||
        curl -fsSL -H "$ACCEPT" "$API" -o "$IPKG" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$IPKG" "$RAW" ||
        wget -qO "$IPKG" --header="$ACCEPT" "$API" ||
            { echo "не удалось скачать ipkg-build ни из $RAW, ни из $API"; exit 1; }
    else
        echo "нужен curl или wget, чтобы взять ipkg-build"; exit 1
    fi
    chmod +x "$IPKG"
fi

# ---- зависимости пакета: не список в голове, а свойство собранного файла ------
#
# Три вещи, которых движку не хватает самому по себе, и все три до сих пор не были
# объявлены — то есть проверить их было нечем, а узнавал о них человек по молчаливо
# неработающей половине.
#
#   nftables, ip-full  — правила и `ip rule`; объявлены с самого начала.
#   kmod-nft-queue     — выражение `queue` в наборе правил: им выход kind=zapret отдаёт
#                        помеченный трафик своему обработчику nfqws. Без модуля ядро
#                        отвергает правило, а `nft -f` атомарен — то есть один такой выход
#                        снимает маршрутизацию ЦЕЛИКОМ, сообщением «No such file or
#                        directory» с указателем на слово queue (проверено на роутере,
#                        OpenWrt 25.12 / nftables 1.1.6). Модуль весит единицы килобайт;
#                        цена объявить его всем несравнимо меньше цены такого отказа.
#                        Движок при этом ещё и проверяет ядро сам (nfqueue_supported в
#                        src/daemon/apply.c) — установке файлом из релиза зависимости не помогают.
#   conntrack          — снятие установленных соединений выхода при смене маршрута
#                        (src/daemon/failover.c, conntrack_evict). Снимает их сам движок, через
#                        ctnetlink, а инструмент — запасной путь на случай, когда ядро по
#                        ctnetlink не отвечает (нет модуля nf_conntrack_netlink). Без
#                        обоих движок предупреждает и работает дальше, но при включённой выгрузке
#                        потоков это значит, что уже установленное соединение маршрут
#                        больше не пересматривает — и запрет on_fail=drop до него не
#                        доходит (H-110, R-096). Предупреждение в журнале читают редко,
#                        а зависимость проверяет менеджер пакетов при установке.
#   libsteer           — ТОЛЬКО когда бинарник связан с разделяемой libsteer.so (шаг 4 выпуска
#                        1.10); libsteer-wolfssl подтягивает уже она сама, своей зависимостью.
#   kmod-tun           — модулям, которые сами создают TUN (steer-vless, steer-xsteer).
#
# Про библиотеки важно, что зависимость выводится ИЗ БИНАРНИКА, а не приписывается пакету
# списком: статический файл без пакета работает, связанный с .so — не запустится ни одной
# командой, и список «пакет зависит от библиотеки» был бы ложью в первом случае и правдой во
# втором. Проверка самого файла верна в обоих и не требует помнить, каким рецептом он собран.
#
# Ищется SONAME в самом файле: у статического бинарника строки «libsteer.so.» нет — она
# появляется только записью DT_NEEDED, которую пишет линковщик. readelf для этого не нужен (его нет
# ни в alpine по умолчанию, ни на машине сборщика гарантированно), а grep -a по бинарнику есть
# везде. Системный libwolfssl OpenWrt сюда не подходит нарочно: его SONAME несёт хеш опций и
# меняется с каждым обновлением, а QUIC в нём нет.
pkg_deps() {  # ФАЙЛ_БИНАРНИКА ВИД (core|mod|tun) -> "nftables ip-full ..." через пробел
    case "$2" in
        core) _pd="nftables ip-full conntrack kmod-nft-queue" ;;
        tun)  _pd="kmod-tun" ;;
        *)    _pd="" ;;
    esac
    if grep -aq 'libsteer\.so\.' "$1" 2>/dev/null; then
        _pd="$_pd libsteer"
    fi
    printf '%s' "$_pd"
}

# ---- зависимости между НАШИМИ пакетами: точная версия --------------------------------
#
# Формат событий между движком и модулями, ABI libsteer и раскладка libsteer-wolfssl между
# выпусками не обещаются (шаг 4 выпуска 1.10), поэтому модуль той же версии, что движок, — не
# пожелание, а условие: `steer-vless (= версия)`, `libsteer (= версия)`. Менеджер пакетов не даст
# обновить один, оставив другой (apk — `имя=версия`, opkg — `имя (= версия)`). Чужие пакеты
# (nftables, kmod-…) остаются без версии. Демон дополнительно проверяет версию при запуске модуля
# (hello, docs/ctl.md) — на случай установки файлами мимо менеджера.
OURS=" steer libsteer libsteer-wolfssl steer-vless steer-xsteer steer-obfs steer-tgws steer-extended "
dep_apk() {  # ИМЕНА через пробел -> "имя=версия ..." для наших
    for _d in $1; do
        case "$OURS" in *" $_d "*) printf '%s=%s-r1 ' "$_d" "$VERSION" ;; *) printf '%s ' "$_d" ;; esac
    done
}
dep_ipk() {  # ИМЕНА через пробел -> "имя (= версия), ..." для наших
    _sep=""
    for _d in $1; do
        case "$OURS" in
            *" $_d "*) printf '%s%s (= %s-1)' "$_sep" "$_d" "$VERSION" ;;
            *)         printf '%s%s' "$_sep" "$_d" ;;
        esac
        _sep=", "
    done
}

# mk_ipk КОРЕНЬ ИМЯ АРХ ЗАВИСИМОСТИ ОПИСАНИЕ [ДОПОЛНИТЕЛЬНЫЕ ПОЛЯ CONTROL] [СКРИПТЫ]
#
# СКРИПТЫ — префикс файлов build/scripts (умолчание «steer»: steer.postinst, steer.prerm).
# Каталог CONTROL создаётся ВНУТРИ дерева пакета, поэтому зовётся строго ПОСЛЕ apk mkpkg
# по тому же дереву: иначе служебные файлы уехали бы в полезную нагрузку apk.
mk_ipk() {
    ipk_root="$1"; ipk_name="$2"; ipk_arch="$3"; ipk_dep="$4"; ipk_desc="$5"; ipk_extra="${6:-}"
    ipk_scr="${7:-steer}"
    mkdir -p "$ipk_root/CONTROL"
    {
        echo "Package: $ipk_name"
        echo "Version: $VERSION-1"
        [ -n "$ipk_dep" ] && echo "Depends: $ipk_dep"
        echo "Architecture: $ipk_arch"
        echo "Maintainer: xyzmean"
        echo "Section: net"
        [ -n "$ipk_extra" ] && printf '%s\n' "$ipk_extra"
        echo "Description: $ipk_desc"
    } > "$ipk_root/CONTROL/control"
    cp "build/scripts/$ipk_scr.postinst" "$ipk_root/CONTROL/postinst"
    cp "build/scripts/$ipk_scr.prerm" "$ipk_root/CONTROL/prerm"
    cp "build/scripts/$ipk_scr.postrm" "$ipk_root/CONTROL/postrm"
    chmod 0755 "$ipk_root/CONTROL/postinst" "$ipk_root/CONTROL/prerm" "$ipk_root/CONTROL/postrm"
    # Без -o/-g: нынешний ipkg-build их не понимает (они были в старых версиях), а
    # молчаливый отказ здесь означал бы релиз без половины пакетов.
    if "$PWD/$IPKG" "$ipk_root" "$PWD/$OUT" >/dev/null 2>&1; then
        # ipkg-build называет файл через подчёркивания; приводим к тому же виду, что у
        # apk, чтобы в релизе оба формата одного пакета лежали рядом и читались одинаково.
        mv "$OUT/${ipk_name}_${VERSION}-1_${ipk_arch}.ipk" \
           "$OUT/${ipk_name}-${VERSION}-1_${ipk_arch}.ipk" 2>/dev/null || true
    else
        echo "    (ipk packaging failed for $ipk_name $ipk_arch)"
    fi
    rm -rf "$ipk_root/CONTROL"
}

echo "steer $VERSION"
for spec in $ISAS; do
    arch=${spec%%:*}; rest=${spec#*:}
    target=${rest%%:*}; mcpu=${rest#*:}
    printf '  %-26s ' "$arch"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -DSTEER_VERSION="\"$VERSION\"" -DSTEER_REV="\"$REV\"" \
               -o "build/steerd-$arch" $BASE_INC $THIRD_DEFS $BASE_SRC \
               2>"build/$arch.err"; then
        echo "$(stat -c %s "build/steerd-$arch") bytes"
    else
        # Старый бинарник обязан исчезнуть: иначе упаковка молча положит в пакет
        # сборку от прошлого раза, и ошибка компиляции превратится в «версия
        # обновилась, а поведение прежнее» — самый дорогой вид тихого сбоя.
        rm -f "build/steerd-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch.err" || head -1 "build/$arch.err")"
        continue
    fi

    # Клиент. Без него пакета нет: /usr/sbin/steer зовут все, кто был до демона, — пакет с одним
    # steerd выглядел бы установленным, а splify2 получал бы «команда не найдена».
    printf '  %-26s ' "$arch (клиент steer)"
    if docker run --rm -v "$PWD:/src" -w /src "$IMAGE" \
            cc -target "$target" -mcpu="$mcpu" -static -Os -Wall -Wextra \
               -o "build/steer-client-$arch" $BASE_INC $CLIENT_SRC \
               2>"build/$arch-client.err"; then
        echo "$(stat -c %s "build/steer-client-$arch") bytes"
    else
        rm -f "build/steer-client-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-client.err" || head -1 "build/$arch-client.err")"
        continue
    fi

    # Мини-вариант для микропакета tgws: только перехват Telegram и то, на чём он стоит.
    # Нужен потому, что тот пакет носит бинарник внутри себя, и три четверти мегабайта там
    # заметны: на 4/32 разница между «ставится» и «места нет».
    printf '  %-26s ' "$arch (tgws)"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/steer-tgws-$arch" \
            "$VERSION" tgws "$REV" \
            2>"build/$arch-tgws.err"; then
        echo "$(stat -c %s "build/steer-tgws-$arch") bytes"
    else
        rm -f "build/steer-tgws-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-tgws.err" || head -1 "build/$arch-tgws.err")"
    fi

    # Мини-вариант для микропакета tgws: только перехват Telegram и то, на чём он стоит.
    # Нужен потому, что тот пакет носит бинарник внутри себя, и три четверти мегабайта там
    # заметны: на 4/32 разница между «ставится» и «места нет».
    #
    # ИМЯ ДРУГОЕ — stgws, а не steer. Микропакет ставится и туда, где полный движок уже стоит
    # (его ставит splify2 или сам brb), и один путь на два разных бинарника означал бы, что
    # установка микропакета молча подменяет полный движок урезанным.
    printf '  %-26s ' "$arch (stgws)"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/stgws-$arch" \
            "$VERSION" tgws "$REV" \
            2>"build/$arch-tgws.err"; then
        echo "$(stat -c %s "build/stgws-$arch") bytes"
    else
        rm -f "build/stgws-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-tgws.err" || head -1 "build/$arch-tgws.err")"
    fi

    # Разделяемая раскладка роутера (шаг 4 выпуска 1.10): libsteer-wolfssl.so, libsteer.so, steerd и
    # модули steer-vless, steer-xsteer, steer-obfs, steer-tgws. Логика — build/build-libs.sh (одна
    # для этого цикла и для tests/libs-test.sh), списки файлов — build/sources.mk. Статического
    # расширенного бинарника роутера больше нет: его место — steerd + модули на общих библиотеках
    # (статическая сборка расширенной части остаётся у телефона, шаг 6, и у стендов).
    #
    # Загрузчик задаётся на каждую архитектуру (interp_of): у динамического бинарника он вшит по
    # абсолютному пути и обязан совпасть с файлом musl на роутере.
    printf '  %-26s ' "$arch (libs)"
    libs="build/libs/$arch"
    rm -rf "$libs"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh \
            -e CC="zig cc -target $target -mcpu=$mcpu" -e AR="zig ar" -e ZIG=1 \
            -e INTERP="$(interp_of "$target" "$mcpu")" "$IMAGE" \
            /src/build/build-libs.sh "/src/$libs" "$VERSION" "$REV" \
            >"build/$arch-libs.log" 2>"build/$arch-libs.err"; then
        echo "libsteer $(stat -c %s "$libs"/libsteer.so.*) + wolfssl $(stat -c %s "$libs"/libsteer-wolfssl.so.*)" \
             "+ steerd $(stat -c %s "$libs/steerd") bytes"
        rm -rf "$libs/obj"
    else
        rm -rf "$libs"
        echo "FAILED — $(grep -m1 error "build/$arch-libs.err" || head -1 "build/$arch-libs.err")"
        continue
    fi

    # ---- пакеты ---------------------------------------------------------------------------
    #
    # Шесть пакетов и один мета-пакет на архитектуру (шаг 4 выпуска 1.10, docs/architecture.md,
    # «Сборки»):
    #
    #   libsteer-wolfssl   наша wolfSSL (QUIC включён заранее, см. build/wolfssl) как .so;
    #   libsteer           libsteer.so.<версия>: модель, виды, TLS, транспорты, стек, слой
    #                      криптографии; зависит от libsteer-wolfssl;
    #   steer              ядро: steerd на общих библиотеках, клиент steer, init-скрипт, обработчик
    #                      обхода; зависит от libsteer (и через неё от libsteer-wolfssl);
    #   steer-vless, steer-xsteer, steer-obfs, steer-tgws
    #                      по бинарнику модуля; зависят от steer и libsteer ТОЧНОЙ версии;
    #   steer-extended     мета-пакет из прежних времён: ставит ядро и все четыре модуля. Имя
    #                      сохранено, потому что его ставит splify2 (`steer_install`) и читает
    #                      определение вида пакета; замена базового пакета (provides/replaces)
    #                      ему больше не нужна — у файлов ядра один владелец, пакет steer.
    #
    # Ядро зависит от libsteer и libsteer-wolfssl, а не только от libsteer: steerd сам ходит по
    # HTTPS (замер групп, urltls; в 1.11 к DoH и DoT добавится dnsd), то есть ему нужен TLS и
    # слой криптографии — и без модулей. Отдельного пакета «ядро без TLS» нет: цена — 0,6 МБ
    # библиотеки на флеше и в памяти, выигрыш — один набор файлов и ни одной веточки «есть ли TLS».
    root="build/pkg/$arch"
    rm -rf "$root"
    mkdir -p "$root/usr/sbin" "$root/etc/init.d" "$root/etc/steer/lists" \
             "$root/lib/upgrade/keep.d" "$root/etc/hotplug.d/iface"
    # Три имени (docs/architecture.md, раздел 4а): steerd — движок целиком, steer — клиент сокета,
    # steer-tools — ссылка на steerd, под этим именем движок отвечает только на инструменты.
    cp "$libs/steerd" "$root/usr/sbin/steerd"
    cp "build/steer-client-$arch" "$root/usr/sbin/steer"
    ln -sf steerd "$root/usr/sbin/steer-tools"
    # Обработчик обхода DPI: его запускает procd для каждого выхода kind=zapret, и читает он
    # файл стратегии при КАЖДОМ запуске (см. его шапку). Обработчик — часть ядра, а не модуль:
    # правила очереди пишет ядро, а kind=zapret входит в каждый профиль.
    cp files/usr/sbin/steer-nfqws "$root/usr/sbin/steer-nfqws"
    cp files/etc/init.d/steer "$root/etc/init.d/steer"
    # Реакция на события сети: подъём и падение интерфейса доходят до сторожа сразу, а не
    # через минуту опроса. Файл невелик, но без него правка I-137 существует только в дереве.
    cp files/etc/hotplug.d/iface/95-steer "$root/etc/hotplug.d/iface/95-steer"
    # Настройки объявляются системе, иначе их не существует для sysupgrade и для «Создать
    # архив» в LuCI: список файлов там собирается из /etc/sysupgrade.conf и
    # /lib/upgrade/keep.d/*, и всё, чего в нём нет, обновление прошивки «с сохранением
    # настроек» просто теряет — молча (I-037: на стенде sysupgrade -l не знал ни spec.json,
    # ни sub.txt, то есть переживал обновление только URL подписки в /etc/config, без узлов).
    # Файл кладётся В ПОЛЕЗНУЮ НАГРУЗКУ, а не в скрипт установки: он обязан исчезнуть вместе
    # с пакетом и принадлежать ему, как init-скрипт.
    cp files/lib/upgrade/keep.d/steer "$root/lib/upgrade/keep.d/steer"
    chmod 0755 "$root/usr/sbin/steerd" "$root/usr/sbin/steer" "$root/usr/sbin/steer-nfqws" \
               "$root/etc/init.d/steer" "$root/etc/hotplug.d/iface/95-steer"
    chmod 0644 "$root/lib/upgrade/keep.d/steer"

    # OUTSIDE the package root: anything inside it ships as a FILE, so a
    # .post-install written there arrives on the router as /.post-install and
    # collides with every other package doing the same — apk refused the install of a
    # second package with "trying to overwrite .post-install owned by steer". The
    # script belongs to --script, not to the payload.
    #
    # Скрипты пакетов — три вида (файлы build/scripts/<вид>.<хук>, apk и opkg берут их же):
    #   steer  ядро: включить и перезапустить службу при установке, остановить и выключить при
    #          удалении;
    #   mod    модуль: перезапустить службу при установке и после удаления — реестр видов и
    #          состав помощников зависят от того, какие модули лежат рядом с движком, и демон
    #          видит их, только стартуя заново; службу не включает и не выключает — это дело ядра;
    #   noop   библиотеки и мета-пакет: делать нечего.
    mkdir -p build/scripts
    {
        printf '#!/bin/sh\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n'
        printf '/etc/init.d/steer enable 2>/dev/null\n/etc/init.d/steer restart 2>/dev/null\nexit 0\n'
    } > build/scripts/steer.postinst
    {
        printf '#!/bin/sh\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n'
        printf '/etc/init.d/steer stop 2>/dev/null\n/etc/init.d/steer disable 2>/dev/null\nexit 0\n'
    } > build/scripts/steer.prerm
    {
        printf '#!/bin/sh\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n'
        printf '[ -x /etc/init.d/steer ] && /etc/init.d/steer restart 2>/dev/null\nexit 0\n'
    } > build/scripts/mod.postinst
    cp build/scripts/mod.postinst build/scripts/mod.postrm
    printf '#!/bin/sh\nexit 0\n' > build/scripts/mod.prerm
    printf '#!/bin/sh\nexit 0\n' > build/scripts/noop.postinst
    cp build/scripts/noop.postinst build/scripts/noop.prerm
    cp build/scripts/noop.postinst build/scripts/noop.postrm
    printf '#!/bin/sh\nexit 0\n' > build/scripts/steer.postrm
    chmod +x build/scripts/*

    # pack ИМЯ КОРЕНЬ ЗАВИСИМОСТИ ОПИСАНИЕ ВИД-СКРИПТОВ — оба формата из одного дерева. Зависимости
    # пишутся один раз (имена через пробел), версии нашим пакетам ставят dep_apk и dep_ipk.
    pack() {
        _n="$1"; _r="$2"; _dp="$3"; _ds="$4"; _sk="$5"
        _dinfo=""
        [ -n "$_dp" ] && _dinfo="--info depends:'$(dep_apk "$_dp")'"
        # apk: скрипты — три хука. post-deinstall нужен модулям (перезапуск после удаления).
        docker run --rm -v "$PWD":/w -w /w alpine:latest sh -c \
            "apk add --no-cache apk-tools >/dev/null 2>&1; apk mkpkg \
               --info name:$_n --info version:$VERSION-r1 \
               --info description:'$_ds' \
               --info arch:$arch $_dinfo \
               --script post-install:build/scripts/$_sk.postinst \
               --script pre-deinstall:build/scripts/$_sk.prerm \
               --script post-deinstall:build/scripts/$_sk.postrm \
               -F $_r -o $OUT/$_n-$VERSION-1_$arch.apk" >/dev/null 2>&1 \
            || echo "    (apk packaging failed for $_n $arch)"
        mk_ipk "$_r" "$_n" "$arch" "$(dep_ipk "$_dp")" "$_ds" "" "$_sk"
    }

    # Библиотеки. Зависимости считаются по СОБРАННОМУ файлу — см. pkg_deps выше; libsteer-wolfssl
    # не зависит ни от чего нашего, libsteer — от неё (pkg_deps по DT_NEEDED самой libsteer).
    lroot="build/pkg/$arch-libsteer-wolfssl"
    rm -rf "$lroot"
    mkdir -p "$lroot/usr/lib"
    cp "$libs"/libsteer-wolfssl.so.* "$lroot/usr/lib/"
    pack libsteer-wolfssl "$lroot" "" "wolfSSL со своими опциями для steer (TLS 1.3, QUIC): общая библиотека" noop
    lroot="build/pkg/$arch-libsteer"
    rm -rf "$lroot"
    mkdir -p "$lroot/usr/lib"
    cp "$libs"/libsteer.so.* "$lroot/usr/lib/"
    ldeps=""
    grep -aq 'libsteer-wolfssl\.so\.' "$lroot"/usr/lib/libsteer.so.* && ldeps="libsteer-wolfssl"
    pack libsteer "$lroot" "$ldeps" "libsteer: модель, TLS и транспорты, стек TUN — общее для steerd и модулей" noop

    # Ядро. Зависит от libsteer (по DT_NEEDED steerd), а через неё — от libsteer-wolfssl.
    deps="$(pkg_deps "$root/usr/sbin/steerd" core)"
    pack steer "$root" "$deps" "policy routing engine: channels in, nftables out" steer

    # Модули: по одному бинарнику в usr/sbin рядом со steerd, где их находит движок (src/lib/
    # module.c). Зависимость от steer — точной версии: ядро и модуль общаются линией событий, формат
    # которой между выпусками не обещан (hello в docs/ctl.md).
    for m in vless xsteer obfs tgws; do
        mroot="build/pkg/$arch-$m"
        rm -rf "$mroot"
        mkdir -p "$mroot/usr/sbin"
        cp "$libs/steer-$m" "$mroot/usr/sbin/steer-$m"
        chmod 0755 "$mroot/usr/sbin/steer-$m"
        case "$m" in
            vless)  md="steer-vless: клиент VLESS/Reality для steer (модуль)"; mk=tun ;;
            xsteer) md="steer-xsteer: клиент звезды xsteer для steer (модуль)"; mk=tun ;;
            obfs)   md="steer-obfs: обфускатор WireGuard для steer (модуль)"; mk=mod ;;
            tgws)   md="steer-tgws: мост Telegram для steer (модуль)"; mk=mod ;;
        esac
        mdeps="steer $(pkg_deps "$mroot/usr/sbin/steer-$m" "$mk")"
        pack "steer-$m" "$mroot" "$mdeps" "$md" mod
    done

    # Мета-пакет steer-extended: ядро и все четыре модуля. Пустой пакет менеджеры не любят, поэтому
    # в нём один маленький файл-метка. Имя сохранено ради splify2, который ставит его по имени.
    xroot="build/pkg/$arch-extended"
    rm -rf "$xroot"
    mkdir -p "$xroot/usr/lib/steer"
    printf 'steer-extended %s: мета-пакет — steer, steer-vless, steer-xsteer, steer-obfs, steer-tgws\n' \
        "$VERSION" > "$xroot/usr/lib/steer/extended"
    pack steer-extended "$xroot" "steer steer-vless steer-xsteer steer-obfs steer-tgws" \
        "steer со всеми модулями: VLESS/Reality, xsteer, обфускатор, мост Telegram (как dnsmasq-full)" noop
done

# ---- серверная половина обфускации: архив для VPS -----------------------------
#
# steer obfs-server живёт не на роутере, а на VPS рядом с WireGuard, и пакетом OpenWrt
# туда не поставишь: там обычный Linux с systemd. До сих пор единственным путём была
# сборка из исходников (server/install.sh), то есть на голой VPS установка начиналась с
# apt install build-essential ради одного файла — и упиралась в него же на образах, где
# компилятора нет и ставить его нельзя.
#
# Архив содержит ровно то, что нужно на той стороне: статический бинарник, установщик и
# краткую справку. Код тот же, что у модуля steer-obfs в пакете для роутера (obfs.c и obfsmain.c
# входят в статическую базовую сборку, а в пакете — в libsteer и модуль), — отдельной обфускации
# для сервера нет и быть не должно: две реализации означали бы две обфускации, расходящиеся в
# мелочах на проводе. Сборка здесь статическая, без библиотек: на VPS нет пакетов OpenWrt.
#
# Архитектуры только те, на которых VPS реально бывают. Собирать архив под mips значило
# бы предлагать людям то, чего не существует.
echo "серверная половина:"
for arch in x86_64 aarch64_generic; do
    # Движок, а не клиент: на VPS нет ни демона, ни сокета — obfs-server подкомандой самого
    # движка. Имя внутри архива прежнее (steer): его зовут server/install.sh и человек.
    bin="build/steerd-$arch"
    if [ ! -f "$bin" ]; then
        printf '  %-26s пропуск (движок не собрался)\n' "$arch"
        continue
    fi
    # Имя внутри архива — привычное человеку, а не имя цели OpenWrt: на VPS про
    # aarch64_generic никто не знает, там знают uname -m.
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    stage="build/obfs-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$bin" "$stage/steer"
    cp server/install.sh "$stage/install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer" "$stage/install.sh"
    tar -C build -czf "$OUT/steer-obfs-$VERSION-$uarch.tar.gz" "obfs-$uarch"
    printf '  %-26s %s bytes\n' "$uarch" "$(stat -c %s "$OUT/steer-obfs-$VERSION-$uarch.tar.gz")"
done

# ---- хаб xsteer: архив для VPS -----------------------------------------------
#
# Клиент xsteer живёт на роутере (роль router, уже собран выше в extended), а хаб звезды —
# на VPS. Хабу нужна подкоманда xsteer-hub, поднимающая слушателя на публичном порту, и
# ради безопасности её нет в сборке для роутера: это отдельная РОЛЬ server сборки ext
# (см. build/build-ext.sh — там объяснено, почему гейт стоит на списках файлов).
#
# Отсюда отдельный бинарник steer-hub и отдельный архив: смешивать его с обфускацией из
# steer-obfs нельзя — там другая половина и другой протокол. Архитектуры те же, что у VPS
# вообще (см. серверную половину выше): собирать хаб под mips значило бы предлагать
# несуществующее.
#
# Имя архива БЕЗ версии — steer-hub-$uarch.tar.gz: установщик server/xs_install.sh тянет его
# по фиксированному пути releases/latest/download/steer-hub-$arch.tar.gz, где имя не должно
# зависеть от версии. Внутри — бинарник, установщик и справка: распаковал и запустил, даже
# без сети (xs_install.sh берёт steer-hub рядом с собой, если он есть).
echo "хаб xsteer:"
for arch in x86_64 aarch64_generic; do
    # Цель и mcpu берём из того же ISAS, что и основную сборку: одна таблица архитектур,
    # чтобы хаб и движок не разошлись в флагах компилятора.
    spec=""
    for s in $ISAS; do [ "${s%%:*}" = "$arch" ] && spec="$s" && break; done
    if [ -z "$spec" ]; then
        printf '  %-26s пропуск (нет в ISAS)\n' "$arch"
        continue
    fi
    rest=${spec#*:}; target=${rest%%:*}; mcpu=${rest#*:}
    case "$arch" in
        x86_64)           uarch=x86_64 ;;
        aarch64_generic)  uarch=aarch64 ;;
        *)                uarch=$arch ;;
    esac
    printf '  %-26s ' "$uarch"
    if docker run --rm -v "$PWD:/src" -w /src --entrypoint sh "$IMAGE" \
            /src/build/build-ext.sh "$target" "$mcpu" "/src/build/steer-hub-$arch" \
            "$VERSION" server "$REV" \
            2>"build/$arch-hub.err"; then
        :
    else
        rm -f "build/steer-hub-$arch"
        echo "FAILED — $(grep -m1 error "build/$arch-hub.err" || head -1 "build/$arch-hub.err")"
        continue
    fi
    stage="build/hub-$uarch"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "build/steer-hub-$arch" "$stage/steer-hub"
    cp server/xs_install.sh "$stage/xs_install.sh"
    [ -f server/README.md ] && cp server/README.md "$stage/README.md"
    chmod 0755 "$stage/steer-hub" "$stage/xs_install.sh"
    tar -C "$stage" -czf "$OUT/steer-hub-$uarch.tar.gz" .
    printf '%s bytes\n' "$(stat -c %s "$OUT/steer-hub-$uarch.tar.gz")"
done

echo "packages:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
