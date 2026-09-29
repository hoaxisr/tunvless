/* СПЕКА v2 → МОДЕЛЬ (docs/architecture.md, «3. Спека v2», «4в», шаг 2; справочник формата —
 * docs/spec-v2.md).
 *
 * Спека v2 — YAML (или JSON: libyaml читает и его) с `version: 2` наверху. Дерево строит
 * src/lib/ynode.c, этот файл обходит его и собирает ту же модель, что перевод v1 (model/v1.c):
 * правила, списки, клиенты, выходы и группы. Остальной движок формата не видит.
 *
 * ЧЕМ ОТЛИЧАЕТСЯ ОТ v1 ПО ПОВЕДЕНИЮ РАЗБОРА:
 *   - НЕИЗВЕСТНЫЙ КЛЮЧ — ОТКАЗ. v1 пропускал незнакомые ключи ради совместимости вперёд внутри
 *     мажора, и цена этого известна: опечатка в ключе молча не действовала. У v2 совместимость
 *     вперёд держит `version`, а опечатка называется строкой и столбцом;
 *   - ключ чужого вида — тоже отказ, по битам kind_ops.keys, с тем же доводом;
 *   - все отказы — «файл:строка:столбец: …» (ynode_err): спеку v2 пишет человек руками, и
 *     сообщение без места в тексте заставляло бы искать;
 *   - ссылки по именам (`for`, `to`, `out`, `members`, `over`, `default`, `dns`) проверяются здесь
 *     же: несуществующее имя и круг в группах — отказ.
 *
 * КЛЮЧИ ВИДОВ разбирает не этот файл, а сам вид: здесь значения ключей раскладываются в struct
 * out_keys (то же, что делает v1.c из JSON), и kind_ops.parse проверяет и толкует их одинаково для
 * обоих форматов. Отказ вида приходит без места в тексте — его дополняет место выхода.
 *
 * ЧЕГО ДВИЖОК ЕЩЁ НЕ УМЕЕТ, разбор принимает, проверяет и хранит в модели, но спеку отвергает
 * отказом «ещё не поддерживается в этой версии движка: …» — ПОСЛЕ всех настоящих проверок, чтобы
 * ошибка в спеке называлась раньше, чем то, чего ждать выпуска: balance у правил на само
 * устройство (телефон); dns.cache и dns.upstreams
 * (выпуск 1.11); транспорт туннеля (1.10); встроенные domains/prefixes у списка и app у клиента
 * (потребители читают только файлы и UID); клиенты или списки, которые нельзя свести в одного
 * клиента или один список (компилятор пока берёт у правила одного клиента и один список). Молча
 * не игнорируется ничего. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>

#include "spec.h"
#include "ynode.h"
#include "check.h"
#include "grpurl.h"
#include "v2.h"

/* Протоколы вида `tunnel` (раздел 3: `kind: tunnel, protocol: vless`). Сегодня протокол и есть
 * вид выхода движка (kinds/vless.c); общий помощник steer-tunnel с дайлерами — выпуск 1.10, и
 * запись спеки к нему уже готова. xsteer туннелем в этом смысле не является (везёт пакеты, а не
 * потоки) и остаётся своим видом. */
static const char *const TUNNEL_PROTOS[] = { "vless", NULL };

int v2_tunnel_proto(const char *name) {
    for (size_t i = 0; TUNNEL_PROTOS[i]; i++)
        if (!strcmp(TUNNEL_PROTOS[i], name)) return 1;
    return 0;
}

/* Что о клиенте нужно правилам после его разбора. */
struct v2_client {
    unsigned addr : 1, mac : 1, local : 1, self : 1;
    unsigned hosts : 1;             /* все записи — одиночные хозяева (правило на устройство) */
};

struct v2 {
    const struct ydoc *d;
    struct spec *s;
    struct err *e;
    /* Первое «ещё не поддерживается»: место и что именно. */
    const struct ynode *un_node;
    char un_what[400];
    int realip_default;             /* dns.mode */
    char base[1040];                /* каталог файла спеки — для относительных путей */
    /* Узлы выходов для сообщений и второго прохода. */
    const struct ynode *out_key[MAX_OUTPUTS];
    const struct ynode *out_over[MAX_OUTPUTS];
    const struct ynode *out_members[MAX_OUTPUTS];
    const struct ynode *out_default[MAX_OUTPUTS];
    const struct ynode *out_weights[MAX_OUTPUTS];
    const struct ynode *out_ipv6[MAX_OUTPUTS], *out_prefix[MAX_OUTPUTS];
    struct v2_client cl[MAX_CLIENTS];
    size_t clients_named, lists_named;
};

/* ---- отказы -------------------------------------------------------------------------------- */

__attribute__((format(printf, 3, 4)))
static int fail(struct v2 *x, const struct ynode *n, const char *fmt, ...) {
    char msg[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    return ynode_err(x->e, x->d, n, "%s", msg);
}

/* Отказ, который уже сформулирован без места (вид, группа, сквозная проверка), — с местом. */
static int wrap(struct v2 *x, const struct ynode *n) {
    char msg[sizeof(x->e->msg)];
    snprintf(msg, sizeof(msg), "%s", x->e->msg);
    return ynode_err(x->e, x->d, n, "%s", msg);
}

__attribute__((format(printf, 3, 4)))
static void unsup(struct v2 *x, const struct ynode *n, const char *fmt, ...) {
    if (x->un_node) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(x->un_what, sizeof(x->un_what), fmt, ap);
    va_end(ap);
    x->un_node = n;
}

/* ---- значения ------------------------------------------------------------------------------ */

static const char *shape(const struct ynode *n) {
    if (!n) return "ничего";
    if (n->kind == YN_MAP) return "отображение";
    if (n->kind == YN_SEQ) return "список";
    return ynode_is_null(n) ? "пустое значение" : "строка";
}

static int want_map(struct v2 *x, const struct ynode *n, const char *where) {
    if (n && n->kind == YN_MAP) return 0;
    return fail(x, n, "%s — отображение «ключ: значение», а не %s", where, shape(n));
}

/* Строка: скаляр в любом стиле записи, но не пустое значение. */
static int str_of(struct v2 *x, const struct ynode *n, const char *where, const char **out) {
    if (!n || n->kind != YN_SCALAR || ynode_is_null(n))
        return fail(x, n, "%s — строка, а не %s", where, shape(n));
    if (!n->str[0]) return fail(x, n, "%s: пустая строка", where);
    *out = n->str;
    return 0;
}

static int copy_to(struct v2 *x, const struct ynode *n, const char *where, const char *v, char *dst,
                   size_t cap) {
    if (strlen(v) >= cap) return fail(x, n, "%s: длиннее %zu байт", where, cap - 1);
    memcpy(dst, v, strlen(v) + 1);
    return 0;
}

static int bool_of(struct v2 *x, const struct ynode *n, const char *where, int *out) {
    if (ynode_bool(n, out) == 0) return 0;
    return fail(x, n, "%s — true или false", where);
}

static int long_of(struct v2 *x, const struct ynode *n, const char *where, long lo, long hi,
                   long *out) {
    if (ynode_long(n, out) != 0) return fail(x, n, "%s — целое число без кавычек", where);
    if (*out < lo || *out > hi) return fail(x, n, "%s — от %ld до %ld", where, lo, hi);
    return 0;
}

/* Перечень: список скаляров или один скаляр — сокращение для списка из одного (`to: youtube` и
 * `to: [youtube]` значат одно). Пустое значение — пустой перечень. */
static size_t n_items(const struct ynode *n) {
    if (!n || ynode_is_null(n)) return 0;
    if (n->kind == YN_SCALAR) return 1;
    return n->kind == YN_SEQ ? n->len : 0;
}

static const struct ynode *item(const struct ynode *n, size_t i) {
    return n->kind == YN_SCALAR ? n : ynode_at(n, i);
}

static int items_ok(struct v2 *x, const struct ynode *n, const char *where, size_t max) {
    if (n && n->kind == YN_MAP)
        return fail(x, n, "%s — список [a, b] или одно значение, а не отображение", where);
    size_t k = n_items(n);
    if (k > max) return fail(x, n, "%s: больше %zu элементов", where, max);
    for (size_t i = 0; i < k; i++) {
        const struct ynode *it = item(n, i);
        if (it->kind != YN_SCALAR || ynode_is_null(it) || !it->str[0])
            return fail(x, it, "%s: элемент — непустая строка, а не %s", where,
                        it->kind == YN_SCALAR && !ynode_is_null(it) ? "пустая строка" : shape(it));
    }
    return 0;
}

/* Ключи отображения — только из перечня. */
static int keys_known(struct v2 *x, const struct ynode *map, const char *where,
                      const char *const *allowed) {
    for (size_t i = 0; i < ynode_len(map); i++) {
        const char *k = ynode_key_at(map, i)->str;
        size_t a = 0;
        while (allowed[a] && strcmp(allowed[a], k)) a++;
        if (allowed[a]) continue;
        char list[256];
        size_t l = 0;
        list[0] = '\0';
        for (a = 0; allowed[a] && l < sizeof(list); a++)
            l += (size_t)snprintf(list + l, sizeof(list) - l, "%s%s", a ? ", " : "", allowed[a]);
        return fail(x, ynode_key_at(map, i), "неизвестный ключ «%s» в %s (есть: %s)", k, where, list);
    }
    return 0;
}

/* Имя сущности — ключ отображения раздела. */
static int name_of(struct v2 *x, const struct ynode *key, const char *section, char *dst) {
    const char *v = key->str;
    if (!name_ok(v))
        return fail(x, key, "%s: имя «%s» — только буквы, цифры, _ - и точка", section, v);
    return copy_to(x, key, section, v, dst, 32);
}

/* ---- пути ----------------------------------------------------------------------------------
 *
 * ОТНОСИТЕЛЬНЫЙ ПУТЬ — ОТ КАТАЛОГА ФАЙЛА СПЕКИ. Пример раздела 3 пишет `srs: lists/youtube.srs`,
 * `subscription: sub/nl`, `strategy: zapret/yt.opts` — то есть файлы рядом со спекой, в {etc}. От
 * рабочего каталога такой путь значил бы разное у разных процессов (procd, клиент в шелле, init
 * телефона), а виды zapret, xsteer и awg по той же причине требуют абсолютного пути. Поэтому
 * разбор делает путь абсолютным сам, и вид получает уже готовый; в модель, status и diag уходит
 * абсолютный. Спека со стандартного ввода — от рабочего каталога. ctl apply проверяет тело во
 * временном файле рядом со спекой, так что каталог тот же. */
static int path_of(struct v2 *x, const struct ynode *n, const char *where, const char *v, char *dst,
                   size_t cap) {
    if (v[0] == '/' || !x->base[0]) return copy_to(x, n, where, v, dst, cap);
    char full[1400];
    snprintf(full, sizeof(full), "%.1039s/%.300s", x->base, v);
    return copy_to(x, n, where, full, dst, cap);
}

static void base_of(struct v2 *x, const char *name) {
    x->base[0] = '\0';
    if (!name || !strcmp(name, "stdin")) return;
    const char *sl = strrchr(name, '/');
    char dir[512];
    if (sl) snprintf(dir, sizeof(dir), "%.*s", (int)(sl - name), name);
    else snprintf(dir, sizeof(dir), ".");
    if (!dir[0]) snprintf(dir, sizeof(dir), "/");
    if (dir[0] == '/') { snprintf(x->base, sizeof(x->base), "%s", dir); return; }
    char cwd[512];
    if (!getcwd(cwd, sizeof(cwd))) return;
    if (!strcmp(dir, ".")) snprintf(x->base, sizeof(x->base), "%s", cwd);
    else snprintf(x->base, sizeof(x->base), "%s/%s", cwd, dir);
}

/* ---- адреса клиентов ----------------------------------------------------------------------- */

static int hexd(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int mac_ok(const char *s) {
    for (int i = 0; i < 6; i++, s += 3) {
        if (!hexd(s[0]) || !hexd(s[1])) return 0;
        if (s[2] != (i < 5 ? ':' : '\0')) return 0;
    }
    return 1;
}

/* Адрес, подсеть или диапазон клиента — IPv4 или IPv6. С 1.9 адреса IPv6 законны
 * (docs/architecture.md, «4б»): правило IPv4 берёт записи IPv4, его v6-двойник — записи IPv6, и
 * смесь семейств в одном клиенте допустима. */
static int addr_check(struct v2 *x, const struct ynode *n, const char *where, const char *v) {
    if (!spec_line_is_addr(v))
        return fail(x, n, "%s: «%s» — не адрес IPv4 или IPv6, не подсеть и не диапазон", where, v);
    return 0;
}

static int from_push(struct v2 *x, const struct ynode *n, const char *where, struct spec_client *c,
                     const char *v) {
    if (c->from_n >= MAX_FROM) return fail(x, n, "%s: больше %d записей", where, MAX_FROM);
    return copy_to(x, n, where, v, c->from[c->from_n++], sizeof(c->from[0]));
}

/* ---- lan ---------------------------------------------------------------------------------- */

static int p_lan(struct v2 *x, const struct ynode *n) {
    struct spec *s = x->s;
    static const char *const K[] = { "devices", "addr", NULL };
    if (want_map(x, n, "lan") || keys_known(x, n, "lan", K)) return -1;
    const struct ynode *dv = ynode_get(n, "devices"), *ad = ynode_get(n, "addr");
    if (dv) {
        if (items_ok(x, dv, "lan.devices", MAX_LAN_DEV)) return -1;
        if (!n_items(dv)) return fail(x, dv, "lan.devices: пустой список — некому адресовать правила");
        s->lan_dev_n = 0;
        for (size_t i = 0; i < n_items(dv); i++) {
            const struct ynode *it = item(dv, i);
            if (!name_ok(it->str))
                return fail(x, it, "lan.devices: «%s» — имя устройства негодного состава", it->str);
            for (size_t k = 0; k < s->lan_dev_n; k++)
                if (!strcmp(s->lan_dev[k], it->str))
                    return fail(x, it, "lan.devices: устройство %s указано дважды", it->str);
            if (copy_to(x, it, "lan.devices", it->str, s->lan_dev[s->lan_dev_n], sizeof(s->lan_dev[0])))
                return -1;
            s->lan_dev_n++;
        }
    }
    if (ad) {
        if (items_ok(x, ad, "lan.addr", MAX_FROM)) return -1;
        for (size_t i = 0; i < n_items(ad); i++) {
            const struct ynode *it = item(ad, i);
            if (addr_check(x, it, "lan.addr", it->str) || from_push(x, it, "lan.addr", &s->lan, it->str))
                return -1;
        }
    }
    /* Клиентов по умолчанию описывают ЛИБО адреса, либо устройства — довод у той же проверки в
     * v1.c (from_default рядом с несколькими lan_devices). Одно устройство рядом с адресами —
     * законно: адреса выбирают клиентов, устройство тогда не участвует. */
    if (s->lan.from_n && s->lan_dev_n > 1)
        return fail(x, ad, "lan: клиенты описаны дважды — и addr, и несколько devices. Уберите "
                    "addr — устройства опишут клиентов точнее");
    return 0;
}

/* ---- clients ------------------------------------------------------------------------------ */

static int p_client(struct v2 *x, const struct ynode *key, const struct ynode *val) {
    struct spec *s = x->s;
    static const char *const K[] = { "addr", "mac", "uid", "self", "app", NULL };
    if (s->client_n >= MAX_CLIENTS) return fail(x, key, "clients: больше %d клиентов", MAX_CLIENTS);
    struct spec_client *c = &s->client[s->client_n];
    struct v2_client *f = &x->cl[s->client_n];
    memset(c, 0, sizeof(*c));
    memset(f, 0, sizeof(*f));
    if (name_of(x, key, "clients", c->name)) return -1;
    if (!strcmp(c->name, "lan"))
        return fail(x, key, "clients: имя lan занято — так называются клиенты по умолчанию (раздел lan)");
    for (size_t i = 0; i < s->client_n; i++)
        if (!strcmp(s->client[i].name, c->name))
            return fail(x, key, "clients: клиент %s описан дважды", c->name);
    char where[64];
    snprintf(where, sizeof(where), "clients.%s", c->name);
    if (want_map(x, val, where) || keys_known(x, val, where, K)) return -1;
    f->hosts = 1;
    const struct ynode *ad = ynode_get(val, "addr"), *mc = ynode_get(val, "mac"),
                       *ud = ynode_get(val, "uid"), *sf = ynode_get(val, "self"),
                       *ap = ynode_get(val, "app");
    char w[96];
    if (ad) {
        snprintf(w, sizeof(w), "%s.addr", where);
        if (items_ok(x, ad, w, MAX_FROM)) return -1;
        for (size_t i = 0; i < n_items(ad); i++) {
            const struct ynode *it = item(ad, i);
            if (addr_check(x, it, w, it->str) || from_push(x, it, w, c, it->str)) return -1;
            if (!spec_one_host(it->str)) f->hosts = 0;
            f->addr = 1;
        }
    }
    if (mc) {
        snprintf(w, sizeof(w), "%s.mac", where);
        if (items_ok(x, mc, w, MAX_FROM)) return -1;
        for (size_t i = 0; i < n_items(mc); i++) {
            const struct ynode *it = item(mc, i);
            if (!mac_ok(it->str))
                return fail(x, it, "%s: «%s» — не MAC-адрес (шесть пар шестнадцатеричных цифр через "
                            "двоеточие)", w, it->str);
            if (from_push(x, it, w, c, it->str)) return -1;
            f->mac = 1;
        }
    }
    /* «Кто» на самом телефоне — см. from_is_local в spec.h. В модели это те же строки, что пишет
     * спека v1 в from: «uid:N», «uid:N-M», «self». */
    if (ud) {
        snprintf(w, sizeof(w), "%s.uid", where);
        if (!plat()->local_channels)
            return fail(x, ud, "%s: приложения (uid) — только на телефоне", w);
        if (items_ok(x, ud, w, MAX_FROM)) return -1;
        for (size_t i = 0; i < n_items(ud); i++) {
            const struct ynode *it = item(ud, i);
            char one[64];
            unsigned lo, hi;
            snprintf(one, sizeof(one), "uid:%.50s", it->str);
            if (from_uid_range(one, &lo, &hi) != 0)
                return fail(x, it, "%s: «%s» — не UID приложения (нужно N или N-M)", w, it->str);
            if (lo == 0)
                return fail(x, it, "%s: uid 0 — это root, то есть сам движок и системные демоны; их "
                            "трафик правилом не маршрутизируется", w);
            if (lo != hi) f->hosts = 0;
            if (from_push(x, it, w, c, one)) return -1;
            f->local = 1;
        }
    }
    if (sf) {
        int on = 0;
        snprintf(w, sizeof(w), "%s.self", where);
        if (bool_of(x, sf, w, &on)) return -1;
        if (on) {
            if (!plat()->local_channels)
                return fail(x, sf, "%s: трафик самого устройства — только на телефоне", w);
            if (from_push(x, sf, w, c, "self")) return -1;
            f->local = f->self = 1;
        }
    }
    if (ap) {
        snprintf(w, sizeof(w), "%s.app", where);
        if (!plat()->local_channels)
            return fail(x, ap, "%s: приложения — только на телефоне", w);
        if (items_ok(x, ap, w, MAX_FROM)) return -1;
        unsup(x, ap, "%s — имена пакетов приложений; пока пишите uid", w);
    }
    if (!c->from_n && !ap)
        return fail(x, val, "%s: пустой клиент — нужен addr, mac, uid или self", where);
    /* nft не умеет «или» внутри правила: смешанный клиент пришлось бы разбить на два правила
     * (порядок и приоритет разошлись бы с написанным) или взять половину молча. */
    if (f->addr && f->mac)
        return fail(x, val, "%s: и addr, и mac в одном клиенте — nft не умеет «или» внутри правила; "
                    "заведите два клиента", where);
    if (f->local && (f->addr || f->mac))
        return fail(x, val, "%s: сам телефон (uid, self) и клиенты раздачи (addr, mac) — разные пути "
                    "пакета; заведите два клиента", where);
    if (f->self && c->from_n > 1)
        return fail(x, sf, "%s: self уже включает все приложения — уберите uid", where);
    s->client_n++;
    return 0;
}

/* ---- lists -------------------------------------------------------------------------------- */

static int files_of(struct v2 *x, const struct ynode *n, const char *where, const char **dst,
                    size_t *cnt) {
    if (items_ok(x, n, where, MAX_FILES)) return -1;
    for (size_t i = 0; i < n_items(n); i++) {
        const struct ynode *it = item(n, i);
        char p[256];
        if (path_of(x, it, where, it->str, p, sizeof(p))) return -1;
        const char *kept = keep(p, x->e);
        if (!kept) return wrap(x, it);
        dst[(*cnt)++] = kept;
    }
    return 0;
}

static int p_list(struct v2 *x, const struct ynode *key, const struct ynode *val) {
    struct spec *s = x->s;
    static const char *const K[] = { "srs", "prefixes_file", "domains_file", "domains", "prefixes",
                                     "proto", "ports", "all", NULL };
    if (s->list_n >= MAX_LISTS) return fail(x, key, "lists: больше %d списков", MAX_LISTS);
    struct spec_list *l = &s->list[s->list_n];
    memset(l, 0, sizeof(*l));
    if (name_of(x, key, "lists", l->name)) return -1;
    if (!strcmp(l->name, "all"))
        return fail(x, key, "lists: имя all занято — to: all значит весь трафик");
    for (size_t i = 0; i < s->list_n; i++)
        if (!strcmp(s->list[i].name, l->name))
            return fail(x, key, "lists: список %s описан дважды", l->name);
    char where[64], w[96];
    snprintf(where, sizeof(where), "lists.%s", l->name);
    if (want_map(x, val, where) || keys_known(x, val, where, K)) return -1;
    const struct ynode *n;
    if ((n = ynode_get(val, "srs"))) {
        snprintf(w, sizeof(w), "%s.srs", where);
        if (files_of(x, n, w, l->srs_files, &l->srs_n)) return -1;
    }
    if ((n = ynode_get(val, "prefixes_file"))) {
        snprintf(w, sizeof(w), "%s.prefixes_file", where);
        if (files_of(x, n, w, l->prefixes_files, &l->prefixes_n)) return -1;
    }
    if ((n = ynode_get(val, "domains_file"))) {
        snprintf(w, sizeof(w), "%s.domains_file", where);
        if (files_of(x, n, w, l->domains_files, &l->domains_n)) return -1;
    }
    /* Встроенные адреса и домены (`work: { domains: [corp.example], prefixes: [10.20.0.0/16] }`
     * в примере раздела 3). Компилятор и резолвер читают списки только файлами — потоком, не
     * загружая больших списков в память, — и встроенным записям в модели пока нет места. Форма
     * проверяется сейчас, чтобы спека не оказалась битой в тот день, когда их начнут принимать. */
    size_t inl = 0;
    static const char *const INL[] = { "domains", "prefixes", NULL };
    for (size_t a = 0; INL[a]; a++) {
        if (!(n = ynode_get(val, INL[a]))) continue;
        snprintf(w, sizeof(w), "%s.%s", where, INL[a]);
        if (items_ok(x, n, w, 65536)) return -1;
        for (size_t i = 0; i < n_items(n); i++) {
            const struct ynode *it = item(n, i);
            if (a == 1 && !spec_line_is_addr(it->str))
                return fail(x, it, "%s: «%s» — не адрес, не подсеть и не диапазон", w, it->str);
            if (a == 0 && spec_line_is_addr(it->str))
                return fail(x, it, "%s: «%s» — адрес, а не домен; ему место в prefixes", w, it->str);
        }
        inl += n_items(n);
        unsup(x, n, "встроенные %s у списка — пока только файлами: prefixes_file, domains_file, srs",
              INL[a]);
    }
    if ((n = ynode_get(val, "all"))) {
        snprintf(w, sizeof(w), "%s.all", where);
        if (bool_of(x, n, w, &l->all)) return -1;
    }
    if ((n = ynode_get(val, "proto"))) {
        const char *v;
        snprintf(w, sizeof(w), "%s.proto", where);
        if (str_of(x, n, w, &v)) return -1;
        /* `both` — записанное умолчание, как в v1: сужения по протоколу из него не выходит. */
        if (!strcmp(v, "tcp")) l->l4.proto = CH_PROTO_TCP;
        else if (!strcmp(v, "udp")) l->l4.proto = CH_PROTO_UDP;
        else if (!strcmp(v, "both")) l->l4.proto = CH_PROTO_ANY;
        else return fail(x, n, "%s: «%s» — нужен tcp, udp или both", w, v);
    }
    if ((n = ynode_get(val, "ports"))) {
        snprintf(w, sizeof(w), "%s.ports", where);
        if (items_ok(x, n, w, MAX_PORTS)) return -1;
        for (size_t i = 0; i < n_items(n); i++) {
            const struct ynode *it = item(n, i);
            struct port_range *r = &l->l4.ports[l->l4.ports_n];
            if (port_range_parse(it->str, r) != 0)
                return fail(x, it, "%s: «%s» — нужно 443 или 50000-65535, числа от 1 до 65535, начало "
                            "не больше конца", w, it->str);
            /* Пересечения ядро в множестве интервалов не примет, и отвергнет весь набор правил. */
            for (size_t k = 0; k < l->l4.ports_n; k++)
                if (l->l4.ports[k].lo <= r->hi && r->lo <= l->l4.ports[k].hi)
                    return fail(x, it, "%s: диапазоны %u-%u и %u-%u пересекаются — сложите их в один",
                                w, l->l4.ports[k].lo, l->l4.ports[k].hi, r->lo, r->hi);
            l->l4.ports_n++;
        }
    }
    int files = l->srs_n || l->prefixes_n || l->domains_n;
    if (l->all && (files || inl))
        return fail(x, val, "%s: all — весь трафик; источники рядом с ним ничего не значат", where);
    /* Порты источником совпадения не являются (довод — у той же проверки в v1.c): правило без
     * набора адресов безусловно, и «udp 50000-65535» ко всему интернету уехало бы в выход. */
    if (!l->all && !files && !inl)
        return fail(x, val, "%s: у списка нет источника — нужен srs, prefixes_file, domains_file или "
                    "all: true", where);
    s->list_n++;
    return 0;
}

/* ---- outputs ------------------------------------------------------------------------------ */

/* Ключ вида и чей он: бит kind_ops.keys и кому принадлежит — для отказа «ключ чужого вида». */
static const struct { const char *key; unsigned bit; const char *owner; } KIND_KEYS[] = {
    { "obfs",         KK_OBFS,   "kind: interface" },
    { "conf",         KK_CONF,   "kind: xsteer и kind: awg" },
    { "subscription", KK_SUB,    "kind: tunnel" },
    { "nodes",        KK_NODES,  "kind: tunnel" },
    { "transport",    KK_SUB,    "kind: tunnel" },
    { "stream",       KK_STREAM, "kind: xsteer" },
    { "stream_port",  KK_STREAM, "kind: xsteer" },
    { "strategy",     KK_OPTS,   "kind: zapret" },
    { "domain",       KK_DOMAIN, "kind: tgws" },
};
#define KIND_KEYS_N (sizeof(KIND_KEYS) / sizeof(KIND_KEYS[0]))

static const char *const GROUP_KEYS[] = { "pick", "members", "default", "tolerance", "interval",
                                          "url", "idle_timeout", "weights", NULL };

static int p_obfs(struct v2 *x, const struct ynode *n, const char *name, struct out_obfs *ob) {
    static const char *const K[] = { "mode", "server", "listen", NULL };
    char where[64];
    snprintf(where, sizeof(where), "outputs.%s.obfs", name);
    if (want_map(x, n, where) || keys_known(x, n, where, K)) return -1;
    const char *v[3] = { "", "", "" };
    for (size_t i = 0; K[i]; i++) {
        const struct ynode *it = ynode_get(n, K[i]);
        char w[96];
        snprintf(w, sizeof(w), "%s.%s", where, K[i]);
        if (it && str_of(x, it, w, &v[i])) return -1;
        if (strlen(v[i]) > 79) return fail(x, it, "%s: длиннее 79 байт", w);
    }
    if (obfs_set(name, v[0], v[1], v[2], ob, x->e) != 0) return wrap(x, n);
    return 0;
}

/* Первый проход по выходу: вид, общие поля, ключи вида (разбор — у вида), настройка группы.
 * Ссылки на другие выходы (over, members, default) — во втором проходе: цель может стоять ниже. */
static int p_output(struct v2 *x, const struct ynode *key, const struct ynode *val) {
    struct spec *s = x->s;
    if (s->out_n >= MAX_OUTPUTS) return fail(x, key, "outputs: больше %d выходов", MAX_OUTPUTS);
    size_t idx = s->out_n;
    struct output o;
    memset(&o, 0, sizeof(o));
    if (name_of(x, key, "outputs", o.name)) return -1;
    for (size_t i = 0; i < s->out_n; i++)
        if (!strcmp(s->out[i].name, o.name))
            return fail(x, key, "outputs: выход %s описан дважды", o.name);
    char where[64], w[128];
    snprintf(where, sizeof(where), "outputs.%s", o.name);
    if (want_map(x, val, where)) return -1;

    const struct ynode *kn = ynode_get(val, "kind"), *pn = ynode_get(val, "protocol");
    const char *kname, *proto = NULL;
    snprintf(w, sizeof(w), "%s.kind", where);
    if (!kn) return fail(x, val, "%s: нет kind", where);
    if (str_of(x, kn, w, &kname)) return -1;
    const struct kind_ops *kd;
    int tunnel = !strcmp(kname, "tunnel");
    if (tunnel) {
        snprintf(w, sizeof(w), "%s.protocol", where);
        if (!pn) return fail(x, val, "%s: kind: tunnel нужен protocol (сейчас есть vless)", where);
        if (str_of(x, pn, w, &proto)) return -1;
        if (!v2_tunnel_proto(proto))
            return fail(x, pn, "%s: протокол «%s» не знаю (сейчас есть vless)", w, proto);
        kd = kind_by_name(proto);
    } else if (v2_tunnel_proto(kname)) {
        return fail(x, kn, "%s: в спеке v2 туннель пишется kind: tunnel, protocol: %s", where, kname);
    } else {
        kd = kind_by_name_v2(kname);
        if (!kd)
            return fail(x, kn, "%s: неизвестный kind «%s» (есть direct, interface, tunnel, xsteer, awg, "
                        "zapret, tgws, group)", where, kname);
    }
    if (kd->absent) return fail(x, tunnel ? pn : kn, "%s: %s", where, kd->absent);
    o.kind = kd;
    int group = out_group(&o) != NULL;
    unsigned caps = kd->caps;
    if (group) group_cfg_init(&o.grp);

    struct out_keys k;
    memset(&k, 0, sizeof(k));
    k.v2 = 1;
    /* Ключи группы, у которых свой pick: tolerance, interval, url, idle_timeout — latency; weights —
     * balance. Какой pick, известно только после всех ключей (pick может стоять последним). */
    const struct ynode *lat_key = NULL, *w_key = NULL;
    for (size_t i = 0; i < ynode_len(val); i++) {
        const struct ynode *kk = ynode_key_at(val, i), *v = ynode_val_at(val, i);
        const char *ks = kk->str, *sv;
        snprintf(w, sizeof(w), "%s.%s", where, ks);
        if (!strcmp(ks, "kind")) continue;
        if (!strcmp(ks, "protocol")) {
            if (!tunnel) return fail(x, kk, "%s: protocol есть только у kind: tunnel", where);
            continue;
        }
        if (!strcmp(ks, "on_fail")) {
            /* Что делать, когда выход не работает, — у выхода с устройством, у группы и у видов
             * с меткой (zapret, tgws). У direct отказывать нечему. */
            if (!group && !(caps & (KC_DEVICE | KC_MARK)))
                return fail(x, kk, "%s: у kind: %s нет on_fail — он не может отказать", where, kd->name);
            if (str_of(x, v, w, &sv)) return -1;
            if (!strcmp(sv, "drop")) o.on_fail = FAIL_DROP;
            else if (!strcmp(sv, "direct")) o.on_fail = FAIL_DIRECT;
            else if (!strcmp(sv, "zapret") && plat()->zapret) o.on_fail = FAIL_ZAPRET;
            else if (!strcmp(sv, "zapret"))
                return fail(x, v, "%s: zapret на телефоне нет — нужен drop или direct", w);
            else if (!plat()->zapret) return fail(x, v, "%s: «%s» — нужен drop или direct", w, sv);
            else return fail(x, v, "%s: «%s» — нужен drop, direct или zapret", w, sv);
            continue;
        }
        if (!strcmp(ks, "ipv6")) {
            /* IPv6 от хоста (шаг 8 выпуска 1.10, spec.h: enum out_ipv6). off — любому выходу, чей
             * вид IPv6 несёт (interface, awg, zapret), и группе; routed и nat — только туннелю с
             * устройством (interface, awg): это свойство пира на том конце, а у группы его нет —
             * его пишут у члена. */
            if (str_of(x, v, w, &sv)) return -1;
            enum out_ipv6 m;
            if (!strcmp(sv, "routed")) m = OUT_V6_ROUTED;
            else if (!strcmp(sv, "nat")) m = OUT_V6_NAT;
            else if (!strcmp(sv, "off")) m = OUT_V6_OFF;
            else return fail(x, v, "%s: «%s» — нужен routed, nat или off", w, sv);
            if (!group && !(caps & KC_IPV6))
                return fail(x, kk, "%s: kind: %s IPv6 не несёт — его правила IPv6 и так отвергаются, "
                            "ключ ipv6 ему не нужен", where, kd->name);
            if (m != OUT_V6_OFF && group)
                return fail(x, v, "%s: %s — свойство туннеля на том конце, у группы его нет: "
                            "задайте его у члена", w, sv);
            if (m != OUT_V6_OFF && !(caps & KC_DEVICE))
                return fail(x, v, "%s: %s — только у выхода с туннелем (kind: interface, awg); "
                            "у kind: %s есть только off", w, sv, kd->name);
            o.ipv6 = m;
            x->out_ipv6[idx] = v;
            continue;
        }
        if (!strcmp(ks, "prefix")) {
            /* Префикс хоста у ipv6: routed. Что с ним не так — говорит разбор префикса; что он
             * стоит без routed — проверка после всех ключей (ipv6 может стоять и после). */
            if (str_of(x, v, w, &sv)) return -1;
            char why[200];
            if (v6pfx_parse(sv, &o.v6pfx, why, sizeof(why)) != 0) return fail(x, v, "%s: %s", w, why);
            o.v6pfx_given = 1;
            x->out_prefix[idx] = v;
            continue;
        }
        if (!strcmp(ks, "over")) {
            if (str_of(x, v, w, &sv)) return -1;
            if (!name_ok(sv)) return fail(x, v, "%s: «%s» — имя другого выхода", w, sv);
            if (copy_to(x, v, w, sv, o.over, sizeof(o.over))) return -1;
            x->out_over[idx] = v;
            continue;
        }
        if (!strcmp(ks, "device")) {
            if (group)
                return fail(x, kk, "%s: у группы нет своего устройства — оно у членов (members)", where);
            if (!(caps & KC_DEVICE))
                return fail(x, kk, "%s: у kind: %s нет устройства — трафик никуда не уводится", where,
                            kd->name);
            if (str_of(x, v, w, &sv)) return -1;
            if (!name_ok(sv)) return fail(x, v, "%s: «%s» — имя устройства негодного состава", w, sv);
            if (copy_to(x, v, w, sv, o.device, sizeof(o.device))) return -1;
            continue;
        }
        size_t gk = 0;
        while (GROUP_KEYS[gk] && strcmp(GROUP_KEYS[gk], ks)) gk++;
        if (GROUP_KEYS[gk]) {
            if (!group) return fail(x, kk, "%s: %s есть только у kind: group", where, ks);
            long lv;
            if (!strcmp(ks, "pick")) {
                if (str_of(x, v, w, &sv)) return -1;
                if (!strcmp(sv, "order")) o.grp.pick = PICK_ORDER;
                else if (!strcmp(sv, "latency")) o.grp.pick = PICK_LATENCY;
                else if (!strcmp(sv, "manual")) o.grp.pick = PICK_MANUAL;
                else if (!strcmp(sv, "balance")) o.grp.pick = PICK_BALANCE;
                else return fail(x, v, "%s: «%s» — нужен order, latency, manual или balance", w, sv);
            } else if (!strcmp(ks, "members")) {
                if (items_ok(x, v, w, MAX_MEMBERS)) return -1;
                if (!n_items(v)) return fail(x, v, "%s: у группы нет членов", w);
                x->out_members[idx] = v;
            } else if (!strcmp(ks, "default")) {
                if (str_of(x, v, w, &sv)) return -1;
                x->out_default[idx] = v;
            } else if (!strcmp(ks, "tolerance")) {
                if (long_of(x, v, w, 0, GROUP_TOL_MAX_MS, &lv)) return -1;
                o.grp.lat_tolerance_ms = (int)lv;
                lat_key = kk;
            } else if (!strcmp(ks, "interval")) {
                if (long_of(x, v, w, GROUP_INT_MIN_S, GROUP_INT_MAX_S, &lv)) return -1;
                o.grp.lat_interval_s = (int)lv;
                lat_key = kk;
            } else if (!strcmp(ks, "url")) {
                /* Адрес проверки urltest (docs/spec-v2.md). https — только в полном пакете: в
                 * steer-mini нет TLS, и адрес, который замер не сможет спросить, лучше назвать
                 * при разборе, чем молча мерить им «не измерено» у всех членов. */
                struct urltest_url u;
                char why[160];
                if (str_of(x, v, w, &sv)) return -1;
                if (urltest_url_parse(sv, &u, why, sizeof(why)) != 0)
                    return fail(x, v, "%s: %s", w, why);
                if (u.https && !urltest_https_ok())
                    return fail(x, v, "%s: https:// в этой сборке нет (steer-mini без TLS) — нужен полный "
                                "пакет steer или адрес http://", w);
                if (copy_to(x, v, w, sv, o.grp.url, sizeof(o.grp.url))) return -1;
                lat_key = kk;
            } else if (!strcmp(ks, "idle_timeout")) {
                if (long_of(x, v, w, 0, GROUP_IDLE_MAX_S, &lv)) return -1;
                o.grp.idle_timeout_s = (int)lv;
                lat_key = kk;
            } else {
                /* weights — число на каждого члена, по порядку members; сколько членов, станет
                 * известно во втором проходе — там и сверяется длина. */
                if (items_ok(x, v, w, MAX_MEMBERS)) return -1;
                for (size_t i2 = 0; i2 < n_items(v); i2++) {
                    if (long_of(x, item(v, i2), w, 1, GROUP_WEIGHT_MAX, &lv)) return -1;
                    o.grp.weight[i2] = (unsigned char)lv;
                }
                x->out_weights[idx] = v;
                w_key = kk;
            }
            continue;
        }
        size_t a = 0;
        while (a < KIND_KEYS_N && strcmp(KIND_KEYS[a].key, ks)) a++;
        if (a == KIND_KEYS_N) {
            /* Подсказка — ключи, которые у этого вида есть. */
            char list[200];
            size_t l = (size_t)snprintf(list, sizeof(list), "kind%s%s%s", tunnel ? ", protocol" : "",
                                        group || (caps & (KC_DEVICE | KC_MARK)) ? ", on_fail" : "",
                                        !group && (caps & KC_DEVICE) ? ", device, over" : "");
            if (group || (caps & KC_IPV6))
                l += (size_t)snprintf(list + l, sizeof(list) - l, ", ipv6%s",
                                      !group && (caps & KC_DEVICE) ? ", prefix" : "");
            for (size_t b = 0; b < KIND_KEYS_N && l < sizeof(list); b++)
                if (!group && (kd->keys & KIND_KEYS[b].bit))
                    l += (size_t)snprintf(list + l, sizeof(list) - l, ", %s", KIND_KEYS[b].key);
            for (size_t b = 0; group && GROUP_KEYS[b] && l < sizeof(list); b++)
                l += (size_t)snprintf(list + l, sizeof(list) - l, ", %s", GROUP_KEYS[b]);
            return fail(x, kk, "неизвестный ключ «%s» в %s (есть: %s)", ks, where, list);
        }
        if (group || !(kd->keys & KIND_KEYS[a].bit))
            return fail(x, kk, "%s: ключ %s есть только у %s", where, ks, KIND_KEYS[a].owner);
        if (!strcmp(ks, "obfs")) {
            if (p_obfs(x, v, o.name, &k.obfs)) return -1;
        } else if (!strcmp(ks, "conf")) {
            if (str_of(x, v, w, &sv) || path_of(x, v, w, sv, k.conf, sizeof(k.conf))) return -1;
        } else if (!strcmp(ks, "subscription")) {
            if (str_of(x, v, w, &sv) || path_of(x, v, w, sv, k.sub_file, sizeof(k.sub_file))) return -1;
        } else if (!strcmp(ks, "strategy")) {
            if (str_of(x, v, w, &sv) || path_of(x, v, w, sv, k.opts_file, sizeof(k.opts_file))) return -1;
        } else if (!strcmp(ks, "domain")) {
            if (str_of(x, v, w, &sv) || copy_to(x, v, w, sv, k.domain, sizeof(k.domain))) return -1;
        } else if (!strcmp(ks, "transport")) {
            if (str_of(x, v, w, &sv)) return -1;
            unsup(x, v, "%s — транспорты туннеля (ws, httpupgrade…), выпуск 1.10", w);
        } else if (!strcmp(ks, "stream")) {
            if (bool_of(x, v, w, &k.stream)) return -1;
        } else if (!strcmp(ks, "stream_port")) {
            long lv;
            if (long_of(x, v, w, 1, 65535, &lv)) return -1;
            k.stream_port = (int)lv;
        } else if (!strcmp(ks, "nodes")) {
            /* Номера — среди ПРИГОДНЫХ узлов подписки, как печатает `steer vless-nodes`. */
            if (items_ok(x, v, w, MAX_NODE_SEL)) return -1;
            for (size_t i2 = 0; i2 < n_items(v); i2++) {
                const struct ynode *it = item(v, i2);
                long lv;
                if (long_of(x, it, w, 0, 65535, &lv)) return -1;
                for (size_t b = 0; b < k.nodes_n; b++)
                    if (k.nodes[b] == (int)lv)
                        return fail(x, it, "%s: узел %ld указан дважды", w, lv);
                k.nodes[k.nodes_n++] = (int)lv;
            }
            k.node_many = 1;
        }
    }

    if (x->out_prefix[idx] && o.ipv6 != OUT_V6_ROUTED)
        return fail(x, x->out_prefix[idx], "%s: prefix — префикс хоста, он есть только у ipv6: routed",
                    where);
    if (group) {
        if (!x->out_members[idx]) return fail(x, val, "%s: у группы нужен members", where);
        if (lat_key && o.grp.pick != PICK_LATENCY)
            return fail(x, lat_key, "%s: %s — замер задержки, он есть только у pick: latency", where,
                        lat_key->str);
        if (w_key && o.grp.pick != PICK_BALANCE)
            return fail(x, w_key, "%s: weights — доли соединений, они есть только у pick: balance", where);
    } else {
        /* Разбор и проверка ключей — у вида (один разбор на оба формата, kind.h). */
        if (kd->parse && kd->parse(&o, &k, x->e) != 0) return wrap(x, key);
        if (kd->check && kd->check(s, &o, x->e) != 0) return wrap(x, key);
    }
    x->out_key[idx] = key;
    s->out[s->out_n++] = o;
    return 0;
}

static int out_idx(const struct spec *s, const char *name) {
    for (size_t i = 0; i < s->out_n; i++)
        if (!strcmp(s->out[i].name, name)) return (int)i;
    return -1;
}

/* Круг в группах: a → b → a. Обход в глубину по членам-группам; path — путь для сообщения. */
static int group_cycle(const struct spec *s, int at, int *state, int *path, int depth, int *len) {
    state[at] = 1;
    path[depth] = at;
    const struct group_cfg *g = out_group(&s->out[at]);
    for (size_t i = 0; g && i < g->members_n; i++) {
        int m = g->members[i];
        if (!out_group(&s->out[m])) continue;
        if (state[m] == 1) { path[depth + 1] = m; *len = depth + 2; return 1; }
        if (!state[m] && group_cycle(s, m, state, path, depth + 1, len)) return 1;
    }
    state[at] = 2;
    return 0;
}

/* Второй проход: ссылки выходов друг на друга. */
static int p_outputs_links(struct v2 *x) {
    struct spec *s = x->s;
    for (size_t i = 0; i < s->out_n; i++) {
        struct output *o = &s->out[i];
        if (x->out_over[i] && out_idx(s, o->over) < 0)
            return fail(x, x->out_over[i], "outputs.%s.over: выхода «%s» нет в outputs", o->name,
                        o->over);
        if (!out_group(o)) continue;
        const struct ynode *mn = x->out_members[i];
        for (size_t k = 0; k < n_items(mn); k++) {
            const struct ynode *it = item(mn, k);
            int m = out_idx(s, it->str);
            if (m < 0) return fail(x, it, "outputs.%s.members: выхода «%s» нет в outputs", o->name, it->str);
            if (m == (int)i)
                return fail(x, it, "outputs.%s.members: группа не может быть членом самой себя", o->name);
            for (size_t b = 0; b < o->grp.members_n; b++)
                if (o->grp.members[b] == m)
                    return fail(x, it, "outputs.%s.members: %s указан дважды", o->name, it->str);
            o->grp.members[o->grp.members_n++] = (unsigned short)m;
        }
        const struct ynode *dn = x->out_default[i];
        if (dn) {
            for (size_t b = 0; b < o->grp.members_n; b++)
                if (!strcmp(s->out[o->grp.members[b]].name, dn->str)) o->grp.def = (int)b;
            if (o->grp.def < 0)
                return fail(x, dn, "outputs.%s.default: «%s» — не член группы", o->name, dn->str);
            if (o->grp.pick != PICK_MANUAL)
                return fail(x, dn, "outputs.%s.default: default есть только у pick: manual", o->name);
        }
        const struct ynode *wn = x->out_weights[i];
        if (wn && n_items(wn) != o->grp.members_n)
            return fail(x, wn, "outputs.%s.weights: весов %zu, а членов %zu — по весу на каждого члена, "
                        "по порядку members", o->name, n_items(wn), o->grp.members_n);
    }
    int state[MAX_OUTPUTS] = {0}, path[MAX_OUTPUTS + 1], len = 0;
    for (size_t i = 0; i < s->out_n; i++) {
        if (!out_group(&s->out[i]) || state[i]) continue;
        if (group_cycle(s, (int)i, state, path, 0, &len)) {
            int start = 0;
            while (path[start] != path[len - 1]) start++;
            char p[400];
            size_t pl = 0;
            p[0] = '\0';
            for (int k = start; k < len && pl < sizeof(p); k++)
                pl += (size_t)snprintf(p + pl, sizeof(p) - pl, "%s%s", k > start ? " → " : "",
                                       s->out[path[k]].name);
            return fail(x, x->out_members[path[start]], "группы замыкаются в круг (%s) — выбор члена "
                        "не кончился бы никогда", p);
        }
    }
    /* Члены без устройства — отказ с местом члена; вложенные группы проверяются так же, когда
     * замкнутся (их устройство — устройство их членов). */
    for (size_t i = 0; i < s->out_n; i++) {
        const struct output *o = &s->out[i];
        if (!out_group(o)) continue;
        const struct ynode *mn = x->out_members[i];
        for (size_t k = 0; k < o->grp.members_n; k++) {
            const struct output *m = &s->out[o->grp.members[k]];
            if (!out_group(m) && !out_has_device(m))
                return fail(x, item(mn, k), "outputs.%s.members: %s — kind: %s, у него нет устройства, "
                            "выбирать группе нечего", o->name, m->name, out_kind_name(m));
        }
    }
    /* ДОНОР IPv6 ОДИН (ipv6: routed): у клиентов LAN адреса из префикса одного хоста, и адрес из
     * префикса второго первый не пропустит — какой из двух выбрать клиенту, решает его выбор адреса
     * источника, а не правило. Счёт — по записанному, а не по действующему (на телефоне routed не
     * действует): спека одна на оба случая и не должна быть годной только на одной платформе. */
    int donor = -1;
    for (size_t i = 0; i < s->out_n; i++) {
        if (s->out[i].ipv6 != OUT_V6_ROUTED) continue;
        if (donor >= 0)
            return fail(x, x->out_ipv6[i], "outputs.%s.ipv6: routed уже у выхода %s — донор IPv6 в "
                        "спеке один: адрес из префикса одного хоста другой хост не пропустит",
                        s->out[i].name, s->out[donor].name);
        donor = (int)i;
    }
    /* Кому снять IPv6 — до замыкания групп: свойства группы — пересечение out_caps членов. */
    spec_v6_resolve(s);
    /* ЗАМЫКАНИЕ — ПО ВЛОЖЕННОСТИ: сначала группы, у которых среди членов групп нет, потом те, чьи
     * члены-группы уже замкнуты, и так до конца. Свойства внешней — пересечение свойств членов, и у
     * вложенной они обязаны быть посчитаны раньше; круги отвергнуты выше, так что каждый круг
     * этого цикла замыкает хотя бы одну группу. */
    unsigned char sealed[MAX_OUTPUTS] = {0};
    for (int progress = 1; progress; ) {
        progress = 0;
        for (size_t i = 0; i < s->out_n; i++) {
            struct output *o = &s->out[i];
            if (!out_group(o) || sealed[i]) continue;
            int ready = 1;
            for (size_t k = 0; k < o->grp.members_n; k++) {
                size_t m = o->grp.members[k];
                if (m < MAX_OUTPUTS && out_group(&s->out[m]) && !sealed[m]) ready = 0;
            }
            if (!ready) continue;
            if (group_seal(s, o, x->e) != 0) return wrap(x, x->out_key[i]);
            /* Активное устройство до первого прохода сторожа — лист первого по предпочтению члена
             * (у вложенной группы — её собственное такое же, так же делает перевод v1 у пула). */
            snprintf(o->device, sizeof(o->device), "%s", s->out[o->grp.members[0]].device);
            sealed[i] = 1;
            progress = 1;
        }
    }
    return 0;
}

/* Есть ли среди выбора группы (сама она или вложенные по цепочке) pick: balance. */
static int reaches_balance(const struct spec *s, const struct output *o, int depth) {
    const struct group_cfg *g = out_group(o);
    if (!g || depth > MAX_OUTPUTS) return 0;
    if (g->pick == PICK_BALANCE) return 1;
    for (size_t k = 0; k < g->members_n; k++)
        if (g->members[k] < MAX_OUTPUTS && reaches_balance(s, &s->out[g->members[k]], depth + 1))
            return 1;
    return 0;
}

/* ---- dns ---------------------------------------------------------------------------------- */

static int p_dns(struct v2 *x, const struct ynode *n) {
    struct spec *s = x->s;
    static const char *const K[] = { "mode", "cache", "upstreams", "traceroute_hops", NULL };
    if (want_map(x, n, "dns") || keys_known(x, n, "dns", K)) return -1;
    const struct ynode *v;
    const char *sv;
    if ((v = ynode_get(n, "mode"))) {
        if (str_of(x, v, "dns.mode", &sv)) return -1;
        if (!strcmp(sv, "realip")) x->realip_default = 1;
        else if (strcmp(sv, "fakeip") != 0) return fail(x, v, "dns.mode: «%s» — нужен fakeip или realip", sv);
    }
    if ((v = ynode_get(n, "traceroute_hops")) && bool_of(x, v, "dns.traceroute_hops", &s->traceroute_hops))
        return -1;
    if ((v = ynode_get(n, "cache"))) {
        if (long_of(x, v, "dns.cache", 0, 1000000, &s->dns.cache)) return -1;
        if (s->dns.cache) unsup(x, v, "dns.cache — кэш ответов резолвера, выпуск 1.11");
    }
    if ((v = ynode_get(n, "upstreams"))) {
        if (want_map(x, v, "dns.upstreams")) return -1;
        static const char *const U[] = { "url", "out", NULL };
        for (size_t i = 0; i < ynode_len(v); i++) {
            const struct ynode *key = ynode_key_at(v, i), *val = ynode_val_at(v, i);
            if (s->dns.up_n >= MAX_DNS_UP)
                return fail(x, key, "dns.upstreams: больше %d апстримов", MAX_DNS_UP);
            struct spec_dns_up *u = &s->dns.up[s->dns.up_n];
            memset(u, 0, sizeof(*u));
            u->out = -1;
            if (name_of(x, key, "dns.upstreams", u->name)) return -1;
            char where[64], w[80];
            snprintf(where, sizeof(where), "dns.upstreams.%s", u->name);
            if (want_map(x, val, where) || keys_known(x, val, where, U)) return -1;
            const struct ynode *un = ynode_get(val, "url"), *on = ynode_get(val, "out");
            snprintf(w, sizeof(w), "%s.url", where);
            if (!un) return fail(x, val, "%s: нет url", where);
            if (str_of(x, un, w, &sv) || copy_to(x, un, w, sv, u->url, sizeof(u->url))) return -1;
            if (strncmp(sv, "https://", 8) != 0 && strncmp(sv, "tls://", 6) != 0)
                return fail(x, un, "%s: «%s» — нужен https://… (DoH) или tls://… (DoT)", w, sv);
            if (on) {
                snprintf(w, sizeof(w), "%s.out", where);
                if (str_of(x, on, w, &sv)) return -1;
                if ((u->out = out_idx(s, sv)) < 0)
                    return fail(x, on, "%s: выхода «%s» нет в outputs", w, sv);
            }
            s->dns.up_n++;
        }
        if (s->dns.up_n)
            unsup(x, v, "dns.upstreams — свой DNS у правил через выход, выпуск 1.11");
    }
    return 0;
}

/* ---- rules -------------------------------------------------------------------------------- */

static int client_idx(const struct spec *s, size_t named, const char *name) {
    for (size_t i = 0; i < named; i++) if (!strcmp(s->client[i].name, name)) return (int)i;
    return -1;
}

static int list_idx(const struct spec *s, size_t named, const char *name) {
    for (size_t i = 0; i < named; i++) if (!strcmp(s->list[i].name, name)) return (int)i;
    return -1;
}

/* Несколько списков у правила. Компилятор пока берёт у правила один список (rule_list), и если
 * списки сводятся в один без потери смысла — одно сужение, ни одного «весь трафик», — правилу
 * достаётся безымянный список-объединение: ровно то, что спека v1 пишет несколькими файлами в
 * одном канале. Иначе ссылки хранятся как есть, а спека отвергается «ещё не поддерживается». */
static int merge_lists(struct v2 *x, struct spec_rule *r, const struct ynode *tn, const char *rn) {
    struct spec *s = x->s;
    const struct spec_list *a = &s->list[r->lists[0]];
    int same = 1;
    for (size_t i = 0; i < r->lists_n; i++) {
        const struct spec_list *b = &s->list[r->lists[i]];
        if (b->all || !l4match_same(&a->l4, &b->l4)) same = 0;
    }
    if (!same) {
        unsup(x, tn, "правило %s: списки с разными proto/ports или с all в одном to — разнесите их по "
              "правилам", rn);
        return 0;
    }
    if (s->list_n >= MAX_LISTS)
        return fail(x, tn, "правило %s: списков вместе с объединёнными больше %d", rn, MAX_LISTS);
    struct spec_list *m = &s->list[s->list_n];
    memset(m, 0, sizeof(*m));
    m->l4 = a->l4;
    for (size_t i = 0; i < r->lists_n; i++) {
        const struct spec_list *b = &s->list[r->lists[i]];
        if (m->srs_n + b->srs_n > MAX_FILES || m->prefixes_n + b->prefixes_n > MAX_FILES ||
            m->domains_n + b->domains_n > MAX_FILES)
            return fail(x, tn, "правило %s: файлов одного вида в списках правила больше %d", rn, MAX_FILES);
        memcpy(m->srs_files + m->srs_n, b->srs_files, b->srs_n * sizeof(b->srs_files[0]));
        m->srs_n += b->srs_n;
        memcpy(m->prefixes_files + m->prefixes_n, b->prefixes_files,
               b->prefixes_n * sizeof(b->prefixes_files[0]));
        m->prefixes_n += b->prefixes_n;
        memcpy(m->domains_files + m->domains_n, b->domains_files,
               b->domains_n * sizeof(b->domains_files[0]));
        m->domains_n += b->domains_n;
    }
    r->lists[0] = (unsigned char)s->list_n++;
    r->lists_n = 1;
    return 0;
}

/* Несколько клиентов у правила — тот же приём: одного вида (все адреса, все MAC или все
 * приложения без self) сводятся в безымянного клиента-объединение, как `from` канала v1. */
static int merge_clients(struct v2 *x, struct spec_rule *r, const struct ynode *fn, const char *rn) {
    struct spec *s = x->s;
    const struct v2_client *a = &x->cl[r->clients[0]];
    int same = 1;
    for (size_t i = 0; i < r->clients_n; i++) {
        const struct v2_client *b = &x->cl[r->clients[i]];
        if (b->addr != a->addr || b->mac != a->mac || b->local != a->local || b->self) same = 0;
    }
    if (!same) {
        unsup(x, fn, "правило %s: клиенты разных видов (адреса, MAC, телефон) в одном for — разнесите "
              "их по правилам", rn);
        return 0;
    }
    if (s->client_n >= MAX_CLIENTS)
        return fail(x, fn, "правило %s: клиентов вместе с объединёнными больше %d", rn, MAX_CLIENTS);
    struct spec_client *m = &s->client[s->client_n];
    memset(m, 0, sizeof(*m));
    struct v2_client *mf = &x->cl[s->client_n];
    *mf = *a;
    for (size_t i = 0; i < r->clients_n; i++) {
        const struct spec_client *b = &s->client[r->clients[i]];
        if (!x->cl[r->clients[i]].hosts) mf->hosts = 0;
        for (size_t k = 0; k < b->from_n; k++) {
            size_t d = 0;
            while (d < m->from_n && strcmp(m->from[d], b->from[k])) d++;
            if (d < m->from_n) continue;
            if (m->from_n >= MAX_FROM)
                return fail(x, fn, "правило %s: у клиентов правила больше %d записей", rn, MAX_FROM);
            memcpy(m->from[m->from_n++], b->from[k], sizeof(m->from[0]));
        }
    }
    r->clients[0] = (unsigned char)s->client_n++;
    r->clients_n = 1;
    return 0;
}

static int p_rule(struct v2 *x, const struct ynode *n, size_t no) {
    struct spec *s = x->s;
    static const char *const K[] = { "name", "for", "to", "out", "resolve", "dns", "enabled", "scope",
                                     NULL };
    if (s->rule_n >= MAX_RULES) return fail(x, n, "rules: больше %d правил", MAX_RULES);
    struct spec_rule *r = &s->rule[s->rule_n];
    memset(r, 0, sizeof(*r));
    char where[64];
    snprintf(where, sizeof(where), "rules[%zu]", no);
    if (want_map(x, n, where) || keys_known(x, n, "правиле", K)) return -1;
    const struct ynode *v;
    const char *sv;
    /* Подпись, а не идентификатор: по-русски можно, кавычку нельзя (label_ok). Без имени —
     * номер правила: оно уходит в status и в журнал резолвера, и пустым быть не может. */
    if ((v = ynode_get(n, "name"))) {
        if (str_of(x, v, "name", &sv)) return -1;
        if (!label_ok(sv))
            return fail(x, v, "имя правила «%s»: нельзя кавычку, обратную косую и управляющие символы", sv);
        if (copy_to(x, v, "имя правила", sv, r->name, sizeof(r->name))) return -1;
    } else snprintf(r->name, sizeof(r->name), "rule-%zu", no + 1);
    const char *rn = r->name;
    char w[96];

    snprintf(w, sizeof(w), "правило %s: out", rn);
    if (!(v = ynode_get(n, "out"))) return fail(x, n, "правило %s: нет out — куда вести трафик", rn);
    if (str_of(x, v, w, &sv)) return -1;
    if ((r->out = out_idx(s, sv)) < 0) return fail(x, v, "правило %s: выхода «%s» нет в outputs", rn, sv);
    const struct ynode *outn = v;

    snprintf(w, sizeof(w), "правило %s: to", rn);
    const struct ynode *tn = ynode_get(n, "to");
    if (!tn) return fail(x, n, "правило %s: нет to — списки из lists или all (весь трафик)", rn);
    if (items_ok(x, tn, w, MAX_RULE_REFS)) return -1;
    if (!n_items(tn)) return fail(x, tn, "правило %s: to пустой — списки из lists или all", rn);
    int all = 0;
    for (size_t i = 0; i < n_items(tn); i++) {
        const struct ynode *it = item(tn, i);
        if (!strcmp(it->str, "all")) { all = 1; continue; }
        int li = list_idx(s, x->lists_named, it->str);
        if (li < 0) return fail(x, it, "правило %s: списка «%s» нет в lists", rn, it->str);
        for (size_t b = 0; b < r->lists_n; b++)
            if (r->lists[b] == li) return fail(x, it, "правило %s: список %s указан дважды", rn, it->str);
        r->lists[r->lists_n++] = (unsigned char)li;
    }
    if (all && n_items(tn) > 1)
        return fail(x, tn, "правило %s: all — весь трафик; другие списки рядом с ним ничего не значат", rn);

    const struct ynode *fn = ynode_get(n, "for");
    int lan = 0;
    if (fn) {
        snprintf(w, sizeof(w), "правило %s: for", rn);
        if (items_ok(x, fn, w, MAX_RULE_REFS)) return -1;
        for (size_t i = 0; i < n_items(fn); i++) {
            const struct ynode *it = item(fn, i);
            if (!strcmp(it->str, "lan")) { lan = 1; continue; }
            int ci = client_idx(s, x->clients_named, it->str);
            if (ci < 0) return fail(x, it, "правило %s: клиента «%s» нет в clients", rn, it->str);
            for (size_t b = 0; b < r->clients_n; b++)
                if (r->clients[b] == ci)
                    return fail(x, it, "правило %s: клиент %s указан дважды", rn, it->str);
            r->clients[r->clients_n++] = (unsigned char)ci;
        }
        if (lan && n_items(fn) > 1)
            return fail(x, fn, "правило %s: lan — клиенты по умолчанию; с другими клиентами в одном for "
                        "не сочетается", rn);
    }

    r->realip = x->realip_default;
    if ((v = ynode_get(n, "resolve"))) {
        snprintf(w, sizeof(w), "правило %s: resolve", rn);
        if (str_of(x, v, w, &sv)) return -1;
        if (!strcmp(sv, "realip")) r->realip = 1;
        else if (!strcmp(sv, "fakeip")) r->realip = 0;
        else return fail(x, v, "%s: «%s» — нужен fakeip или realip", w, sv);
    }
    if ((v = ynode_get(n, "dns"))) {
        snprintf(w, sizeof(w), "правило %s: dns", rn);
        if (str_of(x, v, w, &sv)) return -1;
        size_t u = 0;
        while (u < s->dns.up_n && strcmp(s->dns.up[u].name, sv)) u++;
        if (u == s->dns.up_n) return fail(x, v, "правило %s: апстрима «%s» нет в dns.upstreams", rn, sv);
        r->dns = (unsigned char)(u + 1);
    }
    if ((v = ynode_get(n, "enabled"))) {
        int on = 1;
        snprintf(w, sizeof(w), "правило %s: enabled", rn);
        if (bool_of(x, v, w, &on)) return -1;
        r->disabled = !on;
    }
    const struct ynode *sn = ynode_get(n, "scope");
    if (sn) {
        snprintf(w, sizeof(w), "правило %s: scope", rn);
        if (str_of(x, sn, w, &sv)) return -1;
        if (!strcmp(sv, "device")) r->dev_scope = 1;
        else if (strcmp(sv, "global") != 0) return fail(x, sn, "%s: «%s» — нужен device или global", w, sv);
    }

    /* Ссылки на клиентов правила до объединения — для проверок ниже. */
    unsigned char refs[MAX_RULE_REFS];
    size_t refs_n = r->clients_n;
    memcpy(refs, r->clients, sizeof(refs));
    if (r->lists_n > 1 && merge_lists(x, r, tn, rn)) return -1;
    if (r->clients_n > 1 && merge_clients(x, r, fn, rn)) return -1;

    /* Выключенное правило не проверяем по смыслу (довод — в v1.c: иначе сломанное правило нельзя
     * выключить, только удалить). Имена в нём всё равно обязаны существовать: ссылка хранится
     * номером. */
    if (!r->disabled) {
        /* Правило на устройство — приоритет ОДНОМУ хозяину, см. dev_scope в spec.h. */
        if (r->dev_scope) {
            if (!refs_n)
                return fail(x, sn, "правило %s объявлено правилом на устройство (scope: device), но в "
                            "for нет клиентов — назовите клиента с адресом или MAC", rn);
            for (size_t i = 0; i < refs_n; i++)
                if (!x->cl[refs[i]].hosts)
                    return fail(x, fn, "правило %s: правило на устройство принимает только одиночных "
                                "хозяев, а у клиента %s подсеть или диапазон — приоритет достался бы не "
                                "одному устройству, а всем в нём", rn, s->client[refs[i]].name);
        }
        /* Выход только для клиентов раздачи (мост Telegram) у правила на сам телефон стоял бы
         * применённым, ничего не делая. Почему — говорит вид. */
        const struct output *o = &s->out[r->out];
        for (size_t i = 0; i < refs_n; i++)
            if (x->cl[refs[i]].local && kind_of(o)->lan_only)
                return fail(x, outn, "правило %s: выход kind=%s работает только для клиентов раздачи — %s",
                            rn, out_kind_name(o), kind_of(o)->lan_only);
        /* balance у правил на сам телефон: разметка там — на хуке output в цепочке type route, и
         * на ядре 4.9 (раскладка legacy.c) перемаршрутизацию после метки члена из перехода по карте
         * пришлось бы переносить в каждую цепочку члена. Пока — честный отказ. */
        for (size_t i = 0; i < refs_n; i++)
            if (x->cl[refs[i]].local && reaches_balance(s, o, 0)) {
                unsup(x, outn, "правило %s: pick: balance для трафика самого телефона (uid, self)", rn);
                break;
            }
    }
    s->rule_n++;
    return 0;
}

/* ---- документ ----------------------------------------------------------------------------- */

int spec_parse_v2(const struct ydoc *d, struct spec *s, struct err *e) {
    /* static: struct v2 — десятки указателей на узлы на каждый выход и клиента, а разбор идёт
     * по разу на процесс (стек помощника на телефоне беречь, как у v1). */
    static struct v2 x;
    memset(&x, 0, sizeof(x));
    x.d = d;
    x.s = s;
    x.e = e;
    base_of(&x, ydoc_name(d));
    const struct ynode *root = ydoc_root(d), *v;
    static const char *const TOP[] = { "version", "lan", "clients", "lists", "outputs", "dns", "rules",
                                       NULL };
    if (want_map(&x, root, "спека v2") || keys_known(&x, root, "спеке", TOP)) return -1;
    long ver = 0;
    v = ynode_get(root, "version");
    if (!v) return fail(&x, root, "нет version: 2");
    if (ynode_long(v, &ver) != 0 || ver != 2)
        return fail(&x, v, "version %s не поддерживается (эта сборка понимает 2)", v->str ? v->str : "?");

    if ((v = ynode_get(root, "lan")) && p_lan(&x, v)) return -1;
    if ((v = ynode_get(root, "clients"))) {
        if (want_map(&x, v, "clients")) return -1;
        for (size_t i = 0; i < ynode_len(v); i++)
            if (p_client(&x, ynode_key_at(v, i), ynode_val_at(v, i))) return -1;
    }
    x.clients_named = s->client_n;
    if ((v = ynode_get(root, "lists"))) {
        if (want_map(&x, v, "lists")) return -1;
        for (size_t i = 0; i < ynode_len(v); i++)
            if (p_list(&x, ynode_key_at(v, i), ynode_val_at(v, i))) return -1;
    }
    x.lists_named = s->list_n;
    if ((v = ynode_get(root, "outputs"))) {
        if (want_map(&x, v, "outputs")) return -1;
        for (size_t i = 0; i < ynode_len(v); i++)
            if (p_output(&x, ynode_key_at(v, i), ynode_val_at(v, i))) return -1;
        if (p_outputs_links(&x)) return -1;
    }
    if ((v = ynode_get(root, "dns")) && p_dns(&x, v)) return -1;
    if ((v = ynode_get(root, "rules"))) {
        if (!ynode_is_null(v) && v->kind != YN_SEQ)
            return fail(&x, v, "rules — список правил «- { to: …, out: … }», а не %s", shape(v));
        for (size_t i = 0; i < ynode_len(v); i++)
            if (p_rule(&x, ynode_at(v, i), i)) return -1;
    }
    /* Петля в локальную сеть, устройство дважды в группе, подложка — общие с v1 (check.c). */
    int bad = -1;
    if (spec_check_outputs(s, "over", &bad, e) != 0)
        return bad >= 0 && bad < MAX_OUTPUTS && x.out_key[bad] ? wrap(&x, x.out_key[bad]) : -1;
    if (x.un_node)
        return fail(&x, x.un_node, "ещё не поддерживается в этой версии движка: %s", x.un_what);
    return 0;
}
