/* Модель спеки — то, что общее у всех её читателей и не зависит от формата файла (see spec.h
 * for why this is shared): состав имён, имена наборов nftables, что такое строка списка и «кто»
 * на самом телефоне, поиск выхода по имени и точка входа load_spec.
 *
 * Разбор ФОРМАТА — не здесь. Спека v1 (JSON со `schema: 1` или `2`, до 2.0.0) разбирается и
 * переводится в модель v2 в model/v1.c; спека v2 (YAML или JSON с `version: 2`) — в model/v2.c
 * (docs/spec-v2.md). load_spec читает файл, узнаёт формат по содержимому и отдаёт текст нужному
 * разборщику, а всё остальное в движке видит только модель: правила, списки, клиенты, выходы и
 * группы. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "spec.h"
#include "srsplan.h"
#include "obfs.h"
#include "ynode.h"
#include "v1.h"
#include "v2.h"

/* Список правила без списков — весь трафик (rule_list в spec.h). Один на процесс: правило
 * ссылается на него, а не держит свой, и сужения у него нет. */
const struct spec_list spec_list_all = { .all = 1 };


/* Состав идентификатора, пришедшего из спеки: имя выхода, имя устройства, имя канала,
 * записи lan_devices.
 *
 * Заслон стоит В ПАРСЕРЕ, а не у каждого вызова оболочки, и это принципиально. Имена
 * отсюда подставляются в командные строки в нескольких разных местах — `pgrep -f 'steer
 * obfs %s'` и `nft list chain … o_%s` в diag, имя набора в set_count, — и проверять их по
 * месту значит проверять по разу в каждом и забыть в следующем. Забыли: спека с lan_device
 * вида «x;id>/tmp/pwned;#» уезжала в `ip -4 -o addr show %s` через popen и выполняла это от
 * root, причём у ЛЮБОЙ команды, читающей спеку, потому что автоопределение подсети
 * включалось штатно. Того вызова больше нет (клиенты выбираются по имени устройства, а не
 * по выведенной подсети), но проверка от этого не менее нужна: имя устройства теперь уходит
 * в текст правил nftables. Имя выхода с кавычкой давало то же самое через diag, а diag
 * дёргает rpcd интерфейса.
 *
 * Проверенное однажды при загрузке имя безопасно везде и навсегда, включая места,
 * которых ещё нет. Это то же решение, что с адресом в explain: там проверка формы стоит
 * до подстановки, и по той же причине — подстановка непроверенной строки уже была дырой.
 *
 * Состав нарочно уже, чем позволяет ядро: буквы, цифры, `_`, `-`, `.`. Имена интерфейсов
 * Linux этим и ограничены на практике, а имя выхода придумывает человек в интерфейсе —
 * ему хватает. Пустое имя отвергается тоже: оно ломает и набор, и pgrep. */
int name_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-' || *q == '.'))
            return 0;
    return 1;
}

/* Имя КАНАЛА — не идентификатор, а подпись, которую человек читает в интерфейсе, и
 * требовать от неё латиницу нельзя: каналы в этом проекте называют по-русски, и стенд
 * с «адресами»/«доменами» — ровно тот случай. В оболочку это имя не попадает никогда:
 * комментарий в ruleset собирается из имени ГРУППЫ, а то выводится из имени выхода.
 * Дойти оно может до JSON у status и до текста ruleset, поэтому запрещено ровно то, что
 * ломает их разбор: кавычка, обратная косая и управляющие символы. Всё остальное, включая
 * любой UTF-8, разрешено. */
int label_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (*q == '"' || *q == '\\' || *q < 0x20 || *q == 0x7F) return 0;
    return 1;
}

/* ---- имя набора группы -----------------------------------------------------
 *
 * Живёт ЗДЕСЬ, а не в компиляторе, потому что имя вычисляют двое: steer.c, когда
 * генерирует набор, и dnsd.c, когда решает, в какой набор класть адрес разрешённого
 * домена. Разойдись они — резолвер наполнял бы набор, которого нет, и доменная
 * маршрутизация молча переставала бы работать. Одна функция, два вызывающих.
 *
 * Почему у имени появился различитель. Раньше имя собиралось только из выхода и вида
 * (`vpn_ip`, `vpn_dom`), а группы компилятор разделяет ещё и по списку клиентов (`from`)
 * и по режиму резолвера. Две группы получали ОДНО имя, ядро сливало их наборы в один, и
 * список, заведённый «только для телевизора», уезжал в туннель для всей сети. Никакого
 * отказа при этом не было: nft принимает два объявления одного набора.
 *
 * Различитель — порядковый номер списка клиентов в спеке, а не хэш: номер точен, а хэш
 * мог бы совпасть у двух разных списков и вернуть ту же беду тихо. Номер считается по
 * правилам в порядке спеки, поэтому оба вызывающих получают одно и то же число, не
 * сговариваясь.
 *
 * Умолчания суффикса не получают: `vpn_ip` у обычной конфигурации остаётся `vpn_ip`, и
 * на уже установленных роутерах имена наборов (а с ними и перенос счётчиков) не меняются.
 */
static int from_same(const char (*a)[64], size_t an, const char (*b)[64], size_t bn) {
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) if (strcmp(a[i], b[i]) != 0) return 0;
    return 1;
}

/* Действующий список клиентов правила — rule_who в spec.h: свой, а если его нет — клиенты по
 * умолчанию. Правило то же, что у компилятора при сборке групп. */
static const char (*rule_from(const struct spec *sp, const struct spec_rule *r, size_t *n))[64] {
    const struct spec_client *c = rule_who(sp, r);
    *n = c->from_n;
    return c->from;
}

/* Номер списка клиентов среди РАЗЛИЧНЫХ списков, встреченных в спеке, в порядке первого
 * появления. Список по умолчанию участвует в нумерации наравне с прочими: он всё равно
 * попадает в ветку без суффикса, кроме случая realip. */
static int from_disc(const struct spec *sp, const char (*from)[64], size_t from_n) {
    int idx = 0;
    for (size_t i = 0; i < sp->rule_n; i++) {
        size_t cn;
        const char (*cf)[64] = rule_from(sp, &sp->rule[i], &cn);
        if (from_same(cf, cn, from, from_n)) return idx;
        /* Считаем только первое появление каждого списка. */
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++) {
            size_t kn;
            const char (*kf)[64] = rule_from(sp, &sp->rule[k], &kn);
            seen = from_same(kf, kn, cf, cn);
        }
        if (!seen) idx++;
    }
    return idx;
}

int l4match_same(const struct l4match *a, const struct l4match *b) {
    int ae = l4match_empty(a), be = l4match_empty(b);
    if (ae || be) return ae && be;
    if (a->proto != b->proto || a->ports_n != b->ports_n) return 0;
    /* ПОРЯДОК ЗНАЧИМ, и это сознательно. Два канала с одними диапазонами, записанными в
     * разном порядке, дадут разные группы и разные наборы — то есть лишнее правило вместо
     * слияния. Цена ошибки в эту сторону — одно правило; в другую (счесть разное одним) —
     * молча поделённый набор адресов. Сортировать перед сравнением значило бы завести
     * второй порядок помимо написанного человеком, а он виден в тексте правил. */
    for (size_t i = 0; i < a->ports_n; i++)
        if (a->ports[i].lo != b->ports[i].lo || a->ports[i].hi != b->ports[i].hi) return 0;
    return 1;
}

/* Номер СУЖЕНИЯ среди различных сужений, встреченных в спеке, в порядке первого появления.
 * Нуль — сужения нет.
 *
 * Тот же приём и та же причина, что у from_disc: ядро сливает одноимённые наборы МОЛЧА, и
 * два канала одного выхода с разными портами поделили бы один набор адресов. Тогда
 * ограничение по портам либо распространилось бы на чужие адреса (сузили то, чего не
 * просили), либо пропало бы вовсе (весь TCP к Cloudflare в туннель) — в зависимости от
 * того, чьё правило встанет первым. Номер, а не хэш: номер точен, а хэш мог бы совпасть у
 * двух разных сужений и вернуть ту же беду тихо.
 *
 * Считается по спискам правил в порядке спеки (у перевода v1 — по списку на канал), поэтому
 * компилятор и резолвер получают одно и то же число, не сговариваясь. */
/* Сужение i-го правила: сужение его списка (у правила без списков — пустое). */
static const struct l4match *rule_l4(const struct spec *sp, size_t i) {
    return &rule_list(sp, &sp->rule[i])->l4;
}

/* Различные сужения клауз наборов, которых нет среди сужений правил, — в порядке появления. */
struct l4seen { const struct spec *sp; struct l4match *v; size_t n; };
static void l4seen_add(void *ctx, const struct l4match *m) {
    struct l4seen *c = ctx;
    for (size_t i = 0; i < c->sp->rule_n; i++)
        if (!l4match_empty(rule_l4(c->sp, i)) && l4match_same(rule_l4(c->sp, i), m)) return;
    for (size_t k = 0; k < c->n; k++) if (l4match_same(&c->v[k], m)) return;
    if (c->n < 256) c->v[c->n++] = *m;
}

static int l4_disc(const struct spec *sp, const struct l4match *m) {
    if (l4match_empty(m)) return 0;
    int idx = 0;
    for (size_t i = 0; i < sp->rule_n; i++) {
        const struct l4match *c = rule_l4(sp, i);
        if (l4match_empty(c)) continue;
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++)
            seen = l4match_same(rule_l4(sp, k), c);
        if (seen) continue;                 /* посчитан при первом появлении */
        idx++;
        if (l4match_same(c, m)) return idx;
    }
    /* Сужение не из канала — значит из набора .srs (у клаузы набора своё сужение, см.
     * src/model/srsplan.c). Такие нумеруются ПОСЛЕ сужений каналов, в порядке каналов, файлов и
     * клауз: номера каналов тогда не сдвигаются от того, что в спеке появился набор, и имена
     * наборов у прежних каналов — а от них зависит перенос счётчиков — остаются прежними. */
    static struct l4match seen[256];
    struct l4seen c = { sp, seen, 0 };
    for (size_t i = 0; i < sp->rule_n; i++) {
        const struct spec_list *l = rule_list(sp, &sp->rule[i]);
        if (l->srs_n) srs_list_l4_each(l, l4seen_add, &c);
    }
    for (size_t k = 0; k < c.n; k++)
        if (l4match_same(&seen[k], m)) return idx + 1 + (int)k;
    /* Недостижимо: сужение приходит из спеки или её наборов. Возвращать здесь нуль значило бы
     * отдать имя без суффикса, то есть ровно то слияние наборов, от которого функция и
     * заведена, — поэтому число, которого ни у кого нет. */
    return idx + 1 + (int)c.n;
}

void group_set_name(const struct spec *sp, char *dst, size_t n, const char *out, const char *kind,
                    const char (*from)[64], size_t from_n, int realip,
                    const struct l4match *l4) {
    /* realip различает только доменные группы: у адресных резолвер не участвует. */
    int rip = realip && !strcmp(kind, "dom");
    int pd = l4_disc(sp, l4);
    /* Ветки без сужения оставлены КАК БЫЛИ, до последнего символа формата. От имени набора
     * зависит перенос счётчиков между применениями (см. counter_find в steer.c), и
     * переименование стоило бы обнулённых объёмов у каждого канала на каждом установленном
     * роутере — при обновлении движка, которое для человека выглядит как «ничего не менял». */
    if (!pd) {
        if (!rip && from_same(from, from_n, sp->lan.from, sp->lan.from_n)) {
            snprintf(dst, n, "%.24s_%s", out, kind);
            return;
        }
        /* Выход обрезается сильнее, чтобы имя с суффиксом осталось коротким: у наборов
         * nftables на старых ядрах предел длины 32 символа. */
        snprintf(dst, n, "%.18s_%s_c%d%s", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
        return;
    }
    /* Выход обрезается ещё сильнее: суффиксов теперь два, а предел в 32 символа тот же. */
    snprintf(dst, n, "%.14s_%s_c%d%s_p%d", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", pd);
}

/* Имя СОСТАВНОГО набора канала со смешанным сужением (src/model/srsplan.c): у элементов свои
 * протокол и порты, поэтому сужения в имени нет — только выход, вид, клиенты и режим, как у
 * группы без сужения, и свой хвост «_m», чтобы с ней не совпасть. Выход обрезается до 16:
 * имя обязано уложиться в 31 символ (старые ядра). */
void group_set_name_mixed(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.16s_%s_c%d%s_m", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
}

/* Имя доп. группы канала — клауз набора с условиями, которых у канала нет (клиент, приложение,
 * исключения-подсети): номер id задаёт раскладка (номер канала * 100 + порядковый), и рядом с
 * ним остаётся место на «_x» набора исключений. */
void group_set_name_extra(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip,
                          unsigned id) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.12s_%s_c%d%s_e%u", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", id);
}

/* «адрес:порт» → адрес и порт. Живёт здесь, а не в obfs.c, потому что нужен обоим:
 * парсеру спеки при чтении и обфускатору при разборе своих аргументов, а линкуются
 * они всегда вместе. Порт по последнему двоеточию — чтобы форма не мешала будущему
 * IPv6-литералу. */
int obfs_split_hostport(const char *s, char *host, size_t hn, int *port) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    size_t hl = (size_t)(colon - s);
    if (hl + 1 > hn) return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';
    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (!end || *end || p < 1 || p > 65535) return -1;
    *port = (int)p;
    return 0;
}

/* Есть ли на верхнем уровне JSON-объекта ключ key. Читается только верхний уровень (значения
 * пропускаются js_skip), до первой неувязки: на битом тексте ответ — «что успели увидеть». Нужна
 * выбору формата, и дешевле разбора в дерево: v1 читают на каждый status. */
static int json_top_key(const char *text, const char *key) {
    struct err scratch = {0};
    struct js j = { text };
    if (js_lit(&j, '{') != 0) return 0;
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char k[64];
        if (js_str(&j, k, sizeof(k), &scratch) != 0 || js_lit(&j, ':') != 0) return 0;
        if (!strcmp(k, key)) return 1;
        if (js_skip(&j, &scratch) != 0) return 0;
        js_ws(&j);
        if (*j.p != ',') return 0;
        j.p++;
        js_ws(&j);
    }
    return 0;
}

static void spec_defaults(struct spec *s) {
    memset(s, 0, sizeof(*s));
    snprintf(s->lan_dev[0], sizeof(s->lan_dev[0]), "br-lan");
    s->lan_dev_n = 1;
}

/* Спека v2 из текста: дерево YAML (JSON читается им же) и разбор v2. */
static int load_v2(const char *buf, size_t n, const char *name, struct spec *s, struct err *e) {
    struct ydoc *d = ydoc_parse_buf(buf, n, name, e);
    if (!d) return -1;
    const struct ynode *root = ydoc_root(d);
    int rc;
    if (root && root->kind == YN_MAP && !ynode_get(root, "version") && ynode_get(root, "schema"))
        rc = ynode_err(e, d, ynode_get(root, "schema"), "%s", "спека v1 пишется JSON-объектом "
                       "({\"schema\": 1, …}); спека YAML — это v2, и начинается она с version: 2");
    else if (root && root->kind == YN_MAP && !ynode_get(root, "version"))
        rc = ynode_err(e, d, root, "%s", "нет version: 2 — спека YAML — это спека v2 "
                       "(docs/spec-v2.md); спека v1 — JSON-объект со schema");
    else
        rc = spec_parse_v2(d, s, e);
    ydoc_free(d);
    return rc;
}

/* ФАЙЛ СПЕКИ ПО УМОЛЧАНИЮ: spec.json или spec.yaml рядом (plat_spec_default). Обе сразу — отказ,
 * а не правило старшинства: какая из двух настоящая, знает только тот, кто их положил, и
 * молча читать одну значило бы, что правки во второй не действуют, а понять это нечем. Так же
 * устроены device/devices и lan_device/lan_devices в v1. Путь, названный явно (--spec), кроме
 * этих двух, читается как есть. */
static int spec_pick_default(const char **path, struct err *e) {
    const char *js = plat()->spec_path, *ym = plat_spec_yaml();
    if (strcmp(*path, js) != 0 && strcmp(*path, ym) != 0) return 0;
    int hj = access(js, F_OK) == 0, hy = access(ym, F_OK) == 0;
    if (hj && hy) {
        char msg[640];
        snprintf(msg, sizeof(msg), "две спеки: %.255s и %.255s — движок не выбирает между ними, "
                 "оставьте одну", js, ym);
        return err_set(e, "%s", msg);
    }
    if (!strcmp(*path, js) && !hj && hy) *path = ym;
    return 0;
}

int load_spec(const char *path, struct spec *s, struct err *e) {
    /* Спека — значение (правило 6): экземпляр обнуляется здесь, а не оставляется на
     * совести вызывающего, и получает те же умолчания, что раньше стояли инициализаторами
     * глобалов — один br-lan клиентским устройством, всё остальное пусто/нуль. */
    spec_defaults(s);
    if (spec_pick_default(&path, e) != 0) return -1;
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) return err_set(e, "%s: cannot open", path);
    static char buf[262144];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    if (n == sizeof(buf) - 1) {
        int c = fgetc(f);
        if (c != EOF) {
            if (f != stdin) fclose(f);
            return err_set(e, "spec too large (max 256 KiB)", NULL);
        }
    }
    buf[n] = '\0';
    if (f != stdin) fclose(f);
    /* ФОРМАТ — ПО СОДЕРЖИМОМУ, а не по имени файла: ctl apply кладёт тело в тот файл, который
     * сейчас спека, каким бы форматом тело ни было записано.
     *
     *   - текст начинается с `{` (JSON-объект) или пуст: ключ `version` наверху — спека v2
     *     (JSON тоже YAML); иначе — спека v1, с прежними отказами разбора v1 слово в слово
     *     (их сверяет снимок генератора). И `version`, и `schema` — отказ: это два формата;
     *   - всё остальное — YAML, то есть спека v2.
     * Одна поблажка: потоковый YAML `{version: 2, …}` (ключи без кавычек) начинается со скобки,
     * а JSON-разбор его не прочтёт. Если v1 отказал, `schema` наверху нет, а слово version в
     * тексте есть, — ответ даёт разбор v2. */
    const char *p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    const char *name = strcmp(path, "-") ? path : "stdin";
    if (*p == '{' || !*p) {
        int ver = json_top_key(p, "version"), sch = json_top_key(p, "schema");
        if (ver && sch)
            return err_set(e, "в спеке и version, и schema — это два формата (version: 2 — спека v2, "
                           "schema — v1); оставьте одно", NULL);
        if (!ver) {
            int rc = spec_parse_v1(buf, s, e);
            if (rc == 0 || sch || !strstr(buf, "version")) return rc;
            spec_defaults(s);
            e->msg[0] = '\0';
        }
    }
    return load_v2(buf, n, name, s, e);
}

struct output *out_by_name(const struct spec *sp, const char *n) {
    /* Возврат — НЕ const: правило 6 просит sp константным параметром (эта функция только
     * ищет), а вызывающие с изменяемой спекой (load_spec, registry_assign) правят найденный
     * выход дальше — тем же способом, каким это делал g_out[i] до перехода на struct spec.
     * Приведение снимает константность указателя, а не массива за ним: массив мутабелен
     * ровно тогда, когда мутабелен *sp у вызывающего. */
    for (size_t i = 0; i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, n)) return (struct output *)&sp->out[i];
    return NULL;
}


/* ---- что такое строка списка -------------------------------------------------------
 *
 * ЖИВЁТ ЗДЕСЬ, А НЕ В steer.c, потому что читателей стало двое. Компилятор набора правил
 * берёт из файла адресные строки (emit_elements), резолвер — доменные (ruleset_add), и с
 * гибридными списками они читают ОДИН И ТОТ ЖЕ файл. Две копии этого правила означали бы
 * строку, которую не взял никто, или строку, которую взяли оба, — и ни то ни другое не
 * заметно снаружи: набор соберётся, резолвер запустится, а часть списка просто не будет
 * действовать.
 *
 * Проверяется ФОРМА, а не значения октетов: `1.1.1.1` и `8.8.8.0/24` адреса, `youtube.com`
 * нет. Строка вроде `123.456.789.0` формой проходит, а адресом не является — её отвергнет
 * nft, и это правильное место для такого отказа: там она названа по имени, а угадывать
 * здесь значило бы завести второй разборщик адресов рядом с ядерным. */
static int addr_half_ok(const char *s, const char *end) {
    int digits = 0, dots = 0, slash = 0;
    for (const char *p = s; p < end; p++) {
        if (*p >= '0' && *p <= '9') { digits++; continue; }
        if (*p == '.') { dots++; continue; }
        if (*p == '/') { slash++; continue; }
        return 0;                       /* буква, двоеточие — это не IPv4 */
    }
    return digits > 0 && dots == 3 && slash <= 1;
}

/* Диапазон здесь обязателен, и это не расширение ради полноты: `steer fit` сам ВЫДАЁТ
 * диапазоны — два соседних адреса, не складывающихся в выровненный префикс, объединяются
 * именно так (emit_range в aggregate.c). Раньше дефис отвергался, поэтому подогнанный
 * список, поданный каналу, терял такие строки целиком. */
/* Одиночный хозяин: адрес без маски, адрес с /32 или MAC. Всё остальное — подсеть или не
 * адрес вовсе.
 *
 * Нужно правилу на устройство: приоритет там даётся ОДНОМУ хозяину, и подсеть в этом месте
 * означала бы приоритет для всех в ней. Проверяется форма, а не значения октетов, — по той
 * же причине, что у spec_line_is_addr ниже. */
int spec_one_host(const char *s) {
    if (!s || !*s) return 0;
    /* MAC: шесть пар шестнадцатеричных через двоеточие. Точную форму проверяет is_mac в
     * генераторе; здесь достаточно отличить его от адреса — двоеточие в IPv4 не бывает. */
    if (strchr(s, ':')) return 1;
    const char *sl = strchr(s, '/');
    if (sl && strcmp(sl, "/32") != 0) return 0;
    char buf[64];
    size_t n = sl ? (size_t)(sl - s) : strlen(s);
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return spec_line_is_addr(buf) && !strchr(buf, '-');
}

int from_is_local(const char *s) {
    return s && (!strcmp(s, "self") || !strncmp(s, "uid:", 4));
}

int from_uid_range(const char *s, unsigned *lo, unsigned *hi) {
    if (!s || strncmp(s, "uid:", 4)) return -1;
    const char *p = s + 4;
    unsigned long a, b;
    char *end;
    if (*p < '0' || *p > '9') return -1;
    a = strtoul(p, &end, 10);
    if (*end == '-') {
        p = end + 1;
        if (*p < '0' || *p > '9') return -1;
        b = strtoul(p, &end, 10);
    } else {
        b = a;
    }
    /* UID ядра — 32 бита, но (uid_t)-1 означает «нет» и в правило попадать не должен. */
    if (*end || a > 0x7fffffffUL || b > 0x7fffffffUL || a > b) return -1;
    *lo = (unsigned)a;
    *hi = (unsigned)b;
    return 0;
}

int spec_line_is_addr(const char *s) {
    const char *dash = strchr(s, '-');
    const char *end = s + strlen(s);
    if (!dash) return addr_half_ok(s, end);
    /* Ровно один дефис, и обе половины — адреса. */
    if (strchr(dash + 1, '-')) return 0;
    return addr_half_ok(s, dash) && addr_half_ok(dash + 1, end);
}
