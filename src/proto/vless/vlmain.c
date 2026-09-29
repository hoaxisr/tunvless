/* Модуль VLESS: подкоманды `steer vless`, `vless-nodes` и `vless-probe`.
 *
 * Точка входа протокола. Жила в конце цикла туннеля (tunnel.c), пока цикл был сварен с VLESS;
 * при выделении стека (шаг 2 выпуска 1.10) переехала сюда без изменений в выводе и кодах
 * выхода. Отсюда модуль читает спеку и подписку, выбирает узел, заводит слежку за ним
 * (vlwatch.c) и отдаёт устройство стеку вместе с дайлером (vless_tunnel_run в vldial.c).
 *
 * В пакете роутера (1.10, шаг 4) эти команды — команды бинарника модуля steer-vless: демон
 * запускает его ребёнком (механизм prog, daemon/helpers.c), а в steerd от них остаётся заглушка
 * (cli/modcmd.c): запустить модуль, если он установлен, иначе отказ «нужен пакет steer-vless».
 * Точка входа модуля — src/modules/main_vless.c. В статических сборках (телефон, стенды) файл
 * входит в сам steerd, и команды исполняются на месте.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vless.h"
#include "client.h"
#include "vldial.h"
#include "vlwatch.h"
#include "spec.h"
#include "evline.h"
#include "jsonw.h"

/* Без слова tunnel: подъём выхода и разбор подписки — это ещё не туннель. */
#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

/* ---- подкоманда steer vless -------------------------------------------------
 *
 * Поднимает TUN для выхода kind=vless из спеки. Отдельный процесс, а не поток внутри
 * apply: apply должен завершаться, а туннель — жить. Init-скрипт держит по экземпляру
 * procd на каждый такой выход, поэтому падение одного не уносит остальные.
 */
#define MAX_NODES 128
static struct vless_node g_nodes[MAX_NODES];
/* Что нужно слежке за узлом, когда стек поднимет устройство (vl_ready). */
struct vl_ready_arg {
    const struct vless_node *nodes;
    const int *sel;
    size_t sel_n;
    int cur, checked;
};
/* Спека — значение, а не глобалы (правило 6, docs/architecture.md, раздел 2): экземпляр
 * заводит каждая точка входа (cmd_vless, cmd_vless_nodes, cmd_vless_probe) и передаёт его
 * параметром в load_nodes и underlay_setup. Выделяется по требованию, а не static в каждой из
 * трёх: struct spec — под 300 КБ, и три статических экземпляра заняли бы в bss втрое больше
 * того одного, что был общим на файл, хотя на процесс команда всегда одна. Не освобождается:
 * живёт до конца процесса, как и прежний static. */
static struct spec *spec_new(void) {
    struct spec *sp = calloc(1, sizeof(*sp));
    if (!sp) die("нет памяти под спеку", NULL);
    return sp;
}

/* Найти выход и разобрать его подписку. Одно место на все три команды: иначе «как
 * читается подписка» разошлось бы между подъёмом, списком и проверкой — а расхождение
 * здесь означало бы, что человек выбирает в интерфейсе не тот узел, который поднимется. */
/* Узлы подписки из ФАЙЛА, без выхода. Вынесено отдельно ради `vless-nodes /путь`: управляющему
 * слою нужно показать локации подписки ДО того, как на неё заведён хоть один выход — иначе
 * человек собирает выход из подписки, локаций которой не видит. */
static int load_nodes_file(const char *path, size_t *cnt, struct vless_sub_stats *st) {
    /* Подписка читается с диска: скачивание — дело управляющего слоя. */
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, LOG_W2 "%s не читается\n", path); return 2; }
    static char raw[262144], dec[262144];
    size_t n = fread(raw, 1, sizeof(raw) - 1, f);
    raw[n] = '\0';
    fclose(f);
    /* Какой это формат — решает sub.c: там же, где формат и разбирается, и там же, где это
     * можно проверить стендом. */
    const char *text = vless_sub_text(raw, n, dec, sizeof(dec));

    *cnt = vless_parse_sub(text, g_nodes, MAX_NODES, st);
    return 0;
}

static int load_nodes(struct spec *sp, const char *spec_path, const char *out_name,
                      struct output **out, size_t *cnt, struct vless_sub_stats *st) {
    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec. */
    struct err e = {0};
    if (load_spec(spec_path, sp, &e) < 0) err_die(&e);
    struct output *o = out_by_name(sp, out_name);
    if (!o) { fprintf(stderr, LOG_W2 "выхода %s нет в спеке\n", out_name); return 2; }
    /* Настройку своего выхода спрашиваем у вида: не vless — не наш. */
    const struct vless_cfg *vc = out_vless(o);
    if (!vc) {
        fprintf(stderr, LOG_W2 "выход %s не vless (kind другой)\n", out_name);
        return 2;
    }
    *out = o;
    return load_nodes_file(vc->sub_file, cnt, st);
}

/* Метка сокетов к узлам — до первого соединения, то есть и до перебора узлов: проверка узла
 * при подъёме и `vless-probe` обязаны идти тем же путём, что и сам туннель, иначе при `via`
 * проба стучалась бы напрямую и объявляла мёртвым узел, который через выход-цель жив (или
 * наоборот). Смысл метки — «вложенные выходы» в spec.h. Ставится у транспорта
 * (proto/transport/trdial.c): метит он сокеты любого протокола, не только VLESS.
 *
 * Реестр — только при via: у цели метка появляется там, а без via этот процесс реестра до
 * подъёма не трогал, и трогать его ради метки «мимо каналов» незачем. Без выхода (проба
 * файла подписки) метка — обычная «мимо каналов»: её отдаёт та же функция для выхода без via. */
static void underlay_setup(struct spec *sp, const struct output *o) {
    static const struct output none;
    if (o && o->over[0]) {
        struct err e = {0};
        if (registry_assign(sp, &e) < 0) err_die(&e);
    }
    transport_set_sock_mark(out_underlay_mark(sp, o ? o : &none), o && o->over[0]);
}

static void node_json(const struct vless_node *n, int index) {
    printf("{\"index\":%d,", index);
    printf("\"name\":"); jsonw_str(stdout, n->name);
    printf(",\"host\":"); jsonw_str(stdout, n->host);
    printf(",\"port\":%u,\"type\":", n->port);
    jsonw_str(stdout, n->type);
    printf(",\"security\":"); jsonw_str(stdout, n->security);
    printf(",\"vision\":%s", n->flow[0] ? "true" : "false");
    if (n->mode[0]) { printf(",\"mode\":"); jsonw_str(stdout, n->mode); }
    printf("}");
}

/* Ключ `transport:` спеки v2 (vless_cfg.transports в spec.h): из кандидатов остаются узлы с
 * этими транспортами, порядок предпочтения прежний. Одна функция на подъём и на `vless-probe` —
 * по той же причине, что out_node_list. Возвращает, сколько осталось. */
static size_t transport_filter(const struct output *o, const struct vless_node *nodes, int *sel,
                               size_t sel_n) {
    unsigned want = o ? o->vless.transports : 0;
    if (!want) return sel_n;
    size_t k = 0;
    for (size_t i = 0; i < sel_n; i++)
        if (tunnel_transport_bit(nodes[sel[i]].type) & want) sel[k++] = sel[i];
    return k;
}

/* Причины, по которым узлы не попали в список. Массив, а не одна строка: причин у
 * одной подписки бывает несколько, и «поддержки ws нет» рядом с «reality без pbk» —
 * это два разных действия для владельца подписки. Печатается всегда, в том числе
 * пустым: потребитель, который проверяет наличие поля, не должен отличать «причин нет»
 * от «движок старый». */
static void skipped_json(const struct vless_sub_stats *st) {
    printf(",\"skipped_reasons\":[");
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (i) putchar(',');
        printf("{\"reason\":");
        jsonw_str(stdout, st->reasons[i].reason);
        printf(",\"count\":%zu,\"example\":", st->reasons[i].count);
        jsonw_str(stdout, st->reasons[i].example);
        printf("}");
    }
    printf("]");
    /* Причин больше, чем влезло в VLESS_SKIP_REASONS. Печатается только когда есть, но
     * молчать об этом нельзя: иначе сумма count разойдётся со skipped, и читающий
     * решит, что часть узлов пропала. */
    if (st->reasons_dropped) printf(",\"skipped_other\":%zu", st->reasons_dropped);
}

/* Перечислить узлы подписки.
 *
 * Индекс здесь — это индекс среди ПРИГОДНЫХ узлов, и он же понимается движком в поле
 * `node` спеки. Одно значение слова «номер узла» на весь проект: если бы список включал
 * непригодные, человек выбрал бы номер 5, а поднялся бы другой узел — и понять это было
 * бы невозможно, потому что оба списка выглядят правдоподобно. Непригодные считаются
 * отдельно и объясняются причиной, но номеров не занимают. */
int cmd_vless_nodes(const char *spec_path, const char *out_name) {
    struct output *o = NULL;
    size_t cnt = 0;
    struct vless_sub_stats st;
    /* Аргумент с косой чертой — путь к файлу подписки, а не имя выхода: имена выходов
     * состоят из [A-Za-z0-9_.-] (см. name_ok), и косая черта в них невозможна, так что
     * спутать нечего. Тогда спека не нужна вовсе, а `chosen` пуст: выбора ещё не было. */
    int by_file = out_name && out_name[0] == '/';
    int rc = by_file ? load_nodes_file(out_name, &cnt, &st)
                     : load_nodes(spec_new(), spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;

    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->vless.sub_file);
    /* `node` — прежнее поле: один выбранный номер либо -1. Выбор из нескольких узлов оно
     * выразить не может, поэтому при нём печатается -1, а сам выбор лежит в `chosen`. Старый
     * потребитель этого поля читает то же, что читал: «узел не назначен, ищем рабочий». */
    size_t chosen_n = o ? o->vless.nodes_n : 0;
    printf(",\"node\":%d,\"chosen\":[", chosen_n == 1 ? o->vless.nodes[0] : -1);
    for (size_t i = 0; i < chosen_n; i++) printf("%s%d", i ? "," : "", o->vless.nodes[i]);
    printf("],\"usable\":%zu,\"skipped\":%zu,\"foreign\":%zu,\"nodes\":[",
           cnt, st.skipped, st.foreign);
    for (size_t i = 0; i < cnt; i++) {
        if (i) putchar(',');
        node_json(&g_nodes[i], (int)i);
    }
    printf("]");
    skipped_json(&st);
    printf("}\n");
    return 0;
}

/* Проверить узел и измерить задержку.
 *
 * node >= 0 — только этот узел. node < 0 — по порядку до первого рабочего, то есть ровно
 * то, что сделает движок при подъёме выхода.
 *
 * По одному узлу за вызов не случайно: проверка узла упирается в таймаут, и «проверить
 * все» на подписке из двадцати шести узлов заняло бы минуты — дольше, чем живёт вызов
 * ubus. Интерфейс спрашивает по одному и заполняет таблицу постепенно. */
int cmd_vless_probe(const char *spec_path, const char *out_name, int node, int timeout_s) {
    struct output *o = NULL;
    size_t cnt = 0;
    struct vless_sub_stats st;
    /* Вместо имени выхода — путь к файлу подписки, как у vless-nodes и по той же причине:
     * узлы выбирают там, где выход собирают, и подписке, на которую ещё не заведён ни один
     * выход, иначе нечем было бы ответить «какой из этих узлов живой». Без выхода нет и
     * порядка предпочтения, поэтому `--node -1` здесь значит «все по порядку подписки», а
     * не «как поднимется выход». */
    int by_file = out_name && out_name[0] == '/';
    /* Спека нужна и пробе файла: метку «мимо каналов» underlay_setup спрашивает у неё же. */
    struct spec *sp = spec_new();
    int rc = by_file ? load_nodes_file(out_name, &cnt, &st)
                     : load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    if (!cnt) {
        printf("{\"ok\":false,\"error\":\"в подписке нет пригодных узлов\","
               "\"skipped\":%zu,\"foreign\":%zu", st.skipped, st.foreign);
        skipped_json(&st);
        printf("}\n");
        return 1;
    }
    if (node >= (int)cnt) {
        printf("{\"ok\":false,\"error\":\"узла %d нет, всего %zu\"}\n", node, cnt);
        return 1;
    }

    /* node < 0 — «как поднимется выход», а поднимется он по кандидатам из спеки: при
     * выбранном подмножестве перебор идёт по нему и в его порядке. Той же функцией, что и
     * подъём, — иначе диагностика показывала бы порядок, которого не будет. */
    static int sel[MAX_NODES];
    size_t sel_n = 0;
    if (node >= 0) { sel[0] = node; sel_n = 1; }
    else if (by_file) {
        for (size_t i = 0; i < cnt && i < MAX_NODES; i++) sel[sel_n++] = (int)i;
    } else {
        sel_n = out_node_list(o, cnt, sel, MAX_NODES);
        if (!sel_n) {
            printf("{\"ok\":false,\"error\":\"выбранных узлов нет в подписке, "
                   "пригодных всего %zu\"}\n", cnt);
            return 1;
        }
        sel_n = transport_filter(o, g_nodes, sel, sel_n);
        if (!sel_n) {
            printf("{\"ok\":false,\"error\":\"среди выбранных узлов нет узлов с транспортом "
                   "из transport\"}\n");
            return 1;
        }
    }
    int found = -1;
    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->vless.sub_file);
    printf(",\"results\":[");
    for (size_t k = 0; k < sel_n; k++) {
        size_t i = (size_t)sel[k];
        char why[256] = "";
        int hs = -1, ttfb = -1;
        int pr = vless_probe_timed(&g_nodes[i], timeout_s, why, sizeof(why), &hs, &ttfb);
        if (k) putchar(',');
        printf("{\"index\":%zu,\"name\":", i);
        jsonw_str(stdout, g_nodes[i].name);
        printf(",\"type\":");
        jsonw_str(stdout, g_nodes[i].type);
        printf(",\"ok\":%s,\"handshake_ms\":%d,\"ttfb_ms\":%d,\"why\":",
               pr == 0 ? "true" : "false", hs, ttfb);
        jsonw_str(stdout, why);
        printf("}");
        if (pr == 0) { found = (int)i; if (node < 0) break; }
    }
    printf("],\"working\":%d}\n", found);
    return found >= 0 ? 0 : 1;
}

/* Ход перебора — в файл probe-<выход> (probe_report), только если о нём некому сказать иначе:
 * у ребёнка демона с --supervise есть труба событий (evline_enabled), и демон знает то же из
 * node/nonode/down — файл там не нужен никому, а флеш телефона изнашивает (probe.h). Снимается
 * запись (probe_clear) в любом режиме: удалить отсутствующий файл ничего не пишет, а оставшийся
 * от прежнего запуска под procd рассказывал бы про перебор, которого больше нет. */
static void vl_probe_report(const char *out_name, enum probe_state st, int node, int total) {
    if (!evline_enabled()) probe_report(out_name, st, node, total);
}

/* Устройство поднято (ready у stack_run, stack.h): сказать up и завести слежку за узлом.
 *
 * МАРШРУТ ВЫХОДА ЗДЕСЬ НЕ СТАВИТСЯ (1.10, шаг 3). До того клиент сам звал bind_device — код
 * демона в процессе помощника: таблица, ip rule, conntrack, набор failopen. С шага 4 модуль —
 * свой бинарник на libsteer, и маршрутизации с её моделью в нём быть не должно, а под демоном она
 * и не нужна: демон привязывает маршрут по этому же up (поле dev, evline.h) в своём процессе,
 * рядом со стражем правил и сторожем.
 *
 * БЕЗ ДЕМОНА (трубы событий нет: ручной запуск, стенды вроде tests/run-tunnel.sh, прежний `steer
 * supervise`) маршрут выхода не привязывает никто: ни этот процесс, ни сторож без демона
 * (`steer failover --loop` — проверено в сетевом пространстве: таблица остаётся с запретом apply).
 * Отказать в подъёме было бы хуже: такие запуски нужны именно туннелем, и маршрут в устройство
 * стенд ставит себе сам (`ip route … dev vl` у tests/run-tunnel.sh). Потеряна при этом только
 * связка «`steer supervise` + сторож без демона», а она в бою не живёт: на роутере и на телефоне
 * помощников держит демон (init.d/steer, steerd.rc в vendor/der — `steerd daemon --watch
 * --supervise --apply`). Об этом — одна строка в журнал, чтобы «туннель поднят, а трафика по
 * каналам нет» не пришлось разгадывать. */
static void vl_ready(void *arg, const char *dev) {
    const struct vl_ready_arg *ra = arg;
    vl_watch_start(ra->nodes, ra->sel, ra->sel_n, ra->cur, ra->checked, dev);
    if (!evline_enabled())
        fprintf(stderr, LOG_I2 "%s поднят; маршрут выхода к нему ставит демон — без демона "
                        "таблица выхода не тронута\n", dev);
}

int cmd_vless(const char *spec_path, const char *out_name) {
    evline_open();
    struct output *o = NULL;
    size_t cnt = 0;
    struct vless_sub_stats st;
    struct spec *sp = spec_new();
    int rc = load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    struct vless_node *nodes = g_nodes;
    if (!cnt) {
        /* Приговор — не только в журнал. Диагностика без него говорила «устройства нет,
         * смотрите журнал движка», то есть отправляла человека искать то, что уже известно
         * здесь (I-100). total=0 отличает «узлов в подписке нет» от «ни один не ответил». */
        vl_probe_report(out_name, PROBE_FAILED, 0, 0);
        evline_emit("down", "why", EVLINE_STR, "в подписке нет пригодных узлов",
                     (const char *)NULL);
        fprintf(stderr, LOG_W2 "в подписке нет пригодных узлов "
                        "(пропущено %zu, чужих протоколов %zu)\n", st.skipped, st.foreign);
        /* Причины — в журнал тоже, а не только в ubus: подъём выхода идёт из procd, и
         * человек, который смотрит logread, иначе видит ровно то же «пропущено 26» без
         * объяснения, из-за которого и завёлся splicicd#16. */
        for (size_t i = 0; i < st.reasons_n; i++)
            fprintf(stderr, LOG_W2 "  %s — узлов %zu%s%s\n", st.reasons[i].reason,
                    st.reasons[i].count, st.reasons[i].example[0] ? ", например " : "",
                    st.reasons[i].example);
        return 1;
    }
    fprintf(stderr, LOG_I2 "узлов %zu (пропущено %zu, чужих %zu)\n", cnt, st.skipped, st.foreign);

    /* Кандидаты в порядке предпочтения. Пустой `nodes` (и прежнее `node: -1`) означает «вся
     * подписка», выбранное подмножество — только его узлы и только в написанном порядке. Одна
     * функция на подъём и на `vless-probe`: покажи диагностика другой порядок, она объясняла
     * бы не тот перебор, который случится (см. out_node_list в kinds/vless.c). */
    static int sel[MAX_NODES];
    size_t sel_n = out_node_list(o, cnt, sel, MAX_NODES);
    if (!sel_n) {
        /* Сюда попадают только выборы, целиком уехавшие за пределы подписки: она обновилась,
         * узлов стало меньше. Перебирать вместо выбранного что попало нельзя — это увело бы
         * трафик в локацию, которую человек не выбирал, и молча.
         *
         * Приговор — СВОЙ, а не общий `failed` с total=0. Раньше здесь стояло ровно то же,
         * что при пустой подписке, и диагностика говорила «в подписке нет пригодных узлов»
         * на подписке из двадцати девяти живых узлов, где человек написал `node: 31`. Снято
         * с роутера; в запись теперь едет и номер, который он написал, и настоящее число
         * пригодных — по ним приговор читается без journal. */
        vl_probe_report(out_name, PROBE_NO_SUCH_NODE, o->vless.nodes_n ? o->vless.nodes[0] : -1, (int)cnt);
        evline_emit("nonode",
                     "node", EVLINE_INT, (long)(o->vless.nodes_n ? o->vless.nodes[0] : -1),
                     "total", EVLINE_INT, (long)cnt, (const char *)NULL);
        fprintf(stderr, LOG_W2 "выбранных узлов нет в подписке (пригодных всего %zu) — "
                        "проверьте nodes\n", cnt);
        return 1;
    }
    if (sel_n < o->vless.nodes_n)
        fprintf(stderr, LOG_W2 "узлов выбрано %zu, в подписке есть %zu — остальные номера "
                        "вне подписки\n", o->vless.nodes_n, sel_n);
    /* transport: — фильтр по транспорту узла. Не осталось никого — отказ со своей причиной, а
     * не перебор чего попало: человек написал `transport: ws`, и увести туннель на tcp-узел
     * значило бы молча сменить путь трафика (например, мимо CDN). */
    size_t before = sel_n;
    sel_n = transport_filter(o, nodes, sel, sel_n);
    if (!sel_n) {
        vl_probe_report(out_name, PROBE_FAILED, 0, 0);
        evline_emit("down", "why", EVLINE_STR, "в подписке нет узлов с транспортом из transport",
                    (const char *)NULL);
        fprintf(stderr, LOG_W2 "среди %zu выбранных узлов нет ни одного с транспортом из "
                        "transport — проверьте transport и подписку\n", before);
        return 1;
    }

    int chosen = -1;
    if (out_node_named(o)) {
        chosen = sel[0];
        /* Узел назван номером — перебора нет, и объяснять нечего. Прежняя запись снимается:
         * она осталась бы от предыдущей настройки и рассказывала бы про перебор, которого
         * больше не будет.
         *
         * Спрашивается именно «назван ли», а не «остался ли один кандидат»: кандидат
         * остаётся один и в подписке из единственного узла, и когда из трёх выбранных
         * уцелел один. По длине списка проверка там пропускалась вовсе — туннель поднимался
         * на молчащем узле, и вместо приговора возвращалось «устройства нет» (I-100). */
        probe_clear(out_name);
    } else {
        /* Перебор — то самое состояние, у которого не было имени. Устройство появится только
         * после выбора, а до тех пор его нет, и раньше это выглядело как отказ: одинаково с
         * «ни один узел не ответил» и с «выход не настроен» (I-100). Номер проверяемого узла
         * пишется ПЕРЕД проверкой: она длится до восьми секунд, и всё это время строка
         * состояния обязана называть то, что происходит сейчас.
         *
         * Счёт идёт по КАНДИДАТАМ, а не по подписке: при `nodes: [6,7,12]` человек ждёт «2 из
         * 3», а не «2 из 26» — перебираться будут три, и обещать двадцать шесть значило бы
         * назвать чужое ожидание. */
        for (size_t i = 0; i < sel_n; i++) {
            char why[256];
            vl_probe_report(out_name, PROBE_RUNNING, (int)i + 1, (int)sel_n);
            evline_emit("node", "n", EVLINE_INT, (long)(i + 1), "total", EVLINE_INT, (long)sel_n,
                        (const char *)NULL);
            if (vless_probe(&nodes[sel[i]], 8, why, sizeof(why)) == 0) {
                fprintf(stderr, LOG_I2 "выбран %s (%s)\n", nodes[sel[i]].name, why);
                chosen = sel[i];
                break;
            }
            fprintf(stderr, LOG_I2 "%s — %s\n", nodes[sel[i]].name, why);
        }
    }
    if (chosen < 0) {
        vl_probe_report(out_name, PROBE_FAILED, 0, (int)sel_n);
        evline_emit("down", "why", EVLINE_STR, "ни один узел подписки не отвечает",
                     (const char *)NULL);
        fprintf(stderr, LOG_W2 "ни один узел подписки не отвечает\n");
        return 1;
    }
    /* Узел выбран — устройство сейчас появится, и дальше о состоянии выхода говорит само
     * устройство. Запись снимается здесь, а не в vless_tunnel_run: снять её обязан тот, кто её
     * поставил, иначе на каждом пути выхода из подъёма про неё придётся помнить.
     *
     * Под демоном об узле за устройством дальше говорит слежка (vl_watch_start, vlwatch.c):
     * up с watch, down, когда узел перестал отвечать, и снова up. Заводится она не здесь, а когда
     * стек поднял устройство (vl_ready ниже): up несёт имя устройства, и по нему демон привязывает
     * маршрут выхода. Без демона — прежний up, которого никто не читает. */
    probe_clear(out_name);
    static struct vl_ready_arg ra;
    ra.nodes = nodes;
    ra.sel = sel;
    ra.sel_n = sel_n;
    ra.cur = chosen;
    ra.checked = !out_node_named(o);

    /* Реестр — чтобы узнать таблицу выхода: из неё берётся адрес устройства. Вызов
     * идемпотентен и с apply не спорит: тот же файл, те же номера. Правило 5,
     * docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал die()
     * изнутри registry_assign. */
    struct err e = {0};
    if (registry_assign(sp, &e) < 0) err_die(&e);
    return vless_tunnel_run(o, &nodes[chosen], vl_ready, &ra);
}
