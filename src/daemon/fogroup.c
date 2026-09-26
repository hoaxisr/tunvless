/* Группы выходов в сторожe (docs/architecture.md, «4в», шаг 3) и команда select.
 *
 * Проход сторожа — автомат failover.c; решения выбора — функции группы (src/kinds/group.c). Здесь
 * то, что между ними: порядок обхода с вложенностью, память групп между проходами (записи
 * хранилища fostate.h), простой группы для idle_timeout, сверка карты balance с ядром и команда
 * select. Отдельным файлом, чтобы автомат прохода менялся точечно.
 *
 * ЧЛЕНЫ v2 — ВЫХОДЫ СО СВОИМ ПРИГОВОРОМ. У группы спеки v2 члены именованные: у каждого своя
 * метка, таблица и свой проход в том же обходе (раньше группы — fog_order). Поэтому группа своих
 * устройств не пробует и не оживляет: жив ли член — это приговор его собственного прохода (тот же
 * via, та же проба, то же оживление), а лист члена — устройство, которое его проход выбрал (у
 * вложенной группы — её текущий лист). Пул v1 (безымянные члены) идёт прежним путём: пробы
 * устройств самим пулом, и его поведение не меняется ни в чём, кроме меры задержки.
 *
 * ЗАПИСИ ХРАНИЛИЩА (тексты, как файлы каталога состояния; у демона — в памяти, с копией на диск):
 *   select  — `группа член` по строке: выбор человека у pick: manual. Переживает перезапуск: файл
 *             <каталог состояния>/select рядом с реестром меток, пишется только при изменении;
 *   groups  — `группа член|- живые,через,запятую|-`: итог прохода для status и для следующего
 *             прохода (кто был выбран — у вложенных групп устройство листа неоднозначно);
 *   latency — прежняя запись замеров; у именованного члена ключ — его имя, у безымянного —
 *             устройство (fog_lat_key).
 *
 * СВЕРКА КАРТЫ balance — по факту в ядре (nfv_map_read), а не по памяти, тем же доводом, что
 * сверка маршрутизации в failover.c: apply пересоздаёт таблицу с картой «все живы», и сторож,
 * помнящий «член X мёртв, карту уже переписал», не заметил бы, что X снова получает соединения.
 * Чтение карты — один дамп netlink на группу за проход; запись — только при расхождении. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "spec.h"
#include "fostate.h"
#include "fogroup.h"
#include "nftvmap.h"
#include "nftdump.h"
#include "failover_int.h"

#define LOG_W "steer[warn] failover: "

/* ---- порядок обхода ---------------------------------------------------------------------- */

size_t fog_order(const struct spec *sp, size_t *ord) {
    unsigned char placed[MAX_OUTPUTS] = {0};
    size_t n = 0;
    for (int progress = 1; progress && n < sp->out_n; ) {
        progress = 0;
        /* Круг: все, чьи зависимости уже в порядке. Кладутся после круга, а не сразу, — так внутри
         * круга остаётся порядок спеки, и выходы одной глубины over идут как прежде. */
        size_t add[MAX_OUTPUTS], an = 0;
        for (size_t i = 0; i < sp->out_n; i++) {
            if (placed[i]) continue;
            const struct output *o = &sp->out[i];
            int ready = 1;
            const struct output *t = out_over(sp, o);
            if (t && !placed[t - sp->out]) ready = 0;
            const struct group_cfg *g = out_group(o);
            for (size_t k = 0; ready && g && k < g->members_n; k++)
                if (g->members[k] < sp->out_n && !placed[g->members[k]]) ready = 0;
            if (ready) add[an++] = i;
        }
        for (size_t k = 0; k < an; k++) {
            placed[add[k]] = 1;
            ord[n++] = add[k];
            progress = 1;
        }
    }
    /* Не бывает (круги отвергает разбор), но стенд может собрать спеку руками: остаток — как есть. */
    for (size_t i = 0; i < sp->out_n; i++)
        if (!placed[i]) ord[n++] = i;
    return n;
}

/* ---- записи ------------------------------------------------------------------------------- */

/* Прочитать запись целиком. Строка malloc'ом ("" — записи нет); NULL — нет памяти. */
static char *rec_read(struct fo_store *st, const char *name) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *out = open_memstream(&buf, &bn);
    if (!out) return NULL;
    FILE *f = st->ops->open_r(st, name);
    if (f) {
        char chunk[1024];
        size_t k;
        while ((k = fread(chunk, 1, sizeof(chunk), f)) > 0) fwrite(chunk, 1, k, out);
        fclose(f);
    }
    if (fclose(out) != 0) { free(buf); return NULL; }
    return buf;
}

/* Значение (остаток строки после первого слова) строки с первым словом key. 1 — нашлась. */
static int rec_get(const char *text, const char *key, char *val, size_t n) {
    size_t kl = strlen(key);
    for (const char *ln = text; ln && *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        if (len > kl && !strncmp(ln, key, kl) && ln[kl] == ' ') {
            size_t vl = len - kl - 1;
            if (vl >= n) vl = n - 1;
            memcpy(val, ln + kl + 1, vl);
            val[vl] = '\0';
            return 1;
        }
        ln = end ? end + 1 : NULL;
    }
    return 0;
}

/* Заменить (или дописать) строку key в записи name; line NULL — снять строку. Пишет только при
 * изменении текста. */
static void rec_set(struct fo_store *st, const char *name, const char *key, const char *line) {
    char *old = rec_read(st, name);
    if (!old) return;
    char *buf = NULL;
    size_t bn = 0;
    FILE *out = open_memstream(&buf, &bn);
    if (!out) { free(old); return; }
    size_t kl = strlen(key);
    int done = 0;
    for (const char *ln = old; *ln; ) {
        const char *end = strchr(ln, '\n');
        size_t len = end ? (size_t)(end - ln) : strlen(ln);
        int mine = len >= kl && !strncmp(ln, key, kl) && (len == kl || ln[kl] == ' ');
        if (mine) {
            if (line && !done) fprintf(out, "%s\n", line);
            done = 1;
        } else if (len) {
            fwrite(ln, 1, len, out);
            fputc('\n', out);
        }
        if (!end) break;
        ln = end + 1;
    }
    if (line && !done) fprintf(out, "%s\n", line);
    if (fclose(out) == 0 && (bn != strlen(old) || memcmp(buf, old, bn) != 0))
        st->ops->put(st, name, buf, bn);
    free(buf);
    free(old);
}

static int member_idx(const struct spec *sp, const struct group_cfg *g, const char *name) {
    for (size_t k = 0; k < g->members_n; k++)
        if (!strcmp(sp->out[g->members[k]].name, name)) return (int)k;
    return -1;
}

int fog_manual_pick(const struct spec *sp, struct fo_store *st, const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (!g || !g->members_n) return -1;
    char *text = rec_read(st, "select");
    char val[64];
    int k = -1;
    if (text && rec_get(text, go->name, val, sizeof(val))) k = member_idx(sp, g, val);
    free(text);
    if (k >= 0) return k;
    return g->def >= 0 && (size_t)g->def < g->members_n ? g->def : 0;
}

const char *fog_lat_key(const struct output *m) {
    return m->name[0] ? m->name : m->device;
}

/* ---- простой группы (idle_timeout) --------------------------------------------------------- */

int fog_idle_limit(const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (g && g->idle_timeout_s >= 0) return g->idle_timeout_s;
    /* Умолчание — по платформе: на телефоне сторож в фоне обязан не тратить батарею на замеры
     * группы, через которую ничего не идёт (решение владельца: «на телефоне проверка идёт, только
     * пока через группу идёт трафик»); полчаса — как idle_timeout у urltest sing-box. На роутере
     * питание от сети, и замер по интервалу, как было у prefer_latency. */
    return plat()->netifd ? 0 : 1800;
}

struct idle_rec {
    char name[32];
    unsigned long long pkts;
    long changed;       /* CLOCK_MONOTONIC, с: когда счётчик последний раз рос */
    int seen;
};
static struct idle_rec g_idle[MAX_OUTPUTS];

static long mono_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

int fog_idle(const struct spec *sp, const struct output *go, int limit, fo_traffic_fn fn, void *arg) {
    if (limit <= 0 || !fn) return 0;
    unsigned long long pk = 0;
    if (fn(arg, sp, go, &pk) != 0) return 0;
    struct idle_rec *r = NULL, *free_slot = NULL;
    for (size_t i = 0; i < MAX_OUTPUTS && !r; i++) {
        if (g_idle[i].seen && !strcmp(g_idle[i].name, go->name)) r = &g_idle[i];
        else if (!g_idle[i].seen && !free_slot) free_slot = &g_idle[i];
    }
    long now = mono_s();
    if (!r) {
        if (!free_slot) return 0;
        r = free_slot;
        snprintf(r->name, sizeof(r->name), "%s", go->name);
        r->seen = 1;
        r->pkts = pk;
        /* Первая встреча: отсчёт взят, трафика ещё не видели — замера нет, пока он не пойдёт. */
        r->changed = now - limit - 1;
        return 1;
    }
    if (pk != r->pkts) {
        r->pkts = pk;
        r->changed = now;
    }
    return now - r->changed > limit;
}

/* ---- balance: карта в ядре --------------------------------------------------------------- */

int fog_balance_sync(const struct spec *sp, const struct output *go, unsigned alive) {
    static int told;
    const struct group_cfg *g = out_group(go);
    if (!g || g->pick != PICK_BALANCE) return 0;
    char map[32];
    group_bal_map(go, map, sizeof(map));
    static char have[GROUP_BAL_SLOTS][NFV_CHAIN_MAX], want[GROUP_BAL_SLOTS][NFV_CHAIN_MAX];
    memset(have, 0, sizeof(have));
    memset(want, 0, sizeof(want));
    if (nfv_map_read(NFD_INET, nft_table(), map, have, GROUP_BAL_SLOTS) < 0) {
        /* Карты нет: набор правил не применён или группа не ведёт ни одного правила (карту
         * компилятор ставит только тем, в кого идут каналы). Второе — не беда, первое сторож
         * всё равно увидит по маршрутизации. */
        if (!told && errno != ENOENT) {
            told = 1;
            fprintf(stderr, LOG_W "%s: карту %s не прочитать (%s) — раздачу не сверяю\n", go->name,
                    map, strerror(errno));
        }
        return -1;
    }
    unsigned char owner[GROUP_BAL_SLOTS];
    group_balance_slots(g, alive, owner);
    for (unsigned s = 0; s < GROUP_BAL_SLOTS; s++)
        if (owner[s] != 0xff) group_bal_target(&sp->out[g->members[owner[s]]], want[s], NFV_CHAIN_MAX);
    if (!memcmp(have, want, sizeof(have))) return 0;
    if (nfv_map_write(NFD_INET, nft_table(), map, (const char (*)[NFV_CHAIN_MAX])want,
                      (const char (*)[NFV_CHAIN_MAX])have, GROUP_BAL_SLOTS) != 0) {
        fprintf(stderr, LOG_W "%s: карту %s не переписать (%s)\n", go->name, map, strerror(errno));
        return -1;
    }
    return 1;
}

/* ---- запись groups ------------------------------------------------------------------------- */

static void alive_csv(const struct spec *sp, const struct group_cfg *g, unsigned alive, char *dst,
                      size_t n) {
    size_t l = 0;
    dst[0] = '\0';
    for (size_t k = 0; k < g->members_n && l < n; k++)
        if ((alive >> k) & 1u)
            l += (size_t)snprintf(dst + l, n - l, "%s%s", l ? "," : "", sp->out[g->members[k]].name);
}

void fog_groups_save(struct fo_store *st, const struct spec *sp, const int *cur, const unsigned *alive) {
    char want[MAX_OUTPUTS * 600];
    size_t wn = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct group_cfg *g = out_group(&sp->out[i]);
        if (!group_named(g)) continue;
        char al[MAX_MEMBERS * 33];
        alive_csv(sp, g, alive[i], al, sizeof(al));
        int w = snprintf(want + wn, sizeof(want) - wn, "%s %s %s\n", sp->out[i].name,
                         cur[i] >= 0 && (size_t)cur[i] < g->members_n ? sp->out[g->members[cur[i]]].name
                                                                     : "-",
                         al[0] ? al : "-");
        if (w < 0 || (size_t)w >= sizeof(want) - wn) break;
        wn += (size_t)w;
    }
    char *have = rec_read(st, "groups");
    if (have && strlen(have) == wn && !memcmp(have, want, wn)) { free(have); return; }
    free(have);
    st->ops->put(st, "groups", want, wn);
}

int fog_groups_cur(struct fo_store *st, const struct spec *sp, const struct output *go) {
    const struct group_cfg *g = out_group(go);
    if (!g) return -1;
    char *text = rec_read(st, "groups");
    char val[700], m[64] = "";
    int k = -1;
    if (text && rec_get(text, go->name, val, sizeof(val)) && sscanf(val, "%63s", m) == 1)
        k = member_idx(sp, g, m);
    free(text);
    return k;
}

void fog_adopt(struct spec *sp, struct fo_store *st) {
    char *groups = rec_read(st, "groups"), *sel = rec_read(st, "select");
    char *lat = rec_read(st, "latency");
    for (size_t i = 0; i < sp->out_n; i++) {
        struct group_cfg *g = (struct group_cfg *)out_group(&sp->out[i]);
        if (!g) continue;
        char val[700], m[64], al[640];
        g->cur = -1;
        g->alive = 0;
        g->sel = -1;
        if (groups && rec_get(groups, sp->out[i].name, val, sizeof(val)) &&
            sscanf(val, "%63s %639s", m, al) == 2) {
            g->cur = member_idx(sp, g, m);
            for (char *tok = strtok(al, ","); tok; tok = strtok(NULL, ",")) {
                int k = member_idx(sp, g, tok);
                if (k >= 0) g->alive |= 1u << k;
            }
        }
        if (g->pick == PICK_MANUAL) {
            if (sel && rec_get(sel, sp->out[i].name, val, sizeof(val))) g->sel = member_idx(sp, g, val);
            if (g->sel < 0) g->sel = g->def >= 0 ? g->def : 0;
        }
        /* Замеры: строки `группа ключ мс отметка` (формат записи latency в failover.c). */
        for (size_t k = 0; k < MAX_MEMBERS; k++) g->lat_ms[k] = -1;
        for (const char *ln = lat; ln && *ln; ) {
            char o[32], d[32];
            int v;
            long at;
            if (sscanf(ln, "%31s %31s %d %ld", o, d, &v, &at) == 4 && !strcmp(o, sp->out[i].name))
                for (size_t k = 0; k < g->members_n; k++)
                    if (!strcmp(fog_lat_key(&sp->out[g->members[k]]), d)) g->lat_ms[k] = v;
            const char *e = strchr(ln, '\n');
            ln = e ? e + 1 : NULL;
        }
    }
    free(groups);
    free(sel);
    free(lat);
}

/* ---- select ------------------------------------------------------------------------------- */

/* Запись active: устройство выхода и серия. "" — записи нет. */
static void active_of(struct fo_store *st, const char *out, char *dev, size_t n, int *streak) {
    dev[0] = '\0';
    if (streak) *streak = 0;
    char *text = rec_read(st, "active");
    char val[96];
    if (text && rec_get(text, out, val, sizeof(val))) {
        char d[32] = "";
        int sk = 0;
        if (sscanf(val, "%31s %d", d, &sk) >= 1) {
            snprintf(dev, n, "%s", d);
            if (streak) *streak = sk;
        }
    }
    free(text);
}

static int dev_up(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", dev);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char s[16] = "";
    int up = fgets(s, sizeof(s), f) && strncmp(s, "down", 4) != 0;
    fclose(f);
    return up;
}

int fog_select(struct spec *sp, struct fo_store *st, const char *gname, const char *mname,
               int route, fo_event_fn ev, void *arg, FILE *out) {
    struct output *go = NULL;
    for (size_t i = 0; i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, gname)) go = &sp->out[i];
    if (!go || !out_group(go)) {
        fprintf(stderr, "steer: select: группы «%s» в спеке нет\n", gname);
        return 2;
    }
    const struct group_cfg *g = out_group(go);
    if (g->pick != PICK_MANUAL || !group_named(g)) {
        fprintf(stderr, "steer: select: у группы %s pick: %s — выбирает сторож, а не команда; "
                        "select — для pick: manual\n", gname, group_pick_name(g->pick));
        return 2;
    }
    int k = member_idx(sp, g, mname);
    if (k < 0) {
        fprintf(stderr, "steer: select: %s — не член группы %s\n", mname, gname);
        return 2;
    }
    char line[80];
    snprintf(line, sizeof(line), "%s %s", gname, mname);
    rec_set(st, "select", gname, line);
    if (!route) {
        fprintf(out, "steer: группа %s — выбран %s; движок выключен, выбор применится при "
                     "включении\n", gname, mname);
        return 0;
    }

    /* Лист члена и жив ли он — по памяти сторожа: приговор последнего прохода члена (запись
     * active: «-» — отказ). Записи нет (сторож ещё не проходил) — по наличию устройства. */
    const struct output *m = &sp->out[g->members[k]];
    char mdev[32], was[32];
    active_of(st, m->name, mdev, sizeof(mdev), NULL);
    int alive = strcmp(mdev, "-") != 0;
    if (!mdev[0]) {
        snprintf(mdev, sizeof(mdev), "%s", m->device);
        alive = dev_up(mdev);
    }
    active_of(st, go->name, was, sizeof(was), NULL);
    char gline[96];
    if (alive) {
        int moved = strcmp(was, mdev) != 0;
        if (moved) bind_device(go, mdev);
        snprintf(gline, sizeof(gline), "%s %s 0", go->name, mdev);
        rec_set(st, "active", go->name, gline);
        /* Событие — только если маршрут группы действительно сменился (повтор того же выбора —
         * не новость). */
        if (ev && moved) {
            struct fo_event e = { .kind = FO_EV_SWITCHED, .out = go->name,
                                  .from = was[0] && strcmp(was, "-") ? was : NULL, .to = mdev,
                                  .why = "select", .on_fail = NULL, .member = m->name, .by = "select" };
            ev(arg, &e);
        }
        fprintf(out, "steer: группа %s — выбран %s (%s)\n", gname, mname, mdev);
    } else {
        /* manual — выбор человека: молча отдать трафик другому члену значило бы решить за него.
         * Группа получает свой on_fail, пока выбранный член не поднимется (сторож вернёт трафик
         * на него сам, как только его проход скажет «жив»). */
        int moved = strcmp(was, "-") != 0;
        if (moved) fo_fail_apply(go);
        snprintf(gline, sizeof(gline), "%s - 0", go->name);
        rec_set(st, "active", go->name, gline);
        const char *of = go->on_fail == FAIL_DROP ? "drop" : go->on_fail == FAIL_ZAPRET ? "zapret"
                                                                                       : "direct";
        if (ev && moved) {
            struct fo_event e = { .kind = FO_EV_FAILED, .out = go->name,
                                  .from = was[0] && strcmp(was, "-") ? was : NULL, .to = NULL,
                                  .why = "down", .on_fail = of, .member = m->name, .by = "select" };
            ev(arg, &e);
        }
        fprintf(out, "steer: группа %s — выбран %s, но он не работает: трафик группы по on_fail=%s, "
                     "пока %s не поднимется\n", gname, mname, of, mname);
    }
    /* Запись groups — выбранный член сразу, чтобы status не ждал прохода. */
    char *text = rec_read(st, "groups");
    char val[700], cur[64] = "-", al[640] = "-";
    if (text && rec_get(text, go->name, val, sizeof(val))) sscanf(val, "%63s %639s", cur, al);
    free(text);
    snprintf(gline, sizeof(gline), "%s %s ", go->name, alive ? mname : "-");
    char full[800];
    snprintf(full, sizeof(full), "%s%s", gline, al);
    rec_set(st, "groups", go->name, full);
    return 0;
}

int cmd_select(const char *spec, const char *group, const char *member) {
    static struct spec cfg;
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    return fog_select(&cfg, &fo_store_files, group, member, 1, NULL, NULL, stdout);
}
