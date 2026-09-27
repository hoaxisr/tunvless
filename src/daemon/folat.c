/* Замер групп pick: latency (urltest) своими таймерами цикла демона (docs/architecture.md, «4в»).
 *
 * ЗАЧЕМ СВОИ ТАЙМЕРЫ. Прежде замер шёл внутри прохода сторожа: проход видел, что запись замеров
 * старше `interval` группы, и мерил всех членов. Проход идёт раз в период (60 с), поэтому
 * `interval: 10` на деле значил 60, а смена быстрого члена ждала ближайшего прохода. Теперь у
 * каждой группы latency в демоне свой таймер на её интервал: замер идёт, когда пришёл его срок, а
 * не когда сторож проходит, и проход сторожа зовётся внеочередным ТОЛЬКО если замер меняет выбор —
 * лучший член другой, и выигрыш больше допуска (тот же гистерезис, что у прохода:
 * group_latency_pick и group_latency_keep в src/kinds/group.c). Замер, который выбор не меняет,
 * только обновляет запись: проход ради него не нужен.
 *
 * Проход в демоне сам не меряет по сроку (fo_pass_lat_extern в failover.c): только если у живого
 * члена замера нет вовсе — первый проход после старта или член только что ожил. Так первый выбор
 * делается по замеру сразу, без лишнего переключения «по порядку, потом на быстрого», и замер не
 * идёт дважды — проходом и таймером. `steer failover` (один проход на процесс) меряет по-прежнему
 * в проходе: расписания у него нет.
 *
 * idle_timeout — как у прохода (fog_idle, счётчики правил каналов по netlink): без трафика через
 * группу таймер тикает, но запросов не шлёт. Выключенный движок — ни одного таймера (folat_stop):
 * требование батареи телефона то же, что у сторожа.
 *
 * СПЕКА НЕ ХРАНИТСЯ. apply посреди замера заменяет спеку демона (и освобождает прежнюю), поэтому
 * замер держит только имя группы и ключи членов, а спеку берёт у демона на каждом шаге; группа
 * сменила состав или ушла — замер выбрасывается.
 *
 * ПО IPv4 И IPv6. Выбор члена один на оба семейства, и прежде замер шёл только по IPv4: путь IPv4
 * есть у каждого члена, IPv6 — не у всех. Но группа, у которой IPv6 несёт каждый живой член
 * (KC_IPV6: у правила группы есть двойник IPv6, и клиенты ходят через неё по обоим семействам),
 * меряется по обоим — запросом из сокета AF_INET6 с меткой члена к адресу из AAAA (urltest.c).
 * Выбор — по ХУДШЕМУ из двух у каждого члена (group_latency_score): член, быстрый по IPv4, но
 * медленный или глухой по IPv6, половине соединений клиента хуже того, кто ровен по обоим, а
 * выбор «по лучшему» или «по IPv4» отдал бы группу именно ему. Если по IPv6 не ответил никто
 * (у адреса проверки нет AAAA, туннели не выпускают IPv6 наружу) — выбор по IPv4: мерить нечем, и
 * наказывать за это всех членов незачем. Пул v1 (безымянные члены без своей метки) меряется, как
 * прежде, только по IPv4: привязка сокета к устройству ведёт IPv6 по main, а не по таблице члена.
 * status показывает обе задержки (latency4, latency6) рядом с той, по которой выбирают. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>

#include "spec.h"
#include "loop.h"
#include "fostate.h"
#include "fogroup.h"
#include "folat.h"
#include "urltest.h"
#include "grpurl.h"
#include "failover_int.h"

static long mono_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec;
}

/* ---- запись latency ---------------------------------------------------------------------- */

/* Разобрать строку записи. 1 — строка годна. */
static int rec_line(const char *ln, char *o, char *k, struct folat_rec *r) {
    int ms4 = -2, ms6 = -2;
    int got = sscanf(ln, "%31s %31s %d %ld %d %d", o, k, &r->ms, &r->at, &ms4, &ms6);
    if (got < 4) return 0;
    r->ms4 = got >= 6 ? ms4 : -2;
    r->ms6 = got >= 6 ? ms6 : -2;
    return 1;
}

int folat_rec_get(struct fo_store *st, const char *out, const char *key, struct folat_rec *r) {
    FILE *f = st->ops->open_r(st, "latency");
    if (!f) return 0;
    char ln[160], o[32], k[32];
    struct folat_rec x;
    int found = 0;
    while (fgets(ln, sizeof(ln), f))
        if (rec_line(ln, o, k, &x) && !strcmp(o, out) && !strcmp(k, key)) { *r = x; found = 1; }
    fclose(f);
    return found;
}

void folat_rec_put(struct fo_store *st, const char *out, const struct output *const *m,
                   const struct folat_rec *r, size_t n, int keep_failed) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *f = open_memstream(&buf, &bn);
    if (!f) return;
    FILE *old = st->ops->open_r(st, "latency");
    if (old) {
        char ln[160], o[32], k[32];
        struct folat_rec x;
        while (fgets(ln, sizeof(ln), old)) {
            if (!rec_line(ln, o, k, &x) || !strcmp(o, out)) continue;
            fputs(ln, f);
            if (!strchr(ln, '\n')) fputc('\n', f);
        }
        fclose(old);
    }
    /* Ключ члена — устройство у безымянного члена пула v1 (как было) и имя у именованного члена
     * группы v2: у вложенной группы устройство листа меняется, а член — нет (fog_lat_key). */
    for (size_t k = 0; k < n; k++) {
        if (r[k].ms == -2 || (r[k].ms < 0 && !keep_failed)) continue;
        fprintf(f, "%s %s %d %ld", out, fog_lat_key(m[k]), r[k].ms < 0 ? -1 : r[k].ms, r[k].at);
        if (r[k].ms4 != -2 || r[k].ms6 != -2) fprintf(f, " %d %d", r[k].ms4, r[k].ms6);
        fputc('\n', f);
    }
    if (fclose(f) == 0) st->ops->put(st, "latency", buf, bn);
    free(buf);
}

/* ---- замер члена ----------------------------------------------------------------------------- */

int folat_want_v6(const struct spec *sp, const struct output *go, unsigned alive) {
    const struct group_cfg *g = out_group(go);
    if (!g || !group_named(g) || !alive) return 0;
    for (size_t k = 0; k < g->members_n; k++)
        if (((alive >> k) & 1u) && !out_route6(&sp->out[g->members[k]])) return 0;
    return 1;
}

void folat_score(const int *ms4, const int *ms6, size_t n, int v6, int *score) {
    if (v6) {
        group_latency_score(ms4, ms6, n, score);
        return;
    }
    for (size_t k = 0; k < n; k++) score[k] = ms4[k] >= 0 ? ms4[k] : -1;
}

struct folat_m {
    struct urltest *u4, *u6;
    int ms4, ms6, left;
    folat_m_cb cb;
    void *arg;
};

static void fm_done(struct folat_m *fm) {
    if (--fm->left > 0) return;
    folat_m_cb cb = fm->cb;
    void *arg = fm->arg;
    int a = fm->ms4, b = fm->ms6;
    free(fm);
    cb(arg, a, b);
}

static void fm_cb4(void *arg, int ms) {
    struct folat_m *fm = arg;
    fm->u4 = NULL;
    fm->ms4 = ms;
    fm_done(fm);
}

static void fm_cb6(void *arg, int ms) {
    struct folat_m *fm = arg;
    fm->u6 = NULL;
    fm->ms6 = ms;
    fm_done(fm);
}

struct folat_m *folat_member(struct loop *l, const struct spec *sp, const struct output *go,
                             const struct output *m, const char *dev, struct fo_hsrc *hs, int v6,
                             folat_m_cb cb, void *arg, int *ms4, int *ms6) {
    *ms4 = -1;
    *ms6 = v6 ? -1 : -2;
    if (g_latency_probe) { *ms4 = g_latency_probe(sp, go, dev); *ms6 = -2; return NULL; }
    if (!device_present(dev)) return NULL;
    const struct group_cfg *g = out_group(go);
    uint32_t mark = m && m >= sp->out && m < sp->out + MAX_OUTPUTS ? m->mark : 0;
    const struct output *o = out_for_device(sp, m && mark ? m : go, dev);
    const struct kind_ops *k = kind_of(o);
    /* Своя мера у вида (xsteer не меряется: его путь — хаб, а не выход в интернет). */
    if (k->latency) { *ms4 = k->latency(sp, o, dev); *ms6 = -2; return NULL; }
    /* И туннель xsteer, поднятый netifd, — по тому же доводу, что у вида xsteer: мерить его нечем,
     * а число из пробы наружу означало бы не задержку туннеля, а наличие интернета у хаба. */
    if (hs && hs->ops->xsdev(hs, dev, NULL, NULL)) { *ms6 = -2; return NULL; }
    if (!mark) {                        /* безымянный член пула v1 — только IPv4 (шапка) */
        v6 = 0;
        *ms6 = -2;
    }
    const char *url = g && g->url[0] ? g->url : GROUP_URL_DEFAULT;
    struct folat_m *fm = calloc(1, sizeof(*fm));
    if (!fm) return NULL;
    fm->cb = cb;
    fm->arg = arg;
    fm->ms4 = -1;
    fm->ms6 = v6 ? -1 : -2;
    int r;
    fm->u4 = urltest_start(l, url, AF_INET, mark, mark ? NULL : dev, FOLAT_TIMEOUT_MS, fm_cb4, fm, &r);
    if (fm->u4) fm->left++;
    else fm->ms4 = r;
    if (v6) {
        fm->u6 = urltest_start(l, url, AF_INET6, mark, NULL, FOLAT_TIMEOUT_MS, fm_cb6, fm, &r);
        if (fm->u6) fm->left++;
        else fm->ms6 = r;
    }
    if (!fm->left) {
        *ms4 = fm->ms4;
        *ms6 = fm->ms6;
        free(fm);
        return NULL;
    }
    return fm;
}

void folat_member_cancel(struct folat_m *fm) {
    if (!fm) return;
    urltest_cancel(fm->u4);
    urltest_cancel(fm->u6);
    free(fm);
}

/* ---- расписание ------------------------------------------------------------------------------ */

struct fl_grp {
    int used;
    char name[32];
    struct folat *f;
    struct loop_timer *tm;
    /* Идущий замер: ключи членов на момент начала (сверка в конце), кого мерить, итоги. */
    int running;
    size_t n, k;
    char key[MAX_MEMBERS][32];
    unsigned todo;
    int v6;
    int ms4[MAX_MEMBERS], ms6[MAX_MEMBERS];
    struct folat_m *fm;
};

struct folat {
    struct folat_conf c;
    struct fl_grp g[MAX_OUTPUTS];
    unsigned long rounds;
};

/* Группа по имени в спеке прямо сейчас — только latency с двумя членами и больше. */
static const struct output *fl_group(const struct spec *sp, const char *name) {
    if (!sp) return NULL;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        const struct group_cfg *g = out_group(o);
        if (strcmp(o->name, name) || !g || g->pick != PICK_LATENCY || g->members_n < 2) continue;
        return o;
    }
    return NULL;
}

static long fl_interval_ms(const struct output *go) {
    const struct group_cfg *g = out_group(go);
    long s = g && g->lat_interval_s > 0 ? g->lat_interval_s : FOLAT_INTERVAL_S;
    return s * 1000L;
}

static void fl_rearm(struct fl_grp *g, const struct output *go) {
    loop_timer_set(g->tm, go ? fl_interval_ms(go) : FOLAT_INTERVAL_S * 1000L);
}

static void fl_abort(struct fl_grp *g) {
    folat_member_cancel(g->fm);
    g->fm = NULL;
    g->running = 0;
}

/* Члены группы go сейчас те же, что в начале замера? */
static int fl_same(const struct fl_grp *g, const struct spec *sp, const struct output *go,
                   const struct output **cand) {
    size_t n = out_members(sp, go, cand, MAX_MEMBERS);
    if (n != g->n) return 0;
    for (size_t k = 0; k < n; k++)
        if (strcmp(fog_lat_key(cand[k]), g->key[k])) return 0;
    return 1;
}

static void fl_finish(struct fl_grp *g) {
    struct folat *f = g->f;
    g->running = 0;
    f->rounds++;
    const struct spec *sp = f->c.spec(f->c.arg);
    const struct output *go = fl_group(sp, g->name);
    const struct output *cand[MAX_MEMBERS];
    if (!go || !fl_same(g, sp, go, cand)) { fl_rearm(g, go); return; }
    const struct group_cfg *gc = out_group(go);
    int score[MAX_MEMBERS];
    folat_score(g->ms4, g->ms6, g->n, g->v6, score);
    struct folat_rec rec[MAX_MEMBERS];
    long now = mono_s();
    for (size_t k = 0; k < g->n; k++) {
        int mine = (g->todo >> k) & 1u;
        rec[k].ms = mine ? score[k] : -2;
        rec[k].ms4 = mine && g->v6 ? g->ms4[k] : -2;
        rec[k].ms6 = mine && g->v6 ? g->ms6[k] : -2;
        rec[k].at = now;
        if (!mine) score[k] = -1;
    }
    folat_rec_put(f->c.st, g->name, cand, rec, g->n, 1);

    /* Сменил бы проход выбор? Тот же гистерезис, что у прохода (S_LAT_C в failover.c): лучший с
     * допуском, а с живого текущего — только при выигрыше больше допуска. */
    int cur = -1;
    char dev[32];
    active_get_st(f->c.st, go->name, dev, sizeof(dev));
    if (dev[0] && strcmp(dev, "-") != 0) {
        if (group_named(gc)) {
            cur = fog_groups_cur(f->c.st, sp, go);
        } else {
            for (size_t k = 0; k < g->n && cur < 0; k++)
                if (!strcmp(cand[k]->device, dev)) cur = (int)k;
        }
    }
    int tol = gc->lat_tolerance_ms > 0 ? gc->lat_tolerance_ms : FOLAT_TOLERANCE_MS;
    int best = -1;
    int pick = group_latency_pick(score, g->n, tol, &best);
    if (cur >= 0 && pick >= 0 && pick != cur &&
        !(score[cur] >= 0 && group_latency_keep(score, cur, pick, tol)) && f->c.kick)
        f->c.kick(f->c.arg, g->name);
    fl_rearm(g, go);
}

static void fl_next(struct fl_grp *g);

static void fl_member_cb(void *arg, int ms4, int ms6) {
    struct fl_grp *g = arg;
    g->fm = NULL;
    g->ms4[g->k] = ms4;
    g->ms6[g->k] = ms6;
    g->k++;
    fl_next(g);
}

static void fl_next(struct fl_grp *g) {
    struct folat *f = g->f;
    while (g->k < g->n) {
        size_t k = g->k;
        if (!((g->todo >> k) & 1u)) {
            g->ms4[k] = -1;
            g->ms6[k] = g->v6 ? -1 : -2;
            g->k++;
            continue;
        }
        const struct spec *sp = f->c.spec(f->c.arg);
        const struct output *go = fl_group(sp, g->name);
        const struct output *cand[MAX_MEMBERS];
        if (!go || !fl_same(g, sp, go, cand)) { g->running = 0; fl_rearm(g, go); return; }
        const struct output *m = cand[k];
        /* Устройство именованного члена — то, что выбрал его проход (запись active; у вложенной
         * группы — её лист); безымянного — его собственное. */
        char dev[32] = "";
        if (group_named(out_group(go))) active_get_st(f->c.st, m->name, dev, sizeof(dev));
        if (!strcmp(dev, "-")) {
            g->ms4[k] = -1;
            g->ms6[k] = g->v6 ? -1 : -2;
            g->k++;
            continue;
        }
        if (!dev[0]) snprintf(dev, sizeof(dev), "%s", m->device);
        int a4, a6;
        g->fm = folat_member(f->c.l, sp, go, m, dev, f->c.hs ? f->c.hs(f->c.arg) : NULL, g->v6,
                             fl_member_cb, g, &a4, &a6);
        if (g->fm) return;
        g->ms4[k] = a4;
        g->ms6[k] = a6;
        g->k++;
    }
    fl_finish(g);
}

static void fl_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct fl_grp *g = arg;
    struct folat *f = g->f;
    if (g->running) return;
    const struct spec *sp = f->c.spec(f->c.arg);
    const struct output *go = fl_group(sp, g->name);
    if (!go) return;                          /* ушла — folat_sync снимет слот */
    /* Без трафика через группу замеров нет (idle_timeout) — таймер идёт дальше. */
    if (fog_idle(sp, go, fog_idle_limit(go), f->c.traffic, f->c.arg)) { fl_rearm(g, go); return; }
    const struct output *cand[MAX_MEMBERS];
    g->n = out_members(sp, go, cand, MAX_MEMBERS);
    unsigned alive = 0;
    if (group_named(out_group(go))) {
        /* Живые — по последнему проходу; сторож группу ещё не проходил — мерить некого. */
        if (!fog_groups_alive(f->c.st, sp, go, &alive) || !alive) { fl_rearm(g, go); return; }
    } else {
        alive = g->n >= 32 ? ~0u : (1u << g->n) - 1u;
    }
    for (size_t k = 0; k < g->n; k++) snprintf(g->key[k], sizeof(g->key[k]), "%s", fog_lat_key(cand[k]));
    g->todo = alive;
    g->v6 = folat_want_v6(sp, go, alive);
    g->k = 0;
    g->running = 1;
    fl_next(g);
}

struct folat *folat_new(const struct folat_conf *c) {
    struct folat *f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->c = *c;
    return f;
}

static void fl_free(struct fl_grp *g) {
    fl_abort(g);
    loop_timer_free(g->tm);
    memset(g, 0, sizeof(*g));
}

void folat_sync(struct folat *f) {
    if (!f) return;
    const struct spec *sp = f->c.spec(f->c.arg);
    unsigned char seen[MAX_OUTPUTS] = {0};
    for (size_t i = 0; sp && i < sp->out_n; i++) {
        const struct output *go = &sp->out[i];
        if (fl_group(sp, go->name) != go) continue;
        struct fl_grp *g = NULL, *slot = NULL;
        for (size_t s = 0; s < MAX_OUTPUTS && !g; s++) {
            if (f->g[s].used && !strcmp(f->g[s].name, go->name)) g = &f->g[s];
            else if (!f->g[s].used && !slot) slot = &f->g[s];
        }
        if (!g) {
            if (!slot) continue;
            slot->tm = loop_timer_new(f->c.l, fl_timer, slot);
            if (!slot->tm) continue;
            slot->used = 1;
            slot->f = f;
            snprintf(slot->name, sizeof(slot->name), "%s", go->name);
            /* Первый замер — проходом (у членов замера ещё нет), дальше — таймером. */
            fl_rearm(slot, go);
            g = slot;
        } else if (!g->running && !loop_timer_armed(g->tm)) {
            fl_rearm(g, go);
        }
        seen[g - f->g] = 1;
    }
    for (size_t s = 0; s < MAX_OUTPUTS; s++)
        if (f->g[s].used && !seen[s]) fl_free(&f->g[s]);
}

void folat_stop(struct folat *f) {
    if (!f) return;
    for (size_t s = 0; s < MAX_OUTPUTS; s++)
        if (f->g[s].used) fl_free(&f->g[s]);
}

unsigned long folat_rounds(const struct folat *f) {
    return f ? f->rounds : 0;
}
