/* kind=group — ГРУППА ВЫХОДОВ (docs/architecture.md, «4в. Устройство 1.9»).
 *
 * Группа — выход, у которого вместо своего устройства члены: другие выходы. Своя метка, своя
 * таблица и свой on_fail у неё есть, как у любого выхода с устройством, — правило ведёт трафик в
 * группу, а сторож привязывает таблицу группы к устройству выбранного члена. КАК выбрать, говорит
 * pick (group_cfg в spec.h):
 *   order   — первый живой член по порядку. Это прежний пул `devices` у выхода v1: перевод
 *             (model/v1.c) делает из каждого устройства безымянный член-интерфейс, а имя группы
 *             — прежнее имя выхода, поэтому status, реестр меток и имена наборов не меняются;
 *   latency — самый быстрый с допуском (прежний `prefer: latency`);
 *   manual, balance, вложенные группы — шаг 3 из 1.9; структура заложена, поведения нет, и
 *             спека v1 их не рождает.
 *
 * ЧТО ЗДЕСЬ, А ЧТО У СТОРОЖА. Сторож (src/daemon/failover.c) — автомат на цикле событий: он
 * пробует устройства, ждёт ответов и оживляет. Решения о выборе — чистые функции над ответами
 * проб — здесь: первый живой, выбор по замеру с допуском, гистерезис возврата. Их зовёт сторож в
 * тех же местах и в том же порядке, в каких прежде принимал их сам, поэтому число проб и их
 * порядок прежние (это проверяет стенд failovermatch).
 *
 * КАК ГРУППА ОТВЕЧАЕТ НА ВОПРОСЫ О ВИДЕ. Свойства группы — пересечение свойств её членов
 * (group_seal): у пула интерфейсов это ровно свойства интерфейса без obfs, то есть устройство,
 * метка, метка соединения, мимо общего обхода — всё, по чему компилятор, apply и сторож вели
 * прежний пул. Своих проб, оживления, помощника и правил у группы нет (функции NULL): проба и
 * оживление принадлежат устройству и его владельцу (out_for_device), а у безымянного члена
 * владельца нет — и тогда отвечает группа тем же общим путём, каким отвечал выход-пул вида
 * interface (ICMP, ifdown/ifup). */
#include <stdio.h>
#include <string.h>

#include "spec.h"

const struct group_cfg *out_group(const struct output *o) {
    return kind_of(o) == &kind_group ? &o->grp : NULL;
}

const struct kind_ops *out_kind_shown(const struct output *o) {
    const struct group_cfg *g = out_group(o);
    return g && g->shown ? g->shown : kind_of(o);
}

const char *out_kind_name(const struct output *o) {
    return out_kind_shown(o)->name;
}

size_t out_members(const struct spec *sp, const struct output *o, const struct output **dst,
                   size_t max) {
    const struct group_cfg *g = out_group(o);
    if (g) {
        size_t n = 0;
        for (size_t i = 0; i < g->members_n && n < max; i++)
            dst[n++] = &sp->out[g->members[i]];
        return n;
    }
    if (!out_has_device(o) || !max) return 0;
    dst[0] = o;
    return 1;
}

int group_seal(struct spec *sp, struct output *go, struct err *e) {
    struct group_cfg *g = &go->grp;
    if (!g->members_n) return err_set(e, "outputs.%s: у группы нет членов", go->name);
    unsigned caps = ~0u;
    for (size_t i = 0; i < g->members_n; i++) {
        const struct output *m = &sp->out[g->members[i]];
        /* Вложенные группы — шаг 3: выбор разворачивается до листа, и сторожу нужна своя ветка
         * на это. Перевод v1 вложенных не рождает. */
        if (out_group(m))
            return err_set(e, "outputs.%s: группа в группе — пока нет (шаг 3 из 1.9)", go->name);
        if (!out_has_device(m))
            return err_set(e, "outputs.%s: член группы без устройства", go->name);
        caps &= out_caps(m);
    }
    /* Своего сокета наверх и своего процесса у группы нет: KC_OVER и KC_ENGINE_OWNED — свойства
     * членов, не группы. У пула интерфейсов без obfs их и не было. */
    g->caps = caps & ~(unsigned)(KC_OVER | KC_ENGINE_OWNED);
    return 0;
}

int group_of_devices(struct spec *sp, struct output *o, const char (*devs)[32], size_t n,
                     struct err *e) {
    if (n > MAX_MEMBERS) return err_set(e, "outputs.%s: too many devices", o->name);
    if (sp->anon_n + n > MAX_ANON) {
        char msg[160];
        snprintf(msg, sizeof(msg), "outputs.%.31s: устройств в пулах больше %d на спеку", o->name,
                 MAX_ANON);
        return err_set(e, "%s", msg);
    }
    /* Члены — того же вида, каким был выход: пул `devices` у interface — это интерфейсы. Своих
     * настроек вида (obfs) у безымянного члена нет: их нёс выход, а не его устройства. */
    const struct kind_ops *k = kind_of(o);
    struct output g = {0};
    memcpy(g.name, o->name, sizeof(g.name));
    memcpy(g.device, o->device, sizeof(g.device));
    memcpy(g.over, o->over, sizeof(g.over));
    g.on_fail = o->on_fail;
    g.mark = o->mark;
    g.table = o->table;
    g.kind = &kind_group;
    g.grp.def = -1;
    g.grp.shown = k;
    for (size_t i = 0; i < n; i++) {
        size_t idx = MAX_OUTPUTS + sp->anon_n++;
        struct output *m = &sp->out[idx];
        memset(m, 0, sizeof(*m));
        m->kind = k;
        snprintf(m->device, sizeof(m->device), "%s", devs[i]);
        m->on_fail = o->on_fail;
        g.grp.members[g.grp.members_n++] = (unsigned short)idx;
    }
    /* Активное устройство до первого прохода сторожа — первое по предпочтению, если выход не
     * назвал своё (так делал разбор interface: device выводится из devices[0]). */
    if (!g.device[0] && n) snprintf(g.device, sizeof(g.device), "%s", devs[0]);
    *o = g;
    return group_seal(sp, o, e);
}

int group_latency_pick(const int *ms, size_t n, int tol, int *best) {
    int b = -1;
    for (size_t k = 0; k < n; k++)
        if (ms[k] >= 0 && (b < 0 || ms[k] < b)) b = ms[k];
    *best = b;
    if (b < 0) return -1;
    for (size_t k = 0; k < n; k++)
        if (ms[k] >= 0 && ms[k] - b <= tol) return (int)k;
    return -1;
}

int group_latency_keep(const int *ms, int cur, int pick, int tol) {
    return ms[cur] - ms[pick] <= tol;
}

int group_hysteresis(int cur, int first, int cur_alive, int streak, int hyst, int *new_streak) {
    *new_streak = 0;
    if (cur > first && cur_alive) {
        int s = streak + 1;
        if (hyst > 0 && s < hyst) { *new_streak = s; return cur; }
    }
    return first;
}

static unsigned group_caps_of(const struct output *o) {
    return o->grp.caps;
}

const struct kind_ops kind_group = {
    .name = "group",
    .caps_of = group_caps_of,
    .novia = "группа",
};
