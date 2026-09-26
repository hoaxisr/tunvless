/* Сквозные проверки спеки, общие для v1 и v2 (check.h).
 *
 * Всё здесь переехало из model/v1.c без изменения смысла и текстов: разбор v2 (model/v2.c)
 * обязан отказывать на тех же конфигурациях, что и v1, и держать две копии проверки подложки —
 * самой хитрой из них — значило бы однажды получить две разные. Слово для подложки («via» в v1,
 * «over» в v2) приходит параметром; с «via» тексты совпадают с прежними байт в байт (снимок
 * генератора tests/snapshot.sh). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "spec.h"
#include "obfs.h"
#include "check.h"

/* ---- порты ---------------------------------------------------------------------------------
 *
 * ТИРЕ, А НЕ ДВОЕТОЧИЕ, хотя в `.srs` у sing-box записано `port_range 50000:65535`. Тире — это
 * форма, которой у нас уже пишется диапазон АДРЕСОВ в списках (`10.0.9.0-10.0.9.5`), и два
 * синтаксиса диапазона в одной настройке — это вопрос «а тут как?» на каждом поле. Чужую форму
 * переводит тот, кто читает чужой файл, а не спека.
 *
 * Разбор свой, а не strtol по месту: strtol на не-числе НЕ ПРОДВИГАЕТ указатель и возвращает
 * нуль, то есть «abc» без явной проверки прошло бы как порт 0. Проверяется поэтому КАЖДЫЙ
 * символ, и хвост тоже: «1-2-3» это описка, а не «1-2 и ещё что-то». */
static int port_num(const char **pp, long *out) {
    const char *p = *pp;
    if (*p < '0' || *p > '9') return -1;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p++ - '0');
        if (v > 65535) return -1;           /* обрываем до переполнения, а не после */
    }
    if (v < 1) return -1;                   /* порт 0 не адресуем ничем */
    *pp = p;
    *out = v;
    return 0;
}

int port_range_parse(const char *s, struct port_range *r) {
    long lo = 0, hi = 0;
    const char *p = s;
    if (port_num(&p, &lo) != 0) return -1;
    hi = lo;                                /* одиночный порт — диапазон из одного */
    if (*p == '-') {
        p++;
        if (port_num(&p, &hi) != 0) return -1;
    }
    if (*p) return -1;                      /* хвост: «1-2-3», «443 », «443/tcp» */
    if (lo > hi) return -1;                 /* «9-1» — почти наверняка перепутанные концы */
    r->lo = (unsigned short)lo;
    r->hi = (unsigned short)hi;
    return 0;
}

/* ---- обфускация ----------------------------------------------------------------------------
 *
 * `listen` обязателен и должен совпадать с `Endpoint` пира в /etc/config/network: это
 * единственное место, где две настройки обязаны знать друг о друге, и вывести одну из другой
 * движок не может — ключи и пиры не его. Несовпадение молчаливо: WireGuard шлёт в никуда, туннель
 * не поднимается, и причина не видна ниоткуда, кроме tcpdump. */
int obfs_set(const char *name, const char *mode, const char *server, const char *listen,
             struct out_obfs *ob, struct err *e) {
    /* Отсутствующий mode — это сегодняшний единственный режим: спека, написанная до появления
     * второго, обязана значить то же, что значила. Неизвестный — отказ, а не молчаливое
     * «наверное, тот самый»: обфускация, которой нет, выглядит как рабочий выход, из которого
     * не выходит ни один пакет. */
    if (mode[0] && strcmp(mode, "wg-over-tcp") != 0)
        return err_set(e, "outputs.%s: неизвестный obfs.mode (сейчас есть только wg-over-tcp)", name);
    if (!server[0]) return err_set(e, "outputs.%s: obfs нужен server вида адрес:порт", name);
    if (obfs_split_hostport(server, ob->server, sizeof(ob->server), &ob->server_port) != 0)
        return err_set(e, "outputs.%s: obfs.server должен быть вида адрес:порт", name);
    /* Имя, а не адрес — отказ. Имя пришлось бы разрешать, и разрешать его через тот самый DNS,
     * который может идти в туннель, который поднимается через этот самый сервер. Управляющий
     * слой резолвит один раз и кладёт сюда адрес — то же правило, что со списками: движок
     * читает то, что ему положили. */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ob->server, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.server должен быть адресом, а не именем", name);

    if (!listen[0]) return err_set(e, "outputs.%s: obfs нужен listen — тот же адрес и порт, что в "
                        "Endpoint пира WireGuard", name);
    if (obfs_split_hostport(listen, ob->listen, sizeof(ob->listen), &ob->listen_port) != 0)
        return err_set(e, "outputs.%s: obfs.listen должен быть вида адрес:порт", name);
    if (inet_pton(AF_INET, ob->listen, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.listen должен быть адресом, а не именем", name);
    ob->on = 1;
    return 0;
}

/* ---- подложка: `over` (v1: `via`) ---------------------------------------------------------
 *
 * Смысл поля — в блоке «подложка» в spec.h. Здесь — то, что обязано быть отказом, а не
 * применённой спекой, и у каждого отказа своя причина:
 *
 *   - подложка у выхода без своего соединения с сервером (direct, zapret, tgws, обычный
 *     interface, группа) ничего бы не сделала: метку ставит тот, кто открывает сокет (или, у
 *     awg, настраивает устройство), а у этих видов его открывает не движок. Принять поле молча —
 *     сказать «настроено», не настроив;
 *   - цели нет в спеке или она без устройства — метке некуда вести, и туннель тихо ушёл бы
 *     напрямую (правила на метку нет — пакет идёт по main);
 *   - круг (a → b → a, в том числе a → a) — пакет туннеля вечно заворачивался бы сам в себя:
 *     соединение a идёт в устройство b, соединение b — в устройство a, и не встаёт ни одно;
 *   - круг ЧЕРЕЗ ПУЛ: цель — группа, среди устройств членов которой устройство самого выхода или
 *     выхода, который сам зависит от него. Снаружи в спеке круга не видно — он проходит через имя
 *     устройства, — а по сути это тот же круг, только проявится он лишь в тот момент, когда
 *     сторож переключит группу на это устройство;
 *   - цепочка длиннее MAX_OVER_DEPTH переходов — скорее описка, чем замысел (см. spec.h).
 *
 * Проверяется ПОСЛЕ разбора всех выходов: цель может стоять ниже того, кто на неё ссылается. */
static int via_idx(const struct spec *sp, const struct output *o) { return (int)(o - sp->out); }

/* Устройства, в которые может уйти трафик выхода: у группы — устройства её членов, у выхода с
 * устройством — его собственное (out_members). */
static size_t via_devs(const struct spec *sp, const struct output *o, const char **dst) {
    const struct output *m[MAX_MEMBERS];
    size_t n = out_members(sp, o, m, MAX_MEMBERS);
    for (size_t i = 0; i < n; i++) dst[i] = m[i]->device;
    return n;
}

/* Выход, которому принадлежит устройство пула, — тот же ответ, что device_owner в failover.c
 * (владелец — выход, чей процесс устройство создаёт). Своя копия, а не вызов: specmatch
 * собирает модель без failover.c. Отвечает она на узкий вопрос этой проверки и расходиться с той
 * функцией ей негде — обе смотрят на out_engine_managed и имя устройства. */
static const struct output *via_dev_owner(const struct spec *sp, const char *dev,
                                          const struct output *not) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (&sp->out[i] != not && out_engine_managed(&sp->out[i]) && !strcmp(sp->out[i].device, dev))
            return &sp->out[i];
    return NULL;
}

static int over_check(const struct spec *sp, const char *w, int *bad, struct err *e) {
    static char msg[512];
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!o->over[0]) continue;
        if (bad) *bad = (int)i;
        if (!out_over_capable(o)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: %s есть только у выходов со своим соединением с сервером — "
                     "vless, xsteer, awg и interface с obfs; у kind=%s соединение открывает не движок, "
                     "и пустить его через другой выход нечем", o->name, w,
                     out_kind_shown(o)->novia ? out_kind_shown(o)->novia : out_kind_name(o));
            return err_set(e, "%s", msg);
        }
        if (!strcmp(o->over, o->name)) {
            snprintf(msg, sizeof(msg), "выход %s: %s указывает на него самого — туннель не может "
                     "идти внутри себя", o->name, w);
            return err_set(e, "%s", msg);
        }
        const struct output *v = out_over(sp, o);
        if (!v) {
            snprintf(msg, sizeof(msg), "выход %.31s: %s «%.31s» — такого выхода в спеке нет",
                     o->name, w, o->over);
            return err_set(e, "%s", msg);
        }
        if (!out_over_target_ok(v)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: %s «%.31s» — это kind=%s, у него нет устройства, в которое "
                     "можно пустить туннель (нужен выход с устройством: interface, vless, xsteer, awg)",
                     o->name, w, v->name, out_kind_name(v));
            return err_set(e, "%s", msg);
        }

        /* Цепочка по одним подложкам: круг и глубина. Путь печатается целиком — по одному имени
         * человек круга не найдёт, если в спеке шестнадцать выходов. */
        char path[256];
        int on_path[MAX_OUTPUTS] = {0};
        size_t pl = (size_t)snprintf(path, sizeof(path), "%s", o->name);
        on_path[via_idx(sp, o)] = 1;
        int hops = 0;
        for (const struct output *t = o, *n; (n = out_over(sp, t)); t = n) {
            hops++;
            if (pl < sizeof(path))
                pl += (size_t)snprintf(path + pl, sizeof(path) - pl, " → %s", n->name);
            if (on_path[via_idx(sp, n)]) {
                snprintf(msg, sizeof(msg), "выход %.31s: %s замыкается в круг (%s) — туннели "
                         "заворачивались бы друг в друга, и не встал бы ни один", o->name, w, path);
                return err_set(e, "%s", msg);
            }
            on_path[via_idx(sp, n)] = 1;
            if (hops > MAX_OVER_DEPTH) {
                snprintf(msg, sizeof(msg), "выход %.31s: цепочка %s длиннее %d переходов (%s)",
                         o->name, w, MAX_OVER_DEPTH, path);
                return err_set(e, "%s", msg);
            }
        }

        /* Круг через пул: обход всего, во что может уйти трафик туннеля o, — целей подложки и
         * владельцев устройств в пулах целей. Встретить устройство самого o или сам o — круг. */
        int seen[MAX_OUTPUTS] = {0};
        int stack[MAX_OUTPUTS * (MAX_MEMBERS + 1)];
        int top = 0;
        stack[top++] = via_idx(sp, v);
        while (top) {
            const struct output *t = &sp->out[stack[--top]];
            if (seen[via_idx(sp, t)]) continue;
            seen[via_idx(sp, t)] = 1;
            if (t == o) {
                snprintf(msg, sizeof(msg), "выход %.31s: %s замыкается в круг через устройства "
                         "пула — туннель однажды пошёл бы внутрь себя", o->name, w);
                return err_set(e, "%s", msg);
            }
            const char *td[MAX_MEMBERS], *od[MAX_MEMBERS];
            size_t tn = via_devs(sp, t, td), on = via_devs(sp, o, od);
            for (size_t d = 0; d < tn; d++) {
                for (size_t k = 0; k < on; k++)
                    if (!strcmp(td[d], od[k])) {
                        snprintf(msg, sizeof(msg), "выход %.31s: %s ведёт в %.31s, а среди его "
                                 "устройств %.31s — устройство самого выхода, туннель пошёл бы "
                                 "внутрь себя", o->name, w, t->name, td[d]);
                        return err_set(e, "%s", msg);
                    }
                const struct output *wo = via_dev_owner(sp, td[d], t);
                if (wo && !seen[via_idx(sp, wo)]) stack[top++] = via_idx(sp, wo);
            }
            const struct output *n = out_over(sp, t);
            if (n && !seen[via_idx(sp, n)]) stack[top++] = via_idx(sp, n);
        }
    }
    return 0;
}

/* ---- защита от конфигураций, которые отрежут доступ к роутеру ------------------------------
 *
 * Всё ниже — про ошибки, которые компилируются и применяются без единой жалобы, а замечаются
 * как «роутер пропал». Отказать на них дешевле, чем потом объяснять, как чинить коробку, до
 * которой уже не достучаться. */
int spec_check_outputs(const struct spec *sp, const char *over_word, int *bad, struct err *e) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o)) continue;
        if (bad) *bad = (int)i;

        /* Выход в локальное устройство — это петля: помеченный пакет получает маршрут обратно в
         * ту же сеть, откуда пришёл. Проверяется ВЕСЬ список: выход в tailscale0, с которого мы
         * забираем клиентов, закольцуется ровно так же, как выход в br-lan. */
        for (size_t d = 0; d < sp->lan_dev_n; d++)
            if (!strcmp(o->device, sp->lan_dev[d])) {
                /* 256, не 160: через указатель на struct spec gcc считает границы имени и
                 * устройства не так точно, и -Wformat-truncation видит в этом риск. */
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "выход %s ведёт в %s — это локальная сеть, трафик закольцуется",
                         o->name, sp->lan_dev[d]);
                return err_set(e, "%s", msg);
            }

        /* Дубликат устройства внутри одного пула делает failover бессмысленным: второй
         * кандидат ничем не отличается от первого. */
        const char *dv[MAX_MEMBERS];
        size_t dn = via_devs(sp, o, dv);
        for (size_t a = 0; a < dn; a++)
            for (size_t b = a + 1; b < dn; b++)
                if (!strcmp(dv[a], dv[b])) {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "выход %s: устройство %s указано дважды",
                             o->name, dv[a]);
                    return err_set(e, "%s", msg);
                }
    }
    return over_check(sp, over_word, bad, e);
}
