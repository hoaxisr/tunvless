/* Слежка за узлом VLESS: клиент под демоном сам говорит, жив ли узел.
 *
 * Жила в цикле туннеля (tunnel.c) и переехала в модуль VLESS при выделении стека (шаг 2
 * выпуска 1.10): мерой здесь служит проверка VLESS (vless_probe), а кандидаты — узлы подписки,
 * то есть это знание протокола, а не стека. Со стеком её связывает одна точка — установщик
 * докладывает исходы рукопожатий, и докладывает через дайлер (vldial.c), а не напрямую.
 *
 * ЗАЧЕМ. Клиент сообщал демону `up` при выборе узла и больше ничего, а умерший потом узел сторож
 * будто бы замечал пробой TCP через устройство. Не замечал: SYN-ACK на SYN клиент отдаёт сам и
 * сразу, ДО рукопожатия с узлом (handle_packet в stack.c, «SYN-ACK — СРАЗУ»), поэтому connect
 * пробы сторожа удавался и на мёртвом узле. Рукопожатие, которое эта проба заводила у
 * установщика, не мерил никто: проба к тому времени уже закрыла сокет. Жив ли узел, знает
 * только клиент, — и сказать это должен он сам, событием в трубу (evline.h): `down` с причиной,
 * когда узел перестал отвечать, и снова `up`, когда ответил. Сторож такого клиента пробой не
 * спрашивает (fostate.h, watch), а принимает его слово.
 *
 * МЕРА — vless_probe: та же проверка, по которой узел выбирается при подъёме (соединение,
 * TLS/Reality, запрос через узел и первый байт ответа). Одна мера на «выбран», «потерян» и
 * «нашёлся», иначе down и up мерились бы разными линейками, и выход мигал бы там, где одна
 * говорит «жив», а другая — нет. Исходы соединений живого трафика приговором НЕ служат, они
 * только зовут проверку раньше срока: NW_STREAK отказов vless_connect подряд (без удачи между
 * ними) — проверить сейчас. Приговором их не сделать потому, что пачка SYN при открытии
 * страницы отказывает вся разом на одной потере пакетов, а удачное рукопожатие не говорит, что
 * узел пропускает трафик дальше себя.
 *
 * РИТМ. Пока узел жив — проверка раз в NW_PERIOD_S: это период сторожа по умолчанию, то есть
 * частота той самой пробы, которую слежка заменяет, и фонового трафика не прибавляется: прежде
 * за период шли проба TCP, рукопожатие её соединения с узлом и пополнение запасных сессий
 * (spare_refill на её SYN), теперь — одна проверка. Неудачная проверка
 * повторяется через NW_CONFIRM_S, и `down` — только после двух неудач подряд: одна потеря на
 * радиоканале не должна переключать группу туда и обратно. Узел назван номером — при подъёме
 * его не проверяли (перебора нет, out_node_named), и первая проверка идёт сразу.
 *
 * УЗЕЛ ПОТЕРЯН. Круг проверок: сперва свой узел (короткий сбой проходит на месте, с тем же
 * устройством), потом остальные кандидаты в порядке предпочтения (out_node_list — тот же, что у
 * подъёма). Свой ответил — `up`. Ответил другой — процесс выходит: сменить узел на ходу нельзя,
 * каждое соединение несёт параметры своего узла (UUID, flow и транспорт берутся у узла на каждой
 * отправке), а подъём заново — тот же перебор, что при старте, и выберет первого отвечающего по
 * порядку. Поднимет процесс супервизор демона. Не ответил никто — следующий круг через
 * NW_RETRY_S, с каждым пустым кругом вдвое дольше, до NW_RETRY_MAX_S: подписку, где мертвы все,
 * незачем перебирать без передышки.
 *
 * ТОЛЬКО ПОД ДЕМОНОМ (evline_enabled): кроме демона, `down` услышать некому. Под procd и при
 * ручном запуске потока нет и проверок нет — поведение прежнее, и сторож там пробует устройство,
 * как пробовал.
 *
 * ПОТОК свой, с одной задачей: спит на условной переменной до срока (CLOCK_MONOTONIC — во сне
 * телефона эти часы стоят, и слежка его не будит), установщик будит его раньше по серии отказов.
 * В тишине — одно пробуждение в минуту.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "vless.h"
#include "client.h"
#include "evline.h"
#include "vlwatch.h"

/* Без слова tunnel: подъём выхода и разбор подписки — это ещё не туннель. */
#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

#define NW_PERIOD_S    60
#define NW_CONFIRM_S   3
#define NW_RETRY_S     15
#define NW_RETRY_MAX_S 300
#define NW_STREAK      3
#define NW_TIMEOUT_S   8

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int on;                         /* поток слежки завёлся: только тогда ему докладывают */
    int streak;                     /* отказов vless_connect подряд */
    int kick;                       /* серия набралась — проверить сейчас */
    const struct vless_node *nodes;
    const int *sel;                 /* кандидаты в порядке предпочтения (индексы в nodes) */
    size_t sel_n;
    int cur;                        /* узел, которым идёт трафик */
    int checked;                    /* узел проверен при подъёме (перебор) */
} g_nw = { .mu = PTHREAD_MUTEX_INITIALIZER };

/* Исход рукопожатия с узлом — от установщика (и живого соединения, и запасной сессии). */
void vl_watch_seen(int rc) {
    if (!__atomic_load_n(&g_nw.on, __ATOMIC_ACQUIRE)) return;
    pthread_mutex_lock(&g_nw.mu);
    if (rc == 0) g_nw.streak = 0;
    else if (++g_nw.streak >= NW_STREAK) {
        g_nw.kick = 1;
        pthread_cond_signal(&g_nw.cv);
    }
    pthread_mutex_unlock(&g_nw.mu);
}

static uint64_t nw_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* Ждать срока due (мс CLOCK_MONOTONIC) или, пока узел жив, серии отказов. Под замком. */
static void nw_wait(uint64_t due, int up) {
    struct timespec ts = { .tv_sec = (time_t)(due / 1000), .tv_nsec = (long)(due % 1000) * 1000000L };
    while (!(up && g_nw.kick) && nw_now_ms() < due)
        pthread_cond_timedwait(&g_nw.cv, &g_nw.mu, &ts);
    g_nw.kick = 0;
}

/* down с причиной проверки (vless_probe: «TCP не соединился», «ответа нет: …»). Причина — как
 * есть, без приставки «узел не отвечает»: это и так значит down после up, а место в событии
 * дорого. Событие пишется одной записью не длиннее EVLINE_WRITE_MAX (480 байт, evline.c), и
 * каждый байт вне ASCII идёт в ней шестью знаками \u00XX — то есть кириллицы влезает меньше
 * восьмидесяти байт. Длиннее — событие потерялось бы целиком, поэтому причина обрезается здесь,
 * по границе знака UTF-8: не больше NW_WHY_ESC знаков в записи. */
#define NW_WHY_ESC 440
static void nw_down(const char *why) {
    char w[160];
    size_t n = 0, esc = 0;
    for (const unsigned char *s = (const unsigned char *)why; *s && n + 1 < sizeof(w); ) {
        /* Знак целиком: ведущий байт и его продолжения. */
        size_t len = *s >= 0xF0 ? 4 : *s >= 0xE0 ? 3 : *s >= 0xC0 ? 2 : 1;
        size_t cost = 0, k;
        for (k = 0; k < len && s[k]; k++)
            cost += s[k] >= 0x80 || s[k] < 0x20 ? 6 : (s[k] == '"' || s[k] == '\\') ? 2 : 1;
        if (k < len || n + len + 1 > sizeof(w) || esc + cost > NW_WHY_ESC) break;
        memcpy(w + n, s, len);
        n += len;
        esc += cost;
        s += len;
    }
    w[n] = '\0';
    evline_emit("down", "why", EVLINE_STR, w[0] ? w : "узел не отвечает", (const char *)NULL);
}

static void *nw_thread(void *arg) {
    (void)arg;
    const struct vless_node *cur = &g_nw.nodes[g_nw.cur];
    int up = 1, fails = 0;
    uint64_t retry = NW_RETRY_S;
    uint64_t due = nw_now_ms() + (g_nw.checked ? NW_PERIOD_S * 1000ull : 0);
    char why[256];
    for (;;) {
        pthread_mutex_lock(&g_nw.mu);
        nw_wait(due, up);
        pthread_mutex_unlock(&g_nw.mu);
        if (up) {
            if (vless_probe(cur, NW_TIMEOUT_S, why, sizeof(why)) == 0) {
                fails = 0;
                pthread_mutex_lock(&g_nw.mu);
                g_nw.streak = 0;
                pthread_mutex_unlock(&g_nw.mu);
                due = nw_now_ms() + NW_PERIOD_S * 1000ull;
                continue;
            }
            if (++fails < 2) { due = nw_now_ms() + NW_CONFIRM_S * 1000ull; continue; }
            up = 0;
            fails = 0;
            retry = NW_RETRY_S;
            nw_down(why);
            fprintf(stderr, LOG_W2 "узел %s не отвечает: %s — проверяю узлы\n", cur->name, why);
            due = nw_now_ms() + retry * 1000ull;
            continue;
        }
        /* Круг: сперва свой, потом остальные кандидаты по порядку (см. шапку). */
        if (vless_probe(cur, NW_TIMEOUT_S, why, sizeof(why)) == 0) {
            up = 1;
            pthread_mutex_lock(&g_nw.mu);
            g_nw.streak = 0;
            g_nw.kick = 0;
            pthread_mutex_unlock(&g_nw.mu);
            evline_emit("up", "watch", EVLINE_INT, 1L, (const char *)NULL);
            fprintf(stderr, LOG_I2 "узел %s снова отвечает\n", cur->name);
            due = nw_now_ms() + NW_PERIOD_S * 1000ull;
            continue;
        }
        for (size_t k = 0; k < g_nw.sel_n; k++) {
            const struct vless_node *n = &g_nw.nodes[g_nw.sel[k]];
            if (g_nw.sel[k] == g_nw.cur || vless_probe(n, NW_TIMEOUT_S, why, sizeof(why)) != 0)
                continue;
            fprintf(stderr, LOG_W2 "узел %s не отвечает, а %s отвечает — выхожу, чтобы выбрать "
                            "узел заново\n", cur->name, n->name);
            exit(0);
        }
        retry = retry * 2 > NW_RETRY_MAX_S ? NW_RETRY_MAX_S : retry * 2;
        due = nw_now_ms() + retry * 1000ull;
    }
    return NULL;
}

/* Узел выбран: сказать демону up и, если он слушает, завести слежку (шапка выше). Замок держится
 * от создания потока до записи up: первая проверка названного узла идёт сразу, и её down не
 * должен обогнать up в трубе. */
void vl_watch_start(const struct vless_node *nodes, const int *sel, size_t sel_n, int cur,
                    int checked) {
    if (!evline_enabled()) { evline_emit("up", (const char *)NULL); return; }
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_nw.cv, &ca);
    pthread_condattr_destroy(&ca);
    g_nw.nodes = nodes;
    g_nw.sel = sel;
    g_nw.sel_n = sel_n;
    g_nw.cur = cur;
    g_nw.checked = checked;
    pthread_attr_t a;
    pthread_attr_init(&a);
    /* Проверка держит соединение (struct transport, ~40 КБ) на своём стеке — с запасом против
     * 128 КБ потока по умолчанию у musl. */
    pthread_attr_setstacksize(&a, 512 * 1024);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    pthread_mutex_lock(&g_nw.mu);
    int err = pthread_create(&t, &a, nw_thread, NULL);
    pthread_attr_destroy(&a);
    if (err) {
        pthread_mutex_unlock(&g_nw.mu);
        /* Без слежки up — прежний, без watch: сторож тогда пробует устройство сам, как раньше
         * (и так же не видит узла за ним — см. шапку). */
        fprintf(stderr, LOG_W2 "поток слежки за узлом не создался (%s) — потерю узла клиент "
                        "не заметит\n", strerror(err));
        evline_emit("up", (const char *)NULL);
        return;
    }
    __atomic_store_n(&g_nw.on, 1, __ATOMIC_RELEASE);
    evline_emit("up", "watch", EVLINE_INT, 1L, (const char *)NULL);
    pthread_mutex_unlock(&g_nw.mu);
}
