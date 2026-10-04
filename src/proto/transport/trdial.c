/* Сокет до узла: TCP по ВСЕМ адресам имени, а не по первому, и метка выхода-подложки.
 *
 * Нижний ярус транспорта (transport.h). Переехал сюда из клиента VLESS (client.c) без
 * изменений: от протокола здесь не зависит ничего, а любой следующий дайлер поверх тех же
 * транспортов обязан соединяться тем же путём — с тем же перебором адресов, тем же кэшем
 * победителя и той же меткой, иначе `over` у него значил бы другое.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/if.h>

#include "transport.h"

/* ---- установление TCP: ВСЕ адреса узла, а не первый ---------------------------
 *
 * Одно имя узла — это, как правило, не один адрес. Живой пример, на котором это нашлось:
 * pl.riotvpn.eu отдаёт ПЯТНАДЦАТЬ записей A, и шесть из них — чёрные дыры: SYN уходит, в
 * ответ тишина. DNS перемешивает список при каждом запросе, поэтому «первый адрес» каждый
 * раз другой, и в сорока процентах случаев он мёртвый.
 *
 * Прежний код брал res->ai_next == первый и на этом останавливался. Последствия оказались
 * куда хуже, чем «иногда не соединяется»:
 *
 *   - блокирующий connect к чёрной дыре ждёт SO_SNDTIMEO целиком — восемь секунд, — и
 *     всё это время событийный цикл СТОИТ. Не тормозит, а стоит: ни один другой поток не
 *     двигается. На роутере это выглядело как «сайты еле открываются» при простое
 *     процессора 80% и нулевых счётчиках ошибок;
 *   - Linux сообщает об этом таймауте кодом EINPROGRESS (см. __inet_stream_connect:
 *     истёк timeo — err остаётся -EINPROGRESS), а не ETIMEDOUT. То есть в логе стояло
 *     «Operation in progress» у блокирующего вызова — вид сообщения, за которым не видно
 *     ни таймаута, ни мёртвого адреса;
 *   - сторож считал узел живым или мёртвым по одной пробе, то есть по жребию.
 *
 * Поэтому здесь: неблокирующий connect, свой таймаут вместо SO_SNDTIMEO, несколько
 * попыток одновременно с задержкой между запусками, и адрес-победитель запоминается,
 * чтобы следующее соединение начиналось с него. */

#define ADDR_MAX      16   /* сколько адресов имени вообще рассматриваем */
#define ATTEMPT_MAX    4   /* сколько держим в воздухе одновременно */
#define STAGGER_MS   150   /* пауза перед запуском следующей попытки */

/* Победивший адрес на имя. Живёт по потоку: работники независимы, блокировка не нужна, а
 * «каждый узнал сам» стоит одного лишнего перебора на работника при старте. */
#define GOOD_MAX 8
static __thread struct { char host[96]; struct in_addr ip; uint16_t port; } g_good[GOOD_MAX];
static __thread unsigned g_good_n;

static struct in_addr *good_get(const char *host, uint16_t port) {
    for (unsigned i = 0; i < g_good_n; i++)
        if (g_good[i].port == port && strcmp(g_good[i].host, host) == 0) return &g_good[i].ip;
    return NULL;
}

static void good_put(const char *host, uint16_t port, struct in_addr ip) {
    struct in_addr *p = good_get(host, port);
    if (p) { *p = ip; return; }
    unsigned i = g_good_n < GOOD_MAX ? g_good_n++ : GOOD_MAX - 1;
    snprintf(g_good[i].host, sizeof(g_good[i].host), "%s", host);
    g_good[i].port = port;
    g_good[i].ip = ip;
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Готовит установленный сокет к работе остального кода: снимает O_NONBLOCK (чтение и
 * запись дальше блокирующие, с таймаутом через SO_*TIMEO) и ставит опции. */
static void sock_ready(int fd, int timeout_s) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    /* Таймаут на чтение и запись. Без него мёртвый узел вешает проверку до таймаута
     * ядра — минуты, за которые сторож не успеет обойти остальных кандидатов. */
    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* SO_RCVBUF здесь НЕ ставится, и это отказ от прежней «оптимизации», а не упущение.
     *
     * Любой вызов setsockopt(SO_RCVBUF) ОТКЛЮЧАЕТ автоподстройку приёмного окна в Linux и
     * прибивает его к заданному размеру. А скорость приёма равна «окно, поделённое на круг
     * до сервера»: при круге 60 мс полмегабайта — это потолок 68 Мбит/с, сколько бы ни
     * давал канал. Автоподстройка дошла бы до нескольких мегабайт сама.
     *
     * То есть «поставил буфер побольше» на деле означало «запретил ядру увеличивать его
     * дальше». Пределы живут в net.ipv4.tcp_rmem и настраиваются системой, а не нами. */
}

/* --mark: SO_MARK on every socket to the node, set before connect — the route, and with it the
 * device and the source address, is chosen there, by the mark. required: a socket the mark cannot
 * be set on is not used, or it would silently take the unmarked route — into the tunnel. */
static uint32_t g_sock_mark;
static int g_sock_mark_req;

void transport_set_sock_mark(uint32_t mark, int required) {
    g_sock_mark = mark;
    g_sock_mark_req = mark && required;
}

/* --bind-dev: sockets to the node leave through this interface (SO_BINDTODEVICE) whatever the
 * routing table says — the other way, next to SO_MARK, to keep them out of the tunnel when the
 * default route points into it. A socket that cannot be bound is not used: unbound, it would go
 * into the tunnel and loop. */
static char g_bind_dev[IFNAMSIZ];

void transport_set_bind_dev(const char *ifname) {
    snprintf(g_bind_dev, sizeof(g_bind_dev), "%s", ifname ? ifname : "");
}

/* Addresses of the nodes resolved once, at startup (transport_pin_host). Once the routes point into
 * the tunnel, the DNS query for a node's name would itself go into the tunnel and wait for a
 * connection that is waiting for that query. Filled before the loop threads start and only read
 * afterwards, so no lock. */
struct pin { char host[128]; struct in_addr ip[ADDR_MAX]; unsigned n; };
static struct pin *g_pin;
static unsigned g_pin_n, g_pin_cap;

static unsigned resolve(const char *host, struct in_addr out[ADDR_MAX]) {
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    unsigned an = 0;
    for (struct addrinfo *p = res; p && an < ADDR_MAX; p = p->ai_next)
        if (p->ai_family == AF_INET)
            out[an++] = ((struct sockaddr_in *)p->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return an;
}

int transport_pin_host(const char *host) {
    for (unsigned i = 0; i < g_pin_n; i++)
        if (!strcmp(g_pin[i].host, host)) return (int)g_pin[i].n;
    if (strlen(host) >= sizeof(g_pin[0].host)) return TR_EDNS;
    if (g_pin_n == g_pin_cap) {
        unsigned cap = g_pin_cap ? g_pin_cap * 2 : 8;
        struct pin *p = realloc(g_pin, cap * sizeof(*p));
        if (!p) return TR_EDNS;
        g_pin = p;
        g_pin_cap = cap;
    }
    struct pin *p = &g_pin[g_pin_n];
    unsigned an = resolve(host, p->ip);
    if (!an) return TR_EDNS;
    snprintf(p->host, sizeof(p->host), "%s", host);
    p->n = an;
    g_pin_n++;
    return (int)an;
}

static unsigned pinned(const char *host, struct in_addr out[ADDR_MAX]) {
    for (unsigned i = 0; i < g_pin_n; i++)
        if (!strcmp(g_pin[i].host, host)) {
            memcpy(out, g_pin[i].ip, g_pin[i].n * sizeof(out[0]));
            return g_pin[i].n;
        }
    return 0;
}

int transport_pinned_addrs(const char *host, uint32_t *out, int max) {
    struct in_addr a[ADDR_MAX];
    unsigned n = pinned(host, a);
    int k = 0;
    for (unsigned i = 0; i < n && k < max; i++) out[k++] = a[i].s_addr;
    return k;
}

/* Запускает неблокирующий connect. Возвращает fd (соединение уже установлено или в
 * процессе) либо -1. */
static int attempt_start(struct in_addr ip, uint16_t port, int *done) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    /* До connect(): маршрут, а с ним устройство и адрес источника, ядро выбирает там — по
     * метке, то есть по таблице выхода-цели. */
    if (g_sock_mark &&
        setsockopt(fd, SOL_SOCKET, SO_MARK, &g_sock_mark, sizeof(g_sock_mark)) != 0 &&
        g_sock_mark_req) {
        static int told;
        if (!told) {
            told = 1;
            fprintf(stderr, "tunvless[warn]: mark 0x%08x not set on a socket to the node (%s) — "
                            "not connecting: unmarked, it would go into the tunnel\n",
                    g_sock_mark, strerror(errno));
        }
        close(fd);
        return -1;
    }
    if (g_bind_dev[0] &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, g_bind_dev, (socklen_t)strlen(g_bind_dev) + 1) != 0) {
        static int told;
        if (!told) {
            told = 1;
            fprintf(stderr, "tunvless[warn]: socket to the node not bound to %s (%s) — not "
                            "connecting: unbound, it would go into the tunnel\n",
                    g_bind_dev, strerror(errno));
        }
        close(fd);
        return -1;
    }
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = ip };
    *done = 0;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) { *done = 1; return fd; }
    if (errno != EINPROGRESS) { close(fd); return -1; }
    return fd;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_s) {
    struct in_addr addr[ADDR_MAX];
    unsigned an = pinned(host, addr);
    if (an == 0) an = resolve(host, addr);
    if (an == 0) return TR_EDNS;

    /* Прошлый победитель — вперёд. В устойчивом состоянии это означает одно соединение за
     * один круг до сервера вместо перебора мёртвых адресов заново каждый раз. */
    struct in_addr *g = good_get(host, port);
    if (g) for (unsigned i = 1; i < an; i++)
        if (addr[i].s_addr == g->s_addr) { struct in_addr t = addr[0]; addr[0] = addr[i]; addr[i] = t; break; }

    int fd[ATTEMPT_MAX];
    struct in_addr fa[ATTEMPT_MAX];
    unsigned nf = 0;     /* попыток в воздухе */
    unsigned next = 0;   /* следующий адрес к запуску */
    unsigned dead = 0;   /* сколько адресов отвалилось */
    int64_t deadline = now_ms() + (long long)timeout_s * 1000;
    int64_t stagger_at = 0;
    int win = -1;

    while (win < 0) {
        int64_t t = now_ms();
        if (t >= deadline) break;

        /* Запуск новых попыток: первая сразу, дальше через STAGGER_MS. Пауза нужна, чтобы
         * при живом первом адресе (обычный случай) второй сокет вообще не открывался. */
        while (nf < ATTEMPT_MAX && next < an && t >= stagger_at) {
            int d = 0;
            struct in_addr ip = addr[next++];
            int s = attempt_start(ip, port, &d);
            if (s < 0) { dead++; continue; }
            if (d) {   /* соединилось сразу: обычно это адрес в той же сети */
                for (unsigned j = 0; j < nf; j++) close(fd[j]);
                nf = 0;
                good_put(host, port, ip);
                win = s;
                break;
            }
            fd[nf] = s; fa[nf] = ip;
            nf++;
            stagger_at = t + STAGGER_MS;
        }
        if (win >= 0) break;
        if (nf == 0) break;   /* адреса кончились, и ни одна попытка не жива */

        struct pollfd pv[ATTEMPT_MAX];
        for (unsigned i = 0; i < nf; i++) { pv[i].fd = fd[i]; pv[i].events = POLLOUT; pv[i].revents = 0; }

        /* Ждём до ближайшего из двух событий: пора запускать следующую попытку или вышел
         * общий срок. Ограничение «только если есть куда запускать» — не мелочь: без него
         * при четырёх попытках в воздухе и непустом остатке адресов poll получал таймаут 0
         * и цикл крутился на месте, съедая ядро. */
        int64_t wait = deadline - t;
        if (next < an && nf < ATTEMPT_MAX) {
            int64_t till = stagger_at > t ? stagger_at - t : 0;
            if (till < wait) wait = till;
        }
        if (wait < 0) wait = 0;
        int pr = poll(pv, nf, (int)wait);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        for (unsigned i = 0; i < nf; ) {
            if (!pv[i].revents) { i++; continue; }
            int err = 0; socklen_t el = sizeof(err);
            getsockopt(fd[i], SOL_SOCKET, SO_ERROR, &err, &el);
            if (err == 0 && !(pv[i].revents & (POLLERR | POLLHUP))) {
                win = fd[i];
                good_put(host, port, fa[i]);
                for (unsigned j = 0; j < nf; j++) if (j != i) close(fd[j]);
                nf = 0;
                break;
            }
            /* Этот адрес отпал — освобождаем место и сразу пробуем следующий. */
            close(fd[i]); dead++;
            nf--; fd[i] = fd[nf]; fa[i] = fa[nf]; pv[i] = pv[nf];
            stagger_at = 0;
        }
    }

    if (win < 0) {
        for (unsigned i = 0; i < nf; i++) close(fd[i]);
        /* Сообщение называет масштаб: «ни один из N адресов» — это про имя узла, а не
         * про сеть, и лечится сменой узла, а не настройкой роутера. */
        fprintf(stderr, "tunvless: %s:%u — ни один адрес не ответил (адресов %u, отпало %u)\n",
                host, port, an, dead);
        return TR_ECONNECT;
    }
    if (dead)
        fprintf(stderr, "tunvless: %s:%u — соединился, пропущено мёртвых адресов: %u из %u\n",
                host, port, dead, an);
    sock_ready(win, timeout_s);
    return win;
}

/* Шов установления TCP — симметрично g_latency_probe в failover.c и по той же причине:
 * стенду нужно провести рукопожатие с собеседником, которого он держит сам, не поднимая
 * ни сокета наружу, ни настоящего узла. В бою указатель NULL, и соединяет tcp_connect.
 *
 * Почему шов появился именно здесь. У ветвей отказа установления не было НИ ОДНОГО
 * стенда: tests/fake-vless.py говорит только security=none и до TLS не доходит, а
 * tests/run-reality.sh требует sing-box, root и сетевых пространств и потому не входит ни
 * в `make test`, ни в `make ext-test`. Всё, что охраняло здесь освобождение ключей и
 * дескриптора, — чтение кода глазами, тогда как у xsteer на ту же болезнь (I-067) стенд
 * стоит под AddressSanitizer с запуска 42. Шов дешевле поддельного сервера: адрес узла
 * перестаёт быть обязан быть настоящим, и дальше рукопожатие идёт по socketpair
 * (tests/vlessmatch.c, R-114; стенд включает этот файл, чтобы дотянуться до шва).
 *
 * Возвращает то же, что tcp_connect: дескриптор либо отрицательный код TR_*. */
static int (*g_tcp_dial)(const char *host, uint16_t port, int timeout_s);

int tr_dial(const char *host, uint16_t port, int timeout_s) {
    if (g_tcp_dial) return g_tcp_dial(host, port, timeout_s);
    return tcp_connect(host, port, timeout_s);
}
