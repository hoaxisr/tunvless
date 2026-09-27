/* HTTPS для замера задержки члена группы (urltest, src/daemon/urltest.c) — полный пакет.
 *
 * ЗАЧЕМ ПОТОК. Рукопожатие tls13.c блокирующее по устройству: оно читает сокет со SO_RCVTIMEO и
 * ждёт записи целиком (tls13.h, TLS13_ETIMEOUT). Цикл демона ждать не вправе — на нём status,
 * apply и сторож, — а второй, неблокирующий TLS ради одного запроса раз в несколько минут значил
 * бы вторую реализацию того, что уже проверено на живых узлах. Поэтому замер HTTPS целиком идёт в
 * отсоединённом рабочем потоке — по образцу разрешения имён (src/daemon/gaiw.c): поток получает
 * копию параметров, делает соединение, рукопожатие, запрос и чтение первого байта обычными
 * блокирующими вызовами со сроком, а итог — одно число — пишет в сокет-пару, конец которой лежит
 * в epoll цикла. Отмена — закрыть свой конец: запись потока получит отказ (MSG_NOSIGNAL), поток
 * освободит своё и уйдёт сам. Процесса на замер нет.
 *
 * ЧЕМ ГОВОРИТ. ClientHello — тот же сборщик, что у узлов VLESS с security=tls (reality_build_hello
 * с plain: облик браузера живёт в одном месте), ALPN — http/1.1: запрос обычный HTTP/1.1, и
 * сервер, согласившийся на h2, ответил бы кадрами, которые здесь читать нечем. Подлинность
 * сервера проверяется по цепочке до корня (auth.host): страница плена провайдера с чужим
 * сертификатом — это не «быстрый член», а отказ. Корни — те же, что у клиента VLESS
 * (vless_cert_roots: на телефоне склейка системного каталога, на роутере умолчание certverify).
 *
 * ВРЕМЯ — от начала соединения до первого прикладного байта ответа, по CLOCK_MONOTONIC: как у
 * HTTP в urltest.c плюс рукопожатие TLS — два оборота того же пути, что и сам запрос. Годен ответ
 * со статусом 204 или 200. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "loop.h"
#include "reality.h"
#include "tls13.h"
#include "client.h"
#include "urltls.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

const int steer_urltls_present = 1;

struct urltls {
    struct loop *l;
    int fd;
    void (*cb)(void *arg, int ms);
    void *arg;
    unsigned char got[sizeof(int)];
    size_t gn;
};

struct urltls_work {
    int fd;
    struct sockaddr_storage dst;
    char host[128];
    char path[160];
    uint32_t mark;
    char dev[32];
    int timeout_ms;
};

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Остаток срока — в SO_RCVTIMEO/SO_SNDTIMEO. 0 — поставлено; -1 — срок вышел. */
static int set_timeo(int fd, long deadline) {
    long left = deadline - mono_ms();
    if (left <= 0) return -1;
    struct timeval tv = { left / 1000, (left % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 0;
}

static int write_all(int fd, const unsigned char *p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int status_ok(const unsigned char *b, size_t n) {
    if (n < 12 || memcmp(b, "HTTP/1.", 7) != 0 || b[8] != ' ') return 0;
    for (int i = 9; i < 12; i++)
        if (b[i] < '0' || b[i] > '9') return 0;
    int code = (b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0');
    return code == 204 || code == 200;
}

/* Весь замер — в потоке. Итог: мс или -1. */
static int measure(const struct urltls_work *w) {
    long t0 = mono_ms(), deadline = t0 + w->timeout_ms;
    int v6 = w->dst.ss_family == AF_INET6;
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (w->mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &w->mark, sizeof(w->mark)) != 0) goto fail;
    if (!w->mark && w->dev[0] &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, w->dev, (socklen_t)strlen(w->dev) + 1) != 0)
        goto fail;
    socklen_t dl = v6 ? (socklen_t)sizeof(struct sockaddr_in6) : (socklen_t)sizeof(struct sockaddr_in);
    if (connect(fd, (const struct sockaddr *)&w->dst, dl) != 0) {
        if (errno != EINPROGRESS) goto fail;
        struct pollfd p = { fd, POLLOUT, 0 };
        long left = deadline - mono_ms();
        if (left <= 0) goto fail;
        int pr;
        do pr = poll(&p, 1, (int)left); while (pr < 0 && errno == EINTR);
        if (pr <= 0) goto fail;
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) goto fail;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    if (set_timeo(fd, deadline)) goto fail;

    struct reality_cfg cfg = { .sni = w->host, .alpn = "http/1.1", .plain = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    if (reality_build_hello(&cfg, &rst, hello, sizeof(hello), &hello_n) != 0) goto fail;
    if (write_all(fd, hello, hello_n) != 0) goto fail;

    struct tls13 *t = calloc(1, sizeof(*t));
    if (!t) goto fail;
    struct tls13_auth auth = { .host = w->host, .roots = vless_cert_roots() };
    int res = -1;
    if (tls13_handshake_auth(t, fd, hello, hello_n, rst.priv, &auth) != 0) goto done;
    if (t->alpn[0] && strcmp(t->alpn, "http/1.1") != 0) goto done;

    /* Порт в Host — только нестандартный (RFC 9110 §7.2), как у HTTP в urltest.c. */
    char hh[160], req[512];
    unsigned port = ntohs(v6 ? ((const struct sockaddr_in6 *)&w->dst)->sin6_port
                             : ((const struct sockaddr_in *)&w->dst)->sin_port);
    if (port != 443)
        snprintf(hh, sizeof(hh), "%.127s:%u", w->host, port);
    else
        snprintf(hh, sizeof(hh), "%s", w->host);
    int rn = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: steer/%s\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n", w->path, hh, STEER_VERSION);
    if (rn <= 0 || (size_t)rn >= sizeof(req)) goto done;
    if (tls13_write(t, (const unsigned char *)req, (size_t)rn) != 0) goto done;

    /* Первый прикладной байт: пустые чтения — пропущенные NewSessionTicket и набивка. */
    static __thread unsigned char buf[TLS13_MAX_PLAIN];
    unsigned char line[64];
    size_t ln = 0;
    long t_first = 0;
    for (;;) {
        if (set_timeo(fd, deadline)) goto done;
        size_t got = 0;
        if (tls13_read(t, buf, sizeof(buf), &got) != 0) goto done;
        if (!got) continue;
        if (!t_first) t_first = mono_ms();
        size_t take = got < sizeof(line) - ln ? got : sizeof(line) - ln;
        memcpy(line + ln, buf, take);
        ln += take;
        if (memchr(line, '\n', ln) || ln >= sizeof(line)) break;
    }
    if (status_ok(line, ln)) res = (int)(t_first - t0 > 0 ? t_first - t0 : 0);
done:
    tls13_free(t);
    free(t);
    close(fd);
    return res;
fail:
    close(fd);
    return -1;
}

static void *urltls_thread(void *arg) {
    struct urltls_work *w = arg;
    int ms = measure(w);
    const unsigned char *p = (const unsigned char *)&ms;
    size_t left = sizeof(ms);
    while (left) {
        ssize_t k = send(w->fd, p, left, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;     /* отменено: другой конец закрыт */
        p += k;
        left -= (size_t)k;
    }
    close(w->fd);
    free(w);
    return NULL;
}

static void urltls_free(struct urltls *t) {
    loop_fd_del(t->l, t->fd);
    close(t->fd);
    free(t);
}

static void urltls_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct urltls *t = arg;
    for (;;) {
        if (t->gn >= sizeof(t->got)) break;
        ssize_t k = recv(fd, t->got + t->gn, sizeof(t->got) - t->gn, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (k <= 0) break;
        t->gn += (size_t)k;
    }
    int ms = -1;
    if (t->gn == sizeof(t->got)) memcpy(&ms, t->got, sizeof(ms));
    void (*cb)(void *, int) = t->cb;
    void *a = t->arg;
    urltls_free(t);
    cb(a, ms);
}

struct urltls *urltls_start(struct loop *l, const struct sockaddr_storage *dst, const char *host,
                            const char *path, uint32_t mark, const char *dev, int timeout_ms,
                            void (*cb)(void *arg, int ms), void *arg) {
    struct urltls *t = calloc(1, sizeof(*t));
    struct urltls_work *w = calloc(1, sizeof(*w));
    int sv[2] = { -1, -1 };
    if (!t || !w || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) goto fail;
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    t->l = l;
    t->fd = sv[0];
    t->cb = cb;
    t->arg = arg;
    w->fd = sv[1];
    w->dst = *dst;
    snprintf(w->host, sizeof(w->host), "%s", host);
    snprintf(w->path, sizeof(w->path), "%s", path);
    w->mark = mark;
    if (dev) snprintf(w->dev, sizeof(w->dev), "%s", dev);
    w->timeout_ms = timeout_ms > 0 ? timeout_ms : 1;
    if (loop_fd_add(l, sv[0], EPOLLIN, urltls_ready, t) != 0) goto fail;
    pthread_attr_t at;
    int attr_ok = pthread_attr_init(&at) == 0;
    if (attr_ok) pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, attr_ok ? &at : NULL, urltls_thread, w);
    if (attr_ok) pthread_attr_destroy(&at);
    if (rc != 0) {
        loop_fd_del(l, sv[0]);
        goto fail;
    }
    return t;
fail:
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
    free(t);
    free(w);
    return NULL;
}

void urltls_cancel(struct urltls *t) {
    if (t) urltls_free(t);
}
