/* Апстримы резолвера: цикл событий, очередь вопросов, транспорты UDP, TCP, DoT и DoH.
 * Устройство, доводы и границы — в шапке dup.h; установка соединения TLS — в dupdial.c.
 *
 * КАК УСТРОЕНО. Вопрос (dup_ask) получает запись в таблице запросов и уходит на транспорт
 * апстрима:
 *   - UDP — датаграмма из подключённого сокета апстрима, с одной повторной отправкой через
 *     1,5 с; усечённый ответ (TC) переигрывается по TCP к тому же серверу;
 *   - TCP и DoT — сообщения с длиной в два байта (RFC 1035, RFC 7858) по одному долгоживущему
 *     соединению, вопросы идут по нему вперемешку и сопоставляются с ответами по номеру
 *     транзакции: номер у каждого вопроса свой на апстрим, а не тот, что дал вызывающий (исходный
 *     возвращается в ответе). DoT отличается от TCP только слоем TLS;
 *   - DoH — HTTP/1.1 поверх TLS, POST application/dns-message (RFC 8484), keep-alive. HTTP/2
 *     не взят нарочно: h2.c у нас — клиент одного потока для xsteer, а мультиплексировать вопросы
 *     на одном соединении ему нечем. Вместо этого до DUP_CONNS соединений, на каждом один вопрос
 *     за раз; следующий ждёт свободного или нового соединения. Номер в теле — 0, как рекомендует
 *     RFC 8484 (кэшируемость), а исходный возвращается в ответе.
 * Соединение TLS создаётся потоком (dial), сокет тогда переходит циклу. Пока соединения нет,
 * вопросы ждут в той же таблице (ci < 0); не установилось — все ожидающие получают отказ сразу,
 * а следующая попытка — через растущую паузу (1, 2, 4 ... 30 с). Обрыв соединения под вопросом —
 * вопрос переставляется в ожидание один раз (сервер закрыл простаивающее соединение как раз
 * тогда, когда мы его выбрали: это обычное дело), второй раз — отказ.
 *
 * СРОКИ. Вопрос живёт не дольше DUP_REQ_MS (4 с, меньше PENDING_TTL_SEC резолвера, чтобы отказ
 * успел дойти до клиента SERVFAIL, а не молчанием). У DoH просроченный вопрос рвёт своё
 * соединение: состояние протокола на нём неизвестно, а запоздавший ответ склеился бы со
 * следующим вопросом. Простаивающее соединение закрывается через DUP_IDLE_MS.
 *
 * ПАМЯТЬ. Объекты апстримов лежат в статическом хранилище и не освобождаются: адреса внутри них
 * (метки epoll) переживают перенастройку, и запоздалое событие закрытого апстрима попадает в
 * живую, пусть и чужую по содержимому, память. Соединение занимает struct tls13 (около 17 КБ) и
 * буфер чтения; их нет, пока соединения нет. */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include "dnsd_int.h"
#include "dupint.h"
#include "tls13.h"

extern int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) __attribute__((weak));
extern int tls13_has_record(const struct tls13 *t) __attribute__((weak));
extern int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) __attribute__((weak));
extern void tls13_free(struct tls13 *t) __attribute__((weak));

#define DUP_CONNS 3
#define DUP_MAXREQ 256
#define DUP_QMAX 1024
#define DUP_REQ_MS 4000
#define DUP_UDP_RETRY_MS 1500
#define DUP_IDLE_MS 300000L
#define DUP_DIAL_MS 6000
#define DUP_RBUF_MAX (70 * 1024)
#define DUP_BACKOFF_MAX 30000

enum { CS_FREE = 0, CS_DIAL, CS_TCPCONN, CS_READY };

struct dup;
struct dconn {
    struct dtag tag;
    struct dup *up;
    int fd, st;
    struct tls13 *tls;
    struct dial *dial;
    uint8_t *rb;
    size_t rn, rcap;
    uint8_t *wb;
    size_t wn, woff;
    long last_ms;
    int busy;                   /* DoH: номер вопроса плюс один; DoT/TCP: число вопросов на нём */
    int close_after;
    /* Разбор ответа HTTP. */
    int hdr_done, chunked;
    long clen;
    size_t body_off;
};

struct dup {
    struct dtag utag;
    int live;
    unsigned gen;
    struct dup_cfg cfg;
    int ufd;
    struct sockaddr_storage srv;
    int srv_ok;
    struct dconn c[DUP_CONNS];
    struct sockaddr_storage ad[DIAL_MAXADDR];
    int ad_n;
    long ad_exp_ms;
    int dialing;
    long retry_at_ms;
    long backoff_ms;
    char err[192];
    long err_ms, ok_ms;
    unsigned long q_sent, q_ok, q_fail;
    uint16_t next_id;
};

struct dreq {
    int used;
    struct dup *up;
    unsigned up_gen;
    int ci;                     /* соединение или -1 — ждёт */
    int tcp;                    /* усечённый ответ по UDP: идти по TCP */
    uint8_t tries;
    uint16_t wid, oid;
    long t0, deadline;
    dup_done_fn cb;
    void *ctx;
    uint8_t q[DUP_QMAX];
    uint16_t qn;
};

static struct dup g_store[MAX_DNS_UP * 2];
static struct dup *g_dups[MAX_DNS_UP];
static size_t g_dups_n;
static struct dreq g_req[DUP_MAXREQ];

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int sa_len(const struct sockaddr_storage *a) {
    return a->ss_family == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
}

static int stream_proto(const struct dup *up) {
    return up->cfg.u.proto == DNSP_TCP || up->cfg.u.proto == DNSP_DOT || up->cfg.u.proto == DNSP_DOH;
}
static int tls_proto(const struct dup *up) {
    return up->cfg.u.proto == DNSP_DOT || up->cfg.u.proto == DNSP_DOH;
}

static void up_err(struct dup *up, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void up_err(struct dup *up, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(up->err, sizeof(up->err), fmt, ap);
    va_end(ap);
    up->err_ms = now_ms();
}

/* Конец секции вопроса пакета (после имени, типа и класса); 0 — не разобралось. */
static size_t qsec_end(const uint8_t *p, size_t n) {
    if (n < 17 || ((p[4] << 8) | p[5]) != 1) return 0;
    size_t off = 12;
    for (;;) {
        if (off >= n) return 0;
        uint8_t l = p[off];
        if (!l) { off++; break; }
        if (l & 0xC0) return 0;
        off += 1u + l;
    }
    return off + 4 <= n ? off + 4 : 0;
}

/* Вопрос ответа совпадает с вопросом запроса (без учёта регистра имени). */
static int same_question(const struct dreq *r, const uint8_t *a, size_t an) {
    size_t qe = qsec_end(r->q, r->qn);
    if (!qe || an < qe) return 0;
    for (size_t i = 12; i < qe; i++) {
        uint8_t x = r->q[i], y = a[i];
        if (x >= 'A' && x <= 'Z') x = (uint8_t)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (uint8_t)(y + 32);
        if (x != y) return 0;
    }
    return 1;
}

/* ---- запросы --------------------------------------------------------------------------------- */

static void req_finish(struct dreq *r, uint8_t *ans, size_t n) {
    uint8_t q[DUP_QMAX];
    uint16_t qn = r->qn;
    memcpy(q, r->q, qn);
    dup_done_fn cb = r->cb;
    void *ctx = r->ctx;
    struct dup *up = r->up;
    r->used = 0;
    if (ans) {
        ans[0] = (uint8_t)(r->oid >> 8);
        ans[1] = (uint8_t)r->oid;
        up->q_ok++;
        up->ok_ms = now_ms();
    } else {
        up->q_fail++;
    }
    cb(ctx, ans, n, q, qn);
}

static struct dreq *req_at(int i) { return (i >= 0 && i < DUP_MAXREQ && g_req[i].used) ? &g_req[i] : NULL; }

/* ---- соединения ------------------------------------------------------------------------------ */

static void conn_free_bufs(struct dconn *c) {
    free(c->rb); free(c->wb);
    c->rb = c->wb = NULL;
    c->rn = c->rcap = c->wn = c->woff = 0;
}

static int cidx(const struct dconn *c) { return (int)(c - c->up->c); }

static void up_kick(struct dup *up);

/* Закрыть соединение: вопросы на нём переставляются в ожидание (один раз) или получают отказ. */
static void conn_close(struct dconn *c, const char *why) {
    struct dup *up = c->up;
    int i = cidx(c);
    if (c->fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    if (c->tls) {
        if (tls13_free) tls13_free(c->tls);
        free(c->tls);
    }
    c->fd = -1;
    c->tls = NULL;
    int was_ready = c->st == CS_READY;
    c->st = CS_FREE;
    c->busy = 0;
    c->close_after = 0;
    c->hdr_done = 0;
    conn_free_bufs(c);
    int had = 0;
    for (int k = 0; k < DUP_MAXREQ; k++) {
        struct dreq *r = &g_req[k];
        if (!r->used || r->up != up || r->ci != i) continue;
        had = 1;
        if (r->tries < 1) { r->tries++; r->ci = -1; }
        else req_finish(r, NULL, 0);
    }
    /* Простаивающее соединение сервер закрывает по своему сроку — это не сбой; сбой — обрыв под
     * вопросом. */
    if (why && was_ready && had) up_err(up, "%s", why);
}

static int rb_reserve(struct dconn *c, size_t more) {
    if (c->rn + more > DUP_RBUF_MAX) return -1;
    if (c->rn + more > c->rcap) {
        size_t cap = c->rcap ? c->rcap : 2048;
        while (cap < c->rn + more) cap *= 2;
        uint8_t *nb = realloc(c->rb, cap);
        if (!nb) return -1;
        c->rb = nb;
        c->rcap = cap;
    }
    return 0;
}

static void conn_ev(struct dconn *c, uint32_t ev) {
    struct epoll_event e = {0};
    e.events = ev;
    e.data.ptr = &c->tag;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &e);
}

static void conn_register(struct dconn *c, uint32_t ev) {
    struct epoll_event e = {0};
    e.events = ev;
    e.data.ptr = &c->tag;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, c->fd, &e);
}

/* Отправить байты по соединению. 0 — ушло или поставлено в очередь; -1 — соединение сломано. */
static int conn_write(struct dconn *c, const uint8_t *b, size_t n) {
    if (c->tls) {
        if (!tls13_write || tls13_write(c->tls, b, n) != 0) return -1;
        return 0;
    }
    size_t done = 0;
    if (!c->wn) {
        ssize_t w = send(c->fd, b, n, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            w = 0;
        }
        done = (size_t)w;
        if (done == n) return 0;
    }
    if (c->wn - c->woff + (n - done) > 256 * 1024) return -1;
    if (c->woff == c->wn) c->wn = c->woff = 0;
    uint8_t *nb = realloc(c->wb, c->wn + (n - done));
    if (!nb) return -1;
    c->wb = nb;
    memcpy(c->wb + c->wn, b + done, n - done);
    c->wn += n - done;
    conn_ev(c, EPOLLIN | EPOLLOUT);
    return 0;
}

/* Поставить вопрос r на готовое соединение c. */
static int conn_send(struct dup *up, struct dconn *c, struct dreq *r) {
    r->ci = cidx(c);
    if (up->cfg.u.proto == DNSP_DOH) {
        /* Порт в Host — только нестандартный (RFC 9110, 7.2), как у остальных HTTPS движка. */
        char auth[160], hdr[512];
        if (up->cfg.u.port != 443) snprintf(auth, sizeof(auth), "%s:%u", up->cfg.u.host, up->cfg.u.port);
        else snprintf(auth, sizeof(auth), "%s", up->cfg.u.host);
        int hn = snprintf(hdr, sizeof(hdr),
                          "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\n"
                          "Accept: application/dns-message\r\nContent-Length: %u\r\n\r\n",
                          up->cfg.u.path, auth, r->qn);
        if (hn <= 0 || (size_t)hn >= sizeof(hdr)) return -1;
        uint8_t buf[sizeof(hdr) + DUP_QMAX];
        memcpy(buf, hdr, (size_t)hn);
        memcpy(buf + hn, r->q, r->qn);
        buf[hn] = 0;                                   /* тело — с номером 0 */
        buf[hn + 1] = 0;
        c->busy = (int)(r - g_req) + 1;
        c->hdr_done = 0;
        c->chunked = 0;
        c->rn = 0;
        c->last_ms = now_ms();
        up->q_sent++;
        if (conn_write(c, buf, (size_t)hn + r->qn) != 0) return -1;
        return 0;
    }
    uint8_t buf[2 + DUP_QMAX];
    buf[0] = (uint8_t)(r->qn >> 8);
    buf[1] = (uint8_t)r->qn;
    memcpy(buf + 2, r->q, r->qn);
    c->busy++;
    c->last_ms = now_ms();
    up->q_sent++;
    return conn_write(c, buf, (size_t)r->qn + 2) == 0 ? 0 : -1;
}

/* ---- установка соединения -------------------------------------------------------------------- */

static void dial_event_cb(struct dial *d);

static int up_conns_alive(const struct dup *up) {
    int n = 0;
    for (int i = 0; i < DUP_CONNS; i++) n += up->c[i].st != CS_FREE;
    return n;
}

static int up_want_conns(const struct dup *up) {
    if (up->cfg.u.proto != DNSP_DOH) return 1;
    /* DoH: по соединению на ожидающий вопрос, но не больше DUP_CONNS, и уже идущие не считаются. */
    int waiting = 0;
    for (int k = 0; k < DUP_MAXREQ; k++)
        if (g_req[k].used && g_req[k].up == up && g_req[k].ci == -1) waiting++;
    return waiting > DUP_CONNS ? DUP_CONNS : (waiting ? waiting : 1);
}

static void fail_waiting(struct dup *up) {
    for (int k = 0; k < DUP_MAXREQ; k++)
        if (g_req[k].used && g_req[k].up == up && g_req[k].ci == -1) req_finish(&g_req[k], NULL, 0);
}

static void up_backoff(struct dup *up) {
    up->backoff_ms = up->backoff_ms ? up->backoff_ms * 2 : 1000;
    if (up->backoff_ms > DUP_BACKOFF_MAX) up->backoff_ms = DUP_BACKOFF_MAX;
    up->retry_at_ms = now_ms() + up->backoff_ms;
}

/* Начать соединение по TCP без TLS (tcp://): неблокирующий connect в цикле. */
static int tcp_dial(struct dup *up, struct dconn *c) {
    int fd = socket(up->srv.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (up->cfg.mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &up->cfg.mark, sizeof(up->cfg.mark)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (const struct sockaddr *)&up->srv, (socklen_t)sa_len(&up->srv)) != 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    c->fd = fd;
    c->st = CS_TCPCONN;
    c->last_ms = now_ms();
    conn_register(c, EPOLLOUT);
    return 0;
}

static void up_dial(struct dup *up) {
    struct dconn *c = NULL;
    for (int i = 0; i < DUP_CONNS; i++) if (up->c[i].st == CS_FREE) { c = &up->c[i]; break; }
    if (!c) return;
    c->up = up;
    c->tag.magic = DTAG_MAGIC; c->tag.kind = DT_CONN; c->tag.obj = c;
    if (!tls_proto(up)) {
        if (tcp_dial(up, c) != 0) {
            up_err(up, "TCP: %s", strerror(errno));
            up_backoff(up);
            fail_waiting(up);
        }
        return;
    }
    struct dial *d = calloc(1, sizeof(*d));
    int sv[2] = { -1, -1 };
    if (!d || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
        free(d);
        up_err(up, "нет ресурсов для соединения");
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    d->fd = -1;
    d->tag.magic = DTAG_MAGIC; d->tag.kind = DT_DIAL; d->tag.obj = d;
    d->rfd = sv[0]; d->wfd = sv[1];
    d->up = up; d->up_gen = up->gen; d->conn = cidx(c);
    d->u = up->cfg.u;
    d->mark = up->cfg.mark;
    d->doh = up->cfg.u.proto == DNSP_DOH;
    d->timeout_ms = DUP_DIAL_MS;
    if (g_dup_ca_file) snprintf(d->ca, sizeof(d->ca), "%s", g_dup_ca_file);
    long now = now_ms();
    d->cached_n = up->ad_n;
    d->cached_fresh = up->ad_n && now < up->ad_exp_ms;
    for (int i = 0; i < up->ad_n; i++) d->cached[i] = up->ad[i];
    struct epoll_event e = {0};
    e.events = EPOLLIN;
    e.data.ptr = &d->tag;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, sv[0], &e) != 0 || dial_launch(d) != 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, sv[0], NULL);
        close(sv[0]); close(sv[1]);
        up_err(up, "%s", d->err[0] ? d->err : "соединение не начато");
        free(d);
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    c->st = CS_DIAL;
    c->dial = d;
    up->dialing++;
}

static void dial_event_cb(struct dial *d) {
    char b;
    ssize_t k;
    do k = recv(d->rfd, &b, 1, 0); while (k < 0 && errno == EINTR);
    if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, d->rfd, NULL);
    close(d->rfd);
    struct dup *up = d->up;
    int same = up->live && up->gen == d->up_gen && !d->cancel;
    int alive = same && k > 0;
    struct dconn *c = &up->c[d->conn];
    if (same) { c->dial = NULL; up->dialing--; }
    if (!alive || d->rc != 0) {
        if (d->fd >= 0) close(d->fd);
        if (d->tls) { if (tls13_free) tls13_free(d->tls); free(d->tls); }
        if (same) {
            c->st = CS_FREE;
            up_err(up, "%s", d->err[0] ? d->err : "соединение не установилось");
            /* Найденные адреса не подошли — в следующий раз искать заново. */
            if (!d->res_n) up->ad_n = 0;
            up_backoff(up);
            fail_waiting(up);
        }
        free(d);
        return;
    }
    if (d->res_n) {
        for (int i = 0; i < d->res_n; i++) up->ad[i] = d->res[i];
        up->ad_n = d->res_n;
        up->ad_exp_ms = now_ms() + d->res_ttl * 1000L;
    }
    c->fd = d->fd;
    c->tls = d->tls;
    c->st = CS_READY;
    c->last_ms = now_ms();
    c->busy = 0;
    up->backoff_ms = 0;
    up->retry_at_ms = 0;
    up->err[0] = '\0';
    free(d);
    conn_register(c, EPOLLIN);
    up_kick(up);
}

/* ---- диспетчер ожидающих --------------------------------------------------------------------- */

static struct dconn *pick_conn(struct dup *up) {
    struct dconn *best = NULL;
    for (int i = 0; i < DUP_CONNS; i++) {
        struct dconn *c = &up->c[i];
        if (c->st != CS_READY) continue;
        if (up->cfg.u.proto == DNSP_DOH) { if (!c->busy) return c; }
        else if (!best || c->busy < best->busy) best = c;
    }
    return best;
}

static void up_kick(struct dup *up) {
    for (int k = 0; k < DUP_MAXREQ; k++) {
        struct dreq *r = &g_req[k];
        if (!r->used || r->up != up || r->ci != -1) continue;
        struct dconn *c = pick_conn(up);
        if (!c) break;
        if (conn_send(up, c, r) != 0) { conn_close(c, "запись в соединение не удалась"); k = -1; }
    }
    int waiting = 0;
    for (int k = 0; k < DUP_MAXREQ; k++) if (g_req[k].used && g_req[k].up == up && g_req[k].ci == -1) waiting++;
    if (!waiting) return;
    if (now_ms() < up->retry_at_ms) { fail_waiting(up); return; }
    int have = 0;
    for (int i = 0; i < DUP_CONNS; i++) have += up->c[i].st == CS_DIAL || up->c[i].st == CS_TCPCONN;
    if (have < up_want_conns(up) && up_conns_alive(up) < DUP_CONNS) up_dial(up);
}

/* ---- чтение ---------------------------------------------------------------------------------- */

static struct dreq *find_by_wid(struct dup *up, int ci, uint16_t wid) {
    for (int k = 0; k < DUP_MAXREQ; k++) {
        struct dreq *r = &g_req[k];
        if (r->used && r->up == up && r->ci == ci && r->wid == wid) return r;
    }
    return NULL;
}

static void stream_frames(struct dconn *c) {
    struct dup *up = c->up;
    size_t off = 0;
    while (c->rn - off >= 2) {
        size_t len = ((size_t)c->rb[off] << 8) | c->rb[off + 1];
        if (c->rn - off < 2 + len) break;
        uint8_t *m = c->rb + off + 2;
        if (len >= 12) {
            struct dreq *r = find_by_wid(up, cidx(c), (uint16_t)((m[0] << 8) | m[1]));
            if (r && same_question(r, m, len)) {
                if (c->busy > 0) c->busy--;
                req_finish(r, m, len);
            }
        }
        off += 2 + len;
    }
    if (off) {
        memmove(c->rb, c->rb + off, c->rn - off);
        c->rn -= off;
    }
}

static int ci_lower(const char *s, const char *word) {
    return strncasecmp(s, word, strlen(word)) == 0;
}

/* Разбор ответа HTTP по накопленным байтам. 1 — ответ целиком доставлен; 0 — ждём; -1 — соединение
 * негодно. */
static int doh_parse(struct dconn *c) {
    struct dup *up = c->up;
    if (!c->hdr_done) {
        uint8_t *e = NULL;
        for (size_t i = 0; i + 3 < c->rn; i++)
            if (!memcmp(c->rb + i, "\r\n\r\n", 4)) { e = c->rb + i; break; }
        if (!e) return c->rn > 16384 ? -1 : 0;
        size_t hl = (size_t)(e - c->rb);
        char *h = malloc(hl + 1);
        if (!h) return -1;
        memcpy(h, c->rb, hl);
        h[hl] = '\0';
        int code = 0;
        if (sscanf(h, "HTTP/1.%*d %d", &code) != 1) { free(h); return -1; }
        c->clen = -1;
        c->chunked = 0;
        c->close_after = 0;
        for (char *ln = strstr(h, "\r\n"); ln; ln = strstr(ln + 2, "\r\n")) {
            char *v = ln + 2;
            if (ci_lower(v, "content-length:")) c->clen = strtol(v + 15, NULL, 10);
            else if (ci_lower(v, "transfer-encoding:")) {
                char *t = v + 18;
                size_t l = strcspn(t, "\r\n");
                for (size_t i = 0; i + 7 <= l; i++) if (strncasecmp(t + i, "chunked", 7) == 0) c->chunked = 1;
            } else if (ci_lower(v, "connection:")) {
                char *t = v + 11;
                size_t l = strcspn(t, "\r\n");
                for (size_t i = 0; i + 5 <= l; i++) if (strncasecmp(t + i, "close", 5) == 0) c->close_after = 1;
            }
        }
        free(h);
        c->hdr_done = 1;
        c->body_off = hl + 4;
        if (code != 200) {
            up_err(up, "HTTP %d от сервера", code);
            return -1;
        }
        if (c->clen < 0 && !c->chunked) { up_err(up, "ответ HTTP без длины"); return -1; }
    }
    const uint8_t *body = c->rb + c->body_off;
    size_t have = c->rn - c->body_off;
    uint8_t *msg = NULL;
    size_t mlen = 0;
    uint8_t dec[DUP_QMAX * 4];
    if (c->chunked) {
        size_t o = 0, out = 0;
        int done = 0;
        while (o < have) {
            char sz[20];
            size_t l = 0;
            while (o + l < have && body[o + l] != '\r' && l < sizeof(sz) - 1) { sz[l] = (char)body[o + l]; l++; }
            if (o + l + 2 > have) break;
            sz[l] = '\0';
            long cl = strtol(sz, NULL, 16);
            if (cl < 0 || (size_t)cl > sizeof(dec)) return -1;
            o += l + 2;
            if (cl == 0) { done = o + 2 <= have; break; }
            if (o + (size_t)cl + 2 > have) break;
            if (out + (size_t)cl > sizeof(dec)) return -1;
            memcpy(dec + out, body + o, (size_t)cl);
            out += (size_t)cl;
            o += (size_t)cl + 2;
        }
        if (!done) return 0;
        msg = dec;
        mlen = out;
    } else {
        if ((long)have < c->clen) return c->clen > DUP_RBUF_MAX ? -1 : 0;
        msg = c->rb + c->body_off;
        mlen = (size_t)c->clen;
    }
    struct dreq *r = req_at(c->busy - 1);
    c->busy = 0;
    c->hdr_done = 0;
    c->rn = 0;
    if (r && mlen >= 12 && same_question(r, msg, mlen)) {
        c->last_ms = now_ms();
        req_finish(r, msg, mlen);
    } else if (r) {
        up_err(up, "ответ не на наш вопрос");
        req_finish(r, NULL, 0);
    }
    return 1;
}

static void conn_readable(struct dconn *c) {
    struct dup *up = c->up;
    if (c->st == CS_TCPCONN) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            up_err(up, "TCP: %s", strerror(err ? err : errno));
            conn_close(c, NULL);
            up_backoff(up);
            fail_waiting(up);
            return;
        }
        c->st = CS_READY;
        c->busy = 0;
        up->backoff_ms = 0;
        up->retry_at_ms = 0;
        up->err[0] = '\0';
        conn_ev(c, EPOLLIN);
        up_kick(up);
        return;
    }
    for (int guard = 0; guard < 64; guard++) {
        if (c->tls) {
            static unsigned char pl[TLS13_MAX_PLAIN + 16];
            size_t got = 0;
            int rc = tls13_read ? tls13_read(c->tls, pl, sizeof(pl), &got) : -1;
            if (rc != 0) { conn_close(c, rc == TLS13_ECLOSED ? "сервер закрыл соединение" : "ошибка TLS"); return; }
            if (got) {
                if (rb_reserve(c, got) != 0) { conn_close(c, "ответ слишком велик"); return; }
                memcpy(c->rb + c->rn, pl, got);
                c->rn += got;
            }
            if (up->cfg.u.proto == DNSP_DOH) {
                if (c->rn) {
                    int pr = doh_parse(c);
                    if (pr < 0) { conn_close(c, NULL); return; }
                    if (pr == 1 && c->close_after) { conn_close(c, NULL); up_kick(up); return; }
                }
            } else if (got) {
                stream_frames(c);
            }
            if (!got && !(tls13_has_record && tls13_has_record(c->tls))) break;
        } else {
            if (rb_reserve(c, 4096) != 0) { conn_close(c, "ответ слишком велик"); return; }
            ssize_t r = recv(c->fd, c->rb + c->rn, c->rcap - c->rn, MSG_DONTWAIT);
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
            if (r <= 0) { conn_close(c, "сервер закрыл соединение"); return; }
            c->rn += (size_t)r;
            stream_frames(c);
        }
    }
    up_kick(up);
}

static void conn_writable(struct dconn *c) {
    if (c->st == CS_TCPCONN) { conn_readable(c); return; }
    while (c->woff < c->wn) {
        ssize_t w = send(c->fd, c->wb + c->woff, c->wn - c->woff, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            conn_close(c, "запись в соединение не удалась");
            return;
        }
        c->woff += (size_t)w;
    }
    c->wn = c->woff = 0;
    conn_ev(c, EPOLLIN);
}

/* ---- UDP ------------------------------------------------------------------------------------- */

static int udp_open(struct dup *up) {
    if (up->ufd >= 0) return 0;
    if (!up->srv_ok) return -1;
    int fd = socket(up->srv.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (up->cfg.mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &up->cfg.mark, sizeof(up->cfg.mark)) != 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (const struct sockaddr *)&up->srv, (socklen_t)sa_len(&up->srv)) != 0) {
        close(fd);
        return -1;
    }
    struct epoll_event e = {0};
    e.events = EPOLLIN;
    e.data.ptr = &up->utag;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &e) != 0) { close(fd); return -1; }
    up->ufd = fd;
    return 0;
}

static int udp_send(struct dup *up, struct dreq *r) {
    if (udp_open(up) != 0) return -1;
    if (send(up->ufd, r->q, r->qn, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) return -1;
    up->q_sent += r->tries == 0;
    return 0;
}

static void udp_readable(struct dup *up) {
    for (int guard = 0; guard < 64; guard++) {
        uint8_t buf[4096];
        ssize_t n = recv(up->ufd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            /* Отложенная ошибка сокета (ICMP unreachable): следующее чтение — дальше. */
            up_err(up, "UDP: %s", strerror(errno));
            continue;
        }
        if (n < 12) continue;
        struct dreq *r = find_by_wid(up, -1, (uint16_t)((buf[0] << 8) | buf[1]));
        /* UDP-вопросы живут с ci == -2: не «ждёт соединения» (-1), а «в полёте по UDP». */
        if (!r) r = find_by_wid(up, -2, (uint16_t)((buf[0] << 8) | buf[1]));
        if (!r || r->tcp || !same_question(r, buf, (size_t)n)) continue;
        if (buf[2] & 0x02) {                                      /* TC: то же самое по TCP */
            r->tcp = 1;
            r->ci = -1;
            up_kick(up);
            continue;
        }
        req_finish(r, buf, (size_t)n);
    }
}

/* ---- публичное ------------------------------------------------------------------------------- */

static void up_reset_state(struct dup *up) {
    up->ad_n = 0;
    up->backoff_ms = 0;
    up->retry_at_ms = 0;
    up->err[0] = '\0';
    up->dialing = 0;
    up->q_sent = up->q_ok = up->q_fail = 0;
}

static void up_retire(struct dup *up) {
    if (!up->live) return;
    for (int i = 0; i < DUP_CONNS; i++) {
        struct dconn *c = &up->c[i];
        if (c->dial) { c->dial->cancel = 1; c->dial = NULL; }
        if (c->st != CS_FREE && c->st != CS_DIAL) {
            /* Вопросы без повтора: апстрима больше нет. */
            for (int k = 0; k < DUP_MAXREQ; k++)
                if (g_req[k].used && g_req[k].up == up && g_req[k].ci == i) g_req[k].tries = 2;
            conn_close(c, NULL);
        }
        c->st = CS_FREE;
    }
    for (int k = 0; k < DUP_MAXREQ; k++)
        if (g_req[k].used && g_req[k].up == up) req_finish(&g_req[k], NULL, 0);
    if (up->ufd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, up->ufd, NULL);
        close(up->ufd);
        up->ufd = -1;
    }
    up->live = 0;
    up->gen++;
}

static int cfg_same(const struct dup_cfg *a, const struct dup_cfg *b) {
    if (strcmp(a->u.name, b->u.name) || strcmp(a->u.url, b->u.url) || strcmp(a->via, b->via) ||
        a->mark != b->mark || a->need_mark != b->need_mark || a->u.ips_n != b->u.ips_n ||
        a->u.boot_n != b->u.boot_n)
        return 0;
    for (int i = 0; i < a->u.ips_n; i++) if (strcmp(a->u.ips[i], b->u.ips[i])) return 0;
    for (int i = 0; i < a->u.boot_n; i++) if (strcmp(a->u.boot[i], b->u.boot[i])) return 0;
    return 1;
}

void dup_apply(const struct dup_cfg *c, size_t n) {
    if (n > MAX_DNS_UP) n = MAX_DNS_UP;
    struct dup *old[MAX_DNS_UP], *nw[MAX_DNS_UP];
    size_t oldn = g_dups_n;
    memcpy(old, g_dups, sizeof(old));
    int taken[MAX_DNS_UP] = { 0 };
    for (size_t i = 0; i < n; i++) {
        nw[i] = NULL;
        for (size_t j = 0; j < oldn; j++)
            if (!taken[j] && cfg_same(&old[j]->cfg, &c[i])) { taken[j] = 1; nw[i] = old[j]; break; }
    }
    for (size_t j = 0; j < oldn; j++) if (!taken[j]) up_retire(old[j]);
    for (size_t i = 0; i < n; i++) {
        if (nw[i]) continue;
        struct dup *up = NULL;
        for (size_t k = 0; k < sizeof(g_store) / sizeof(g_store[0]); k++)
            if (!g_store[k].live) { up = &g_store[k]; break; }
        if (!up) continue;
        unsigned gen = up->gen;
        memset(up, 0, sizeof(*up));
        up->gen = gen + 1;
        up->live = 1;
        up->ufd = -1;
        up->cfg = c[i];
        up->utag.magic = DTAG_MAGIC; up->utag.kind = DT_UDP; up->utag.obj = up;
        for (int k = 0; k < DUP_CONNS; k++) {
            up->c[k].up = up; up->c[k].fd = -1;
            up->c[k].tag.magic = DTAG_MAGIC; up->c[k].tag.kind = DT_CONN; up->c[k].tag.obj = &up->c[k];
        }
        up_reset_state(up);
        uint16_t seed = 0;
        if (getrandom(&seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) seed = (uint16_t)time(NULL);
        up->next_id = seed;
        /* Адрес сервера обычного DNS и DoT/DoH-по-адресу известен сразу. */
        struct sockaddr_in *v4 = (struct sockaddr_in *)&up->srv;
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&up->srv;
        if (inet_pton(AF_INET, up->cfg.u.host, &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
            v4->sin_port = htons(up->cfg.u.port);
            up->srv_ok = 1;
        } else if (inet_pton(AF_INET6, up->cfg.u.host, &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
            v6->sin6_port = htons(up->cfg.u.port);
            up->srv_ok = 1;
        }
        nw[i] = up;
    }
    g_dups_n = 0;
    for (size_t i = 0; i < n; i++) g_dups[g_dups_n++] = nw[i];
}

int dup_ask(size_t idx, const uint8_t *q, size_t n, dup_done_fn cb, void *ctx) {
    if (idx >= g_dups_n || !g_dups[idx] || n < 12 || n > DUP_QMAX) return -1;
    struct dup *up = g_dups[idx];
    if (up->cfg.u.proto == DNSP_QUIC || up->cfg.u.proto == DNSP_NONE) return -1;
    if (up->cfg.need_mark && !up->cfg.mark) {
        up_err(up, "выход «%s» не размечен: запрос через него не отправить", up->cfg.via);
        return -1;
    }
    if (tls_proto(up) && !dup_have_tls()) {
        up_err(up, "в этой сборке нет TLS: DoT и DoH недоступны");
        return -1;
    }
    struct dreq *r = NULL;
    for (int k = 0; k < DUP_MAXREQ; k++) if (!g_req[k].used) { r = &g_req[k]; break; }
    if (!r) return -1;
    memset(r, 0, offsetof(struct dreq, q));
    memcpy(r->q, q, n);
    r->qn = (uint16_t)n;
    r->used = 1;
    r->up = up;
    r->up_gen = up->gen;
    r->oid = (uint16_t)((q[0] << 8) | q[1]);
    for (;;) {                                          /* номер, не занятый другим вопросом апстрима */
        r->wid = up->next_id++;
        int taken = 0;
        for (int k = 0; k < DUP_MAXREQ; k++)
            if (&g_req[k] != r && g_req[k].used && g_req[k].up == up && g_req[k].wid == r->wid) taken = 1;
        if (!taken) break;
    }
    r->q[0] = (uint8_t)(r->wid >> 8);
    r->q[1] = (uint8_t)r->wid;
    r->cb = cb;
    r->ctx = ctx;
    r->t0 = now_ms();
    r->deadline = r->t0 + DUP_REQ_MS;
    r->ci = -1;
    if (up->cfg.u.proto == DNSP_UDP) {
        r->ci = -2;
        if (udp_send(up, r) != 0) {
            up_err(up, "UDP: %s", strerror(errno));
            r->used = 0;
            return -1;
        }
        return 0;
    }
    if (now_ms() < up->retry_at_ms && !pick_conn(up)) {
        r->used = 0;
        return -1;                                     /* пауза после неудачи: отказ сразу */
    }
    up_kick(up);
    if (!r->used) return 0;                             /* отказ уже отдан обратным вызовом */
    return 0;
}

int dup_event(void *ptr, uint32_t evs) {
    struct dtag *t = ptr;
    if (!t || t->magic != DTAG_MAGIC) return 0;
    switch (t->kind) {
    case DT_UDP: {
        struct dup *up = t->obj;
        if (up->live && up->ufd >= 0) udp_readable(up);
        break;
    }
    case DT_CONN: {
        struct dconn *c = t->obj;
        if (c->st != CS_READY && c->st != CS_TCPCONN) break;
        if (evs & (EPOLLERR | EPOLLHUP) && c->st == CS_TCPCONN) { conn_readable(c); break; }
        if (evs & EPOLLOUT) conn_writable(c);
        if (c->fd >= 0 && (evs & (EPOLLIN | EPOLLERR | EPOLLHUP))) conn_readable(c);
        break;
    }
    case DT_DIAL:
        dial_event_cb(t->obj);
        break;
    }
    return 1;
}

void dup_tick(void) {
    long now = now_ms();
    for (int k = 0; k < DUP_MAXREQ; k++) {
        struct dreq *r = &g_req[k];
        if (!r->used) continue;
        struct dup *up = r->up;
        if (up->cfg.u.proto == DNSP_UDP && r->ci == -2 && r->tries == 0 && now - r->t0 >= DUP_UDP_RETRY_MS &&
            now < r->deadline) {
            r->tries = 1;
            udp_send(up, r);
            continue;
        }
        if (now < r->deadline) continue;
        int ci = r->ci;
        up_err(up, "нет ответа за %d мс", DUP_REQ_MS);
        req_finish(r, NULL, 0);
        if (ci >= 0 && up->c[ci].st == CS_READY) {
            if (up->cfg.u.proto == DNSP_DOH) conn_close(&up->c[ci], NULL);
            else if (up->c[ci].busy > 0) up->c[ci].busy--;
        }
    }
    for (size_t i = 0; i < g_dups_n; i++) {
        struct dup *up = g_dups[i];
        for (int k = 0; k < DUP_CONNS; k++) {
            struct dconn *c = &up->c[k];
            if (c->st == CS_READY && !c->busy && now - c->last_ms > DUP_IDLE_MS) conn_close(c, NULL);
        }
    }
}

int dup_wait_ms(void) {
    long now = now_ms(), best = -1;
    for (int k = 0; k < DUP_MAXREQ; k++) {
        if (!g_req[k].used) continue;
        long t = g_req[k].deadline;
        if (g_req[k].ci == -2 && g_req[k].tries == 0 && g_req[k].t0 + DUP_UDP_RETRY_MS < t)
            t = g_req[k].t0 + DUP_UDP_RETRY_MS;
        if (best < 0 || t < best) best = t;
    }
    if (best < 0) return -1;
    return best - now > 0 ? (int)(best - now) : 0;
}

int dup_busy(void) {
    for (int k = 0; k < DUP_MAXREQ; k++) if (g_req[k].used) return 1;
    return 0;
}

void dup_close_all(void) {
    dup_apply(NULL, 0);
}

static const char *up_state(const struct dup *up) {
    if (up->cfg.u.proto == DNSP_QUIC) return "unsupported";
    if (up->cfg.need_mark && !up->cfg.mark) return "unmarked";
    if (tls_proto(up) && !dup_have_tls()) return "no-tls";
    if (stream_proto(up)) {
        for (int i = 0; i < DUP_CONNS; i++) if (up->c[i].st == CS_READY) return "ready";
        if (up->dialing) return "connecting";
        if (now_ms() < up->retry_at_ms) return "down";
        return "idle";
    }
    if (up->q_ok) return up->q_fail > up->q_ok ? "down" : "ready";
    return up->q_fail ? "down" : "idle";
}

static const char *proto_name(int p) {
    switch (p) {
    case DNSP_UDP: return "udp";
    case DNSP_TCP: return "tcp";
    case DNSP_DOT: return "dot";
    case DNSP_DOH: return "doh";
    case DNSP_QUIC: return "doq";
    default: return "?";
    }
}

void dup_render(FILE *f) {
    long now = now_ms();
    for (size_t i = 0; i < g_dups_n; i++) {
        const struct dup *up = g_dups[i];
        int conns = 0, queued = 0;
        for (int k = 0; k < DUP_CONNS; k++) conns += up->c[k].st == CS_READY;
        for (int k = 0; k < DUP_MAXREQ; k++) queued += g_req[k].used && g_req[k].up == up;
        fprintf(f, "%s{\"name\":\"%s\",\"url\":\"%s\",\"proto\":\"%s\",\"via\":", i ? "," : "",
                up->cfg.u.name, up->cfg.u.url, proto_name(up->cfg.u.proto));
        if (up->cfg.via[0]) fprintf(f, "\"%s\"", up->cfg.via); else fputs("null", f);
        fprintf(f, ",\"state\":\"%s\",\"conns\":%d,\"inflight\":%d,\"sent\":%lu,\"ok\":%lu,\"failed\":%lu,"
                   "\"last_ok_ago\":", up_state(up), conns, queued, up->q_sent, up->q_ok, up->q_fail);
        if (up->ok_ms) fprintf(f, "%ld", (now - up->ok_ms) / 1000); else fputs("null", f);
        fputs(",\"error\":", f);
        if (up->err[0]) {
            fputc('"', f);
            for (const char *p = up->err; *p; p++) {
                if (*p == '"' || *p == '\\') fputc('\\', f);
                if ((unsigned char)*p >= 0x20) fputc(*p, f);
            }
            fprintf(f, "\",\"error_ago\":%ld", (now - up->err_ms) / 1000);
        } else {
            fputs("null,\"error_ago\":null", f);
        }
        fputc('}', f);
    }
}
