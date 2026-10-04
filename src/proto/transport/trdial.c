/* The socket to the node: TCP to EVERY address of the name, not just the first, plus the mark
 * and the bound device that keep it out of the tunnel (the lower layer of transport.h). Nothing
 * here depends on the protocol.
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

/* ---- TCP connect: EVERY address of the node, not the first ----------------------------
 *
 * A node name is often several addresses, and some may be black holes: a SYN goes out and nothing
 * comes back (one real node had fifteen A records, six of them dead). DNS shuffles the list on
 * every query, so "the first address" changes each time. Using only the first one is worse than
 * "sometimes fails to connect":
 *
 *   - a blocking connect to a black hole waits the whole SO_SNDTIMEO, holding the thread;
 *   - Linux reports that timeout as EINPROGRESS, not ETIMEDOUT (__inet_stream_connect: when timeo
 *     runs out err stays -EINPROGRESS), so the log shows "Operation in progress" for a blocking
 *     call and hides both the timeout and the dead address;
 *   - a health check of the node becomes a coin toss.
 *
 * So: a non-blocking connect with its own timeout instead of SO_SNDTIMEO, several staggered
 * attempts at once, and the winning address is remembered so the next connection starts with
 * it. */

#define ADDR_MAX      16   /* addresses of a name considered at all */
#define ATTEMPT_MAX    4   /* attempts in flight at once */
#define STAGGER_MS   150   /* pause before starting the next attempt */

/* The winning address per name, per thread: no lock is needed, and each thread learning on its
 * own costs one extra search per thread at startup. */
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

/* Clears O_NONBLOCK on a connected socket (reads and writes from here on block, with SO_*TIMEO
 * timeouts) and sets its options. */
static void sock_ready(int fd, int timeout_s) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    /* Without a read and write timeout a dead node holds a probe until the kernel gives up —
     * minutes in which the pool cannot get round the other candidates. */
    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* SO_RCVBUF is deliberately NOT set. Any setsockopt(SO_RCVBUF) DISABLES Linux receive
     * window autotuning and pins the window at that size. Throughput is window / RTT: half a
     * megabyte at a 60 ms RTT caps it at 68 Mbit/s whatever the link, while autotuning grows to
     * several megabytes on its own. The limits belong to the system, in net.ipv4.tcp_rmem. */
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

/* Starts a non-blocking connect. Returns the fd (connected, *done = 1, or in progress) or
 * -1. */
static int attempt_start(struct in_addr ip, uint16_t port, int *done) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    /* Before connect(): the kernel picks the route, and with it the device and the source
     * address, there — by the mark. */
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

    /* The last winner goes first: in steady state one connect takes one round trip instead of
     * going through the dead addresses again each time. */
    struct in_addr *g = good_get(host, port);
    if (g) for (unsigned i = 1; i < an; i++)
        if (addr[i].s_addr == g->s_addr) { struct in_addr t = addr[0]; addr[0] = addr[i]; addr[i] = t; break; }

    int fd[ATTEMPT_MAX];
    struct in_addr fa[ATTEMPT_MAX];
    unsigned nf = 0;     /* attempts in flight */
    unsigned next = 0;   /* next address to start */
    unsigned dead = 0;   /* addresses that failed */
    int64_t deadline = now_ms() + (long long)timeout_s * 1000;
    int64_t stagger_at = 0;
    int win = -1;

    while (win < 0) {
        int64_t t = now_ms();
        if (t >= deadline) break;

        /* Start new attempts: the first at once, the next ones STAGGER_MS apart, so that with a
         * live first address (the usual case) no second socket is opened at all. */
        while (nf < ATTEMPT_MAX && next < an && t >= stagger_at) {
            int d = 0;
            struct in_addr ip = addr[next++];
            int s = attempt_start(ip, port, &d);
            if (s < 0) { dead++; continue; }
            if (d) {   /* connected at once: usually an address on the local network */
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
        if (nf == 0) break;   /* no addresses left and no attempt alive */

        struct pollfd pv[ATTEMPT_MAX];
        for (unsigned i = 0; i < nf; i++) { pv[i].fd = fd[i]; pv[i].events = POLLOUT; pv[i].revents = 0; }

        /* Wait until the next attempt is due or the deadline passes. The stagger counts only if
         * another attempt can start: otherwise, with ATTEMPT_MAX in flight and addresses left,
         * poll gets a 0 timeout and the loop spins, eating a CPU. */
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
            /* This address failed: free its place and try the next one at once. */
            close(fd[i]); dead++;
            nf--; fd[i] = fd[nf]; fa[i] = fa[nf]; pv[i] = pv[nf];
            stagger_at = 0;
        }
    }

    if (win < 0) {
        for (unsigned i = 0; i < nf; i++) close(fd[i]);
        /* The message gives the scale: when none of N addresses answers, the problem is the
         * node's name, not the local network. */
        fprintf(stderr, "tunvless: %s:%u — no address answered (%u addresses, %u failed)\n",
                host, port, an, dead);
        return TR_ECONNECT;
    }
    if (dead)
        fprintf(stderr, "tunvless: %s:%u — connected, skipped %u of %u addresses as dead\n",
                host, port, dead, an);
    sock_ready(win, timeout_s);
    return win;
}

/* The TCP connect seam: a test runs the handshake against a peer it holds itself, with no
 * outside socket and no real node. tests/vlessmatch.c includes this file to reach the seam and
 * runs the handshake over a socketpair, so the failure branches (freeing keys and the fd) are
 * checked under AddressSanitizer; fake-vless.py speaks only security=none, and run-reality.sh
 * needs sing-box, root and network namespaces. NULL in production: tcp_connect connects.
 *
 * Returns what tcp_connect does: an fd or a negative TR_* code. */
static int (*g_tcp_dial)(const char *host, uint16_t port, int timeout_s);

int tr_dial(const char *host, uint16_t port, int timeout_s) {
    if (g_tcp_dial) return g_tcp_dial(host, port, timeout_s);
    return tcp_connect(host, port, timeout_s);
}
