/* Дайлеры steer-proxy без сети и криптографии: trojan (разбор UDP вниз) и http (CONNECT) через
 * таблицы dialer_ops, как их зовёт стек. Транспорт подменён заглушками ниже: запись копится в
 * буфер, чтение отдаёт заготовленный ответ сервера. Провод против настоящего сервера — run-proxy.sh. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "proxy.h"
#include "pxdial.h"
#include "pxwire.h"
#include "scrypto.h"
#include "unit.h"

/* ---- заглушки ------------------------------------------------------------------------------ */

static unsigned char g_tx[8192];
static size_t g_tx_n;
static const unsigned char *g_rx;     /* ответ сервера: отдаётся кусками по g_rx_chunk */
static size_t g_rx_n, g_rx_off, g_rx_chunk = 4096;

time_t stack_now_s(void) { return time(NULL); }
void px_watch_seen(int rc) { (void)rc; }
const char *px_strerror(int rc) { (void)rc; return "?"; }
int px_stream_open(const struct px_node *n, struct transport *t, int timeout_s) {
    (void)n; (void)timeout_s; t->link.fd = 99; return 0;
}
int transport_write(struct transport *t, const unsigned char *d, size_t n) {
    (void)t;
    if (g_tx_n + n > sizeof g_tx) return TR_EIO;
    memcpy(g_tx + g_tx_n, d, n); g_tx_n += n;
    return 0;
}
int transport_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    (void)t;
    size_t k = g_rx_n - g_rx_off;
    if (!k) return TR_ECLOSED;
    if (k > g_rx_chunk) k = g_rx_chunk;
    if (k > cap) k = cap;
    memcpy(d, g_rx + g_rx_off, k); g_rx_off += k; *got = k;
    return 0;
}
int transport_read_zc(struct transport *t, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    *data = buf; *got = 0;
    return transport_read(t, buf, cap, got);
}
int transport_has_data(const struct transport *t) { (void)t; return 0; }
void transport_moved(struct transport *t) { (void)t; }
void transport_close(struct transport *t) { t->link.fd = -1; }
int sc_hash(enum sc_hash h, const void *d, size_t n, unsigned char *out) {
    (void)h; (void)d; (void)n; memset(out, 0xab, 28); return 0;
}
size_t px_socks_addr(unsigned char *out, uint32_t dst_net, uint16_t dport_host) {
    out[0] = 1; memcpy(out + 1, &dst_net, 4);
    out[5] = (unsigned char)(dport_host >> 8); out[6] = (unsigned char)dport_host;
    return 7;
}

static unsigned char g_em[8192];
static size_t g_em_n, g_em_calls;
static int emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    if (g_em_n + n <= sizeof g_em) { memcpy(g_em + g_em_n, p, n); g_em_n += n; }
    g_em_calls++;
    return 0;
}

static void feed_reset(const unsigned char *rx, size_t n) {
    g_rx = rx; g_rx_n = n; g_rx_off = 0; g_tx_n = 0; g_em_n = 0; g_em_calls = 0;
}

/* ---- trojan: UDP вниз ---------------------------------------------------------------------- */

static void trojan_deliver_bytes(const unsigned char *pkt, size_t n, size_t step) {
    const struct dialer_ops *ops = &proxy_trojan_dialer;
    struct px_node node; memset(&node, 0, sizeof node);
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&node, sess, &k, 1);
    feed_reset(NULL, 0);
    for (size_t o = 0; o < n; o += step)
        ops->deliver(&node, sess, 1, pkt + o, n - o < step ? n - o : step, emit, NULL);
    free(sess);
}

static void test_trojan_udp(void) {
    /* Ответ с адресом-именем (ATYP 3): [3][len][имя][порт][длина(2)][CRLF][данные]. */
    static const unsigned char dom[] = {
        3, 11, 'e','x','a','m','p','l','e','.','c','o','m', 0x00, 0x35,
        0x00, 0x04, '\r', '\n', 'p','o','n','g',
        1, 1, 2, 3, 4, 0x00, 0x35, 0x00, 0x02, '\r', '\n', 'o','k',
    };
    trojan_deliver_bytes(dom, sizeof dom, sizeof dom);
    check("trojan udp: адрес-имя, затем IPv4 — две датаграммы", 2, (long)g_em_calls);
    check("trojan udp: нагрузка «pongok»", 1, g_em_n == 6 && !memcmp(g_em, "pongok", 6));
    trojan_deliver_bytes(dom, sizeof dom, 1);
    check("trojan udp: адрес-имя по байту — две датаграммы", 2, (long)g_em_calls);
    check("trojan udp: по байту — нагрузка «pongok»", 1, g_em_n == 6 && !memcmp(g_em, "pongok", 6));
}

/* ---- http CONNECT ------------------------------------------------------------------------- */

static void http_node(struct px_node *n, const char *user, const char *pass) {
    memset(n, 0, sizeof *n);
    n->proto = PX_HTTP;
    snprintf(n->user, sizeof n->user, "%s", user);
    snprintf(n->pass, sizeof n->pass, "%s", pass);
}

static int http_connect_with(const struct px_node *n, const char *resp, size_t resp_n, void **sessp) {
    const struct dialer_ops *ops = &proxy_http_dialer;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "1.2.3.4", &k.dst); k.dport = 443;
    ops->flow_open(n, sess, &k, 0);
    feed_reset((const unsigned char *)resp, resp_n);
    int rc = ops->connect(n, sess, 2);
    if (sessp) *sessp = sess; else free(sess);
    return rc;
}

static void test_http_long_auth(void) {
    /* Имя и пароль наибольшей длины, какую держит узел: запрос обязан уйти целиком. */
    char user[PX_USER_MAX], pass[PX_PASS_MAX];
    memset(user, 'u', sizeof user - 1); user[sizeof user - 1] = 0;
    memset(pass, 'p', sizeof pass - 1); pass[sizeof pass - 1] = 0;
    struct px_node n;
    http_node(&n, user, pass);
    static const char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    check("http: длинные имя и пароль — CONNECT прошёл", 0, http_connect_with(&n, ok, sizeof ok - 1, NULL));
    g_tx[g_tx_n < sizeof g_tx ? g_tx_n : sizeof g_tx - 1] = 0;
    check("http: запрос кончается пустой строкой", 1,
          g_tx_n >= 4 && !memcmp(g_tx + g_tx_n - 4, "\r\n\r\n", 4));
    /* base64 от «u…u:p…p»: 127 + 1 + 255 = 383 байта → 512 знаков. */
    const char *b = strstr((const char *)g_tx, "Proxy-Authorization: Basic ");
    size_t bl = b ? strcspn(b + 27, "\r") : 0;
    check("http: Basic целиком (512 знаков)", 512, (long)bl);
}

int main(void) {
    test_trojan_udp();
    test_http_long_auth();
    return unit_done("pxdialmatch");
}
