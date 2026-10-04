/* A server's answer to an xhttp upload (stream-up and packet-up): a refusal must reach the sender.
 *
 * In stream-up and packet-up the upload goes over its own link, and its answers are read only by
 * up_drain, which runs as part of a write. The xhttp server answers 400 to a chunk with bad
 * padding; if up_drain drops that answer, the write reports success, and the node looks alive
 * while no data flows. packet-up is harder: the answer to a chunk arrives when the next chunk is
 * already open, so h2.c must not throw it away as a frame of another stream. The
 * tests/run-tunnel*.sh stands do not reach this: their fake server speaks bare TCP, not xhttp.
 *
 * The file includes the xhttp transport whole (src/proto/transport/trxhttp.c: up_drain and
 * up_request are static) and links the real h2.c and the other transport layers as separate
 * objects. The upload link is plain (as with security=none) on a socket pair: what the client
 * writes, the test reads and drops, and the "server" writes HTTP/2 frames to the other end by
 * hand. TLS and Reality are not needed and are stubbed out. No header stubs are needed: tls13.h
 * includes only src/lib/scrypto.h, which has no crypto library types. No network and no
 * privileges, so the test runs in `make test`. */
#include "../src/proto/transport/trxhttp.c"

#include <stdlib.h>
#include <sys/socket.h>
#include "reality.h"

/* ---- TLS and Reality stubs: the test link is plain, they are never reached --------- */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
/* trsec.c also calls the carrier variant (ALPN http/1.1 for ws and httpupgrade); not reached
 * here either. */
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
/* trsec.c parses the pqv key with it (reality.c); not reached here. */
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n)
    { (void)in; (void)out; (void)out_n; return -1; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap)
    { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn)
    { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

/* ---- test -------------------------------------------------------------------------- */

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-74s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* the "server" end of the socket pair */

/* Drop everything the client has written so far: preface, HEADERS, DATA. */
static void srv_drain(void) {
    unsigned char b[8192];
    while (recv(g_srv, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

/* HEADERS from the server on stream sid with one HPACK byte, a static index of :status:
 * 0x88 is 200, 0x8C is 400 (RFC 7541, Appendix A). */
static void srv_headers(uint32_t sid, unsigned char hpack, int end_stream) {
    unsigned char f[10] = { 0, 0, 1, 0x01, (unsigned char)(0x04 | (end_stream ? 0x01 : 0)),
                            (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, hpack };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

static void conn_init(struct transport *c, enum xhttp_mode xh, int fd) {
    memset(c, 0, sizeof(*c));
    c->link.fd = -1;
    c->fr = &tr_xhttp;
    c->xh.mode = xh;
    c->xh.up.link.fd = fd;
    c->xh.up.link.plain = 1;
    snprintf(c->xh.authority, sizeof(c->xh.authority), "stand.example");
    snprintf(c->xh.up_path, sizeof(c->xh.up_path), "/xh/0f1e2d3c");
}

static int new_pair(int *cli) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    *cli = sp[0];
    return 0;
}

static const unsigned char piece[] = "upload chunk";

/* packet-up: the answer to chunk 0 arrives when chunk 1 is already open. */
static void t_packet_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* chunk 0, stream 1 */
    srv_drain();
    srv_headers(1, hpack, 1);                                /* answer to chunk 0 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* chunk 1, stream 3 */
    srv_drain();
    if (want_refused)
        check(rc0 == 0 && rc1 == H2_ESTATUS &&
              strstr(transport_strerror(rc1), "400") != NULL, what);
    else
        check(rc0 == 0 && rc1 == 0, what);
    close(fd);
}

/* stream-up: one long POST, and the refusal comes on that same stream. */
static void t_stream_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "socket pair created"); return; }
    struct transport c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);                        /* as up_open does: the POST opens at once */
    srv_drain();
    srv_headers(1, hpack, 0);
    int rc = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    if (want_refused)
        check(ro == 0 && rc == H2_ESTATUS && strstr(transport_strerror(rc), "400") != NULL, what);
    else
        check(ro == 0 && rc == 0, what);
    close(fd);
}

int main(void) {
    t_packet_up(0x8C, 1, "packet-up: 400 to the previous chunk fails the next write, naming 400");
    t_packet_up(0x88, 0, "packet-up: 200 to the previous chunk is not a refusal");
    t_stream_up(0x8C, 1, "stream-up: 400 to the upload fails the write, naming 400");
    t_stream_up(0x88, 0, "stream-up: 200 to the upload is not a refusal");
    printf(g_fail ? "\nxhupmatch: FAILED\n" : "\nall checks passed\n");
    return g_fail;
}
