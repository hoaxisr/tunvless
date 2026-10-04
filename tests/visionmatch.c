/* Parsing a Vision stream on fixtures: no network, no server, no root.
 *
 * vision_unwrap reads the stream FROM THE SERVER, that is untrusted bytes, and it parses as a
 * stream: state carries over between calls. So what matters is less the content than the
 * SLICING: where exactly a TLS record boundary falls. The live stand (tests/run-tunnel.sh) cannot
 * choose the slicing and does not reach these cases; it runs the good path end to end and needs
 * root with ip netns.
 *
 * Checked: a stream start that arrives in pieces (bytes before the UUID is recognized must not be
 * lost, or the parser loses sync and hands frame header bytes to the client as data), and an
 * invalid command (it must fail every time, never leave the parser consuming zero bytes forever).
 *
 * The module is linked with the test, not included: the state checked here is the fields of
 * struct vision, declared in vision.h, and nothing static in vision.c is needed. */
#include <stdio.h>
#include <string.h>
#include "../src/proto/vless/vision.h"

static int fails;

static void check(const char *what, long want, long got) {
    if (want == got) { printf("%-58s ok\n", what); return; }
    printf("%-58s FAIL: expected %ld, got %ld\n", what, want, got);
    fails++;
}

static const unsigned char UUID[16] = {
    0x96, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* A server stream: UUID, frame header (command, payload length, padding length) and the
 * payload. The same shape vision_wrap builds on the other side. */
static size_t make_stream(unsigned char *out, unsigned char cmd,
                          const char *data, size_t data_n) {
    size_t i = 0;
    memcpy(out + i, UUID, 16); i += 16;
    out[i++] = cmd;
    out[i++] = (unsigned char)(data_n >> 8);
    out[i++] = (unsigned char)(data_n & 0xFF);
    out[i++] = 0;                       /* no padding */
    out[i++] = 0;
    memcpy(out + i, data, data_n); i += data_n;
    return i;
}

/* Feed the whole stream to the parser in chunks of step bytes and collect the output. */
static size_t drain(struct vision *v, const unsigned char *in, size_t n, size_t step,
                    char *out, size_t out_cap, int *rc_out) {
    size_t got = 0, pos = 0;
    *rc_out = 0;
    while (pos < n) {
        size_t chunk = n - pos < step ? n - pos : step;
        size_t off = 0;
        /* Loop within a chunk while the parser consumes or returns something, as
         * downstream_pump in stack.c does. */
        for (;;) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int rc = vision_unwrap(v, in + pos + off, chunk - off, &used, &pl, &pl_n);
            if (rc != 0) { *rc_out = rc; return got; }
            if (pl_n) {
                if (got + pl_n > out_cap) return got;
                memcpy(out + got, pl, pl_n);
                got += pl_n;
            }
            off += used;
            if (!used && !pl_n) break;
            if (off >= chunk) break;
        }
        pos += chunk;
    }
    return got;
}

int main(void) {
    unsigned char stream[256];
    const char *msg = "the payload of one Vision frame";
    size_t msg_n = strlen(msg);
    size_t n = make_stream(stream, VISION_CMD_CONTINUE, msg, msg_n);

    /* The whole stream in one chunk: the base case. */
    {
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        char out[256];
        int rc = 0;
        size_t got = drain(&v, stream, n, n, out, sizeof(out), &rc);
        check("stream in one chunk: no error", 0, rc);
        check("stream in one chunk: payload length", (long)msg_n, (long)got);
        check("stream in one chunk: payload content", 0, memcmp(out, msg, msg_n));
    }

    /* Every chunk size, down to 1 byte. A chunk shorter than the 21-byte start (UUID and
     * first frame header) must be kept, not dropped: otherwise the UUID is compared at a
     * shifted offset, does not match, and the parser slips. */
    {
        int bad_step = -1;
        for (size_t step = 1; step <= n && bad_step < 0; step++) {
            struct vision v;
            memset(&v, 0, sizeof(v));
            memcpy(v.uuid, UUID, 16);
            char out[256];
            int rc = 0;
            size_t got = drain(&v, stream, n, step, out, sizeof(out), &rc);
            if (rc != 0 || got != msg_n || memcmp(out, msg, msg_n) != 0)
                bad_step = (int)step;
        }
        check("any chunk size down to 1 byte gives the same payload", -1, bad_step);
    }

    /* Another UUID: the stream is not wrapped and passes as is. The start collected while
     * looking for the UUID must reach the client whole, not stay in the parser's buffer. */
    {
        unsigned char plain[64];
        memset(plain, 0, sizeof(plain));
        memcpy(plain, "not a Vision stream: plain data, byte by byte.", 46);
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);            /* the stream does not carry this UUID */
        char out[128];
        int rc = 0;
        size_t got = drain(&v, plain, 46, 7, out, sizeof(out), &rc);
        check("another UUID: no error", 0, rc);
        check("another UUID: the whole stream comes through", 46, (long)got);
        check("another UUID: content unchanged", 0, memcmp(out, plain, 46));
    }

    /* An invalid command: an error, not endless re-reading of one frame. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);   /* there is no command 0x7F */
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        char out[64];
        int rc = 0;
        drain(&v, bad, bn, bn, out, sizeof(out), &rc);
        check("invalid command: parser returns VISION_EPROTO", VISION_EPROTO, rc);
    }

    /* The same broken frame fed again must give EPROTO again, not a success that consumes
     * nothing: that would leave a live connection re-reading the frame forever. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);
        struct vision v;
        memset(&v, 0, sizeof(v));
        memcpy(v.uuid, UUID, 16);
        size_t used = 0, pl_n = 0;
        const unsigned char *pl = NULL;
        int rc1 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("broken frame: error on the first call", VISION_EPROTO, rc1);
        int rc2 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("broken frame: error again on the second call, not a silent success",
              VISION_EPROTO, rc2);
    }

    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
