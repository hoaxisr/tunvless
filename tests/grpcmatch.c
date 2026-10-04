/* gRPC message framing of the grpc transport (src/proto/transport/trgrpc.c): what grpc_wrap writes
 * grpc_unwrap reads back, in chunks of any size, and a malformed stream is refused rather than
 * misread. The file is included for its static functions; HTTP/2 and the link are stubbed out,
 * since only the framing is tested. */
#include <stdio.h>
#include <string.h>

#include "../src/proto/transport/trgrpc.c"

int h2_start(struct h2 *h, const struct h2_io *io, const char *authority, const char *path,
             const char *content_type, const char *referer) {
    (void)h; (void)io; (void)authority; (void)path; (void)content_type; (void)referer;
    return -1;
}
int h2_write(struct h2 *h, const unsigned char *d, size_t n) { (void)h; (void)d; (void)n; return -1; }
int h2_read(struct h2 *h, unsigned char *out, size_t cap, size_t *got) {
    (void)h; (void)out; (void)cap; *got = 0;
    return -1;
}
int tr_link_write(void *ctx, const unsigned char *d, size_t n) { (void)ctx; (void)d; (void)n; return -1; }
int tr_link_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    (void)ctx; (void)d; (void)cap; *got = 0;
    return -1;
}

static int fails;

static void check(int ok, const char *what) {
    printf("%-62s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

/* Feed in to a fresh decoder in pieces of step bytes; the decoded bytes go to out. */
static int unwrap_steps(const unsigned char *in, size_t n, size_t step, unsigned char *out,
                        size_t cap, size_t *out_n) {
    struct grpc_de de;
    memset(&de, 0, sizeof(de));
    *out_n = 0;
    for (size_t i = 0; i < n; i += step) {
        size_t k = n - i < step ? n - i : step, got = 0;
        int rc = grpc_unwrap(&de, in + i, k, out + *out_n, cap - *out_n, &got);
        if (rc) return rc;
        *out_n += got;
    }
    return 0;
}

/* A message whose field length is written as a varint of exactly len_bytes bytes (padded with
 * continuation bytes, as protobuf allows for a non-minimal encoding). */
static size_t msg_with_varint(unsigned char *out, const char *data, int len_bytes) {
    size_t dn = strlen(data), o = 5;
    out[o++] = 0x0A;
    uint32_t v = (uint32_t)dn;
    for (int b = 0; b < len_bytes; b++) {
        unsigned char c = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (b < len_bytes - 1) c |= 0x80;
        out[o++] = c;
    }
    memcpy(out + o, data, dn);
    o += dn;
    size_t msg = o - 5;
    out[0] = 0;
    out[1] = (unsigned char)(msg >> 24); out[2] = (unsigned char)(msg >> 16);
    out[3] = (unsigned char)(msg >> 8);  out[4] = (unsigned char)msg;
    return o;
}

int main(void) {
    unsigned char wire[4096], back[4096], data[1000];
    size_t got = 0;
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (unsigned char)(i * 7 + 3);

    size_t wn = grpc_wrap(data, sizeof(data), wire, sizeof(wire));
    check(wn == 5 + 1 + 2 + sizeof(data), "wrap: header, tag, 2-byte length, data");
    int bad = 0;
    for (size_t step = 1; step <= wn; step += (step < 16 ? 1 : 97)) {
        if (unwrap_steps(wire, wn, step, back, sizeof(back), &got) != 0 || got != sizeof(data) ||
            memcmp(back, data, sizeof(data)) != 0)
            bad = 1;
    }
    check(!bad, "unwrap: the data back, in pieces of any size");

    size_t mn = msg_with_varint(wire, "hello", 5);
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == 0 && got == 5 &&
          !memcmp(back, "hello", 5), "a 5-byte length varint is read");
    mn = msg_with_varint(wire, "hello", 6);
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a 6-byte length varint is refused, not shifted past 32 bits");
    mn = msg_with_varint(wire, "hello", 7);
    check(unwrap_steps(wire, mn, 1, back, sizeof(back), &got) == TR_EGRPC,
          "a 7-byte varint is refused, byte by byte too");

    mn = msg_with_varint(wire, "hello", 1);
    wire[5] = 0x12;                                        /* field 2 */
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a field other than 1 is refused");
    mn = msg_with_varint(wire, "hello", 1);
    wire[0] = 1;                                           /* compressed */
    check(unwrap_steps(wire, mn, mn, back, sizeof(back), &got) == TR_EGRPC,
          "a compressed message is refused");

    if (fails) printf("\ngrpcmatch: %d FAILED\n", fails);
    else printf("\ngrpcmatch: all checks passed\n");
    return fails ? 1 : 0;
}
