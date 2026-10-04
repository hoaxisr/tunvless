/* Ring of bytes sent to the client and not yet acknowledged: what a retransmit resends.
 *
 * Kept apart from stack.c because all of it is modular arithmetic, and an error there does not
 * look like one: the ring turns the wrong way, the client gets garbage instead of a retransmit,
 * TCP drops it, and from outside the transfer just stalls now and then. Its bounds have to be
 * testable on their own, outside the tunnel loop.
 */
#ifndef STEER_RTX_H
#define STEER_RTX_H
#include <stdint.h>
#include <stddef.h>

struct rtx {
    unsigned char *buf;
    uint32_t cap;
    uint32_t len;       /* unacknowledged bytes held */
    uint32_t head;      /* offset of the oldest unacknowledged byte */
};

/* 0, or -1 when out of memory. */
int rtx_init(struct rtx *r, uint32_t cap);
void rtx_done(struct rtx *r);

/* Enlarge the ring, keeping its contents. 0, or -1 on failure (the ring stays as it was and fully
 * usable). Shrinking is refused with -1.
 *
 * The ring is allocated per connection at SYN, so it starts small and grows only on a connection
 * that actually carries data: browsers keep dozens of idle connections open, and a full-size ring
 * on each would eat the memory new ones need. A failed grow is not a connection error: the
 * connection goes on with the old ring and a smaller window. */
int rtx_grow(struct rtx *r, uint32_t cap);

uint32_t rtx_room(const struct rtx *r);

/* Remember sent bytes. The caller must ensure n <= rtx_room(). */
void rtx_push(struct rtx *r, const unsigned char *p, uint32_t n);

/* The client acknowledged n bytes: drop them. Returns how many were actually dropped: an ACK may
 * cover more than was sent, and turning the ring past its data would resend foreign bytes. */
uint32_t rtx_drop(struct rtx *r, uint32_t n);

/* A contiguous piece from the start of the unacknowledged data, at most want bytes.
 *
 * Contiguous: past the end of the buffer the data wraps to offset 0 and cannot be returned as one
 * pointer. The caller sends what it gets; the rest goes with the next retransmit. */
uint32_t rtx_peek(const struct rtx *r, uint32_t want, const unsigned char **p);

#endif
