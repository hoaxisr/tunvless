/* Spare sessions: a connection set up ahead of time is moved into the client's session, and the
 * pointers the transport keeps to itself must follow it.
 *
 * Needs the crypto library: the VLESS dialer pulls in the transport, TLS 1.3 and Reality. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stack.h"
#include "vldial.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-66s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("     want: %ld\n     got:  %ld\n", want, got);
        fails++;
    }
}

int main(void) {
    /* Taking a spare copies the link from the pool slot into the connection's session (memcpy),
     * and the transport fixes its self-pointers (xhttp_moved). There are two: h2.io.ctx, and the
     * xhttp upload's xh.up.h2.io.ctx, which up_request sets to &t->xh.up. In stream-up that
     * happens while the link is still IN THE SLOT (up_open runs as the link opens). Left unfixed,
     * it points into the abandoned slot, which the next spare reuses at once, and one
     * connection's upload goes into another connection's socket.
     *
     * Both self-pointers are checked on the real transport, and so is that the move does not
     * overwrite the connection's own state (UUID and Vision, set up before the take). Releasing
     * the pool slot is the stack's job and is checked in tests/tunnelmatch.c. */
    printf("\n== spare pool: both self-pointers fixed after the move ==\n");
    {
        static struct vl_sess spare, out;
        memset(&spare, 0, sizeof(spare));
        spare.t.link.fd = -1;
        spare.t.fr = &tr_xhttp;
        spare.t.h2.io.ctx = &spare.t.link;
        spare.t.xh.up.started = 1;
        spare.t.xh.up.h2.io.ctx = &spare.t.xh.up;
        memset(&out, 0, sizeof(out));
        out.uuid[0] = 0x5a;
        out.vis.need_uuid = 1;
        vless_dialer.take(&out, &spare);
        check("transport state moved", 1, out.t.fr == &tr_xhttp && out.t.xh.up.started == 1);
        check("h2.io.ctx points to the new struct", 1, out.t.h2.io.ctx == &out.t.link);
        check("up.h2.io.ctx points to the new struct, not into the slot", 1,
              out.t.xh.up.h2.io.ctx == &out.t.xh.up);
        check("UUID and Vision state kept", 1, out.uuid[0] == 0x5a && out.vis.need_uuid == 1);
    }

    printf(fails ? "\nFAILED: %d\n" : "\nall checks passed\n", fails);
    return fails ? 1 : 0;
}
