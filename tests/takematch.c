/* Spare sessions: a connection set up ahead of time is moved into the client's session, and the
 * pointers the transport keeps to itself must follow it.
 *
 * Taken from the steer device bring-up test, where it lived next to checks of the `ip` commands
 * (tunvless configures the device by netlink, src/tunnel/ifcfg.c). Needs the crypto library: the
 * VLESS dialer pulls in the transport, TLS 1.3 and Reality. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stack.h"
#include "vldial.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-66s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть: %ld\n", want, got);
        fails++;
    }
}

int main(void) {
    /* ---- пул запасных: указатели после переезда структуры -----------------------
     *
     * Взятие запасной копирует связь из слота пула в сессию соединения (memcpy) и чинит
     * самоуказатель — h2.io.ctx. Второй такой же живёт у выгрузки xhttp: up_request ставит
     * xh.up.h2.io.ctx = &t->xh.up, и для stream-up это происходит ЕЩЁ В СЛОТЕ (up_open внутри
     * открытия связи). После переезда он указывал в брошенный слот, который тут же
     * переиспользовала следующая запасная — выгрузка одного соединения уезжала в сокет чужого.
     *
     * С шага 2 выпуска 1.10 переселение — у дайлера (vless_dialer.take), а чинит указатели
     * транспорт (xhttp_moved); слот пула освобождает стек, и это проверяет tests/tunnelmatch.c.
     * Здесь — оба самоуказателя на настоящем транспорте и то, что поток соединения (UUID и
     * Vision, заведённые до взятия) переселение не затирает. */
    printf("\n== пул запасных: оба самоуказателя чинятся после переезда ==\n");
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
        check("связь переселена", 1, out.t.fr == &tr_xhttp && out.t.xh.up.started == 1);
        check("h2.io.ctx указывает на новую структуру", 1, out.t.h2.io.ctx == &out.t.link);
        check("up.h2.io.ctx указывает на новую структуру, а не в слот", 1,
              out.t.xh.up.h2.io.ctx == &out.t.xh.up);
        check("поток соединения не затёрт", 1, out.uuid[0] == 0x5a && out.vis.need_uuid == 1);
    }

    printf(fails ? "\nПРОВАЛОВ: %d\n" : "\nвсе проверки прошли\n", fails);
    return fails ? 1 : 0;
}
