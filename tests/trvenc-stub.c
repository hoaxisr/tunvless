/* Заглушки для стендов `make test`, которые компонуют transport.c, но без криптографии (wsmatch, xhupmatch):
 * связь у них голая, и ярус VLESS encryption (trvenc.c) до них не доходит. Настоящий ярус проверяется на
 * настоящей библиотеке и против настоящего Xray — tests/vencprobe.c и tests/venc.sh в `make ext-test`. */
#include <stddef.h>
#include "transport.h"

int tr_venc_open(struct transport *t, const struct tr_node *n, int timeout_s)
    { (void)t; (void)n; (void)timeout_s; return TR_EVENC; }
int tr_venc_write(struct transport *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return TR_EVENC; }
int tr_venc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got)
    { (void)t; (void)d; (void)cap; *got = 0; return TR_EVENC; }
int tr_venc_pending(const struct transport *t) { (void)t; return 0; }
void tr_venc_close(struct transport *t) { (void)t; }
const char *tr_venc_reason(void) { return ""; }
