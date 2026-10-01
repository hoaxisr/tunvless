/* Дайлеры steer-proxy и общее между ними: подъём туннеля, проба узла, выбор дайлера по протоколу
 * (proxy.h, dialer.h). Каждый протокол — свой файл с таблицей dialer_ops; здесь то, что у них
 * общее. */
#ifndef STEER_PXDIAL_H
#define STEER_PXDIAL_H
#include "dialer.h"
#include "transport.h"
#include "proxy.h"

struct output;

extern const struct dialer_ops proxy_trojan_dialer, proxy_ss_dialer, proxy_socks_dialer,
                               proxy_http_dialer, proxy_vmess_dialer;

/* Таблица дайлера по протоколу узла. */
const struct dialer_ops *px_dialer_for(enum px_proto p);

/* Узел глазами транспорта: sl_tr_node плюс поправки протоколов прокси (ss/socks — всегда голый
 * tcp). */
void px_tr_node(const struct px_node *n, struct tr_node *t);

/* Открыть поток к узлу поверх транспорта (TCP/TLS/Reality и type= узла). Для ss/socks/http это и
 * есть связь; trojan/vmess поверх неё кладут свой заголовок. 0 — готово. */
int px_stream_open(const struct px_node *n, struct transport *t, int timeout_s);

/* Строка причины для кода транспорта (TR_*) и общих кодов прокси ниже. */
#define PX_EAUTH   (-60)   /* сервер отверг авторизацию (socks/http/ss) */
#define PX_EPROTO  (-61)   /* ответ не по протоколу */
#define PX_EADDR   (-62)   /* сервер отказал в адресе назначения */
const char *px_strerror(int rc);

/* Проба узла: поднять поток к 1.1.1.1:80 дайлером этого протокола и дождаться ответа — тем же
 * путём, которым пойдёт трафик (как vless_probe). 0 — ok, иначе код; why — человеку, hs_ms —
 * время рукопожатия. */
int px_probe(const struct px_node *n, int timeout_s, char *why, size_t why_n, int *hs_ms);

/* Поднять туннель выхода к узлу (stack_run с дайлером протокола). ready — как у stack_run. */
int px_tunnel_run(struct output *o, const struct px_node *node,
                  void (*ready)(void *arg, const char *dev), void *arg);

/* Слежка за узлом (pxmain.c): исход открытия потока зовёт проверку раньше срока. */
void px_watch_seen(int rc);

#endif
