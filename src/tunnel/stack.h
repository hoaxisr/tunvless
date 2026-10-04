/* Стек туннеля: пакеты из TUN в потоки к узлу через дайлер (dialer.h). Границы — в stack.c. */
#ifndef STEER_STACK_H
#define STEER_STACK_H
#include <stdint.h>
#include "dialer.h"

/* The device the stack creates and brings up. */
struct tun_cfg {
    const char *dev;    /* name as asked; the kernel's limit is 15 characters */
    uint32_t addr;      /* IPv4 address of the device, network order */
    int prefix;         /* its prefix length */
};

/* The device is up, has its address and is ready to carry traffic: called once, from the
 * stack_run thread, before the loop threads start. The caller adds its routes here. */
typedef void (*stack_ready_fn)(void *arg, const char *dev);

/* Create the TUN device tc, bring it up (ifcfg.c) and carry its traffic through dialer d until
 * the queues end. ready may be NULL.
 *
 * Always returns 1: the loop has no successful exit (see the end of stack_run). */
int stack_run(const struct tun_cfg *tc, const struct dialer *d, stack_ready_fn ready, void *arg);

/* Набор активных узлов изменился: соединения, чей узел больше не активен (dialer_ops.stale), стек
 * сбрасывает — RST клиенту, — чтобы приложения переподключались сразу, а не ждали своего таймаута
 * на повисшем соединении. Зовётся из любого потока; поток цикла замечает это на ближайшем витке (не
 * позже секунды). */
void stack_nodes_changed(void);

#endif
