/* Слежка за узлом VLESS под демоном: клиент сам говорит, жив ли узел. Подробности — в vlwatch.c. */
#ifndef STEER_VLWATCH_H
#define STEER_VLWATCH_H
#include <stddef.h>
#include "vless.h"

/* Узел выбран: сказать демону up и, если он слушает, завести слежку. nodes и sel живут до
 * конца процесса (статические массивы модуля). checked — узел проверен при подъёме (перебор). */
void vl_watch_start(const struct vless_node *nodes, const int *sel, size_t sel_n, int cur,
                    int checked);

/* Исход рукопожатия с узлом — от установщика стека (живое соединение и запасная сессия). Серия
 * отказов зовёт проверку раньше срока. До vl_watch_start (и без демона) — ничего не делает. */
void vl_watch_seen(int rc);

#endif
