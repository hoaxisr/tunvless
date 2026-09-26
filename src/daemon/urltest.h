/* ЗАМЕР ЗАДЕРЖКИ ЧЛЕНА ГРУППЫ — urltest (docs/architecture.md, «4в», решение владельца).
 *
 * Задержка члена `pick: latency` — время до первого байта ответа на HTTP(S)-запрос к адресу
 * проверки (`url` группы, умолчание — GROUP_URL_DEFAULT в grpurl.h), отправленный ЧЕРЕЗ этого
 * члена. Годен ответ со статусом 204 или 200; всё остальное — «не измерилось» (-1). Устройство и
 * доводы — в шапке urltest.c. */
#ifndef STEER_URLTEST_H
#define STEER_URLTEST_H

#include <stdint.h>
#include <stddef.h>

#include "grpurl.h"

struct loop;
struct urltest;

/* Итог замера: ms >= 0 — пришёл ответ 204 или 200, время до ПЕРВОГО байта ответа от начала
 * соединения; -1 — ответа нет, он не тот или срок вышел. */
typedef void (*urltest_cb)(void *arg, int ms);

/* Замер url через члена. mark != 0 — сокет с SO_MARK (метка члена: запрос идёт по его правилу
 * fwmark и таблице); иначе dev != NULL — SO_BINDTODEVICE (безымянный член пула v1, у которого своей
 * метки нет); ни того ни другого — обычный путь (стенды). timeout_ms — на весь замер, с DNS.
 *
 * NULL — замер кончился сразу (адрес негоден, HTTPS нет в сборке, сокет не открылся): итог в *ms,
 * обратного вызова не будет. Иначе cb позовётся ровно один раз, если замер не отменён. Цикл не
 * блокируется ни на миг. */
struct urltest *urltest_start(struct loop *l, const char *url, uint32_t mark, const char *dev,
                              int timeout_ms, urltest_cb cb, void *arg, int *ms);
/* Отменить идущий замер: сокет, таймер, разрешение имени и поток HTTPS снимаются, cb не
 * зовётся. NULL — ничего. */
void urltest_cancel(struct urltest *u);

#endif
