/* Страж правил выходов в демоне (`steerd daemon --watch`) — устройство и доводы в шапке rulewd.c. */
#ifndef STEER_RULEWD_H
#define STEER_RULEWD_H

#include <stddef.h>

struct steerd;
struct spec;
struct rulewd;

struct rulewd_conf {
    /* Идёт своя изменяющая операция демона (apply, reload, починка): проверка ждёт её конца —
     * посреди неё правило бывает снято, а таблица ещё не сброшена. NULL — не спрашивать. */
    int (*busy)(void *arg);
    /* Правил не хватает, а сам страж вернуть их не смог: починить (сервер сокета ставит починку
     * в очередь изменяющих команд). */
    void (*repair)(void *arg);
    /* Страж вернул правила сам, в процессе демона (выходы через запятую в list): сказать в
     * журнал и подписчикам, позвать внеочередной проход сторожа. NULL — сам страж не чинит, всё
     * идёт через repair. */
    void (*restored)(void *arg, const char *list);
    void *arg;
};

/* Завести стража. on — движок включён: только тогда открыт сокет событий правил. NULL — нет
 * памяти. */
struct rulewd *rulewd_start(struct steerd *d, const struct rulewd_conf *c, int on);
/* Движок включили или выключили: сокет событий открывается или закрывается, отложенная
 * проверка снимается. */
void rulewd_enable(struct rulewd *r, int on);
/* Своя операция кончилась: отложенная из-за неё проверка — сейчас. NULL — ничего. */
void rulewd_kick(struct rulewd *r);

/* Каких правил выходов спеки sp не хватает: имена через запятую в list (n байт). Возврат —
 * сколько выходов без правила; 0 — всё на месте или нечего чинить; -1 — ядро не спросить. */
int rulewd_missing(const struct spec *sp, char *list, size_t n);

#endif
