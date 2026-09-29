#ifndef STEER_DNSD_DUPINT_H
#define STEER_DNSD_DUPINT_H

/* Общее у dup.c (цикл событий, очередь, транспорты) и dupdial.c (поток установки соединения).
 * Снаружи резолвера не видно: proxy.c знает только dup.h. */

#include <sys/socket.h>
#include "dup.h"

/* Метка объекта, чей адрес лежит в epoll (data.ptr). Первое поле — число: proxy.c держит в тех же
 * data.ptr указатели на int и на свои структуры, и dup_event узнаёт своё по числу, не разыменовывая
 * ничего сверх четырёх байт. */
#define DTAG_MAGIC 0x44555031u
enum { DT_UDP = 1, DT_CONN, DT_DIAL };
struct dtag { uint32_t magic; int kind; void *obj; };

#define DIAL_MAXADDR 6

/* Одно соединение с сервером, которое поток устанавливает целиком: имя (bootstrap) -> адрес ->
 * connect -> рукопожатие TLS. Хозяин структуры — цикл резолвера; поток берёт её, пока не запишет в
 * wfd байт «готово», и после этого её не касается. */
struct dial {
    struct dtag tag;                    /* DT_DIAL, для epoll на rfd */
    int rfd, wfd;                       /* концы socketpair: цикл читает rfd, поток пишет wfd */
    void *up;                           /* владелец (struct dup *) и его поколение — для отмены */
    unsigned up_gen;
    int conn;                           /* номер соединения владельца */
    volatile int cancel;                /* владелец ушёл: результат выбросить */

    /* Вход. */
    struct spec_dns_up u;
    unsigned mark;
    int doh;                            /* ALPN http/1.1 и проверка, что выбрано оно */
    struct sockaddr_storage cached[DIAL_MAXADDR];
    int cached_n, cached_fresh;         /* прежде найденные адреса и не истёк ли их срок */
    char ca[256];                       /* файл корней вместо системного ("" — системный) */
    int timeout_ms;                     /* на всё: bootstrap, connect, рукопожатие */

    /* Выход. */
    int rc;                             /* 0 — соединение готово */
    char err[192];
    int fd;                             /* сокет, уже неблокирующий */
    void *tls;                          /* struct tls13 *, владение переходит циклу */
    struct sockaddr_storage res[DIAL_MAXADDR];  /* заново найденные адреса (bootstrap) */
    int res_n;
    long res_ttl;                       /* секунд */
    int peer_i;                         /* к какому адресу подключились: индекс в res/cached */
    int peer_from_res;
};

/* Запустить поток. 0 — запущен и вернёт байт в wfd; -1 — не удалось (rc и err заполнены). */
int dial_launch(struct dial *d);

/* Разрешить имя серверами bootstrap (UDP, метка mark). Адреса — в out, срок в *ttl. Число адресов
 * или -1. Отдельно и без TLS: его проверяет стенд без сети. */
int dup_bootstrap(const char *host, const char (*boot)[46], size_t boot_n, unsigned mark,
                  int timeout_ms, struct sockaddr_storage *out, size_t max, long *ttl);

#endif
