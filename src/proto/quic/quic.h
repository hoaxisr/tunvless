/* QUIC-соединение движка: тонкая обёртка над ngtcp2 (шаг 7 выпуска 1.10, docs/architecture.md,
 * «Криптография»/«Туннели»: QUIC как слой).
 *
 * ЗАЧЕМ. Потребителей у слоя два, оба позже: DoQ в dnsd (1.11) и модуль hysteria2. Им нужно одно и
 * то же — клиентское соединение поверх UDP-сокета, потоки, датаграммы RFC 9221, таймеры, — и
 * ни тому, ни другому не нужны ни ngtcp2, ни wolfSSL в заголовках. Поэтому здесь ни одного типа
 * обеих библиотек: наружу торчат сокет, потоки как целые идентификаторы и колбэки с байтами.
 * Сами протоколы (DoQ, запрос авторизации HTTP/3 и кадры TCP/UDP у hysteria2) — на стороне
 * потребителя: это байты внутри потоков и датаграмм.
 *
 * МОДЕЛЬ ВЫПОЛНЕНИЯ — ОДНОПОТОЧНАЯ, ВНЕШНЯЯ ЛИНИЯ СОБЫТИЙ. Соединение владеет одним неблокирующим
 * UDP-сокетом (qc_fd) и ничего не запускает само:
 *
 *     qc_open ─► регистрируем qc_fd() в своём epoll (EPOLLIN)
 *     готов сокет  ─► qc_on_readable()    (читает все дейтаграммы, отвечает, зовёт колбэки)
 *     истёк таймер ─► qc_on_timer()       (потеря, PTO, пейсинг, idle; срок — qc_timeout_ms())
 *     хочешь писать ─► qc_stream_send / qc_datagram_send (ставят в очередь и сразу пытаются
 *                     отправить; остальное уходит по ACK и таймеру)
 *
 * Для простых потребителей и стендов — qc_run(): один проход epoll_wait по этому сокету и таймеру.
 * После любого вызова срок таймера мог измениться — его надо перечитать (qc_timeout_ms).
 *
 * КОЛБЭКИ ВЫЗЫВАЮТСЯ ТОЛЬКО ИЗ qc_on_readable, qc_on_timer и qc_run (отправка ничего не читает).
 * Из колбэка можно звать qc_stream_send, qc_datagram_send, qc_stream_open и qc_close; qc_free —
 * нельзя (объект ещё в работе у вызвавшего): закрытие сообщается on_closed, освобождает
 * потребитель после возврата.
 *
 * ПЕРЕГРУЗКА. По умолчанию CUBIC (это то, чего ждёт DoQ). cfg.brutal_bps != 0 включает Brutal —
 * наш патч к ngtcp2 (build/ngtcp2/patches): заданная скорость в БАЙТАХ в секунду, без снижения при
 * потерях, как у hysteria2.
 *
 * ЧТО ЗДЕСЬ НАМЕРЕННО ПРОСТО. Один путь (без миграции), одна пара адресов, без 0-RTT и билетов
 * сессии, без переупорядочения приёма потоков: данные передаются потребителю сразу, окно
 * приёма продлевается сразу (обратного давления на отправителя нет — потребитель, которому
 * нужно замедлить, закрывает поток). Отправка — по одной датаграмме UDP за системный вызов, без
 * GSO: на роутере узкое место — не вызовы, а шифр. */
#ifndef STEER_QUIC_H
#define STEER_QUIC_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define QC_EINVAL   (-1)    /* неверный аргумент */
#define QC_ENOMEM   (-2)
#define QC_ESOCK    (-3)    /* сокет или адрес */
#define QC_ETLS     (-4)    /* не создался контекст TLS (roots, сертификат) */
#define QC_EQUIC    (-5)    /* ngtcp2 отказал при создании */
#define QC_EAGAIN   (-6)    /* сейчас нельзя: потоков больше нет, очередь полна, рукопожатие идёт */
#define QC_ECLOSED  (-7)    /* соединение закрыто */
#define QC_ETOOBIG  (-8)    /* датаграмма больше допустимой */
#define QC_ENOSTREAM (-9)   /* нет такого потока */

/* Причины закрытия для on_closed. */
#define QC_CLOSE_LOCAL      0   /* закрыли мы (qc_close) */
#define QC_CLOSE_PEER       1   /* закрыл сервер (CONNECTION_CLOSE, draining) */
#define QC_CLOSE_IDLE       2   /* молчание дольше max_idle */
#define QC_CLOSE_HANDSHAKE  3   /* рукопожатие не уложилось в срок или отвергнуто (TLS, ALPN) */
#define QC_CLOSE_ERROR      4   /* ошибка протокола или сокета */

struct qc;          /* соединение */
struct qc_tls;      /* контекст TLS: корни проверки, при желании общий для соединений */

struct qc_ops {
    void (*on_handshake)(void *user);
    /* fin != 0 — сервер закончил передачу по этому потоку (данных в вызове может не быть). */
    void (*on_stream_data)(void *user, int64_t sid, const uint8_t *d, size_t n, int fin);
    /* Поток закрыт целиком (обе стороны). app_err — код приложения, 0 если его не было. */
    void (*on_stream_close)(void *user, int64_t sid, uint64_t app_err);
    void (*on_datagram)(void *user, const uint8_t *d, size_t n);
    /* Единственный раз. why — короткая строка для журнала (не для показа человеку). */
    void (*on_closed)(void *user, int reason, const char *why);
};

struct qc_cfg {
    /* Сервер: IPv4/IPv6 в текстовом виде (имён не разбираем — резолвит потребитель). */
    const char *host;
    uint16_t    port;
    /* Имя для SNI и проверки сертификата; NULL — без SNI (и без проверки имени). */
    const char *sni;
    /* ALPN, одна строка: "h3" для hysteria2, "doq" для DNS over QUIC. */
    const char *alpn;
    /* Проверка сертификата. 1 (по умолчанию нулевая структура = проверять) — цепочка до корней
     * из ca_pem либо, если его нет, из файла ca_file (NULL — общий файл ca-bundle роутера,
     * CERTV_DEFAULT_ROOTS; на телефоне путь даёт tls_cert_roots()) и имя sni. insecure = 1 —
     * не проверять ничего (как в hysteria2 с insecure: true). */
    int         insecure;
    const uint8_t *ca_pem;
    size_t      ca_pem_n;
    const char *ca_file;
    /* Готовый общий контекст TLS (qc_tls_new): корни разбираются один раз на процесс. NULL — свой
     * на соединение (ca_pem/ca_file/insecure выше берутся тогда). */
    struct qc_tls *tls;

    /* Brutal: целевая скорость, БАЙТ/с. 0 — обычный CUBIC. */
    uint64_t    brutal_bps;
    /* Датаграммы RFC 9221: наибольшая принимаемая, 0 — датаграмм не принимаем (и не шлём). Нужны
     * hysteria2 (UDP-релей); DoQ их не использует. */
    size_t      datagram_max;

    /* Пределы; нули — умолчания. */
    unsigned    idle_ms;            /* max_idle_timeout, по умолчанию 30000 */
    unsigned    handshake_ms;       /* по умолчанию 10000 */
    uint64_t    max_data;           /* окно приёма соединения, по умолчанию 8 МиБ */
    uint64_t    max_stream_data;    /* окно приёма потока, по умолчанию 2 МиБ */
    uint64_t    max_streams;        /* потоков, которые открывает сервер, по умолчанию 16 */
    size_t      send_buf;           /* буфер отправки на поток (неподтверждённое + очередь), 1 МиБ */
};

struct qc_stats {
    uint64_t rtt_us;            /* сглаженный RTT */
    uint64_t cwnd;              /* окно перегрузки, байт */
    uint64_t in_flight;         /* байт в полёте */
    uint64_t pkt_sent, pkt_lost, pkt_recv;
    uint64_t bytes_sent, bytes_recv;
    int      handshake_done;
    int      brutal;            /* 1 — работает Brutal */
};

/* Контекст TLS отдельно от соединения: разбор корней (полторы сотни сертификатов) — не то, что
 * стоит делать на каждое соединение. Потоки не защищены: контекст принадлежит потоку, где
 * создан. Освобождает потребитель, когда все соединения на нём закрыты. */
struct qc_tls *qc_tls_new(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
void qc_tls_free(struct qc_tls *t);

/* Открыть соединение: сокет, TLS, первый пакет рукопожатия уходит сразу. 0 — успех, *out —
 * соединение; иначе QC_E*. ops копируется; user возвращается в колбэках. */
int  qc_open(const struct qc_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out);
/* Закрыть: CONNECTION_CLOSE(app_err) серверу, затем on_closed(LOCAL). Память освобождает qc_free. */
void qc_close(struct qc *q, uint64_t app_err);
void qc_free(struct qc *q);

int  qc_fd(const struct qc *q);
/* Мс до следующего срока: 0 — пора, -1 — сроков нет (соединение закрыто). Округляется вверх. */
int  qc_timeout_ms(struct qc *q);
/* Оба возвращают 0, пока соединение живо, и QC_ECLOSED после on_closed. */
int  qc_on_readable(struct qc *q);
int  qc_on_timer(struct qc *q);
/* Проход epoll_wait(timeout_ms) по сокету и таймеру (-1 — ждать срока таймера сколько нужно). */
int  qc_run(struct qc *q, int timeout_ms);

int  qc_handshake_done(const struct qc *q);
/* Двунаправленный поток. QC_EAGAIN — рукопожатие не завершено или у сервера нет разрешения. */
int  qc_stream_open(struct qc *q, int64_t *sid);
/* Поставить n байт в очередь потока; fin — после них закрыть передачу. Возвращает принятое число
 * байт (0..n; меньше n — буфер потока полон, повторить после освобождения по ACK) или QC_E*. */
ssize_t qc_stream_send(struct qc *q, int64_t sid, const uint8_t *d, size_t n, int fin);
/* Не отправленное и не подтверждённое в потоке, байт. */
size_t qc_stream_buffered(const struct qc *q, int64_t sid);
/* Отменить поток (RESET_STREAM и STOP_SENDING с кодом). */
int  qc_stream_reset(struct qc *q, int64_t sid, uint64_t app_err);
/* Датаграмма: 0 — в очереди; QC_ETOOBIG — больше qc_datagram_max; QC_EAGAIN — очередь полна (64).
 * Датаграммы ненадёжны: отправленную можно потерять, повторять их — дело потребителя. */
int  qc_datagram_send(struct qc *q, const uint8_t *d, size_t n);
/* Наибольшая датаграмма, что влезает сейчас (0 — сервер датаграмм не принимает). */
size_t qc_datagram_max(const struct qc *q);

void qc_stats_get(struct qc *q, struct qc_stats *st);

#ifdef QC_WITH_SERVER
/* Сервер ДЛЯ СТЕНДОВ (ключ QC_WITH_SERVER задают tests/qcloop.c и tests/qcserver.c, в libsteer его
 * нет): одно соединение на сокет, сертификат и ключ — DER. Те же колбэки, те же qc_on_readable,
 * qc_on_timer, qc_run, qc_stream_send, qc_datagram_send, что у клиента — это и делает эхо-сервер
 * стенда одним экраном кода. Соединение создаётся по первому пакету Initial. */
struct qc_srv_cfg {
    const char *bind_host;
    uint16_t    port;               /* 0 — любой свободный; узнать: qc_local_port */
    const char *alpn;
    const uint8_t *cert_der; size_t cert_n;
    const uint8_t *key_der;  size_t key_n;
    uint64_t    brutal_bps;
    size_t      datagram_max;
    unsigned    idle_ms;
    uint64_t    max_data, max_stream_data, max_streams;
    size_t      send_buf;
};
int qc_listen(const struct qc_srv_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out);
uint16_t qc_local_port(const struct qc *q);
#endif

#endif
