/* Транспорт: как поток протокола (VLESS, позже другие дайлеры) едет до узла.
 *
 * Три яруса снизу вверх, и у каждого свой файл:
 *
 *   сокет         TCP до узла по всем адресам имени, с меткой выхода-подложки (trdial.c);
 *   безопасность  поле security= ссылки узла: none, tls, reality (trsec.c, struct security_ops);
 *   транспорт     поле type= ссылки узла: tcp, grpc, xhttp — и на шаге 5 выпуска 1.10 ws и
 *                 httpupgrade (transport.c, trgrpc.c, trxhttp.c; struct transport_ops).
 *
 * ПОЧЕМУ ДВЕ ТАБЛИЦЫ, А НЕ ОДНА ЦЕПОЧКА «tcp → tls → grpc». В проекте раздела 2
 * docs/architecture.md все они перечислены одним списком transport_ops, но в ссылке узла это
 * ДВА независимых поля, и сочетаются они любые: grpc поверх reality, xhttp поверх tls, tcp без
 * security вовсе. Одна цепочка слоёв одного типа потребовала бы правила, какой слой над каким
 * вправе стоять, — то есть второго способа сказать то, что два поля ссылки говорят и так.
 * Кроме того, слои безопасности различаются ТОЛЬКО рукопожатием: после него у tls и reality
 * одни и те же записи TLS 1.3, у none — сокет как есть. Поэтому у security_ops одна функция,
 * а поток после рукопожатия читает и пишет общий код связи (tr_link_* в transport.c).
 *
 * КТО ЭТИМ ПОЛЬЗУЕТСЯ. Клиент VLESS (proto/vless/client.c: vless_connect и проверка узла) и
 * через него дайлер стека туннеля (proto/vless/vldial.c). Про протокол транспорт не знает
 * ничего: узел приходит ему struct tr_node — теми полями ссылки, которые касаются транспорта,
 * указателями в узел подписки. Поэтому следующий протокол поверх тех же транспортов (trojan,
 * shadowsocks через ws) — это новый дайлер, а не правка этого слоя.
 *
 * При выпуске 1.10 (шаг 4) весь этот каталог уходит в разделяемую libsteer вместе с TLS: модули
 * протоколов пользуются им, а не носят свою копию.
 */
#ifndef STEER_TRANSPORT_H
#define STEER_TRANSPORT_H
#include <stdint.h>
#include <stddef.h>
#include "tls13.h"
#include "h2.h"

/* Коды отказа транспорта. Значения — прежние VLESS_CONN_* клиента: их видят журнал, строка
 * причины проверки узла и стенды, а менять число ради переезда в другой файл незачем.
 * -35 и -36 заняты кодами самого VLESS (client.h) — там они и остались. */
#define TR_EDNS      (-30)
#define TR_ESOCK     (-31)
#define TR_ECONNECT  (-32)
#define TR_EIO       (-33)
#define TR_ECLOSED   (-34)
/* Транспорт требует HTTP/2, а сервер на него не согласился. Отдельный код: всё остальное при
 * этом работает, данные просто не идут, и без имени этой ошибки узел выглядит как
 * «подключается и молчит». */
#define TR_ENOH2     (-37)
#define TR_EGRPC     (-38)   /* поток gRPC устроен не так, как мы умеем читать */

/* Узел глазами транспорта: только то, что касается связи. Указатели — в узел подписки
 * (struct vless_node), без копий: узел живёт дольше любого соединения к нему. */
struct tr_node {
    const char *host;
    uint16_t port;
    const char *type;          /* tcp | grpc | xhttp */
    const char *security;      /* none | tls | reality */
    const char *sni;           /* маскировочный домен — он же SNI в ClientHello */
    const char *fp;            /* отпечаток браузера */
    const char *pbk;           /* публичный ключ Reality, base64url */
    const char *sid;           /* short id Reality, hex */
    const char *path;          /* xhttp */
    const char *service;       /* grpc serviceName */
    const char *mode;          /* grpc: multi/gun; xhttp: auto/packet-up… */
    /* Длина набивки xhttp, объявленная узлом (см. vless_node.pad_from в vless.h). 0 в pad_to —
     * не объявлено, тогда умолчание Xray. */
    uint16_t pad_from, pad_to;
};

/* Связь: сокет и безопасность над ним — один защищённый поток байт.
 *
 * Отдельной структурой потому, что связей у соединения бывает ДВЕ: xhttp в режимах stream-up и
 * packet-up поднимает вторую под выгрузку (см. trxhttp.c), и рукопожатие у неё то же самое. */
struct tr_link {
    int fd;
    int plain;                 /* security=none: TLS нет вовсе */
    /* Сервер перешёл на прямое копирование (команда direct в Vision): в сокете больше не наши
     * записи TLS, а поток целевого соединения как есть. Ставится извне — тем, кто разбирает
     * кадры Vision (transport_direct), потому что команда живёт в них. */
    int rx_direct;
    struct tls13 tls;
};

/* Разбор потока сообщений gRPC.
 *
 * Состояние нужно потому, что границы сообщения gRPC, кадра HTTP/2 и записи TLS не
 * совпадают ни в одном месте: одно сообщение может приехать тремя записями, а одна
 * запись — принести полтора сообщения. Держим счётчики, а не буфер: буфер на каждое из
 * 64 соединений стоил бы мегабайт, а счётчики — двадцать байт. */
struct grpc_de {
    unsigned char hdr[5];        /* признак сжатия(1) + длина(4) */
    unsigned char hdr_n;
    uint32_t msg_left;           /* сколько осталось от тела сообщения */
    unsigned char pb[8];         /* тег и длина поля protobuf */
    unsigned char pb_n;
    uint32_t field_left;         /* сколько осталось от поля bytes внутри сообщения */
};

/* Режим xhttp. Определяет, СКОЛЬКО запросов HTTP несёт одно соединение и как они делят
 * направления — а не «формат кадров»: байты в теле у всех трёх одинаковы.
 *
 *   stream-one  один запрос POST: тело запроса наверх, тело ответа вниз. Одно соединение,
 *               один поток, наименьшая задержка. Его и выбирает Xray при reality;
 *   stream-up   два запроса: GET за загрузкой и длинный POST под выгрузку. Нужен там, где
 *               посредник не пропускает двунаправленное тело, но потоковую выгрузку терпит;
 *   packet-up   GET за загрузкой и ЧЕРЕДА коротких POST, по одному на кусок, с номером в
 *               пути. Единственное, что проходит через посредника, который выгрузку
 *               потоком не пропускает вовсе — например через CDN, буферизующий запросы.
 */
enum xhttp_mode { XH_STREAM_ONE = 0, XH_STREAM_UP, XH_PACKET_UP };

/* Вторая связь — под выгрузку xhttp.
 *
 * ПОЧЕМУ ОТДЕЛЬНОЕ СОЕДИНЕНИЕ, А НЕ ВТОРОЙ ПОТОК В ТОМ ЖЕ. stream-up и packet-up требуют,
 * чтобы загрузка и выгрузка шли РАЗНЫМИ запросами и одновременно. В HTTP/2 это два потока
 * в одном соединении, и Xray делает именно так — но у нашего клиента h2 мультиплексора нет
 * по построению (см. заголовок h2.c), и заводить планировщик окон между потоками ради двух
 * ролей, одна из которых только читает, а другая только пишет, дороже, чем второе TCP.
 *
 * Протоколу это ничем не мешает: сервер связывает запросы по идентификатору сессии в ПУТИ,
 * а не по соединению (hub.go в Xray), и по HTTP/1.1 выгрузка вообще всегда идёт отдельным
 * соединением. Цена — второе рукопожатие TLS на соединение, и платят её только эти два
 * режима. */
struct xh_up {
    struct tr_link link;
    struct h2 h2;
    int started;               /* HEADERS первого запроса уже отправлены */
};

/* Состояние xhttp. У stream-one всё, кроме mode, здесь не используется. */
struct xh_state {
    enum xhttp_mode mode;
    struct xh_up up;           /* выгрузка stream-up и packet-up */
    uint64_t seq;              /* номер куска packet-up, с нуля */
    char authority[128];       /* повторяется в каждом запросе череды */
    char up_path[288];         /* путь с идентификатором сессии, без номера куска */
    /* Длина набивки, объявленная узлом. Запоминается здесь, потому что запросы выгрузки
     * (packet-up) собираются уже без узла на руках, а набивка нужна каждому: сервер
     * проверяет её у КАЖДОГО запроса, а не только у первого. */
    uint16_t pad_from, pad_to;
};

struct transport;

/* Транспорт — поле type= ссылки: как поток протокола уложен внутри защищённой связи.
 *
 * Шаг 5 (ws и httpupgrade) — это ещё две такие таблицы и два файла рядом с trgrpc.c: запрос
 * Upgrade по HTTP/1.1 в open, кадры WebSocket в write/read (у httpupgrade кадров нет — после
 * ответа 101 поток идёт как есть), ALPN "http/1.1". Ни стек туннеля, ни дайлер при этом не
 * меняются: они видят транспорт только через transport_write и transport_read. */
struct transport_ops {
    const char *name;          /* как в ссылке узла: tcp, grpc, xhttp */
    /* Что просить в ALPN, или NULL — тогда расширения нет вовсе. Hello без ALPN проверен на
     * живых узлах, и состав Hello — это то, по чему Reality отличает нас от постороннего:
     * добавлять расширение туда, где оно не нужно, значит менять проверенное ради ничего.
     * Если сервер согласовал ДРУГОЕ, соединение отвергается кодом TR_ENOH2. */
    const char *alpn;
    /* Данные протокола лежат в записях TLS как есть: чтение вправе отдать указатель внутрь
     * расшифрованной записи вместо копии (transport_read_zc). Правда только у tcp — у grpc и
     * xhttp между TLS и данными лежит HTTP/2, и он всё равно перекладывает тело кадра. */
    int zc;
    /* Открыть транспорт поверх уже защищённой связи: HTTP/2, запросы, вторая связь. NULL —
     * открывать нечего (tcp). На отказе закрывать ничего не нужно: закроет transport_open. */
    int  (*open)(struct transport *t, const struct tr_node *n, int timeout_s);
    int  (*write)(struct transport *t, const unsigned char *d, size_t n);
    /* 0 байт при коде 0 — законно: пришёл служебный кадр HTTP/2. Конец потока — кодом. */
    int  (*read)(struct transport *t, unsigned char *d, size_t cap, size_t *got);
    /* Структура переехала в памяти (запасная сессия стека → таблица соединений): поправить
     * указатели на саму себя. NULL — таких указателей у транспорта нет. */
    void (*moved)(struct transport *t);
    /* Освободить своё сверх основной связи (вторую связь xhttp). NULL — нечего. */
    void (*close)(struct transport *t);
};

/* Безопасность — поле security= ссылки. Различаются только рукопожатием (см. шапку). */
struct security_ops {
    const char *name;          /* none | tls | reality */
    /* Рукопожатие поверх l->fd. alpn — от транспорта. На отказе сокет НЕ закрывает: это
     * делает вызывающий, одним и тем же образом у основной связи и у второй. */
    int (*handshake)(struct tr_link *l, const struct tr_node *n, const char *alpn);
};

/* Соединение с узлом: основная связь, транспорт над ней и его состояние. */
struct transport {
    struct tr_link link;
    const struct transport_ops *fr;
    struct h2 h2;              /* только для grpc и xhttp */
    struct grpc_de de;         /* только для grpc */
    struct xh_state xh;        /* только для xhttp */
};

/* Полное установление: TCP, рукопожатие безопасности, открытие транспорта. 0 — готово; иначе
 * код отказа, и тогда ни дескриптора, ни ключей в куче за соединением не остаётся. */
int transport_open(struct transport *t, const struct tr_node *n, int timeout_s);

/* Обмен данными в форме, которую требует транспорт узла. Вызывающий про транспорт не
 * знает — иначе о нём пришлось бы помнить и в туннеле, и в проверке, и в каждом новом
 * месте, а забытое место означало бы поток, который уходит не в той упаковке. */
int transport_write(struct transport *t, const unsigned char *d, size_t n);
int transport_read(struct transport *t, unsigned char *d, size_t cap, size_t *got);

/* Приём БЕЗ ЛИШНЕЙ КОПИИ там, где транспорт это позволяет (transport_ops.zc).
 *
 * *data указывает либо внутрь соединения (на расшифрованную на месте запись), либо в buf —
 * вызывающему всё равно, он читает по указателю. Через это место идёт весь скачиваемый
 * трафик, поэтому копия здесь стоила прохода по памяти на каждый байт загрузки.
 *
 * Правило одно: использовать данные ДО следующего вызова по этому соединению. Подробнее —
 * в tls13.h у tls13_read_ref. */
int transport_read_zc(struct transport *t, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got);

/* Лежат ли у нас уже прочитанные данные, которых ядро не покажет как готовность сокета.
 * Подробности — в transport.c. */
int transport_has_data(const struct transport *t);

/* Сервер объявил прямое копирование (Vision): дальше в сокете не записи TLS, а поток как
 * есть. Зовёт тот, кто разбирает кадры протокола. */
void transport_direct(struct transport *t);

/* Структура переехала в памяти — поправить указатели на саму себя (transport_ops.moved). */
void transport_moved(struct transport *t);

static inline int transport_fd(const struct transport *t) { return t->link.fd; }

/* Закрыть всё: дескрипторы обеих связей и контексты шифров в куче. Годится и для структуры,
 * которую transport_open не довёл до конца или не открывал вовсе (fd -1). */
void transport_close(struct transport *t);

const char *transport_strerror(int rc);

/* Метка сокетов к узлу (SO_MARK до connect) — для `via`/`over`, см. «вложенные выходы» в
 * spec.h. 0 — не метить. required — метка обязательна: без неё соединение не открывается. */
void transport_set_sock_mark(uint32_t mark, int required);

/* Сколько места обязан дать вызывающий transport_read: транспорты поверх HTTP/2 отдают за
 * один раз до целой записи TLS. */
#define TRANSPORT_MIN_READ_CAP H2_MIN_READ_CAP

/* ---- для файлов этого каталога ------------------------------------------------------ */

extern const struct transport_ops tr_tcp, tr_grpc, tr_xhttp;
extern const struct security_ops tr_sec_none, tr_sec_tls, tr_sec_reality;

/* TCP до узла по всем адресам имени (trdial.c). Дескриптор либо отрицательный код TR_*. */
int tr_dial(const char *host, uint16_t port, int timeout_s);

/* Безопасность по полю ссылки: none, tls, иначе reality (trsec.c). */
const struct security_ops *tr_security(const char *name);

/* Связь целиком: сокет и рукопожатие безопасности. На отказе сокет закрыт и fd == -1. Общая
 * для основной связи и второй связи xhttp — ровно ради того, чтобы они не разошлись. */
int tr_link_open(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s);

/* Ввод-вывод основной связи в форме struct h2_io (ctx — struct tr_link). */
int tr_link_write(void *ctx, const unsigned char *d, size_t n);
int tr_link_read(void *ctx, unsigned char *d, size_t cap, size_t *got);

/* Закрыть связь: сокет и, если это был TLS, ключи в куче. */
void tr_link_close(struct tr_link *l);

#endif
