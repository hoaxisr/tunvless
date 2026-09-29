/* Дайлер VLESS: как стек туннеля (stack.c) везёт потоки клиента к узлу VLESS.
 *
 * Всё, что здесь, жило прямо в цикле туннеля (tunnel.c) — в upstream_send, downstream_pump,
 * udp_downstream и в заводе соединения на SYN, — пока цикл был сварен с VLESS. При выделении
 * стека (шаг 2 выпуска 1.10) оно переехало сюда без изменений в поведении: те же байты на
 * проводе, те же строки журнала, тот же порядок. Стек видит только таблицу vless_dialer.
 *
 * Сессия — struct vl_sess (vldial.h): состояние потока (заголовок, Vision, сборка датаграммы) и
 * связь с узлом (struct transport). Связь можно установить заранее — адрес назначения в VLESS
 * едет в заголовке запроса вместе с первыми данными, а до того связь ничья (DC_PRECONNECT), —
 * поэтому у стека есть пул запасных связей, и take переселяет из запасной только связь.
 *
 * При выпуске 1.10 (шаг 4) этот файл уходит в бинарник модуля steer-vless.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "vless.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"
#include "vldial.h"
#include "vlwatch.h"
#include "stack.h"

#define LOG_W  "steer[warn] tunnel: "

/* Буфер стека обязан вмещать целую запись транспорта и запас на заголовок и набивку Vision
 * (см. TUNNEL_BUF в dialer.h). Число там записано числом, а проверяется — здесь. */
_Static_assert(TUNNEL_BUF >= VLESS_MIN_RECV_CAP + 2048,
               "TUNNEL_BUF меньше записи транспорта с запасом под заголовок VLESS и Vision");

static int g_trace;
#define TR(...) do { if (g_trace) fprintf(stderr, "tun: " __VA_ARGS__); } while (0)

void vl_set_trace(int on) { g_trace = on; }

/* ---- узел ------------------------------------------------------------------------------ */

static const char *vl_peer(const void *ctx) {
    const struct vless_node *node = ctx;
    return node->host;
}

static void vl_describe(const void *ctx, char *out, size_t n) {
    const struct vless_node *node = ctx;
    snprintf(out, n, "%s (%s:%u %s%s)", node->name, node->host, node->port, node->type,
             node->flow[0] ? " +vision" : "");
}

/* ---- связь ----------------------------------------------------------------------------- */

static int vl_connect(const void *ctx, void *sess, int timeout_s) {
    struct vl_sess *s = sess;
    int rc = vless_connect(ctx, &s->t, timeout_s);
    /* Исход — слежке за узлом (под демоном, vlwatch.c): серия отказов зовёт её проверку раньше
     * срока. Здесь, а не в стеке: мера «жив ли узел» — протокола. */
    vl_watch_seen(rc);
    return rc;
}

/* Связь из запасной сессии — в сессию соединения. Копируется только struct transport: UUID и
 * Vision потока в dst уже заведены (flow_open), и затереть их значило бы потерять поток.
 *
 * h2 держит указатель на своё же соединение (io.ctx) — после переезда структуры он указывает в
 * брошенный слот пула; таких самоуказателей ДВА (см. xhttp_moved в trxhttp.c), и чинит их
 * транспорт, а не мы. */
static void vl_take(void *dst, void *src) {
    struct vl_sess *d = dst;
    struct vl_sess *s = src;
    memcpy(&d->t, &s->t, sizeof(d->t));
    transport_moved(&d->t);
}

static void vl_close(void *sess) {
    struct vl_sess *s = sess;
    transport_close(&s->t);
}

/* Толстую половину НЕ трём целиком: 40 КБ memset на каждое закрытие это 40 КБ, прогнанных
 * через кэш ради нулей, которые всё равно перепишет открытие связи (transport_open начинается
 * с memset своей структуры). Здесь достаточно обнулить то, что читаем сами.
 *
 * Счётчики сборки датаграммы — но НЕ сам буфер: 4 КБ нулей на каждое закрытие это те же 4 КБ
 * через кэш ради данных, которые всё равно перепишет следующая датаграмма. Всё тронутое здесь
 * лежит в начале сессии (порядок полей — в vldial.h). */
static void vl_clear(void *sess) {
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    s->t.link.fd = -1;
    memset(&s->vis, 0, sizeof(s->vis));
    s->dg_want = s->dg_have = 0;
    s->dg_skip = 0;
    s->lenb_n = 0;
}

static int vl_fd(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_fd(&s->t);
}

static int vl_has_data(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_has_data(&s->t);
}

/* ---- поток ----------------------------------------------------------------------------- */

/* Идентификатор узла не разобрался, и соединение закрывается. Причина известна здесь и
 * обязана быть сказана: молчаливое закрытие снаружи выглядит как «трафика нет», и ровно так
 * выглядел бы следующий похожий случай (I-097). Сегодня сюда не попасть — узел с негодным
 * UUID отсеивается при разборе подписки, а vless_tunnel_run проверяет его до подъёма
 * устройства, — поэтому строка через ограничитель, а не на каждый пакет. Сам UUID не
 * печатается: это ключ доступа к узлу. */
static void node_id_refused(const struct vless_node *node, const char *what) {
    static __thread time_t said;
    time_t now = stack_now_s();
    if (now - said < 5) return;
    said = now;
    fprintf(stderr, LOG_W "у узла %s не разбирается UUID — %s отклонено; "
                    "проверьте ссылку узла\n", node->name, what);
}

static int vl_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k;
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    if (vless_uuid_parse(node->uuid, s->uuid) != 0) {
        node_id_refused(node, udp ? "соединение UDP" : "соединение TCP");
        return -1;
    }
    /* У UDP Vision не заводим вовсе: в запросе UDP flow не объявлен, значит кадров не будет
     * ни в ту, ни в другую сторону. */
    if (!udp) vision_init(&s->vis, s->uuid);
    return 0;
}

/* Отправить узлу данные в правильной форме: с заголовком VLESS на первом кадре и в обёртке
 * Vision, если узел её требует. */
static int vl_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* Буфер нужен ТОЛЬКО чтобы приклеить заголовок или кадр Vision к данным одной записью.
     * Когда клеить нечего — а это обычный случай, потому что заголовок уходит один раз на
     * соединение, а Vision заканчивает набивку первым же кадром, — данные отдаются прямо из
     * пакета, без копии вовсе. */
    static __thread unsigned char out[TUNNEL_BUF];
    const unsigned char *body = data;
    size_t len = 0;

    if (!s->header_sent) {
        /* Адрес назначения берём из пакета: имени у нас нет, клиент уже разрешил его сам
         * (или через наш резолвер, который вернул fake-IP и подменит адрес в DNAT). */
        unsigned char ip4[4];
        memcpy(ip4, &k->dst, 4);
        /* Поток UDP объявляется командой 2 и БЕЗ flow.
         *
         * Vision (xtls-rprx-vision) — это про TCP: он подменяет копирование потока после
         * рукопожатия, а у датаграмм такого потока нет. Xray это и требует: аккаунту с
         * flow=xtls-rprx-vision он запрещает vision на TCP-запросе без flow, но UDP-запрос
         * с пустым flow принимает — именно так ходит UDP у самого Xray. Прислать здесь flow
         * значило бы получить закрытый поток без внятной причины.
         *
         * dport уже в хостовом порядке — см. комментарий в tun.h. */
        len = vless_build_request(s->uuid, udp ? VLESS_CMD_UDP : VLESS_CMD_TCP,
                                  NULL, ip4, k->dport,
                                  udp ? NULL : node->flow, out, sizeof(out));
        if (!len) return SEND_FATAL;
    }

    /* Оборачивать нужно только пока Vision не закончил набивку. После кадра end vision_wrap
     * сводится к копированию данных на месте — а копию мы делали ДВАЖДЫ: сначала в framed,
     * потом из него в out. То есть каждый байт выгрузки проходил по памяти трижды (третий
     * раз — внутри tls13_write, где он обязателен: шифрование идёт на месте в записи).
     * Теперь до шифрования копий ноль или одна. */
    /* Состояние Vision снимается ДО обёртки и возвращается, если отправка не удалась.
     *
     * Иначе первый кадр терялся безвозвратно при закрытом окне HTTP/2: vision_wrap уже
     * пометил бы UUID отправленным и набивку законченной, а h2_write не отправил НИЧЕГО
     * (он либо всё, либо ничего). Клиент повторяет тот же пакет, мы отправляем его уже без
     * кадра и без UUID — сервер такого не ждёт и закрывает поток. Снаружи это выглядело бы
     * как «узел с vision и grpc иногда не работает», причём «иногда» означало бы «когда
     * сервер не успел принять», то есть на быстром канале чаще.
     *
     * Шестьдесят четыре байта копии против невоспроизводимой поломки протокола. */
    struct vision vis_before = s->vis;
    if (node->flow[0] && !udp && !s->vis.sent_end) {
        size_t fn = vision_wrap(&s->vis, data, n, out + len, sizeof(out) - len);
        if (!fn) return SEND_FATAL;
        len += fn;
        body = out;
    } else if (len) {
        /* Заголовок уже лежит в out — данные приклеиваем к нему. */
        if (len + n > sizeof(out)) return SEND_FATAL;
        memcpy(out + len, data, n);
        len += n;
        body = out;
    } else {
        len = n;
    }

    /* Через транспорт: упаковку (tcp, grpc, xhttp) знает он, а не дайлер. */
    int rc = transport_write(&s->t, body, len);
    if (rc == H2_EWINDOW) {
        /* Окно HTTP/2 закрыто: сервер не успевает принимать. Это НЕ отказ — это то, для
         * чего управление потоком и существует. Ничего не ушло (h2_write либо отправляет
         * всё, либо ничего), поэтому достаточно не подтверждать пакет: клиент повторит
         * его сам, как при потере, и повторит уже тогда, когда окно откроется.
         *
         * Первая версия считала это ошибкой и разрывала соединение. Выглядело как
         * «выгрузка обрывается на случайном месте» — месте, где сервер впервые не успел. */
        s->vis = vis_before;                /* кадр не ушёл — обёртка как бы не делалась */
        return SEND_AGAIN;
    }
    if (rc == H2_ESTATUS) {
        /* Сервер xhttp ответил отказом на выгрузку (stream-up, packet-up): кусок не принят, и
         * поток за ним цел не будет. Закрываем, как любую неудачу отправки, но причину
         * называем — иначе узел, отказывающий каждому куску, выглядит живым (I-219). */
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 5) {
            said = now;
            fprintf(stderr, LOG_W "узел %s не принял данные: %s — соединение закрыто; "
                            "проверьте настройки xhttp узла\n", node->name, vless_strerror(rc));
        }
    }
    if (rc) return SEND_FATAL;
    /* Заголовок отмечаем отправленным только теперь: пометить раньше значило бы, что
     * повторная попытка уйдёт без него, и сервер не поймёт, куда соединять. */
    s->header_sent = 1;
    return SEND_OK;
}

/* Датаграмма узлу: двухбайтовая длина и данные ОДНИМ куском.
 *
 * Одним обязательно: h2_write отправляет либо всё, либо ничего, и датаграмма, разрезанная
 * на два вызова, при закрытом окне уехала бы половиной — сервер прочитал бы длину и стал
 * ждать хвост, которого нет, а следующая датаграмма приехала бы внутрь предыдущей. */
static size_t vl_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_MAX || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

/* Через транспорт, а не tls13_read напрямую: у grpc и xhttp между TLS и VLESS лежит HTTP/2, и
 * чтение мимо него отдавало бы кадры вместо данных. Прямой вызов работал, пока транспорт был
 * единственный, и это ровно тот случай, когда «работает» и «правильно» разошлись молча.
 *
 * Вариант _zc отдаёт указатель на расшифрованную запись там, где копия не нужна: на голом tcp
 * данные так и остаются в буфере соединения. Буфер стека при этом всё равно нужен — под
 * транспорты поверх HTTP/2, где кадр собирается из нескольких записей. */
static int vl_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data,
                   size_t *got) {
    struct vl_sess *s = sess;
    return transport_read_zc(&s->t, buf, cap, data, got);
}

/* Разобрать поток датаграмм от узла и отдать их клиенту.
 *
 * Состояние сборки живёт в сессии между вызовами: границы датаграммы, кадра HTTP/2 и записи
 * TLS не совпадают ни в одном месте, и «дочитать до конца датаграммы» здесь нельзя — чтение
 * заблокировалось бы и остановило весь цикл. Возвращает 0 или -1. */
static int udp_downstream(struct vl_sess *s, const unsigned char *d, size_t n,
                          dialer_emit_fn emit, void *arg) {
    while (n) {
        /* Слишком крупная датаграмма выбрасывается РОВНО ПО ДЛИНЕ. Оборвать отсчёт нельзя:
         * её хвост тут же был бы прочитан как длина следующей, и поток разъехался бы
         * навсегда — то есть одна такая датаграмма убивала бы соединение. */
        if (s->dg_skip) {
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take;
            n -= take;
            s->dg_skip -= take;
            continue;
        }
        if (!s->dg_want) {
            if (s->lenb_n) {                        /* первый байт длины приехал раньше */
                s->dg_want = (uint16_t)((s->lenb << 8) | d[0]);
                s->lenb_n = 0;
                d++;
                n--;
            } else if (n == 1) {
                /* Запись кончилась ровно между двумя байтами длины. Случай редкий, и
                 * именно поэтому его надо обработать: потерянный байт длины — это не
                 * потерянная датаграмма, а сдвиг всего потока после неё. */
                s->lenb = d[0];
                s->lenb_n = 1;
                return 0;
            } else {
                s->dg_want = (uint16_t)((d[0] << 8) | d[1]);
                d += 2;
                n -= 2;
            }
            if (!s->dg_want) continue;              /* длина 0: отдавать нечего */
            if (s->dg_want > UDP_DGRAM_MAX) {
                /* Строка — слово в слово прежняя, вместе с повтором «tunnel:» после
                 * приставки: по ней журнал уже читают. */
                static __thread time_t said;
                time_t now = stack_now_s();
                if (now - said >= 10) {
                    said = now;
                    fprintf(stderr, LOG_W "tunnel: датаграмма %u байт больше предела %d — "
                            "выброшена\n", s->dg_want, UDP_DGRAM_MAX);
                }
                s->dg_skip = s->dg_want;
                s->dg_want = 0;
                continue;
            }
            s->dg_have = 0;
        }
        size_t need = (size_t)s->dg_want - s->dg_have;
        size_t take = n < need ? n : need;
        memcpy(s->dg + s->dg_have, d, take);
        s->dg_have = (uint16_t)(s->dg_have + take);
        d += take;
        n -= take;
        if (s->dg_have < s->dg_want) return 0;      /* хвост приедет следующей записью */

        /* Датаграмма целиком — клиенту. Метку времени соединения стек двигает сам, на КАЖДОЙ
         * отданной датаграмме: поток, по которому идёт только приём, иначе убрали бы по простою
         * прямо во время работы. */
        if (emit(arg, s->dg, s->dg_want) != 0) return -1;
        s->dg_want = 0;
        s->dg_have = 0;
    }
    return 0;
}

static int vl_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* Порядок разбора: сначала заголовок ОТВЕТА VLESS, потом кадры Vision.
     *
     * Сервер отвечает так: [версия|длина_доп|доп] и только ДАЛЬШЕ поток в кадрах Vision.
     * Заголовок ответа обёрткой не покрыт, и первая версия пыталась развернуть его как
     * кадр: получала «00 00 96 67 ad» (версия 0, длина 0, начало данных), длины кадра
     * выходили бессмысленные, unwrap возвращал EAGAIN, и ответ терялся целиком.
     *
     * Это зеркало ошибки на отправке: там заголовок ЗАПРОСА тоже идёт до кадра, а не
     * внутри него. Один и тот же принцип, который я дважды прочитал наоборот. */
    const unsigned char *cur = rx;
    size_t left = got;

    if (!s->established) {
        size_t skip = 0;
        if (vless_parse_response(cur, left, &skip) != 0) {
            TR("ответ VLESS не разобран (%zu байт)\n", left);
            return -1;
        }
        cur += skip;
        left -= skip;
        s->established = 1;
        TR("заголовок ответа снят (%zu байт), осталось %zu\n", skip, left);
    }

    /* Дальше пути расходятся: у TCP это поток в кадрах Vision, у UDP — датаграммы с
     * двухбайтовой длиной и без всякого Vision (его в запросе UDP мы не объявляли). */
    if (udp)
        return left ? udp_downstream(s, cur, left, emit, arg) : 0;

    while (left) {
        const unsigned char *p = cur;
        size_t pn = left;

        if (node->flow[0]) {
            size_t used = 0;
            const unsigned char *pl = NULL;
            size_t pl_n = 0;
            int ur = vision_unwrap(&s->vis, cur, left, &used, &pl, &pl_n);
            /* Недопустимая команда в кадре — это КОНЕЦ соединения, а не пауза.
             *
             * Разбор возвращает EPROTO, не сбросив накопленный заголовок, поэтому каждый
             * следующий вызов перечитывает тот же испорченный кадр и потребляет ноль
             * байт. Прежний `break` при этом отдавал неотрицательный итог, то есть
             * соединение считалось живым: одного байта команды 3 от сервера хватало,
             * чтобы туннель до бесконечности читал записи, расшифровывал их (самая
             * дорогая работа на этом железе) и выбрасывал целиком, а клиент ждал ответа,
             * которого не будет, пока слот не уберут по простою в 120 секунд. */
            if (ur == VISION_EPROTO) {
                TR("недопустимый кадр Vision: рвём соединение, осталось %zu\n", left);
                return -1;
            }
            if (ur != 0 || (!used && !pl_n)) {
                /* Нехватка данных ошибкой больше не считается: разбор потоковый и копит
                 * начало потока сам (см. rx_pre в vision.h). Ноль потреблённых байт при
                 * нулевой выдаче означает, что двигаться некуда. */
                TR("кадр не разобран: ur=%d осталось %zu\n", ur, left);
                break;
            }
            p = pl;
            pn = pl_n;
            cur += used;
            left -= used;

        } else {
            cur += left;
            left = 0;
        }

        /* Отдаём кадр сразу, а не складываем в общий буфер: складывать было незачем — всё
         * равно потом нарезали, — а стоило это копии всего трафика и предела «не влезло». */
        if (pn && emit(arg, p, pn) != 0) return -1;
    }

    /* Сервер объявил прямое копирование — сообщаем об этом связи, чтобы следующее чтение шло
     * мимо расшифровки. Ставится ЗДЕСЬ, потому что команда живёт в кадрах Vision, а про них
     * знает только этот код. */
    if (s->vis.recv_direct && !s->t.link.rx_direct) {
        transport_direct(&s->t);
        TR("сервер перешёл на прямое копирование — читаем сокет как есть\n");
    }
    return 0;
}

/* ---- подъём ---------------------------------------------------------------------------- */

int vless_tunnel_run(struct output *o, const struct vless_node *node) {
    /* Идентификатор узла — ДО устройства и потоков, пока узел ещё можно назвать. Дальше он
     * разбирается заново на каждое соединение (vl_flow_open), и отказ там означал бы туннель,
     * который поднят, но закрывает всё подряд (I-097). */
    unsigned char id[16];
    if (vless_uuid_parse(node->uuid, id) != 0) {
        fprintf(stderr, "steer[warn]: у узла %s не разбирается UUID — туннель %s не поднят; "
                        "проверьте ссылку узла\n", node->name, o->device);
        return 1;
    }
    g_trace = getenv("STEER_TUN_TRACE") != NULL;
    /* Статический: стек держит указатель на дайлер до конца процесса (g_dl в stack.c). */
    static struct dialer d;
    d.ops = &vless_dialer;
    d.ctx = node;
    return stack_run(o, &d);
}

const struct dialer_ops vless_dialer = {
    .name = "vless",
    .caps = DC_PRECONNECT,
    .sess_size = sizeof(struct vl_sess),
    .peer = vl_peer,
    .describe = vl_describe,
    .strerror = vless_strerror,
    .connect = vl_connect,
    .take = vl_take,
    .close = vl_close,
    .clear = vl_clear,
    .fd = vl_fd,
    .has_data = vl_has_data,
    .flow_open = vl_flow_open,
    .send = vl_send,
    .dgram_frame = vl_dgram_frame,
    .read = vl_read,
    .deliver = vl_deliver,
};
