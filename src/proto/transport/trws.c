/* Транспорт ws: поток протокола в кадрах WebSocket (RFC 6455) после запроса Upgrade.
 *
 * Верхний ярус транспорта (transport.h), шаг 5 выпуска 1.10. Запрос Upgrade и ответ 101 — общие с
 * httpupgrade (trupgrade.c); здесь — только кадры.
 *
 * ОТПРАВКА — КАК У XRAY. Клиент Xray пишет в gorilla/websocket одним WriteMessage(BinaryMessage)
 * на каждую свою запись, а буфер записи у него 4096 байт (websocket/dialer.go: WriteBufferSize), и
 * сообщение длиннее буфера gorilla режет на кадры по 4096: первый — binary без FIN, дальше
 * continuation, последний — с FIN (messageWriter.flushFrame в conn.go). Перехват Xray 26.3.27 на
 * выгрузке 30 КБ так и показал: 4096 без FIN, 4096 с FIN, 34 с FIN, … Каждый кадр уходит своей
 * записью в сокет — у TLS это своя запись TLS. Мы режем так же и пишем так же, по кадру на запись:
 * размеры записей на проводе тогда совпадают с клиентом Xray, а не выдают «другую реализацию»
 * одним своим видом. (Правило Go о малых записях TLS в начале соединения — dynamic record
 * sizing — этим не повторено: у нашего TLS своя раскладка, общая для всех транспортов.)
 *
 * Маска — у каждого кадра своя, из случайности ядра (RFC 6455, 5.3: клиент обязан маскировать,
 * ключ обязан быть непредсказуем, иначе посредник-кеш можно отравить подобранными байтами).
 * Ключи берутся пачкой, по 64 кадра на один getrandom: вызов ядра на каждые 4 КБ выгрузки на
 * роутере заметен, а пачка на поток ничем не хуже по непредсказуемости.
 *
 * ПРИЁМ — потоком (tr_ws_parse): сервер (у Xray — WriteMessage без буфера) шлёт сообщение одним
 * незамаскированным кадром, но RFC разрешает и фрагменты, и служебные кадры посреди них, и кадр
 * любой длины до 2^63 — поэтому разбор ничего не предполагает о границах и копит только
 * заголовок кадра и тело служебного. Нарушения RFC — маска от сервера, биты RSV без
 * согласованных расширений, служебный кадр длиннее 125 байт или разрезанный, continuation вне
 * сообщения и новое сообщение внутри неразрезанного, неизвестный опкод — рвут соединение
 * (TR_EWSFRAME), как у gorilla: поток после такого кадра уже не понять. Текстовые кадры
 * читаются как двоичные: Xray сам поступает так же (connection.go читает NextReader, не глядя на
 * тип), а проверять UTF-8 у байтов VLESS бессмысленно.
 *
 * ping — ответ pong с тем же телом; pong — ничего; close — ответный close с тем же кодом (так
 * отвечает gorilla по умолчанию) и конец потока. Данные, приехавшие в одном куске ДО close,
 * отдаются, а конец потока — следующим чтением.
 *
 * Своего close при закрытии соединения не шлём (Xray шлёт его со сроком 5 секунд): закрытие идёт
 * из цикла туннеля, и блокирующая запись в соединение, которое, возможно, уже мертво, стояла бы
 * там до срока сокета. Сервер видит FIN, как у любого другого транспорта. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "transport.h"

#define WS_FRAG 4096               /* кадр отправки: как буфер записи gorilla у Xray */

size_t tr_ws_frame(unsigned char *out, size_t cap, int opcode, int fin, const unsigned char key[4],
                   const unsigned char *d, size_t n) {
    size_t h = n > 65535 ? 10 : n > 125 ? 4 : 2;
    if (h + 4 + n > cap || h + 4 + n < n) return 0;
    out[0] = (unsigned char)((fin ? 0x80 : 0) | (opcode & 0x0f));
    if (n > 65535) {
        out[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) out[2 + i] = (unsigned char)((uint64_t)n >> (56 - 8 * i));
    } else if (n > 125) {
        out[1] = 0x80 | 126;
        out[2] = (unsigned char)(n >> 8);
        out[3] = (unsigned char)n;
    } else {
        out[1] = (unsigned char)(0x80 | n);
    }
    memcpy(out + h, key, 4);
    unsigned char *p = out + h + 4;
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(d[i] ^ key[i & 3]);
    return h + 4 + n;
}

/* Служебный кадр дочитан. */
static int ws_ctl(struct ws_rx *r) {
    switch (r->op) {
    case 9:                                    /* ping */
        r->pong_due = 1;
        r->pong_n = r->ctl_n;
        memcpy(r->pong, r->ctl, r->ctl_n);
        return 0;
    case 10:                                   /* pong — ответ на наш ping; мы их не шлём */
        return 0;
    case 8:                                    /* close */
        /* Тело close — либо пусто, либо код (2 байта) и причина. Один байт — нарушение
         * (RFC 6455, 5.5.1). */
        if (r->ctl_n == 1) return TR_EWSFRAME;
        r->closed = 1;
        r->close_code = r->ctl_n >= 2 ? (uint16_t)((r->ctl[0] << 8) | r->ctl[1]) : 1005;
        return 0;
    default:
        return TR_EWSFRAME;
    }
}

int tr_ws_parse(struct ws_rx *r, const unsigned char *in, size_t n,
                unsigned char *out, size_t cap, size_t *out_n) {
    size_t i = 0, o = 0;
    *out_n = 0;
    while (i < n && !r->closed) {
        if (!r->in_payload) {
            r->hdr[r->hdr_n++] = in[i++];
            if (r->hdr_n < 2) continue;
            unsigned b0 = r->hdr[0], b1 = r->hdr[1];
            /* Кадр сервера маскироваться не вправе (RFC 6455, 5.1): клиент обязан закрыть
             * соединение. Проверяется до длины — дальше этот кадр читать незачем. */
            if (b1 & 0x80) return TR_EWSFRAME;
            unsigned l7 = b1 & 0x7f;
            size_t need = 2 + (l7 == 126 ? 2 : l7 == 127 ? 8 : 0);
            if (r->hdr_n < need) continue;
            uint64_t len = l7;
            if (l7 == 126) {
                len = ((uint64_t)r->hdr[2] << 8) | r->hdr[3];
            } else if (l7 == 127) {
                len = 0;
                for (int k = 2; k < 10; k++) len = (len << 8) | r->hdr[k];
                if (len >> 63) return TR_EWSFRAME;     /* старший бит длины обязан быть 0 */
            }
            r->hdr_n = 0;
            if (b0 & 0x70) return TR_EWSFRAME;         /* RSV: расширений не согласовывали */
            unsigned op = b0 & 0x0f, fin = b0 >> 7;
            if (op & 8) {
                if (op > 10 || !fin || len > 125) return TR_EWSFRAME;
            } else if (op == 0) {
                if (!r->in_msg) return TR_EWSFRAME;
                r->in_msg = (uint8_t)!fin;
            } else if (op == 1 || op == 2) {
                if (r->in_msg) return TR_EWSFRAME;
                r->in_msg = (uint8_t)!fin;
            } else {
                return TR_EWSFRAME;
            }
            r->op = (uint8_t)op;
            r->left = len;
            r->ctl_n = 0;
            if (len) { r->in_payload = 1; continue; }
            if (op & 8) {
                int rc = ws_ctl(r);
                if (rc) return rc;
            }
            continue;
        }
        size_t take = n - i;
        if (take > r->left) take = (size_t)r->left;
        if (r->op & 8) {
            memcpy(r->ctl + r->ctl_n, in + i, take);
            r->ctl_n = (uint8_t)(r->ctl_n + take);
        } else {
            if (o + take > cap) return H2_ETOOBIG;
            memmove(out + o, in + i, take);
            o += take;
        }
        i += take;
        r->left -= take;
        if (!r->left) {
            r->in_payload = 0;
            if (r->op & 8) {
                int rc = ws_ctl(r);
                if (rc) return rc;
            }
        }
    }
    *out_n = o;
    return 0;
}

/* Ключ маски: пачка случайности на поток. */
static int mask_key(unsigned char key[4]) {
    static __thread unsigned char pool[256];
    static __thread unsigned left;
    if (left < 4) {
        if (tr_h1_random(pool, sizeof(pool)) != 0) return -1;
        left = sizeof(pool);
    }
    memcpy(key, pool + sizeof(pool) - left, 4);
    left -= 4;
    return 0;
}

static int ws_control(struct transport *t, int op, const unsigned char *d, size_t n) {
    unsigned char key[4], f[2 + 4 + 125];
    if (mask_key(key) != 0) return TR_EIO;
    size_t fl = tr_ws_frame(f, sizeof(f), op, 1, key, d, n);
    return fl ? tr_link_write(&t->link, f, fl) : TR_EWSFRAME;
}

/* Ответить на служебное, что накопил разбор: pong на ping, ответный close на close. */
static int ws_answer(struct transport *t) {
    struct ws_rx *r = &t->h1.rx;
    int rc = 0;
    if (r->pong_due && !r->closed) {
        r->pong_due = 0;
        rc = ws_control(t, 10, r->pong, r->pong_n);
    }
    if (r->closed && !r->close_sent) {
        r->close_sent = 1;
        unsigned char c[2] = { (unsigned char)(r->close_code >> 8), (unsigned char)r->close_code };
        /* Ошибка ответного close не важна: соединение и так кончается. */
        (void)ws_control(t, 8, c, r->close_code == 1005 ? 0 : 2);
    }
    return rc;
}

static int ws_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    return tr_h1_upgrade(t, n, 1, timeout_s);
}

static int ws_write(struct transport *t, const unsigned char *d, size_t n) {
    static __thread unsigned char fb[WS_FRAG + 14];
    size_t off = 0;
    int op = 2;                                /* binary, дальше — continuation */
    while (off < n) {
        size_t take = n - off > WS_FRAG ? WS_FRAG : n - off;
        unsigned char key[4];
        if (mask_key(key) != 0) return TR_EIO;
        size_t fl = tr_ws_frame(fb, sizeof(fb), op, off + take == n, key, d + off, take);
        int rc = tr_link_write(&t->link, fb, fl);
        if (rc) return rc;
        off += take;
        op = 0;
    }
    return 0;
}

/* Кусок входа — целиком в разбор, тела кадров — в d. Выход не длиннее входа (заголовки кадров
 * только убывают), поэтому запись TLS, влезающая в d, влезает и разобранной. */
static int ws_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    struct h1_state *s = &t->h1;
    struct ws_rx *r = &s->rx;
    if (r->closed) return TR_ECLOSED;
    size_t on = 0;
    int rc;
    if (s->stash) {
        /* Сначала то, что приехало вместе с ответом 101. */
        size_t left = s->stash_n - s->stash_off;
        size_t take = left < cap ? left : cap;
        rc = tr_ws_parse(r, s->stash + s->stash_off, take, d, cap, &on);
        s->stash_off += (uint32_t)take;
        if (s->stash_off >= s->stash_n) tr_h1_free(t);
    } else if (!t->link.plain) {
        const unsigned char *in = NULL;
        size_t n = 0;
        rc = tls13_read_ref(&t->link.tls, &in, &n);
        if (rc) return rc;
        if (!n) return 0;
        rc = tr_ws_parse(r, in, n, d, cap, &on);
    } else {
        /* Голый сокет: читаем прямо в d и разбираем на месте. */
        ssize_t k = read(t->link.fd, d, cap);
        if (k <= 0) return k == 0 ? TR_ECLOSED : TR_EIO;
        rc = tr_ws_parse(r, d, (size_t)k, d, cap, &on);
    }
    if (rc) return rc;
    rc = ws_answer(t);
    *got = on;
    if (rc) return rc;
    if (r->closed && !on) return TR_ECLOSED;
    return 0;
}

/* Остаток после 101 и отложенный конец потока: и то, и другое цикл туннеля обязан забрать
 * чтением, хотя сокет может молчать. */
static int ws_pending(const struct transport *t) {
    return t->h1.stash != NULL || t->h1.rx.closed;
}

static void ws_close(struct transport *t) { tr_h1_free(t); }

const struct transport_ops tr_ws = {
    .name = "ws", .alpn = "http/1.1", .zc = 0,
    .open = ws_open, .write = ws_write, .read = ws_read,
    .moved = NULL, .close = ws_close, .pending = ws_pending,
};
