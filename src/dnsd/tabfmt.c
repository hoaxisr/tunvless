/* Формат таблицы доменных каналов — см. шапку tabfmt.h.
 *
 * Файл НЕ включает proxy.c и ничего из него не зовёт: демону, которому нужна только сборка
 * таблицы (steerd, docs/architecture.md, раздел 4а), незачем линковать epoll резолвера, сеть
 * и fake-IP ради двух функций ниже — table.c (dch_build) и этот файл собираются отдельно от
 * DNSD_SRC переменной DNSD_TABLE_SRC (build/sources.mk). */
#include "dnsd_int.h"
#include "tabfmt.h"
#include <errno.h>

/* ---- сборка: демон и `steer dnsd-table --spec` ------------------------------------------- */

void tabfmt_build(const struct spec *sp, FILE *out) {
    dch_build(sp);
    fprintf(out, "%zu\n", g_dch_n);
    for (size_t i = 0; i < g_dch_n; i++) {
        const struct dchan *c = &g_dch[i];
        /* family — по факту (1.9, IPv6): «46», когда у доменной группы есть половина IPv6
         * (dom6_ok — парный набор «<set>6» и v6-двойник у компилятора) и спека не v1, иначе
         * «4» (решает dch_fam, table.c). */
        fprintf(out, "%s|%s|%d|%s|%s", c->set, c->out, c->realip ? 1 : 0,
                (c->fam & DCH_V6) ? ((c->fam & DCH_V4) ? "46" : "6") : "4", c->chan);
        for (size_t k = 0; k < c->rules_n; k++)
            fprintf(out, "|%s", c->rules_path[k]);
        fputc('\n', out);
    }
}

/* ---- разбор: резолвер (--table-fd) --------------------------------------------------------- */

/* Освободить всё, чем СЕЙЧАС владеет g_dch: набор правил (загружает reload_rules, proxy.c,
 * не эта функция) и пути его файлов, которые в режиме --table-fd всегда strdup'нуты прежним
 * вызовом tabfmt_parse (первым — нечего освобождать, g_dch тогда ещё в нулях BSS, free(NULL)
 * от этого не портится). */
static void tabfmt_release_current(void) {
    for (size_t i = 0; i < g_dch_n; i++) {
        ruleset_free(&g_dch[i].rules);
        dch_parts_free(g_dch[i].parts, g_dch[i].parts_n);
        for (size_t k = 0; k < g_dch[i].rules_n; k++)
            free((char *)g_dch[i].rules_path[k]);
    }
    memset(g_dch, 0, sizeof(g_dch));
    g_dch_n = 0;
}

/* Индекс первого '\n' в buf[from, len), или len — «не нашли» (len сам никогда не индекс
 * настоящего байта таблицы, поэтому сравнение результата с len у вызывающих однозначно). */
static size_t find_nl(const char *buf, size_t len, size_t from) {
    for (size_t i = from; i < len; i++)
        if (buf[i] == '\n') return i;
    return len;
}

/* Скопировать поле дли ины flen в dst[dcap] с усечением — то же truncate-по-построению, что и
 * dch_build (snprintf "%.31s" и соседи, table.c): поле от испорченной строки длиннее буфера
 * усекается, а не переполняет его. */
static void field_copy(char *dst, size_t dcap, const char *src, size_t flen) {
    if (flen >= dcap) flen = dcap - 1;
    memcpy(dst, src, flen);
    dst[flen] = '\0';
}

/* Разобрать одну строку канала buf[from, line_end) (без завершающего '\n') в *c и в family
 * (family_cap байт, включая '\0'). Возвращает 0 при успехе, -1 — меньше пяти полей
 * (set|out|realip|family|chan обязательны, путей может не быть вовсе). */
static int parse_chan_line(const char *buf, size_t from, size_t line_end, struct dchan *c,
                            char *family, size_t family_cap) {
    memset(c, 0, sizeof(*c));
    if (family_cap) family[0] = '\0';
    size_t pos = from;
    int field = 0;
    while (pos <= line_end) {
        size_t fend = pos;
        while (fend < line_end && buf[fend] != '|') fend++;
        size_t flen = fend - pos;
        switch (field) {
            case 0: field_copy(c->set, sizeof(c->set), buf + pos, flen); break;
            case 1: field_copy(c->out, sizeof(c->out), buf + pos, flen); break;
            case 2: {
                char digit[8];
                field_copy(digit, sizeof(digit), buf + pos, flen);
                c->realip = atoi(digit) != 0;
                break;
            }
            case 3: field_copy(family, family_cap, buf + pos, flen); break;
            case 4: field_copy(c->chan, sizeof(c->chan), buf + pos, flen); break;
            default:
                if (c->rules_n < MAX_FILES) {
                    char *p = malloc(flen + 1);
                    if (!p) return -1;
                    memcpy(p, buf + pos, flen);
                    p[flen] = '\0';
                    c->rules_path[c->rules_n++] = p;
                }
                /* Путей больше MAX_FILES — поле молча отбрасывается (та же граница, что у
                 * dch_build: g_dch[k].rules_n < MAX_FILES в цикле по domains_files/prefixes_files,
                 * table.c), а не отказ разбора: обрезанный список правил хуже полного, но не хуже
                 * отсутствующего резолвера. */
                break;
        }
        field++;
        if (fend >= line_end) break;
        pos = fend + 1;
    }
    return field >= 5 ? 0 : -1;
}

int tabfmt_parse(const char *buf, size_t len) {
    size_t nl = find_nl(buf, len, 0);
    if (nl >= len) return -1; /* нет даже строки-счётчика */
    char digits[16];
    field_copy(digits, sizeof(digits), buf, nl);
    char *end = NULL;
    long want = strtol(digits, &end, 10);
    if (end == digits || *end != '\0' || want < 0 || (size_t)want > MAX_RULES) return -1;

    tabfmt_release_current();

    size_t out_n = 0;
    size_t pos = nl + 1;
    for (long i = 0; i < want; i++) {
        size_t line_end = find_nl(buf, len, pos);
        if (line_end >= len) return -1; /* обещали want строк, а текст кончился раньше */
        struct dchan tmp;
        char family[8];
        if (parse_chan_line(buf, pos, line_end, &tmp, family, sizeof(family)) != 0) return -1;
        /* family — «4», «6» или «46» (1.9, IPv6): DCH_V6 — у канала есть парный набор «<set>6»,
         * и на AAAA его имён резолвер отвечает адресом (fake-IP v6 или настоящим) вместо
         * пустого ответа. Канал «6» (без IPv4) принимается так же: A его имён он не забирает
         * (proxy.c, match_for). */
        int has4 = !strcmp(family, "4") || !strcmp(family, "46");
        int has6 = !strcmp(family, "6") || !strcmp(family, "46");
        if (!has4 && !has6) return -1; /* не «4», не «6», не «46» — испорченный текст */
        tmp.fam = (has4 ? DCH_V4 : 0) | (has6 ? DCH_V6 : 0);
        g_dch[out_n++] = tmp;
        pos = line_end + 1;
    }
    g_dch_n = out_n;
    return 0;
}

/* ---- приёмник из трубы: буферизация между вызовами epoll ---------------------------------- */

int tabfmt_feed(struct tabfmt_feed *st, const char *data, size_t n) {
    if (n) {
        if (st->len + n > sizeof(st->buf)) return -1;
        memcpy(st->buf + st->len, data, n);
        st->len += n;
    }

    size_t nl = find_nl(st->buf, st->len, 0);
    if (nl >= st->len) return 0; /* строка-счётчик ещё не дописана */
    char digits[16];
    field_copy(digits, sizeof(digits), st->buf, nl);
    char *end = NULL;
    long want = strtol(digits, &end, 10);
    if (end == digits || *end != '\0' || want < 0 || (size_t)want > MAX_RULES) return -1;

    size_t pos = nl + 1;
    for (long i = 0; i < want; i++) {
        size_t line_end = find_nl(st->buf, st->len, pos);
        if (line_end >= st->len) return 0; /* строк пока меньше, чем обещал счётчик */
        pos = line_end + 1;
    }
    /* pos — конец РОВНО ОДНОЙ таблицы: столько и передаётся в tabfmt_parse, остаток (начало
     * следующей, если демон прислал две таблицы одной записью в трубу) остаётся в буфере. */
    if (tabfmt_parse(st->buf, pos) != 0) return -1;
    memmove(st->buf, st->buf + pos, st->len - pos);
    st->len -= pos;
    return 1;
}

int tabfmt_read_first(int fd, struct tabfmt_feed *st) {
    /* st — буфер вызывающего (в run_proxy это то же состояние, которым потом кормит труба через
     * epoll): переполнение первой блокирующей записи демона второй таблицей — редкость, но
     * оставлять её хвост здесь и не отдать вызывающему значило бы потерять байты, уже прочитанные
     * с fd. Поэтому состояние ровно одно на весь процесс, а не своё у каждого вызова. */
    for (;;) {
        char chunk[4096];
        ssize_t r = read(fd, chunk, sizeof(chunk));
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1; /* труба закрылась раньше первой таблицы — демон умер */
        int rc = tabfmt_feed(st, chunk, (size_t)r);
        if (rc < 0) return -1;
        if (rc > 0) return 0; /* первая таблица разобрана; хвост (если демон прислал вторую
                                * следом же записью) остался в st — его доберёт та же tabfmt_feed
                                * из цикла epoll, без потери байт */
    }
}
